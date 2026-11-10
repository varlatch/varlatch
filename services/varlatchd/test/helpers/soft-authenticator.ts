// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import type { Querier } from "../../src/db/migrate.js";

/**
 * A software passkey for tests: an ES256 key whose public half is stored the
 * way Better Auth stores passkeys (COSE key, base64), linked to a Varlatch
 * identity, and which signs WebAuthn assertions the server verifies with
 * its real verification code.
 */
export interface SoftAuthenticator {
  credentialId: string;
  /** Better Auth's passkey row id, once the key is stored. */
  passkeyId: string;
  /**
   * An assertion over `challenge` for `origin`, as a browser would post it.
   * The authenticator verifies the user (a PIN or biometric) unless
   * `userVerified` is false: then only user presence is flagged.
   */
  assert(challenge: string, options?: { origin?: string; rpId?: string; tamper?: boolean; userVerified?: boolean }): Record<string, unknown>;
}

/** A software authenticator not stored anywhere yet: it can answer a registration ceremony (attestation "none"). */
export interface UnregisteredAuthenticator extends Omit<SoftAuthenticator, "passkeyId"> {
  /** A registration response (RegistrationResponseJSON) over `challenge`. */
  attest(challenge: string, options?: { origin?: string; rpId?: string; userVerified?: boolean; credentialId?: string }): Record<string, unknown>;
  coseKey: Buffer;
}

function cbor(bytes: Buffer): Buffer {
  // Byte string of 24..255 bytes: major type 2, one-byte length.
  return Buffer.concat([Buffer.from([0x58, bytes.length]), bytes]);
}

function coseKey(publicKey: KeyObject): Buffer {
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  return Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21]), // {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x
    cbor(Buffer.from(jwk.x, "base64url")),
    Buffer.from([0x22]), // -3: y
    cbor(Buffer.from(jwk.y, "base64url")),
  ]);
}

function cborBytes(bytes: Buffer): Buffer {
  if (bytes.length < 24) return Buffer.concat([Buffer.from([0x40 + bytes.length]), bytes]);
  if (bytes.length < 256) return Buffer.concat([Buffer.from([0x58, bytes.length]), bytes]);
  const len = Buffer.alloc(2);
  len.writeUInt16BE(bytes.length);
  return Buffer.concat([Buffer.from([0x59]), len, bytes]);
}

function cborText(text: string): Buffer {
  const bytes = Buffer.from(text, "utf8");
  return Buffer.concat([Buffer.from([0x60 + bytes.length]), bytes]);
}

/** A new software authenticator for `options.rpId`, with its own key pair and credential id. */
export function softAuthenticator(options: { rpId: string; origin: string }): UnregisteredAuthenticator {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const credentialId = randomBytes(16).toString("base64url");
  const key = coseKey(publicKey);
  let counter = 0;
  return {
    credentialId,
    coseKey: key,
    assert(challenge, assertOptions = {}) {
      counter++;
      const clientDataJSON = Buffer.from(JSON.stringify({
        type: "webauthn.get",
        challenge,
        origin: assertOptions.origin ?? options.origin,
        crossOrigin: false,
      }));
      const signCount = Buffer.alloc(4);
      signCount.writeUInt32BE(counter);
      const authenticatorData = Buffer.concat([
        createHash("sha256").update(assertOptions.rpId ?? options.rpId).digest(),
        // 0x05: user present and user verified; 0x01: user present only.
        Buffer.from([assertOptions.userVerified === false ? 0x01 : 0x05]),
        signCount,
      ]);
      const signature = sign("sha256", Buffer.concat([authenticatorData, createHash("sha256").update(clientDataJSON).digest()]), privateKey);
      if (assertOptions.tamper) signature[signature.length - 1] ^= 0x01;
      return {
        id: credentialId,
        rawId: credentialId,
        type: "public-key",
        clientExtensionResults: {},
        response: {
          clientDataJSON: clientDataJSON.toString("base64url"),
          authenticatorData: authenticatorData.toString("base64url"),
          signature: signature.toString("base64url"),
        },
      };
    },
    attest(challenge, attestOptions = {}) {
      const id = attestOptions.credentialId ?? credentialId;
      const rawId = Buffer.from(id, "base64url");
      const clientDataJSON = Buffer.from(JSON.stringify({
        type: "webauthn.create",
        challenge,
        origin: attestOptions.origin ?? options.origin,
        crossOrigin: false,
      }));
      const idLength = Buffer.alloc(2);
      idLength.writeUInt16BE(rawId.length);
      const authData = Buffer.concat([
        createHash("sha256").update(attestOptions.rpId ?? options.rpId).digest(),
        // 0x45: user present, user verified, attested credential data; 0x41 without verification.
        Buffer.from([attestOptions.userVerified === false ? 0x41 : 0x45]),
        Buffer.alloc(4),
        Buffer.alloc(16), // AAGUID: none
        idLength,
        rawId,
        key,
      ]);
      const attestationObject = Buffer.concat([
        Buffer.from([0xa3]),
        cborText("fmt"), cborText("none"),
        cborText("attStmt"), Buffer.from([0xa0]),
        cborText("authData"), cborBytes(authData),
      ]);
      return {
        id,
        rawId: id,
        type: "public-key",
        clientExtensionResults: {},
        response: {
          clientDataJSON: clientDataJSON.toString("base64url"),
          attestationObject: attestationObject.toString("base64url"),
          transports: ["internal"],
        },
      };
    },
  };
}

/**
 * A software passkey stored for the identity, as Better Auth stores one.
 * `trust` records its provenance (ADR-0054 Decision 4); without it the
 * passkey has no provenance row and counts as unconfirmed.
 */
export async function registerSoftPasskey(
  db: Querier,
  identityId: string,
  options: { rpId: string; origin: string; trust?: "trusted" | "unconfirmed" },
): Promise<SoftAuthenticator> {
  const authenticator = softAuthenticator(options);
  const { credentialId } = authenticator;
  const linked = (await db.query("SELECT better_auth_user_id FROM auth_user_links WHERE identity_id = $1", [identityId])).rows[0] as
    | { better_auth_user_id: string }
    | undefined;
  const userId = linked?.better_auth_user_id ?? `bau_${identityId}`;
  if (!linked) {
    await db.query(
      `INSERT INTO "user" (id, name, email, "emailVerified", "updatedAt") VALUES ($1, $2, $3, false, now())`,
      [userId, identityId, `${identityId}@varlatch.placeholder.invalid`],
    );
    await db.query("INSERT INTO auth_user_links (better_auth_user_id, identity_id) VALUES ($1, $2)", [userId, identityId]);
  }
  const passkeyId = `pk_${credentialId}`;
  await db.query(
    `INSERT INTO passkey (id, name, "publicKey", "userId", "credentialID", counter, "deviceType", "backedUp", transports, "createdAt")
     VALUES ($1, 'test passkey', $2, $3, $4, 0, 'singleDevice', false, 'internal', now())`,
    [passkeyId, authenticator.coseKey.toString("base64"), userId, credentialId],
  );
  if (options.trust === "trusted") {
    await db.query(
      "INSERT INTO passkey_provenance (passkey_id, trust, trusted_via, trusted_at, setup_grant_kind) VALUES ($1, 'trusted', 'setup-grant', now(), 'invite')",
      [passkeyId],
    );
  } else if (options.trust === "unconfirmed") {
    await db.query("INSERT INTO passkey_provenance (passkey_id, trust) VALUES ($1, 'unconfirmed')", [passkeyId]);
  }
  return { credentialId, passkeyId, assert: (challenge, assertOptions) => authenticator.assert(challenge, assertOptions) };
}
