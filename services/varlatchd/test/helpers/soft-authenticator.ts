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
  /** An assertion over `challenge` for `origin`, as a browser would post it. */
  assert(challenge: string, options?: { origin?: string; rpId?: string; tamper?: boolean }): Record<string, unknown>;
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

export async function registerSoftPasskey(
  db: Querier,
  identityId: string,
  options: { rpId: string; origin: string },
): Promise<SoftAuthenticator> {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const credentialId = randomBytes(16).toString("base64url");
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
  await db.query(
    `INSERT INTO passkey (id, name, "publicKey", "userId", "credentialID", counter, "deviceType", "backedUp", transports, "createdAt")
     VALUES ($1, 'test passkey', $2, $3, $4, 0, 'singleDevice', false, 'internal', now())`,
    [`pk_${credentialId}`, coseKey(publicKey).toString("base64"), userId, credentialId],
  );
  let counter = 0;
  return {
    credentialId,
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
        Buffer.from([0x05]), // user present, user verified
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
  };
}
