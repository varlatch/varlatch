// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/server";
import type { Querier } from "../db/migrate.js";

/**
 * A fresh passkey assertion for one operation (device sign-in approval):
 * Better Auth's passkey sign-in cannot bind a ceremony to an operation, so
 * this module runs its own WebAuthn authentication against the passkeys
 * Better Auth stores. The challenge is generated here and kept server-side
 * by the caller, bound to the operation, identity, and session.
 */

export interface RelyingParty {
  /** WebAuthn RP ID: the public URL's host name. */
  rpId: string;
  /** The public URL's origin. */
  origin: string;
}

export function relyingPartyOf(publicUrl: string): RelyingParty {
  const url = new URL(publicUrl);
  return { rpId: url.hostname, origin: url.origin };
}

interface PasskeyRow {
  id: string;
  credentialID: string;
  publicKey: string;
  counter: number;
  transports: string | null;
}

async function passkeysOf(db: Querier, identityId: string): Promise<PasskeyRow[]> {
  const res = await db.query(
    `SELECT p.id, p."credentialID", p."publicKey", p.counter, p.transports
     FROM passkey p JOIN auth_user_links l ON l.better_auth_user_id = p."userId"
     WHERE l.identity_id = $1 ORDER BY p."createdAt", p.id`,
    [identityId],
  );
  return res.rows as PasskeyRow[];
}

/** `{ transports }` when the passkey recorded any, else nothing. */
function transportsOf(row: PasskeyRow): { transports: AuthenticatorTransportFuture[] } | Record<string, never> {
  return row.transports ? { transports: row.transports.split(",") as AuthenticatorTransportFuture[] } : {};
}

/** Request options for the identity's own passkeys, with a new random challenge; null when it has none. */
export async function assertionOptions(
  db: Querier,
  rp: RelyingParty,
  identityId: string,
  timeoutMs: number,
): Promise<PublicKeyCredentialRequestOptionsJSON | null> {
  const passkeys = await passkeysOf(db, identityId);
  if (passkeys.length === 0) return null;
  return generateAuthenticationOptions({
    rpID: rp.rpId,
    timeout: timeoutMs,
    // As Better Auth's passkey sign-in: user presence always, verification when the authenticator can.
    userVerification: "preferred",
    allowCredentials: passkeys.map((p) => ({ id: p.credentialID, ...transportsOf(p) })),
  });
}

/** The challenge an assertion's client data carries, or null when it is not a WebAuthn assertion. */
export function assertionChallenge(response: unknown): string | null {
  const clientDataJSON = (response as { response?: { clientDataJSON?: unknown } } | null)?.response?.clientDataJSON;
  if (typeof clientDataJSON !== "string") return null;
  try {
    const clientData = JSON.parse(Buffer.from(clientDataJSON, "base64url").toString("utf8")) as { challenge?: unknown };
    return typeof clientData.challenge === "string" ? clientData.challenge : null;
  } catch {
    return null;
  }
}

/**
 * Verify an assertion made with one of the identity's own passkeys over
 * `expectedChallenge`, and advance that passkey's signature counter. Run it
 * inside the transaction that consumes the challenge. Returns the reason on
 * refusal; never throws for a bad assertion.
 */
export async function verifyAssertion(
  db: Querier,
  rp: RelyingParty,
  identityId: string,
  response: unknown,
  expectedChallenge: string,
): Promise<{ ok: true } | { ok: false; reason: "unknown-passkey" | "invalid-assertion" }> {
  const credentialId = (response as { id?: unknown } | null)?.id;
  const passkey = typeof credentialId === "string"
    ? (await passkeysOf(db, identityId)).find((p) => p.credentialID === credentialId)
    : undefined;
  // A passkey of another identity, or none at all, never approves for this one.
  if (!passkey) return { ok: false, reason: "unknown-passkey" };
  try {
    const verification = await verifyAuthenticationResponse({
      response: response as AuthenticationResponseJSON,
      expectedChallenge,
      expectedOrigin: rp.origin,
      expectedRPID: rp.rpId,
      credential: {
        id: passkey.credentialID,
        publicKey: new Uint8Array(Buffer.from(passkey.publicKey, "base64")),
        counter: passkey.counter,
        ...transportsOf(passkey),
      },
      requireUserVerification: false,
    });
    if (!verification.verified) return { ok: false, reason: "invalid-assertion" };
    await db.query("UPDATE passkey SET counter = $2 WHERE id = $1", [passkey.id, verification.authenticationInfo.newCounter]);
    return { ok: true };
  } catch {
    return { ok: false, reason: "invalid-assertion" };
  }
}
