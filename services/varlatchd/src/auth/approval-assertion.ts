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
 * A fresh passkey assertion for one operation (device sign-in approval, a
 * passkey confirmation): Better Auth's passkey sign-in cannot bind a
 * ceremony to an operation, so this module runs its own WebAuthn
 * authentication against the passkeys Better Auth stores. The challenge is
 * generated here and kept server-side by the caller, bound to the
 * operation, identity, and session.
 *
 * User verification (ADR-0054 Decision 6): the caller says whether the
 * operation requires it, and a verified assertion reports what the
 * authenticator said, with the passkey that asserted, so the caller can
 * record that evidence.
 */

/** WebAuthn's userVerification for a ceremony's options. */
export type UserVerification = "preferred" | "required";

/** Which of the identity's passkeys may assert; all of them when absent. */
export interface PasskeyScope {
  passkeyIds?: readonly string[] | undefined;
}

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
  transports: string | null;
}

async function passkeysOf(db: Querier, identityId: string): Promise<PasskeyRow[]> {
  const res = await db.query(
    `SELECT p.id, p."credentialID", p."publicKey", p.transports
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

function inScope(passkeys: PasskeyRow[], scope: PasskeyScope): PasskeyRow[] {
  if (!scope.passkeyIds) return passkeys;
  const allowed = new Set(scope.passkeyIds);
  return passkeys.filter((p) => allowed.has(p.id));
}

/**
 * Request options for the identity's own passkeys (those in scope), with a
 * new random challenge; null when it has none. `userVerification` is
 * "preferred" for device sign-in approval, as Better Auth's passkey sign-in
 * (user presence always, verification when the authenticator can), and
 * "required" for a passkey confirmation.
 */
export async function assertionOptions(
  db: Querier,
  rp: RelyingParty,
  identityId: string,
  timeoutMs: number,
  options: { userVerification: UserVerification } & PasskeyScope,
): Promise<PublicKeyCredentialRequestOptionsJSON | null> {
  const passkeys = inScope(await passkeysOf(db, identityId), options);
  if (passkeys.length === 0) return null;
  return generateAuthenticationOptions({
    rpID: rp.rpId,
    timeout: timeoutMs,
    userVerification: options.userVerification,
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

/** A verified assertion: which passkey asserted, and whether the authenticator verified the user. */
export interface AssertionEvidence {
  passkeyId: string;
  userVerified: boolean;
}

export type AssertionRefusal = "unknown-passkey" | "invalid-assertion" | "user-verification-required";

/**
 * Verify an assertion made with one of the identity's own passkeys (one in
 * scope) over `expectedChallenge`, and advance that passkey's signature
 * counter. When `requireUserVerification` is set, an assertion without
 * user verification is refused. Run it inside the transaction that consumes
 * the challenge: the passkey row stays locked until that transaction ends.
 * Returns the reason on refusal; never throws for a bad assertion.
 */
export async function verifyAssertion(
  db: Querier,
  rp: RelyingParty,
  identityId: string,
  response: unknown,
  expectedChallenge: string,
  options: { requireUserVerification: boolean } & PasskeyScope,
): Promise<({ ok: true } & AssertionEvidence) | { ok: false; reason: AssertionRefusal }> {
  const credentialId = (response as { id?: unknown } | null)?.id;
  const passkey = typeof credentialId === "string"
    ? inScope(await passkeysOf(db, identityId), options).find((p) => p.credentialID === credentialId)
    : undefined;
  // A passkey of another identity, one out of scope, or none at all, never approves for this one.
  if (!passkey) return { ok: false, reason: "unknown-passkey" };
  // The signature counter is verified and advanced under the passkey row's
  // lock, held until the caller's transaction ends: two assertions of one
  // passkey verified at once would otherwise both pass against the same
  // stored counter, and the later write could lower it. Verified against
  // the counter as committed now, the second is refused like a replay.
  // Better Auth's sign-in, which does not lock, waits for this lock at its
  // update, where migration 40 refuses a counter that does not increase.
  const locked = (await db.query("SELECT counter FROM passkey WHERE id = $1 FOR UPDATE", [passkey.id])).rows[0] as
    | { counter: number }
    | undefined;
  // Removed meanwhile.
  if (!locked) return { ok: false, reason: "unknown-passkey" };
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: response as AuthenticationResponseJSON,
      expectedChallenge,
      expectedOrigin: rp.origin,
      expectedRPID: rp.rpId,
      credential: {
        id: passkey.credentialID,
        publicKey: new Uint8Array(Buffer.from(passkey.publicKey, "base64")),
        counter: locked.counter,
        ...transportsOf(passkey),
      },
      // Checked below, so a missing verification has its own reason.
      requireUserVerification: false,
    });
  } catch {
    return { ok: false, reason: "invalid-assertion" };
  }
  if (!verification.verified) return { ok: false, reason: "invalid-assertion" };
  const userVerified = verification.authenticationInfo.userVerified;
  if (options.requireUserVerification && !userVerified) return { ok: false, reason: "user-verification-required" };
  await db.query("UPDATE passkey SET counter = $2 WHERE id = $1", [passkey.id, verification.authenticationInfo.newCounter]);
  return { ok: true, passkeyId: passkey.id, userVerified };
}
