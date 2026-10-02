// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash, randomBytes, randomInt } from "node:crypto";
import type { PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/server";
import { recordAuditEvent } from "../audit/events.js";
import { assertionChallenge, assertionOptions, verifyAssertion, type RelyingParty } from "../auth/approval-assertion.js";
import { clientLabel } from "../auth/client-label.js";
import { issueCredential } from "../auth/credentials.js";
import { newId } from "../db/ids.js";
import type { Querier } from "../db/migrate.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";

/**
 * Device-authorization sign-in (ADR-0043 Decision 2, design notes
 * "Device-authorization sign-in"): RFC 8628 adapted to Varlatch's
 * credentials. A CLI requests a pending sign-in and keeps the device code
 * private; a human types the user code in the dashboard and approves with a
 * fresh passkey assertion; the CLI collects one `cli` credential for that
 * human. Every state change is one conditional update or happens under the
 * row's lock, so decisions and collection are single under concurrency.
 */

export const DEVICE_SIGN_IN = {
  /** Lifetime of a pending sign-in (RFC 8628 expires_in). */
  lifetimeSeconds: 600,
  /** Polling interval; SLOW_DOWN adds slowDownSeconds to it. */
  intervalSeconds: 5,
  slowDownSeconds: 5,
  /** Lifetime of an approval challenge. */
  challengeSeconds: 300,
  pendingPerPeer: 10,
  pendingTotal: 1000,
  /** Wrong user codes allowed per window, per approving identity, per peer, and in total. */
  attemptWindowSeconds: 600,
  wrongCodes: { identity: 5, peer: 20, global: 100 },
  /** The issued credential's lifetime, as ADR-0024's exchange. */
  defaultTtlSeconds: 43_200,
} as const;

/** RFC 8628 §6.1: no vowels, no look-alikes. 20^8 codes, about 34.6 bits. */
export const USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ";
const USER_CODE = /^[BCDFGHJKLMNPQRSTVWXZ]{8}$/;
const DEVICE_CODE = /^[A-Za-z0-9_-]{43}$/;
/** Serializes requests so the pending caps hold under concurrency. */
const REQUEST_LOCK = 7330035;

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function generateUserCode(): string {
  let code = "";
  for (let i = 0; i < 8; i++) code += USER_CODE_ALPHABET[randomInt(USER_CODE_ALPHABET.length)];
  return code;
}

/** A typed code compared case-insensitively, the dash (and spaces) optional; null when it cannot be a code. */
export function normalizeUserCode(input: string): string | null {
  const code = input.replace(/[\s-]/g, "").toUpperCase();
  return USER_CODE.test(code) ? code : null;
}

/** As shown to people: WDJB-MJHT. */
export function formatUserCode(code: string): string {
  return `${code.slice(0, 4)}-${code.slice(4)}`;
}

/**
 * Housekeeping, run with each new request: mark lapsed sign-ins expired
 * (which also frees their user codes) and delete rows a day after expiry.
 */
async function sweep(db: Querier): Promise<void> {
  await db.query("UPDATE device_sign_ins SET status = 'expired' WHERE status IN ('pending', 'approved') AND expires_at <= now()");
  await db.query("DELETE FROM device_sign_ins WHERE expires_at < now() - interval '1 day'");
  await db.query("DELETE FROM device_sign_in_challenges WHERE expires_at < now() - interval '1 day'");
  await db.query("DELETE FROM device_code_attempt_windows WHERE window_started_at < now() - interval '1 day'");
}

export interface DeviceSignInRequest {
  id: string;
  /** The bearer secret: returned once, to the requesting CLI only. */
  deviceCode: string;
  userCode: string;
  expiresIn: number;
  interval: number;
}

export async function requestDeviceSignIn(
  ctx: AppCtx,
  input: { ttlSeconds?: number | undefined; name?: string | undefined; peer: string; userAgent: string | null; requestId: string },
): Promise<DeviceSignInRequest> {
  const ttlSeconds = input.ttlSeconds ?? DEVICE_SIGN_IN.defaultTtlSeconds;
  return withTx(ctx.db, async (db) => {
    await db.query("SELECT pg_advisory_xact_lock($1)", [REQUEST_LOCK]);
    await sweep(db);
    const counts = (await db.query(
      `SELECT count(*) FILTER (WHERE requester_ip = $1)::int AS peer, count(*)::int AS total
       FROM device_sign_ins WHERE status = 'pending' AND expires_at > now()`,
      [input.peer],
    )).rows[0] as { peer: number; total: number };
    if (counts.peer >= DEVICE_SIGN_IN.pendingPerPeer) {
      throw new DomainError("RATE_LIMITED", `At most ${DEVICE_SIGN_IN.pendingPerPeer} sign-ins may be pending from one address; let one complete or expire`);
    }
    if (counts.total >= DEVICE_SIGN_IN.pendingTotal) {
      throw new DomainError("RATE_LIMITED", "Too many sign-ins are pending; try again in a few minutes");
    }
    const id = newId("deviceSignIn");
    const deviceCode = randomBytes(32).toString("base64url");
    // The user code is unique among pending sign-ins; a collision draws again.
    for (let attempt = 0; attempt < 8; attempt++) {
      const userCode = generateUserCode();
      const inserted = await db.query(
        `INSERT INTO device_sign_ins
           (id, device_code_hash, user_code, requested_ttl, requested_name, requester_ip, requester_user_agent,
            expires_at, poll_interval)
         VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8), $9)
         ON CONFLICT DO NOTHING RETURNING id`,
        [id, sha256(deviceCode), userCode, ttlSeconds, input.name ?? null, input.peer,
          input.userAgent ? input.userAgent.slice(0, 512) : null, DEVICE_SIGN_IN.lifetimeSeconds, DEVICE_SIGN_IN.intervalSeconds],
      );
      if (!inserted.rows[0]) continue;
      await recordAuditEvent(db, {
        eventType: "authentication.device_requested",
        decision: "info",
        requestId: input.requestId,
        resource: { deviceSignInId: id },
        metadata: { ttlSeconds },
      });
      return {
        id,
        deviceCode,
        userCode: formatUserCode(userCode),
        expiresIn: DEVICE_SIGN_IN.lifetimeSeconds,
        interval: DEVICE_SIGN_IN.intervalSeconds,
      };
    }
    throw new DomainError("INTERNAL", "Could not allocate a user code");
  });
}

export type PollOutcome =
  | { kind: "pending"; interval: number }
  | { kind: "slow_down"; interval: number }
  | { kind: "denied" }
  | { kind: "expired" }
  | { kind: "unknown" }
  | { kind: "consumed"; credentialId: string | null }
  | { kind: "issued"; id: string; token: string; expiresAt: string };

interface SignInRow {
  id: string;
  status: "pending" | "approved" | "denied" | "consumed" | "expired";
  lapsed: boolean;
  polled_too_soon: boolean;
  poll_interval: number;
  requested_ttl: number;
  requested_name: string | null;
  approved_by_identity_id: string | null;
  issued_credential_id: string | null;
}

/**
 * The CLI's poll (RFC 8628 §3.4/3.5). Collection marks the sign-in consumed
 * and mints the credential in one transaction under the row's lock: of two
 * concurrent collectors, the second sees `consumed` and gets the issued
 * credential's id, never a second credential.
 */
export async function pollDeviceSignIn(
  ctx: AppCtx,
  input: { deviceCode: string; userAgent: string | null; requestId: string },
): Promise<PollOutcome> {
  if (!DEVICE_CODE.test(input.deviceCode)) return { kind: "unknown" };
  return withTx(ctx.db, async (db) => {
    const row = (await db.query(
      `SELECT id, status, expires_at <= now() AS lapsed,
              (last_polled_at IS NOT NULL AND last_polled_at > now() - make_interval(secs => poll_interval)) AS polled_too_soon,
              poll_interval, requested_ttl, requested_name, approved_by_identity_id, issued_credential_id
       FROM device_sign_ins WHERE device_code_hash = $1 FOR UPDATE`,
      [sha256(input.deviceCode)],
    )).rows[0] as SignInRow | undefined;
    if (!row) return { kind: "unknown" };
    if (row.status === "consumed") return { kind: "consumed", credentialId: row.issued_credential_id };
    if (row.status === "denied") return { kind: "denied" };
    if (row.status === "expired") return { kind: "expired" };
    if (row.lapsed) {
      // Approved but not collected in time yields no credential.
      await db.query("UPDATE device_sign_ins SET status = 'expired' WHERE id = $1 AND status IN ('pending', 'approved')", [row.id]);
      return { kind: "expired" };
    }
    if (row.status === "pending") {
      if (row.polled_too_soon) {
        const slowed = (await db.query(
          "UPDATE device_sign_ins SET poll_interval = poll_interval + $2, last_polled_at = now() WHERE id = $1 RETURNING poll_interval",
          [row.id, DEVICE_SIGN_IN.slowDownSeconds],
        )).rows[0] as { poll_interval: number };
        return { kind: "slow_down", interval: slowed.poll_interval };
      }
      await db.query("UPDATE device_sign_ins SET last_polled_at = now() WHERE id = $1", [row.id]);
      return { kind: "pending", interval: row.poll_interval };
    }
    const claimed = (await db.query(
      `UPDATE device_sign_ins SET status = 'consumed', last_polled_at = now()
       WHERE id = $1 AND status = 'approved' AND expires_at > now()
       RETURNING approved_by_identity_id`,
      [row.id],
    )).rows[0] as { approved_by_identity_id: string } | undefined;
    if (!claimed) return { kind: "expired" };
    const identityId = claimed.approved_by_identity_id;
    const expiresAt = new Date(Date.now() + row.requested_ttl * 1000).toISOString();
    const issued = await issueCredential(db, {
      identityId,
      kind: "cli",
      name: row.requested_name ?? "device sign-in",
      expiresAt,
      actorIdentityId: identityId,
      metadata: { deviceSignInId: row.id, ttlSeconds: row.requested_ttl },
      // The collecting CLI's User-Agent, summarized: this request comes from the CLI.
      client: clientLabel(input.userAgent),
    });
    await db.query("UPDATE device_sign_ins SET issued_credential_id = $2 WHERE id = $1", [row.id, issued.credentialId]);
    await recordAuditEvent(db, {
      eventType: "authentication.device_collected",
      decision: "info",
      actorIdentityId: identityId,
      credentialId: issued.credentialId,
      requestId: input.requestId,
      resource: { deviceSignInId: row.id, identityId },
    });
    return { kind: "issued", id: issued.credentialId, token: issued.token, expiresAt };
  });
}

export interface PendingSignIn {
  id: string;
  userCode: string;
  requestedTtl: number;
  requestedName: string | null;
  requesterIp: string | null;
  requesterUserAgent: string | null;
  createdAt: string;
  expiresAt: string;
}

export type CodeOutcome =
  | { kind: "found"; signIn: PendingSignIn }
  | { kind: "wrong" }
  | { kind: "locked"; retryAt: string };

type AttemptScope = "identity" | "peer" | "global";

/**
 * Find the pending sign-in a human typed the code of, under the persistent
 * attempt limits: wrong codes count per approving identity (across all its
 * sessions), per peer, and in total, in the database. The three counter rows
 * are locked in one order for the check and the count, so concurrent
 * attempts from several sessions cannot exceed a limit. A locked scope
 * refuses even a correct code until its window ends.
 */
export async function findSignInByCode(
  ctx: AppCtx,
  input: { identityId: string; peer: string; userCode: string; requestId: string },
): Promise<CodeOutcome> {
  const keys: [AttemptScope, string][] = [["global", "all"], ["identity", input.identityId], ["peer", input.peer]];
  return withTx(ctx.db, async (db) => {
    await db.query(
      `INSERT INTO device_code_attempt_windows (scope, key, window_started_at, failures)
       VALUES ($1, $2, now(), 0), ($3, $4, now(), 0), ($5, $6, now(), 0) ON CONFLICT DO NOTHING`,
      keys.flat(),
    );
    const windows = (await db.query(
      `SELECT scope, failures, window_started_at > now() - make_interval(secs => $7) AS current,
              window_started_at + make_interval(secs => $7) AS ends_at
       FROM device_code_attempt_windows
       WHERE (scope, key) IN (($1, $2), ($3, $4), ($5, $6))
       ORDER BY scope, key FOR UPDATE`,
      [...keys.flat(), DEVICE_SIGN_IN.attemptWindowSeconds],
    )).rows as { scope: AttemptScope; failures: number; current: boolean; ends_at: Date | string }[];
    const locked = windows.filter((w) => w.current && w.failures >= DEVICE_SIGN_IN.wrongCodes[w.scope]);
    if (locked.length > 0) {
      const retryAt = new Date(Math.max(...locked.map((w) => new Date(w.ends_at).getTime()))).toISOString();
      return { kind: "locked", retryAt };
    }
    const code = normalizeUserCode(input.userCode);
    const row = code
      ? ((await db.query(
          `SELECT id, user_code, requested_ttl, requested_name, requester_ip, requester_user_agent, created_at, expires_at
           FROM device_sign_ins WHERE user_code = $1 AND status = 'pending' AND expires_at > now()`,
          [code],
        )).rows[0] as
          | { id: string; user_code: string; requested_ttl: number; requested_name: string | null; requester_ip: string | null;
              requester_user_agent: string | null; created_at: Date | string; expires_at: Date | string }
          | undefined)
      : undefined;
    if (row) {
      return {
        kind: "found",
        signIn: {
          id: row.id,
          userCode: formatUserCode(row.user_code),
          requestedTtl: row.requested_ttl,
          requestedName: row.requested_name,
          requesterIp: row.requester_ip,
          requesterUserAgent: row.requester_user_agent,
          createdAt: new Date(row.created_at).toISOString(),
          expiresAt: new Date(row.expires_at).toISOString(),
        },
      };
    }
    const counted = (await db.query(
      `UPDATE device_code_attempt_windows SET
         failures = CASE WHEN window_started_at > now() - make_interval(secs => $7) THEN failures + 1 ELSE 1 END,
         window_started_at = CASE WHEN window_started_at > now() - make_interval(secs => $7) THEN window_started_at ELSE now() END
       WHERE (scope, key) IN (($1, $2), ($3, $4), ($5, $6))
       RETURNING scope, failures, window_started_at + make_interval(secs => $7) AS ends_at`,
      [...keys.flat(), DEVICE_SIGN_IN.attemptWindowSeconds],
    )).rows as { scope: AttemptScope; failures: number; ends_at: Date | string }[];
    // Never the typed code: a near miss of a live code must not reach the audit log.
    await recordAuditEvent(db, {
      eventType: "authentication.device_code_rejected",
      decision: "deny",
      actorIdentityId: input.identityId,
      requestId: input.requestId,
    });
    for (const w of counted) {
      if (w.failures !== DEVICE_SIGN_IN.wrongCodes[w.scope]) continue;
      await recordAuditEvent(db, {
        eventType: "authentication.device_code_locked",
        decision: "deny",
        actorIdentityId: input.identityId,
        requestId: input.requestId,
        metadata: { scope: w.scope, until: new Date(w.ends_at).toISOString() },
      });
    }
    return { kind: "wrong" };
  });
}

/**
 * A fresh approval challenge for this sign-in, identity, and session, kept
 * server-side; null when the identity has no passkey. An earlier unused
 * challenge of the same three is replaced.
 */
export async function issueApprovalChallenge(
  ctx: AppCtx,
  rp: RelyingParty,
  input: { signInId: string; identityId: string; authSessionId: string },
): Promise<PublicKeyCredentialRequestOptionsJSON | null> {
  return withTx(ctx.db, async (db) => {
    const options = await assertionOptions(db, rp, input.identityId, DEVICE_SIGN_IN.challengeSeconds * 1000);
    if (!options) return null;
    await db.query(
      `DELETE FROM device_sign_in_challenges
       WHERE device_sign_in_id = $1 AND identity_id = $2 AND auth_session_id = $3 AND consumed_at IS NULL`,
      [input.signInId, input.identityId, input.authSessionId],
    );
    await db.query(
      `INSERT INTO device_sign_in_challenges (id, device_sign_in_id, identity_id, auth_session_id, challenge, expires_at)
       VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))`,
      [newId("deviceSignInChallenge"), input.signInId, input.identityId, input.authSessionId, options.challenge, DEVICE_SIGN_IN.challengeSeconds],
    );
    return options;
  });
}

function noLongerPending(): DomainError {
  return new DomainError("STATE_CHANGED", "This sign-in is no longer pending: it was decided or it expired");
}

export async function denyDeviceSignIn(
  ctx: AppCtx,
  input: { signInId: string; identityId: string; requestId: string },
): Promise<void> {
  await withTx(ctx.db, async (db) => {
    const denied = await db.query(
      `UPDATE device_sign_ins SET status = 'denied', decided_at = now()
       WHERE id = $1 AND status = 'pending' AND expires_at > now() RETURNING id`,
      [input.signInId],
    );
    if (!denied.rows[0]) throw noLongerPending();
    await db.query("DELETE FROM device_sign_in_challenges WHERE device_sign_in_id = $1", [input.signInId]);
    await recordAuditEvent(db, {
      eventType: "authentication.device_denied",
      decision: "info",
      actorIdentityId: input.identityId,
      requestId: input.requestId,
      resource: { deviceSignInId: input.signInId },
    });
  });
}

/**
 * Approve with a fresh passkey assertion. In one transaction, under the
 * sign-in's row lock: check it is still pending and unexpired, consume the
 * challenge (only one issued for this sign-in, identity, and session, unused
 * and unexpired), verify the assertion with one of the identity's passkeys,
 * and move the sign-in from pending to approved, again only while pending
 * and unexpired. A refused challenge or assertion stays consumed.
 */
export async function approveDeviceSignIn(
  ctx: AppCtx,
  rp: RelyingParty,
  input: { signInId: string; identityId: string; authSessionId: string; assertion: unknown; requestId: string },
): Promise<void> {
  const challenge = assertionChallenge(input.assertion);
  const refusal = await withTx(ctx.db, async (db) => {
    // Decided or expired meanwhile (a concurrent denial wins, say): say so,
    // and leave the challenge and the audit log alone. The row lock orders
    // this approval after any decision in flight.
    const current = (await db.query(
      "SELECT status = 'pending' AND expires_at > now() AS pending FROM device_sign_ins WHERE id = $1 FOR UPDATE",
      [input.signInId],
    )).rows[0] as { pending: boolean } | undefined;
    if (!current?.pending) throw noLongerPending();
    const consumed = challenge
      ? (await db.query(
          `UPDATE device_sign_in_challenges SET consumed_at = now()
           WHERE challenge = $1 AND device_sign_in_id = $2 AND identity_id = $3 AND auth_session_id = $4
             AND consumed_at IS NULL AND expires_at > now()
           RETURNING id`,
          [challenge, input.signInId, input.identityId, input.authSessionId],
        )).rows[0]
      : undefined;
    const verified = consumed && challenge
      ? await verifyAssertion(db, rp, input.identityId, input.assertion, challenge)
      : ({ ok: false, reason: "challenge" } as const);
    if (!verified.ok) {
      await recordAuditEvent(db, {
        eventType: "authentication.failed",
        decision: "deny",
        actorIdentityId: input.identityId,
        requestId: input.requestId,
        resource: { deviceSignInId: input.signInId },
        metadata: { method: "device-approval", reason: verified.reason },
      });
      return verified.reason;
    }
    const approved = await db.query(
      `UPDATE device_sign_ins SET status = 'approved', approved_by_identity_id = $2, decided_at = now()
       WHERE id = $1 AND status = 'pending' AND expires_at > now() RETURNING id`,
      [input.signInId, input.identityId],
    );
    if (!approved.rows[0]) throw noLongerPending();
    await recordAuditEvent(db, {
      eventType: "authentication.device_approved",
      decision: "info",
      actorIdentityId: input.identityId,
      authenticationMethodId: "passkey",
      requestId: input.requestId,
      resource: { deviceSignInId: input.signInId },
    });
    return null;
  });
  if (refusal) {
    throw new DomainError(
      "PERMISSION_DENIED",
      refusal === "challenge"
        ? "This passkey confirmation was not issued for this sign-in and session, or it was used or expired; enter the code again"
        : "The passkey confirmation could not be verified with one of your passkeys",
    );
  }
}
