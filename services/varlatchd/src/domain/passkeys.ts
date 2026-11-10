// SPDX-License-Identifier: AGPL-3.0-or-later
import type { PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/server";
import { recordAuditEvent } from "../audit/events.js";
import { assertionChallenge, assertionOptions, verifyAssertion, type RelyingParty } from "../auth/approval-assertion.js";
import { newId } from "../db/ids.js";
import type { Querier } from "../db/migrate.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";

/**
 * A person's passkeys as approval keys (ADR-0054 Decision 4) and the
 * evidence a sign-in leaves (Decision 6). Recorded whatever the Security
 * Controls say: nothing here refuses a sign-in, a device sign-in, or adding,
 * using or removing a passkey.
 *
 * - Provenance: a passkey is `trusted` when it existed at the upgrade, came
 *   from a setup grant (bootstrap, invitation, `admin recover`, `admin
 *   reenroll`), or was confirmed; one added by a signed-in session is
 *   `unconfirmed` until the person confirms it with a trusted passkey, with
 *   user verification, in a ceremony bound to it. A passkey without a
 *   provenance row counts as unconfirmed.
 * - Evidence: whether the authenticator verified the user, and which
 *   passkey asserted. Better Auth sessions carry it (auth_session_evidence),
 *   browser and browser-handoff CLI credentials through their session,
 *   device sign-in CLI credentials on the credential itself.
 *
 * Time is PostgreSQL's live clock, clock_timestamp(), read after the locks
 * are held, as in device sign-in.
 */

export const PASSKEY_CONFIRMATION = {
  /** Lifetime of a confirmation challenge. */
  challengeSeconds: 300,
  /** At most this many confirmation challenges per person per window. */
  challengesPerWindow: 10,
  windowSeconds: 600,
} as const;

/** How long evidence of an ended session is kept: past the longest credential that can link it (24 hours). */
const ENDED_SESSION_EVIDENCE_DAYS = 2;

export type PasskeyTrust = "trusted" | "unconfirmed";
export type TrustedVia = "existing-at-upgrade" | "setup-grant" | "confirmed";
export type SetupGrantKind = "bootstrap" | "recover" | "invite" | "reenroll";

export interface OwnPasskey {
  id: string;
  name: string | null;
  deviceType: string;
  backedUp: boolean;
  createdAt: string | null;
  trust: PasskeyTrust;
  trustedVia: TrustedVia | null;
  trustedAt: string | null;
  /** setup-grant: which kind of grant enrolled it. */
  setupGrantKind: SetupGrantKind | null;
  /** confirmed: the trusted passkey that confirmed it (it may have been removed since). */
  confirmedByPasskeyId: string | null;
}

interface PasskeyRow {
  id: string;
  name: string | null;
  deviceType: string;
  backedUp: boolean;
  createdAt: Date | string | null;
  trust: PasskeyTrust | null;
  trusted_via: TrustedVia | null;
  trusted_at: Date | string | null;
  setup_grant_kind: SetupGrantKind | null;
  confirmed_by_passkey_id: string | null;
}

const iso = (v: Date | string | null): string | null => (v === null ? null : new Date(v).toISOString());

function toOwnPasskey(r: PasskeyRow): OwnPasskey {
  return {
    id: r.id,
    name: r.name,
    deviceType: r.deviceType,
    backedUp: r.backedUp,
    createdAt: iso(r.createdAt),
    trust: r.trust ?? "unconfirmed",
    trustedVia: r.trusted_via,
    trustedAt: iso(r.trusted_at),
    setupGrantKind: r.setup_grant_kind,
    confirmedByPasskeyId: r.confirmed_by_passkey_id,
  };
}

const OWN_PASSKEYS = `
  SELECT p.id, p.name, p."deviceType", p."backedUp", p."createdAt",
         pp.trust, pp.trusted_via, pp.trusted_at, pp.setup_grant_kind, pp.confirmed_by_passkey_id
  FROM passkey p
  JOIN auth_user_links l ON l.better_auth_user_id = p."userId"
  LEFT JOIN passkey_provenance pp ON pp.passkey_id = p.id
  WHERE l.identity_id = $1`;

/** The identity's passkeys with their provenance, oldest first. */
export async function listOwnPasskeys(db: Querier, identityId: string): Promise<OwnPasskey[]> {
  const res = await db.query(`${OWN_PASSKEYS} ORDER BY p."createdAt" NULLS FIRST, p.id`, [identityId]);
  return (res.rows as PasskeyRow[]).map(toOwnPasskey);
}

async function ownPasskey(db: Querier, identityId: string, passkeyId: string, lock = false): Promise<OwnPasskey | null> {
  const res = await db.query(`${OWN_PASSKEYS} AND p.id = $2${lock ? " FOR UPDATE OF p" : ""}`, [identityId, passkeyId]);
  const row = res.rows[0] as PasskeyRow | undefined;
  return row ? toOwnPasskey(row) : null;
}

/**
 * Record a new passkey's provenance, once: trusted when a setup grant
 * enrolled it, unconfirmed when a signed-in session added it. An existing
 * row is never changed here (only confirmation moves a key to trusted).
 */
export async function recordPasskeyProvenance(
  db: Querier,
  passkeyId: string,
  origin: { setupGrantKind: SetupGrantKind } | { addedBySession: true },
): Promise<void> {
  if ("setupGrantKind" in origin) {
    await db.query(
      `INSERT INTO passkey_provenance (passkey_id, trust, trusted_via, trusted_at, setup_grant_kind)
       VALUES ($1, 'trusted', 'setup-grant', clock_timestamp(), $2) ON CONFLICT (passkey_id) DO NOTHING`,
      [passkeyId, origin.setupGrantKind],
    );
  } else {
    await db.query(
      "INSERT INTO passkey_provenance (passkey_id, trust) VALUES ($1, 'unconfirmed') ON CONFLICT (passkey_id) DO NOTHING",
      [passkeyId],
    );
  }
}

export interface Evidence {
  userVerified: boolean;
  passkeyId: string;
}

/**
 * Write the evidence of the ceremony that created this session, onto this
 * session only. The passkey is the one with this credential id of the
 * session's own Better Auth user; with none, or more than one (two rows can
 * share a credential id only from before such registrations were refused),
 * nothing is recorded and the session counts as unverified. Also sweeps the
 * evidence of sessions that ended long enough ago.
 */
export async function recordSessionEvidence(
  db: Querier,
  input: { sessionId: string; betterAuthUserId: string; credentialId: string; userVerified: boolean; ceremony: "sign-in" | "enrollment" },
): Promise<boolean> {
  const passkeys = (await db.query(
    `SELECT id FROM passkey WHERE "credentialID" = $1 AND "userId" = $2 LIMIT 2`,
    [input.credentialId, input.betterAuthUserId],
  )).rows as { id: string }[];
  if (passkeys.length !== 1) return false;
  await db.query(
    `INSERT INTO auth_session_evidence (session_id, ceremony, user_verified, passkey_id)
     VALUES ($1, $2, $3, $4) ON CONFLICT (session_id) DO NOTHING`,
    [input.sessionId, input.ceremony, input.userVerified, passkeys[0]!.id],
  );
  await db.query(
    `DELETE FROM auth_session_evidence e
     WHERE e.recorded_at < clock_timestamp() - make_interval(days => $1)
       AND NOT EXISTS (SELECT 1 FROM "session" s WHERE s.id = e.session_id)`,
    [ENDED_SESSION_EVIDENCE_DAYS],
  );
  return true;
}

/** Evidence as it counts when used: with the asserting passkey's provenance now, not at sign-in. */
export interface CredentialEvidence extends Evidence {
  /** Where the evidence lives: the credential's Better Auth session, or the credential itself (device sign-in). */
  source: "session" | "credential";
  /** The asserting passkey is still the person's and trusted. */
  passkeyTrusted: boolean;
}

/**
 * The sign-in evidence a credential carries, or null when it has none
 * (machine credentials, and anything issued before evidence was recorded:
 * unverified). Step 3 of ADR-0054's build reads it for
 * `passkey-verification`; nothing uses it to refuse anything yet.
 */
export async function credentialEvidence(db: Querier, credentialId: string): Promise<CredentialEvidence | null> {
  const row = (await db.query(
    `SELECT c.identity_id, c.evidence_user_verified, c.evidence_passkey_id,
            e.user_verified AS session_user_verified, e.passkey_id AS session_passkey_id
     FROM credentials c LEFT JOIN auth_session_evidence e ON e.session_id = c.auth_session_id
     WHERE c.id = $1`,
    [credentialId],
  )).rows[0] as
    | { identity_id: string; evidence_user_verified: boolean | null; evidence_passkey_id: string | null;
        session_user_verified: boolean | null; session_passkey_id: string | null }
    | undefined;
  if (!row) return null;
  const evidence: (Evidence & { source: CredentialEvidence["source"] }) | null =
    row.evidence_passkey_id !== null && row.evidence_user_verified !== null
      ? { userVerified: row.evidence_user_verified, passkeyId: row.evidence_passkey_id, source: "credential" }
      : row.session_passkey_id !== null && row.session_user_verified !== null
        ? { userVerified: row.session_user_verified, passkeyId: row.session_passkey_id, source: "session" }
        : null;
  if (!evidence) return null;
  const passkey = await ownPasskey(db, row.identity_id, evidence.passkeyId);
  return { ...evidence, passkeyTrusted: passkey?.trust === "trusted" };
}

/**
 * A fresh confirmation challenge for one of the person's unconfirmed
 * passkeys: the options list only their trusted passkeys and require user
 * verification. Bound to the person, their dashboard session and the
 * passkey being confirmed; an earlier unused challenge of the same three is
 * superseded. At most PASSKEY_CONFIRMATION.challengesPerWindow per person
 * per window, whatever the session.
 */
export async function issueConfirmationChallenge(
  ctx: AppCtx,
  rp: RelyingParty,
  input: { identityId: string; authSessionId: string; passkeyId: string },
): Promise<PublicKeyCredentialRequestOptionsJSON> {
  return withTx(ctx.db, async (db) => {
    // Serializes this person's confirmations and removals.
    await db.query("SELECT id FROM identities WHERE id = $1 FOR UPDATE", [input.identityId]);
    const target = await ownPasskey(db, input.identityId, input.passkeyId);
    if (!target) throw new DomainError("RESOURCE_NOT_FOUND", "Passkey not found");
    if (target.trust === "trusted") throw new DomainError("STATE_CHANGED", "This passkey is already trusted");
    const window = (await db.query(
      `SELECT count(*)::int AS issued, min(created_at) + make_interval(secs => $2) AS retry_at
       FROM passkey_confirmation_challenges
       WHERE identity_id = $1 AND created_at > clock_timestamp() - make_interval(secs => $2)`,
      [input.identityId, PASSKEY_CONFIRMATION.windowSeconds],
    )).rows[0] as { issued: number; retry_at: Date | string | null };
    if (window.issued >= PASSKEY_CONFIRMATION.challengesPerWindow) {
      const retryAt = new Date(window.retry_at ?? Date.now()).toISOString();
      throw new DomainError("RATE_LIMITED", `Too many passkey confirmations started; try again after ${retryAt}`, { retryAt });
    }
    const trusted = (await listOwnPasskeys(db, input.identityId)).filter((p) => p.trust === "trusted").map((p) => p.id);
    const options = await assertionOptions(db, rp, input.identityId, PASSKEY_CONFIRMATION.challengeSeconds * 1000, {
      userVerification: "required",
      passkeyIds: trusted,
    });
    if (!options) {
      throw new DomainError(
        "PERMISSION_DENIED",
        "You have no trusted passkey to confirm it with. Whoever runs this Varlatch server can send you a link that enrolls a trusted one (varlatch admin reenroll)",
        { reason: "no-trusted-passkey" },
      );
    }
    await db.query(
      `UPDATE passkey_confirmation_challenges SET consumed_at = clock_timestamp()
       WHERE identity_id = $1 AND auth_session_id = $2 AND target_passkey_id = $3 AND consumed_at IS NULL`,
      [input.identityId, input.authSessionId, input.passkeyId],
    );
    await db.query(
      `INSERT INTO passkey_confirmation_challenges (id, identity_id, auth_session_id, target_passkey_id, challenge, created_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, clock_timestamp(), clock_timestamp() + make_interval(secs => $6))`,
      [newId("passkeyConfirmationChallenge"), input.identityId, input.authSessionId, input.passkeyId, options.challenge,
        PASSKEY_CONFIRMATION.challengeSeconds],
    );
    return options;
  });
}

/**
 * Confirm an unconfirmed passkey. In one transaction, under the person's
 * row lock: consume the challenge (issued for this person, session and
 * passkey; unused; unexpired on the live clock), verify the assertion with
 * one of the person's trusted passkeys other than the one being confirmed,
 * user verification required, and mark the passkey trusted (confirmed, by
 * which key, when) with `authentication.passkey_confirmed`. A refused
 * challenge or assertion stays consumed and is audited as
 * `authentication.failed`.
 */
export async function confirmPasskey(
  ctx: AppCtx,
  rp: RelyingParty,
  input: { identityId: string; authSessionId: string; passkeyId: string; assertion: unknown; requestId: string },
): Promise<OwnPasskey> {
  const challenge = assertionChallenge(input.assertion);
  const outcome = await withTx(ctx.db, async (db) => {
    await db.query("SELECT id FROM identities WHERE id = $1 FOR UPDATE", [input.identityId]);
    const bound = challenge
      ? ((await db.query(
          `SELECT id FROM passkey_confirmation_challenges
           WHERE challenge = $1 AND identity_id = $2 AND auth_session_id = $3 AND target_passkey_id = $4
           FOR UPDATE`,
          [challenge, input.identityId, input.authSessionId, input.passkeyId],
        )).rows[0] as { id: string } | undefined)
      : undefined;
    const consumed = bound
      ? (await db.query(
          `UPDATE passkey_confirmation_challenges SET consumed_at = clock_timestamp()
           WHERE id = $1 AND consumed_at IS NULL AND expires_at > clock_timestamp() RETURNING id`,
          [bound.id],
        )).rows[0]
      : undefined;
    const target = await ownPasskey(db, input.identityId, input.passkeyId);
    if (!target) throw new DomainError("RESOURCE_NOT_FOUND", "Passkey not found");
    if (consumed && target.trust === "trusted") return { kind: "already-trusted" as const };
    const trusted = (await listOwnPasskeys(db, input.identityId))
      .filter((p) => p.trust === "trusted" && p.id !== input.passkeyId)
      .map((p) => p.id);
    const verified = consumed && challenge
      ? await verifyAssertion(db, rp, input.identityId, input.assertion, challenge, { requireUserVerification: true, passkeyIds: trusted })
      : ({ ok: false, reason: "challenge" } as const);
    if (!verified.ok) {
      await recordAuditEvent(db, {
        eventType: "authentication.failed",
        decision: "deny",
        actorIdentityId: input.identityId,
        requestId: input.requestId,
        resource: { passkeyId: input.passkeyId },
        metadata: { method: "passkey-confirmation", reason: verified.reason },
      });
      return { kind: "refused" as const, reason: verified.reason };
    }
    await db.query(
      `INSERT INTO passkey_provenance (passkey_id, trust, trusted_via, trusted_at, confirmed_by_passkey_id)
       VALUES ($1, 'trusted', 'confirmed', clock_timestamp(), $2)
       ON CONFLICT (passkey_id) DO UPDATE SET trust = 'trusted', trusted_via = 'confirmed',
         trusted_at = clock_timestamp(), confirmed_by_passkey_id = $2, setup_grant_kind = NULL
       WHERE passkey_provenance.trust = 'unconfirmed'`,
      [input.passkeyId, verified.passkeyId],
    );
    await recordAuditEvent(db, {
      eventType: "authentication.passkey_confirmed",
      decision: "info",
      actorIdentityId: input.identityId,
      authenticationMethodId: "passkey",
      requestId: input.requestId,
      resource: { passkeyId: input.passkeyId },
      metadata: { confirmedByPasskeyId: verified.passkeyId, userVerified: verified.userVerified },
    });
    return { kind: "confirmed" as const, passkey: (await ownPasskey(db, input.identityId, input.passkeyId))! };
  });
  if (outcome.kind === "confirmed") return outcome.passkey;
  if (outcome.kind === "already-trusted") throw new DomainError("STATE_CHANGED", "This passkey is already trusted");
  throw new DomainError(
    "PERMISSION_DENIED",
    outcome.reason === "challenge"
      ? "This confirmation was not started for this passkey and session, or it was used or expired; start it again"
      : outcome.reason === "user-verification-required"
        ? "The passkey did not verify you with a PIN, fingerprint or face; confirm with a passkey that does"
        : "The confirmation could not be verified with one of your trusted passkeys",
    { reason: outcome.reason },
  );
}

/**
 * Whether removing this passkey needs a step-up approval. ADR-0054
 * Decision 4: removing a trusted passkey will need one when the person holds
 * a live membership in an Organization with any Security Control at
 * `enforce`. Security Controls do not exist yet, so nothing is restricted.
 * The rule belongs here, in one place, run inside the removal's transaction
 * after the person's row is locked.
 */
export async function passkeyRemovalRestriction(
  _db: Querier,
  _input: { identityId: string; passkey: OwnPasskey },
): Promise<{ restricted: false }> {
  return { restricted: false };
}

/**
 * Remove one of the caller's own passkeys, as Better Auth's
 * `/passkey/delete-passkey` did (which is now disabled): another person's,
 * or an unknown id, is not found. Locks the person's row first, so the
 * removal and any later rule it reads (passkeyRemovalRestriction) are
 * serialized with confirmations and with each other.
 */
export async function removeOwnPasskey(ctx: AppCtx, input: { identityId: string; passkeyId: string }): Promise<void> {
  await withTx(ctx.db, async (db) => {
    await db.query("SELECT id FROM identities WHERE id = $1 FOR UPDATE", [input.identityId]);
    const passkey = await ownPasskey(db, input.identityId, input.passkeyId, true);
    if (!passkey) throw new DomainError("RESOURCE_NOT_FOUND", "Passkey not found");
    const restriction = await passkeyRemovalRestriction(db, { identityId: input.identityId, passkey });
    if (restriction.restricted) throw new DomainError("PERMISSION_DENIED", "Removing this passkey needs an approval");
    await db.query("DELETE FROM passkey WHERE id = $1", [input.passkeyId]);
  });
}
