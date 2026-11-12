// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Querier } from "../db/migrate.js";
import { DomainError } from "./errors.js";
import { credentialEvidence } from "./passkeys.js";
import type { EntryRequester, PendingAccessReport, ReportReason } from "./securityreport.js";

/**
 * `passkey-verification` (ADR-0054 Decision 7): an Organization access by
 * a person's credential (browser or cli; any other kind of a person's
 * credential counts as having no evidence) whose sign-in evidence (Decision
 * 6) lacks user verification, or comes from a passkey that is not trusted
 * now (Decision 4), is counted under `report` and refused under `enforce`.
 * Machine credentials are exempt by kind and read nothing here.
 *
 * This is decided for the requester only, once per request, where the
 * request enters its Organization (http/organization.ts) and, for the
 * Convex token, per Organization in it. It is not part of the authority
 * loaders (getOrgRole, loadGrants, captureAuthority), which also compute
 * other people's authority: a member's removal, the exposure report and
 * machine reach stay as they are.
 *
 * Where the refusal happens: not at entry. The entry runs before the
 * route's authorization, and an outsider must keep getting the answer
 * they got before (not-found where the route hides existence). So entry
 * only notes the block; an authorization decision that would have
 * allowed the request in that Organization becomes the refusal
 * (http/support.ts, decide). Every denial, existence hiding included,
 * answers first.
 */

/** Why a credential's evidence does not satisfy the control. */
export type VerificationGap = Extract<ReportReason, "no-evidence" | "not-user-verified" | "untrusted-passkey">;

/** An Organization that refuses this request under `enforce`, noted at entry. */
export interface EntryBlock {
  organizationId: string;
  reason: VerificationGap;
}

export interface PasskeyVerificationOutcome {
  /** Organizations in `report` mode: one pending count each, counted once the request succeeded. */
  reports: PendingAccessReport[];
  /** Organizations in `enforce` mode, with why the credential does not satisfy them. */
  blocked: Map<string, VerificationGap>;
}

const NONE: PasskeyVerificationOutcome = { reports: [], blocked: new Map() };

/**
 * Whether this requester is subject to the control: every credential of a
 * person, whatever its kind (fail closed: a kind added later is checked,
 * and one that carries no sign-in counts as no-evidence). Machine
 * identities are exempt by kind.
 */
export function subjectToPasskeyVerification(requester: Pick<EntryRequester, "identityKind">): boolean {
  return requester.identityKind === "human";
}

/** The credential kinds that can carry a passkey sign-in's evidence. */
const EVIDENCE_KINDS: ReadonlySet<string> = new Set(["browser", "cli"]);

/**
 * What a person's credential lacks, or null when its evidence is
 * user-verified and from a passkey trusted now. A kind that cannot carry a
 * sign-in's evidence has none.
 */
export async function verificationGap(db: Querier, credentialId: string, credentialKind?: string): Promise<VerificationGap | null> {
  if (credentialKind !== undefined && !EVIDENCE_KINDS.has(credentialKind)) return "no-evidence";
  const evidence = await credentialEvidence(db, credentialId);
  if (!evidence) return "no-evidence";
  if (!evidence.userVerified) return "not-user-verified";
  if (!evidence.passkeyTrusted) return "untrusted-passkey";
  return null;
}

/**
 * passkey-verification for one request entering these Organizations: per
 * Organization whose control is `report` or `enforce`, against the mode
 * and version read now in `db` (a retrieval's snapshot, when there is
 * one). Reads only, so it can run inside a read-only snapshot. Nothing is
 * read when every control is off, or for a machine credential.
 */
export async function passkeyVerification(
  db: Querier,
  requester: EntryRequester,
  organizationIds: readonly string[],
): Promise<PasskeyVerificationOutcome> {
  if (!subjectToPasskeyVerification(requester) || organizationIds.length === 0) return NONE;
  const active = (await db.query(
    `SELECT organization_id, mode, version, now() AS at FROM security_controls
     WHERE organization_id = ANY($1) AND control = 'passkey-verification' AND mode IN ('report', 'enforce')
     ORDER BY organization_id`,
    [[...organizationIds]],
  )).rows as { organization_id: string; mode: "report" | "enforce"; version: number; at: Date | string }[];
  if (active.length === 0) return NONE;
  const reason = await verificationGap(db, requester.credentialId, requester.credentialKind);
  if (!reason) return NONE;
  const outcome: PasskeyVerificationOutcome = { reports: [], blocked: new Map() };
  for (const r of active) {
    if (r.mode === "enforce") {
      outcome.blocked.set(r.organization_id, reason);
    } else {
      outcome.reports.push({
        organizationId: r.organization_id,
        actorIdentityId: requester.identityId,
        configVersion: r.version,
        reason,
        at: new Date(r.at),
      });
    }
  }
  return outcome;
}

const GAP_MESSAGES: Record<VerificationGap, string> = {
  "no-evidence": "your sign-in carries no passkey evidence (it may predate this check)",
  "not-user-verified": "the passkey you signed in with did not verify you with a PIN or biometric",
  "untrusted-passkey": "you signed in with a passkey that is not trusted (confirm it on your account's Security page first)",
};

/**
 * The refusal (PASSKEY_VERIFICATION_REQUIRED, HTTP 403). It names what the
 * person's own sign-in lacks and how to get a sign-in that satisfies the
 * control; nothing about the Organization's contents.
 */
export function passkeyVerificationRequired(reason: VerificationGap): DomainError {
  return new DomainError(
    "PASSKEY_VERIFICATION_REQUIRED",
    `This Organization requires a sign-in with a trusted passkey that verifies you with a PIN or biometric, and ${GAP_MESSAGES[reason]}. ` +
      "Sign in again with such a passkey: in the dashboard, sign out and sign in; for the CLI, run varlatch login and approve it with that passkey.",
    { control: "passkey-verification", reason },
  );
}

/**
 * Turning the control to `enforce` from a sign-in it would refuse is
 * refused too, with the same code: the change would lock its own author
 * out of the Organization at once, and the way back would be the host
 * operator's reset (Decision 10). Nothing is changed. It protects only the
 * person making the change; report mode shows who else it would refuse.
 */
export function enforceWouldRefuseYou(reason: VerificationGap): DomainError {
  return new DomainError(
    "PASSKEY_VERIFICATION_REQUIRED",
    `Enforcing passkey-verification would refuse your own sign-in: ${GAP_MESSAGES[reason]}. ` +
      "Sign in again with a trusted passkey that verifies you with a PIN or biometric, then turn it on. Nothing was changed.",
    { control: "passkey-verification", reason, change: "refused" },
  );
}
