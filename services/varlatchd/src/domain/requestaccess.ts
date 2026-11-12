// SPDX-License-Identifier: AGPL-3.0-or-later
import { AsyncLocalStorage } from "node:async_hooks";
import type { Querier } from "../db/migrate.js";
import { currentTxAttempt, type TxAttempt } from "../db/tx.js";
import { passkeyVerification, PasskeyVerificationRefusal, type PasskeyVerificationOutcome } from "./passkeyverification.js";
import type { EntryRequester, PendingAccessReport } from "./securityreport.js";

/**
 * Where passkey-verification is decided for a request (ADR-0054 Decisions
 * 2 and 7): the requester's security context, and the two stages of the
 * decision.
 *
 * The context. The /v1 bearer middleware runs the rest of an authenticated
 * request inside withRequester, with the requester's identifiers only: its
 * identity and credential, and their kinds, as authentication resolved
 * them. Never a verdict taken earlier, and never anything the client says
 * about itself (audit/attribution.ts keeps that, for the audit log only).
 * Work that does not serve the request (access counts, sync delivery,
 * webhooks) runs outsideRequest, so it never inherits the context;
 * requests without a principal (the OIDC exchange, device sign-in's CLI
 * calls) and host commands have none.
 *
 * 1. Capture. The outcome for an Organization is read together, from one
 *    querier: the control's mode and version and the credential's sign-in
 *    evidence, with the passkey's trust now (passkeyVerification).
 *    - A write captures it under the Organization lock: lockLiveScope and
 *      lockScope (liveness.ts) call captureOrganizationAccess right after
 *      the Organization row is locked and checked, as separate statements.
 *      A control change takes that row FOR UPDATE and bumps its
 *      security_epoch, so a writer either commits under the old mode
 *      before the change, or reads the new one; a SERIALIZABLE writer
 *      whose snapshot is older than the change fails to lock the row and
 *      runs again on a new snapshot.
 *    - A retrieval captures it inside its snapshot, at the first
 *      checkpoint there.
 *    - Anything else captures it at its checkpoint.
 *    The capture belongs to the transaction attempt (tx.ts TxAttempt): a
 *    serializable retry starts again with nothing captured, and a nested
 *    call in the same attempt reuses the first capture, never a newer or
 *    an older one.
 *
 * 2. The checkpoint (requireOrganizationAccess) applies the outcome: under
 *    `enforce` a blocked person's request is refused with
 *    PasskeyVerificationRefusal; under `report` the request's pending count
 *    is noted. It runs after the operation's authorized existence checks
 *    (a missing Project, revision, Grant or value keeps its not-found) and
 *    before its first business mutation, approval intent, disclosure audit,
 *    decryption or external effect. lockLiveScope runs it itself once its
 *    scope is locked and live, unless the writer defers it (accessCheck:
 *    "deferred") because it looks up more after the lock; such a writer
 *    calls requireOrganizationAccess itself.
 *
 * At the request's end (http/app.ts) an Organization the request entered
 * without a checkpoint is checked before the response leaves: this is how
 * an effect-free metadata read is decided, and for anything else it is a
 * coverage failure, which the tests report (takeAccessCoverageNotes).
 *
 * Machine credentials are exempt by kind: their capture reads nothing and
 * their checkpoint always passes, but both are still noted, so the test
 * harness checks that machines' writes, too, pass a checkpoint.
 */

/** The requester's identifiers, as authentication resolved them. */
export type Requester = Readonly<EntryRequester>;

/** One Organization's decision in this request, by its last checkpoint. */
interface Decided {
  /** Report mode: the count this request makes when it succeeds. */
  pending: PendingAccessReport | null;
}

interface RequestAccess {
  readonly requester: Requester;
  /** Organizations this request entered (http/organization.ts resolveOrganization). */
  readonly entered: Set<string>;
  /** Organizations whose checkpoint passed in this request, with what it noted. */
  readonly decided: Map<string, Decided>;
}

/** What one transaction attempt captured and checked, per Organization. */
interface AttemptAccess {
  captured: Map<string, PasskeyVerificationOutcome>;
  checked: Set<string>;
}

const storage = new AsyncLocalStorage<RequestAccess>();
const ATTEMPT = Symbol("passkey-verification");

/** Run `fn`, and everything it awaits, as this requester's request. */
export function withRequester<T>(requester: EntryRequester, fn: () => T): T {
  return storage.run(
    { requester: Object.freeze({ ...requester }), entered: new Set(), decided: new Map() },
    fn,
  );
}

/** Run `fn` outside any request's security context: work that does not serve the request. */
export function outsideRequest<T>(fn: () => T): T {
  return storage.exit(fn);
}

/** The requester of the request being served, if any. */
export function currentRequester(): Requester | undefined {
  return storage.getStore()?.requester;
}

function attemptAccess(attempt: TxAttempt): AttemptAccess {
  let access = attempt.notes.get(ATTEMPT) as AttemptAccess | undefined;
  if (!access) {
    access = { captured: new Map(), checked: new Set() };
    attempt.notes.set(ATTEMPT, access);
  }
  return access;
}

/** Notes that the request entered this Organization (resolveOrganization). */
export function noteOrganizationEntered(organizationId: string): void {
  storage.getStore()?.entered.add(organizationId);
}

/**
 * Stage 1: capture this request's outcome for the Organization in the
 * current transaction attempt, reading through `db` (the transaction's or
 * the snapshot's querier). Once per attempt and Organization: a later call
 * reuses the first. Outside a request, or outside a transaction, nothing.
 */
export async function captureOrganizationAccess(db: Querier, organizationId: string): Promise<void> {
  const request = storage.getStore();
  const attempt = currentTxAttempt();
  if (!request || !attempt) return;
  const access = attemptAccess(attempt);
  if (access.captured.has(organizationId)) return;
  access.captured.set(organizationId, await passkeyVerification(db, request.requester, [organizationId]));
}

/**
 * Stage 2, the checkpoint: refuse a blocked person's request with
 * PasskeyVerificationRefusal, or note its report-mode count. Call it after
 * the operation's authorized existence checks and before its first
 * protected effect.
 *
 * - In a transaction or snapshot attempt: the attempt's capture, captured
 *   now through `db` if this is the first look in the attempt.
 * - Outside one: the decision this request already took for the
 *   Organization (a write that committed, or a snapshot that ended), never
 *   read again; otherwise read now through `db`.
 *
 * Outside a request (background work, host commands): nothing.
 */
export async function requireOrganizationAccess(db: Querier, organizationId: string): Promise<void> {
  const request = storage.getStore();
  if (!request) return;
  const attempt = currentTxAttempt();
  let outcome: PasskeyVerificationOutcome;
  if (attempt) {
    await captureOrganizationAccess(db, organizationId);
    outcome = attemptAccess(attempt).captured.get(organizationId)!;
  } else if (request.decided.has(organizationId)) {
    return;
  } else {
    outcome = await passkeyVerification(db, request.requester, [organizationId]);
  }
  const reason = outcome.blocked.get(organizationId);
  if (reason) throw new PasskeyVerificationRefusal(organizationId, reason);
  if (attempt) attemptAccess(attempt).checked.add(organizationId);
  // The last checkpoint decides: a write's, under its lock, replaces an
  // earlier read's; a serializable retry's replaces the failed attempt's.
  request.decided.set(organizationId, { pending: outcome.reports.find((r) => r.organizationId === organizationId) ?? null });
}

/**
 * Before a protected effect that its operation's checkpoint must precede
 * (a disclosure audit, a decryption, an outbound call): a request that
 * reaches it with no checkpoint for the Organization is a coverage gap.
 * It is noted for the tests and, failing closed, checked now.
 */
export async function assertOrganizationAccessChecked(db: Querier, organizationId: string, effect: string): Promise<void> {
  const request = storage.getStore();
  if (!request || request.decided.has(organizationId)) return;
  noteCoverageGap(`${effect} in ${organizationId} before its passkey-verification checkpoint`);
  await requireOrganizationAccess(db, organizationId);
}

/** Organizations the request entered whose checkpoint never ran: decided at the request's end. */
export function uncheckedOrganizations(): string[] {
  const request = storage.getStore();
  if (!request) return [];
  return [...request.entered].filter((id) => !request.decided.has(id));
}

/** Report-mode counts this request makes, one per Organization, if it succeeded. */
export function pendingAccessReports(): PendingAccessReport[] {
  const request = storage.getStore();
  if (!request) return [];
  return [...request.decided.values()].flatMap((d) => (d.pending ? [d.pending] : []));
}

/**
 * The current attempt's marks, for the lock-order test harness
 * (test/helpers/lock-trace.ts): whether the transaction serves a request,
 * which Organizations the request entered and decided, and which this
 * attempt captured and checked so far. Read only; never an input.
 */
export function accessMarks(): { request: boolean; entered: string[]; decided: string[]; captured: string[]; checked: string[] } {
  const request = storage.getStore();
  const attempt = currentTxAttempt();
  const access = attempt ? (attempt.notes.get(ATTEMPT) as AttemptAccess | undefined) : undefined;
  return {
    request: request !== undefined,
    entered: request ? [...request.entered] : [],
    decided: request ? [...request.decided.keys()] : [],
    captured: access ? [...access.captured.keys()] : [],
    checked: access ? [...access.checked] : [],
  };
}

// Coverage gaps, for the tests: a protected effect before its checkpoint,
// or a route other than an effect-free read left to the request's end.
const gaps: string[] = [];

export function noteCoverageGap(gap: string): void {
  gaps.push(gap);
}

/** Coverage gaps noted since the last call (tests). */
export function takeAccessCoverageNotes(): string[] {
  return gaps.splice(0);
}
