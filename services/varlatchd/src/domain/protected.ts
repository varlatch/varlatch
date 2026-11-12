// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Querier } from "../db/migrate.js";
import { DomainError } from "./errors.js";
import { ApprovalNeeded, type ApprovalBinding, type ProtectedGate, type UsedApproval } from "./approvals.js";
import { lockLiveScope, type LiveScope } from "./liveness.js";
import { lockPeople } from "./personlocks.js";
import { countWouldBlock, lifetimeReason, type ProtectedCheck, type ReportReason, type WouldBlock } from "./securityreport.js";
import type { ControlMode, LifetimeConfig, SecurityControlName } from "./securitycontrols.js";

/**
 * Enforcement of the Security Controls (ADR-0054 step 4), shared by every
 * protected operation: what withApproval (approvals.ts) gives an operation
 * that a control may restrict, inside the operation's own transaction.
 *
 * prepareProtectedOperation, in amendment E's lock order (liveness.ts):
 *
 *   1. the Organization row in the scope's mode, with the deletion and
 *      incident-freeze checks (lockLiveScope's step 1): a refusal there
 *      comes before any approval, so nobody approves an operation that
 *      cannot run (ADR-0055 Decision 4);
 *   then the applicable controls, read under that lock: a control change
 *      takes the row FOR UPDATE, so the operation either commits before it
 *      or sees the new mode (Decision 2);
 *   then credential-lifetime, for an operation that issues a machine
 *      credential: at `enforce`, a TTL above the maximum is refused
 *      (CREDENTIAL_LIFETIME_EXCEEDED) and a request without one gets the
 *      default, which the operation uses as its effective TTL. The refusal
 *      does not depend on an approval, so it comes before any is asked for
 *      (amendment A); when an approval is asked for, it binds the effective
 *      TTL (the binding catalogue's `effectiveTtlSeconds`);
 *   then, only when a control at `enforce` asks for an approval, the exact
 *      binding (the operation's callback): its validation and every other
 *      refusal that does not depend on the approval come first (amendment
 *      A, "Refusals come first"), and a request that changes nothing needs
 *      no approval (the callback returns null). Without an approval the
 *      request throws ApprovalNeeded, which escapes the whole mutation
 *      (withApproval then stores the intent in a transaction of its own);
 *      a machine credential is refused at once, since it can never pass
 *      one;
 *   2. the people: the scope's, and the requester FOR UPDATE when it
 *      consumes, each in its mode, in id order, in one step;
 *   4, 6, 7. consumption (consumeApproval): the intent, the dashboard
 *      session, the credential; then the operation's authorization
 *      rechecked in this transaction;
 *   8, 9. the scope's Project and environments.
 *
 * The operation then takes its domain rows (step 10), checks that the
 * state it bound is still the state it changes (a difference rolls back
 * the transaction, consumption included), writes, counts the report
 * entries this returns (`count`, step 11, before its indexes and audit),
 * and records its audit event last.
 *
 * With every control off, it takes exactly the locks lockLiveScope took
 * before, reads one row set more, and changes nothing else.
 *
 * External effects: none here. An operation that calls anything outside
 * Varlatch does so only after this returned (amendment D).
 */

/** The controls whose `enforce` asks for an approval. */
const APPROVAL_CONTROLS: ReadonlySet<SecurityControlName> = new Set(["requirement-protection", "admin-step-up"]);

interface ControlRow {
  control: SecurityControlName;
  mode: ControlMode;
  version: number;
  config: LifetimeConfig | null;
}

async function applicableControls(db: Querier, organizationId: string): Promise<Map<SecurityControlName, ControlRow>> {
  const rows = (await db.query(
    "SELECT control, mode, version, config FROM security_controls WHERE organization_id = $1 AND mode <> 'off'",
    [organizationId],
  )).rows as (Omit<ControlRow, "config"> & { config: LifetimeConfig | string | null })[];
  return new Map(rows.map((r) => {
    const config = typeof r.config === "string" ? (JSON.parse(r.config) as LifetimeConfig) : r.config;
    return [r.control, {
      control: r.control,
      mode: r.mode,
      version: r.version,
      config: config ? { defaultTtlSeconds: Number(config.defaultTtlSeconds), maxTtlSeconds: Number(config.maxTtlSeconds) } : null,
    }];
  }));
}

export interface ProtectedOperationInput {
  /**
   * The operation's scope, as lockLiveScope takes it: the Organization
   * (step 1), every person it locks or references (step 2), its Project
   * and environments (steps 8 and 9).
   */
  scope: LiveScope;
  /** The controls that may act on this operation, and the operation each one counts it as. */
  checks: readonly ProtectedCheck[];
  /**
   * The exact binding of this request (amendment A and the binding
   * catalogue), asked for only when a control at `enforce` needs an
   * approval: after the Organization lock and the controls, before the
   * people. It runs the operation's refusals that do not depend on the
   * approval first, and reads without locking; a target state it binds
   * (a version it reads, a PATCH's resulting state) the operation checks
   * again under its row lock. Null when the request changes nothing,
   * which needs no approval.
   */
  binding: (db: Querier, decided: { effectiveTtlSeconds: number | undefined }) => Promise<ApprovalBinding | null>;
  /**
   * Rechecks the requester's authorization for the operation in this
   * transaction, after an approval was consumed ("the person still holds
   * the action", Decision 3).
   */
  authorizeIn?: ((db: Querier) => Promise<void>) | undefined;
}

export interface PreparedOperation {
  /** The approval consumed for this request; null when none was needed. */
  approval: UsedApproval | null;
  /** What the approval was bound to; null when none was needed. */
  binding: ApprovalBinding | null;
  /** What the controls in `report` would have done, counted only by `count`. */
  reports: WouldBlock[];
  /**
   * The issuance TTL credential-lifetime makes of the requested one (for
   * the credential-lifetime check; undefined when there is none, or none
   * was requested and none applies). Report mode changes nothing, so this
   * is the requested TTL unless the control is at `enforce`, where a
   * request without one gets the default.
   */
  effectiveTtlSeconds: number | undefined;
  /** Whether effectiveTtlSeconds is credential-lifetime's default, for a request that gave none. */
  ttlDefaulted: boolean;
  /**
   * Count the report entries in this transaction: call it once the
   * operation changed something, after its domain rows and before its
   * indexes and first audit insert (step 11). A refused, failed or
   * unchanged request is not counted.
   */
  count(db: Querier): Promise<void>;
}

/** An approval-requiring operation by a machine credential under `enforce`: refused, without an intent. */
export function machineCannotApprove(operation: string): DomainError {
  return new DomainError(
    "PERMISSION_DENIED",
    `${operation} needs a person's approval with a passkey under this organization's security controls, which a machine credential cannot give`,
    { reason: "machine-credential" },
  );
}

/**
 * credential-lifetime at `enforce` refusing a machine credential's TTL
 * above the Organization's maximum. Nothing was issued.
 */
export function credentialLifetimeExceeded(requestedTtlSeconds: number, maxTtlSeconds: number): DomainError {
  return new DomainError(
    "CREDENTIAL_LIFETIME_EXCEEDED",
    `This organization's credential-lifetime control allows machine credentials of at most ${maxTtlSeconds} seconds, ` +
      `not ${requestedTtlSeconds}: ask for a shorter lifetime, or none to get the organization's default. Nothing was issued`,
    { control: "credential-lifetime", requestedTtlSeconds, maxTtlSeconds },
  );
}

/**
 * The gate of an operation that cannot carry an approval: one run outside
 * an HTTP request (a host command, a test). It never consumes one, so an
 * operation that a control at `enforce` would ask an approval for throws
 * ApprovalNeeded, which nothing turns into an intent.
 */
export function noApprovalGate(requester: ProtectedGate["requester"]): ProtectedGate {
  return {
    requester,
    approvalId: null,
    require: async (_db, binding) => {
      throw new ApprovalNeeded(binding);
    },
  };
}

const isPersonCredential = (r: ProtectedGate["requester"]) =>
  r.identityKind === "human" && (r.credentialKind === "browser" || r.credentialKind === "cli");

/**
 * Prepare a protected operation in its own transaction (see the top of
 * this file): lock its scope in amendment E's order, read its controls,
 * consume one exact approval when a control at `enforce` needs one (or
 * throw ApprovalNeeded), and return what report mode counts and the
 * effective issuance TTL.
 */
export async function prepareProtectedOperation(
  db: Querier,
  gate: ProtectedGate,
  input: ProtectedOperationInput,
): Promise<PreparedOperation> {
  const { scope } = input;
  const requester = gate.requester;
  // Step 1, with the deletion and freeze checks: lockLiveScope with nothing
  // after the Organization.
  await lockLiveScope(db, {
    organizationId: scope.organizationId,
    organizationMode: scope.organizationMode,
    allowFrozen: scope.allowFrozen,
    duringIncidentFreeze: scope.duringIncidentFreeze,
    people: [],
  });
  const controls = await applicableControls(db, scope.organizationId);

  let needsApproval = false;
  const reports: WouldBlock[] = [];
  let effectiveTtlSeconds: number | undefined;
  let ttlDefaulted = false;
  let approvalReason: ReportReason | undefined;
  for (const check of input.checks) {
    const control = controls.get(check.control);
    if (check.control === "credential-lifetime") {
      effectiveTtlSeconds = check.ttlSeconds;
      if (!control) continue;
      if (control.mode === "report") {
        const reason = lifetimeReason(control.config, check.ttlSeconds);
        if (reason) reports.push({ control: check.control, configVersion: control.version, operation: check.operation, actorIdentityId: requester.identityId, reason });
      } else if (control.mode === "enforce" && control.config) {
        // A refusal that does not depend on an approval: before one is
        // asked for, and before the people are locked (amendment A).
        if (check.ttlSeconds === undefined) {
          effectiveTtlSeconds = control.config.defaultTtlSeconds;
          ttlDefaulted = true;
        } else if (!Number.isInteger(check.ttlSeconds) || check.ttlSeconds <= 0) {
          // The HTTP routes never send one; a direct caller's 0 would mean
          // "never expires" (expiryOf), which enforce rules out.
          throw new DomainError("VALIDATION_FAILED", "A credential's lifetime must be a whole number of seconds above zero");
        } else if (check.ttlSeconds > control.config.maxTtlSeconds) {
          throw credentialLifetimeExceeded(check.ttlSeconds, control.config.maxTtlSeconds);
        }
      }
      continue;
    }
    if (!control || !APPROVAL_CONTROLS.has(check.control)) continue;
    if (control.mode === "enforce") {
      needsApproval = true;
    } else if (control.mode === "report") {
      // A machine credential can never pass an approval: told apart, as
      // enforce refuses it outright.
      approvalReason ??= requester.identityKind === "human" ? "no-approval" : "machine-credential";
      reports.push({ control: check.control, configVersion: control.version, operation: check.operation, actorIdentityId: requester.identityId, reason: approvalReason });
    }
  }

  let binding: ApprovalBinding | null = null;
  if (needsApproval) {
    binding = await input.binding(db, { effectiveTtlSeconds });
    if (binding !== null) {
      if (!isPersonCredential(requester)) throw machineCannotApprove(binding.operation);
      if (gate.approvalId === null) throw new ApprovalNeeded(binding);
    }
  }
  const consuming = binding !== null;

  // Step 2: every person at once, the requester FOR UPDATE when its
  // approval is consumed (never KEY SHARE first and upgraded later).
  await lockPeople(db, [...scope.people, ...(consuming ? [{ id: requester.identityId, mode: "update" as const }] : [])]);
  let approval: UsedApproval | null = null;
  if (binding !== null) {
    // Steps 4, 6, 7, then the action rechecked in this transaction.
    approval = await gate.require(db, binding);
    await input.authorizeIn?.(db);
  }
  // Steps 8 and 9 (the Organization and the people are held: reuse).
  if (scope.projectId !== undefined) await lockLiveScope(db, scope);

  return {
    approval,
    binding,
    reports,
    effectiveTtlSeconds,
    ttlDefaulted,
    count: (tx) => countWouldBlock(tx, scope.organizationId, reports),
  };
}

/** The approval an operation used, as flat audit metadata; nothing when it used none. */
export function approvalMetadata(approval: UsedApproval | null): Record<string, string | boolean> {
  return approval ? { approvalId: approval.id, approvalPasskeyId: approval.passkeyId, approvalUserVerified: approval.userVerified } : {};
}
