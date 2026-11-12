// SPDX-License-Identifier: AGPL-3.0-or-later
import { recordAuditEvent } from "../audit/events.js";
import { newId } from "../db/ids.js";
import type { Querier } from "../db/migrate.js";
import { withTx } from "../db/tx.js";
import { closeOpenApprovals, type ApprovalChange, type ApprovalGate, type UsedApproval } from "./approvals.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";
import { lockLiveScope, openFreeze } from "./liveness.js";
import { requireOrganizationAccess } from "./requestaccess.js";
import { lockPerson } from "./personlocks.js";

/**
 * The incident freeze (ADR-0055): one action that stops all access to an
 * Organization, reads included, keeps the audit trail flowing, and leaves a
 * narrow path to clean up and come back.
 *
 * - Freezing needs a person's credential with organization.manage and no
 *   approval: it only takes access away. It closes every open Approval
 *   Intent of the Organization, so nothing approved before the freeze can
 *   be used after it.
 * - Lifting needs a person's credential with organization.manage and,
 *   always, a step-up approval with a trusted passkey, bound to the freeze
 *   id (operation organization.unfreeze), whatever the Security Controls'
 *   modes. Any admin may lift, not only the one who froze. Lifting undoes
 *   nothing done during the freeze.
 * - The host operator lifts with `varlatchd admin unfreeze`, with no
 *   person and no approval: whoever controls the host bypasses everything
 *   here already.
 *
 * Where the freeze is enforced: liveness.ts (refuseIfIncidentFrozen and
 * lockLiveScope), http/organization.ts (the entry check), retrieval.ts and
 * capabilities.ts (the snapshots), syncdelivery.ts (the lease and the send
 * check), orgdeletion.ts (the worker) and the Convex token.
 *
 * Lock order (top of liveness.ts; ADR-0055 Decision 9 in amendment E's
 * numbering): freezing takes 1 UPDATE, then the freezer with the open
 * intents' people (2, KEY SHARE, id order) and the intents (4), then 11
 * (the freeze row, the audit last). A lift with an approval takes 1
 * UPDATE, 2 UPDATE, consumption's 4, 6 and 7, then 11. The operator's lift
 * takes 1 UPDATE, closeOpenApprovals' 2 and 4, then 11. Each passes
 * allowFrozen and the `freeze` exception, so it works while a deletion is
 * pending and leaves that deletion in place.
 */

export const FREEZE_REASON_MAX = 200;

export interface FreezeView {
  id: string;
  frozenAt: string;
  frozenBy: { id: string; name: string | null };
  reason: string;
  liftedAt: string | null;
  liftedBy: { id: string; name: string | null } | null;
  liftMethod: "approval" | "operator" | null;
}

/** A Sync Target that resumes pushing when the freeze is lifted: active, not revoked. */
export interface ResumingTarget {
  id: string;
  projectSlug: string;
  environmentName: string;
  platform: string;
  destination: string;
}

interface FreezeRow {
  id: string;
  frozen_at: Date | string;
  frozen_by: string;
  frozen_by_name: string | null;
  reason: string;
  lifted_at: Date | string | null;
  lifted_by: string | null;
  lifted_by_name: string | null;
  lift_method: "approval" | "operator" | null;
}

const iso = (v: Date | string) => new Date(v).toISOString();

function toView(r: FreezeRow): FreezeView {
  return {
    id: r.id,
    frozenAt: iso(r.frozen_at),
    frozenBy: { id: r.frozen_by, name: r.frozen_by_name },
    reason: r.reason,
    liftedAt: r.lifted_at ? iso(r.lifted_at) : null,
    liftedBy: r.lifted_by ? { id: r.lifted_by, name: r.lifted_by_name } : null,
    liftMethod: r.lift_method,
  };
}

const FREEZES_OF = `
  SELECT f.id, f.frozen_at, f.frozen_by, a.name AS frozen_by_name, f.reason, f.lifted_at, f.lifted_by,
         b.name AS lifted_by_name, f.lift_method
  FROM organization_freezes f
  JOIN identities a ON a.id = f.frozen_by
  LEFT JOIN identities b ON b.id = f.lifted_by
  WHERE f.organization_id = $1`;

/** The Organization's open freeze, as members see it, or null. */
export async function currentFreeze(db: Querier, organizationId: string): Promise<FreezeView | null> {
  const row = (await db.query(`${FREEZES_OF} AND f.lifted_at IS NULL`, [organizationId])).rows[0] as FreezeRow | undefined;
  return row ? toView(row) : null;
}

/** Which of these Organizations are frozen for an incident now. */
export async function frozenOrganizations(db: Querier, organizationIds: readonly string[]): Promise<Set<string>> {
  if (organizationIds.length === 0) return new Set();
  const rows = (await db.query(
    "SELECT organization_id FROM organization_freezes WHERE organization_id = ANY($1) AND lifted_at IS NULL",
    [[...organizationIds]],
  )).rows as { organization_id: string }[];
  return new Set(rows.map((r) => r.organization_id));
}

/** The Organization's freezes, newest first: the history. */
export async function freezeHistory(db: Querier, organizationId: string, limit = 20): Promise<FreezeView[]> {
  const rows = (await db.query(`${FREEZES_OF} ORDER BY f.frozen_at DESC, f.id DESC LIMIT $2`, [organizationId, limit])).rows as FreezeRow[];
  return rows.map(toView);
}

/**
 * The Sync Targets that resume pushing when the freeze is lifted: every
 * active Target of the Organization. A Target paused or revoked meanwhile
 * (recovery) stays paused or revoked, so it is not listed.
 */
export async function resumingTargets(db: Querier, organizationId: string): Promise<ResumingTarget[]> {
  const rows = (await db.query(
    `SELECT t.id, p.slug AS project_slug, e.name AS environment_name, c.platform, t.canonical_destination
     FROM sync_targets t
     JOIN projects p ON p.id = t.project_id
     JOIN environments e ON e.id = t.environment_id
     JOIN platform_connections c ON c.id = t.connection_id
     WHERE t.organization_id = $1 AND t.revoked_at IS NULL AND t.state = 'active'
     ORDER BY p.slug, e.name, t.id`,
    [organizationId],
  )).rows as { id: string; project_slug: string; environment_name: string; platform: string; canonical_destination: string }[];
  return rows.map((r) => ({
    id: r.id,
    projectSlug: r.project_slug,
    environmentName: r.environment_name,
    platform: r.platform,
    destination: r.canonical_destination,
  }));
}

/** Freezing and lifting are a person's: refused for machine credentials. */
function requirePerson(actor: { kind: string }, credentialKind: string, what: "freeze" | "lift"): void {
  if (actor.kind !== "human" || (credentialKind !== "browser" && credentialKind !== "cli")) {
    throw new DomainError(
      "PERMISSION_DENIED",
      what === "freeze"
        ? "Only a person can freeze an Organization; machine credentials never can"
        : "Only a person can lift a freeze, with a passkey approval; machine credentials never can",
      { reason: "machine-credential" },
    );
  }
}

/** The reason as stored: trimmed, 1 to 200 characters. */
export function normalizeReason(raw: string): string {
  const reason = raw.trim();
  if (reason.length < 1 || reason.length > FREEZE_REASON_MAX) {
    throw new DomainError("VALIDATION_FAILED", `reason: 1 to ${FREEZE_REASON_MAX} characters`);
  }
  return reason;
}

/**
 * Freeze the Organization (ADR-0055 Decision 2). One transaction: the
 * Organization row FOR UPDATE (through lockLiveScope, with allowFrozen and
 * the `freeze` exception: the deletion check still runs first, so freezing
 * during a pending deletion works and both apply), the requester's
 * authorization rechecked, STATE_CHANGED if a freeze is already open, the
 * Organization's open Approval Intents closed (reason `frozen`), the freeze
 * row inserted, and `organization.frozen` audited last.
 */
export async function freezeOrganization(
  ctx: AppCtx,
  input: {
    organizationId: string;
    actor: { id: string; kind: string };
    credentialKind: string;
    reason: string;
    requestId: string;
    authorizeIn: (db: Querier) => Promise<void>;
  },
): Promise<FreezeView> {
  requirePerson(input.actor, input.credentialKind, "freeze");
  const reason = normalizeReason(input.reason);
  return withTx(ctx.db, async (db) => {
    // Step 1 UPDATE: writes in progress (FOR KEY SHARE) commit first; later
    // ones read the freeze and refuse.
    await lockLiveScope(db, {
      organizationId: input.organizationId,
      organizationMode: "update",
      allowFrozen: true,
      duringIncidentFreeze: "freeze",
      // Step 2 comes later: closeOpenApprovals' people, or the requester.
      people: [],
    });
    await input.authorizeIn(db);
    if (await openFreeze(db, input.organizationId)) {
      throw new DomainError("STATE_CHANGED", "This Organization is already frozen");
    }
    // Steps 2 (the freezer with the intents' people, KEY SHARE, id order) and 4.
    const approvalsClosed = await closeOpenApprovals(db, {
      organizationId: input.organizationId,
      reason: "frozen",
      people: [input.actor.id],
    });
    // Step 11: the freeze row, then the audit.
    const id = newId("organizationFreeze");
    await db.query(
      `INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason)
       VALUES ($1, $2, $3, clock_timestamp(), $4)`,
      [id, input.organizationId, input.actor.id, reason],
    );
    await recordAuditEvent(db, {
      eventType: "organization.frozen",
      decision: "info",
      actorIdentityId: input.actor.id,
      organizationId: input.organizationId,
      action: "organization.manage",
      requestId: input.requestId,
      resource: { freezeId: id },
      // The reason is free text shown to members: never in the audit log.
      metadata: { freezeId: id, reasonGiven: true, approvalsClosed },
    });
    return (await currentFreeze(db, input.organizationId))!;
  });
}

export interface LiftOutcome {
  freeze: FreezeView;
  /** null when the requester may not read the Organization's Sync Targets (config.sync.manage). */
  resumingTargets: ResumingTarget[] | null;
}

function durationSeconds(from: Date | string, to: Date | string): number {
  return Math.max(0, Math.round((new Date(to).getTime() - new Date(from).getTime()) / 1000));
}

/** The freeze `freezeId` of the Organization, which must be the open one. */
async function requireOpenFreeze(db: Querier, organizationId: string, freezeId: string) {
  const row = (await db.query(
    "SELECT id, frozen_at, lifted_at FROM organization_freezes WHERE id = $1 AND organization_id = $2",
    [freezeId, organizationId],
  )).rows[0] as { id: string; frozen_at: Date | string; lifted_at: Date | string | null } | undefined;
  if (!row) throw new DomainError("RESOURCE_NOT_FOUND", "Freeze not found");
  if (row.lifted_at) throw new DomainError("STATE_CHANGED", "This freeze was already lifted");
  return row;
}

/**
 * Lift the open freeze `freezeId` with the requester's step-up approval
 * (ADR-0055 Decision 2), always, whatever the Security Controls' modes.
 * One transaction: the Organization row FOR UPDATE (with allowFrozen and
 * the `freeze` exception, so a pending deletion stays in place), the
 * authorization rechecked, the freeze checked open, the requester FOR
 * UPDATE (step 2), the approval for exactly this freeze consumed (steps 4,
 * 6, 7) or ApprovalNeeded thrown, then the freeze row updated and
 * `organization.unfrozen` audited (step 11).
 */
export async function liftFreeze(
  ctx: AppCtx,
  gate: ApprovalGate,
  input: {
    organizationId: string;
    freezeId: string;
    actor: { id: string; kind: string };
    credentialKind: string;
    requestId: string;
    authorizeIn: (db: Querier) => Promise<void>;
    /**
     * Whether the requester may read the Organization's Sync Targets
     * (config.sync.manage): the approval's summary and the answer name them
     * only then, and give their number otherwise.
     */
    mayListTargets: boolean;
  },
): Promise<LiftOutcome> {
  requirePerson(input.actor, input.credentialKind, "lift");
  return withTx(ctx.db, async (db) => {
    await lockLiveScope(db, {
      organizationId: input.organizationId,
      organizationMode: "update",
      allowFrozen: true,
      duringIncidentFreeze: "freeze",
      // Step 2 comes later: closeOpenApprovals' people, or the requester.
      people: [],
      accessCheck: "deferred",
    });
    await input.authorizeIn(db);
    const freeze = await requireOpenFreeze(db, input.organizationId, input.freezeId);
    // The freeze exists; then passkey-verification, before any approval is
    // asked for or consumed (ADR-0054 Decision 7).
    await requireOrganizationAccess(db, input.organizationId);
    // Step 2: the requester FOR UPDATE, whose approval is consumed
    // (consumption takes no person lock of its own).
    await lockPerson(db, input.actor.id, "update");
    const org = (await db.query("SELECT name FROM organizations WHERE id = $1", [input.organizationId])).rows[0] as { name: string };
    const targets = await resumingTargets(db, input.organizationId);
    const changes: ApprovalChange[] = [
      { field: "freeze", from: "frozen", to: "lifted", loosens: true },
      ...(input.mayListTargets
        ? targets.map((t) => ({
            field: `Sync Target ${t.projectSlug}/${t.environmentName} (${t.platform})`,
            from: "held",
            to: "resumes pushing",
            loosens: true,
          }))
        : targets.length > 0
          ? [{ field: "Sync Targets", from: "held", to: `${targets.length} resume pushing`, loosens: true }]
          : []),
    ];
    const approval: UsedApproval = await gate.require(db, {
      operation: "organization.unfreeze",
      organizationId: input.organizationId,
      // The freeze id: an approval can never lift a later freeze.
      target: { freezeId: input.freezeId },
      body: {},
      query: {},
      expectedVersion: null,
      summary: { title: `Lift the incident freeze of ${org.name}`, changes },
    });
    // Step 11: the freeze row, then the audit.
    const lifted = (await db.query(
      `UPDATE organization_freezes SET lifted_at = clock_timestamp(), lifted_by = $2, lift_method = 'approval'
       WHERE id = $1 AND lifted_at IS NULL RETURNING lifted_at`,
      [input.freezeId, input.actor.id],
    )).rows[0] as { lifted_at: Date | string };
    await recordAuditEvent(db, {
      eventType: "organization.unfrozen",
      decision: "info",
      actorIdentityId: input.actor.id,
      organizationId: input.organizationId,
      action: "organization.manage",
      requestId: input.requestId,
      resource: { freezeId: input.freezeId },
      metadata: {
        freezeId: input.freezeId,
        method: "approval",
        durationSeconds: durationSeconds(freeze.frozen_at, lifted.lifted_at),
        targetsResuming: targets.length,
        approvalId: approval.id,
        approvalPasskeyId: approval.passkeyId,
        approvalUserVerified: approval.userVerified,
      },
    });
    const view = (await db.query(`${FREEZES_OF} AND f.id = $2`, [input.organizationId, input.freezeId])).rows[0] as FreezeRow;
    return { freeze: toView(view), resumingTargets: input.mayListTargets ? targets : null };
  });
}

export interface OperatorLiftOutcome {
  organization: { id: string; slug: string };
  freeze: FreezeView;
  approvalsClosed: number;
  resumingTargets: ResumingTarget[];
  deletionPending: boolean;
}

/**
 * The host operator's lift (`varlatchd admin unfreeze`, ADR-0055 Decision
 * 2): no API reaches it. One transaction: the Organization row FOR UPDATE
 * (allowFrozen and the `freeze` exception), the open freeze, its open
 * organization.unfreeze intents closed, the freeze lifted with method
 * `operator`, and `organization.unfrozen` audited with no actor.
 */
export async function operatorUnfreeze(ctx: AppCtx, input: { organization: string; confirm: string }): Promise<OperatorLiftOutcome> {
  return withTx(ctx.db, async (db) => {
    const org = (await db.query(
      "SELECT id, slug FROM organizations WHERE (id = $1 OR slug = $1) AND deleted_at IS NULL",
      [input.organization],
    )).rows[0] as { id: string; slug: string } | undefined;
    if (!org) throw new DomainError("RESOURCE_NOT_FOUND", `No live Organization ${input.organization}`);
    if (input.confirm !== org.slug) {
      throw new DomainError("VALIDATION_FAILED", `--confirm must repeat the Organization's slug: ${org.slug}`);
    }
    await lockLiveScope(db, { organizationId: org.id, organizationMode: "update", allowFrozen: true, duringIncidentFreeze: "freeze", people: [] });
    const open = await openFreeze(db, org.id);
    if (!open) throw new DomainError("STATE_CHANGED", `${org.slug} is not frozen`);
    const freeze = await requireOpenFreeze(db, org.id, open.id);
    // Steps 2 (the intents' people, KEY SHARE) and 4: the open approvals
    // for a lift, which nothing can use now. The host operator's closure,
    // as the reset's.
    const approvalsClosed = await closeOpenApprovals(db, {
      organizationId: org.id,
      reason: "reset",
      operations: ["organization.unfreeze"],
    });
    const targets = await resumingTargets(db, org.id);
    const deletionPending = ((await db.query(
      "SELECT 1 FROM organization_deletions WHERE organization_id = $1 AND cancelled_at IS NULL AND completed_at IS NULL",
      [org.id],
    )).rows.length) > 0;
    const lifted = (await db.query(
      `UPDATE organization_freezes SET lifted_at = clock_timestamp(), lift_method = 'operator'
       WHERE id = $1 AND lifted_at IS NULL RETURNING lifted_at`,
      [open.id],
    )).rows[0] as { lifted_at: Date | string };
    await recordAuditEvent(db, {
      eventType: "organization.unfrozen",
      decision: "info",
      actorIdentityId: null,
      organizationId: org.id,
      resource: { freezeId: open.id },
      metadata: {
        freezeId: open.id,
        method: "operator",
        operator: true,
        durationSeconds: durationSeconds(freeze.frozen_at, lifted.lifted_at),
        targetsResuming: targets.length,
        approvalsClosed,
      },
    });
    const view = (await db.query(`${FREEZES_OF} AND f.id = $2`, [org.id, open.id])).rows[0] as FreezeRow;
    return { organization: org, freeze: toView(view), approvalsClosed, resumingTargets: targets, deletionPending };
  });
}

export const UNFREEZE_USAGE = "Usage: varlatchd admin unfreeze --org <slug> --confirm <slug> [--json]";

/** `admin unfreeze`'s arguments, or why they are wrong. --confirm must repeat the slug. */
export function parseUnfreezeArgs(args: readonly string[]): { organization: string; confirm: string; json: boolean } | { error: string } {
  let organization: string | undefined;
  let confirm: string | undefined;
  let json = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--org") organization = args[++i];
    else if (a === "--confirm") confirm = args[++i];
    else if (a === "--json") json = true;
    else return { error: `Unknown argument: ${a}\n${UNFREEZE_USAGE}` };
  }
  if (!organization || !confirm) return { error: UNFREEZE_USAGE };
  return { organization, confirm, json };
}

/** What the operator's lift prints for a person. */
export function unfreezeReportLines(outcome: OperatorLiftOutcome): string[] {
  return [
    `Incident freeze of ${outcome.organization.slug} [${outcome.organization.id}] lifted by the host operator.`,
    `Frozen since ${outcome.freeze.frozenAt}; lifted at ${outcome.freeze.liftedAt}.`,
    `Open lift approvals closed: ${outcome.approvalsClosed}.`,
    outcome.resumingTargets.length === 0
      ? "No Sync Target resumes pushing."
      : `Sync Targets that resume pushing (${outcome.resumingTargets.length}):`,
    ...outcome.resumingTargets.map((t) => `  ${t.projectSlug}/${t.environmentName} -> ${t.platform} ${t.destination} [${t.id}]`),
    ...(outcome.deletionPending ? ["A deletion of this Organization is still pending: writes stay refused until it is cancelled."] : []),
    "Nothing done during the freeze was undone. Recorded as organization.unfrozen.",
  ];
}
