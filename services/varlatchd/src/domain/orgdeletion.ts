// SPDX-License-Identifier: AGPL-3.0-or-later
import { recordAuditEvent, recordAuditEvents, type AuditEventInput } from "../audit/events.js";
import { evaluate, type OrgRole } from "../authz/evaluate.js";
import { newId } from "../db/ids.js";
import type { Querier } from "../db/migrate.js";
import { withTx } from "../db/tx.js";
import { loadGrants } from "../http/support.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";
import { closeOpenApprovals } from "./approvals.js";
import { lockPeople } from "./personlocks.js";
import { lockLiveScope, openDeletion, openFreeze } from "./liveness.js";
import { reportAdminStepUp } from "./securityreport.js";
import { endMembership, lockMembershipRows } from "./members.js";
import { lockedQuery } from "../db/locks.js";

/**
 * Deleting an Organization (ADR-0051 Decisions 4 to 8): a request with a
 * lifecycle. Scheduling freezes the Organization and suspends what can be
 * undone; a waiting period of 1 to 30 days, and a second admin's approval
 * when there was more than one admin, come before a worker finalizes it in
 * one transaction. Each step is one transaction with its audit event last.
 */

export const DEFAULT_WAIT_DAYS = 7;

export interface DeletionView {
  id: string;
  requestedBy: string;
  scheduledAt: string;
  runAfter: string;
  approvalRequired: boolean;
  approvedBy: string | null;
  approvedAt: string | null;
  cancelledAt: string | null;
  completedAt: string | null;
}

const iso = (v: unknown) => (v ? new Date(v as string).toISOString() : null);

function view(row: Record<string, unknown>): DeletionView {
  return {
    id: row.id as string,
    requestedBy: row.requested_by as string,
    scheduledAt: iso(row.scheduled_at)!,
    runAfter: iso(row.run_after)!,
    approvalRequired: row.approval_required as boolean,
    approvedBy: (row.approved_by as string | null) ?? null,
    approvedAt: iso(row.approved_at),
    cancelledAt: iso(row.cancelled_at),
    completedAt: iso(row.completed_at),
  };
}

/** A human with a live built-in admin membership; an explicit Grant does not substitute. */
async function requireLiveAdmin(db: Querier, organizationId: string, actor: { id: string; kind: string }): Promise<void> {
  const res = await db.query(
    `SELECT 1 FROM org_memberships m JOIN identities i ON i.id = m.identity_id
     WHERE m.organization_id = $1 AND m.identity_id = $2 AND m.role = 'admin' AND m.removed_at IS NULL AND NOT i.disabled`,
    [organizationId, actor.id],
  );
  if (actor.kind !== "human" || !res.rows[0]) {
    throw new DomainError("PERMISSION_DENIED", "Only an Organization Admin can schedule, approve or cancel its deletion");
  }
}

async function requestRow(db: Querier, deletionId: string, organizationId: string): Promise<Record<string, unknown>> {
  const row = (
    await lockedQuery(db, { table: "organization_deletions", mode: "update" }, "SELECT * FROM organization_deletions WHERE id = $1 AND organization_id = $2 FOR UPDATE", [deletionId, organizationId])
  ).rows[0] as Record<string, unknown> | undefined;
  if (!row) throw new DomainError("RESOURCE_NOT_FOUND", "Deletion request not found");
  if (row.cancelled_at || row.completed_at) {
    throw new DomainError("STATE_CHANGED", `This deletion request is ${row.cancelled_at ? "cancelled" : "completed"}`);
  }
  return row;
}

/** The open request, if any, for the dashboard and the CLI. */
export async function getDeletion(ctx: AppCtx, organizationId: string): Promise<DeletionView | null> {
  const row = (
    await ctx.db.query(
      "SELECT * FROM organization_deletions WHERE organization_id = $1 AND cancelled_at IS NULL AND completed_at IS NULL",
      [organizationId],
    )
  ).rows[0] as Record<string, unknown> | undefined;
  return row ? view(row) : null;
}

/**
 * Schedules the deletion, which freezes the Organization (Decision 5). In
 * the same transaction: Sync Targets paused with the ADR-0050 fence,
 * webhooks and enabled machine identities suspended under this request's
 * marker (a cancel restores exactly those), pending invitations revoked,
 * and unfinished GitHub App registrations invalidated.
 */
export async function scheduleDeletion(
  ctx: AppCtx,
  organizationId: string,
  actor: { id: string; kind: string },
  input: { afterDays?: number | undefined },
): Promise<DeletionView> {
  const days = input.afterDays ?? DEFAULT_WAIT_DAYS;
  if (!Number.isInteger(days) || days < 1 || days > 30) {
    throw new DomainError("VALIDATION_FAILED", "The waiting period is 1 to 30 days");
  }
  return withTx(ctx.db, async (db) => {
    // FOR UPDATE: writers in progress finish first, later ones see the freeze.
    await lockLiveScope(db, { organizationId, organizationMode: "update", allowFrozen: true, people: [] });
    if (await openDeletion(db, organizationId)) {
      throw new DomainError("STATE_CHANGED", "This Organization is already being deleted");
    }
    await requireLiveAdmin(db, organizationId, actor);
    const admins = Number(
      (
        (await db.query(
          `SELECT count(*)::int AS n FROM org_memberships m JOIN identities i ON i.id = m.identity_id
           WHERE m.organization_id = $1 AND m.role = 'admin' AND m.removed_at IS NULL AND NOT i.disabled`,
          [organizationId],
        )).rows[0] as { n: number }
      ).n,
    );
    // Step 2 of the lock order (liveness.ts): the requester
    // (requested_by), and the machine identities this suspends FOR UPDATE,
    // in id order, before any domain row. A bulk UPDATE alone would take
    // them in the order it scans them. The Organization row, held FOR
    // UPDATE, keeps that set from changing meanwhile.
    const suspending = (
      (await db.query("SELECT id FROM identities WHERE organization_id = $1 AND kind <> 'human' AND NOT disabled ORDER BY id", [organizationId]))
        .rows as { id: string }[]
    ).map((r) => r.id);
    await lockPeople(db, [actor.id, ...suspending.map((sid) => ({ id: sid, mode: "update" as const }))]);
    const id = newId("organizationDeletion");
    const inserted = await db.query(
      `INSERT INTO organization_deletions (id, organization_id, requested_by, run_after, approval_required)
       VALUES ($1, $2, $3, now() + ($4 * interval '1 day'), $5) RETURNING *`,
      [id, organizationId, actor.id, days, admins > 1],
    );
    const targets = await lockedQuery(db, { table: "sync_targets", mode: "update" }, "SELECT id FROM sync_targets WHERE organization_id = $1 AND revoked_at IS NULL AND state = 'active' ORDER BY id FOR UPDATE",
      [organizationId],
    );
    const targetIds = (targets.rows as { id: string }[]).map((r) => r.id);
    if (targetIds.length > 0) {
      // Paused with the fence (ADR-0050): a push in progress stops. A cancel
      // leaves them paused: resuming pushes is a deliberate choice.
      await db.query(
        `UPDATE sync_targets SET state = 'paused', generation = generation + 1, lease_expires_at = NULL,
           repair_cycle_started_at = NULL, version = version + 1, updated_at = now()
         WHERE id = ANY($1)`,
        [targetIds],
      );
    }
    // The other domain rows it changes, each in key order, before their
    // bulk updates.
    await lockedQuery(
      db,
      { table: "webhooks", mode: "no key update" },
      "SELECT id FROM webhooks WHERE organization_id = $1 AND revoked_at IS NULL AND suspended_by_deletion IS NULL ORDER BY id FOR NO KEY UPDATE",
      [organizationId],
    );
    await lockedQuery(
      db,
      { table: "setup_grants", mode: "no key update" },
      `SELECT id FROM setup_grants
       WHERE kind = 'invite' AND invite_organization_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > now()
       ORDER BY id FOR NO KEY UPDATE`,
      [organizationId],
    );
    await lockedQuery(
      db,
      { table: "github_app_registrations", mode: "update", key: "state_hash" },
      `SELECT state_hash FROM github_app_registrations WHERE organization_id = $1 ORDER BY state_hash COLLATE "C" FOR UPDATE`,
      [organizationId],
    );
    const webhooks = await db.query(
      `UPDATE webhooks SET suspended_by_deletion = $2
       WHERE organization_id = $1 AND revoked_at IS NULL AND suspended_by_deletion IS NULL RETURNING id`,
      [organizationId, id],
    );
    const identities = await db.query(
      `UPDATE identities SET disabled = true, suspended_by_deletion = $2
       WHERE organization_id = $1 AND kind <> 'human' AND NOT disabled RETURNING id`,
      [organizationId, id],
    );
    const invitations = await db.query(
      `UPDATE setup_grants SET revoked_at = now()
       WHERE kind = 'invite' AND invite_organization_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > now()
       RETURNING id`,
      [organizationId],
    );
    await db.query("DELETE FROM github_app_registrations WHERE organization_id = $1", [organizationId]);
    const row = inserted.rows[0] as Record<string, unknown>;
    await reportAdminStepUp(db, organizationId, actor.id, "organization.delete");
    await recordAuditEvent(db, {
      eventType: "organization.deletion_scheduled",
      decision: "info",
      actorIdentityId: actor.id,
      organizationId,
      action: "organization.manage",
      resource: { deletionId: id },
      metadata: {
        runAfter: iso(row.run_after),
        approvalRequired: admins > 1,
        targetsPaused: targetIds.length,
        webhooksSuspended: webhooks.rows.length,
        identitiesSuspended: identities.rows.length,
        invitationsRevoked: invitations.rows.length,
      },
    });
    return view(row);
  });
}

/**
 * A second admin's approval, bound to this request: a different, enabled
 * human with a live admin membership. Checked again when the deletion runs.
 */
export async function approveDeletion(
  ctx: AppCtx,
  organizationId: string,
  deletionId: string,
  actor: { id: string; kind: string },
): Promise<DeletionView> {
  return withTx(ctx.db, async (db) => {
    await lockLiveScope(db, { organizationId, organizationMode: "update", allowFrozen: true, people: [] });
    const row = await requestRow(db, deletionId, organizationId);
    // Step 2 (liveness.ts), after the request (step 1): the approver, whom
    // approved_by references.
    await lockPeople(db, [actor.id]);
    if (!row.approval_required) throw new DomainError("VALIDATION_FAILED", "This deletion needs no approval");
    if (row.approved_by) return view(row);
    await requireLiveAdmin(db, organizationId, actor);
    if (row.requested_by === actor.id) {
      throw new DomainError("PERMISSION_DENIED", "Another admin than the one who scheduled the deletion must approve it");
    }
    const updated = await db.query(
      "UPDATE organization_deletions SET approved_by = $2, approved_at = now() WHERE id = $1 RETURNING *",
      [deletionId, actor.id],
    );
    await recordAuditEvent(db, {
      eventType: "organization.deletion_approved",
      decision: "info",
      actorIdentityId: actor.id,
      organizationId,
      action: "organization.manage",
      resource: { deletionId },
    });
    return view(updated.rows[0] as Record<string, unknown>);
  });
}

/**
 * Any admin can cancel until completion commits. The machine identities
 * and webhooks this request suspended come back; Sync Targets stay paused,
 * and revoked invitations stay revoked.
 */
export async function cancelDeletion(
  ctx: AppCtx,
  organizationId: string,
  deletionId: string,
  actor: { id: string; kind: string },
): Promise<DeletionView> {
  return withTx(ctx.db, async (db) => {
    // The Organization row, then the request: the worker's order, so a
    // cancel and a run are serialized. Cancelling is recovery while frozen
    // for an incident (ADR-0055 Decision 7); scheduling and approving are
    // refused then.
    await lockLiveScope(db, { organizationId, organizationMode: "update", allowFrozen: true, duringIncidentFreeze: "recovery", people: [] });
    await requestRow(db, deletionId, organizationId);
    // Step 2 (liveness.ts): the canceller (cancelled_by), and the machine
    // identities this restores FOR UPDATE, in id order; then the webhooks
    // it resumes, in id order, before the bulk updates.
    const restoring = (
      (await db.query("SELECT id FROM identities WHERE suspended_by_deletion = $1 ORDER BY id", [deletionId])).rows as { id: string }[]
    ).map((r) => r.id);
    await lockPeople(db, [actor.id, ...restoring.map((rid) => ({ id: rid, mode: "update" as const }))]);
    await lockedQuery(
      db,
      { table: "webhooks", mode: "no key update" },
      "SELECT id FROM webhooks WHERE suspended_by_deletion = $1 ORDER BY id FOR NO KEY UPDATE",
      [deletionId],
    );
    await requireLiveAdmin(db, organizationId, actor);
    const updated = await db.query(
      "UPDATE organization_deletions SET cancelled_by = $2, cancelled_at = now() WHERE id = $1 RETURNING *",
      [deletionId, actor.id],
    );
    const identities = await db.query(
      "UPDATE identities SET disabled = false, suspended_by_deletion = NULL WHERE suspended_by_deletion = $1 RETURNING id",
      [deletionId],
    );
    const webhooks = await db.query(
      "UPDATE webhooks SET suspended_by_deletion = NULL WHERE suspended_by_deletion = $1 RETURNING id",
      [deletionId],
    );
    await recordAuditEvent(db, {
      eventType: "organization.deletion_cancelled",
      decision: "info",
      actorIdentityId: actor.id,
      organizationId,
      action: "organization.manage",
      resource: { deletionId },
      metadata: { identitiesRestored: identities.rows.length, webhooksResumed: webhooks.rows.length },
    });
    return view(updated.rows[0] as Record<string, unknown>);
  });
}

export interface FinalizeOutcome {
  deletionId: string;
  organizationId: string;
  members: number;
  readers: number;
  projects: number;
  versionsErased: number;
  targetsRevoked: number;
  identitiesRetired: number;
  credentialsRevoked: number;
  webhooksRemoved: number;
  connectionsRevoked: number;
  githubAppRemoved: boolean;
}

/**
 * Runs one due deletion, if it can claim it (Decision 6). One transaction:
 * on any failure it rolls back, the Organization stays frozen, and the
 * worker tries again later. Every lock and change comes first; the audit
 * events are appended at the end.
 */
export async function finalizeDeletion(ctx: AppCtx, deletionId: string, organizationId: string): Promise<FinalizeOutcome | null> {
  return withTx(ctx.db, async (db) => {
    // Claim: the Organization row (another process may hold it), then the request.
    const org = await lockedQuery(db, { table: "organizations", mode: "update" }, "SELECT id, slug, name FROM organizations WHERE id = $1 AND deleted_at IS NULL FOR UPDATE SKIP LOCKED",
      [organizationId],
    );
    const orgRow = org.rows[0] as { id: string; slug: string; name: string } | undefined;
    if (!orgRow) return null;
    const request = (
      await lockedQuery(db, { table: "organization_deletions", mode: "update" }, `SELECT * FROM organization_deletions WHERE id = $1 AND organization_id = $2
           AND cancelled_at IS NULL AND completed_at IS NULL AND run_after <= now() FOR UPDATE`,
        [deletionId, organizationId],
      )
    ).rows[0] as Record<string, unknown> | undefined;
    if (!request) return null;
    // An Organization frozen for an incident waits for the lift (ADR-0055
    // Decision 7): read after the claim, under the Organization row, which
    // a freeze writes under FOR UPDATE.
    if (await openFreeze(db, organizationId)) return null;
    if (request.approval_required) {
      if (!request.approved_by) return null;
      // The approver must still be an enabled, live admin when it runs.
      const approver = await db.query(
        `SELECT 1 FROM org_memberships m JOIN identities i ON i.id = m.identity_id
         WHERE m.organization_id = $1 AND m.identity_id = $2 AND m.role = 'admin' AND m.removed_at IS NULL AND NOT i.disabled`,
        [organizationId, request.approved_by],
      );
      if (!approver.rows[0]) return null;
    }
    const requester = request.requested_by as string;
    const events: AuditEventInput[] = [];

    // Step 2 of the lock order (domain/liveness.ts): every person this
    // transaction locks or references, in id order, in one step. FOR KEY
    // SHARE for the people it only references (the audit readers, the
    // members whose removals it writes, the requester as their actor, the
    // owners of the open approvals it closes); FOR UPDATE for the
    // Organization's machine identities, which it disables.
    const referenced = (
      await db.query(
        `SELECT m.identity_id AS id FROM org_memberships m JOIN identities i ON i.id = m.identity_id
         WHERE m.organization_id = $1 AND m.removed_at IS NULL AND i.kind = 'human'
         UNION SELECT identity_id FROM approval_intents WHERE organization_id = $1 AND consumed_at IS NULL AND closed_at IS NULL`,
        [organizationId],
      )
    ).rows as { id: string }[];
    const machines = (
      (await db.query("SELECT id FROM identities WHERE organization_id = $1 AND kind <> 'human' ORDER BY id", [organizationId])).rows as { id: string }[]
    ).map((r) => r.id);
    await lockPeople(db, [requester, ...referenced.map((r) => r.id), ...machines.map((id) => ({ id, mode: "update" as const }))]);

    // Step 4: open step-up approvals end with it (ADR-0054); its Security
    // Controls rows stay with the Organization's tombstone row, like its
    // other rows.
    await closeOpenApprovals(db, { organizationId, reason: "organization-deleted" });

    // Step 7: the machine identities' credentials, in id order.
    await lockedQuery(
      db,
      { table: "credentials", mode: "update" },
      "SELECT id FROM credentials WHERE identity_id = ANY($1) AND revoked_at IS NULL ORDER BY id FOR UPDATE",
      [machines],
    );

    // The audit tombstone's readers (Decision 8), before memberships end:
    // the people holding Organization-level audit.read, through any Grant.
    const members = (
      await db.query(
        `SELECT m.identity_id, m.role, i.disabled FROM org_memberships m JOIN identities i ON i.id = m.identity_id
         WHERE m.organization_id = $1 AND m.removed_at IS NULL AND i.kind = 'human' ORDER BY m.identity_id`,
        [organizationId],
      )
    ).rows as { identity_id: string; role: OrgRole; disabled: boolean }[];
    const readers: string[] = [];
    for (const m of members) {
      if (m.disabled) continue;
      const grants = await loadGrants({ ...ctx, db }, organizationId, m.identity_id);
      const decision = evaluate({
        action: "audit.read",
        resource: { organizationId },
        orgRole: m.role,
        grants,
        requirements: [],
        tailnetContext: null,
      });
      if (decision.allowed) readers.push(m.identity_id);
    }

    // Steps 8 and 9: every Project, then every environment, in id order.
    await lockedQuery(db, { table: "projects", mode: "update" }, "SELECT id FROM projects WHERE organization_id = $1 ORDER BY id FOR UPDATE", [organizationId]);
    const envIds = (
      (await lockedQuery(db, { table: "environments", mode: "update" }, `SELECT e.id FROM environments e JOIN projects p ON p.id = e.project_id WHERE p.organization_id = $1 ORDER BY e.id FOR UPDATE OF e`,
        [organizationId],
      )).rows as { id: string }[]
    ).map((r) => r.id);

    // Step 10: values, then the integrations (App, Connections, Targets),
    // then the other domain rows, each in key order and in the mode its
    // update or deletion below takes.
    const memberIds = members.map((m) => m.identity_id);
    const lockAll = (table: string, mode: "no key update" | "update", sql: string, params: unknown[], key?: string) =>
      lockedQuery(db, { table, mode, ...(key ? { key } : {}) }, sql, params);
    await lockAll("env_values", "no key update", "SELECT id FROM env_values WHERE environment_id = ANY($1) ORDER BY id FOR NO KEY UPDATE", [envIds]);
    await lockAll(
      "value_versions",
      "no key update",
      `SELECT id FROM value_versions WHERE erased_at IS NULL AND value_id IN (SELECT id FROM env_values WHERE environment_id = ANY($1))
       ORDER BY id FOR NO KEY UPDATE`,
      [envIds],
    );
    await lockAll("github_apps", "no key update", "SELECT id FROM github_apps WHERE organization_id = $1 AND removed_at IS NULL ORDER BY id FOR NO KEY UPDATE", [organizationId]);
    await lockAll("platform_connections", "no key update", "SELECT id FROM platform_connections WHERE organization_id = $1 AND revoked_at IS NULL ORDER BY id FOR NO KEY UPDATE", [organizationId]);
    const targetIds = (
      (await lockAll("sync_targets", "update", "SELECT id FROM sync_targets WHERE organization_id = $1 AND revoked_at IS NULL ORDER BY id FOR UPDATE", [organizationId]))
        .rows as { id: string }[]
    ).map((r) => r.id);
    await lockAll("capabilities", "no key update", "SELECT id FROM capabilities WHERE organization_id = $1 AND revoked_at IS NULL ORDER BY id FOR NO KEY UPDATE", [organizationId]);
    await lockAll("webhooks", "no key update", "SELECT id FROM webhooks WHERE organization_id = $1 AND revoked_at IS NULL ORDER BY id FOR NO KEY UPDATE", [organizationId]);
    await lockMembershipRows(db, organizationId, memberIds);
    await lockAll("oidc_bindings", "no key update", "SELECT id FROM oidc_bindings WHERE organization_id = $1 AND revoked_at IS NULL ORDER BY id FOR NO KEY UPDATE", [organizationId]);

    if (readers.length > 0) {
      await db.query(
        "INSERT INTO audit_tombstone_readers (organization_id, identity_id) SELECT $1, unnest($2::text[])",
        [organizationId, readers],
      );
    }

    // Memberships end through removal's finalization mode: the same cleanup
    // and events, without the actor check and the last-admin rule.
    for (const m of members) {
      const ended = await endMembership(ctx, db, organizationId, m.identity_id, m.role, requester);
      events.push({
        eventType: "membership.removed",
        decision: "info",
        actorIdentityId: requester,
        organizationId,
        resource: { identityId: m.identity_id, removalId: ended.removalId },
        metadata: {
          role: m.role,
          left: false,
          finalization: true,
          grantsRevoked: ended.grants,
          groupsLeft: ended.groups,
          invitationsRevoked: ended.invitations,
        },
      });
    }

    const projects = await db.query(
      "UPDATE projects SET deleted_at = now() WHERE organization_id = $1 AND deleted_at IS NULL RETURNING id",
      [organizationId],
    );
    await db.query("UPDATE environments SET deleted_at = now() WHERE id = ANY($1) AND deleted_at IS NULL", [envIds]);
    await db.query(
      `UPDATE env_values SET deleted_at = COALESCE(deleted_at, now()), current_version_id = NULL,
         retiring_version_id = NULL, rotation_deadline = NULL, rotation_started_at = NULL
       WHERE environment_id = ANY($1)`,
      [envIds],
    );
    const erased = await db.query(
      `UPDATE value_versions SET payload = NULL, wrapped_dek = NULL, erased_at = now()
       WHERE erased_at IS NULL AND value_id IN (SELECT id FROM env_values WHERE environment_id = ANY($1)) RETURNING id`,
      [envIds],
    );
    await db.query("UPDATE capabilities SET revoked_at = now() WHERE organization_id = $1 AND revoked_at IS NULL", [organizationId]);
    await db.query(
      `UPDATE sync_targets SET revoked_at = now(), generation = generation + 1, lease_expires_at = NULL,
         repair_cycle_started_at = NULL, version = version + 1, updated_at = now()
       WHERE id = ANY($1)`,
      [targetIds],
    );
    const connections = await db.query(
      "UPDATE platform_connections SET revoked_at = now(), version = version + 1, updated_at = now() WHERE organization_id = $1 AND revoked_at IS NULL RETURNING id",
      [organizationId],
    );
    // The local registration goes, so the App can be imported elsewhere;
    // GitHub still has it (the runbook lists the provider steps).
    const app = await db.query(
      "UPDATE github_apps SET removed_at = now(), key_envelope = NULL WHERE organization_id = $1 AND removed_at IS NULL RETURNING id",
      [organizationId],
    );
    const webhooks = await db.query(
      "UPDATE webhooks SET revoked_at = now(), suspended_by_deletion = NULL WHERE organization_id = $1 AND revoked_at IS NULL RETURNING id",
      [organizationId],
    );
    // Machine identities are retired: credentials revoked, bindings removed.
    await db.query("UPDATE identities SET disabled = true, suspended_by_deletion = NULL WHERE id = ANY($1)", [machines]);
    const credentials = await db.query(
      "UPDATE credentials SET revoked_at = now() WHERE identity_id = ANY($1) AND revoked_at IS NULL RETURNING id",
      [machines],
    );
    await db.query("UPDATE oidc_bindings SET revoked_at = now() WHERE organization_id = $1 AND revoked_at IS NULL", [organizationId]);

    // Step 11: report counters (ADR-0054 Decision 9) go with the
    // Organization, in key order, after its domain rows and before the
    // audit: no increment can come in (they hold this row FOR KEY SHARE
    // first), and nothing is summarized for a deleted Organization.
    await lockAll(
      "security_control_counters",
      "update",
      `SELECT concat_ws('|', organization_id::text, control::text, config_version::text, operation::text, actor_identity_id::text,
                        reason::text, bucket_hour::text) AS lock_key
       FROM security_control_counters WHERE organization_id = $1
       ORDER BY concat_ws('|', organization_id::text, control::text, config_version::text, operation::text, actor_identity_id::text,
                          reason::text, bucket_hour::text) COLLATE "C"
       FOR UPDATE`,
      [organizationId],
      "lock_key",
    );
    await db.query("DELETE FROM security_control_counters WHERE organization_id = $1", [organizationId]);

    // The tombstone, and the Organization KEK destroyed: what it protected
    // (platform credentials, webhook secrets, the App key, the sync
    // fingerprint key) is unreadable through the key hierarchy from now on.
    await db.query(
      "UPDATE organizations SET deleted_at = now(), wrapped_org_kek = NULL, org_kek_destroyed_at = now() WHERE id = $1",
      [organizationId],
    );
    await db.query("UPDATE organization_deletions SET completed_at = now() WHERE id = $1", [deletionId]);

    const outcome: FinalizeOutcome = {
      deletionId,
      organizationId,
      members: members.length,
      readers: readers.length,
      projects: projects.rows.length,
      versionsErased: erased.rows.length,
      targetsRevoked: targetIds.length,
      identitiesRetired: machines.length,
      credentialsRevoked: credentials.rows.length,
      webhooksRemoved: webhooks.rows.length,
      connectionsRevoked: connections.rows.length,
      githubAppRemoved: app.rows.length > 0,
    };
    events.push({
      eventType: "organization.deleted",
      decision: "info",
      actorIdentityId: null,
      organizationId,
      resource: { deletionId, organizationSlug: orgRow.slug },
      metadata: {
        name: orgRow.name,
        requestedBy: requester,
        approvedBy: (request.approved_by as string | null) ?? null,
        members: outcome.members,
        readers: outcome.readers,
        projects: outcome.projects,
        versionsErased: outcome.versionsErased,
        targetsRevoked: outcome.targetsRevoked,
        identitiesRetired: outcome.identitiesRetired,
        credentialsRevoked: outcome.credentialsRevoked,
        webhooksRemoved: outcome.webhooksRemoved,
        connectionsRevoked: outcome.connectionsRevoked,
        githubAppRemoved: outcome.githubAppRemoved,
      },
    });
    // Audit last: every resource lock and change is done.
    await recordAuditEvents(db, events);
    return outcome;
  });
}

/** One pass of the deletion worker: every due request it can claim. Never throws. */
export async function runDueDeletions(ctx: AppCtx): Promise<FinalizeOutcome[]> {
  // Found without locking; each is then claimed in its own transaction.
  const due = (
    await ctx.db.query(
      `SELECT id, organization_id FROM organization_deletions
       WHERE cancelled_at IS NULL AND completed_at IS NULL AND run_after <= now()
         AND (NOT approval_required OR approved_by IS NOT NULL)
       ORDER BY run_after, id`,
    )
  ).rows as { id: string; organization_id: string }[];
  const done: FinalizeOutcome[] = [];
  for (const d of due) {
    try {
      const outcome = await finalizeDeletion(ctx, d.id, d.organization_id);
      if (outcome) done.push(outcome);
    } catch (err) {
      console.error(`organization deletion ${d.id} failed; it stays frozen and is tried again:`, err);
    }
  }
  return done;
}

/** The deletion worker: a loop in every `varlatchd serve` process (Decision 6). */
export function startDeletionLoop(ctx: AppCtx, intervalMs = 60_000): () => void {
  let busy = false;
  const tick = async () => {
    if (busy) return;
    const leave = ctx.maintenance?.enter();
    if (ctx.maintenance && !leave) return;
    busy = true;
    try {
      await runDueDeletions(ctx);
    } catch (err) {
      console.error("deletion loop error:", err);
    } finally {
      busy = false;
      leave?.();
    }
  };
  const timer = setInterval(tick, intervalMs);
  timer.unref();
  void tick();
  return () => clearInterval(timer);
}
