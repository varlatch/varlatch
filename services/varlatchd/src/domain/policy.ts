// SPDX-License-Identifier: AGPL-3.0-or-later
import { recordAuditEvent } from "../audit/events.js";
import type { Action } from "../authz/evaluate.js";
import { newId } from "../db/ids.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";

/**
 * Roles, Groups, and Teams (ADR-0028): the reusable authorization constructs.
 * None of this grants directly — a Role is a named Action bundle, a Group an
 * identity set, a Team a Group that owns Projects; they only take effect
 * through Grants that reference them, expanded flat in loadGrants. All CRUD
 * here is gated by policy.manage at the HTTP layer and audited.
 */

export interface RoleRow {
  id: string;
  name: string;
  actions: string[];
  version: number;
  updatedAt: string | null;
}
export interface GroupRow {
  id: string;
  name: string;
  kind: "group" | "team";
  version: number;
  updatedAt: string | null;
}

function isoOrNull(v: string | Date | null): string | null {
  return v === null ? null : new Date(v).toISOString();
}

export async function createRole(
  ctx: AppCtx,
  organizationId: string,
  input: { name: string; actions: Action[] },
  actorIdentityId: string,
): Promise<RoleRow> {
  if (!input.name || input.name.length > 200) {
    throw new DomainError("VALIDATION_FAILED", "Invalid role name");
  }
  if (input.actions.length === 0) {
    throw new DomainError("VALIDATION_FAILED", "A role must grant at least one action");
  }
  return withTx(ctx.db, async (db) => {
    const id = newId("role");
    try {
      await db.query(
        "INSERT INTO roles (id, organization_id, name, actions, created_by) VALUES ($1,$2,$3,$4,$5)",
        [id, organizationId, input.name, input.actions, actorIdentityId],
      );
    } catch {
      throw new DomainError("VALIDATION_FAILED", "A role with that name already exists");
    }
    await recordAuditEvent(db, {
      eventType: "role.created",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "policy.manage",
      resource: { roleId: id },
      metadata: { name: input.name, actions: input.actions.join(",") },
    });
    return { id, name: input.name, actions: input.actions, version: 1, updatedAt: null };
  });
}

export async function listRoles(ctx: AppCtx, organizationId: string): Promise<RoleRow[]> {
  const res = await ctx.db.query(
    "SELECT id, name, actions, version, updated_at FROM roles WHERE organization_id = $1 AND revoked_at IS NULL ORDER BY name",
    [organizationId],
  );
  return (res.rows as (RoleRow & { updated_at: string | null })[]).map((r) => ({
    id: r.id,
    name: r.name,
    actions: r.actions,
    version: r.version,
    updatedAt: isoOrNull(r.updated_at),
  }));
}

/**
 * In-place Role update (ADR-0029): takes effect on the next authorization
 * decision — loadGrants expands the Role's current actions, so every Grant
 * citing it re-points with no revoke/recreate gap. Omitted fields are
 * unchanged; a supplied actions array replaces the whole set. A patch that
 * changes nothing returns the current row without a version bump or event.
 */
export async function updateRole(
  ctx: AppCtx,
  organizationId: string,
  roleId: string,
  patch: { expectedVersion: number; name?: string | undefined; actions?: Action[] | undefined },
  actorIdentityId: string,
): Promise<RoleRow> {
  if (patch.name !== undefined && (!patch.name || patch.name.length > 200)) {
    throw new DomainError("VALIDATION_FAILED", "Invalid role name");
  }
  if (patch.actions !== undefined && patch.actions.length === 0) {
    throw new DomainError("VALIDATION_FAILED", "A role must grant at least one action");
  }
  return withTx(ctx.db, async (db) => {
    const res = await db.query(
      "SELECT id, name, actions, version, updated_at FROM roles WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL FOR UPDATE",
      [roleId, organizationId],
    );
    const row = res.rows[0] as (RoleRow & { updated_at: string | null }) | undefined;
    if (!row) throw new DomainError("RESOURCE_NOT_FOUND", "Role not found");
    if (row.version !== patch.expectedVersion) {
      throw new DomainError("VERSION_CONFLICT", "Role was modified concurrently; reload and retry");
    }
    const name = patch.name ?? row.name;
    const actions = patch.actions ?? (row.actions as Action[]);
    const unchanged =
      name === row.name &&
      actions.length === row.actions.length &&
      actions.every((a, i) => a === row.actions[i]);
    if (unchanged) {
      return { id: row.id, name: row.name, actions: row.actions, version: row.version, updatedAt: isoOrNull(row.updated_at) };
    }
    let updated;
    try {
      updated = await db.query(
        "UPDATE roles SET name = $1, actions = $2, version = version + 1, updated_at = now() WHERE id = $3 RETURNING version, updated_at",
        [name, actions, roleId],
      );
    } catch {
      throw new DomainError("VALIDATION_FAILED", "A role with that name already exists");
    }
    const out = updated.rows[0] as { version: number; updated_at: string };
    await recordAuditEvent(db, {
      eventType: "role.updated",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "policy.manage",
      resource: { roleId },
      metadata: {
        oldName: row.name,
        newName: name,
        oldActions: row.actions.join(","),
        newActions: actions.join(","),
        version: out.version,
      },
    });
    return { id: roleId, name, actions, version: out.version, updatedAt: isoOrNull(out.updated_at) };
  });
}

export async function deleteRole(
  ctx: AppCtx,
  organizationId: string,
  roleId: string,
  actorIdentityId: string,
): Promise<void> {
  await withTx(ctx.db, async (db) => {
    const res = await db.query(
      "UPDATE roles SET revoked_at = now() WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL RETURNING id",
      [roleId, organizationId],
    );
    if (!res.rows[0]) throw new DomainError("RESOURCE_NOT_FOUND", "Role not found");
    await recordAuditEvent(db, {
      eventType: "role.deleted",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "policy.manage",
      resource: { roleId },
    });
  });
}

export async function createGroup(
  ctx: AppCtx,
  organizationId: string,
  input: { name: string; kind: "group" | "team" },
  actorIdentityId: string,
): Promise<GroupRow> {
  if (!input.name || input.name.length > 200) {
    throw new DomainError("VALIDATION_FAILED", "Invalid group name");
  }
  return withTx(ctx.db, async (db) => {
    const id = newId(input.kind === "team" ? "team" : "group");
    try {
      await db.query(
        "INSERT INTO groups (id, organization_id, name, kind, created_by) VALUES ($1,$2,$3,$4,$5)",
        [id, organizationId, input.name, input.kind, actorIdentityId],
      );
    } catch {
      throw new DomainError("VALIDATION_FAILED", `A ${input.kind} with that name already exists`);
    }
    await recordAuditEvent(db, {
      eventType: input.kind === "team" ? "team.created" : "group.created",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "policy.manage",
      resource: { groupId: id },
      metadata: { name: input.name },
    });
    return { id, name: input.name, kind: input.kind, version: 1, updatedAt: null };
  });
}

export async function listGroups(
  ctx: AppCtx,
  organizationId: string,
  kind: "group" | "team",
): Promise<GroupRow[]> {
  const res = await ctx.db.query(
    "SELECT id, name, kind, version, updated_at FROM groups WHERE organization_id = $1 AND kind = $2 AND revoked_at IS NULL ORDER BY name",
    [organizationId, kind],
  );
  return (res.rows as (GroupRow & { updated_at: string | null })[]).map((r) => ({
    id: r.id,
    name: r.name,
    kind: r.kind,
    version: r.version,
    updatedAt: isoOrNull(r.updated_at),
  }));
}

/**
 * In-place Group/Team rename (ADR-0029). Membership and project ownership
 * have their own add/remove endpoints and never bump the version.
 */
export async function updateGroup(
  ctx: AppCtx,
  organizationId: string,
  groupId: string,
  kind: "group" | "team",
  patch: { expectedVersion: number; name?: string | undefined },
  actorIdentityId: string,
): Promise<GroupRow> {
  if (patch.name !== undefined && (!patch.name || patch.name.length > 200)) {
    throw new DomainError("VALIDATION_FAILED", "Invalid group name");
  }
  return withTx(ctx.db, async (db) => {
    const res = await db.query(
      "SELECT id, name, kind, version, updated_at FROM groups WHERE id = $1 AND organization_id = $2 AND kind = $3 AND revoked_at IS NULL FOR UPDATE",
      [groupId, organizationId, kind],
    );
    const row = res.rows[0] as (GroupRow & { updated_at: string | null }) | undefined;
    if (!row) {
      throw new DomainError("RESOURCE_NOT_FOUND", kind === "team" ? "Team not found" : "Group not found");
    }
    if (row.version !== patch.expectedVersion) {
      throw new DomainError("VERSION_CONFLICT", `${kind === "team" ? "Team" : "Group"} was modified concurrently; reload and retry`);
    }
    const name = patch.name ?? row.name;
    if (name === row.name) {
      return { id: row.id, name: row.name, kind: row.kind, version: row.version, updatedAt: isoOrNull(row.updated_at) };
    }
    let updated;
    try {
      updated = await db.query(
        "UPDATE groups SET name = $1, version = version + 1, updated_at = now() WHERE id = $2 RETURNING version, updated_at",
        [name, groupId],
      );
    } catch {
      throw new DomainError("VALIDATION_FAILED", `A ${kind} with that name already exists`);
    }
    const out = updated.rows[0] as { version: number; updated_at: string };
    await recordAuditEvent(db, {
      eventType: kind === "team" ? "team.updated" : "group.updated",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "policy.manage",
      resource: { groupId },
      metadata: { oldName: row.name, newName: name, version: out.version },
    });
    return { id: groupId, name, kind, version: out.version, updatedAt: isoOrNull(out.updated_at) };
  });
}

export async function deleteGroup(
  ctx: AppCtx,
  organizationId: string,
  groupId: string,
  actorIdentityId: string,
): Promise<void> {
  await withTx(ctx.db, async (db) => {
    const res = await db.query(
      "UPDATE groups SET revoked_at = now() WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL RETURNING kind",
      [groupId, organizationId],
    );
    if (!res.rows[0]) throw new DomainError("RESOURCE_NOT_FOUND", "Group not found");
    const kind = (res.rows[0] as { kind: string }).kind;
    await recordAuditEvent(db, {
      eventType: kind === "team" ? "team.deleted" : "group.deleted",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "policy.manage",
      resource: { groupId },
    });
  });
}

/** Verify the group exists in the org (and, when required, is a Team). */
async function requireGroup(
  ctx: AppCtx,
  organizationId: string,
  groupId: string,
  kind?: "group" | "team",
): Promise<GroupRow> {
  const res = await ctx.db.query(
    "SELECT id, name, kind FROM groups WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL",
    [groupId, organizationId],
  );
  const row = res.rows[0] as GroupRow | undefined;
  if (!row || (kind && row.kind !== kind)) {
    throw new DomainError("RESOURCE_NOT_FOUND", kind === "team" ? "Team not found" : "Group not found");
  }
  return row;
}

export async function addGroupMember(
  ctx: AppCtx,
  organizationId: string,
  groupId: string,
  identityId: string,
  actorIdentityId: string,
): Promise<void> {
  const group = await requireGroup(ctx, organizationId, groupId);
  await withTx(ctx.db, async (db) => {
    const member = await db.query(
      `SELECT id FROM identities WHERE id = $1 AND NOT disabled AND (
         organization_id = $2 OR (kind = 'human' AND EXISTS (
           SELECT 1 FROM org_memberships WHERE identity_id = $1 AND organization_id = $2
         )))`,
      [identityId, organizationId],
    );
    if (!member.rows[0]) throw new DomainError("RESOURCE_NOT_FOUND", "Identity not in this organization");
    await db.query(
      "INSERT INTO group_members (group_id, identity_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
      [groupId, identityId],
    );
    await recordAuditEvent(db, {
      eventType: group.kind === "team" ? "team.member_added" : "group.member_added",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "policy.manage",
      resource: { groupId, identityId },
    });
  });
}

export async function removeGroupMember(
  ctx: AppCtx,
  organizationId: string,
  groupId: string,
  identityId: string,
  actorIdentityId: string,
): Promise<void> {
  const group = await requireGroup(ctx, organizationId, groupId);
  await withTx(ctx.db, async (db) => {
    const res = await db.query(
      "DELETE FROM group_members WHERE group_id = $1 AND identity_id = $2 RETURNING group_id",
      [groupId, identityId],
    );
    if (!res.rows[0]) throw new DomainError("RESOURCE_NOT_FOUND", "Membership not found");
    await recordAuditEvent(db, {
      eventType: group.kind === "team" ? "team.member_removed" : "group.member_removed",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "policy.manage",
      resource: { groupId, identityId },
    });
  });
}

export async function listGroupMembers(
  ctx: AppCtx,
  organizationId: string,
  groupId: string,
): Promise<{ identityId: string }[]> {
  await requireGroup(ctx, organizationId, groupId);
  const res = await ctx.db.query(
    "SELECT identity_id FROM group_members WHERE group_id = $1 ORDER BY created_at",
    [groupId],
  );
  return (res.rows as { identity_id: string }[]).map((r) => ({ identityId: r.identity_id }));
}

export async function addTeamProject(
  ctx: AppCtx,
  organizationId: string,
  teamId: string,
  projectId: string,
  actorIdentityId: string,
): Promise<void> {
  await requireGroup(ctx, organizationId, teamId, "team");
  await withTx(ctx.db, async (db) => {
    const project = await db.query(
      "SELECT id FROM projects WHERE id = $1 AND organization_id = $2",
      [projectId, organizationId],
    );
    if (!project.rows[0]) throw new DomainError("RESOURCE_NOT_FOUND", "Project not in this organization");
    await db.query(
      "INSERT INTO team_projects (team_id, project_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
      [teamId, projectId],
    );
    await recordAuditEvent(db, {
      eventType: "team.project_added",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "policy.manage",
      resource: { groupId: teamId, projectId },
    });
  });
}

export async function removeTeamProject(
  ctx: AppCtx,
  organizationId: string,
  teamId: string,
  projectId: string,
  actorIdentityId: string,
): Promise<void> {
  await requireGroup(ctx, organizationId, teamId, "team");
  await withTx(ctx.db, async (db) => {
    const res = await db.query(
      "DELETE FROM team_projects WHERE team_id = $1 AND project_id = $2 RETURNING team_id",
      [teamId, projectId],
    );
    if (!res.rows[0]) throw new DomainError("RESOURCE_NOT_FOUND", "Team does not own that project");
    await recordAuditEvent(db, {
      eventType: "team.project_removed",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "policy.manage",
      resource: { groupId: teamId, projectId },
    });
  });
}

export async function listTeamProjects(
  ctx: AppCtx,
  organizationId: string,
  teamId: string,
): Promise<{ projectId: string }[]> {
  await requireGroup(ctx, organizationId, teamId, "team");
  const res = await ctx.db.query(
    "SELECT project_id FROM team_projects WHERE team_id = $1 ORDER BY created_at",
    [teamId],
  );
  return (res.rows as { project_id: string }[]).map((r) => ({ projectId: r.project_id }));
}
