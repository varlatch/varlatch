// SPDX-License-Identifier: AGPL-3.0-or-later
import { recordAuditEvent } from "../audit/events.js";
import type { Action } from "../authz/evaluate.js";
import { newId } from "../db/ids.js";
import type { Querier } from "../db/migrate.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";
import { pinLiveMembership } from "./orgs.js";
import { lockedQuery } from "../db/locks.js";
import type { ProtectedGate } from "./approvals.js";
import type { ProtectedOptions } from "./identities.js";
import { approvalMetadata, prepareProtectedOperation } from "./protected.js";
import {
  groupCreateBinding,
  groupDeleteBinding,
  groupOperation,
  groupUpdateBinding,
  isGroupMember,
  isTeamProject,
  memberAddBinding,
  memberRemoveBinding,
  readEligibleMember,
  readGroup,
  readLiveProject,
  readPerson,
  readProjectName,
  readRole,
  refuseTakenName,
  roleCreateBinding,
  roleDeleteBinding,
  roleUpdateBinding,
  sameRole,
  teamProjectAddBinding,
  teamProjectRemoveBinding,
} from "./accessstepup.js";

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

/**
 * A protected operation (ADR-0054): admin-step-up's role.create. Under
 * enforce it needs the requester's approval, bound to the Organization and
 * the role's name and set of actions (accessstepup.ts). A name already
 * taken is refused first.
 */
export async function createRole(
  ctx: AppCtx,
  gate: ProtectedGate,
  organizationId: string,
  input: { name: string; actions: Action[] },
  options: ProtectedOptions = {},
): Promise<RoleRow> {
  const actorIdentityId = gate.requester.identityId;
  if (!input.name || input.name.length > 200) {
    throw new DomainError("VALIDATION_FAILED", "Invalid role name");
  }
  if (input.actions.length === 0) {
    throw new DomainError("VALIDATION_FAILED", "A role must grant at least one action");
  }
  return withTx(ctx.db, async (db) => {
    const prepared = await prepareProtectedOperation(db, gate, {
      scope: { organizationId, people: [actorIdentityId] },
      checks: [{ control: "admin-step-up", operation: "role.create" }],
      binding: async (db) => {
        await refuseTakenName(db, "roles", organizationId, input.name, null, "A role with that name already exists");
        return roleCreateBinding({ id: organizationId }, input);
      },
      authorizeIn: options.authorizeIn,
    });
    const id = newId("role");
    try {
      await db.query(
        "INSERT INTO roles (id, organization_id, name, actions, created_by) VALUES ($1,$2,$3,$4,$5)",
        [id, organizationId, input.name, input.actions, actorIdentityId],
      );
    } catch {
      throw new DomainError("VALIDATION_FAILED", "A role with that name already exists");
    }
    // Report mode (ADR-0054 Decision 9), before the audit insert.
    await prepared.count(db);
    await recordAuditEvent(db, {
      eventType: "role.created",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "policy.manage",
      resource: { roleId: id },
      metadata: { name: input.name, actions: input.actions.join(","), ...approvalMetadata(prepared.approval) },
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
 *
 * A protected operation (ADR-0054): admin-step-up's role.update. Under
 * enforce it needs the requester's approval, bound to the role, its
 * resulting name and set of actions, and the version the request expects
 * (accessstepup.ts). A patch whose result means the same role (the same
 * name and set of actions, a reordering included) needs none and is not
 * counted by report mode; it is still written as before.
 */
export async function updateRole(
  ctx: AppCtx,
  gate: ProtectedGate,
  organizationId: string,
  roleId: string,
  patch: { expectedVersion: number; name?: string | undefined; actions?: Action[] | undefined },
  options: ProtectedOptions = {},
): Promise<RoleRow> {
  const actorIdentityId = gate.requester.identityId;
  if (patch.name !== undefined && (!patch.name || patch.name.length > 200)) {
    throw new DomainError("VALIDATION_FAILED", "Invalid role name");
  }
  if (patch.actions !== undefined && patch.actions.length === 0) {
    throw new DomainError("VALIDATION_FAILED", "A role must grant at least one action");
  }
  return withTx(ctx.db, async (db) => {
    const prepared = await prepareProtectedOperation(db, gate, {
      scope: { organizationId, people: [actorIdentityId] },
      checks: [{ control: "admin-step-up", operation: "role.update" }],
      // Existence, whatever the controls, before passkey-verification (ADR-0054 Decision 7).
      preflight: async (db) => {
        if (!(await readRole(db, organizationId, roleId))) throw new DomainError("RESOURCE_NOT_FOUND", "Role not found");
      },
      binding: async (db) => {
        // Refusals first (amendment A), read without a lock; the version is
        // checked again under the row lock below, so the state bound is the
        // state changed.
        const current = await readRole(db, organizationId, roleId);
        if (!current) throw new DomainError("RESOURCE_NOT_FOUND", "Role not found");
        if (current.version !== patch.expectedVersion) {
          throw new DomainError("VERSION_CONFLICT", "Role was modified concurrently; reload and retry");
        }
        const next = { name: patch.name ?? current.name, actions: patch.actions ?? current.actions };
        if (sameRole(current, next)) return null;
        if (next.name !== current.name) {
          await refuseTakenName(db, "roles", organizationId, next.name, roleId, "A role with that name already exists");
        }
        return roleUpdateBinding(db, { id: organizationId }, current, next, patch.expectedVersion);
      },
      authorizeIn: options.authorizeIn,
    });
    const res = await lockedQuery(
      db,
      { table: "roles", mode: "update" },
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
    // Report mode counts what enforce would ask an approval for: a change
    // of the name or of the set of actions, not a reordering.
    if (!sameRole(row, { name, actions })) await prepared.count(db);
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
        ...approvalMetadata(prepared.approval),
      },
    });
    return { id: roleId, name, actions, version: out.version, updatedAt: isoOrNull(out.updated_at) };
  });
}

/**
 * A protected operation (ADR-0054): admin-step-up's role.delete. Under
 * enforce it needs the requester's approval, bound to the role and the
 * version the server read (the request carries none), checked again under
 * the role's row lock: an edit since makes the approval stale.
 */
export async function deleteRole(
  ctx: AppCtx,
  gate: ProtectedGate,
  organizationId: string,
  roleId: string,
  options: ProtectedOptions = {},
): Promise<void> {
  const actorIdentityId = gate.requester.identityId;
  await withTx(ctx.db, async (db) => {
    const prepared = await prepareProtectedOperation(db, gate, {
      scope: { organizationId, people: [actorIdentityId] },
      checks: [{ control: "admin-step-up", operation: "role.delete" }],
      // Existence, whatever the controls, before passkey-verification (ADR-0054 Decision 7).
      preflight: async (db) => {
        if (!(await readRole(db, organizationId, roleId))) throw new DomainError("RESOURCE_NOT_FOUND", "Role not found");
      },
      binding: async (db) => {
        const role = await readRole(db, organizationId, roleId);
        if (!role) throw new DomainError("RESOURCE_NOT_FOUND", "Role not found");
        return roleDeleteBinding({ id: organizationId }, role);
      },
      authorizeIn: options.authorizeIn,
    });
    const locked = (await lockedQuery(
      db,
      { table: "roles", mode: "update" },
      "SELECT id, version FROM roles WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL FOR UPDATE",
      [roleId, organizationId],
    )).rows[0] as { id: string; version: number } | undefined;
    if (!locked) throw new DomainError("RESOURCE_NOT_FOUND", "Role not found");
    // The version the approval bound, under the row lock: an edit since
    // rolls back this attempt, consumption included.
    if (prepared.binding && locked.version !== prepared.binding.expectedVersion) {
      throw new DomainError("STATE_CHANGED", "The role changed while it was being deleted; nothing was deleted. Read it again and ask for a new approval");
    }
    await db.query("UPDATE roles SET revoked_at = now() WHERE id = $1", [roleId]);
    // Report mode (ADR-0054 Decision 9), before the audit insert.
    await prepared.count(db);
    await recordAuditEvent(db, {
      eventType: "role.deleted",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "policy.manage",
      resource: { roleId },
      ...(prepared.approval ? { metadata: approvalMetadata(prepared.approval) } : {}),
    });
  });
}

/**
 * A protected operation (ADR-0054): admin-step-up's group.create or
 * team.create. Under enforce it needs the requester's approval, bound to
 * the Organization, the kind and the name (accessstepup.ts). A name
 * already taken is refused first.
 */
export async function createGroup(
  ctx: AppCtx,
  gate: ProtectedGate,
  organizationId: string,
  input: { name: string; kind: "group" | "team" },
  options: ProtectedOptions = {},
): Promise<GroupRow> {
  const actorIdentityId = gate.requester.identityId;
  if (!input.name || input.name.length > 200) {
    throw new DomainError("VALIDATION_FAILED", "Invalid group name");
  }
  return withTx(ctx.db, async (db) => {
    const prepared = await prepareProtectedOperation(db, gate, {
      scope: { organizationId, people: [actorIdentityId] },
      checks: [{ control: "admin-step-up", operation: groupOperation(input.kind, "create") }],
      binding: async (db) => {
        await refuseTakenName(db, "groups", organizationId, input.name, null, `A ${input.kind} with that name already exists`);
        return groupCreateBinding({ id: organizationId }, input);
      },
      authorizeIn: options.authorizeIn,
    });
    const id = newId(input.kind === "team" ? "team" : "group");
    try {
      await db.query(
        "INSERT INTO groups (id, organization_id, name, kind, created_by) VALUES ($1,$2,$3,$4,$5)",
        [id, organizationId, input.name, input.kind, actorIdentityId],
      );
    } catch {
      throw new DomainError("VALIDATION_FAILED", `A ${input.kind} with that name already exists`);
    }
    // Report mode (ADR-0054 Decision 9), before the audit insert.
    await prepared.count(db);
    await recordAuditEvent(db, {
      eventType: input.kind === "team" ? "team.created" : "group.created",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "policy.manage",
      resource: { groupId: id },
      metadata: { name: input.name, ...approvalMetadata(prepared.approval) },
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
 *
 * A protected operation (ADR-0054): admin-step-up's group.update or
 * team.update. Under enforce a rename needs the requester's approval,
 * bound to the group, the resulting name and the version the request
 * expects (accessstepup.ts). Keeping the name needs none.
 */
export async function updateGroup(
  ctx: AppCtx,
  gate: ProtectedGate,
  organizationId: string,
  groupId: string,
  kind: "group" | "team",
  patch: { expectedVersion: number; name?: string | undefined },
  options: ProtectedOptions = {},
): Promise<GroupRow> {
  const actorIdentityId = gate.requester.identityId;
  if (patch.name !== undefined && (!patch.name || patch.name.length > 200)) {
    throw new DomainError("VALIDATION_FAILED", "Invalid group name");
  }
  const notFound = () => new DomainError("RESOURCE_NOT_FOUND", kind === "team" ? "Team not found" : "Group not found");
  const conflict = () => new DomainError("VERSION_CONFLICT", `${kind === "team" ? "Team" : "Group"} was modified concurrently; reload and retry`);
  return withTx(ctx.db, async (db) => {
    const prepared = await prepareProtectedOperation(db, gate, {
      scope: { organizationId, people: [actorIdentityId] },
      checks: [{ control: "admin-step-up", operation: groupOperation(kind, "update") }],
      // Existence, whatever the controls, before passkey-verification (ADR-0054 Decision 7).
      preflight: async (db) => {
        if (!(await readGroup(db, organizationId, groupId, kind))) throw notFound();
      },
      binding: async (db) => {
        // Refusals first (amendment A); the version is checked again under
        // the row lock below.
        const current = await readGroup(db, organizationId, groupId, kind);
        if (!current) throw notFound();
        if (current.version !== patch.expectedVersion) throw conflict();
        const name = patch.name ?? current.name;
        if (name === current.name) return null;
        await refuseTakenName(db, "groups", organizationId, name, groupId, `A ${kind} with that name already exists`);
        return groupUpdateBinding({ id: organizationId }, current, name, patch.expectedVersion);
      },
      authorizeIn: options.authorizeIn,
    });
    const res = await lockedQuery(
      db,
      { table: "groups", mode: "update" },
      "SELECT id, name, kind, version, updated_at FROM groups WHERE id = $1 AND organization_id = $2 AND kind = $3 AND revoked_at IS NULL FOR UPDATE",
      [groupId, organizationId, kind],
    );
    const row = res.rows[0] as (GroupRow & { updated_at: string | null }) | undefined;
    if (!row) throw notFound();
    if (row.version !== patch.expectedVersion) throw conflict();
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
    // Report mode (ADR-0054 Decision 9), before the audit insert.
    await prepared.count(db);
    await recordAuditEvent(db, {
      eventType: kind === "team" ? "team.updated" : "group.updated",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "policy.manage",
      resource: { groupId },
      metadata: { oldName: row.name, newName: name, version: out.version, ...approvalMetadata(prepared.approval) },
    });
    return { id: groupId, name, kind, version: out.version, updatedAt: isoOrNull(out.updated_at) };
  });
}

/**
 * A protected operation (ADR-0054): admin-step-up's group.delete or
 * team.delete, after the stored kind (a team deleted through a /groups/
 * route is team.delete). Under enforce it needs the requester's approval,
 * bound to the group and the version the server read, checked again under
 * the group's row lock.
 */
export async function deleteGroup(
  ctx: AppCtx,
  gate: ProtectedGate,
  organizationId: string,
  groupId: string,
  options: ProtectedOptions = {},
): Promise<void> {
  const actorIdentityId = gate.requester.identityId;
  await withTx(ctx.db, async (db) => {
    // The kind names the operation report mode counts. It never changes,
    // so this read needs no lock; an unknown group is refused below, after
    // the Organization's checks, as before.
    const stored = (await db.query("SELECT kind FROM groups WHERE id = $1 AND organization_id = $2", [groupId, organizationId])).rows[0] as
      | { kind: "group" | "team" }
      | undefined;
    const prepared = await prepareProtectedOperation(db, gate, {
      scope: { organizationId, people: [actorIdentityId] },
      checks: [{ control: "admin-step-up", operation: groupOperation(stored?.kind ?? "group", "delete") }],
      // Existence, whatever the controls, before passkey-verification (ADR-0054 Decision 7).
      preflight: async (db) => {
        if (!(await readGroup(db, organizationId, groupId))) throw new DomainError("RESOURCE_NOT_FOUND", "Group not found");
      },
      binding: async (db) => {
        const group = await readGroup(db, organizationId, groupId);
        if (!group) throw new DomainError("RESOURCE_NOT_FOUND", "Group not found");
        return groupDeleteBinding(db, { id: organizationId }, group);
      },
      authorizeIn: options.authorizeIn,
    });
    const locked = (await lockedQuery(
      db,
      { table: "groups", mode: "update" },
      "SELECT id, kind, version FROM groups WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL FOR UPDATE",
      [groupId, organizationId],
    )).rows[0] as { id: string; kind: string; version: number } | undefined;
    if (!locked) throw new DomainError("RESOURCE_NOT_FOUND", "Group not found");
    if (prepared.binding && locked.version !== prepared.binding.expectedVersion) {
      throw new DomainError("STATE_CHANGED", `The ${locked.kind} changed while it was being deleted; nothing was deleted. Read it again and ask for a new approval`);
    }
    await db.query("UPDATE groups SET revoked_at = now() WHERE id = $1", [groupId]);
    const kind = locked.kind;
    // Report mode (ADR-0054 Decision 9), before the audit insert.
    await prepared.count(db);
    await recordAuditEvent(db, {
      eventType: kind === "team" ? "team.deleted" : "group.deleted",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "policy.manage",
      resource: { groupId },
      ...(prepared.approval ? { metadata: approvalMetadata(prepared.approval) } : {}),
    });
  });
}

/**
 * A Grant's subject identity must be able to act in the Organization
 * (ADR-0052 Decision 1): a machine of this Organization, or a person with a
 * live membership, pinned for the rest of the caller's transaction so a
 * concurrent removal cannot miss the Grant.
 */
export async function requireGrantSubject(db: Querier, organizationId: string, identityId: string): Promise<void> {
  const res = await db.query("SELECT kind, organization_id FROM identities WHERE id = $1", [identityId]);
  const row = res.rows[0] as { kind: string; organization_id: string | null } | undefined;
  const ok =
    row !== undefined &&
    (row.kind === "human"
      ? (await pinLiveMembership(db, organizationId, identityId)) !== null
      : row.organization_id === organizationId);
  if (!ok) throw new DomainError("RESOURCE_NOT_FOUND", "Identity not in this organization");
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

/**
 * A protected operation (ADR-0054): admin-step-up's group.member_add or
 * team.member_add, after the stored kind. Under enforce it needs the
 * requester's approval, bound to the group and the identity
 * (accessstepup.ts). Adding a current member changes nothing and needs
 * none; that is decided again under the locks: a membership removed in
 * between is refused (STATE_CHANGED), never added without its approval.
 */
export async function addGroupMember(
  ctx: AppCtx,
  gate: ProtectedGate,
  organizationId: string,
  groupId: string,
  identityId: string,
  options: ProtectedOptions = {},
): Promise<void> {
  const actorIdentityId = gate.requester.identityId;
  const group = await requireGroup(ctx, organizationId, groupId);
  await withTx(ctx.db, async (db) => {
    let boundMember = false;
    const prepared = await prepareProtectedOperation(db, gate, {
      scope: { organizationId, people: [actorIdentityId, identityId] },
      checks: [{ control: "admin-step-up", operation: groupOperation(group.kind, "member_add") }],
      // Existence, whatever the controls, before passkey-verification (ADR-0054 Decision 7).
      preflight: async (db) => {
        if (!(await readEligibleMember(db, organizationId, identityId))) throw new DomainError("RESOURCE_NOT_FOUND", "Identity not in this organization");
      },
      binding: async (db) => {
        const person = await readEligibleMember(db, organizationId, identityId);
        if (!person) throw new DomainError("RESOURCE_NOT_FOUND", "Identity not in this organization");
        if (await isGroupMember(db, groupId, identityId)) {
          boundMember = true;
          return null;
        }
        return memberAddBinding({ id: organizationId }, group, person);
      },
      authorizeIn: options.authorizeIn,
    });
    const member = await db.query(
      "SELECT kind FROM identities WHERE id = $1 AND NOT disabled AND (organization_id = $2 OR kind = 'human')",
      [identityId, organizationId],
    );
    const kind = (member.rows[0] as { kind: string } | undefined)?.kind;
    // A person joins only through a live membership, which this pins
    // against a concurrent removal (ADR-0052 Decision 1).
    if (!kind || (kind === "human" && !(await pinLiveMembership(db, organizationId, identityId)))) {
      throw new DomainError("RESOURCE_NOT_FOUND", "Identity not in this organization");
    }
    const added = await db.query(
      "INSERT INTO group_members (group_id, identity_id) VALUES ($1,$2) ON CONFLICT DO NOTHING RETURNING group_id",
      [groupId, identityId],
    );
    // A member when the approval was decided, no longer one now: this
    // addition would need an approval it was not asked for.
    if (boundMember && added.rows[0]) {
      throw new DomainError("STATE_CHANGED", "The membership was removed while it was being added; nothing changed. Add it again");
    }
    // Report mode counts only a membership this added; repeating one changes nothing.
    if (added.rows[0]) await prepared.count(db);
    await recordAuditEvent(db, {
      eventType: group.kind === "team" ? "team.member_added" : "group.member_added",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "policy.manage",
      resource: { groupId, identityId },
      ...(prepared.approval ? { metadata: approvalMetadata(prepared.approval) } : {}),
    });
  });
}

/**
 * A protected operation (ADR-0054): admin-step-up's group.member_remove or
 * team.member_remove, after the stored kind. Under enforce it needs the
 * requester's approval, bound to the group and the identity. A membership
 * that does not exist is refused first.
 */
export async function removeGroupMember(
  ctx: AppCtx,
  gate: ProtectedGate,
  organizationId: string,
  groupId: string,
  identityId: string,
  options: ProtectedOptions = {},
): Promise<void> {
  const actorIdentityId = gate.requester.identityId;
  const group = await requireGroup(ctx, organizationId, groupId);
  await withTx(ctx.db, async (db) => {
    const prepared = await prepareProtectedOperation(db, gate, {
      scope: { organizationId, people: [actorIdentityId] },
      checks: [{ control: "admin-step-up", operation: groupOperation(group.kind, "member_remove") }],
      // Existence, whatever the controls, before passkey-verification (ADR-0054 Decision 7).
      preflight: async (db) => {
        if (!(await isGroupMember(db, groupId, identityId))) throw new DomainError("RESOURCE_NOT_FOUND", "Membership not found");
      },
      binding: async (db) => {
        if (!(await isGroupMember(db, groupId, identityId))) throw new DomainError("RESOURCE_NOT_FOUND", "Membership not found");
        return memberRemoveBinding({ id: organizationId }, group, await readPerson(db, identityId));
      },
      authorizeIn: options.authorizeIn,
    });
    const res = await db.query(
      "DELETE FROM group_members WHERE group_id = $1 AND identity_id = $2 RETURNING group_id",
      [groupId, identityId],
    );
    if (!res.rows[0]) throw new DomainError("RESOURCE_NOT_FOUND", "Membership not found");
    // Report mode (ADR-0054 Decision 9), before the audit insert.
    await prepared.count(db);
    await recordAuditEvent(db, {
      eventType: group.kind === "team" ? "team.member_removed" : "group.member_removed",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "policy.manage",
      resource: { groupId, identityId },
      ...(prepared.approval ? { metadata: approvalMetadata(prepared.approval) } : {}),
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

/**
 * A protected operation (ADR-0054): admin-step-up's team.project_add.
 * Under enforce it needs the requester's approval, bound to the team and
 * the project (accessstepup.ts). Adding a linked project changes nothing
 * and needs none; that is decided again under the locks: a link removed in
 * between is refused (STATE_CHANGED), never added without its approval.
 */
export async function addTeamProject(
  ctx: AppCtx,
  gate: ProtectedGate,
  organizationId: string,
  teamId: string,
  projectId: string,
  options: ProtectedOptions = {},
): Promise<void> {
  const actorIdentityId = gate.requester.identityId;
  const team = await requireGroup(ctx, organizationId, teamId, "team");
  await withTx(ctx.db, async (db) => {
    let boundLinked = false;
    // A live Project of this Organization, locked so its deletion, which
    // removes Teams' links, cannot miss this one (ADR-0051); the actor at
    // step 2 of the lock order (liveness.ts), before it.
    const prepared = await prepareProtectedOperation(db, gate, {
      scope: { organizationId, people: [actorIdentityId], projectId },
      checks: [{ control: "admin-step-up", operation: "team.project_add" }],
      // Existence, whatever the controls, before passkey-verification (ADR-0054 Decision 7).
      preflight: async (db) => {
        if (!(await readLiveProject(db, organizationId, projectId))) throw new DomainError("RESOURCE_NOT_FOUND", "Project not found");
      },
      binding: async (db) => {
        const project = await readLiveProject(db, organizationId, projectId);
        if (!project) throw new DomainError("RESOURCE_NOT_FOUND", "Project not found");
        if (await isTeamProject(db, teamId, projectId)) {
          boundLinked = true;
          return null;
        }
        return teamProjectAddBinding({ id: organizationId }, team, project);
      },
      authorizeIn: options.authorizeIn,
    });
    const added = await db.query(
      "INSERT INTO team_projects (team_id, project_id) VALUES ($1,$2) ON CONFLICT DO NOTHING RETURNING team_id",
      [teamId, projectId],
    );
    if (boundLinked && added.rows[0]) {
      throw new DomainError("STATE_CHANGED", "The project was taken from the team while it was being added; nothing changed. Add it again");
    }
    // Report mode counts only a link this added; repeating one changes nothing.
    if (added.rows[0]) await prepared.count(db);
    await recordAuditEvent(db, {
      eventType: "team.project_added",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "policy.manage",
      resource: { groupId: teamId, projectId },
      ...(prepared.approval ? { metadata: approvalMetadata(prepared.approval) } : {}),
    });
  });
}

/**
 * A protected operation (ADR-0054): admin-step-up's team.project_remove.
 * Under enforce it needs the requester's approval, bound to the team and
 * the project. A link that does not exist is refused first.
 */
export async function removeTeamProject(
  ctx: AppCtx,
  gate: ProtectedGate,
  organizationId: string,
  teamId: string,
  projectId: string,
  options: ProtectedOptions = {},
): Promise<void> {
  const actorIdentityId = gate.requester.identityId;
  const team = await requireGroup(ctx, organizationId, teamId, "team");
  await withTx(ctx.db, async (db) => {
    const prepared = await prepareProtectedOperation(db, gate, {
      scope: { organizationId, people: [actorIdentityId] },
      checks: [{ control: "admin-step-up", operation: "team.project_remove" }],
      // Existence, whatever the controls, before passkey-verification (ADR-0054 Decision 7).
      preflight: async (db) => {
        if (!(await isTeamProject(db, teamId, projectId))) throw new DomainError("RESOURCE_NOT_FOUND", "Team does not own that project");
      },
      binding: async (db) => {
        if (!(await isTeamProject(db, teamId, projectId))) throw new DomainError("RESOURCE_NOT_FOUND", "Team does not own that project");
        return teamProjectRemoveBinding({ id: organizationId }, team, await readProjectName(db, organizationId, projectId));
      },
      authorizeIn: options.authorizeIn,
    });
    const res = await db.query(
      "DELETE FROM team_projects WHERE team_id = $1 AND project_id = $2 RETURNING team_id",
      [teamId, projectId],
    );
    if (!res.rows[0]) throw new DomainError("RESOURCE_NOT_FOUND", "Team does not own that project");
    // Report mode (ADR-0054 Decision 9), before the audit insert.
    await prepared.count(db);
    await recordAuditEvent(db, {
      eventType: "team.project_removed",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "policy.manage",
      resource: { groupId: teamId, projectId },
      ...(prepared.approval ? { metadata: approvalMetadata(prepared.approval) } : {}),
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
