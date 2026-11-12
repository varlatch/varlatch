// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Querier } from "../db/migrate.js";
import { canonicalJson, type ApprovalBinding, type ApprovalChange, type ApprovalOperation } from "./approvals.js";
import { DomainError } from "./errors.js";
import type { AdminStepUpOperation } from "./securityreport.js";
import { labelWithId, list, quoted, quotedList, unnamed } from "./approvallabels.js";

/**
 * admin-step-up for the access structure (ADR-0054 Decision 5, step 4.6):
 * what an approval binds for each operation on Grants, roles, groups and
 * teams, their memberships and Team-Project links, per the binding
 * catalogue, and the summary its approver reads. None of these requests
 * carries a secret. Each binds the query `{}` (no route reads one).
 *
 * - grant.create: target the Organization; body the normalized declaration
 *   (`subject` `{identityId}` or `{groupId}`; `scope` as parsed, its
 *   `environmentIds` as a set; `permission` `{actions}` as a set, or
 *   `{roleId}`); no version.
 * - grant.replace: target the old Grant; body the complete normalized
 *   replacement; no version (the old Grant's id pins it: Grants are
 *   immutable). A replacement identical to the old declaration (sets
 *   compared as sets) needs no approval.
 * - grant.revoke: target the Grant; no body; no version.
 * - role.create: target the Organization; body `name` and `actions` (set).
 * - role.update: target the role; body the resulting `name` and `actions`
 *   (set); the version the request expects. A patch that changes neither
 *   (a reordering of the actions included) needs no approval.
 * - role.delete: target the role; no body; the version the server reads,
 *   checked again under the role's row lock.
 * - group.create / team.create: target the Organization; body `kind`, `name`.
 * - group.update / team.update: target the group; body the resulting
 *   `name`; the version the request expects.
 * - group.delete / team.delete: target the group; no body; the version the
 *   server reads, checked again under the group's row lock.
 * - group.member_add / team.member_add, group.member_remove /
 *   team.member_remove: target the group and the identity; no body; no
 *   version. Adding a current member changes nothing and needs none.
 * - team.project_add / team.project_remove: target the team and the
 *   project; no body; no version. Adding a linked project changes nothing
 *   and needs none.
 *
 * Group or team comes from the stored row: a team reached through a
 * `/groups/` route is `team.*`.
 */

const set = (values: readonly string[]) => [...new Set(values)].sort();
const added = (field: string, to: string): ApprovalChange => ({ field, from: null, to, loosens: false });
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

export type GroupKind = "group" | "team";

/** `group.update` or `team.update`, from the stored kind. */
export function groupOperation(
  kind: GroupKind,
  verb: "create" | "update" | "delete" | "member_add" | "member_remove",
): ApprovalOperation & AdminStepUpOperation {
  return `${kind}.${verb}`;
}

// ---- Grants

export type GrantScope =
  | { kind: "organization" }
  | { kind: "project"; projectId: string }
  | {
      kind: "environments";
      projectId: string;
      selector: { kind: "environments"; environmentIds: string[] } | { kind: "tier"; tier: string };
    }
  | { kind: "team"; teamId: string };

/** A Grant declaration as the routes take it: exactly one subject, exactly one permission. */
export interface GrantDeclaration {
  subjectIdentityId?: string | null | undefined;
  subjectGroupId?: string | null | undefined;
  scope: GrantScope;
  actions?: string[] | null | undefined;
  roleId?: string | null | undefined;
}

/** The bound form of a declaration: sets sorted and without duplicates. */
export function normalizedGrant(d: GrantDeclaration) {
  const scope: unknown =
    d.scope.kind === "environments" && d.scope.selector.kind === "environments"
      ? { kind: "environments", projectId: d.scope.projectId, selector: { kind: "environments", environmentIds: set(d.scope.selector.environmentIds) } }
      : d.scope;
  return {
    subject: d.subjectIdentityId ? { identityId: d.subjectIdentityId } : { groupId: d.subjectGroupId ?? null },
    scope,
    permission: d.roleId ? { roleId: d.roleId } : { actions: set(d.actions ?? []) },
  };
}

/** Whether two declarations mean the same Grant (key order, the order of a set and duplicates aside). */
export function sameGrant(a: GrantDeclaration, b: GrantDeclaration): boolean {
  return canonicalJson(normalizedGrant(a)) === canonicalJson(normalizedGrant(b));
}

export interface StoredGrant extends GrantDeclaration {
  id: string;
  revoked: boolean;
}

/** A Grant of the Organization, live or not, read without a lock; null when there is none. */
export async function readGrant(db: Querier, organizationId: string, grantId: string): Promise<StoredGrant | null> {
  const row = (await db.query(
    `SELECT id, subject_identity_id, subject_group_id, scope, actions, role_id, revoked_at IS NOT NULL AS revoked
     FROM grants WHERE id = $1 AND organization_id = $2`,
    [grantId, organizationId],
  )).rows[0] as
    | { id: string; subject_identity_id: string | null; subject_group_id: string | null; scope: unknown; actions: string[] | null; role_id: string | null; revoked: boolean }
    | undefined;
  return row ? storedGrant(row) : null;
}

/** A grants row as a declaration. */
export function storedGrant(row: {
  id: string;
  subject_identity_id: string | null;
  subject_group_id: string | null;
  scope: unknown;
  actions: string[] | null;
  role_id: string | null;
  revoked?: boolean;
}): StoredGrant {
  return {
    id: row.id,
    subjectIdentityId: row.subject_identity_id,
    subjectGroupId: row.subject_group_id,
    scope: (typeof row.scope === "string" ? JSON.parse(row.scope) : row.scope) as GrantScope,
    actions: row.actions,
    roleId: row.role_id,
    revoked: row.revoked ?? false,
  };
}

/**
 * The refusal requireGrantSubject (policy.ts) makes, without its lock: a
 * machine of this Organization, or a person with a live membership. It is
 * checked again, pinned, in the operation's transaction.
 */
export async function checkGrantSubject(db: Querier, organizationId: string, identityId: string): Promise<void> {
  const row = (await db.query(
    `SELECT i.kind, i.organization_id,
            EXISTS (SELECT 1 FROM org_memberships m WHERE m.organization_id = $2 AND m.identity_id = i.id AND m.removed_at IS NULL) AS member
     FROM identities i WHERE i.id = $1`,
    [identityId, organizationId],
  )).rows[0] as { kind: string; organization_id: string | null; member: boolean } | undefined;
  const ok = row !== undefined && (row.kind === "human" ? row.member : row.organization_id === organizationId);
  if (!ok) throw new DomainError("RESOURCE_NOT_FOUND", "Identity not in this organization");
}

/**
 * What declarations refer to, in this Organization, as summaries write
 * them: each with its bound id, always (approvallabels.ts). An id of
 * nothing here is written alone.
 */
interface Names {
  identities: Map<string, string>;
  groups: Map<string, { label: string; kind: GroupKind }>;
  roles: Map<string, string>;
  projects: Map<string, string>;
  environments: Map<string, string>;
}

async function namesFor(db: Querier, organizationId: string, decls: readonly GrantDeclaration[]): Promise<Names> {
  const ids = { identities: new Set<string>(), groups: new Set<string>(), roles: new Set<string>(), projects: new Set<string>(), environments: new Set<string>() };
  for (const d of decls) {
    if (d.subjectIdentityId) ids.identities.add(d.subjectIdentityId);
    if (d.subjectGroupId) ids.groups.add(d.subjectGroupId);
    if (d.roleId) ids.roles.add(d.roleId);
    if (d.scope.kind === "team") ids.groups.add(d.scope.teamId);
    if (d.scope.kind === "project" || d.scope.kind === "environments") ids.projects.add(d.scope.projectId);
    if (d.scope.kind === "environments" && d.scope.selector.kind === "environments") {
      for (const e of d.scope.selector.environmentIds) ids.environments.add(e);
    }
  }
  const q = async (sql: string, list: Set<string>) => (list.size === 0 ? [] : ((await db.query(sql, [[...list], organizationId])).rows as Record<string, string>[]));
  const identities = await q(
    `SELECT i.id, i.name FROM identities i WHERE i.id = ANY($1)
       AND (i.organization_id = $2 OR EXISTS (SELECT 1 FROM org_memberships m WHERE m.organization_id = $2 AND m.identity_id = i.id))`,
    ids.identities,
  );
  const groups = await q("SELECT id, name, kind FROM groups WHERE id = ANY($1) AND organization_id = $2", ids.groups);
  const roles = await q("SELECT id, name FROM roles WHERE id = ANY($1) AND organization_id = $2", ids.roles);
  const projects = await q("SELECT id, slug FROM projects WHERE id = ANY($1) AND organization_id = $2", ids.projects);
  const environments = await q(
    `SELECT e.id, p.slug || '/' || e.name AS name FROM environments e JOIN projects p ON p.id = e.project_id
     WHERE e.id = ANY($1) AND p.organization_id = $2`,
    ids.environments,
  );
  return {
    identities: new Map(identities.map((r) => [r.id!, labelWithId(null, r.name!, r.id!)])),
    groups: new Map(groups.map((r) => [r.id!, { label: labelWithId(r.kind!, r.name!, r.id!), kind: r.kind as GroupKind }])),
    roles: new Map(roles.map((r) => [r.id!, labelWithId("role", r.name!, r.id!)])),
    projects: new Map(projects.map((r) => [r.id!, labelWithId("project", r.slug!, r.id!)])),
    environments: new Map(environments.map((r) => [r.id!, labelWithId(null, r.name!, r.id!)])),
  };
}

function describeSubject(d: GrantDeclaration, n: Names): string {
  if (d.subjectIdentityId) return n.identities.get(d.subjectIdentityId) ?? unnamed("identity", d.subjectIdentityId);
  return n.groups.get(d.subjectGroupId ?? "")?.label ?? unnamed("group", d.subjectGroupId ?? "");
}

function describeScope(d: GrantDeclaration, n: Names): string {
  const s = d.scope;
  switch (s.kind) {
    case "organization":
      return "the whole organization";
    case "project":
      return n.projects.get(s.projectId) ?? unnamed("project", s.projectId);
    case "environments": {
      const project = n.projects.get(s.projectId) ?? unnamed("project", s.projectId);
      if (s.selector.kind === "tier") return `the ${s.selector.tier} environments of ${project}`;
      return `environments ${list(set(s.selector.environmentIds.map((id) => n.environments.get(id) ?? unnamed("environment", id))))}`;
    }
    case "team":
      return `the projects of ${n.groups.get(s.teamId)?.label ?? unnamed("team", s.teamId)}`;
  }
}

function describePermission(d: GrantDeclaration, n: Names): string {
  if (d.roleId) return n.roles.get(d.roleId) ?? unnamed("role", d.roleId);
  return `actions ${quotedList(set(d.actions ?? []))}`;
}

const describeGrant = (d: GrantDeclaration, n: Names) => ({
  subject: describeSubject(d, n),
  scope: describeScope(d, n),
  permission: describePermission(d, n),
});

/** grant.create. */
export async function grantCreateBinding(db: Querier, org: { id: string }, decl: GrantDeclaration): Promise<ApprovalBinding> {
  const g = describeGrant(decl, await namesFor(db, org.id, [decl]));
  return {
    operation: "grant.create",
    organizationId: org.id,
    target: { organizationId: org.id },
    body: normalizedGrant(decl),
    query: {},
    expectedVersion: null,
    summary: {
      title: `Grant ${g.permission} on ${g.scope} to ${g.subject}`,
      changes: [added("subject", g.subject), added("scope", g.scope), added("permission", g.permission)],
    },
  };
}

/** grant.replace of a live Grant by a replacement that differs from it. */
export async function grantReplaceBinding(db: Querier, org: { id: string }, old: StoredGrant, next: GrantDeclaration): Promise<ApprovalBinding> {
  const names = await namesFor(db, org.id, [old, next]);
  const before = describeGrant(old, names);
  const after = describeGrant(next, names);
  // What changed is decided on the bound form (ids, sets), never on the
  // labels: a part that changed is always listed, and when its two labels
  // still read the same, both carry what is bound.
  const from = normalizedGrant(old);
  const to = normalizedGrant(next);
  const changes: ApprovalChange[] = [];
  for (const field of ["subject", "scope", "permission"] as const) {
    const [a, b] = [canonicalJson(from[field]), canonicalJson(to[field])];
    if (a === b) continue;
    const same = before[field] === after[field];
    changes.push({ field, from: same ? `${before[field]} ${a}` : before[field], to: same ? `${after[field]} ${b}` : after[field], loosens: false });
  }
  return {
    operation: "grant.replace",
    organizationId: org.id,
    target: { grantId: old.id },
    body: normalizedGrant(next),
    query: {},
    expectedVersion: null,
    summary: { title: `Change the Grant ${old.id} of ${before.permission} on ${before.scope} to ${before.subject}`, changes },
  };
}

/** grant.revoke of a live Grant. */
export async function grantRevokeBinding(db: Querier, org: { id: string }, grant: StoredGrant): Promise<ApprovalBinding> {
  const g = describeGrant(grant, await namesFor(db, org.id, [grant]));
  return {
    operation: "grant.revoke",
    organizationId: org.id,
    target: { grantId: grant.id },
    body: null,
    query: {},
    expectedVersion: null,
    summary: { title: `Revoke the Grant ${grant.id} of ${g.permission} on ${g.scope} to ${g.subject}`, changes: [] },
  };
}

// ---- Roles

export interface RoleRef {
  id: string;
  name: string;
  actions: string[];
  version: number;
}

/** A live role of the Organization, read without a lock; null when there is none. */
export async function readRole(db: Querier, organizationId: string, roleId: string): Promise<RoleRef | null> {
  const row = (await db.query(
    "SELECT id, name, actions, version FROM roles WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL",
    [roleId, organizationId],
  )).rows[0] as RoleRef | undefined;
  return row ?? null;
}

/** Whether a role's resulting state means the same as its current one: same name, same set of actions. */
export function sameRole(a: { name: string; actions: readonly string[] }, b: { name: string; actions: readonly string[] }): boolean {
  return a.name === b.name && canonicalJson(set(a.actions)) === canonicalJson(set(b.actions));
}

/**
 * Refuses a name a live role, or a live group or team, of the Organization
 * already has (the unique indexes the write would hit), before an approval
 * is asked for. `except` is the row being renamed.
 */
export async function refuseTakenName(
  db: Querier,
  table: "roles" | "groups",
  organizationId: string,
  name: string,
  except: string | null,
  message: string,
): Promise<void> {
  const taken = (await db.query(
    `SELECT 1 FROM ${table} WHERE organization_id = $1 AND name = $2 AND revoked_at IS NULL AND id IS DISTINCT FROM $3`,
    [organizationId, name, except],
  )).rows[0];
  if (taken) throw new DomainError("VALIDATION_FAILED", message);
}

/** role.create. */
export function roleCreateBinding(org: { id: string }, input: { name: string; actions: readonly string[] }): ApprovalBinding {
  const actions = set(input.actions);
  return {
    operation: "role.create",
    organizationId: org.id,
    target: { organizationId: org.id },
    body: { name: input.name, actions },
    query: {},
    expectedVersion: null,
    summary: {
      title: `Create role ${quoted(input.name)} with actions ${quotedList(actions)}`,
      changes: [added("name", quoted(input.name)), added("actions", quotedList(actions))],
    },
  };
}

/** role.update that changes the role: its resulting state, the version the request expects. */
export async function roleUpdateBinding(
  db: Querier,
  org: { id: string },
  current: RoleRef,
  next: { name: string; actions: readonly string[] },
  expectedVersion: number,
): Promise<ApprovalBinding> {
  const grants = ((await db.query(
    "SELECT count(*)::int AS n FROM grants WHERE role_id = $1 AND organization_id = $2 AND revoked_at IS NULL",
    [current.id, org.id],
  )).rows[0] as { n: number }).n;
  const before = new Set(current.actions);
  const after = new Set(next.actions);
  const gained = set([...after].filter((a) => !before.has(a)));
  const lost = set([...before].filter((a) => !after.has(a)));
  const changes: ApprovalChange[] = [];
  if (next.name !== current.name) changes.push({ field: "name", from: quoted(current.name), to: quoted(next.name), loosens: false });
  if (gained.length > 0) changes.push({ field: "actionsAdded", from: null, to: quotedList(gained), loosens: true });
  if (lost.length > 0) changes.push({ field: "actionsRemoved", from: quotedList(lost), to: null, loosens: false });
  return {
    operation: "role.update",
    organizationId: org.id,
    target: { roleId: current.id },
    body: { name: next.name, actions: set(next.actions) },
    query: {},
    expectedVersion,
    summary: { title: `Change ${labelWithId("role", current.name, current.id)}, which ${plural(grants, "Grant")} use${grants === 1 ? "s" : ""}`, changes },
  };
}

/** role.delete of a live role, at the version the server read. */
export function roleDeleteBinding(org: { id: string }, role: RoleRef): ApprovalBinding {
  return {
    operation: "role.delete",
    organizationId: org.id,
    target: { roleId: role.id },
    body: null,
    query: {},
    expectedVersion: role.version,
    summary: { title: `Delete ${labelWithId("role", role.name, role.id)}`, changes: [] },
  };
}

// ---- Groups and teams

export interface GroupRef {
  id: string;
  name: string;
  kind: GroupKind;
  version: number;
}

/** A live group or team of the Organization (of `kind`, when given), read without a lock; null when there is none. */
export async function readGroup(db: Querier, organizationId: string, groupId: string, kind?: GroupKind): Promise<GroupRef | null> {
  const row = (await db.query(
    "SELECT id, name, kind, version FROM groups WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL",
    [groupId, organizationId],
  )).rows[0] as GroupRef | undefined;
  return row && (!kind || row.kind === kind) ? row : null;
}

/** group.create / team.create. */
export function groupCreateBinding(org: { id: string }, input: { name: string; kind: GroupKind }): ApprovalBinding {
  return {
    operation: groupOperation(input.kind, "create"),
    organizationId: org.id,
    target: { organizationId: org.id },
    body: { kind: input.kind, name: input.name },
    query: {},
    expectedVersion: null,
    summary: { title: `Create ${input.kind} ${quoted(input.name)}`, changes: [added("name", quoted(input.name))] },
  };
}

/** group.update / team.update: a rename, at the version the request expects. */
export function groupUpdateBinding(org: { id: string }, group: GroupRef, name: string, expectedVersion: number): ApprovalBinding {
  return {
    operation: groupOperation(group.kind, "update"),
    organizationId: org.id,
    target: { groupId: group.id },
    body: { name },
    query: {},
    expectedVersion,
    summary: {
      title: `Rename ${labelWithId(group.kind, group.name, group.id)} to ${quoted(name)}`,
      changes: [{ field: "name", from: quoted(group.name), to: quoted(name), loosens: false }],
    },
  };
}

/** group.delete / team.delete, at the version the server read. */
export async function groupDeleteBinding(db: Querier, org: { id: string }, group: GroupRef): Promise<ApprovalBinding> {
  const members = ((await db.query("SELECT count(*)::int AS n FROM group_members WHERE group_id = $1", [group.id])).rows[0] as { n: number }).n;
  return {
    operation: groupOperation(group.kind, "delete"),
    organizationId: org.id,
    target: { groupId: group.id },
    body: null,
    query: {},
    expectedVersion: group.version,
    summary: { title: `Delete ${labelWithId(group.kind, group.name, group.id)}. Its ${plural(members, "member")} lose${members === 1 ? "s" : ""} what its Grants gave them`, changes: [] },
  };
}

/** An identity as a summary names it (with labelWithId). */
export interface PersonRef {
  id: string;
  name: string;
}

/**
 * The identity a membership may be added for, as addGroupMember checks it
 * (without its pin): a live machine of this Organization, or a person with
 * a live membership. Null otherwise.
 */
export async function readEligibleMember(db: Querier, organizationId: string, identityId: string): Promise<PersonRef | null> {
  const row = (await db.query(
    `SELECT i.id, i.name FROM identities i
     WHERE i.id = $1 AND NOT i.disabled
       AND ((i.kind <> 'human' AND i.organization_id = $2)
         OR (i.kind = 'human' AND EXISTS (SELECT 1 FROM org_memberships m WHERE m.organization_id = $2 AND m.identity_id = i.id AND m.removed_at IS NULL)))`,
    [identityId, organizationId],
  )).rows[0] as PersonRef | undefined;
  return row ?? null;
}

/** An identity's name, whatever its state; its id when there is none. */
export async function readPerson(db: Querier, identityId: string): Promise<PersonRef> {
  const row = (await db.query("SELECT id, name FROM identities WHERE id = $1", [identityId])).rows[0] as PersonRef | undefined;
  return row ?? { id: identityId, name: identityId };
}

/** Whether the identity is a member of the group, read without a lock. */
export async function isGroupMember(db: Querier, groupId: string, identityId: string): Promise<boolean> {
  return (await db.query("SELECT 1 FROM group_members WHERE group_id = $1 AND identity_id = $2", [groupId, identityId])).rows.length > 0;
}

/** group.member_add / team.member_add of an identity not yet a member. */
export function memberAddBinding(org: { id: string }, group: { id: string; name: string; kind: GroupKind }, person: PersonRef): ApprovalBinding {
  return {
    operation: groupOperation(group.kind, "member_add"),
    organizationId: org.id,
    target: { groupId: group.id, identityId: person.id },
    body: null,
    query: {},
    expectedVersion: null,
    summary: { title: `Add ${labelWithId(null, person.name, person.id)} to ${labelWithId(group.kind, group.name, group.id)}`, changes: [] },
  };
}

/** group.member_remove / team.member_remove of a current member. */
export function memberRemoveBinding(org: { id: string }, group: { id: string; name: string; kind: GroupKind }, person: PersonRef): ApprovalBinding {
  return {
    operation: groupOperation(group.kind, "member_remove"),
    organizationId: org.id,
    target: { groupId: group.id, identityId: person.id },
    body: null,
    query: {},
    expectedVersion: null,
    summary: { title: `Remove ${labelWithId(null, person.name, person.id)} from ${labelWithId(group.kind, group.name, group.id)}`, changes: [] },
  };
}

// ---- Team-Project links

export interface ProjectRef {
  id: string;
  name: string;
  slug: string;
}

/** A live Project of the Organization, read without a lock; null when there is none. */
export async function readLiveProject(db: Querier, organizationId: string, projectId: string): Promise<ProjectRef | null> {
  const row = (await db.query(
    "SELECT id, name, slug FROM projects WHERE id = $1 AND organization_id = $2 AND deleted_at IS NULL",
    [projectId, organizationId],
  )).rows[0] as ProjectRef | undefined;
  return row ?? null;
}

/** A Project of the Organization as a summary names it, whatever its state; its id when there is none. */
export async function readProjectName(db: Querier, organizationId: string, projectId: string): Promise<ProjectRef> {
  const row = (await db.query("SELECT id, name, slug FROM projects WHERE id = $1 AND organization_id = $2", [projectId, organizationId])).rows[0] as
    | ProjectRef
    | undefined;
  return row ?? { id: projectId, name: projectId, slug: projectId };
}

/** Whether the team is linked to the project, read without a lock. */
export async function isTeamProject(db: Querier, teamId: string, projectId: string): Promise<boolean> {
  return (await db.query("SELECT 1 FROM team_projects WHERE team_id = $1 AND project_id = $2", [teamId, projectId])).rows.length > 0;
}

/** team.project_add of a project the team is not linked to. */
export function teamProjectAddBinding(org: { id: string }, team: { id: string; name: string }, project: ProjectRef): ApprovalBinding {
  return {
    operation: "team.project_add",
    organizationId: org.id,
    target: { teamId: team.id, projectId: project.id },
    body: null,
    query: {},
    expectedVersion: null,
    summary: { title: `Give ${labelWithId("team", team.name, team.id)} the ${labelWithId("project", project.slug, project.id)}`, changes: [] },
  };
}

/** team.project_remove of a linked project. */
export function teamProjectRemoveBinding(org: { id: string }, team: { id: string; name: string }, project: ProjectRef): ApprovalBinding {
  return {
    operation: "team.project_remove",
    organizationId: org.id,
    target: { teamId: team.id, projectId: project.id },
    body: null,
    query: {},
    expectedVersion: null,
    summary: { title: `Take the ${labelWithId("project", project.slug, project.id)} from ${labelWithId("team", team.name, team.id)}`, changes: [] },
  };
}
