-- The access structure: Grants, Roles, Groups and Teams, their memberships
-- and Team-Project links (http/app.ts, domain/policy.ts, accessstepup.ts;
-- ADR-0015, ADR-0028, ADR-0029; ADR-0059 step 4.4b). Every time written is
-- varlatchd's clock, passed in.

-- name: OrganizationGrants :many
-- listGrants: the live Grants, oldest first.
SELECT id, organization_id, subject_identity_id, subject_group_id, scope, actions, role_id, created_at
FROM grants WHERE organization_id = ? AND revoked_at IS NULL ORDER BY created_at, id;

-- name: GrantOf :one
-- readGrant: a Grant of the Organization, live or not.
SELECT id, subject_identity_id, subject_group_id, scope, actions, role_id, revoked_at
FROM grants WHERE id = ? AND organization_id = ?;

-- name: InsertGrant :exec
INSERT INTO grants (id, organization_id, subject_identity_id, subject_group_id, scope, actions, role_id, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: RevokeGrant :many
-- A live Grant revoked; no row when there was none.
UPDATE grants SET revoked_at = sqlc.arg(revoked_at)
WHERE id = sqlc.arg(id) AND organization_id = sqlc.arg(organization_id) AND revoked_at IS NULL RETURNING id;

-- name: GrantSubject :one
-- checkGrantSubject: the identity's kind and Organization, and whether it
-- has a live membership in this one.
SELECT i.kind, i.organization_id,
  EXISTS (SELECT 1 FROM org_memberships m WHERE m.organization_id = sqlc.arg(organization_id) AND m.identity_id = i.id AND m.removed_at IS NULL) AS member
FROM identities i WHERE i.id = sqlc.arg(id);

-- name: NamedIdentities :many
-- namesFor: identities of the Organization, machines or (past) members.
-- In every Named query the Organization comes before the list: sqlc
-- numbers it (?1), and a numbered parameter after sqlc.slice would take
-- the list's second element once the list has two.
SELECT i.id, i.name FROM identities i
WHERE (i.organization_id = sqlc.arg(organization_id)
    OR EXISTS (SELECT 1 FROM org_memberships m WHERE m.organization_id = sqlc.arg(organization_id) AND m.identity_id = i.id))
  AND i.id IN (sqlc.slice(ids));

-- name: NamedGroups :many
SELECT id, name, kind FROM groups WHERE organization_id = sqlc.arg(organization_id) AND id IN (sqlc.slice(ids));

-- name: NamedRoles :many
SELECT id, name FROM roles WHERE organization_id = sqlc.arg(organization_id) AND id IN (sqlc.slice(ids));

-- name: NamedProjects :many
SELECT id, slug FROM projects WHERE organization_id = sqlc.arg(organization_id) AND id IN (sqlc.slice(ids));

-- name: NamedEnvironments :many
SELECT e.id, p.slug || '/' || e.name AS name FROM environments e JOIN projects p ON p.id = e.project_id
WHERE p.organization_id = sqlc.arg(organization_id) AND e.id IN (sqlc.slice(ids));

-- name: OrganizationRoles :many
-- listRoles: by name (byte order).
SELECT id, name, actions, version, updated_at FROM roles
WHERE organization_id = ? AND revoked_at IS NULL ORDER BY name;

-- name: LiveRole :one
-- readRole: a live role of the Organization.
SELECT id, name, actions, version, updated_at FROM roles
WHERE id = ? AND organization_id = ? AND revoked_at IS NULL;

-- name: RoleNameTaken :one
-- refuseTakenName on roles: another live role with that name.
SELECT count(*) FROM roles
WHERE organization_id = sqlc.arg(organization_id) AND name = sqlc.arg(name) AND revoked_at IS NULL AND id IS NOT sqlc.arg(except_id);

-- name: InsertRole :exec
INSERT INTO roles (id, organization_id, name, actions, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?);

-- name: UpdateRole :one
UPDATE roles SET name = sqlc.arg(name), actions = sqlc.arg(actions), version = version + 1, updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) RETURNING version, updated_at;

-- name: RevokeRole :exec
UPDATE roles SET revoked_at = ? WHERE id = ?;

-- name: RoleGrantCount :one
-- The live Grants that cite a role.
SELECT count(*) FROM grants WHERE role_id = ? AND organization_id = ? AND revoked_at IS NULL;

-- name: OrganizationGroups :many
-- listGroups: the live groups (or teams), by name (byte order).
SELECT id, name, kind, version, updated_at FROM groups
WHERE organization_id = ? AND kind = ? AND revoked_at IS NULL ORDER BY name;

-- name: LiveGroup :one
-- readGroup and requireGroup: a live group or team of the Organization.
SELECT id, name, kind, version, updated_at FROM groups
WHERE id = ? AND organization_id = ? AND revoked_at IS NULL;

-- name: GroupKindOf :one
-- The stored kind of a group of the Organization, live or not.
SELECT kind FROM groups WHERE id = ? AND organization_id = ?;

-- name: GroupNameTaken :one
-- refuseTakenName on groups (groups and teams share their names).
SELECT count(*) FROM groups
WHERE organization_id = sqlc.arg(organization_id) AND name = sqlc.arg(name) AND revoked_at IS NULL AND id IS NOT sqlc.arg(except_id);

-- name: InsertGroup :exec
INSERT INTO groups (id, organization_id, name, kind, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?);

-- name: RenameGroup :one
UPDATE groups SET name = sqlc.arg(name), version = version + 1, updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) RETURNING version, updated_at;

-- name: RevokeGroup :exec
UPDATE groups SET revoked_at = ? WHERE id = ?;

-- name: GroupMemberCount :one
SELECT count(*) FROM group_members WHERE group_id = ?;

-- name: EligibleMember :one
-- readEligibleMember: a live machine of the Organization, or a person with
-- a live membership.
SELECT i.id, i.name FROM identities i
WHERE i.id = sqlc.arg(id) AND NOT i.disabled
  AND ((i.kind <> 'human' AND i.organization_id = sqlc.arg(organization_id))
    OR (i.kind = 'human' AND EXISTS (SELECT 1 FROM org_memberships m
      WHERE m.organization_id = sqlc.arg(organization_id) AND m.identity_id = i.id AND m.removed_at IS NULL)));

-- name: EnabledMemberKind :one
-- addGroupMember's check under its locks: an enabled identity of the
-- Organization, or a person.
SELECT kind FROM identities
WHERE id = sqlc.arg(id) AND NOT disabled AND (organization_id = sqlc.arg(organization_id) OR kind = 'human');

-- name: PinLiveMembership :many
-- pinLiveMembership: the person's live membership, its version moved on,
-- so an approval bound to the earlier version (a removal, a role change)
-- no longer holds. No row: no live membership.
UPDATE org_memberships SET version = version + 1
WHERE organization_id = ? AND identity_id = ? AND removed_at IS NULL RETURNING role;

-- name: IdentityRef :one
-- readPerson: an identity's name, whatever its state.
SELECT id, name FROM identities WHERE id = ?;

-- name: IsGroupMember :one
SELECT count(*) FROM group_members WHERE group_id = ? AND identity_id = ?;

-- name: AddGroupMember :many
-- A membership added; no row when it was there.
INSERT INTO group_members (group_id, identity_id, created_at) VALUES (?, ?, ?)
ON CONFLICT DO NOTHING RETURNING group_id;

-- name: RemoveGroupMember :many
DELETE FROM group_members WHERE group_id = ? AND identity_id = ? RETURNING group_id;

-- name: GroupMembers :many
-- listGroupMembers: oldest first (PostgreSQL's ties in insertion order).
SELECT identity_id FROM group_members WHERE group_id = ? ORDER BY created_at, rowid;

-- name: LiveProjectRef :one
-- readLiveProject.
SELECT id, name, slug FROM projects WHERE id = ? AND organization_id = ? AND deleted_at IS NULL;

-- name: ProjectRef :one
-- readProjectName: a Project of the Organization, whatever its state.
SELECT id, name, slug FROM projects WHERE id = ? AND organization_id = ?;

-- name: IsTeamProject :one
SELECT count(*) FROM team_projects WHERE team_id = ? AND project_id = ?;

-- name: AddTeamProject :many
INSERT INTO team_projects (team_id, project_id, created_at) VALUES (?, ?, ?)
ON CONFLICT DO NOTHING RETURNING team_id;

-- name: RemoveTeamProject :many
DELETE FROM team_projects WHERE team_id = ? AND project_id = ? RETURNING team_id;

-- name: TeamProjectIDs :many
-- listTeamProjects: oldest first (PostgreSQL's ties in insertion order).
SELECT project_id FROM team_projects WHERE team_id = ? ORDER BY created_at, rowid;

-- name: GroupOrganization :one
-- The Organization of a group or team, live or not.
SELECT organization_id FROM groups WHERE id = ?;

-- name: RoleOrganization :one
-- The Organization of a role, live or not.
SELECT organization_id FROM roles WHERE id = ?;
