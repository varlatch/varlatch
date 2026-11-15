-- Projects and environments (domain/projects.ts without deletion,
-- domain/environments.ts; ADR-0059 step 4.1c). The lookups by slug, name
-- or ID are values.sql's LiveProject and LiveEnvironment.

-- name: ListLiveProjects :many
-- listProjects: the Organization's live Projects, oldest first.
SELECT id, organization_id, slug, name, contract_authority, active_contract_revision_id, created_at FROM projects
WHERE organization_id = ? AND deleted_at IS NULL ORDER BY created_at, id;

-- name: LiveProjectSlugTaken :one
-- A live Project of the Organization has the slug (projects_live_slug):
-- checked before the insert, which the TypeScript server leaves to the
-- unique index.
SELECT count(*) FROM projects WHERE organization_id = ? AND slug = ? AND deleted_at IS NULL;

-- name: InsertProject :exec
INSERT INTO projects (id, organization_id, slug, name, contract_authority, created_at) VALUES (?, ?, ?, ?, ?, ?);

-- name: ProjectNames :one
-- renameProject's read of the slug and the name it replaces.
SELECT slug, name FROM projects WHERE organization_id = ? AND id = ?;

-- name: RenameProject :exec
UPDATE projects SET name = ? WHERE id = ?;

-- name: ListLiveEnvironments :many
-- listEnvironments: the Project's live environments, oldest first.
SELECT id, project_id, name, kind, tier, parent_environment_id, owner_identity_id, expires_at, created_at FROM environments
WHERE project_id = ? AND deleted_at IS NULL ORDER BY created_at, id;

-- name: LiveEnvironmentNameTaken :one
-- environments_live_name_key, checked before the insert.
SELECT count(*) FROM environments WHERE project_id = ? AND name = ? AND deleted_at IS NULL;

-- name: InsertEnvironment :exec
INSERT INTO environments (id, project_id, name, kind, tier, parent_environment_id, owner_identity_id, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: LiveChildEnvironmentNames :many
-- deleteEnvironment: the live environments derived from one, by name. The
-- TypeScript query has no ORDER BY: PostgreSQL answers in heap order, which
-- tuple pruning and space reuse change (go/README.md, Known TypeScript
-- defects).
SELECT name FROM environments WHERE parent_environment_id = ? AND deleted_at IS NULL ORDER BY name;

-- name: DeleteEnvironment :execrows
UPDATE environments SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL;

-- name: DeleteValuesOfEnvironment :exec
UPDATE env_values SET deleted_at = ?, current_version_id = NULL WHERE environment_id = ? AND deleted_at IS NULL;

-- name: RevokeCapabilitiesOfEnvironment :execrows
UPDATE capabilities SET revoked_at = ? WHERE environment_id = ? AND revoked_at IS NULL;
