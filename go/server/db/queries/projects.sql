-- Projects and environments (domain/projects.ts,
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
-- Seeds of one-time codes (ADR-0061) included, which have both columns set.
UPDATE env_values SET deleted_at = ?, current_version_id = NULL
WHERE environment_id = ? AND (deleted_at IS NULL OR current_version_id IS NOT NULL);

-- name: RevokeCapabilitiesOfEnvironment :execrows
UPDATE capabilities SET revoked_at = ? WHERE environment_id = ? AND revoked_at IS NULL;

-- Project deletion (deleteProject, ADR-0051 Decision 2; ADR-0059 step
-- 4.12a). Every row of the Project's environments, live or not, as the
-- TypeScript server's envIds holds them all.

-- name: ProjectForDeletion :one
-- readProjectForDeletion: a live Project of the Organization, with its
-- live environments counted.
SELECT p.id, p.slug, p.name,
  (SELECT count(*) FROM environments e WHERE e.project_id = p.id AND e.deleted_at IS NULL) AS environments
FROM projects p WHERE p.id = ? AND p.organization_id = ? AND p.deleted_at IS NULL;

-- name: DeleteDerivedEnvironmentsOfProject :exec
-- Derived environments first, then roots: an order of updates only.
UPDATE environments SET deleted_at = ? WHERE project_id = ? AND deleted_at IS NULL AND parent_environment_id IS NOT NULL;

-- name: DeleteEnvironmentsOfProject :exec
UPDATE environments SET deleted_at = ? WHERE project_id = ? AND deleted_at IS NULL;

-- name: DeleteValuesOfProject :execrows
-- Every value of the Project, its version pointers and rotation cleared;
-- one deleted before keeps its deletion time.
UPDATE env_values SET deleted_at = COALESCE(deleted_at, @deleted_at), current_version_id = NULL,
  retiring_version_id = NULL, rotation_deadline = NULL, rotation_started_at = NULL
WHERE environment_id IN (SELECT e.id FROM environments e WHERE e.project_id = @project_id);

-- name: EraseVersionsOfProject :execrows
-- The versions' ciphertext and wrapped keys erased from the live database.
UPDATE value_versions SET payload = NULL, wrapped_dek = NULL, erased_at = @erased_at
WHERE erased_at IS NULL AND value_id IN (
  SELECT v.id FROM env_values v JOIN environments e ON e.id = v.environment_id WHERE e.project_id = @project_id);

-- name: RevokeCapabilitiesOfProject :execrows
UPDATE capabilities SET revoked_at = @revoked_at
WHERE revoked_at IS NULL AND environment_id IN (SELECT e.id FROM environments e WHERE e.project_id = @project_id);

-- name: RevokeSyncTargetsOfProject :execrows
-- Revocation fences a push in progress (ADR-0050 Decision 1) and releases
-- the destination claim.
UPDATE sync_targets SET revoked_at = @revoked_at, generation = generation + 1, lease_expires_at = NULL,
  repair_cycle_started_at = NULL, version = version + 1, updated_at = @revoked_at
WHERE project_id = @project_id AND revoked_at IS NULL;

-- name: DeleteTeamLinksOfProject :execrows
DELETE FROM team_projects WHERE project_id = ?;

-- name: MarkProjectDeleted :exec
UPDATE projects SET deleted_at = ? WHERE id = ?;
