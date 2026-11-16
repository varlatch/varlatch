-- name: OrganizationRequirements :many
-- listRequirements: the live Requirements, oldest first.
SELECT id, kind, target, config, created_at, version, updated_at FROM requirements
WHERE organization_id = ? AND revoked_at IS NULL ORDER BY created_at, id;

-- name: LiveRequirement :one
-- readRequirement: a live Requirement of the Organization.
SELECT id, kind, target, config, created_at, version, updated_at FROM requirements
WHERE id = ? AND organization_id = ? AND revoked_at IS NULL;

-- name: InsertRequirement :exec
INSERT INTO requirements (id, organization_id, kind, target, config, created_by, created_at)
VALUES (?, ?, 'tailnet', ?, ?, ?, ?);

-- name: UpdateRequirement :one
UPDATE requirements SET target = ?, config = ?, version = version + 1, updated_at = ?
WHERE id = ? RETURNING version, updated_at;

-- name: RevokeRequirement :exec
UPDATE requirements SET revoked_at = ? WHERE id = ?;
