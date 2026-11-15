-- The write path's checks inside a job (go/server/write, the TypeScript
-- lockLiveScope's) and Idempotency-Key claims (withIdempotency).

-- name: OrganizationDeletedAt :one
SELECT deleted_at FROM organizations WHERE id = ?;

-- name: ProjectDeletedAt :one
SELECT deleted_at FROM projects WHERE id = ? AND organization_id = ?;

-- name: LiveEnvironmentsOf :many
SELECT id FROM environments WHERE project_id = sqlc.arg(project_id) AND id IN (sqlc.slice(ids)) AND deleted_at IS NULL;

-- name: IdempotencyClaim :one
SELECT body_hash, response FROM idempotency_keys WHERE identity_id = ? AND endpoint = ? AND idempotency_key = ?;

-- name: InsertIdempotencyClaim :exec
INSERT INTO idempotency_keys (identity_id, endpoint, idempotency_key, body_hash, response) VALUES (?, ?, ?, ?, ?);

-- Organizations (domain/orgs.ts, step 4.1a).

-- name: OrganizationSlugTaken :one
-- The slug is unique across every Organization, deleted ones included
-- (organizations.slug UNIQUE): checked before the insert, which the
-- TypeScript server leaves to the constraint.
SELECT count(*) FROM organizations WHERE slug = ?;

-- name: InsertOrganization :exec
INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES (?, ?, ?, ?);

-- name: InsertOrganizationAdmin :exec
INSERT INTO org_memberships (organization_id, identity_id, role) VALUES (?, ?, 'admin');

-- name: OrganizationNames :one
SELECT slug, name, created_at FROM organizations WHERE id = ?;

-- name: RenameOrganization :exec
UPDATE organizations SET name = ? WHERE id = ?;

-- name: CurrentFreeze :one
-- domain/freeze.ts currentFreeze: the open incident freeze, as members see it.
SELECT f.id, f.frozen_at, f.frozen_by, a.name AS frozen_by_name, f.reason, f.lifted_at, f.lifted_by,
       b.name AS lifted_by_name, f.lift_method
FROM organization_freezes f
JOIN identities a ON a.id = f.frozen_by
LEFT JOIN identities b ON b.id = f.lifted_by
WHERE f.organization_id = ? AND f.lifted_at IS NULL;
