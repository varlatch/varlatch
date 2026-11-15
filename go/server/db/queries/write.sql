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
