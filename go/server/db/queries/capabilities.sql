-- name: CapabilityAgent :one
-- issueCapability: the named identity, in this Organization.
SELECT id, kind, disabled FROM identities WHERE id = ? AND organization_id = ?;

-- name: InsertCapability :exec
INSERT INTO capabilities
  (id, organization_id, broker_identity_id, agent_identity_id, project_id, environment_id,
   items, destinations, targets, secret_hash, run_id, expires_at, created_by, created_at)
VALUES (sqlc.arg(id), sqlc.arg(organization_id), sqlc.arg(broker_identity_id), sqlc.arg(agent_identity_id),
        sqlc.arg(project_id), sqlc.arg(environment_id), sqlc.arg(items), sqlc.arg(destinations), sqlc.arg(targets),
        sqlc.arg(secret_hash), sqlc.narg(run_id), sqlc.arg(expires_at), sqlc.arg(broker_identity_id), sqlc.arg(created_at));

-- name: ListCapabilities :many
-- listCapabilities: an environment's Capabilities, newest first; a
-- Broker's own only when broker is set.
SELECT * FROM capabilities
WHERE organization_id = sqlc.arg(organization_id) AND environment_id = sqlc.arg(environment_id)
  AND (sqlc.narg(broker) IS NULL OR broker_identity_id = sqlc.narg(broker))
ORDER BY created_at DESC, id;

-- name: LiveCapability :one
-- revokeCapability's existence check: unrevoked, in the Organization, the
-- Broker's own when broker is set (any environment).
SELECT id FROM capabilities
WHERE id = sqlc.arg(id) AND organization_id = sqlc.arg(organization_id) AND revoked_at IS NULL
  AND (sqlc.narg(broker) IS NULL OR broker_identity_id = sqlc.narg(broker));

-- name: RevokeCapability :execrows
UPDATE capabilities SET revoked_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND organization_id = sqlc.arg(organization_id) AND revoked_at IS NULL
  AND (sqlc.narg(broker) IS NULL OR broker_identity_id = sqlc.narg(broker));

-- name: CapabilityOf :one
-- captureExercise: the Capability, in the route's environment.
SELECT * FROM capabilities WHERE id = ? AND organization_id = ? AND environment_id = ?;
