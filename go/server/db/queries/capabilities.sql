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

-- name: LiveCapabilitiesOfIdentity :many
-- retireIdentity: the unrevoked Capabilities issued for the identity as
-- Agent or by it as Broker, in id order.
SELECT id FROM capabilities
WHERE (agent_identity_id = sqlc.arg(identity_id) OR broker_identity_id = sqlc.arg(identity_id)) AND revoked_at IS NULL
ORDER BY id;

-- name: RevokeCapabilitiesOfIdentity :exec
UPDATE capabilities SET revoked_at = sqlc.arg(now)
WHERE (agent_identity_id = sqlc.arg(identity_id) OR broker_identity_id = sqlc.arg(identity_id)) AND revoked_at IS NULL;

-- name: RecentlyRetiredIdentities :many
-- revokeCapabilitiesOfRetiredIdentities: per Organization, through
-- audit_events_org_time_idx, the identities retired since since.
SELECT DISTINCT o.id AS organization_id, CAST(json_extract(e.resource, '$.identityId') AS TEXT) AS identity_id
FROM organizations o JOIN audit_events e ON e.organization_id = o.id
WHERE e.occurred_at > sqlc.arg(since) AND e.event_type = 'identity.retired'
  AND json_extract(e.resource, '$.identityId') IS NOT NULL
ORDER BY o.id, identity_id;

-- name: CapabilitiesEndedByRetirement :many
-- revokeCapabilitiesOfRetiredIdentities: the identity's unexpired, unrevoked
-- Capabilities (as Agent or Broker) that one of its retirements since since
-- ends: one after the Capability was issued, or one before it with no
-- reactivation in between.
SELECT c.id FROM capabilities c
WHERE c.organization_id = sqlc.arg(organization_id)
  AND (c.agent_identity_id = sqlc.arg(identity_id) OR c.broker_identity_id = sqlc.arg(identity_id))
  AND c.revoked_at IS NULL AND c.expires_at > sqlc.arg(now)
  AND EXISTS (
    SELECT 1 FROM audit_events r
    WHERE r.organization_id = sqlc.arg(organization_id) AND r.occurred_at > sqlc.arg(since)
      AND r.event_type = 'identity.retired' AND json_extract(r.resource, '$.identityId') = sqlc.arg(identity_id)
      AND r.occurred_at > COALESCE((
        SELECT max(a.occurred_at) FROM audit_events a
        WHERE a.organization_id = sqlc.arg(organization_id) AND a.occurred_at > sqlc.arg(since)
          AND a.occurred_at <= c.created_at
          AND a.event_type = 'identity.reactivated' AND json_extract(a.resource, '$.identityId') = sqlc.arg(identity_id)
      ), sqlc.arg(since)))
ORDER BY c.id;
