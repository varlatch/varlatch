-- name: CapabilityAgent :one
-- issueCapability: the named identity, in this Organization.
SELECT id, kind, disabled FROM identities WHERE id = ? AND organization_id = ?;

-- name: InsertCapability :exec
INSERT INTO capabilities
  (id, organization_id, broker_identity_id, agent_identity_id, project_id, environment_id,
   items, destinations, targets, secret_hash, run_id, expires_at, created_by, created_at)
VALUES (sqlc.arg(id), sqlc.arg(organization_id), sqlc.arg(broker_identity_id), sqlc.arg(agent_identity_id),
        sqlc.arg(project_id), sqlc.arg(environment_id), sqlc.arg(items), sqlc.arg(destinations), sqlc.arg(targets),
        sqlc.arg(secret_hash), sqlc.narg(run_id), sqlc.arg(expires_at), sqlc.arg(created_by), sqlc.arg(created_at));

-- name: CapabilityBroker :one
-- The Broker a Capability is issued for: one of this Organization's, not
-- disabled.
SELECT id FROM identities WHERE id = ? AND organization_id = ? AND kind = 'broker' AND disabled = 0;

-- name: ListCapabilities :many
-- listCapabilities: an environment's Capabilities, newest first; only the
-- ones issued for or by owner when it is set (a Broker's own, an issuer's
-- own).
SELECT * FROM capabilities
WHERE organization_id = sqlc.arg(organization_id) AND environment_id = sqlc.arg(environment_id)
  AND (sqlc.narg(owner) IS NULL OR broker_identity_id = sqlc.narg(owner) OR created_by = sqlc.narg(owner))
ORDER BY created_at DESC, id;

-- name: LiveCapability :one
-- revokeCapability's existence check: unrevoked, in the Organization, one
-- of owner's when it is set (any environment).
SELECT id, broker_identity_id, created_by FROM capabilities
WHERE id = sqlc.arg(id) AND organization_id = sqlc.arg(organization_id) AND revoked_at IS NULL
  AND (sqlc.narg(owner) IS NULL OR broker_identity_id = sqlc.narg(owner) OR created_by = sqlc.narg(owner));

-- name: RevokeCapability :execrows
UPDATE capabilities SET revoked_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND organization_id = sqlc.arg(organization_id) AND revoked_at IS NULL
  AND (sqlc.narg(owner) IS NULL OR broker_identity_id = sqlc.narg(owner) OR created_by = sqlc.narg(owner));

-- name: IssuedCapability :one
-- Whether the identity issued the Capability, in the Organization.
SELECT id FROM capabilities WHERE id = ? AND organization_id = ? AND created_by = ?;

-- name: CapabilityOf :one
-- captureExercise: the Capability, in the route's environment.
SELECT * FROM capabilities WHERE id = ? AND organization_id = ? AND environment_id = ?;

-- name: LiveCapabilitiesOfIdentity :many
-- retireIdentity: the unrevoked Capabilities issued for the identity as
-- Agent, for it as Broker, or by it for another Broker (ADR-0060), in id
-- order.
SELECT id FROM capabilities
WHERE (agent_identity_id = sqlc.arg(identity_id) OR broker_identity_id = sqlc.arg(identity_id) OR created_by = sqlc.arg(identity_id)) AND revoked_at IS NULL
ORDER BY id;

-- name: RevokeCapabilitiesOfIdentity :exec
UPDATE capabilities SET revoked_at = sqlc.arg(now)
WHERE (agent_identity_id = sqlc.arg(identity_id) OR broker_identity_id = sqlc.arg(identity_id) OR created_by = sqlc.arg(identity_id)) AND revoked_at IS NULL;

-- name: LiveCapabilitiesForRepair :many
-- capabilities.RevokeOfRetired: the next at most batch unexpired, unrevoked
-- Capabilities after (after_org, after_id), by Organization and id: a range
-- of capabilities_live_idx from the cursor on, with no sort of the rest.
SELECT id, organization_id, agent_identity_id, broker_identity_id FROM capabilities
WHERE revoked_at IS NULL AND expires_at > sqlc.arg(now)
  AND (organization_id, id) > (sqlc.arg(after_org), sqlc.arg(after_id))
ORDER BY organization_id, id
LIMIT sqlc.arg(batch);

-- name: IdentityRetiredNow :one
-- capabilities.RevokeOfRetired: whether the identity is retired now
-- (disabled, not by an Organization's deletion).
SELECT count(*) FROM identities WHERE id = ? AND disabled = 1 AND suspended_by_deletion IS NULL;

-- name: LatestIdentityRetirement :one
-- capabilities.RevokeOfRetired: the identity's latest identity.retired,
-- by audit order, through audit_events_identity_lifecycle_idx.
SELECT event_order FROM audit_events
WHERE organization_id = sqlc.arg(organization_id)
  AND event_type IN ('identity.retired', 'identity.reactivated')
  AND event_type = 'identity.retired'
  AND json_extract(resource, '$.identityId') = sqlc.arg(identity_id)
ORDER BY event_order DESC LIMIT 1;

-- name: LatestIdentityLifecycleAt :one
-- capabilities.RevokeOfRetired: the identity's latest identity.retired or
-- identity.reactivated at or before at_order, by audit order, through
-- audit_events_identity_lifecycle_idx.
SELECT event_type, event_order FROM audit_events
WHERE organization_id = sqlc.arg(organization_id)
  AND event_type IN ('identity.retired', 'identity.reactivated')
  AND json_extract(resource, '$.identityId') = sqlc.arg(identity_id)
  AND event_order <= sqlc.arg(at_order)
ORDER BY event_order DESC LIMIT 1;

-- name: CapabilityIssuedOrder :one
-- capabilities.RevokeOfRetired: where the Capability's capability.issued
-- stands in the audit order, by audit_events_capability_issued_idx (its
-- whole history, not a window around its created_at).
SELECT event_order FROM audit_events
WHERE organization_id = sqlc.arg(organization_id) AND event_type = 'capability.issued'
  AND json_extract(resource, '$.capabilityId') = sqlc.arg(capability_id)
ORDER BY event_order LIMIT 1;

-- name: UseCapability :execrows
-- A single-use Capability's use, recorded in its secret_hash (values
-- StoredSecret), unless it was used or revoked meanwhile.
UPDATE capabilities SET secret_hash = sqlc.arg(used)
WHERE id = sqlc.arg(id) AND secret_hash = sqlc.arg(unused) AND revoked_at IS NULL;

-- name: ReleaseCapability :exec
-- The use taken back: the exercise was refused after all. revoked_at is
-- left as it is, so a revocation meanwhile holds.
UPDATE capabilities SET secret_hash = sqlc.arg(unused)
WHERE id = sqlc.arg(id) AND secret_hash = sqlc.arg(used);
