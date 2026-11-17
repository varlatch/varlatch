-- Platform Connections and the Sync Target reads they need (domain/sync.ts,
-- integrationstepup.ts' readConnection; ADR-0031, ADR-0047, ADR-0050;
-- ADR-0059 step 4.9b). Every time written is varlatchd's clock, passed in.

-- name: OrganizationConnections :many
-- listConnections: the live Connections with their live Targets' count,
-- oldest first.
SELECT c.id, c.organization_id, c.platform, c.base_identity, c.name, c.created_at, c.revoked_at, c.version, c.updated_at,
       c.credential_expires_at, c.credential_expiry_seen_at, c.credential_kind, c.github_app_id, c.github_installation_id,
       (SELECT count(*) FROM sync_targets t WHERE t.connection_id = c.id AND t.revoked_at IS NULL) AS target_count
FROM platform_connections c
WHERE c.organization_id = ? AND c.revoked_at IS NULL
ORDER BY c.created_at, c.id;

-- name: LiveConnection :one
-- getConnection and readConnection: a live Connection of the Organization.
SELECT id, organization_id, platform, base_identity, name, created_at, revoked_at, version, updated_at,
       credential_expires_at, credential_expiry_seen_at, credential_kind, github_app_id, github_installation_id
FROM platform_connections WHERE id = ? AND organization_id = ? AND revoked_at IS NULL;

-- name: ConnectionCredential :one
-- resolveCredential: the stored credential and the version it was read at.
SELECT credential_envelope, version, credential_expires_at FROM platform_connections WHERE id = ?;

-- name: InsertConnection :exec
INSERT INTO platform_connections (id, organization_id, platform, base_identity, name, credential_envelope, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: ReplaceConnectionCredential :exec
UPDATE platform_connections
SET credential_envelope = sqlc.arg(credential_envelope), version = version + 1, updated_at = sqlc.arg(updated_at),
    credential_expires_at = NULL, credential_expiry_seen_at = NULL
WHERE id = sqlc.arg(id);

-- name: RevokeConnection :one
UPDATE platform_connections SET revoked_at = sqlc.arg(at), version = version + 1, updated_at = sqlc.arg(at)
WHERE id = sqlc.arg(id) AND organization_id = sqlc.arg(organization_id) AND revoked_at IS NULL RETURNING id;

-- name: RecordCredentialExpiry :exec
-- recordCredentialExpiry: only while the Connection holds the credential
-- read at version; not a Connection change.
UPDATE platform_connections SET credential_expires_at = sqlc.arg(expires_at), credential_expiry_seen_at = sqlc.arg(seen_at)
WHERE id = sqlc.arg(id) AND version = sqlc.arg(version) AND revoked_at IS NULL;

-- name: ConnectionTargets :many
-- readConnectionTargets: a Connection's live Targets, in id order.
SELECT id, organization_id, project_id, environment_id, connection_id, destination, canonical_destination, mapping,
       remove_orphans, redeploy, state, disabled_reason, failure_count, needs_sync, next_attempt_at, last_attempt_at,
       last_result, last_notes, last_repair_at, created_at, revoked_at, version, updated_at, redeploy_owed, redeploy_paid,
       last_drift_at, last_drift_count, last_drift_names, last_drift_event_id
FROM sync_targets WHERE connection_id = ? AND revoked_at IS NULL ORDER BY id;

-- name: OrganizationConnectionTargets :many
-- listTargets of one Connection: oldest first.
SELECT id, organization_id, project_id, environment_id, connection_id, destination, canonical_destination, mapping,
       remove_orphans, redeploy, state, disabled_reason, failure_count, needs_sync, next_attempt_at, last_attempt_at,
       last_result, last_notes, last_repair_at, created_at, revoked_at, version, updated_at, redeploy_owed, redeploy_paid,
       last_drift_at, last_drift_count, last_drift_names, last_drift_event_id
FROM sync_targets WHERE organization_id = ? AND connection_id = ? AND revoked_at IS NULL ORDER BY created_at, id;

-- name: CountConnectionTargets :one
SELECT count(*) FROM sync_targets WHERE connection_id = ? AND revoked_at IS NULL;

-- name: LiveRunStarts :many
-- liveRunStarts: each Target's earliest run that has not passed its deadline.
SELECT target_id, CAST(min(started_at) AS INTEGER) AS started_at FROM sync_runs
WHERE target_id IN (SELECT value FROM json_each(sqlc.arg(target_ids))) AND deadline > sqlc.arg(now)
GROUP BY target_id;

-- name: ResumeTarget :exec
-- A Target the old credential stopped resumes with the new one.
UPDATE sync_targets SET state = 'active', disabled_reason = NULL, version = version + 1, updated_at = sqlc.arg(at)
WHERE id = sqlc.arg(id);

-- name: ResetTargetFailures :exec
UPDATE sync_targets SET failure_count = 0 WHERE id = ?;

-- name: QueueConnectionTargets :exec
-- A credential replacement enqueues every live Target directly.
UPDATE sync_targets SET needs_sync = 1, next_attempt_at = NULL WHERE connection_id = ? AND revoked_at IS NULL;

-- name: DisableTarget :one
-- Revoking a Connection disables each live Target it feeds: fenced (a new
-- generation), its lease and repair cycle cleared.
UPDATE sync_targets
SET state = 'disabled', disabled_reason = 'connection-revoked', generation = generation + 1, lease_expires_at = NULL,
    repair_cycle_started_at = NULL, version = version + 1, updated_at = sqlc.arg(at)
WHERE id = sqlc.arg(id) AND revoked_at IS NULL RETURNING id;

-- name: TargetScope :one
-- The re-authorization gate's Project and Environment of a Target, read
-- whatever their state (SELECT * FROM projects / environments there).
SELECT p.id AS project_id, p.active_contract_revision_id, e.id AS environment_id, e.parent_environment_id, e.tier
FROM projects p, environments e WHERE p.id = sqlc.arg(project_id) AND e.id = sqlc.arg(environment_id);

-- name: UpsertIntegration :exec
-- indexIntegrations, one row: changes (a sorted set, given sorted) is
-- the sorted union, and the times only widen.
INSERT INTO member_integrations (organization_id, identity_id, kind, resource_id, changes, first_at, last_at)
VALUES (sqlc.arg(organization_id), sqlc.arg(identity_id), sqlc.arg(kind), sqlc.arg(resource_id), sqlc.arg(changes), sqlc.arg(at), sqlc.arg(at))
ON CONFLICT (organization_id, identity_id, kind, resource_id) DO UPDATE SET
  changes = (SELECT json_group_array(value) FROM (
    SELECT DISTINCT value FROM (
      SELECT value FROM json_each(member_integrations.changes) UNION ALL SELECT value FROM json_each(excluded.changes))
    ORDER BY value)),
  first_at = min(member_integrations.first_at, excluded.first_at),
  last_at = max(member_integrations.last_at, excluded.last_at);

-- Sync Targets (ADR-0031 sections 1 to 6, ADR-0050; ADR-0059 step 4.9c).

-- name: OrganizationTargets :many
-- listTargets of an Organization: oldest first.
SELECT id, organization_id, project_id, environment_id, connection_id, destination, canonical_destination, mapping,
       remove_orphans, redeploy, state, disabled_reason, failure_count, needs_sync, next_attempt_at, last_attempt_at,
       last_result, last_notes, last_repair_at, created_at, revoked_at, version, updated_at, redeploy_owed, redeploy_paid,
       last_drift_at, last_drift_count, last_drift_names, last_drift_event_id
FROM sync_targets WHERE organization_id = ? AND revoked_at IS NULL ORDER BY created_at, id;

-- name: EnvironmentTargets :many
-- listTargets of an environment: oldest first.
SELECT id, organization_id, project_id, environment_id, connection_id, destination, canonical_destination, mapping,
       remove_orphans, redeploy, state, disabled_reason, failure_count, needs_sync, next_attempt_at, last_attempt_at,
       last_result, last_notes, last_repair_at, created_at, revoked_at, version, updated_at, redeploy_owed, redeploy_paid,
       last_drift_at, last_drift_count, last_drift_names, last_drift_event_id
FROM sync_targets WHERE organization_id = ? AND environment_id = ? AND revoked_at IS NULL ORDER BY created_at, id;

-- name: LiveTarget :one
-- getTarget: a live Target of the Organization.
SELECT id, organization_id, project_id, environment_id, connection_id, destination, canonical_destination, mapping,
       remove_orphans, redeploy, state, disabled_reason, failure_count, needs_sync, next_attempt_at, last_attempt_at,
       last_result, last_notes, last_repair_at, created_at, revoked_at, version, updated_at, redeploy_owed, redeploy_paid,
       last_drift_at, last_drift_count, last_drift_names, last_drift_event_id
FROM sync_targets WHERE id = ? AND organization_id = ? AND revoked_at IS NULL;

-- name: TargetLedger :many
-- targetLedger: per-name delivery state, never fingerprints or values.
SELECT dest_name, state, updated_at, last_error FROM sync_ledger WHERE target_id = ? ORDER BY dest_name;

-- name: AnyConnection :one
-- lockConnectionsAndApps' read of one Connection, revoked or not.
SELECT id, organization_id, platform, base_identity, name, created_at, revoked_at, version, updated_at,
       credential_expires_at, credential_expiry_seen_at, credential_kind, github_app_id, github_installation_id
FROM platform_connections WHERE id = ? AND organization_id = ?;

-- name: LiveGitHubApp :one
SELECT count(*) FROM github_apps WHERE id = ? AND organization_id = ? AND removed_at IS NULL;

-- name: DestinationClaimed :one
-- The destination claim (sync_targets_destination_claim): another live
-- Target with the canonical destination.
SELECT count(*) FROM sync_targets WHERE canonical_destination = sqlc.arg(canonical) AND revoked_at IS NULL AND id <> sqlc.arg(id);

-- name: InsertTarget :exec
INSERT INTO sync_targets (id, organization_id, project_id, environment_id, connection_id, destination, canonical_destination,
  mapping, remove_orphans, redeploy, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateTarget :exec
-- updateTarget: queued for a converge; a destination change takes the
-- notes and drift observed at the old one, and settles an owed redeploy
-- (as does turning redeploys off).
UPDATE sync_targets
SET connection_id = sqlc.arg(connection_id), destination = sqlc.arg(destination), canonical_destination = sqlc.arg(canonical),
    mapping = sqlc.arg(mapping), remove_orphans = sqlc.arg(remove_orphans), redeploy = sqlc.arg(redeploy), needs_sync = 1,
    next_attempt_at = NULL, version = version + 1, updated_at = sqlc.arg(at),
    last_notes = CASE WHEN CAST(sqlc.arg(changed) AS INTEGER) <> 0 THEN NULL ELSE last_notes END,
    last_drift_at = CASE WHEN CAST(sqlc.arg(changed) AS INTEGER) <> 0 THEN NULL ELSE last_drift_at END,
    last_drift_count = CASE WHEN CAST(sqlc.arg(changed) AS INTEGER) <> 0 THEN NULL ELSE last_drift_count END,
    last_drift_names = CASE WHEN CAST(sqlc.arg(changed) AS INTEGER) <> 0 THEN NULL ELSE last_drift_names END,
    last_drift_event_id = CASE WHEN CAST(sqlc.arg(changed) AS INTEGER) <> 0 THEN NULL ELSE last_drift_event_id END,
    redeploy_paid = CASE WHEN CAST(sqlc.arg(changed) AS INTEGER) <> 0 OR NOT sqlc.arg(redeploy) THEN redeploy_owed ELSE redeploy_paid END
WHERE id = sqlc.arg(id);

-- name: FenceTarget :exec
-- A fence: a run holding the old generation sends and records nothing more.
UPDATE sync_targets SET generation = generation + 1, lease_expires_at = NULL WHERE id = ?;

-- name: FenceTargetCycle :exec
UPDATE sync_targets SET generation = generation + 1, lease_expires_at = NULL, repair_cycle_started_at = NULL WHERE id = ?;

-- name: ClearLedger :exec
DELETE FROM sync_ledger WHERE target_id = ?;

-- name: PauseTarget :exec
UPDATE sync_targets
SET state = 'paused', generation = generation + 1, lease_expires_at = NULL, repair_cycle_started_at = NULL,
    version = version + 1, updated_at = sqlc.arg(at)
WHERE id = sqlc.arg(id);

-- name: ResumeTargetState :exec
-- Resumption queues an immediate converge (ADR-0031 section 5).
UPDATE sync_targets
SET state = 'active', disabled_reason = NULL, failure_count = 0, needs_sync = 1, next_attempt_at = NULL,
    version = version + 1, updated_at = sqlc.arg(at)
WHERE id = sqlc.arg(id);

-- name: RevokeTarget :exec
UPDATE sync_targets
SET revoked_at = sqlc.arg(at), generation = generation + 1, lease_expires_at = NULL, repair_cycle_started_at = NULL,
    version = version + 1, updated_at = sqlc.arg(at)
WHERE id = sqlc.arg(id);
