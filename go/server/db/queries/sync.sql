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

-- ---------------------------------------------------------------------------
-- The converge engine (domain/syncdelivery.ts; server/syncs/CONVERGE.md).

-- name: SyncProject :one
-- reconcileUnderLease: the Target's Project, live.
SELECT id, active_contract_revision_id FROM projects WHERE id = ? AND deleted_at IS NULL;

-- name: SyncEnvironment :one
-- reconcileUnderLease: the Target's environment, live.
SELECT id, parent_environment_id, expires_at FROM environments WHERE id = ? AND deleted_at IS NULL;

-- name: SyncCursor :one
SELECT cursor_order FROM sync_cursor WHERE singleton = 1;

-- name: InsertSyncCursor :exec
-- T1: scanSyncTriggers' cursor row.
INSERT INTO sync_cursor (singleton, occurred_at, event_id) VALUES (1, ?, '') ON CONFLICT (singleton) DO NOTHING;

-- name: TriggerEvents :many
-- scanSyncTriggers: the events after the cursor, delivery's own excluded,
-- ordered and limited as the TypeScript query orders them: by event_order
-- as text (its ORDER BY names the output column, event_order::text), a
-- defect kept for parity (CONVERGE.md).
SELECT id, event_order, event_type, decision, resource FROM audit_events
WHERE event_order > ? AND substr(event_type, 1, 5) <> 'sync.'
ORDER BY CAST(event_order AS TEXT) LIMIT ?;

-- name: MarkTriggeredTargets :exec
-- T2: Targets of the environments the events name, of their derived
-- children, and of the Projects whose Contract changed.
UPDATE sync_targets SET needs_sync = 1
WHERE revoked_at IS NULL AND needs_sync = 0 AND (
  environment_id IN (SELECT value FROM json_each(sqlc.arg(environment_ids)))
  OR environment_id IN (SELECT id FROM environments WHERE parent_environment_id IN (SELECT value FROM json_each(sqlc.arg(environment_ids))))
  OR project_id IN (SELECT value FROM json_each(sqlc.arg(project_ids)))
);

-- name: AdvanceSyncCursor :exec
-- T3.
UPDATE sync_cursor SET cursor_order = max(cursor_order, sqlc.arg(event_order)), event_id = sqlc.arg(event_id) WHERE singleton = 1;

-- name: ExpiredRunExists :one
SELECT EXISTS (SELECT 1 FROM sync_runs WHERE deadline <= ?);

-- name: DeleteExpiredRuns :exec
-- T4.
DELETE FROM sync_runs WHERE deadline <= ?;

-- name: DueTargets :many
-- runSyncOnce's candidates: ids only, every fact is read at the lease.
-- A Target on a GitHub App Connection waits for step 4.10's minting.
SELECT t.id FROM sync_targets t
JOIN organizations o ON o.id = t.organization_id
JOIN platform_connections c ON c.id = t.connection_id
WHERE t.revoked_at IS NULL AND t.state = 'active' AND o.deleted_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM organization_freezes f WHERE f.organization_id = t.organization_id AND f.lifted_at IS NULL)
  AND (t.next_attempt_at IS NULL OR t.next_attempt_at <= sqlc.arg(now))
  AND (t.needs_sync = 1 OR t.last_repair_at IS NULL OR t.last_repair_at < sqlc.arg(repair_before))
  AND c.credential_kind <> 'github-app'
ORDER BY t.created_at, t.id;

-- name: LeaseTarget :one
-- C1: the lease; the configuration snapshot the run acts on.
UPDATE sync_targets
SET generation = generation + 1, lease_expires_at = sqlc.arg(lease_expires_at), needs_sync = 0, last_attempt_at = sqlc.arg(now)
WHERE sync_targets.id = sqlc.arg(id) AND sync_targets.revoked_at IS NULL AND sync_targets.state = 'active'
  AND (sync_targets.lease_expires_at IS NULL OR sync_targets.lease_expires_at < sqlc.arg(now))
  AND NOT EXISTS (SELECT 1 FROM organization_freezes f WHERE f.organization_id = sync_targets.organization_id AND f.lifted_at IS NULL)
RETURNING id, organization_id, project_id, environment_id, connection_id, destination, canonical_destination, mapping,
          remove_orphans, redeploy, last_repair_at, generation;

-- name: InsertSyncRun :exec
-- C1: the run's row, with its deadline.
INSERT INTO sync_runs (target_id, generation, started_at, deadline) VALUES (?, ?, ?, ?);

-- name: RunConnection :one
-- reconcileTarget: the Connection and the Organization's key, after the lease.
SELECT c.platform, c.base_identity, c.credential_envelope, c.version, c.revoked_at, c.credential_kind, o.wrapped_org_kek
FROM platform_connections c
JOIN organizations o ON o.id = sqlc.arg(organization_id) AND o.deleted_at IS NULL
WHERE c.id = sqlc.arg(id);

-- name: OpenRepairCycle :one
-- C4.
UPDATE sync_targets SET repair_cycle_started_at = COALESCE(repair_cycle_started_at, sqlc.arg(now))
WHERE id = sqlc.arg(id) AND generation = sqlc.arg(generation)
RETURNING repair_cycle_started_at;

-- name: TargetGeneration :one
SELECT generation FROM sync_targets WHERE id = ?;

-- name: RunLedger :many
-- reconcileUnderLease's ledger read. TypeScript reads it in the table's row
-- order, unspecified, which for a small PostgreSQL table is the order of
-- each row's last write; this is that order, made explicit.
SELECT dest_name, fingerprint, state, generation, repaired_at FROM sync_ledger WHERE target_id = ? ORDER BY updated_at, dest_name;

-- name: SetLedger :exec
-- ledgerSet: a confirmed write or deletion earns repair credit (repaired_at
-- is the time then); an intent or a failure clears it (NULL).
INSERT INTO sync_ledger (target_id, dest_name, fingerprint, state, generation, last_error, updated_at, repaired_at)
VALUES (sqlc.arg(target_id), sqlc.arg(dest_name), sqlc.arg(fingerprint), sqlc.arg(state), sqlc.arg(generation), sqlc.arg(last_error),
        sqlc.arg(now), sqlc.narg(repaired_at))
ON CONFLICT (target_id, dest_name) DO UPDATE
SET fingerprint = excluded.fingerprint, state = excluded.state, generation = excluded.generation, last_error = excluded.last_error,
    updated_at = excluded.updated_at, repaired_at = excluded.repaired_at;

-- name: OweRedeploy :exec
-- Only while the Target still wants redeploys.
UPDATE sync_targets SET redeploy_owed = redeploy_owed + 1 WHERE id = ? AND redeploy = 1;

-- name: CreditVerified :exec
-- C7.
UPDATE sync_ledger SET repaired_at = sqlc.arg(now)
WHERE target_id = sqlc.arg(target_id) AND dest_name IN (SELECT value FROM json_each(sqlc.arg(names))) AND state IN ('written', 'tombstone');

-- name: RecordDrift :exec
-- C9: the Target's last drift.
UPDATE sync_targets SET last_drift_at = sqlc.arg(now), last_drift_count = sqlc.arg(count), last_drift_names = sqlc.arg(names),
       last_drift_event_id = sqlc.arg(event_id)
WHERE id = sqlc.arg(id);

-- name: RedeployDebt :one
-- payRedeploy: the current setting and debt, under the run's generation.
SELECT redeploy, redeploy_owed, redeploy_paid FROM sync_targets WHERE id = ? AND generation = ?;

-- name: SettleRedeploy :exec
-- C16.
UPDATE sync_targets SET redeploy_paid = max(redeploy_paid, sqlc.arg(owed)) WHERE id = sqlc.arg(id) AND generation = sqlc.arg(generation);

-- name: SendCheck :one
-- SEND_CHECK_SQL: the generation, the run's deadline, the freeze.
SELECT t.generation,
       CAST(COALESCE((SELECT r.deadline FROM sync_runs r WHERE r.target_id = t.id AND r.generation = sqlc.arg(generation)), 0) AS INTEGER) AS deadline,
       EXISTS (SELECT 1 FROM organization_freezes f WHERE f.organization_id = t.organization_id AND f.lifted_at IS NULL) AS frozen
FROM sync_targets t WHERE t.id = sqlc.arg(id);

-- name: YieldTarget :exec
-- C18.
UPDATE sync_targets SET needs_sync = 1 WHERE id = ? AND generation = ?;

-- name: RefuseTarget :exec
-- C20: recordRefusal.
UPDATE sync_targets
SET last_result = sqlc.arg(result), needs_sync = 1, next_attempt_at = sqlc.arg(next_attempt_at),
    last_notes = CASE WHEN CAST(sqlc.arg(set_notes) AS INTEGER) <> 0 THEN sqlc.arg(notes) ELSE last_notes END
WHERE id = sqlc.arg(id) AND generation = sqlc.arg(generation) AND revoked_at IS NULL;

-- name: CloseRepairCycle :exec
-- C22.
UPDATE sync_targets SET last_repair_at = COALESCE(repair_cycle_started_at, sqlc.arg(now)), repair_cycle_started_at = NULL
WHERE id = sqlc.arg(id) AND generation = sqlc.arg(generation);

-- name: TargetSucceeded :exec
-- C23.
UPDATE sync_targets
SET failure_count = 0, next_attempt_at = NULL, last_result = sqlc.arg(result),
    last_notes = CASE WHEN CAST(sqlc.arg(set_notes) AS INTEGER) <> 0 THEN sqlc.arg(notes) ELSE last_notes END
WHERE id = sqlc.arg(id) AND generation = sqlc.arg(generation);

-- name: ConnectionVersion :one
SELECT version FROM platform_connections WHERE id = ?;

-- name: GuardedFailureCount :one
-- recordFailure: the count as it is now, under the run's generation.
SELECT failure_count FROM sync_targets WHERE id = ? AND revoked_at IS NULL AND generation = ?;

-- name: TargetFailed :exec
-- recordFailure.
UPDATE sync_targets
SET failure_count = sqlc.arg(failures), last_result = sqlc.arg(result), needs_sync = 1, next_attempt_at = sqlc.arg(next_attempt_at),
    state = CASE WHEN CAST(sqlc.arg(disable) AS INTEGER) <> 0 THEN 'disabled' ELSE state END,
    disabled_reason = CASE WHEN CAST(sqlc.arg(disable) AS INTEGER) <> 0 THEN 'failure-budget-exhausted' ELSE disabled_reason END,
    last_notes = CASE WHEN CAST(sqlc.arg(set_notes) AS INTEGER) <> 0 THEN sqlc.arg(notes) ELSE last_notes END
WHERE id = sqlc.arg(id);

-- name: ReleaseLease :exec
-- C25.
UPDATE sync_targets SET lease_expires_at = NULL WHERE id = ? AND generation = ?;

-- name: DeleteRun :exec
-- C26.
DELETE FROM sync_runs WHERE target_id = ? AND generation = ?;

-- name: ClearRefusedBackoff :exec
-- At startup, Targets the outbound policy refused are due again at once.
UPDATE sync_targets SET next_attempt_at = NULL
WHERE revoked_at IS NULL AND next_attempt_at IS NOT NULL AND substr(last_result, 1, 17) = 'outbound_refused:';

-- name: RequestPush :one
-- requestPush.
UPDATE sync_targets SET needs_sync = 1, next_attempt_at = NULL
WHERE id = ? AND organization_id = ? AND revoked_at IS NULL RETURNING id;
