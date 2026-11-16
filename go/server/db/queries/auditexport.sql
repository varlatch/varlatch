-- Audit export to object storage, its configuration (domain/auditexport.ts;
-- ADR-0056; ADR-0059 step 4.11a). Every time written is varlatchd's clock,
-- passed in.

-- name: LiveAuditExport :one
-- liveExport: the Organization's active or draining export.
SELECT * FROM audit_exports WHERE organization_id = ? AND state IN ('active', 'draining');

-- name: LatestAuditExport :one
-- getAuditExport: the live export, or else the most recent.
SELECT * FROM audit_exports WHERE organization_id = ?
ORDER BY (state IN ('active', 'draining')) DESC, created_at DESC, id DESC LIMIT 1;

-- name: OrganizationAuditExport :one
-- An export of the Organization by id, whatever its state.
SELECT * FROM audit_exports WHERE id = ? AND organization_id = ?;

-- name: AuditExportLag :one
-- auditExportLag: the Organization's events after the cursor, and the
-- oldest one's time.
SELECT count(e.event_order) AS n, min(e.occurred_at) AS oldest FROM audit_exports x
JOIN audit_events e ON e.organization_id = x.organization_id AND e.event_order > x.cursor_order
WHERE x.id = ?;

-- name: AuditExportPlanOf :one
SELECT * FROM audit_export_plans WHERE export_id = ?;

-- name: InsertAuditExport :exec
INSERT INTO audit_exports (id, organization_id, endpoint, region, bucket, prefix, path_style, credential_envelope,
  retention_mode, retention_days, stream_id, stream_started_at, cursor_order, state, created_by,
  conditional_checked_at, lock_verified, key_can_read, retention_readable, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?);

-- name: InsertAuditExportPlan :exec
INSERT INTO audit_export_plans (id, export_id, export_version, stream_id, generation, kind, object_name, body, sha256, md5,
  content_type, format_version, retention_mode, retain_until, first_order, last_order, event_count, heartbeat_hour, planned_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteAuditExportPlan :exec
DELETE FROM audit_export_plans WHERE id = ?;

-- name: ChangeAuditExport :one
-- changeAuditExport's update: the destination and retention; a new stream
-- when stream_id changes; the probe's findings when it ran (probed).
UPDATE audit_exports SET endpoint = sqlc.arg(endpoint), region = sqlc.arg(region), bucket = sqlc.arg(bucket), prefix = sqlc.arg(prefix),
  path_style = sqlc.arg(path_style), retention_mode = sqlc.narg(retention_mode), retention_days = sqlc.narg(retention_days),
  stream_started_at = CASE WHEN sqlc.arg(stream_id) <> stream_id THEN sqlc.arg(at) ELSE stream_started_at END,
  stopped_reason = CASE WHEN sqlc.arg(stream_id) <> stream_id THEN NULL ELSE stopped_reason END,
  stream_id = sqlc.arg(stream_id),
  conditional_checked_at = CASE WHEN sqlc.arg(probed) THEN sqlc.arg(at) ELSE conditional_checked_at END,
  lock_verified = CASE WHEN sqlc.arg(probed) THEN sqlc.narg(lock_verified) WHEN sqlc.narg(retention_days) IS NULL THEN NULL ELSE lock_verified END,
  key_can_read = CASE WHEN sqlc.arg(probed) THEN sqlc.narg(key_can_read) ELSE key_can_read END,
  retention_readable = CASE WHEN sqlc.arg(probed) THEN sqlc.narg(retention_readable) ELSE retention_readable END,
  generation = generation + 1, lease_expires_at = NULL, version = version + 1, updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) RETURNING *;

-- name: ReplaceAuditExportCredential :one
UPDATE audit_exports SET credential_envelope = sqlc.arg(credential_envelope), key_can_read = NULL, retention_readable = NULL,
  generation = generation + 1, lease_expires_at = NULL, version = version + 1, updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) RETURNING *;

-- name: RemoveAuditExport :one
UPDATE audit_exports SET state = 'removed', removed_at = sqlc.arg(at), credential_envelope = NULL, generation = generation + 1,
  lease_expires_at = NULL, version = version + 1, updated_at = sqlc.arg(at)
WHERE id = sqlc.arg(id) RETURNING *;
