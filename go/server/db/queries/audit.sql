-- name: InsertAuditEvent :one
INSERT INTO audit_events (id, event_type, decision, actor_identity_id, credential_id, organization_id, resource, metadata)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING event_order;

-- name: LastAuditPosition :one
-- The highest committed position: PostgreSQL's audit_position.value.
SELECT CAST(coalesce(max(event_order), 0) AS INTEGER) AS position FROM audit_events;

-- name: ListAuditEvents :many
SELECT * FROM audit_events ORDER BY event_order;

-- name: ListAuditEventsOfType :many
SELECT * FROM audit_events WHERE event_type = ? ORDER BY event_order;

-- name: RecordAuditEvent :one
-- One event (go/server/audit Record), at the next position: event_order is
-- left to SQLite, the rowid (MAPPING.md, "Audit positions in commit order").
INSERT INTO audit_events
  (id, schema_version, event_type, actor_identity_id, authentication_method_id,
   credential_id, organization_id, action, resource, decision, authz, tailnet,
   listener, request_id, metadata, client)
VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING event_order, occurred_at;

-- name: GetAuditEvent :one
SELECT * FROM audit_events WHERE id = ?;

-- name: IndexExposure :exec
-- One member_exposure row (ADR-0052 Decision 6, audit/exposure.ts
-- indexExposures); the caller indexes people only. A null time is now; the
-- first and last times only ever widen.
INSERT INTO member_exposure (organization_id, identity_id, version_id, item_name, environment_id, way, first_at, last_at)
VALUES (sqlc.arg(organization_id), sqlc.arg(identity_id), sqlc.arg(version_id), sqlc.arg(item_name),
        sqlc.arg(environment_id), sqlc.arg(way),
        coalesce(sqlc.narg(first_at), CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
        coalesce(sqlc.narg(last_at), CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000))
ON CONFLICT (organization_id, identity_id, version_id, environment_id, way) DO UPDATE SET
  first_at = min(member_exposure.first_at, excluded.first_at),
  last_at = max(member_exposure.last_at, excluded.last_at);

-- name: HumanIdentities :many
-- Which of these identities are people: only their exposure is indexed.
SELECT id FROM identities WHERE kind = 'human' AND id IN (sqlc.slice(ids));
