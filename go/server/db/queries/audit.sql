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
