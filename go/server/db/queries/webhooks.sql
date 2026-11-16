-- Audit webhooks and their delivery (domain/webhooks.ts,
-- integrationstepup.ts' readWebhook; ADR-0016, ADR-0029 section 8,
-- ADR-0051 Decision 9, ADR-0057; ADR-0059 step 4.7b). Every time written
-- is varlatchd's clock, passed in. event_types is a JSON array of strings,
-- or NULL for every event.

-- name: OrganizationWebhooks :many
-- listWebhooks: the live webhooks, oldest first.
SELECT id, organization_id, url, event_types, created_at, revoked_at, failure_count, last_attempt_at, last_status, version, updated_at
FROM webhooks WHERE organization_id = ? AND revoked_at IS NULL
ORDER BY created_at, id;

-- name: LiveWebhook :one
-- readWebhook, and updateWebhook's read of the row it changes.
SELECT id, organization_id, url, event_types, created_at, revoked_at, failure_count, last_attempt_at, last_status, version, updated_at
FROM webhooks WHERE id = ? AND organization_id = ? AND revoked_at IS NULL;

-- name: StoredWebhookURL :one
-- updateWebhook's check of whether the URL changes: any row, revoked ones
-- included.
SELECT url FROM webhooks WHERE id = ? AND organization_id = ?;

-- name: InsertWebhook :exec
INSERT INTO webhooks (id, organization_id, url, event_types, secret_envelope, created_by, created_at, cursor_occurred_at, cursor_event_id, cursor_order)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateWebhook :one
UPDATE webhooks SET url = sqlc.arg(url), event_types = sqlc.arg(event_types), version = version + 1, updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) RETURNING version, updated_at;

-- name: RevokeWebhook :one
UPDATE webhooks SET revoked_at = sqlc.arg(revoked_at)
WHERE id = sqlc.arg(id) AND organization_id = sqlc.arg(organization_id) AND revoked_at IS NULL RETURNING id;

-- name: DeliverableWebhooks :many
-- deliverWebhooksOnce: every active webhook of a live Organization.
SELECT w.id, w.organization_id, w.url, w.event_types, w.secret_envelope, w.cursor_order
FROM webhooks w JOIN organizations o ON o.id = w.organization_id
WHERE w.revoked_at IS NULL AND w.suspended_by_deletion IS NULL AND o.deleted_at IS NULL
ORDER BY w.created_at, w.id;

-- name: WebhookEvents :many
-- A delivery's batch: the Organization's events after the cursor, in
-- order, those of the filter's types when it has any.
SELECT * FROM audit_events
WHERE organization_id = sqlc.arg(organization_id) AND event_order > sqlc.arg(after)
  AND (sqlc.narg(event_types) IS NULL OR event_type IN (SELECT value FROM json_each(sqlc.narg(event_types))))
ORDER BY event_order LIMIT sqlc.arg(batch);

-- name: DeletedProjectsAmong :many
-- withoutDeletedProjects: the deleted Projects, with their environments,
-- among the Projects and environments a batch names.
SELECT p.id AS project_id, e.id AS environment_id
FROM projects p LEFT JOIN environments e ON e.project_id = p.id
WHERE p.deleted_at IS NOT NULL
  AND (p.id IN (SELECT value FROM json_each(sqlc.arg(project_ids))) OR e.id IN (SELECT value FROM json_each(sqlc.arg(environment_ids))));

-- name: WebhookStillDeliverable :one
-- Eligibility right before sending (ADR-0051 Decision 9): the webhook is
-- active, its Organization live and not being deleted; the KEK read afresh.
SELECT o.wrapped_org_kek FROM webhooks w JOIN organizations o ON o.id = w.organization_id
WHERE w.id = ? AND w.revoked_at IS NULL AND w.suspended_by_deletion IS NULL AND o.deleted_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM organization_deletions d
                  WHERE d.organization_id = o.id AND d.cancelled_at IS NULL AND d.completed_at IS NULL);

-- name: SkipWebhookEvents :exec
-- A batch with nothing to deliver: the cursor moves past it.
UPDATE webhooks SET cursor_order = max(cursor_order, sqlc.arg(event_order)), cursor_event_id = sqlc.arg(event_id)
WHERE id = sqlc.arg(id);

-- name: WebhookDelivered :exec
UPDATE webhooks SET cursor_order = max(cursor_order, sqlc.arg(event_order)), cursor_event_id = sqlc.arg(event_id),
  failure_count = 0, last_attempt_at = sqlc.arg(attempt_at), last_status = sqlc.arg(status)
WHERE id = sqlc.arg(id);

-- name: WebhookFailed :exec
UPDATE webhooks SET failure_count = failure_count + 1, last_attempt_at = sqlc.arg(attempt_at), last_status = sqlc.arg(status)
WHERE id = sqlc.arg(id);
