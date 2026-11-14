-- The realtime publisher (go/server/realtime; ADR-0059 Decision 4).

-- name: AuditEventsAfter :many
-- The events committed after a position, oldest first: the TypeScript
-- server's mirror walk (mirror/publisher.ts syncNewMirrorEvents).
SELECT event_order, id, event_type, occurred_at, actor_identity_id, credential_id, organization_id, resource
FROM audit_events
WHERE event_order > sqlc.arg(after)
ORDER BY event_order
LIMIT sqlc.arg(max_events);

-- name: DeletedOrganizationsAmong :many
SELECT id FROM organizations WHERE deleted_at IS NOT NULL AND id IN (sqlc.slice(ids));

-- name: StreamSessionLive :one
-- A stream's session: live, its identity's, and that identity enabled.
SELECT s.expires_at FROM auth_sessions s
JOIN auth_user_links l ON l.better_auth_user_id = s.user_id
JOIN identities i ON i.id = l.identity_id
WHERE s.id = sqlc.arg(id) AND l.identity_id = sqlc.arg(identity_id) AND s.expires_at > sqlc.arg(now) AND i.disabled = 0;

-- name: MemberOrganizationIDs :many
-- The Organizations whose signals an identity's streams receive: the ones
-- it is a live member of (GET /v1/organizations' list).
SELECT o.id FROM organizations o
JOIN org_memberships m ON m.organization_id = o.id
WHERE m.identity_id = ? AND m.removed_at IS NULL AND o.deleted_at IS NULL;

-- name: SessionOfCredential :one
SELECT auth_session_id FROM credentials WHERE id = ?;
