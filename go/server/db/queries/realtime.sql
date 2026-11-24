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

-- name: StreamOrganizations :many
-- The Organizations an identity is a live member of (GET
-- /v1/organizations' list), and what holds their signals back: an open
-- incident freeze, and passkey-verification at enforce, for a sign-in
-- without the evidence it asks for.
SELECT o.id,
       EXISTS (SELECT 1 FROM organization_freezes f WHERE f.organization_id = o.id AND f.lifted_at IS NULL) AS frozen,
       EXISTS (SELECT 1 FROM security_controls c WHERE c.organization_id = o.id AND c.control = 'passkey-verification' AND c.mode = 'enforce') AS verified_only
FROM organizations o
JOIN org_memberships m ON m.organization_id = o.id
WHERE m.identity_id = ? AND m.removed_at IS NULL AND o.deleted_at IS NULL;

-- name: SessionEvidence :one
SELECT user_verified, passkey_id FROM auth_session_evidence WHERE session_id = ?;

-- name: SessionOfCredential :one
SELECT auth_session_id FROM credentials WHERE id = ?;
