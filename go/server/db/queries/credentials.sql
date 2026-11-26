-- Opaque bearer credentials (ADR-0007, ADR-0059 step 3.4; the TypeScript
-- server's auth/credentials.ts). Times are microseconds since the Unix
-- epoch, read from varlatchd's clock inside the write job.

-- name: CredentialByTokenHash :one
SELECT c.id, c.identity_id, c.kind, c.name, c.expires_at, c.revoked_at, c.token_hash,
       c.max_uses, c.use_count, c.auth_session_id, c.last_used_at,
       i.kind AS identity_kind, i.name AS identity_name, i.disabled,
       i.installation_admin, i.organization_id
FROM credentials c JOIN identities i ON i.id = c.identity_id
WHERE c.token_hash = ?;

-- name: ConsumeCredentialUse :execrows
UPDATE credentials SET use_count = use_count + 1
WHERE id = ? AND revoked_at IS NULL AND use_count < max_uses;

-- name: TouchCredential :execrows
UPDATE credentials SET last_used_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND (last_used_at IS NULL OR last_used_at < sqlc.arg(before));

-- name: TouchIdentity :exec
UPDATE identities SET last_seen_at = ? WHERE id = ?;

-- name: InsertCredential :exec
INSERT INTO credentials (id, identity_id, kind, name, token_hash, created_at, expires_at, max_uses, client,
                         auth_session_id, issued_by, evidence_user_verified, evidence_passkey_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: RevokeCredential :one
UPDATE credentials SET revoked_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND revoked_at IS NULL
RETURNING kind, identity_id;

-- name: ConsumeBrowserCredential :execrows
UPDATE credentials SET revoked_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND kind = 'browser' AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > sqlc.arg(now));

-- name: CredentialOfIdentity :one
-- revokeOwnCredential: the caller's credential, its kind and the browser
-- session it came from.
SELECT id, kind, auth_session_id FROM credentials WHERE id = ? AND identity_id = ?;

-- name: ListCredentialsOfIdentity :many
SELECT id, kind, name, created_at, expires_at, revoked_at, max_uses, use_count, client
FROM credentials WHERE identity_id = ?
ORDER BY created_at DESC, id DESC;

-- name: GetIdentity :one
SELECT * FROM identities WHERE id = ?;

-- name: OrganizationsOfMember :many
SELECT o.id, o.slug, o.name, o.created_at FROM organizations o
JOIN org_memberships m ON m.organization_id = o.id
WHERE m.identity_id = ? AND m.removed_at IS NULL AND o.deleted_at IS NULL
ORDER BY o.created_at, o.id;

-- name: LiveOrganization :one
SELECT id, slug, name, created_at FROM organizations WHERE id = ? AND deleted_at IS NULL;

-- name: ProfileOfIdentity :one
SELECT u.email, u.image FROM auth_user_links l JOIN auth_users u ON u.id = l.better_auth_user_id
WHERE l.identity_id = ?;

-- name: CredentialEvidence :one
SELECT c.identity_id, c.evidence_user_verified, c.evidence_passkey_id,
       e.session_id IS NOT NULL AS has_session_evidence, coalesce(e.user_verified, 0) AS session_user_verified,
       e.passkey_id AS session_passkey_id
FROM credentials c LEFT JOIN auth_session_evidence e ON e.session_id = c.auth_session_id
WHERE c.id = ?;

-- name: ActivePasskeyVerificationControls :many
SELECT organization_id, mode, version FROM security_controls
WHERE organization_id IN (sqlc.slice(organization_ids)) AND control = 'passkey-verification' AND mode IN ('report', 'enforce')
ORDER BY organization_id;
