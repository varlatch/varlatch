-- OIDC workload identity (domain/oidc.ts; ADR-0059 step 4.8). Every time
-- written is varlatchd's clock, passed in.

-- name: ListOidcBindings :many
-- listOidcBindings: an identity's live bindings, oldest first.
SELECT * FROM oidc_bindings WHERE organization_id = ? AND identity_id = ? AND revoked_at IS NULL
ORDER BY created_at, id;

-- name: InsertOidcBinding :one
INSERT INTO oidc_bindings (id, identity_id, organization_id, issuer, audience, subject, claims, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: LiveOidcBinding :one
-- readOidcBinding: a live binding of the identity in the Organization.
SELECT * FROM oidc_bindings WHERE id = ? AND organization_id = ? AND identity_id = ? AND revoked_at IS NULL;

-- name: RevokeOidcBinding :one
UPDATE oidc_bindings SET revoked_at = sqlc.arg(revoked_at)
WHERE id = sqlc.arg(id) AND organization_id = sqlc.arg(organization_id) AND identity_id = sqlc.arg(identity_id) AND revoked_at IS NULL
RETURNING id;

-- name: ExchangeOidcBindings :many
-- exchangeOidcToken: the issuer's live bindings in the Organization (by id
-- or slug, not deleted), of identities not disabled, in the order they
-- were made.
SELECT b.* FROM oidc_bindings b
JOIN identities i ON i.id = b.identity_id
JOIN organizations o ON o.id = b.organization_id
WHERE (o.id = sqlc.arg(organization) OR o.slug = sqlc.arg(organization)) AND o.deleted_at IS NULL
  AND b.issuer = sqlc.arg(issuer) AND b.revoked_at IS NULL AND i.disabled = 0
ORDER BY b.rowid;

-- name: InsertOidcTokenUse :execrows
-- A token exchanged under a binding that takes each once: no row when it
-- was exchanged before.
INSERT INTO oidc_token_uses (token_key, used_at, expires_at) VALUES (?, ?, ?)
ON CONFLICT (token_key) DO NOTHING;

-- name: PruneOidcTokenUses :exec
-- Uses of tokens no longer accepted, oldest first, a bounded number at once.
DELETE FROM oidc_token_uses WHERE token_key IN (
  SELECT t.token_key FROM oidc_token_uses t WHERE t.expires_at < sqlc.arg(before) ORDER BY t.expires_at LIMIT 500);
