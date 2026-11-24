-- Setup grants: bootstrap, recovery, invitation and re-enrollment links
-- (ADR-0010, ADR-0020; the TypeScript server's domain/bootstrap.ts).

-- name: InstallationBootstrap :one
SELECT id, bootstrapped_at FROM installation LIMIT 1;

-- name: MarkInstallationBootstrapped :exec
UPDATE installation SET bootstrapped_at = ? WHERE bootstrapped_at IS NULL;

-- name: InsertSetupGrant :exec
INSERT INTO setup_grants (id, kind, subject_identity_id, token_hash, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: PeekSetupGrant :one
SELECT g.id, g.kind, g.invite_name, i.name AS subject_name, coalesce(i.disabled, 0) AS subject_disabled
FROM setup_grants g LEFT JOIN identities i ON i.id = g.subject_identity_id
WHERE g.token_hash = sqlc.arg(token_hash) AND g.consumed_at IS NULL AND g.revoked_at IS NULL
  AND g.expires_at > sqlc.arg(now);

-- name: SetupGrantByTokenHash :one
SELECT * FROM setup_grants WHERE token_hash = ?;

-- name: ConsumeSetupGrant :exec
UPDATE setup_grants SET consumed_at = ? WHERE id = ?;

-- name: SetupGrantKind :one
SELECT kind FROM setup_grants WHERE token_hash = ?;

-- name: InsertHumanIdentity :exec
INSERT INTO identities (id, kind, name, installation_admin, created_at) VALUES (?, 'human', ?, ?, ?);

-- name: InsertMembership :exec
INSERT INTO org_memberships (organization_id, identity_id, role, created_at) VALUES (?, ?, ?, ?);

-- name: AdminsWithoutPasskey :many
SELECT i.id FROM identities i
WHERE i.installation_admin AND NOT i.disabled
  AND NOT EXISTS (
    SELECT 1 FROM auth_user_links l JOIN passkeys p ON p.user_id = l.better_auth_user_id
    WHERE l.identity_id = i.id)
ORDER BY i.id;

-- name: EnabledInstallationAdminCount :one
SELECT count(*) FROM identities WHERE installation_admin AND NOT disabled;

-- name: EnableIdentity :exec
UPDATE identities SET disabled = 0 WHERE id = ?;

-- name: OpenOrganizationDeletion :one
SELECT id, run_after FROM organization_deletions
WHERE organization_id = ? AND cancelled_at IS NULL AND completed_at IS NULL;

-- name: RevokeUnusedSetupLinks :execrows
-- setup's reissue (admin bootstrap|recover --revoke-unused): the
-- bootstrap and recovery links issued before and never used.
UPDATE setup_grants SET revoked_at = @now
WHERE kind IN ('bootstrap', 'recover') AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > @now;
