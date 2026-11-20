-- Moving an installation (ADR-0059 step 6, slice 6.9; domain/bootstrap.ts
-- issueReenrollmentGrants, completePublicUrlChange and moveFacts).

-- name: ReenrollCandidates :many
-- Every enabled person, for `reenroll --all`, in id order.
SELECT id, name, installation_admin, kind, disabled, created_at FROM identities
WHERE kind = 'human' AND NOT disabled
ORDER BY id;

-- name: ReenrollSubjects :many
-- The named identities, for `reenroll --identity`, in id order.
SELECT id, name, installation_admin, kind, disabled, created_at FROM identities
WHERE id IN (sqlc.slice(ids))
ORDER BY id;

-- name: RevokeLiveReenrollGrants :execrows
-- A new link for a person revokes the unused ones issued before it.
UPDATE setup_grants SET revoked_at = sqlc.arg(now)
WHERE kind = 'reenroll' AND subject_identity_id = sqlc.arg(identity_id)
  AND consumed_at IS NULL AND revoked_at IS NULL;

-- name: InstallationPublicURL :one
SELECT public_url FROM installation LIMIT 1;

-- name: SetInstallationPublicURL :exec
UPDATE installation SET public_url = ?;

-- name: AllIdentityIDs :many
SELECT id FROM identities ORDER BY id;

-- name: DeleteAllPasskeys :execrows
DELETE FROM passkeys;

-- name: LiveBrowserCredentials :many
SELECT id, identity_id FROM credentials
WHERE kind = 'browser' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > sqlc.arg(now))
ORDER BY id;

-- name: RevokeBrowserCredential :exec
UPDATE credentials SET revoked_at = sqlc.arg(now) WHERE id = sqlc.arg(id) AND revoked_at IS NULL;

-- name: DeleteAllAuthSessions :execrows
DELETE FROM auth_sessions;

-- name: MoveFacts :one
-- What a move to another public URL affects, read only.
SELECT
  (SELECT count(*) FROM identities WHERE kind = 'human' AND NOT disabled) AS people,
  (SELECT count(*) FROM identities WHERE installation_admin AND NOT disabled) AS installation_admins,
  (SELECT count(*) FROM identities i WHERE i.installation_admin AND NOT i.disabled
     AND EXISTS (SELECT 1 FROM auth_user_links l JOIN passkeys p ON p.user_id = l.better_auth_user_id
                 WHERE l.identity_id = i.id)) AS admins_with_passkey,
  (SELECT count(*) FROM passkeys) AS passkeys,
  (SELECT count(*) FROM auth_sessions) AS sessions,
  (SELECT count(*) FROM requirements r WHERE r.kind = 'tailnet' AND r.revoked_at IS NULL) AS tailnet_constraints,
  (SELECT count(*) FROM setup_grants g
     WHERE g.kind = 'invite' AND g.consumed_at IS NULL AND g.revoked_at IS NULL AND g.expires_at > sqlc.arg(now)) AS pending_invitations;
