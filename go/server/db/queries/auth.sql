-- name: CreateIdentity :exec
INSERT INTO identities (id, kind, name, organization_id) VALUES (?, ?, ?, ?);

-- name: CreateCredential :exec
INSERT INTO credentials (id, identity_id, kind, token_hash, expires_at, revoked_at, auth_session_id)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetCredential :one
SELECT * FROM credentials WHERE id = ?;

-- name: CreateAuthUser :exec
INSERT INTO auth_users (id, name, email) VALUES (?, ?, ?);

-- name: DeleteAuthUser :execrows
DELETE FROM auth_users WHERE id = ?;

-- name: LinkAuthUser :exec
INSERT INTO auth_user_links (better_auth_user_id, identity_id) VALUES (?, ?);

-- name: CreateAuthSession :exec
INSERT INTO auth_sessions (id, expires_at, token_hash, user_id) VALUES (?, ?, ?, ?);

-- name: DeleteAuthSession :execrows
DELETE FROM auth_sessions WHERE id = ?;

-- name: DeleteAuthSessionsOfUser :execrows
DELETE FROM auth_sessions WHERE user_id = ?;

-- name: CreatePasskey :exec
INSERT INTO passkeys (id, name, public_key, user_id, credential_id, counter, device_type, backed_up)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetPasskeyCounter :one
SELECT counter FROM passkeys WHERE id = ?;

-- name: SetPasskeyCounter :exec
UPDATE passkeys SET counter = ? WHERE id = ?;

-- name: RenamePasskey :exec
UPDATE passkeys SET name = ? WHERE id = ?;

-- name: DeleteOtherAuthSessionsOfIdentity :execrows
-- signOutOtherSessions: every browser session of the identity's Better
-- Auth users but keep (the trigger revokes their browser credentials).
DELETE FROM auth_sessions
WHERE id <> sqlc.arg(keep)
  AND user_id IN (SELECT better_auth_user_id FROM auth_user_links WHERE identity_id = sqlc.arg(identity_id));

-- name: BrowserBearerSessionLive :one
-- signOutOtherSessions, in its write: whether the presenting browser bearer
-- and the session it came from are both still live.
SELECT count(*) FROM credentials c JOIN auth_sessions s ON s.id = c.auth_session_id
WHERE c.id = sqlc.arg(credential_id) AND c.identity_id = sqlc.arg(identity_id) AND c.kind = 'browser'
  AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at > sqlc.arg(now))
  AND s.expires_at > sqlc.arg(now);
