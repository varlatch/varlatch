-- SPDX-License-Identifier: AGPL-3.0-or-later

-- OAuth connections (ADR-0062).

-- name: OAuthConnectionOf :one
-- An environment's connection by its item's name, with its tokens' state.
SELECT v.id AS value_id, v.item_name, s.id AS version_id, s.payload, s.wrapped_dek, CAST(json_extract(s.payload, '$.oauth') AS TEXT) AS params,
  s.created_by, s.created_at, e.id AS environment_id, e.expires_at AS environment_expires_at, e.project_id, p.organization_id, sqlc.embed(c)
FROM env_values v JOIN value_versions s ON s.id = v.current_version_id
JOIN environments e ON e.id = v.environment_id JOIN projects p ON p.id = e.project_id
JOIN oauth_connections c ON c.value_id = v.id AND c.version_id = v.current_version_id
WHERE v.environment_id = sqlc.arg(environment_id) AND v.item_name = sqlc.arg(item_name)
  AND v.deleted_at IS NOT NULL AND json_type(s.payload, '$.oauth') = 'object' AND e.deleted_at IS NULL AND p.deleted_at IS NULL;

-- name: OAuthConnectionByID :one
-- A live connection by its value row, as OAuthConnectionOf.
SELECT v.id AS value_id, v.item_name, s.id AS version_id, s.payload, s.wrapped_dek, CAST(json_extract(s.payload, '$.oauth') AS TEXT) AS params,
  s.created_by, s.created_at, e.id AS environment_id, e.expires_at AS environment_expires_at, e.project_id, p.organization_id, sqlc.embed(c)
FROM env_values v JOIN value_versions s ON s.id = v.current_version_id
JOIN environments e ON e.id = v.environment_id JOIN projects p ON p.id = e.project_id
JOIN oauth_connections c ON c.value_id = v.id AND c.version_id = v.current_version_id
WHERE v.id = sqlc.arg(value_id)
  AND v.deleted_at IS NOT NULL AND json_type(s.payload, '$.oauth') = 'object' AND e.deleted_at IS NULL AND p.deleted_at IS NULL;

-- name: OAuthConnectionsOfEnvironment :many
SELECT v.id AS value_id, v.item_name, s.id AS version_id, CAST(json_extract(s.payload, '$.oauth') AS TEXT) AS params,
  s.created_by, s.created_at, sqlc.embed(c)
FROM env_values v JOIN value_versions s ON s.id = v.current_version_id
JOIN oauth_connections c ON c.value_id = v.id AND c.version_id = v.current_version_id
WHERE v.environment_id = ? AND v.deleted_at IS NOT NULL AND json_type(s.payload, '$.oauth') = 'object'
ORDER BY v.item_name;

-- name: OAuthAccessToken :one
-- What an exercise opens: the access token, and what it is sealed with.
SELECT c.access_token, c.access_expires_at, c.generation, c.account FROM oauth_connections c WHERE c.value_id = ? AND c.version_id = ?;

-- name: OAuthConnectionNow :many
-- An exercise's own job: the connection is still one that may be used.
SELECT c.status, c.paused_at, c.generation FROM oauth_connections c JOIN env_values v ON v.id = c.value_id AND v.current_version_id = c.version_id
WHERE c.value_id = ? AND v.deleted_at IS NOT NULL;

-- name: OAuthConnectionStatus :many
-- Why a connection's row is gone, or whose it is now.
SELECT version_id, status, generation, claim_id FROM oauth_connections WHERE value_id = ?;

-- name: PutOAuthConnection :exec
-- A new connection on a value row: nothing of one that was there before.
INSERT INTO oauth_connections (value_id, version_id, status) VALUES (?, ?, 'not_connected')
ON CONFLICT (value_id) DO UPDATE SET version_id = excluded.version_id, status = 'not_connected', reason = NULL, paused_at = NULL,
  generation = oauth_connections.generation + 1, access_token = NULL, access_expires_at = NULL, access_lifetime = NULL,
  refresh_token = NULL, refresh_expires_at = NULL, keepalive_at = NULL, granted_scopes = NULL, account = '', account_label = '',
  connected_by = NULL, connected_at = NULL, refreshed_at = NULL, failures = 0, retry_at = NULL, claim_id = NULL, claim_until = NULL, unanswered = 0;

-- name: MoveOAuthConnection :exec
-- The parameters changed: the tokens, sealed again, are the new version's,
-- and whatever failed may be tried again.
UPDATE oauth_connections SET version_id = sqlc.arg(version_id), access_token = sqlc.arg(access_token), refresh_token = sqlc.arg(refresh_token),
  generation = generation + 1, failures = 0, retry_at = NULL, keepalive_at = sqlc.arg(keepalive_at)
WHERE value_id = sqlc.arg(value_id);

-- name: PauseOAuthConnection :exec
UPDATE oauth_connections SET paused_at = ? WHERE value_id = ?;

-- name: ClaimOAuthRefresh :execrows
-- One refresh at a time, in whichever process: the claim, and that an answer
-- is owed, before anything is sent.
UPDATE oauth_connections SET claim_id = sqlc.arg(claim_id), claim_until = sqlc.arg(claim_until), unanswered = unanswered + 1
WHERE value_id = sqlc.arg(value_id) AND generation = sqlc.arg(generation) AND (claim_id IS NULL OR claim_until <= sqlc.arg(now));

-- name: SetOAuthTokens :execrows
-- The answer's tokens, all in one: the refresh token that was used is
-- replaced by the one that was given with the access token, or stays.
UPDATE oauth_connections SET status = 'connected', reason = NULL, generation = generation + 1,
  access_token = sqlc.arg(access_token), access_expires_at = sqlc.arg(access_expires_at), access_lifetime = sqlc.arg(access_lifetime),
  refresh_token = sqlc.arg(refresh_token), refresh_expires_at = sqlc.arg(refresh_expires_at), keepalive_at = sqlc.arg(keepalive_at),
  granted_scopes = sqlc.arg(granted_scopes), refreshed_at = sqlc.arg(now), failures = 0, retry_at = NULL,
  claim_id = NULL, claim_until = NULL, unanswered = 0
WHERE value_id = sqlc.arg(value_id) AND claim_id = sqlc.arg(claim_id) AND status <> 'revoked';

-- name: KeepOAuthRefreshToken :execrows
-- An answer whose access token is of no use, but which replaced the refresh
-- token: that one is kept, and the access token there was.
UPDATE oauth_connections SET generation = generation + 1, access_token = sqlc.arg(access_token), refresh_token = sqlc.arg(refresh_token),
  status = 'failing', reason = sqlc.arg(reason), failures = failures + 1, retry_at = sqlc.arg(retry_at),
  claim_id = NULL, claim_until = NULL, unanswered = 0
WHERE value_id = sqlc.arg(value_id) AND claim_id = sqlc.arg(claim_id) AND status <> 'revoked';

-- name: FailOAuthRefresh :execrows
-- A refresh that gave nothing, for now: the tokens stay. answered is whether
-- the server is known not to have used the refresh token.
UPDATE oauth_connections SET status = 'failing', reason = sqlc.arg(reason), failures = failures + 1, retry_at = sqlc.arg(retry_at),
  claim_id = NULL, claim_until = NULL, unanswered = CASE WHEN CAST(sqlc.arg(answered) AS INTEGER) = 1 THEN unanswered - 1 ELSE unanswered END
WHERE value_id = sqlc.arg(value_id) AND claim_id = sqlc.arg(claim_id) AND status <> 'revoked';

-- name: EndOAuthTokens :execrows
-- The refresh token is of no use any more: all tokens forgotten, a person has
-- to connect again. Whose account it was stays.
UPDATE oauth_connections SET status = 'needs_reconnect', reason = sqlc.arg(reason), generation = generation + 1,
  access_token = NULL, access_expires_at = NULL, refresh_token = NULL, refresh_expires_at = NULL, keepalive_at = NULL,
  failures = 0, retry_at = NULL, claim_id = NULL, claim_until = NULL, unanswered = 0
WHERE value_id = sqlc.arg(value_id) AND claim_id = sqlc.arg(claim_id) AND status <> 'revoked';

-- name: ConnectOAuth :execrows
-- A person connected: the tokens of this consent and nothing of before.
UPDATE oauth_connections SET status = 'connected', reason = NULL, generation = generation + 1,
  access_token = sqlc.arg(access_token), access_expires_at = sqlc.arg(access_expires_at), access_lifetime = sqlc.arg(access_lifetime),
  refresh_token = sqlc.arg(refresh_token), refresh_expires_at = sqlc.arg(refresh_expires_at), keepalive_at = sqlc.arg(keepalive_at),
  granted_scopes = sqlc.arg(granted_scopes), account = sqlc.arg(account), account_label = sqlc.arg(account_label),
  connected_by = sqlc.arg(connected_by), connected_at = sqlc.arg(now), refreshed_at = sqlc.arg(now),
  failures = 0, retry_at = NULL, claim_id = NULL, claim_until = NULL, unanswered = 0
WHERE value_id = sqlc.arg(value_id) AND version_id = sqlc.arg(version_id) AND generation = sqlc.arg(generation);

-- name: RevokeOAuthConnection :execrows
-- Disconnected here: every token forgotten. Whose account it was stays.
UPDATE oauth_connections SET status = 'revoked', reason = NULL, generation = generation + 1,
  access_token = NULL, access_expires_at = NULL, refresh_token = NULL, refresh_expires_at = NULL, keepalive_at = NULL, granted_scopes = NULL,
  failures = 0, retry_at = NULL, claim_id = NULL, claim_until = NULL, unanswered = 0
WHERE value_id = ?;

-- name: ReopenOAuthConnection :exec
-- A client's own connection, disconnected before, used again by a person.
UPDATE oauth_connections SET status = 'not_connected', reason = NULL WHERE value_id = ? AND status = 'revoked';

-- name: OAuthRowsToForget :one
-- Whether what RunOnce writes has anything to do.
SELECT CAST(EXISTS (
  SELECT 1 FROM env_values a JOIN value_versions b ON b.id = a.current_version_id
  WHERE a.deleted_at IS NOT NULL AND json_type(b.payload, '$.oauth') = 'object'
    AND NOT EXISTS (SELECT 1 FROM oauth_connections d WHERE d.value_id = a.id)) OR EXISTS (SELECT 1 FROM oauth_authorizations WHERE expires_at <= ?) OR EXISTS (
  SELECT 1 FROM oauth_connections c WHERE NOT EXISTS (
    SELECT 1 FROM env_values v JOIN value_versions s ON s.id = v.current_version_id
    WHERE v.id = c.value_id AND v.current_version_id = c.version_id AND v.deleted_at IS NOT NULL)) AS INTEGER) AS any;

-- name: AdoptOAuthConnections :exec
-- A connection without a row, as a migration there and back leaves it: not
-- connected.
INSERT INTO oauth_connections (value_id, version_id, status)
SELECT v.id, s.id, 'not_connected' FROM env_values v JOIN value_versions s ON s.id = v.current_version_id
WHERE v.deleted_at IS NOT NULL AND json_type(s.payload, '$.oauth') = 'object'
  AND NOT EXISTS (SELECT 1 FROM oauth_connections c WHERE c.value_id = v.id);

-- name: ForgetDeadOAuthConnections :exec
-- The tokens of what is no connection any more, however it went: deleted, or
-- overwritten by a server that does not know connections.
DELETE FROM oauth_connections WHERE NOT EXISTS (
  SELECT 1 FROM env_values v JOIN value_versions s ON s.id = v.current_version_id
  WHERE v.id = oauth_connections.value_id AND v.current_version_id = oauth_connections.version_id AND v.deleted_at IS NOT NULL);

-- name: ForgetOAuthConnection :exec
DELETE FROM oauth_connections WHERE value_id = ?;

-- name: ForgetDeadOAuthConnectionsOf :exec
-- A deleted item's.
DELETE FROM oauth_connections WHERE value_id IN (SELECT v.id FROM env_values v WHERE v.environment_id = ? AND v.item_name = ? AND v.current_version_id IS NULL);

-- name: ForgetOAuthConnectionsOfEnvironment :exec
DELETE FROM oauth_connections WHERE value_id IN (SELECT v.id FROM env_values v WHERE v.environment_id = ?);

-- name: ForgetOAuthConnectionsOfProject :exec
DELETE FROM oauth_connections WHERE value_id IN (SELECT v.id FROM env_values v JOIN environments e ON e.id = v.environment_id WHERE e.project_id = ?);

-- name: ForgetOAuthConnectionsOfOrganization :exec
DELETE FROM oauth_connections WHERE value_id IN (
  SELECT v.id FROM env_values v JOIN environments e ON e.id = v.environment_id JOIN projects p ON p.id = e.project_id WHERE p.organization_id = ?);

-- name: OAuthConnectionsDue :many
-- The connections whose refresh token the provider would otherwise drop.
SELECT value_id FROM oauth_connections
WHERE keepalive_at IS NOT NULL AND keepalive_at <= sqlc.arg(now) AND paused_at IS NULL AND (retry_at IS NULL OR retry_at <= sqlc.arg(now))
ORDER BY keepalive_at LIMIT sqlc.arg(lim);

-- name: InsertOAuthAuthorization :exec
INSERT INTO oauth_authorizations (state_hash, organization_id, value_id, version_id, identity_id, auth_session_id, nonce_hash, verifier, redirect_uri, account_change, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: TakeOAuthAuthorization :one
-- Once: whoever takes it, it is gone.
DELETE FROM oauth_authorizations WHERE state_hash = ? AND organization_id = ? AND identity_id = ? AND auth_session_id = ? RETURNING *;

-- name: EndOAuthAuthorizations :exec
-- Of one connection: its parameters changed, or it was disconnected.
DELETE FROM oauth_authorizations WHERE value_id = ?;

-- name: CountOAuthAuthorizations :one
SELECT count(*) FROM oauth_authorizations WHERE identity_id = ? AND expires_at > ?;

-- name: PruneOAuthAuthorizations :exec
DELETE FROM oauth_authorizations WHERE expires_at <= ?;
