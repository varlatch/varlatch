-- name: CreateOrganization :exec
INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES (?, ?, ?, ?);

-- name: CreateGitHubAppRegistration :one
INSERT INTO github_app_registrations (state_hash, organization_id, actor_identity_id, account_login, account_type, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id;

-- name: ConvertGitHubAppRegistration :execrows
UPDATE github_app_registrations
   SET consumed_at = sqlc.arg(converted_at), converted_at = sqlc.arg(converted_at), pending_expires_at = sqlc.arg(pending_expires_at),
       pending_github_app_id = sqlc.arg(pending_github_app_id), pending_slug = sqlc.arg(pending_slug),
       pending_client_id = sqlc.arg(pending_client_id), pending_owner_login = sqlc.arg(pending_owner_login),
       pending_owner_id = sqlc.arg(pending_owner_id), pending_owner_type = sqlc.arg(pending_owner_type),
       pending_key_envelope = sqlc.arg(pending_key_envelope)
 WHERE state_hash = sqlc.arg(state_hash);

-- name: EndGitHubAppRegistration :execrows
UPDATE github_app_registrations SET ended_at = ?, end_reason = ?, pending_key_envelope = NULL WHERE state_hash = ?;

-- name: GetGitHubAppRegistration :one
SELECT * FROM github_app_registrations WHERE state_hash = ?;
