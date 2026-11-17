-- GitHub App connections (domain/githubapps.ts, ADR-0047; ADR-0059 step
-- 4.10): the Organization's App, its registration through GitHub's
-- manifest flow (start, conversion, attachment, discard, the sweep), its
-- import and its removal.

-- name: OrganizationGitHubApp :one
SELECT id, organization_id, github_app_id, slug, client_id, owner_login, owner_id, owner_type, created_by, created_at, version, updated_at,
  key_envelope
FROM github_apps WHERE organization_id = ? AND removed_at IS NULL;

-- name: GitHubAppIDInUse :one
SELECT count(*) FROM github_apps WHERE github_app_id = ? AND removed_at IS NULL;

-- name: InsertGitHubApp :one
-- ON CONFLICT DO NOTHING: another live App of the Organization, or this
-- App live in another one, inserts nothing (github_apps_live_org,
-- github_apps_live_app).
INSERT INTO github_apps (id, organization_id, github_app_id, slug, client_id, owner_login, owner_id, owner_type, key_envelope, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT DO NOTHING
RETURNING id, organization_id, github_app_id, slug, client_id, owner_login, owner_id, owner_type, created_by, created_at, version, updated_at;

-- name: DeleteOldGitHubAppRegistrations :exec
-- Ended registrations, a day past their expiry; one still pending keeps
-- its key until the sweep ends it with its audit event.
DELETE FROM github_app_registrations WHERE expires_at < @cutoff AND (converted_at IS NULL OR ended_at IS NOT NULL);

-- name: InsertGitHubAppRegistration :exec
INSERT INTO github_app_registrations (id, state_hash, organization_id, actor_identity_id, account_login, account_type, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GitHubAppRegistrationByState :one
-- A registration of this person in this Organization, by its state.
SELECT id, account_login, account_type, consumed_at, expires_at, converted_at, ended_at
FROM github_app_registrations WHERE state_hash = ? AND organization_id = ? AND actor_identity_id = ?;

-- name: GitHubAppRegistrationByID :one
SELECT * FROM github_app_registrations WHERE id = ? AND organization_id = ? AND actor_identity_id = ?;

-- name: GitHubAppRegistrationByIDOnly :one
SELECT * FROM github_app_registrations WHERE id = ?;

-- name: ClaimGitHubAppRegistration :exec
-- The claim, with GitHub's answer: one completion per registration.
UPDATE github_app_registrations SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL;

-- name: ConvertGitHubAppRegistrationByID :exec
-- The conversion stored as pending, written once (github_app_registrations_pending_once).
UPDATE github_app_registrations SET converted_at = @converted_at, pending_expires_at = @pending_expires_at,
  pending_github_app_id = @pending_github_app_id, pending_slug = @pending_slug, pending_client_id = @pending_client_id,
  pending_owner_login = @pending_owner_login, pending_owner_id = @pending_owner_id, pending_owner_type = @pending_owner_type,
  pending_key_envelope = @pending_key_envelope
WHERE id = @id;

-- name: EndPendingGitHubAppRegistration :execrows
-- Only while still pending: the key deleted.
UPDATE github_app_registrations SET ended_at = @ended_at, end_reason = @end_reason, pending_key_envelope = NULL
WHERE id = @id AND converted_at IS NOT NULL AND ended_at IS NULL;

-- name: ExpiredPendingGitHubAppRegistrations :many
-- The sweep's candidates, in key order.
SELECT id FROM github_app_registrations
WHERE converted_at IS NOT NULL AND ended_at IS NULL AND pending_expires_at <= @now
ORDER BY state_hash LIMIT @lim;

-- name: GitHubAppReach :one
-- The live Connections of an App, and their live Targets.
SELECT
  (SELECT count(*) FROM platform_connections c WHERE c.github_app_id = @app_id AND c.revoked_at IS NULL) AS connections,
  (SELECT count(*) FROM sync_targets t JOIN platform_connections c ON c.id = t.connection_id
    WHERE c.github_app_id = @app_id AND c.revoked_at IS NULL AND t.revoked_at IS NULL) AS targets;

-- name: GitHubAppConnections :many
SELECT id FROM platform_connections WHERE github_app_id = ? AND revoked_at IS NULL ORDER BY id;

-- name: GitHubAppTargets :many
SELECT t.id FROM sync_targets t JOIN platform_connections c ON c.id = t.connection_id
WHERE c.github_app_id = ? AND c.revoked_at IS NULL AND t.revoked_at IS NULL ORDER BY t.id;

-- name: RevokeGitHubAppConnections :exec
UPDATE platform_connections SET revoked_at = @now, version = version + 1, updated_at = @now
WHERE github_app_id = @app_id AND revoked_at IS NULL;

-- name: DisableGitHubAppTargets :exec
-- Must run before the Connections are revoked: it finds the Targets
-- through their live Connections.
UPDATE sync_targets SET state = 'disabled', disabled_reason = 'connection-revoked', generation = generation + 1,
  lease_expires_at = NULL, repair_cycle_started_at = NULL, version = version + 1, updated_at = @now
WHERE revoked_at IS NULL AND connection_id IN (
  SELECT c.id FROM platform_connections c WHERE c.github_app_id = @app_id AND c.revoked_at IS NULL);

-- name: RemoveGitHubApp :exec
UPDATE github_apps SET removed_at = @now, key_envelope = NULL, version = version + 1, updated_at = @now WHERE id = @id;
