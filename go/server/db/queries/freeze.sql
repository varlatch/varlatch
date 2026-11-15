-- The incident freeze (domain/freeze.ts, ADR-0055) and the operator's
-- reset of Security Controls (securitycontrols.ts resetControls); ADR-0059
-- step 4.3c.

-- name: LiveOrganizationBySlugOrID :one
SELECT id, slug FROM organizations WHERE (id = sqlc.arg(org) OR slug = sqlc.arg(org)) AND deleted_at IS NULL;

-- name: FreezeHistory :many
-- freezeHistory: newest first.
SELECT f.id, f.frozen_at, f.frozen_by, a.name AS frozen_by_name, f.reason, f.lifted_at, f.lifted_by,
       b.name AS lifted_by_name, f.lift_method
FROM organization_freezes f
JOIN identities a ON a.id = f.frozen_by
LEFT JOIN identities b ON b.id = f.lifted_by
WHERE f.organization_id = sqlc.arg(organization_id)
ORDER BY f.frozen_at DESC, f.id DESC
LIMIT sqlc.arg(lim);

-- name: FreezeByID :one
SELECT f.id, f.frozen_at, f.frozen_by, a.name AS frozen_by_name, f.reason, f.lifted_at, f.lifted_by,
       b.name AS lifted_by_name, f.lift_method
FROM organization_freezes f
JOIN identities a ON a.id = f.frozen_by
LEFT JOIN identities b ON b.id = f.lifted_by
WHERE f.organization_id = sqlc.arg(organization_id) AND f.id = sqlc.arg(id);

-- name: InsertFreeze :exec
INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES (?, ?, ?, ?, ?);

-- name: LiftFreeze :execrows
UPDATE organization_freezes SET lifted_at = sqlc.arg(now), lifted_by = sqlc.narg(lifted_by), lift_method = sqlc.arg(method)
WHERE id = sqlc.arg(id) AND lifted_at IS NULL;

-- name: ResumingTargets :many
-- resumingTargets: every active Sync Target of the Organization.
SELECT t.id, p.slug AS project_slug, e.name AS environment_name, c.platform, t.canonical_destination
FROM sync_targets t
JOIN projects p ON p.id = t.project_id
JOIN environments e ON e.id = t.environment_id
JOIN platform_connections c ON c.id = t.connection_id
WHERE t.organization_id = ? AND t.revoked_at IS NULL AND t.state = 'active'
ORDER BY p.slug, e.name, t.id;

-- name: PendingDeletionExists :one
SELECT count(*) FROM organization_deletions WHERE organization_id = ? AND cancelled_at IS NULL AND completed_at IS NULL;

-- name: ResetSecurityControl :exec
UPDATE security_controls SET mode = 'off', version = sqlc.arg(version), changed_by = NULL, changed_at = sqlc.arg(now)
WHERE organization_id = sqlc.arg(organization_id) AND control = sqlc.arg(control);
