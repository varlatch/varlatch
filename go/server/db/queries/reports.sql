-- name: ReachIdentity :one
-- lookupMachine: the identity, and whether it ever had a membership here.
SELECT i.id, i.name, i.kind, i.disabled, i.suspended_by_deletion, i.organization_id,
  EXISTS (SELECT 1 FROM org_memberships m WHERE m.organization_id = sqlc.arg(organization_id) AND m.identity_id = i.id) AS member
FROM identities i WHERE i.id = sqlc.arg(id);

-- name: LiveCredentialCount :one
-- Credentials that are unrevoked, unexpired and not used up.
SELECT count(*) FROM credentials
WHERE identity_id = sqlc.arg(identity_id) AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > sqlc.arg(now))
  AND (max_uses IS NULL OR use_count < max_uses);

-- name: ReachProjects :many
-- The live Projects, by name (byte order).
SELECT id, slug, name FROM projects WHERE organization_id = ? AND deleted_at IS NULL ORDER BY name, id;

-- name: ReachEnvironments :many
-- The live, unexpired Environments of live Projects, by name (byte order).
SELECT e.id, e.project_id, e.name, e.kind, e.tier, e.parent_environment_id FROM environments e
JOIN projects p ON p.id = e.project_id
WHERE p.organization_id = sqlc.arg(organization_id) AND p.deleted_at IS NULL AND e.deleted_at IS NULL
  AND (e.expires_at IS NULL OR e.expires_at > sqlc.arg(now))
ORDER BY e.name, e.id;

-- name: ReviewedCredentials :many
-- credentialReview: the machine credentials that could still authenticate,
-- the short-lived kinds left out, by identity name (byte order).
SELECT c.id, c.name, c.kind, c.created_at, c.expires_at, c.last_used_at,
       c.issued_by, ib.name AS issued_by_name,
       i.id AS identity_id, i.name AS identity_name, i.kind AS identity_kind,
       i.disabled, i.suspended_by_deletion
FROM credentials c
JOIN identities i ON i.id = c.identity_id
LEFT JOIN identities ib ON ib.id = c.issued_by
WHERE i.organization_id = sqlc.arg(organization_id)
  AND i.kind <> 'human'
  AND c.kind NOT IN ('oidc', 'agent-run')
  AND c.revoked_at IS NULL
  AND (c.expires_at IS NULL OR c.expires_at > sqlc.arg(now))
  AND (c.max_uses IS NULL OR c.use_count < c.max_uses)
ORDER BY i.name, i.id, c.created_at, c.id;

-- name: ExpiringCredentials :many
-- The expiry warnings: unrevoked service credentials of machines that
-- expire before the horizon or have expired, soonest first.
SELECT c.id, c.name, c.kind, c.created_at, c.expires_at, c.last_used_at,
       c.issued_by, ib.name AS issued_by_name,
       i.id AS identity_id, i.name AS identity_name, i.kind AS identity_kind,
       i.disabled, i.suspended_by_deletion
FROM credentials c
JOIN identities i ON i.id = c.identity_id
LEFT JOIN identities ib ON ib.id = c.issued_by
WHERE i.organization_id = sqlc.arg(organization_id)
  AND i.kind <> 'human'
  AND c.kind = 'service'
  AND c.revoked_at IS NULL
  AND c.expires_at IS NOT NULL
  AND c.expires_at <= sqlc.arg(horizon)
ORDER BY c.expires_at, c.id;
