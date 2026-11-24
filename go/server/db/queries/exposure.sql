-- name: AnyMembership :one
-- memberExposure: a current or former member, with their name.
SELECT i.id, i.name, m.role, m.removed_at FROM org_memberships m JOIN identities i ON i.id = m.identity_id
WHERE m.organization_id = ? AND m.identity_id = ?;

-- name: ExposureRows :many
-- What the person received (the exposure index), each version with the
-- value that owns it, its environment and Project, and its confirmation.
SELECT x.version_id, x.item_name, x.environment_id, x.way, x.first_at, x.last_at,
       ev.environment_id AS owner_env, ev.current_version_id, ev.retiring_version_id, ev.rotation_deadline,
       ev.deleted_at AS value_deleted, e.deleted_at AS env_deleted, e.project_id,
       CAST(coalesce((SELECT json_type(s.payload, '$.totp') = 'object' FROM value_versions s WHERE s.id = ev.current_version_id AND ev.deleted_at IS NOT NULL), 0) AS INTEGER) AS seed,
       c.confirmed_at, c.actor_identity_id AS confirmed_by
FROM member_exposure x
LEFT JOIN value_versions v ON v.id = x.version_id
LEFT JOIN env_values ev ON ev.id = v.value_id
LEFT JOIN environments e ON e.id = ev.environment_id
LEFT JOIN projects p ON p.id = e.project_id AND p.organization_id = x.organization_id
LEFT JOIN exposure_confirmations c ON c.organization_id = x.organization_id AND c.version_id = x.version_id
WHERE x.organization_id = sqlc.arg(organization_id) AND x.identity_id = sqlc.arg(identity_id)
ORDER BY x.item_name, x.version_id, x.environment_id, x.way;

-- name: ActiveContracts :many
-- The active Contracts of these Projects (rotation hints). The
-- Organization comes before the list (see NamedIdentities).
SELECT p.id, r.contract FROM projects p JOIN contract_revisions r ON r.id = p.active_contract_revision_id
WHERE p.organization_id = sqlc.arg(organization_id) AND p.id IN (sqlc.slice(ids));

-- name: RemovalOf :one
SELECT id, role, removed_at, actor_identity_id FROM membership_removals WHERE organization_id = ? AND identity_id = ?;

-- name: RemovalAuthorityRows :many
SELECT environment_id, action, source, role, grant_id, via_group_id, role_id FROM removal_authority
WHERE removal_id = ? ORDER BY environment_id, action, source;

-- name: RemovalConditionRows :many
SELECT environment_id, requirement_id FROM removal_conditions WHERE removal_id = ? ORDER BY environment_id, requirement_id;

-- name: RemovalRequirementRows :many
SELECT requirement_id, requirement_version, target, selector FROM removal_requirements WHERE removal_id = ? ORDER BY requirement_id;

-- name: ExposedVersion :one
-- exposedVersion: the value owning an exposed version, and whether it,
-- its environment and its Project are live. No ORDER BY, as there: the
-- rows of one version differ only in their environment and way, which are
-- not selected, so any row gives the same answer.
SELECT x.item_name, ev.environment_id, e.project_id,
       ((ev.deleted_at IS NULL OR EXISTS (SELECT 1 FROM value_versions s WHERE s.id = ev.current_version_id AND json_type(s.payload, '$.totp') = 'object'))
         AND e.deleted_at IS NULL AND p.id IS NOT NULL AND p.deleted_at IS NULL) AS live,
       ev.id AS value_id
FROM member_exposure x
LEFT JOIN value_versions v ON v.id = x.version_id
LEFT JOIN env_values ev ON ev.id = v.value_id
LEFT JOIN environments e ON e.id = ev.environment_id
LEFT JOIN projects p ON p.id = e.project_id AND p.organization_id = x.organization_id
WHERE x.organization_id = ? AND x.identity_id = ? AND x.version_id = ?
LIMIT 1;

-- name: EnvironmentForAuthorization :one
SELECT id, tier, parent_environment_id FROM environments WHERE id = ?;

-- name: InsertConfirmation :many
-- Once per version; RETURNING nothing when one exists.
INSERT INTO exposure_confirmations (organization_id, version_id, identity_id, actor_identity_id, confirmed_at)
VALUES (?, ?, ?, ?, ?) ON CONFLICT (organization_id, version_id) DO NOTHING
RETURNING confirmed_at, actor_identity_id;

-- name: ConfirmationOf :one
SELECT confirmed_at, actor_identity_id FROM exposure_confirmations WHERE organization_id = ? AND version_id = ?;
