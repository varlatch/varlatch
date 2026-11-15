-- The cross-project Config Item name search (ADR-0030; the TypeScript
-- config-items route; ADR-0059 step 4.1d). Names only: values never take
-- part.

-- name: SearchEnvironments :many
-- The Organization's live, unexpired environments with their Projects, by
-- Project and name. The TypeScript query has no ORDER BY; PostgreSQL reads
-- the live environments through environments_live_name_key (project_id,
-- name), so it answers in that order (go/README.md, Known TypeScript
-- defects).
SELECT e.id, e.name, e.tier, e.parent_environment_id, e.project_id, p.slug AS project_slug, p.name AS project_name
FROM environments e JOIN projects p ON p.id = e.project_id
WHERE p.organization_id = sqlc.arg(organization_id) AND e.deleted_at IS NULL
  AND (e.expires_at IS NULL OR e.expires_at > sqlc.arg(now))
ORDER BY e.project_id, e.name;

-- name: LiveItemNamesOf :many
-- The live, current item names of these environments.
SELECT environment_id, item_name FROM env_values
WHERE environment_id IN (sqlc.slice(environment_ids)) AND deleted_at IS NULL AND current_version_id IS NOT NULL
ORDER BY rowid;
