-- The writes of values (domain/values.ts setValue, deleteValue and
-- applyChangeSet; ADR-0059 step 4.1d). The read path's queries are
-- values.sql's.

-- name: ValueRowsOfItems :many
-- lockValueRows: an environment's value rows for these names, deleted ones
-- included, in id order. seed is 1 for one that holds a seed of one-time
-- codes (ADR-0061) and 2 for an OAuth connection (ADR-0062): its deleted_at
-- does not mean deleted.
SELECT id, item_name, current_version_id, deleted_at,
  CAST(coalesce((SELECT CASE WHEN json_type(s.payload, '$.totp') = 'object' THEN 1 WHEN json_type(s.payload, '$.oauth') = 'object' THEN 2 END FROM value_versions s WHERE s.id = env_values.current_version_id AND env_values.deleted_at IS NOT NULL), 0) AS INTEGER) AS seed
FROM env_values
WHERE environment_id = sqlc.arg(environment_id) AND item_name IN (sqlc.slice(item_names)) ORDER BY id;

-- name: InsertValueRow :exec
INSERT INTO env_values (id, environment_id, item_name, created_at) VALUES (?, ?, ?, ?);

-- name: InsertValueVersion :exec
INSERT INTO value_versions (id, value_id, payload, wrapped_dek, previous_version_id, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: SetCurrentValueVersion :exec
-- A plain write supersedes any rotation in flight (ADR-0027 section 6).
UPDATE env_values SET current_version_id = ?, deleted_at = NULL,
  retiring_version_id = NULL, rotation_deadline = NULL, rotation_started_at = NULL
WHERE id = ?;

-- name: SetCurrentSeedVersion :exec
-- As SetCurrentValueVersion, for a seed of one-time codes (ADR-0061): the
-- row reads as deleted to whoever does not know seeds.
UPDATE env_values SET current_version_id = sqlc.arg(version), deleted_at = sqlc.arg(now),
  retiring_version_id = NULL, rotation_deadline = NULL, rotation_started_at = NULL
WHERE id = sqlc.arg(id);

-- name: LiveValueCount :one
SELECT count(*) FROM env_values WHERE environment_id = ? AND item_name = ? AND (deleted_at IS NULL OR
  EXISTS (SELECT 1 FROM value_versions s WHERE s.id = env_values.current_version_id AND (json_type(s.payload, '$.totp') = 'object' OR json_type(s.payload, '$.oauth') = 'object')));

-- name: DeleteValueRow :exec
UPDATE env_values SET deleted_at = ?, current_version_id = NULL,
  retiring_version_id = NULL, rotation_deadline = NULL, rotation_started_at = NULL
WHERE id = ?;

-- name: DeleteLiveValue :execrows
UPDATE env_values SET deleted_at = ?, current_version_id = NULL,
  retiring_version_id = NULL, rotation_deadline = NULL, rotation_started_at = NULL
WHERE environment_id = ? AND item_name = ? AND (deleted_at IS NULL OR
  EXISTS (SELECT 1 FROM value_versions s WHERE s.id = env_values.current_version_id AND (json_type(s.payload, '$.totp') = 'object' OR json_type(s.payload, '$.oauth') = 'object')));

-- name: ValueRotationOf :many
-- beginRotation and completeRotation: the item's value row with its
-- rotation, deleted or not (seed as in ValueRowsOfItems).
SELECT id, current_version_id, retiring_version_id, rotation_deadline, deleted_at,
  CAST(coalesce((SELECT CASE WHEN json_type(s.payload, '$.totp') = 'object' THEN 1 WHEN json_type(s.payload, '$.oauth') = 'object' THEN 2 END FROM value_versions s WHERE s.id = env_values.current_version_id AND env_values.deleted_at IS NOT NULL), 0) AS INTEGER) AS seed
FROM env_values
WHERE environment_id = ? AND item_name = ?;

-- name: BeginValueRotation :exec
-- beginRotation (ADR-0027): the new primary, the prior one retiring until
-- the deadline.
UPDATE env_values SET current_version_id = ?, retiring_version_id = ?, rotation_deadline = ?, rotation_started_at = ?
WHERE id = ?;

-- name: CompleteValueRotation :exec
-- completeRotation (ADR-0027): the retiring version dropped.
UPDATE env_values SET retiring_version_id = NULL, rotation_deadline = NULL, rotation_started_at = NULL WHERE id = ?;
