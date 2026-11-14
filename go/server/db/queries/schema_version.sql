-- name: GetSchemaVersion :one
SELECT version, compatible_from, created_at, created_by_release, updated_at, updated_by_release
  FROM schema_version WHERE singleton = 1;

-- name: CreateSchemaVersion :exec
INSERT INTO schema_version (version, compatible_from, created_at, created_by_release, updated_at, updated_by_release)
VALUES (?, ?, ?, ?, ?, ?);
