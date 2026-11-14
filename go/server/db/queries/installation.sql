-- The installation row and its Root KEK canary (ADR-0011, ADR-0019): one
-- row, created at first start (go/server/daemon).

-- name: GetInstallation :one
SELECT id, kek_canary, bootstrapped_at FROM installation LIMIT 1;

-- name: CreateInstallation :exec
INSERT INTO installation (id, kek_canary) VALUES (?, ?);
