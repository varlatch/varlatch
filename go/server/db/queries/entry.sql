-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Entry links (ADR-0063).

-- name: InsertEntryLink :exec
INSERT INTO entry_links (id, token_hash, organization_id, project_id, environment_id, item_name, accepts, replaces, bound_version_id,
  restricted_to, identity_id, description, requested_by, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: EntryLinkByToken :one
SELECT * FROM entry_links WHERE token_hash = ?;

-- name: EntryLinkOf :one
-- An environment's link; only one asked for by requester, when it is set.
SELECT * FROM entry_links
WHERE id = sqlc.arg(id) AND environment_id = sqlc.arg(environment_id)
  AND (CAST(sqlc.narg(requester) AS TEXT) IS NULL OR requested_by = sqlc.narg(requester));

-- name: ListEntryLinks :many
SELECT * FROM entry_links
WHERE environment_id = sqlc.arg(environment_id)
  AND (CAST(sqlc.narg(requester) AS TEXT) IS NULL OR requested_by = sqlc.narg(requester))
ORDER BY created_at DESC, id DESC LIMIT 200;

-- name: EndEntryLink :execrows
-- Once: only a pending link that has not expired ends.
UPDATE entry_links SET status = sqlc.arg(status), reason = sqlc.narg(reason), ended_at = CAST(sqlc.arg(now) AS INTEGER)
WHERE id = sqlc.arg(id) AND status = 'pending' AND expires_at > CAST(sqlc.arg(now) AS INTEGER);

-- name: RefuseEntryLink :one
-- Counts a refusal, so that only the first ones are recorded.
UPDATE entry_links SET refusals = refusals + 1 WHERE id = ? RETURNING refusals;

-- name: CountEntryLinks :one
-- A requester's links: pending now, and made since.
SELECT CAST(coalesce(sum(status = 'pending' AND expires_at > sqlc.arg(now)), 0) AS INTEGER) AS pending,
  CAST(coalesce(sum(created_at > sqlc.arg(since)), 0) AS INTEGER) AS recent
FROM entry_links WHERE requested_by = sqlc.arg(requested_by);

-- name: PruneEntryLinks :exec
DELETE FROM entry_links WHERE id IN (SELECT e.id FROM entry_links e WHERE e.expires_at < sqlc.arg(before) ORDER BY e.expires_at LIMIT 500);

-- name: ForgetEntryLinksOfOrganization :exec
DELETE FROM entry_links WHERE organization_id = ?;

-- name: EntryLinkPlace :one
-- The names the page shows. Only live ones: no row otherwise.
SELECT o.name AS organization, p.name AS project, e.name AS environment, i.name AS requester, i.kind AS requester_kind,
  i.disabled AS requester_disabled, i.organization_id AS requester_organization
FROM organizations o JOIN projects p ON p.organization_id = o.id JOIN environments e ON e.project_id = p.id, identities i
WHERE o.id = sqlc.arg(organization_id) AND p.id = sqlc.arg(project_id) AND e.id = sqlc.arg(environment_id) AND i.id = sqlc.arg(requested_by)
  AND o.deleted_at IS NULL AND p.deleted_at IS NULL AND e.deleted_at IS NULL;

-- name: EntryLinkPerson :one
-- Whether an identity is a person with a membership of the Organization.
SELECT count(*) FROM identities i JOIN org_memberships m ON m.identity_id = i.id
WHERE i.id = sqlc.arg(id) AND i.kind = 'human' AND NOT i.disabled AND m.organization_id = sqlc.arg(organization_id) AND m.removed_at IS NULL;
