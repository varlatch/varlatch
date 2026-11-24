-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Entry links (ADR-0063).

-- name: InsertEntryLink :exec
INSERT INTO entry_links (id, token_hash, organization_id, project_id, environment_id, item_name, accepts, replaces, bound_version_id,
  restricted_to, identity_id, description, requested_by, credential_id, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

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
-- A requester's links: pending now, and made since. A machine's that ended
-- with a revoked credential are none of the first (a person's are ended when
-- that happens).
SELECT CAST(coalesce(sum(l.status = 'pending' AND l.expires_at > sqlc.arg(now) AND (i.kind = 'human' OR c.revoked_at IS NULL)), 0) AS INTEGER) AS pending,
  CAST(coalesce(sum(l.created_at > sqlc.arg(since)), 0) AS INTEGER) AS recent
FROM entry_links l JOIN identities i ON i.id = l.requested_by JOIN credentials c ON c.id = l.credential_id
WHERE l.requested_by = sqlc.arg(requested_by);

-- name: EntryLinkCredential :one
-- What became of the credential a link was made with, and of its identity.
-- binding_revoked_at is when one of the identity's OIDC bindings was revoked
-- after the credential was issued: which one an exchanged credential came
-- from is not kept.
SELECT c.kind, c.revoked_at, c.expires_at, i.kind AS identity_kind, i.disabled, i.suspended_by_deletion,
  CAST(coalesce((SELECT min(b.revoked_at) FROM oidc_bindings b WHERE b.identity_id = c.identity_id AND b.revoked_at >= c.created_at), 0) AS INTEGER) AS binding_revoked_at
FROM credentials c JOIN identities i ON i.id = c.identity_id WHERE c.id = ?;

-- name: EndEntryLinksOfPerson :many
-- A person revoked one of their credentials, with another one: all their
-- pending links end, whatever they were made with, and whether that is revoked
-- now, was before or expired. Not those of the credential, or the browser
-- session, they revoked it with.
UPDATE entry_links SET status = 'cancelled', reason = 'credential-ended', ended_at = CAST(sqlc.arg(now) AS INTEGER)
WHERE requested_by = sqlc.arg(requested_by) AND status = 'pending' AND expires_at > CAST(sqlc.arg(now) AS INTEGER) AND credential_id NOT IN (
  SELECT c.id FROM credentials c, credentials r
  WHERE r.id = sqlc.arg(revoked_with) AND c.identity_id = r.identity_id
    AND (c.id = r.id OR c.kind = 'browser' AND r.kind = 'browser' AND coalesce(c.auth_session_id = r.auth_session_id, 0)))
RETURNING *;

-- name: EndEntryLinksOfMember :many
-- A membership ended: the pending links the person made there end.
UPDATE entry_links SET status = 'cancelled', reason = 'credential-ended', ended_at = CAST(sqlc.arg(now) AS INTEGER)
WHERE requested_by = sqlc.arg(requested_by) AND organization_id = sqlc.arg(organization_id)
  AND status = 'pending' AND expires_at > CAST(sqlc.arg(now) AS INTEGER)
RETURNING *;

-- name: EndEntryLinksOfBrowsers :exec
-- Every browser session was ended by an operator (a move).
UPDATE entry_links SET status = 'cancelled', reason = 'credential-ended', ended_at = CAST(sqlc.arg(now) AS INTEGER)
WHERE status = 'pending' AND expires_at > CAST(sqlc.arg(now) AS INTEGER)
  AND credential_id IN (SELECT c.id FROM credentials c WHERE c.kind = 'browser');

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
