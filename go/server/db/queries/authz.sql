-- What the authorization evaluator reads (ADR-0015, ADR-0028, ADR-0055):
-- go/server/authz, as http/support.ts loadGrants, loadTailnetRequirements
-- and domain/orgs.ts getOrgRole read it.

-- name: GetLiveOrganization :one
-- domain/orgs.ts getOrganization: by ID or slug, not deleted.
SELECT id, slug, name FROM organizations WHERE (id = sqlc.arg(slug_or_id) OR slug = sqlc.arg(slug_or_id)) AND deleted_at IS NULL;

-- name: GetOrgRole :one
-- The built-in role of a live membership (ADR-0052 Decision 1).
SELECT role FROM org_memberships WHERE organization_id = ? AND identity_id = ? AND removed_at IS NULL;

-- name: LoadGrantRows :many
-- The subject's unrevoked Grants in the Organization, direct and through
-- live Groups, with their Role's current actions; a person's only through a
-- live membership (ADR-0052 Decision 1). PostgreSQL's query has no ORDER
-- BY: its rows come in heap order, which for rows never updated is the
-- order they were inserted in. Here that order is the rowid's.
SELECT g.id, g.subject_identity_id, g.subject_group_id, g.scope, g.actions, g.role_id,
       r.actions AS role_actions, r.revoked_at AS role_revoked, r.version AS role_version
FROM grants g
LEFT JOIN roles r ON r.id = g.role_id
WHERE g.organization_id = sqlc.arg(organization_id) AND g.revoked_at IS NULL
  AND EXISTS (
    SELECT 1 FROM identities s WHERE s.id = sqlc.arg(subject_identity_id) AND (s.kind <> 'human' OR EXISTS (
      SELECT 1 FROM org_memberships m
      WHERE m.organization_id = sqlc.arg(organization_id) AND m.identity_id = sqlc.arg(subject_identity_id) AND m.removed_at IS NULL
    ))
  )
  AND (
    g.subject_identity_id = sqlc.arg(subject_identity_id)
    OR g.subject_group_id IN (
      SELECT gm.group_id FROM group_members gm
      JOIN groups grp ON grp.id = gm.group_id
      WHERE gm.identity_id = sqlc.arg(subject_identity_id) AND grp.revoked_at IS NULL
    )
  )
ORDER BY g.rowid;

-- name: TeamProjects :many
-- A team's owned Projects, for a team-scoped Grant (ADR-0028). No ORDER BY
-- in PostgreSQL either: insertion order, here the rowid's.
SELECT project_id FROM team_projects WHERE team_id = ? ORDER BY rowid;

-- name: LoadTailnetRequirements :many
SELECT id, target, config, version FROM requirements
WHERE organization_id = ? AND kind = 'tailnet' AND revoked_at IS NULL
ORDER BY rowid;

-- name: OpenFreeze :one
-- The Organization's open incident freeze (ADR-0055), if any.
SELECT id, frozen_at FROM organization_freezes WHERE organization_id = ? AND lifted_at IS NULL;
