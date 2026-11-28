-- name: LiveMember :one
-- readMember: a person's live membership, with their name and version.
SELECT m.identity_id, i.name, m.role, m.version FROM org_memberships m JOIN identities i ON i.id = m.identity_id
WHERE m.organization_id = ? AND m.identity_id = ? AND m.removed_at IS NULL;

-- name: OtherLiveAdmins :one
-- requireAnotherAdmin: live, enabled admins other than this person.
SELECT count(*) FROM org_memberships m JOIN identities i ON i.id = m.identity_id
WHERE m.organization_id = ? AND m.role = 'admin' AND m.removed_at IS NULL AND m.identity_id <> ? AND i.disabled = 0;

-- name: RemovalCounts :one
-- removalCounts: what ending the membership would end now.
SELECT
  (SELECT count(*) FROM grants g WHERE g.organization_id = sqlc.arg(organization_id) AND g.subject_identity_id = sqlc.arg(identity_id) AND g.revoked_at IS NULL) AS grant_count,
  (SELECT count(*) FROM group_members gm JOIN groups gr ON gr.id = gm.group_id
    WHERE gr.organization_id = sqlc.arg(organization_id) AND gm.identity_id = sqlc.arg(identity_id)) AS group_count,
  (SELECT count(*) FROM setup_grants s WHERE s.kind = 'invite' AND s.invite_organization_id = sqlc.arg(organization_id) AND s.created_by = sqlc.arg(identity_id)
    AND s.consumed_at IS NULL AND s.revoked_at IS NULL AND s.expires_at > sqlc.arg(now)) AS invitation_count;

-- name: OrganizationNameOf :one
SELECT name FROM organizations WHERE id = ?;

-- name: InsertMembershipRemoval :exec
INSERT INTO membership_removals (id, organization_id, identity_id, role, actor_identity_id, removed_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: EndMembershipRow :exec
UPDATE org_memberships SET removed_at = ?, version = version + 1
WHERE organization_id = ? AND identity_id = ?;

-- name: RevokeMemberGrants :many
UPDATE grants SET revoked_at = ?
WHERE organization_id = ? AND subject_identity_id = ? AND revoked_at IS NULL RETURNING id;

-- name: RemoveMemberGroups :many
DELETE FROM group_members
WHERE identity_id = sqlc.arg(identity_id) AND group_id IN (SELECT gr.id FROM groups gr WHERE gr.organization_id = sqlc.arg(organization_id))
RETURNING group_id;

-- name: RevokeMemberInvitations :many
UPDATE setup_grants SET revoked_at = sqlc.arg(now)
WHERE kind = 'invite' AND invite_organization_id = sqlc.arg(organization_id) AND created_by = sqlc.arg(identity_id)
  AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > sqlc.arg(now)
RETURNING id;

-- name: SnapshotEnvironments :many
-- captureAuthority: the Organization's live environments, by id.
SELECT e.id, e.project_id, e.tier, e.parent_environment_id FROM environments e
JOIN projects p ON p.id = e.project_id
WHERE p.organization_id = ? AND e.deleted_at IS NULL ORDER BY e.id;

-- name: InsertRemovalAuthority :exec
INSERT INTO removal_authority (removal_id, environment_id, action, source, role, grant_id, via_group_id, role_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: InsertRemovalRequirement :exec
INSERT INTO removal_requirements (removal_id, requirement_id, requirement_version, target, selector)
VALUES (?, ?, ?, ?, ?);

-- name: InsertRemovalCondition :exec
INSERT INTO removal_conditions (removal_id, environment_id, requirement_id) VALUES (?, ?, ?);

-- name: SetMemberRole :exec
UPDATE org_memberships SET role = ?, version = version + 1
WHERE organization_id = ? AND identity_id = ? AND removed_at IS NULL;

-- name: ReviewSyncTargets :many
-- memberReview: the Sync Targets the person created or changed.
SELECT t.id, t.project_id, t.environment_id, c.platform, t.state, t.revoked_at, t.created_by, mi.changes
FROM sync_targets t
JOIN platform_connections c ON c.id = t.connection_id
LEFT JOIN member_integrations mi
  ON mi.organization_id = t.organization_id AND mi.identity_id = sqlc.arg(identity_id) AND mi.kind = 'target' AND mi.resource_id = t.id
WHERE t.organization_id = sqlc.arg(organization_id) AND (t.created_by = sqlc.arg(identity_id) OR mi.resource_id IS NOT NULL)
ORDER BY t.created_at, t.id;

-- name: ReviewConnections :many
SELECT c.id, c.name, c.platform, c.credential_kind, c.revoked_at, c.created_by, mi.changes
FROM platform_connections c
LEFT JOIN member_integrations mi
  ON mi.organization_id = c.organization_id AND mi.identity_id = sqlc.arg(identity_id) AND mi.kind = 'connection' AND mi.resource_id = c.id
WHERE c.organization_id = sqlc.arg(organization_id) AND (c.created_by = sqlc.arg(identity_id) OR mi.resource_id IS NOT NULL)
ORDER BY c.created_at, c.id;

-- name: ReviewWebhooks :many
SELECT id, url, url_envelope, revoked_at FROM webhooks WHERE organization_id = ? AND created_by = ? ORDER BY created_at, id;

-- name: ReviewOIDCBindings :many
SELECT b.id, b.identity_id, i.name AS identity_name, b.issuer, b.revoked_at
FROM oidc_bindings b JOIN identities i ON i.id = b.identity_id
WHERE b.organization_id = ? AND b.created_by = ? ORDER BY b.created_at, b.id;

-- name: ReviewCredentials :many
-- The machine credentials the person issued, with their state now.
SELECT c.id, c.name, c.identity_id, i.name AS identity_name, c.revoked_at, i.disabled, c.expires_at, c.max_uses, c.use_count
FROM credentials c JOIN identities i ON i.id = c.identity_id
WHERE c.issued_by = sqlc.arg(identity_id) AND i.kind <> 'human' AND i.organization_id = sqlc.arg(organization_id)
ORDER BY c.created_at, c.id;

-- name: ReviewPersonalEnvironments :many
SELECT e.id, e.name, e.project_id FROM environments e JOIN projects p ON p.id = e.project_id
WHERE p.organization_id = ? AND e.kind = 'personal' AND e.owner_identity_id = ? AND e.deleted_at IS NULL
ORDER BY e.created_at, e.id;

-- name: InsertInvitation :exec
INSERT INTO setup_grants (id, kind, token_hash, expires_at, invite_organization_id, invite_role, invite_name, created_by, created_at)
VALUES (?, 'invite', ?, ?, ?, ?, ?, ?, ?);

-- name: InvitationOf :one
SELECT id, invite_name, invite_role, created_at, expires_at, created_by, consumed_at, revoked_at FROM setup_grants
WHERE id = ? AND kind = 'invite' AND invite_organization_id = ?;

-- name: RevokeInvitationRow :exec
UPDATE setup_grants SET revoked_at = ? WHERE id = ?;

-- name: SetAuthUserName :exec
-- The account's display name, beside identities.name.
UPDATE auth_users SET name = ?, updated_at = ?
WHERE id IN (SELECT l.better_auth_user_id FROM auth_user_links l WHERE l.identity_id = ?);

-- name: SetAuthUserImage :exec
-- The account's image: a data URL, an https URL, or none.
UPDATE auth_users SET image = ?, updated_at = ?
WHERE id IN (SELECT l.better_auth_user_id FROM auth_user_links l WHERE l.identity_id = ?);

