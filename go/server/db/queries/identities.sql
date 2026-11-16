-- Machine identities and their credentials (domain/identities.ts,
-- ADR-0034; ADR-0059 step 4.4a).

-- name: OrganizationIdentities :many
-- listOrgIdentities: the Organization's machines and every person with a
-- membership, former members included, oldest first.
SELECT i.id, i.kind, i.name, i.disabled, i.last_seen_at, m.role AS org_role, m.removed_at, u.email, u.image
FROM identities i
LEFT JOIN org_memberships m ON m.identity_id = i.id AND m.organization_id = sqlc.arg(organization_id)
LEFT JOIN auth_user_links l ON l.identity_id = i.id
LEFT JOIN auth_users u ON u.id = l.better_auth_user_id
WHERE i.organization_id = sqlc.arg(organization_id) OR m.identity_id IS NOT NULL
ORDER BY i.created_at, i.id;

-- name: MachineIdentityOf :one
-- readMachineIdentity: a machine identity of the Organization.
SELECT id, name, kind, disabled, suspended_by_deletion FROM identities
WHERE id = ? AND organization_id = ? AND kind <> 'human';

-- name: IdentityInOrganization :one
-- The route's loadMachineIdentity and loadAgentIdentity read.
SELECT id, kind, disabled FROM identities WHERE id = ? AND organization_id = ?;

-- name: InsertMachineIdentity :exec
INSERT INTO identities (id, kind, name, organization_id, created_at) VALUES (?, ?, ?, ?, ?);

-- name: SetIdentityDisabled :exec
UPDATE identities SET disabled = ? WHERE id = ?;

-- name: SetIdentityName :exec
UPDATE identities SET name = ? WHERE id = ?;

-- name: IdentityNameOf :one
SELECT name FROM identities WHERE id = ?;

-- name: LiveCredentialsOfIdentity :many
-- retireIdentity: the live credentials, revoked in their usual order.
SELECT id FROM credentials WHERE identity_id = ? AND revoked_at IS NULL ORDER BY created_at, id;

-- name: CredentialsOfIdentityNewestFirst :many
-- listIdentityCredentials: metadata only, never token material.
SELECT id, kind, name, created_at, expires_at, revoked_at, last_used_at, client
FROM credentials WHERE identity_id = ? ORDER BY created_at DESC, id;

-- name: CredentialOfKinds :one
-- A credential of the identity, of one of the kinds a revocation may name.
SELECT id FROM credentials WHERE id = sqlc.arg(id) AND identity_id = sqlc.arg(identity_id) AND kind IN (sqlc.slice(kinds));
