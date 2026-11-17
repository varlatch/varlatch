-- Organization deletion (domain/orgdeletion.ts, ADR-0051 Decisions 4 to 8;
-- ADR-0059 step 4.12b), and the audit-access tombstone (Decision 8).

-- name: LiveAdminCount :one
-- adminCount: the Organization's live admin memberships of enabled
-- identities.
SELECT count(*) FROM org_memberships m JOIN identities i ON i.id = m.identity_id
WHERE m.organization_id = ? AND m.role = 'admin' AND m.removed_at IS NULL AND NOT i.disabled;

-- name: IsLiveAdmin :one
-- requireLiveAdmin's row: a live built-in admin membership of an enabled
-- identity (the kind is the caller's check).
SELECT count(*) FROM org_memberships m JOIN identities i ON i.id = m.identity_id
WHERE m.organization_id = ? AND m.identity_id = ? AND m.role = 'admin' AND m.removed_at IS NULL AND NOT i.disabled;

-- name: OpenDeletionRow :one
-- getDeletion: the open request, if any.
SELECT * FROM organization_deletions WHERE organization_id = ? AND cancelled_at IS NULL AND completed_at IS NULL;

-- name: DeletionRow :one
-- requestRow: the request by its id, of the Organization.
SELECT * FROM organization_deletions WHERE id = ? AND organization_id = ?;

-- name: InsertDeletion :one
INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required)
VALUES (?, ?, ?, ?, ?, ?) RETURNING *;

-- name: EnabledMachinesOf :many
-- The machine identities scheduling suspends, in id order.
SELECT id FROM identities WHERE organization_id = ? AND kind <> 'human' AND NOT disabled ORDER BY id;

-- name: PauseActiveSyncTargets :execrows
-- Paused with the ADR-0050 fence: a push in progress stops. A cancel
-- leaves them paused.
UPDATE sync_targets SET state = 'paused', generation = generation + 1, lease_expires_at = NULL,
  repair_cycle_started_at = NULL, version = version + 1, updated_at = @now
WHERE organization_id = @organization_id AND revoked_at IS NULL AND state = 'active';

-- name: SuspendWebhooks :execrows
UPDATE webhooks SET suspended_by_deletion = @deletion_id
WHERE organization_id = @organization_id AND revoked_at IS NULL AND suspended_by_deletion IS NULL;

-- name: SuspendMachines :execrows
UPDATE identities SET disabled = 1, suspended_by_deletion = @deletion_id
WHERE organization_id = @organization_id AND kind <> 'human' AND NOT disabled;

-- name: RevokePendingInvitations :execrows
UPDATE setup_grants SET revoked_at = @now
WHERE kind = 'invite' AND invite_organization_id = @organization_id AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > @now;

-- name: DeleteGitHubAppRegistrations :exec
-- Unfinished GitHub App registrations are invalidated (step 4.10's rows).
DELETE FROM github_app_registrations WHERE organization_id = ?;

-- name: ApproveDeletion :one
UPDATE organization_deletions SET approved_by = @approved_by, approved_at = @now WHERE id = @id RETURNING *;

-- name: SuspendedMachinesOf :many
-- The machine identities a request suspended, which its cancel restores.
SELECT id FROM identities WHERE suspended_by_deletion = ? ORDER BY id;

-- name: CancelDeletion :one
UPDATE organization_deletions SET cancelled_by = @cancelled_by, cancelled_at = @now WHERE id = @id RETURNING *;

-- name: RestoreMachines :execrows
UPDATE identities SET disabled = 0, suspended_by_deletion = NULL WHERE suspended_by_deletion = ?;

-- name: ResumeWebhooks :execrows
UPDATE webhooks SET suspended_by_deletion = NULL WHERE suspended_by_deletion = ?;

-- name: DueDeletions :many
-- runDueDeletions: found without a claim; each is claimed in its own job.
SELECT id, organization_id FROM organization_deletions
WHERE cancelled_at IS NULL AND completed_at IS NULL AND run_after <= @now
  AND (NOT approval_required OR approved_by IS NOT NULL)
ORDER BY run_after, id;

-- name: LiveOrganizationForDeletion :one
SELECT id, slug, name FROM organizations WHERE id = ? AND deleted_at IS NULL;

-- name: DueDeletionRow :one
-- The claim's request: open and due.
SELECT * FROM organization_deletions WHERE id = @id AND organization_id = @organization_id
  AND cancelled_at IS NULL AND completed_at IS NULL AND run_after <= @now;

-- name: DeletionReferencedPeople :many
-- The people the finalization references: the live human members and the
-- owners of open approvals.
SELECT m.identity_id AS id FROM org_memberships m JOIN identities i ON i.id = m.identity_id
WHERE m.organization_id = @organization_id AND m.removed_at IS NULL AND i.kind = 'human'
UNION SELECT identity_id FROM approval_intents WHERE organization_id = @organization_id AND consumed_at IS NULL AND closed_at IS NULL;

-- name: MachinesOf :many
-- Every machine identity of the Organization, which the finalization retires.
SELECT id FROM identities WHERE organization_id = ? AND kind <> 'human' ORDER BY id;

-- name: LiveHumanMembers :many
SELECT m.identity_id, m.role, i.disabled FROM org_memberships m JOIN identities i ON i.id = m.identity_id
WHERE m.organization_id = ? AND m.removed_at IS NULL AND i.kind = 'human' ORDER BY m.identity_id;

-- name: InsertTombstoneReader :exec
INSERT INTO audit_tombstone_readers (organization_id, identity_id, added_at) VALUES (?, ?, ?);

-- name: DeleteOrganizationProjects :execrows
UPDATE projects SET deleted_at = @now WHERE organization_id = @organization_id AND deleted_at IS NULL;

-- name: DeleteOrganizationEnvironments :exec
UPDATE environments SET deleted_at = @now
WHERE deleted_at IS NULL AND project_id IN (SELECT p.id FROM projects p WHERE p.organization_id = @organization_id);

-- name: DeleteOrganizationValues :exec
UPDATE env_values SET deleted_at = COALESCE(deleted_at, @now), current_version_id = NULL,
  retiring_version_id = NULL, rotation_deadline = NULL, rotation_started_at = NULL
WHERE environment_id IN (SELECT e.id FROM environments e JOIN projects p ON p.id = e.project_id WHERE p.organization_id = @organization_id);

-- name: EraseOrganizationVersions :execrows
UPDATE value_versions SET payload = NULL, wrapped_dek = NULL, erased_at = @now
WHERE erased_at IS NULL AND value_id IN (
  SELECT v.id FROM env_values v JOIN environments e ON e.id = v.environment_id JOIN projects p ON p.id = e.project_id
  WHERE p.organization_id = @organization_id);

-- name: RevokeOrganizationCapabilities :exec
UPDATE capabilities SET revoked_at = @now WHERE organization_id = @organization_id AND revoked_at IS NULL;

-- name: RevokeOrganizationSyncTargets :execrows
-- Revocation fences a push in progress (ADR-0050 Decision 1).
UPDATE sync_targets SET revoked_at = @now, generation = generation + 1, lease_expires_at = NULL,
  repair_cycle_started_at = NULL, version = version + 1, updated_at = @now
WHERE organization_id = @organization_id AND revoked_at IS NULL;

-- name: RevokeOrganizationConnections :execrows
UPDATE platform_connections SET revoked_at = @now, version = version + 1, updated_at = @now
WHERE organization_id = @organization_id AND revoked_at IS NULL;

-- name: RemoveOrganizationGitHubApps :execrows
-- The local registration goes, so the App can be imported elsewhere;
-- GitHub still has it.
UPDATE github_apps SET removed_at = @now, key_envelope = NULL WHERE organization_id = @organization_id AND removed_at IS NULL;

-- name: RevokeOrganizationWebhooks :execrows
UPDATE webhooks SET revoked_at = @now, suspended_by_deletion = NULL WHERE organization_id = @organization_id AND revoked_at IS NULL;

-- name: RetireOrganizationMachines :exec
UPDATE identities SET disabled = 1, suspended_by_deletion = NULL WHERE organization_id = ? AND kind <> 'human';

-- name: RevokeOrganizationMachineCredentials :execrows
UPDATE credentials SET revoked_at = @now
WHERE revoked_at IS NULL AND identity_id IN (SELECT i.id FROM identities i WHERE i.organization_id = @organization_id AND i.kind <> 'human');

-- name: RevokeOrganizationOIDCBindings :exec
UPDATE oidc_bindings SET revoked_at = @now WHERE organization_id = @organization_id AND revoked_at IS NULL;

-- name: DeleteOrganizationCounters :exec
-- Report counters go with the Organization: nothing is summarized for a
-- deleted one.
DELETE FROM security_control_counters WHERE organization_id = ?;

-- name: TombstoneOrganization :exec
-- The tombstone, and the Organization KEK destroyed.
UPDATE organizations SET deleted_at = @now, wrapped_org_kek = NULL, org_kek_destroyed_at = @now WHERE id = @id;

-- name: CompleteDeletion :exec
UPDATE organization_deletions SET completed_at = @now WHERE id = @id;

-- name: IsTombstoneReader :one
-- requireTombstoneReader: a reader fixed at the deletion, not removed, of
-- a deleted Organization.
SELECT count(*) FROM audit_tombstone_readers r JOIN organizations o ON o.id = r.organization_id
WHERE r.organization_id = ? AND r.identity_id = ? AND r.removed_at IS NULL AND o.deleted_at IS NOT NULL;

-- name: DeletedOrganizations :many
SELECT id, slug, name, deleted_at FROM organizations WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC, id;

-- name: TombstoneReaders :many
-- Every reader of the deleted Organizations, removed or not.
SELECT r.organization_id, r.identity_id, i.name, r.removed_at FROM audit_tombstone_readers r
JOIN identities i ON i.id = r.identity_id
JOIN organizations o ON o.id = r.organization_id AND o.deleted_at IS NOT NULL
ORDER BY r.identity_id;

-- name: RemoveTombstoneReader :execrows
UPDATE audit_tombstone_readers SET removed_at = @now, removed_by = @removed_by
WHERE organization_id = @organization_id AND identity_id = @identity_id AND removed_at IS NULL;
