-- The read path of values (ADR-0059 step 3.6): a retrieval's scope, its
-- captured state, and the report counts of the Security Controls it meets.

-- name: RetrievalOrganization :one
-- The Organization's KEK, read in the retrieval's snapshot (orgKekOf).
SELECT id, wrapped_org_kek FROM organizations WHERE id = ?;

-- name: LiveProject :one
-- domain/projects.ts getProject: by ID or slug, not deleted.
SELECT id, organization_id, slug, name, contract_authority, active_contract_revision_id, created_at FROM projects
WHERE organization_id = sqlc.arg(organization_id) AND (id = sqlc.arg(slug_or_id) OR slug = sqlc.arg(slug_or_id)) AND deleted_at IS NULL;

-- name: LiveEnvironment :one
-- domain/environments.ts getEnvironment: by ID or name, not deleted.
SELECT id, project_id, name, kind, tier, parent_environment_id, owner_identity_id, expires_at, created_at FROM environments
WHERE project_id = sqlc.arg(project_id) AND (id = sqlc.arg(name_or_id) OR name = sqlc.arg(name_or_id)) AND deleted_at IS NULL;

-- name: ProjectContractRevision :one
-- domain/contracts.ts getRevision.
SELECT id, content_hash, contract FROM contract_revisions WHERE id = ? AND project_id = ?;

-- name: CurrentValuesOfEnvironment :many
-- domain/retrieval.ts resolveItems: an environment's live values.
SELECT id, item_name, current_version_id, retiring_version_id, rotation_deadline FROM env_values
WHERE environment_id = ? AND deleted_at IS NULL AND current_version_id IS NOT NULL;

-- name: SeedsOfEnvironment :many
-- An environment's seeds of one-time codes (ADR-0061): the rows a reader of
-- values takes for deleted ones, whose current version says it is a seed.
SELECT v.id, v.item_name, v.current_version_id, v.retiring_version_id, v.rotation_deadline,
  CAST(json_extract(s.payload, '$.totp') AS TEXT) AS params
FROM env_values v JOIN value_versions s ON s.id = v.current_version_id
WHERE v.environment_id = ? AND v.deleted_at IS NOT NULL AND v.current_version_id IS NOT NULL AND json_type(s.payload, '$.totp') = 'object';

-- name: OneTimeCodeGiven :many
-- The newest step a seed's code was given for; no row when there is none.
SELECT step FROM one_time_codes_given WHERE version_id = ?;

-- name: GiveOneTimeCode :exec
INSERT INTO one_time_codes_given (version_id, step, ends_at) VALUES (?, ?, ?)
ON CONFLICT (version_id) DO UPDATE SET step = max(one_time_codes_given.step, excluded.step), ends_at = max(one_time_codes_given.ends_at, excluded.ends_at);

-- name: CapturedCiphertext :many
-- domain/retrieval.ts captureState: an erased version has nothing to capture.
SELECT id, payload, wrapped_dek FROM value_versions WHERE id IN (sqlc.slice(ids)) AND erased_at IS NULL;

-- name: ExportControl :one
-- domain/exportstepup.ts exportControl: admin-step-up when it is not off.
SELECT mode, version FROM security_controls WHERE organization_id = ? AND control = 'admin-step-up' AND mode <> 'off';

-- name: LiveOrganizationExists :one
SELECT count(*) FROM organizations WHERE id = ? AND deleted_at IS NULL;

-- name: LiveMembershipExists :one
SELECT count(*) FROM org_memberships WHERE organization_id = ? AND identity_id = ? AND removed_at IS NULL;

-- name: CountWouldBlock :many
-- domain/securityreport.ts countWouldBlock's upsert: a count into its hour,
-- unless that hour was already summarized (emitted), which returns no row.
INSERT INTO security_control_counters
  (organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour, count, first_seen, last_seen)
VALUES (sqlc.arg(organization_id), sqlc.arg(control), sqlc.arg(config_version), sqlc.arg(operation), sqlc.arg(actor_identity_id),
  sqlc.arg(reason), sqlc.arg(bucket_hour), sqlc.arg(count), sqlc.arg(seen), sqlc.arg(seen))
ON CONFLICT (organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour)
DO UPDATE SET count = security_control_counters.count + excluded.count,
  last_seen = max(security_control_counters.last_seen, excluded.last_seen)
WHERE security_control_counters.emitted_at IS NULL
RETURNING bucket_hour;

-- name: ProjectFreshness :one
-- exportstepup.ts freshnessOf: the Project as it is now.
SELECT active_contract_revision_id, deleted_at FROM projects WHERE id = ?;

-- name: EnvironmentsFreshness :many
-- exportstepup.ts freshnessOf: the environment and its parent as they are now.
SELECT id, deleted_at, expires_at FROM environments WHERE id IN (sqlc.slice(ids));
