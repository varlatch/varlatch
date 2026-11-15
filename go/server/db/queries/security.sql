-- Security Controls, their report counters and the approval keys
-- (domain/securitycontrols.ts, securityreport.ts, approvalKeys.ts;
-- ADR-0059 step 4.3).

-- name: SecurityControlsOf :many
SELECT s.control, s.mode, s.config, s.version, s.changed_at, s.changed_by, i.name AS changed_by_name
FROM security_controls s LEFT JOIN identities i ON i.id = s.changed_by
WHERE s.organization_id = ?;

-- name: ActiveSecurityControls :many
-- The Organization's controls at report or enforce (protected.ts
-- applicableControls).
SELECT control, mode, version, config FROM security_controls
WHERE organization_id = ? AND mode <> 'off';

-- name: AnySecurityControlOn :one
SELECT count(*) FROM security_controls WHERE organization_id = ? AND mode <> 'off';

-- name: UpsertSecurityControl :exec
INSERT INTO security_controls (organization_id, control, mode, config, version, changed_by, changed_at)
VALUES (sqlc.arg(organization_id), sqlc.arg(control), sqlc.arg(mode), sqlc.narg(config), sqlc.arg(version),
  sqlc.narg(changed_by), sqlc.arg(changed_at))
ON CONFLICT (organization_id, control) DO UPDATE
  SET mode = excluded.mode, config = excluded.config, version = excluded.version,
      changed_by = excluded.changed_by, changed_at = excluded.changed_at;

-- name: BumpSecurityEpoch :exec
UPDATE organizations SET security_epoch = security_epoch + 1 WHERE id = ?;

-- name: IdentityKindOf :one
SELECT kind FROM identities WHERE id = ?;

-- name: DueReportCounters :many
-- securityreport.ts emitDueSummaries's claim: unemitted rows whose hour
-- ended long enough ago, of a live Organization, in key order.
SELECT c.organization_id, c.control, c.config_version, c.operation, c.actor_identity_id, c.reason, c.bucket_hour,
  c.count, c.first_seen, c.last_seen
FROM security_control_counters c
WHERE c.emitted_at IS NULL AND c.bucket_hour <= sqlc.arg(cutoff)
  AND EXISTS (SELECT 1 FROM organizations o WHERE o.id = c.organization_id AND o.deleted_at IS NULL)
ORDER BY c.organization_id, c.control, c.config_version, c.operation, c.actor_identity_id, c.reason, c.bucket_hour
LIMIT sqlc.arg(lim);

-- name: MarkReportCounterEmitted :exec
UPDATE security_control_counters SET emitted_at = sqlc.arg(now)
WHERE organization_id = sqlc.arg(organization_id) AND control = sqlc.arg(control)
  AND config_version = sqlc.arg(config_version) AND operation = sqlc.arg(operation)
  AND actor_identity_id = sqlc.arg(actor_identity_id) AND reason = sqlc.arg(reason)
  AND bucket_hour = sqlc.arg(bucket_hour);

-- name: DeleteExpiredReportCounters :execrows
-- securityreport.ts deleteExpiredCounters: rows 35 days past their
-- summary, and any of an Organization that is deleted or gone, a batch at
-- a time in key order.
DELETE FROM security_control_counters
WHERE (organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour) IN (
  SELECT k.organization_id, k.control, k.config_version, k.operation, k.actor_identity_id, k.reason, k.bucket_hour
  FROM security_control_counters k
  WHERE (k.emitted_at IS NOT NULL AND k.emitted_at <= sqlc.arg(cutoff))
     OR NOT EXISTS (SELECT 1 FROM organizations o WHERE o.id = k.organization_id AND o.deleted_at IS NULL)
  ORDER BY k.organization_id, k.control, k.config_version, k.operation, k.actor_identity_id, k.reason, k.bucket_hour
  LIMIT sqlc.arg(lim));

-- name: ReportCounterRows :many
-- securityreport.ts securityControlReport's rows: the window's counters,
-- per control, configuration version, operation, reason and actor. Sorted
-- in Go (by count descending, then the key), as the TypeScript ORDER BY.
SELECT c.control, c.config_version, c.operation, c.reason, c.actor_identity_id,
  i.name AS actor_name, i.kind AS actor_kind,
  CAST(sum(c.count) AS INTEGER) AS count,
  CAST(coalesce(sum(CASE WHEN c.bucket_hour = sqlc.arg(hour) THEN c.count END), 0) AS INTEGER) AS current_hour,
  CAST(coalesce(sum(CASE WHEN c.emitted_at IS NULL THEN c.count END), 0) AS INTEGER) AS pending,
  CAST(min(c.first_seen) AS INTEGER) AS first_seen, CAST(max(c.last_seen) AS INTEGER) AS last_seen
FROM security_control_counters c LEFT JOIN identities i ON i.id = c.actor_identity_id
WHERE c.organization_id = sqlc.arg(organization_id) AND c.bucket_hour >= sqlc.arg(since)
GROUP BY c.control, c.config_version, c.operation, c.reason, c.actor_identity_id, i.name, i.kind;

-- name: AdminApprovalKeys :many
-- approvalKeys.ts: the live admins with their passkeys and provenance.
SELECT i.id AS identity_id, i.name AS identity_name,
  p.id AS passkey_id, p.name AS passkey_name, p.created_at,
  pp.trust, pp.trusted_via, pp.trusted_at
FROM org_memberships m
JOIN identities i ON i.id = m.identity_id
LEFT JOIN auth_user_links l ON l.identity_id = i.id
LEFT JOIN passkeys p ON p.user_id = l.better_auth_user_id
LEFT JOIN passkey_provenance pp ON pp.passkey_id = p.id
WHERE m.organization_id = ? AND m.role = 'admin' AND m.removed_at IS NULL
  AND i.kind = 'human' AND NOT i.disabled
ORDER BY i.name, i.id, p.created_at NULLS FIRST, p.id;
