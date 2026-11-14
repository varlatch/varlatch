-- Step-up approvals (ADR-0054 Decision 3; the TypeScript server's
-- domain/approvals.ts). Every statement runs in a write job, so the single
-- writer orders them; "now" is read inside the job.

-- name: SweepApprovalIntents :exec
DELETE FROM approval_intents WHERE expires_at < ?;

-- name: OpenApprovalsOfCredential :one
SELECT count(*) FROM approval_intents
WHERE credential_id = sqlc.arg(credential_id) AND consumed_at IS NULL AND closed_at IS NULL AND expires_at > sqlc.arg(now);

-- name: ApprovalsCreatedSince :one
SELECT count(*) AS n, CAST(coalesce(min(created_at), 0) AS INTEGER) AS oldest FROM approval_intents
WHERE identity_id = sqlc.arg(identity_id) AND created_at > sqlc.arg(since);

-- name: InsertApprovalIntent :exec
INSERT INTO approval_intents (id, credential_id, identity_id, organization_id, operation, target, body_hash, query_hash,
                              expected_version, summary, origin, created_at, expires_at, poll_interval, auth_session_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ApprovalIntentOf :one
SELECT a.id, a.credential_id, a.identity_id, a.organization_id,
       coalesce(o.slug, '') AS org_slug, coalesce(o.name, '') AS org_name,
       a.operation, a.summary, c.kind AS credential_kind, c.client, a.poll_interval, a.created_at, a.expires_at,
       a.approved_at, a.consumed_at, a.closed_at, a.close_reason, a.last_polled_at, a.origin, a.auth_session_id,
       a.target, a.body_hash, a.query_hash, a.expected_version
FROM approval_intents a
JOIN credentials c ON c.id = a.credential_id
LEFT JOIN organizations o ON o.id = a.organization_id
WHERE a.id = sqlc.arg(id) AND a.identity_id = sqlc.arg(identity_id);

-- name: SlowDownApproval :one
UPDATE approval_intents SET poll_interval = poll_interval + sqlc.arg(slow_down), last_polled_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) RETURNING poll_interval;

-- name: MarkApprovalPolled :exec
UPDATE approval_intents SET last_polled_at = ? WHERE id = ?;

-- name: ApprovalChallengesSince :one
SELECT count(*) AS issued, CAST(coalesce(min(created_at), 0) AS INTEGER) AS oldest FROM approval_intent_challenges
WHERE identity_id = sqlc.arg(identity_id) AND created_at > sqlc.arg(since);

-- name: SupersedeApprovalChallenges :exec
UPDATE approval_intent_challenges SET consumed_at = sqlc.arg(now)
WHERE intent_id = sqlc.arg(intent_id) AND identity_id = sqlc.arg(identity_id) AND auth_session_id = sqlc.arg(auth_session_id)
  AND consumed_at IS NULL;

-- name: InsertApprovalChallenge :exec
INSERT INTO approval_intent_challenges (id, intent_id, identity_id, auth_session_id, challenge, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: BoundApprovalChallenge :one
SELECT id FROM approval_intent_challenges
WHERE challenge = ? AND intent_id = ? AND identity_id = ? AND auth_session_id = ?;

-- name: ConsumeApprovalChallenge :execrows
UPDATE approval_intent_challenges SET consumed_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND consumed_at IS NULL AND expires_at > sqlc.arg(now);

-- name: MarkApprovalApproved :execrows
UPDATE approval_intents SET approved_at = sqlc.arg(now), approved_with_passkey_id = sqlc.arg(passkey_id),
       approval_user_verified = sqlc.arg(user_verified)
WHERE id = sqlc.arg(id) AND approved_at IS NULL AND consumed_at IS NULL AND closed_at IS NULL AND expires_at > sqlc.arg(now);

-- name: CancelApprovalIntent :exec
UPDATE approval_intents SET closed_at = ?, close_reason = 'cancelled' WHERE id = ?;

-- name: ConsumeApprovalIntent :one
UPDATE approval_intents SET consumed_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND approved_at IS NOT NULL AND consumed_at IS NULL AND closed_at IS NULL
  AND expires_at > sqlc.arg(now)
  AND identity_id = sqlc.arg(identity_id) AND operation = sqlc.arg(operation)
  AND ((origin = 'cli' AND credential_id = sqlc.arg(credential_id))
       OR (origin = 'dashboard' AND sqlc.arg(credential_kind) = 'browser' AND auth_session_id = sqlc.narg(auth_session_id)))
  AND organization_id IS sqlc.narg(organization_id) AND json(target) = json(sqlc.arg(target))
  AND body_hash = sqlc.arg(body_hash) AND query_hash = sqlc.arg(query_hash)
  AND expected_version IS sqlc.narg(expected_version)
RETURNING id, approved_with_passkey_id, approval_user_verified, auth_session_id;

-- name: LiveRequesterCredential :one
SELECT count(*) FROM credentials c JOIN identities i ON i.id = c.identity_id
WHERE c.id = sqlc.arg(id) AND c.identity_id = sqlc.arg(identity_id) AND c.revoked_at IS NULL
  AND (c.expires_at IS NULL OR c.expires_at > sqlc.arg(now)) AND NOT i.disabled
  AND (sqlc.narg(auth_session_id) IS NULL OR (c.kind = 'browser' AND c.auth_session_id = sqlc.narg(auth_session_id)));
