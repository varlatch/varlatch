-- Device-authorization sign-in (ADR-0043 Decision 2; the TypeScript
-- server's domain/device-sign-in.ts). Every statement runs in a write job,
-- so the single writer orders them; "now" is read inside the job.

-- name: ExpireLapsedDeviceSignIns :exec
UPDATE device_sign_ins SET status = 'expired'
WHERE status IN ('pending', 'approved') AND expires_at <= ?;

-- name: DeleteOldDeviceSignInChallenges :exec
DELETE FROM device_sign_in_challenges
WHERE device_sign_in_challenges.expires_at < sqlc.arg(before)
   OR device_sign_in_id IN (SELECT d.id FROM device_sign_ins d WHERE d.expires_at < sqlc.arg(before));

-- name: DeleteOldDeviceSignIns :exec
DELETE FROM device_sign_ins WHERE expires_at < ?;

-- name: DeleteOldDeviceCodeWindows :exec
DELETE FROM device_code_attempt_windows WHERE window_started_at < ?;

-- name: PendingDeviceSignInCounts :one
SELECT CAST(coalesce(sum(requester_ip = sqlc.arg(peer)), 0) AS INTEGER) AS peer, count(*) AS total
FROM device_sign_ins WHERE status = 'pending' AND expires_at > sqlc.arg(now);

-- name: PendingUserCodeTaken :one
SELECT count(*) FROM device_sign_ins WHERE user_code = ? AND status = 'pending';

-- name: InsertDeviceSignIn :exec
INSERT INTO device_sign_ins (id, device_code_hash, user_code, requested_ttl, requested_name, requester_ip,
                             requester_user_agent, created_at, expires_at, poll_interval)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeviceSignInByCodeHash :one
SELECT * FROM device_sign_ins WHERE device_code_hash = ?;

-- name: DeviceSignIn :one
SELECT * FROM device_sign_ins WHERE id = ?;

-- name: SetDeviceSignInStatus :exec
UPDATE device_sign_ins SET status = ? WHERE id = ?;

-- name: SlowDownDeviceSignIn :one
UPDATE device_sign_ins SET poll_interval = poll_interval + sqlc.arg(slow_down), last_polled_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) RETURNING poll_interval;

-- name: MarkDeviceSignInPolled :exec
UPDATE device_sign_ins SET last_polled_at = ? WHERE id = ?;

-- name: ConsumeDeviceSignIn :exec
UPDATE device_sign_ins SET status = 'consumed', last_polled_at = sqlc.arg(now), issued_credential_id = sqlc.arg(credential_id)
WHERE id = sqlc.arg(id);

-- name: PendingDeviceSignInByUserCode :one
SELECT * FROM device_sign_ins WHERE user_code = sqlc.arg(user_code) AND status = 'pending' AND expires_at > sqlc.arg(now);

-- name: EnsureDeviceCodeWindow :exec
INSERT INTO device_code_attempt_windows (scope, key, window_started_at, failures) VALUES (?, ?, ?, 0)
ON CONFLICT DO NOTHING;

-- name: DeviceCodeWindow :one
SELECT failures, window_started_at FROM device_code_attempt_windows WHERE scope = ? AND key = ?;

-- name: SetDeviceCodeWindow :exec
UPDATE device_code_attempt_windows SET failures = ?, window_started_at = ? WHERE scope = ? AND key = ?;

-- name: DeleteUnusedDeviceSignInChallenges :exec
DELETE FROM device_sign_in_challenges
WHERE device_sign_in_id = ? AND identity_id = ? AND auth_session_id = ? AND consumed_at IS NULL;

-- name: InsertDeviceSignInChallenge :exec
INSERT INTO device_sign_in_challenges (id, device_sign_in_id, identity_id, auth_session_id, challenge, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: BoundDeviceSignInChallenge :one
SELECT id FROM device_sign_in_challenges
WHERE challenge = ? AND device_sign_in_id = ? AND identity_id = ? AND auth_session_id = ?;

-- name: ConsumeDeviceSignInChallenge :execrows
UPDATE device_sign_in_challenges SET consumed_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND consumed_at IS NULL AND expires_at > sqlc.arg(now);

-- name: DenyDeviceSignIn :execrows
UPDATE device_sign_ins SET status = 'denied', decided_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND status = 'pending' AND expires_at > sqlc.arg(now);

-- name: DeleteDeviceSignInChallenges :exec
DELETE FROM device_sign_in_challenges WHERE device_sign_in_id = ?;

-- name: ApproveDeviceSignIn :execrows
UPDATE device_sign_ins SET status = 'approved', approved_by_identity_id = sqlc.arg(identity_id), decided_at = sqlc.arg(now),
       approval_user_verified = sqlc.arg(user_verified), approval_passkey_id = sqlc.arg(passkey_id)
WHERE id = sqlc.arg(id) AND status = 'pending' AND expires_at > sqlc.arg(now);

-- The conformance harness's probes (daemon/probe_conformance.go, built
-- only with the conformance build tag).

-- name: ExpirePendingDeviceSignIns :exec
UPDATE device_sign_ins SET expires_at = ? WHERE status = 'pending';

-- name: DeviceSignInRequesters :many
SELECT requester_ip FROM device_sign_ins WHERE requested_name = ? ORDER BY created_at, id;
