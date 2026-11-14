-- People, browser sessions and passkeys (ADR-0059 Decision 6, step 3.4;
-- the TypeScript server's auth/humanauth.ts, auth/approval-assertion.ts and
-- domain/passkeys.ts). auth_sessions and passkeys take no upsert: a
-- duplicate is checked before the insert, in the same write job.

-- name: InsertAuthUser :exec
INSERT INTO auth_users (id, name, email, email_verified, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?);

-- name: AuthUserOfIdentity :one
SELECT better_auth_user_id FROM auth_user_links WHERE identity_id = ?;

-- name: InsertAuthSession :exec
INSERT INTO auth_sessions (id, expires_at, token_hash, created_at, updated_at, ip_address, user_agent, user_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: SessionByTokenHash :one
SELECT s.id, s.expires_at, s.updated_at, s.user_id, l.identity_id
FROM auth_sessions s JOIN auth_user_links l ON l.better_auth_user_id = s.user_id
WHERE s.token_hash = ?;

-- name: LiveSessionOfIdentity :one
SELECT s.expires_at FROM auth_sessions s JOIN auth_user_links l ON l.better_auth_user_id = s.user_id
WHERE s.id = sqlc.arg(id) AND l.identity_id = sqlc.arg(identity_id) AND s.expires_at > sqlc.arg(now);

-- name: ExtendAuthSession :exec
UPDATE auth_sessions SET expires_at = ?, updated_at = ? WHERE id = ?;

-- name: DeleteExpiredAuthSessions :execrows
DELETE FROM auth_sessions WHERE expires_at <= ?;

-- name: PasskeysOfIdentity :many
SELECT p.id, p.credential_id, p.public_key, p.transports, p.counter
FROM passkeys p JOIN auth_user_links l ON l.better_auth_user_id = p.user_id
WHERE l.identity_id = ?
ORDER BY p.created_at IS NULL, p.created_at, p.id;

-- name: PasskeyByCredentialID :many
SELECT p.id, p.user_id, p.public_key, p.counter, p.transports, l.identity_id
FROM passkeys p LEFT JOIN auth_user_links l ON l.better_auth_user_id = p.user_id
WHERE p.credential_id = ?
LIMIT 2;

-- name: CountPasskeysWithCredentialID :one
SELECT count(*) FROM passkeys WHERE credential_id = ?;

-- name: InsertPasskey :exec
INSERT INTO passkeys (id, name, public_key, user_id, credential_id, counter, device_type, backed_up, transports, created_at, aaguid)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: PasskeyCounter :one
SELECT counter FROM passkeys WHERE id = ?;

-- name: AdvancePasskeyCounter :exec
UPDATE passkeys SET counter = ? WHERE id = ?;

-- name: DeletePasskey :execrows
DELETE FROM passkeys WHERE id = ?;

-- name: OwnPasskeys :many
SELECT p.id, p.name, p.device_type, p.backed_up, p.created_at,
       coalesce(pp.trust, 'unconfirmed') AS trust, pp.trusted_via, pp.trusted_at, pp.setup_grant_kind, pp.confirmed_by_passkey_id
FROM passkeys p
LEFT JOIN passkey_provenance pp ON pp.passkey_id = p.id
JOIN auth_user_links l ON l.better_auth_user_id = p.user_id
WHERE l.identity_id = ?
ORDER BY p.created_at, p.id;

-- name: InsertProvenanceTrusted :exec
INSERT INTO passkey_provenance (passkey_id, trust, trusted_via, trusted_at, setup_grant_kind, recorded_at)
VALUES (sqlc.arg(passkey_id), 'trusted', 'setup-grant', sqlc.arg(now), sqlc.arg(setup_grant_kind), sqlc.arg(now))
ON CONFLICT (passkey_id) DO NOTHING;

-- name: InsertProvenanceUnconfirmed :exec
INSERT INTO passkey_provenance (passkey_id, trust, recorded_at) VALUES (?, 'unconfirmed', ?)
ON CONFLICT (passkey_id) DO NOTHING;

-- name: ConfirmProvenance :exec
INSERT INTO passkey_provenance (passkey_id, trust, trusted_via, trusted_at, confirmed_by_passkey_id, recorded_at)
VALUES (sqlc.arg(passkey_id), 'trusted', 'confirmed', sqlc.arg(now), sqlc.arg(confirmed_by), sqlc.arg(now))
ON CONFLICT (passkey_id) DO UPDATE SET trust = 'trusted', trusted_via = 'confirmed',
  trusted_at = excluded.trusted_at, confirmed_by_passkey_id = excluded.confirmed_by_passkey_id, setup_grant_kind = NULL
WHERE passkey_provenance.trust = 'unconfirmed';

-- name: InsertSessionEvidence :exec
INSERT INTO auth_session_evidence (session_id, ceremony, user_verified, passkey_id, recorded_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (session_id) DO NOTHING;

-- name: SweepSessionEvidence :exec
DELETE FROM auth_session_evidence
WHERE NOT EXISTS (SELECT 1 FROM auth_sessions s WHERE s.id = auth_session_evidence.session_id)
  AND NOT EXISTS (
    SELECT 1 FROM credentials c
    WHERE c.auth_session_id = auth_session_evidence.session_id AND c.revoked_at IS NULL
      AND (c.expires_at IS NULL OR c.expires_at > sqlc.arg(now)));

-- name: ConfirmationChallengeWindow :one
SELECT count(*) AS issued, CAST(coalesce(min(created_at), 0) AS INTEGER) AS oldest
FROM passkey_confirmation_challenges
WHERE identity_id = sqlc.arg(identity_id) AND created_at > sqlc.arg(since);

-- name: SupersedeConfirmationChallenges :exec
UPDATE passkey_confirmation_challenges SET consumed_at = sqlc.arg(now)
WHERE identity_id = sqlc.arg(identity_id) AND auth_session_id = sqlc.arg(auth_session_id)
  AND target_passkey_id = sqlc.arg(target_passkey_id) AND consumed_at IS NULL;

-- name: InsertConfirmationChallenge :exec
INSERT INTO passkey_confirmation_challenges (id, identity_id, auth_session_id, target_passkey_id, challenge, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: BoundConfirmationChallenge :one
SELECT id FROM passkey_confirmation_challenges
WHERE challenge = ? AND identity_id = ? AND auth_session_id = ? AND target_passkey_id = ?;

-- name: ConsumeConfirmationChallenge :execrows
UPDATE passkey_confirmation_challenges SET consumed_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND consumed_at IS NULL AND expires_at > sqlc.arg(now);

-- name: PasskeyRemovalRestriction :many
SELECT DISTINCT m.organization_id FROM org_memberships m
JOIN organizations o ON o.id = m.organization_id AND o.deleted_at IS NULL
JOIN security_controls s ON s.organization_id = m.organization_id AND s.mode = 'enforce'
WHERE m.identity_id = ? AND m.removed_at IS NULL
ORDER BY m.organization_id;
