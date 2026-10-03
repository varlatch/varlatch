// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Device-authorization sign-in (ADR-0043 Decision 2; the accepted design
 * notes "Device-authorization sign-in"): a CLI starts a pending sign-in,
 * a human approves it in the browser with a fresh passkey assertion, and
 * the CLI collects one `cli` credential.
 *
 * - device_sign_ins: one row per pending sign-in. Only the device code's
 *   SHA-256 is stored; the user code is unique among pending rows. No
 *   credential exists before collection, which mints it.
 * - device_sign_in_challenges: approval challenges, each bound to one
 *   sign-in, the approving identity, and that identity's Better Auth
 *   session; consumed on use.
 * - device_code_attempt_windows: wrong user-code counters per approving
 *   identity, per peer, and in total, so the guessing limits survive a
 *   restart and apply across sessions and instances.
 * - credentials.auth_session_id: the Better Auth session a browser bearer
 *   was minted from, so an approval challenge can be bound to the session
 *   rather than to one 15-minute bearer. NULL for every other kind.
 */
export const sql = /* sql */ `
CREATE TABLE device_sign_ins (
  id text PRIMARY KEY,
  device_code_hash text NOT NULL UNIQUE,
  user_code text NOT NULL CHECK (user_code ~ '^[BCDFGHJKLMNPQRSTVWXZ]{8}$'),
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'denied', 'consumed', 'expired')),
  requested_ttl integer NOT NULL CHECK (requested_ttl BETWEEN 60 AND 86400),
  requested_name text CHECK (requested_name IS NULL OR char_length(requested_name) BETWEEN 1 AND 200),
  requester_ip text,
  requester_user_agent text CHECK (requester_user_agent IS NULL OR char_length(requester_user_agent) <= 512),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  approved_by_identity_id text REFERENCES identities(id),
  decided_at timestamptz,
  last_polled_at timestamptz,
  poll_interval integer NOT NULL DEFAULT 5 CHECK (poll_interval > 0),
  issued_credential_id text REFERENCES credentials(id)
);
CREATE UNIQUE INDEX device_sign_ins_pending_user_code ON device_sign_ins (user_code) WHERE status = 'pending';
CREATE INDEX device_sign_ins_expires_at ON device_sign_ins (expires_at);

CREATE TABLE device_sign_in_challenges (
  id text PRIMARY KEY,
  device_sign_in_id text NOT NULL REFERENCES device_sign_ins(id) ON DELETE CASCADE,
  identity_id text NOT NULL REFERENCES identities(id),
  auth_session_id text NOT NULL,
  challenge text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz
);
CREATE INDEX device_sign_in_challenges_sign_in ON device_sign_in_challenges (device_sign_in_id);

CREATE TABLE device_code_attempt_windows (
  scope text NOT NULL CHECK (scope IN ('identity', 'peer', 'global')),
  key text NOT NULL,
  window_started_at timestamptz NOT NULL,
  failures integer NOT NULL DEFAULT 0 CHECK (failures >= 0),
  PRIMARY KEY (scope, key)
);

ALTER TABLE credentials ADD COLUMN auth_session_id text
  CHECK (auth_session_id IS NULL OR (kind = 'browser' AND char_length(auth_session_id) BETWEEN 1 AND 200));
`;
