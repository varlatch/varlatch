// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Sync Targets (ADR-0031): varlatchd pushes an Environment's Effective
 * Configuration to external platforms.
 *
 * - platform_connections: org-scoped platform auth. The base identity is
 *   immutable (changing where a Connection points would silently redirect
 *   every referencing Target); the Platform Credential rests encrypted under
 *   the Organization KEK and is never displayed after entry.
 * - sync_targets: one Environment bound to one destination on a Connection.
 *   canonical_destination is Connection-independent (platform + base
 *   identity + destination), and the partial unique index is the
 *   installation-wide single-writer claim: at most one non-revoked Target
 *   per destination. generation + lease_expires_at implement the per-Target
 *   reconciliation lease (fencing token).
 * - sync_ledger: per destination name, the content identity (keyed
 *   fingerprint — never a bare hash) last written, its state machine
 *   (intent precedes the wire; tombstones out-live deletions), and the
 *   generation that wrote it.
 * - sync_cursor: the trigger scanner's position in audit_events. sync.*
 *   events are excluded by the scanner so delivery can never trigger itself;
 *   Target mutations enqueue directly (needs_sync) and never rely on it.
 */
export const sql = /* sql */ `
CREATE TABLE platform_connections (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  platform text NOT NULL,
  base_identity text NOT NULL,
  name text NOT NULL,
  credential_envelope jsonb NOT NULL,
  created_by text REFERENCES identities(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  version integer NOT NULL DEFAULT 1,
  updated_at timestamptz
);
CREATE INDEX platform_connections_org_idx
  ON platform_connections(organization_id) WHERE revoked_at IS NULL;

CREATE TABLE sync_targets (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  project_id text NOT NULL REFERENCES projects(id),
  environment_id text NOT NULL REFERENCES environments(id),
  connection_id text NOT NULL REFERENCES platform_connections(id),
  destination jsonb NOT NULL,
  canonical_destination text NOT NULL,
  mapping jsonb NOT NULL,
  remove_orphans boolean NOT NULL DEFAULT false,
  redeploy boolean NOT NULL DEFAULT false,
  state text NOT NULL DEFAULT 'active'
    CHECK (state IN ('active', 'paused', 'disabled')),
  disabled_reason text,
  failure_count integer NOT NULL DEFAULT 0,
  needs_sync boolean NOT NULL DEFAULT true,
  next_attempt_at timestamptz,
  last_attempt_at timestamptz,
  last_result text,
  last_repair_at timestamptz,
  generation bigint NOT NULL DEFAULT 0,
  lease_expires_at timestamptz,
  created_by text REFERENCES identities(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  version integer NOT NULL DEFAULT 1,
  updated_at timestamptz
);
CREATE UNIQUE INDEX sync_targets_destination_claim
  ON sync_targets(canonical_destination) WHERE revoked_at IS NULL;
CREATE INDEX sync_targets_env_idx
  ON sync_targets(environment_id) WHERE revoked_at IS NULL;
CREATE INDEX sync_targets_connection_idx
  ON sync_targets(connection_id) WHERE revoked_at IS NULL;

CREATE TABLE sync_ledger (
  target_id text NOT NULL REFERENCES sync_targets(id),
  dest_name text NOT NULL,
  fingerprint text,
  state text NOT NULL
    CHECK (state IN ('intent-write', 'written', 'failed-write',
                     'intent-delete', 'tombstone', 'failed-delete')),
  generation bigint NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_error text,
  PRIMARY KEY (target_id, dest_name)
);

CREATE TABLE sync_cursor (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  occurred_at timestamptz NOT NULL,
  event_id text NOT NULL DEFAULT ''
);
`;
