// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Report counters (ADR-0054 Decision 9): what a Security Control in
 * `report` mode would have refused, asked an approval for, or changed,
 * counted per hour instead of written to the audit log per request.
 *
 * - One row per Organization, control, the control's configuration
 *   version at decision time, semantic operation, actor identity, reason
 *   and bucket hour (UTC), with a count, the first and last time it was
 *   counted, and emitted_at once the summary worker has written its
 *   `security_control.would_block` audit event. A fixed set of fields:
 *   never a request body, URL, token, hash or value, and no target.
 * - An increment upserts with ON CONFLICT ... DO UPDATE ... WHERE
 *   emitted_at IS NULL, so an emitted row never changes again; a late
 *   increment goes to the current hour's row instead.
 * - No foreign keys: an insert would take FOR KEY SHARE on the identity
 *   and Organization rows at the end of the transaction, out of the lock
 *   order (domain/approvals.ts). The actor and Organization ids are
 *   identifiers only. Organization deletion deletes its Organization's
 *   rows; the worker deletes the others 35 days after their summary.
 * - Indexes: unemitted rows by bucket for the worker, emitted rows by
 *   emission for retention, and an Organization's rows by bucket for the
 *   Security page.
 */
export const sql = /* sql */ `
CREATE TABLE security_control_counters (
  organization_id text NOT NULL CHECK (char_length(organization_id) BETWEEN 1 AND 200),
  control text NOT NULL
    CHECK (control IN ('requirement-protection', 'admin-step-up', 'passkey-verification', 'credential-lifetime')),
  config_version integer NOT NULL CHECK (config_version > 0),
  operation text NOT NULL CHECK (char_length(operation) <= 64 AND operation ~ '^[a-z][a-z_-]*(\\.[a-z][a-z_-]*)+$'),
  actor_identity_id text NOT NULL CHECK (char_length(actor_identity_id) BETWEEN 1 AND 200),
  reason text NOT NULL CHECK (reason IN (
    'no-approval', 'machine-credential',
    'no-evidence', 'not-user-verified', 'untrusted-passkey',
    'would-default', 'would-refuse'
  )),
  bucket_hour timestamptz NOT NULL CHECK (bucket_hour = date_trunc('hour', bucket_hour, 'UTC')),
  count bigint NOT NULL CHECK (count > 0),
  first_seen timestamptz NOT NULL,
  last_seen timestamptz NOT NULL,
  emitted_at timestamptz,
  CHECK (last_seen >= first_seen),
  PRIMARY KEY (organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour)
);
CREATE INDEX security_control_counters_unemitted ON security_control_counters (bucket_hour)
  WHERE emitted_at IS NULL;
CREATE INDEX security_control_counters_emitted ON security_control_counters (emitted_at)
  WHERE emitted_at IS NOT NULL;
CREATE INDEX security_control_counters_organization ON security_control_counters (organization_id, bucket_hour);
`;
