// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Audit export to object storage (ADR-0056).
 *
 * - audit_exports: one row per export an Organization created, kept after
 *   removal with its credential cleared (Decision 1). At most one live
 *   export (active or draining) per Organization: a partial unique index.
 *   The destination (endpoint, region, bucket, prefix, path style); the
 *   credential envelope, under the Organization KEK while active
 *   (purpose audit-export-credential) and under the Root KEK while
 *   draining after the Organization's deletion (purpose
 *   audit-export-drain, Decision 10); the retention (Decision 7); the
 *   current stream and the committed cursor (an audit event_order); the
 *   lease and its generation (Decision 3); the state; the status fields
 *   the Security page shows (Decision 11), among them whether the key could
 *   read an object's content and, separately, its retention; who created
 *   it; a version for changes.
 * - audit_export_plans: the one pending object of an export (Decision 2).
 *   Its bytes are stored as planned, already serialized and compressed,
 *   with their SHA-256 and MD5, the name, the format, the retention and,
 *   for a batch, its range; a retry uploads exactly these, whatever the
 *   release. Deleted when it commits, so the table holds at most one row
 *   per export.
 *
 * Approval Intents gain `audit_export.change` and `audit_export.remove`,
 * which ADR-0056 Decision 9 asks for always, whatever the Security
 * Controls' modes, both bound to an Organization. Every operation 0051
 * named keeps its rules.
 *
 * Nothing else changes. An installation with no export has two empty
 * tables.
 */
const ADMIN_STEP_UP = `'identity.create', 'credential.issue', 'identity.reactivate',
                       'oidc_binding.create', 'oidc_binding.delete',
                       'grant.create', 'grant.replace', 'grant.revoke',
                       'role.create', 'role.update', 'role.delete',
                       'group.create', 'group.update', 'group.delete', 'group.member_add', 'group.member_remove',
                       'team.create', 'team.update', 'team.delete', 'team.member_add', 'team.member_remove',
                       'team.project_add', 'team.project_remove',
                       'member.invite_admin', 'member.promote', 'member.demote', 'member.remove',
                       'webhook.create', 'webhook.update', 'webhook.delete',
                       'connection.create', 'connection.replace_credential', 'connection.delete',
                       'github_app.register', 'github_app.import', 'github_app.replace_key', 'github_app.remove',
                       'project.delete', 'organization.delete', 'secret.export'`;

const AUDIT_EXPORT = `'audit_export.change', 'audit_export.remove'`;

export const sql = /* sql */ `
CREATE TABLE audit_exports (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  endpoint text NOT NULL CHECK (char_length(endpoint) BETWEEN 1 AND 2048),
  region text NOT NULL CHECK (char_length(region) BETWEEN 1 AND 64),
  bucket text NOT NULL CHECK (char_length(bucket) BETWEEN 3 AND 63),
  prefix text NOT NULL CHECK (char_length(prefix) <= 256),
  path_style boolean NOT NULL,
  credential_envelope jsonb,
  retention_mode text CHECK (retention_mode IN ('compliance', 'governance')),
  retention_days integer CHECK (retention_days BETWEEN 1 AND 3650),
  stream_id text NOT NULL,
  stream_started_at timestamptz NOT NULL,
  cursor_order bigint NOT NULL CHECK (cursor_order >= 0),
  generation bigint NOT NULL DEFAULT 0,
  lease_expires_at timestamptz,
  state text NOT NULL CHECK (state IN ('active', 'draining', 'removed', 'completed', 'abandoned')),
  drain_deadline timestamptz,
  -- Status (Decision 11).
  last_attempt_at timestamptz,
  last_success_at timestamptz,
  last_error text,
  failing_since timestamptz,
  failing_recorded boolean NOT NULL DEFAULT false,
  -- What the key could do at the last probe or 412 (Decision 4): read an
  -- object's content (HEAD), and, separately, read its retention.
  key_can_read boolean,
  retention_readable boolean,
  stopped_reason text CHECK (stopped_reason IN ('object_conflict', 'unsupported_format')),
  conditional_checked_at timestamptz,
  lock_verified boolean,
  last_heartbeat_hour timestamptz,
  created_by text NOT NULL REFERENCES identities(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  removed_at timestamptz,
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  CHECK ((retention_mode IS NULL) = (retention_days IS NULL)),
  CHECK ((credential_envelope IS NOT NULL) = (state IN ('active', 'draining'))),
  -- Only a drain has a deadline, and it ends completed or abandoned.
  CHECK ((drain_deadline IS NOT NULL) = (state IN ('draining', 'completed', 'abandoned'))),
  CHECK ((removed_at IS NOT NULL) = (state = 'removed'))
);
CREATE UNIQUE INDEX audit_exports_live_idx ON audit_exports(organization_id) WHERE state IN ('active', 'draining');
CREATE INDEX audit_exports_draining_idx ON audit_exports(drain_deadline) WHERE state = 'draining';

CREATE TABLE audit_export_plans (
  id text PRIMARY KEY,
  export_id text NOT NULL UNIQUE REFERENCES audit_exports(id),
  export_version integer NOT NULL,
  stream_id text NOT NULL,
  generation bigint NOT NULL,
  kind text NOT NULL CHECK (kind IN ('manifest', 'batch', 'heartbeat')),
  object_name text NOT NULL CHECK (char_length(object_name) BETWEEN 1 AND 1024),
  body bytea NOT NULL,
  sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  md5 text NOT NULL CHECK (md5 ~ '^[0-9a-f]{32}$'),
  content_type text NOT NULL,
  content_encoding text CHECK (content_encoding IN ('gzip')),
  format_version integer NOT NULL CHECK (format_version > 0),
  retention_mode text CHECK (retention_mode IN ('compliance', 'governance')),
  retain_until timestamptz,
  first_order bigint,
  last_order bigint,
  event_count integer,
  heartbeat_hour timestamptz,
  planned_at timestamptz NOT NULL,
  CHECK ((retention_mode IS NULL) = (retain_until IS NULL)),
  CHECK ((kind = 'batch') = (first_order IS NOT NULL AND last_order IS NOT NULL AND event_count IS NOT NULL)),
  CHECK ((kind = 'heartbeat') = (heartbeat_hour IS NOT NULL))
);

ALTER TABLE approval_intents DROP CONSTRAINT approval_intents_operation_check;
ALTER TABLE approval_intents ADD CONSTRAINT approval_intents_operation_check
  CHECK (operation IN ('security_control.change', 'passkey.remove', 'organization.unfreeze',
                       'requirement.update', 'requirement.revoke',
                       ${ADMIN_STEP_UP},
                       ${AUDIT_EXPORT}));
ALTER TABLE approval_intents ADD CONSTRAINT approval_intents_audit_export_organization
  CHECK (operation NOT IN (${AUDIT_EXPORT}) OR organization_id IS NOT NULL);
`;
