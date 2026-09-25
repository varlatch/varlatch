// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Audit webhooks: per-organization endpoints that receive batches of audit
 * events, signed with a per-webhook HMAC secret. The secret is stored
 * encrypted under the organization KEK (never plaintext at rest); delivery
 * is cursor-based over audit_events, so it is at-least-once and needs no
 * queue. The cursor starts at creation time: a new webhook never receives
 * history.
 */
export const sql = /* sql */ `
CREATE TABLE webhooks (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  url text NOT NULL,
  event_types text[],
  secret_envelope jsonb NOT NULL,
  created_by text REFERENCES identities(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  cursor_occurred_at timestamptz NOT NULL,
  cursor_event_id text NOT NULL DEFAULT '',
  failure_count integer NOT NULL DEFAULT 0,
  last_attempt_at timestamptz,
  last_status text
);
CREATE INDEX webhooks_org_idx ON webhooks(organization_id) WHERE revoked_at IS NULL;
`;
