// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Capabilities (ADR-0022): server-side records redeemed with a high-entropy
 * capability secret (hash at rest; the secret itself is returned exactly once
 * at issuance). A row narrows potential future use — it never grants: the
 * Agent's secret.use is re-evaluated on every exercise. Items are Contract
 * item names (the stable Config Item identity in this domain); destinations
 * are canonical selectors serialized as text.
 */
export const sql = /* sql */ `
CREATE TABLE capabilities (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  broker_identity_id text NOT NULL REFERENCES identities(id),
  agent_identity_id text NOT NULL REFERENCES identities(id),
  project_id text NOT NULL REFERENCES projects(id),
  environment_id text NOT NULL REFERENCES environments(id),
  items text[] NOT NULL,
  destinations text[] NOT NULL,
  secret_hash text NOT NULL,
  run_id text,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_by text NOT NULL REFERENCES identities(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX capabilities_org_idx ON capabilities (organization_id, created_at);
CREATE INDEX capabilities_broker_idx ON capabilities (broker_identity_id);
`;
