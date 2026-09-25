// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * OIDC machine authentication (foreseen by ADR-0007: CI identities are
 * expected to federate). A binding maps a verified external OIDC token
 * (issuer + audience + subject, plus optional exact-match claims) to one
 * machine Identity; exchanging such a token mints a short-lived 'oidc'
 * credential. No stored secret exists for the workload at all.
 */
export const sql = /* sql */ `
CREATE TABLE oidc_bindings (
  id text PRIMARY KEY,
  identity_id text NOT NULL REFERENCES identities(id),
  organization_id text NOT NULL REFERENCES organizations(id),
  issuer text NOT NULL,
  audience text NOT NULL,
  subject text NOT NULL,
  claims jsonb,
  created_by text REFERENCES identities(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
CREATE INDEX oidc_bindings_issuer_idx ON oidc_bindings(issuer) WHERE revoked_at IS NULL;

ALTER TABLE credentials DROP CONSTRAINT credentials_kind_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_check
  CHECK (kind IN ('service','cli','browser','agent-run','oidc'));
`;
