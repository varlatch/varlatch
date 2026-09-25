// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Machine identities (service/workload/ci/broker/agent) belong to exactly one
 * organization (ADR-0003); human identities are installation-level (ADR-0006)
 * and keep organization_id NULL.
 */
export const sql = /* sql */ `
ALTER TABLE identities ADD COLUMN organization_id text REFERENCES organizations(id);
ALTER TABLE identities ADD CONSTRAINT identity_org_scope CHECK (
  (kind = 'human' AND organization_id IS NULL)
  OR (kind <> 'human' AND organization_id IS NOT NULL)
);
CREATE INDEX identities_org_idx ON identities(organization_id);
`;
