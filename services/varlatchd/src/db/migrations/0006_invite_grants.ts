// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Invitation grants (ADR-0006: invitations are links an admin hands out, not
 * emails). An invite consumes into a NEW installation-level human identity
 * (never an Installation Admin) plus an organization membership with the
 * invited role.
 */
export const sql = /* sql */ `
ALTER TABLE setup_grants DROP CONSTRAINT setup_grants_kind_check;
ALTER TABLE setup_grants ADD CONSTRAINT setup_grants_kind_check
  CHECK (kind IN ('bootstrap','recover','invite'));
ALTER TABLE setup_grants ADD COLUMN invite_organization_id text REFERENCES organizations(id);
ALTER TABLE setup_grants ADD COLUMN invite_role text CHECK (invite_role IN ('admin','member'));
ALTER TABLE setup_grants ADD COLUMN invite_name text;
ALTER TABLE setup_grants ADD CONSTRAINT invite_fields CHECK (
  (kind = 'invite' AND invite_organization_id IS NOT NULL AND invite_role IS NOT NULL)
  OR (kind <> 'invite' AND invite_organization_id IS NULL AND invite_role IS NULL)
);
`;
