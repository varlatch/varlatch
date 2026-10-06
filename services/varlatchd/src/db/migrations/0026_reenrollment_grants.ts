// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Re-enrollment grants (issue #103, ADR-0010): a one-time link that adds a
 * new passkey to an EXISTING human identity, issued by the Infrastructure
 * Operator when every passkey stopped working because the installation moved
 * to another public URL (a new WebAuthn relying party). Unlike an invite it
 * creates nothing; unlike recovery it is not limited to Installation Admins.
 */
export const sql = /* sql */ `
ALTER TABLE setup_grants DROP CONSTRAINT setup_grants_kind_check;
ALTER TABLE setup_grants ADD CONSTRAINT setup_grants_kind_check
  CHECK (kind IN ('bootstrap','recover','invite','reenroll'));
ALTER TABLE setup_grants ADD CONSTRAINT reenroll_subject
  CHECK (kind <> 'reenroll' OR subject_identity_id IS NOT NULL);
`;
