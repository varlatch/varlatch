// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Invitation management: an organization can list its invitations and
 * revoke a pending one. `revoked_at` is a revoked invitation's terminal
 * state (the row stays, for audit correlation), and consumption refuses a
 * revoked grant; a grant is never both consumed and revoked. `created_by`
 * records the issuing identity for invitations issued from now on; earlier
 * rows keep NULL. The partial index serves the per-organization listing,
 * newest first.
 */
export const sql = /* sql */ `
ALTER TABLE setup_grants
  ADD COLUMN revoked_at timestamptz,
  ADD COLUMN created_by text REFERENCES identities(id);
ALTER TABLE setup_grants ADD CONSTRAINT setup_grants_single_terminal_state
  CHECK (revoked_at IS NULL OR consumed_at IS NULL);
CREATE INDEX setup_grants_invite_org_idx
  ON setup_grants (invite_organization_id, created_at DESC, id DESC)
  WHERE kind = 'invite';
`;
