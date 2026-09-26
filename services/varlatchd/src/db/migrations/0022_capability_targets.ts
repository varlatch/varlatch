// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Substitution targets on Capabilities (ADR-0039): each item's targets,
 * recorded immutably at issuance. Capabilities issued before this migration
 * keep NULL, which exercise refuses: no Capability can be exercised without
 * targets after the upgrade.
 */
export const sql = /* sql */ `
ALTER TABLE capabilities ADD COLUMN targets jsonb;
`;
