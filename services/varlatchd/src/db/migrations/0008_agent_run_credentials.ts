// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Agent metadata-credential mode (ADR-0023, foreseen by ADR-0022 §8): a
 * broker may mint a short-lived, read-only "agent-run" credential for an
 * Agent Identity so an Agent Run can read configuration metadata directly.
 * The credential row reuses the existing table; only the kind set widens.
 */
export const sql = /* sql */ `
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_check
  CHECK (kind IN ('service','cli','browser','agent-run'));
`;
