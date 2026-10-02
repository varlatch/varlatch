// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * A readable client label on credentials: a short summary of the
 * User-Agent that requested a browser session credential or a CLI login
 * credential ("Firefox on Linux", "varlatch CLI 0.14.0 on Linux"), shown so
 * a person can tell their sessions apart. Only the summary is stored, never
 * the User-Agent itself. NULL when unknown, for every other kind, and for
 * credentials issued before this migration.
 */
export const sql = /* sql */ `
ALTER TABLE credentials ADD COLUMN client text
  CHECK (client IS NULL OR char_length(client) BETWEEN 1 AND 64);
`;
