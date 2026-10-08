// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The acting request's client on Security Audit Events (ADR-0016 §9): the
 * same readable summary of its User-Agent that credentials carry since
 * migration 24 ("Firefox on Linux", "varlatch CLI 0.16.0 on Linux,
 * assisted"), never the header itself. What the client says, not verified.
 * NULL when unknown, for events no authenticated request recorded, and for
 * every event before this migration: history is not backfilled.
 *
 * Append-only is unchanged: the runtime role's INSERT and SELECT on
 * audit_events are table grants (migration 3), which cover a new column,
 * and it still has no UPDATE or DELETE.
 */
export const sql = /* sql */ `
ALTER TABLE audit_events ADD COLUMN client text
  CHECK (client IS NULL OR char_length(client) BETWEEN 1 AND 64);
`;
