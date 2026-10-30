// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Runs in progress per Sync Target (ADR-0050 Decisions 3 to 5): one row per
 * reconciliation that took the lease, with its deadline on the database
 * clock. The run's send check refuses after the deadline, so a Target is
 * drained (no run of it can start another request) when none of its rows
 * has a deadline still in the future. A run deletes its own row when it
 * ends; the sync loop deletes rows whose deadline passed (a process that
 * died mid-run, a database restored from an archive).
 *
 * The runtime role's default privileges (migration 3) cover the new table.
 */
export const sql = /* sql */ `
CREATE TABLE sync_runs (
  target_id text NOT NULL REFERENCES sync_targets(id),
  generation bigint NOT NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  deadline timestamptz NOT NULL,
  PRIMARY KEY (target_id, generation)
);
CREATE INDEX sync_runs_target_deadline ON sync_runs (target_id, deadline);
`;
