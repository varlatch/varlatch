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
 * Repair cycles (ADR-0050 Decision 4): a forced run opens a cycle on its
 * Target (repair_cycle_started_at) unless one is open. A ledger entry's
 * repaired_at records when a confirmed write, deletion or read-back last
 * proved the name, and an intent or failure clears it; a forced run skips
 * names repaired since the cycle opened, unless ordinary reconciliation
 * needs them, so a repair larger than one run's budget completes over
 * several runs. The cycle closes, setting last_repair_at to its start,
 * when a forced run completes; a pause, revoke or destination change
 * closes it without completing it.
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
ALTER TABLE sync_targets ADD COLUMN repair_cycle_started_at timestamptz;
ALTER TABLE sync_ledger ADD COLUMN repaired_at timestamptz;
`;
