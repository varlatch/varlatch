// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The last drift a Target observed (ADR-0050 Decisions 8 to 11): set in the
 * same guarded transaction as its sync.drift_detected event, kept until the
 * next one, and cleared when the destination changes. Destination names
 * only, never a value: count is exact, names holds at most the first 50,
 * event_id links the audit event.
 */
export const sql = /* sql */ `
ALTER TABLE sync_targets ADD COLUMN last_drift_at timestamptz;
ALTER TABLE sync_targets ADD COLUMN last_drift_count integer;
ALTER TABLE sync_targets ADD COLUMN last_drift_names jsonb;
ALTER TABLE sync_targets ADD COLUMN last_drift_event_id text;
`;
