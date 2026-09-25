// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Dual-phase secret rotation (ADR-0027): a Value may keep the previous
 * version live alongside the new primary for a bounded grace window, so
 * running consumers migrate without an outage. Rotation is runtime state on
 * env_values — version history is unchanged. `retiring_version_id` pins the
 * previous version; `rotation_deadline` bounds the overlap. Both NULL = the
 * ordinary stable single-version behavior.
 */
export const sql = /* sql */ `
ALTER TABLE env_values ADD COLUMN retiring_version_id text REFERENCES value_versions(id);
ALTER TABLE env_values ADD COLUMN rotation_deadline timestamptz;
ALTER TABLE env_values ADD COLUMN rotation_started_at timestamptz;
`;
