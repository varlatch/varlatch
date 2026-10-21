// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * A Sync Target's notes (ADR-0031, amendment 2026-10-21): hints about how
 * the destination itself uses the names the Target manages (a Coolify
 * service's compose file sets a name to its own value, Coolify keeps a
 * removed name), as the last reconciliation that inspected them found.
 * Unlike last_result they never fail a run. A JSON array of bounded note
 * objects; NULL when no run inspected the destination (every application,
 * repository and deployment, and a service before its first run). Each
 * inspecting run replaces the array, so stale notes clear.
 *
 * The runtime role's grants on sync_targets are table grants (migration 3),
 * which cover the new column.
 */
export const sql = /* sql */ `
ALTER TABLE sync_targets ADD COLUMN last_notes jsonb;
`;
