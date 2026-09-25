// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Machine identity lifecycle (ADR-0034): last-used tracking. An operational
 * signal ("is anything still using this credential?"), not an audit record —
 * the successful-verification path updates both columns at most once per
 * credential per 60 seconds. `identities.last_seen_at` is a denormalized
 * max over the identity's credentials so listings need no aggregate.
 */
export const sql = /* sql */ `
ALTER TABLE credentials ADD COLUMN last_used_at timestamptz;
ALTER TABLE identities ADD COLUMN last_seen_at timestamptz;
`;
