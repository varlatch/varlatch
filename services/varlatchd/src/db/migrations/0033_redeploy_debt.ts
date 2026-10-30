// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * A redeploy that is owed is not lost (ADR-0050 Decision 4). When a run
 * confirms a changing write or deletion on a Target with redeploy turned on
 * (an adapter that can redeploy), the same transaction increments
 * redeploy_owed. Any later run pays it, even with nothing to write; only a
 * redeploy the platform accepted settles it, by raising redeploy_paid to
 * the revision that run read. Owed while redeploy_owed > redeploy_paid.
 * Delivery is at least once: a crash between an accepted redeploy and
 * settling it redeploys again. A destination change or turning redeploy
 * off settles the debt without paying it.
 */
export const sql = /* sql */ `
ALTER TABLE sync_targets ADD COLUMN redeploy_owed bigint NOT NULL DEFAULT 0;
ALTER TABLE sync_targets ADD COLUMN redeploy_paid bigint NOT NULL DEFAULT 0;
`;
