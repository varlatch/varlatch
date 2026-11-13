// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The Organization's security epoch (ADR-0054 Decision 2, the
 * passkey-verification decision boundary).
 *
 * A Security Control change, and the host operator's reset, bump
 * organizations.security_epoch under the Organization row lock FOR UPDATE
 * they already take. A writer captures its passkey-verification outcome
 * right after locking that row: under READ COMMITTED it then reads the new
 * mode; under SERIALIZABLE (ADR-0052 Decision 2) a writer whose snapshot
 * is older than the change cannot lock the updated row (40001) and runs
 * again on a new snapshot, so it never commits under a mode that was
 * already replaced when it locked. Nothing reads the value itself.
 */
export const sql = /* sql */ `
ALTER TABLE organizations ADD COLUMN security_epoch bigint NOT NULL DEFAULT 0;
`;
