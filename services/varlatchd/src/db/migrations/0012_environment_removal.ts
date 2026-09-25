// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Environment removal (ADR-0025): environments are tombstoned, never
 * row-deleted, so Security Audit Events keep a resolvable subject. Name
 * uniqueness applies to live environments only — deleting `staging/pr-142`
 * frees the name for a later preview of the same PR; the re-created
 * environment is a new identity.
 */
export const sql = /* sql */ `
ALTER TABLE environments ADD COLUMN deleted_at timestamptz;
ALTER TABLE environments DROP CONSTRAINT environments_project_id_name_key;
CREATE UNIQUE INDEX environments_live_name_key
  ON environments(project_id, name) WHERE deleted_at IS NULL;
`;
