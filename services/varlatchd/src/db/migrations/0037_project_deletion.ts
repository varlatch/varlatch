// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Deleting a Project (ADR-0051 Decisions 2 and 3).
 *
 * projects.deleted_at tombstones a Project: it keeps its Contract Revisions
 * and the IDs audit events name, and reaches nothing else. The slug is
 * unique among live Projects only, so it can be used again; a new Project
 * with the old slug is a new identity.
 *
 * value_versions.erased_at marks a version whose payload and wrapped DEK
 * were removed: a deleted Project's values are erased from the live
 * database, since no Project key exists to destroy. A version is either
 * intact or erased, never half of each.
 */
export const sql = /* sql */ `
ALTER TABLE projects ADD COLUMN deleted_at timestamptz;
ALTER TABLE projects DROP CONSTRAINT projects_organization_id_slug_key;
CREATE UNIQUE INDEX projects_live_slug ON projects (organization_id, slug) WHERE deleted_at IS NULL;

ALTER TABLE value_versions ADD COLUMN erased_at timestamptz;
ALTER TABLE value_versions ALTER COLUMN payload DROP NOT NULL;
ALTER TABLE value_versions ALTER COLUMN wrapped_dek DROP NOT NULL;
ALTER TABLE value_versions ADD CONSTRAINT value_versions_intact_or_erased CHECK (
  (erased_at IS NULL AND payload IS NOT NULL AND wrapped_dek IS NOT NULL)
  OR (erased_at IS NOT NULL AND payload IS NULL AND wrapped_dek IS NULL)
);
`;
