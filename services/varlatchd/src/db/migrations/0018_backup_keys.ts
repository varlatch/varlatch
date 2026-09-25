// SPDX-License-Identifier: AGPL-3.0-or-later
/** Explicit version and rotation metadata for archive recovery requirements. */
export const sql = /* sql */ `
ALTER TABLE installation ADD COLUMN root_kek_version integer NOT NULL DEFAULT 1 CHECK (root_kek_version > 0);
ALTER TABLE installation ADD COLUMN key_rotation_state text NOT NULL DEFAULT 'idle' CHECK (key_rotation_state IN ('idle', 'rewrapping', 'verifying'));
ALTER TABLE organizations ADD COLUMN root_kek_version integer NOT NULL DEFAULT 1 CHECK (root_kek_version > 0);
ALTER TABLE organizations ADD COLUMN key_rotation_state text NOT NULL DEFAULT 'idle' CHECK (key_rotation_state IN ('idle', 'rewrapping', 'verifying'));
`;
