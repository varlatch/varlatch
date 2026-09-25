// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * `.env.schema` names environments directly with env(...), resolved to IDs
 * when a Contract is pushed, so the environment-name mapping (only ever
 * read to resolve forEnv(...) at push time, by its own endpoints, and by the
 * environment-deletion guard) is removed. Contract revisions store resolved
 * environment IDs and are unaffected, and audit history keeps its
 * contract.varlock_mapping_* events: it is append-only, never rewritten.
 */
export const sql = /* sql */ `
DROP TABLE IF EXISTS varlock_env_mappings;
`;
