// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Querier } from "../db/migrate.js";
import { DomainError } from "./errors.js";

/**
 * The writer protocol (ADR-0051 Decision 1). A writer that creates material
 * or authority in an Organization locks its scope inside its own
 * transaction, in one fixed order, and rechecks that it is live before it
 * inserts anything:
 *
 *   Organization → (its open deletion request) → Project → Environment
 *   → value → (integrations: App → Connection → Target)
 *
 * Within one type, rows are locked in ascending ID order. Each row is taken
 * in the strongest mode the transaction will need, at its first
 * acquisition, and never upgraded: upgrading is how two writers deadlock.
 *
 * - "key share": the row is only checked. The weakest lock: compatible with
 *   foreign-key checks and with other writers' updates of non-key columns.
 * - "no key update": the transaction updates the row (a rename, a Contract
 *   activation), without changing a key.
 * - "update": the transaction deletes the row, or freezes everything under
 *   it. It waits for writers in progress, and writers that come later see
 *   the new state and refuse.
 *
 * Scope resolved before the transaction (the route's) is a hint only: a
 * request that resolved a live Environment, or unwrapped the Organization
 * KEK, is refused here if the Environment was deleted meanwhile.
 */

export type LockMode = "key share" | "no key update" | "update";

const SQL_MODE: Record<LockMode, string> = {
  "key share": "FOR KEY SHARE",
  "no key update": "FOR NO KEY UPDATE",
  update: "FOR UPDATE",
};

export interface LiveScope {
  organizationId: string;
  organizationMode?: LockMode | undefined;
  projectId?: string | undefined;
  projectMode?: LockMode | undefined;
  /** Environments of the Project, locked in ascending ID order. */
  environmentIds?: string[] | undefined;
  environmentMode?: LockMode | undefined;
}

/**
 * Locks the Organization, the Project and the Environments of `scope` in
 * the protocol's order and modes, and refuses unless each is live. Returns
 * nothing: callers already hold the rows they resolved; this only makes
 * them safe to write under.
 */
export async function lockLiveScope(db: Querier, scope: LiveScope): Promise<void> {
  const org = await db.query(
    `SELECT deleted_at FROM organizations WHERE id = $1 ${SQL_MODE[scope.organizationMode ?? "key share"]}`,
    [scope.organizationId],
  );
  const orgRow = org.rows[0] as { deleted_at: string | null } | undefined;
  if (!orgRow || orgRow.deleted_at) throw new DomainError("RESOURCE_NOT_FOUND", "Organization not found");

  if (scope.projectId !== undefined) {
    const project = await db.query(
      `SELECT deleted_at FROM projects WHERE id = $1 AND organization_id = $2 ${SQL_MODE[scope.projectMode ?? "key share"]}`,
      [scope.projectId, scope.organizationId],
    );
    const projectRow = project.rows[0] as { deleted_at: string | null } | undefined;
    if (!projectRow || projectRow.deleted_at) throw new DomainError("RESOURCE_NOT_FOUND", "Project not found");
  }

  const envIds = [...new Set(scope.environmentIds ?? [])].sort();
  if (envIds.length > 0) {
    if (scope.projectId === undefined) throw new Error("lockLiveScope: environments need their Project");
    const envs = await db.query(
      `SELECT id, deleted_at FROM environments WHERE id = ANY($1) AND project_id = $2 ORDER BY id ${SQL_MODE[scope.environmentMode ?? "key share"]}`,
      [envIds, scope.projectId],
    );
    const rows = envs.rows as { id: string; deleted_at: string | null }[];
    if (rows.length !== envIds.length || rows.some((r) => r.deleted_at)) {
      throw new DomainError("RESOURCE_NOT_FOUND", "Environment not found");
    }
  }
}
