// SPDX-License-Identifier: AGPL-3.0-or-later
import { lockClause, lockedQuery } from "../db/locks.js";
import type { Querier } from "../db/migrate.js";
import { DomainError } from "./errors.js";
import { lockPeople, type PersonRef } from "./personlocks.js";

/**
 * THE LOCK ORDER (ADR-0054 amendment E). Every transaction that takes row
 * locks, explicitly or through a write or a foreign key, takes them in this
 * one order: approvals, Security Controls, passkeys, the writer protocol of
 * ADR-0051 below, Organization deletion and the sync workers alike. This is
 * the one place it is written down; the other files refer here.
 *
 *   0. createApproval's per-person advisory lock (only it takes one).
 *   1. The Organization row, then its open deletion request.
 *   2. People: every identity row the transaction will lock or reference,
 *      in id order, in one step, each in the mode it needs (lockPeople).
 *      "Reference" includes the implicit FOR KEY SHARE of a foreign key
 *      (created_by, identity_id, owner_identity_id, actor_identity_id,
 *      subject_identity_id, a Capability's broker and agent, issued_by)
 *      and a row of the exposure or integration index. FOR UPDATE for the
 *      person whose approval is consumed; the mode of the write for a
 *      person whose row changes; FOR KEY SHARE for a person only
 *      referenced.
 *   3. That person's passkeys.
 *   4. Approval intents.
 *   5. Challenges: approval challenges, then passkey-confirmation
 *      challenges.
 *   6. The Better Auth session row.
 *   7. The credential row.
 *   8. The Project row.
 *   9. Environment rows, in id order (an environment and its parent
 *      included).
 *  10. Domain rows: values (env_values, value_versions), then the
 *      integrations, App -> Connection -> Target, then every other domain
 *      row in its writer's documented order.
 *  11. Rows nothing else orders against (security_controls, passkey
 *      provenance, the deletion of a passkey already held), then the report
 *      counters in key order, the exposure and integration indexes in key
 *      order, and the audit insert last (it holds the audit counter until
 *      commit).
 *
 * A transaction may skip steps; it never goes back to an earlier one.
 * Within a step, rows are taken in ascending id order. Each row is taken in
 * the strongest mode the transaction will need, at its first acquisition,
 * and never upgraded: upgrading is how two writers deadlock. A later
 * reference to a row already held (a foreign key to the actor locked at
 * step 2) is reuse, not a new acquisition.
 *
 * So people come before any domain row: a foreign-key insert at step 10 or
 * 11 finds its person already held and takes no lock out of order. A
 * consuming transaction takes its requester FOR UPDATE at step 2, then
 * consumption's intent, session and credential (steps 4, 6, 7), and only
 * then its Project, environments and domain rows; nothing returns to steps
 * 2 to 7 after step 8.
 *
 * Explicit row locks go through the tagged helpers of db/locks.ts
 * (lockedQuery, and lockLiveScope and lockPeople built on it); the test
 * harness traces them with every write and foreign-key reference and fails
 * a transaction that breaks this order (test/helpers/lock-trace.ts).
 *
 * THE WRITER PROTOCOL (ADR-0051 Decision 1), steps 1, 2, 8 and 9 of the
 * order. A writer that creates material or authority in an Organization
 * locks its scope inside its own transaction and rechecks that it is live
 * before it inserts anything, with lockLiveScope:
 *
 *   Organization -> (its open deletion request) -> people -> Project
 *   -> Environment -> value -> (integrations: App -> Connection -> Target)
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

export interface LiveScope {
  organizationId: string;
  organizationMode?: LockMode | undefined;
  /**
   * Whether the write is allowed while the Organization is frozen by an open
   * deletion request (ADR-0051 Decision 5): only approving and cancelling
   * the deletion are.
   */
  allowFrozen?: boolean | undefined;
  /**
   * Step 2: every identity the transaction will lock or reference (the
   * actor, an owner, a subject, a broker or agent, a creator), locked in
   * id order after the Organization and before the Project. An id alone is
   * taken FOR KEY SHARE; null and undefined entries are skipped.
   */
  people?: readonly PersonRef[] | undefined;
  projectId?: string | undefined;
  projectMode?: LockMode | undefined;
  /** Environments of the Project, locked in ascending ID order. */
  environmentIds?: string[] | undefined;
  environmentMode?: LockMode | undefined;
}

/**
 * Locks the Organization, the people, the Project and the Environments of
 * `scope` in the order's steps 1, 2, 8 and 9 and their modes, and refuses
 * unless the Organization, the Project and the Environments are live.
 * Returns nothing: callers already hold the rows they resolved; this only
 * makes them safe to write under.
 */
export async function lockLiveScope(db: Querier, scope: LiveScope): Promise<void> {
  const orgMode = scope.organizationMode ?? "key share";
  const org = await lockedQuery(
    db,
    { table: "organizations", mode: orgMode, key: "$1" },
    `SELECT deleted_at FROM organizations WHERE id = $1 ${lockClause(orgMode)}`,
    [scope.organizationId],
  );
  const orgRow = org.rows[0] as { deleted_at: string | null } | undefined;
  if (!orgRow || orgRow.deleted_at) throw new DomainError("RESOURCE_NOT_FOUND", "Organization not found");
  if (!scope.allowFrozen) await refuseIfFrozen(db, scope.organizationId);

  if (scope.people) await lockPeople(db, scope.people);

  if (scope.projectId !== undefined) {
    const projectMode = scope.projectMode ?? "key share";
    const project = await lockedQuery(
      db,
      { table: "projects", mode: projectMode, key: "$1" },
      `SELECT deleted_at FROM projects WHERE id = $1 AND organization_id = $2 ${lockClause(projectMode)}`,
      [scope.projectId, scope.organizationId],
    );
    const projectRow = project.rows[0] as { deleted_at: string | null } | undefined;
    if (!projectRow || projectRow.deleted_at) throw new DomainError("RESOURCE_NOT_FOUND", "Project not found");
  }

  const envIds = [...new Set(scope.environmentIds ?? [])].sort();
  if (envIds.length > 0) {
    if (scope.projectId === undefined) throw new Error("lockLiveScope: environments need their Project");
    const envMode = scope.environmentMode ?? "key share";
    const envs = await lockedQuery(
      db,
      { table: "environments", mode: envMode },
      `SELECT id, deleted_at FROM environments WHERE id = ANY($1) AND project_id = $2 ORDER BY id ${lockClause(envMode)}`,
      [envIds, scope.projectId],
    );
    const rows = envs.rows as { id: string; deleted_at: string | null }[];
    if (rows.length !== envIds.length || rows.some((r) => r.deleted_at)) {
      throw new DomainError("RESOURCE_NOT_FOUND", "Environment not found");
    }
  }
}

/**
 * The Organization's open deletion request, if any. Read under the
 * Organization row's lock: scheduling takes that row FOR UPDATE, so a
 * writer either finishes before a request is scheduled or sees it.
 */
export async function openDeletion(
  db: Querier,
  organizationId: string,
): Promise<{ id: string; run_after: string | Date; approval_required: boolean; approved_by: string | null } | null> {
  const res = await db.query(
    `SELECT id, run_after, approval_required, approved_by FROM organization_deletions
     WHERE organization_id = $1 AND cancelled_at IS NULL AND completed_at IS NULL`,
    [organizationId],
  );
  return (res.rows[0] as { id: string; run_after: string | Date; approval_required: boolean; approved_by: string | null } | undefined) ?? null;
}

/** Refuses every operational write while the Organization is being deleted (ADR-0051 Decision 5). */
export async function refuseIfFrozen(db: Querier, organizationId: string): Promise<void> {
  const open = await openDeletion(db, organizationId);
  if (!open) return;
  const runAfter = new Date(open.run_after).toISOString();
  throw new DomainError(
    "ORGANIZATION_DELETING",
    `This Organization is being deleted: it may be deleted from ${runAfter}. Only reading, and approving or cancelling the deletion, are possible. Nothing was changed.`,
    { deletionId: open.id, runAfter },
  );
}
