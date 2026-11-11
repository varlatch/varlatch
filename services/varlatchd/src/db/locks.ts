// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Querier } from "./migrate.js";

/**
 * Tagged row locks (ADR-0054 amendment E). Every statement with a locking
 * clause (FOR UPDATE, FOR NO KEY UPDATE, FOR SHARE, FOR KEY SHARE) goes
 * through {@link lockedQuery}, directly or through a helper built on it
 * (lockLiveScope, lockPeople): it appends a comment naming the table, the
 * mode and the result column that holds each locked row's key.
 *
 * In production the comment is inert. The test harness (test/helpers/
 * lock-trace.ts) reads it to record each acquisition in its lock trace,
 * and refuses any locking statement that carries no tag, so a lock taken
 * outside these helpers cannot escape the order check.
 *
 * The one lock order is written down once, at the top of domain/liveness.ts.
 */

export type RowLockMode = "key share" | "share" | "no key update" | "update";

const CLAUSE: Record<RowLockMode, string> = {
  "key share": "FOR KEY SHARE",
  share: "FOR SHARE",
  "no key update": "FOR NO KEY UPDATE",
  update: "FOR UPDATE",
};

/** The SQL locking clause for a mode. */
export function lockClause(mode: RowLockMode): string {
  return CLAUSE[mode];
}

export interface LockTag {
  /** The table whose rows the clause locks (for `FOR … OF alias`, the aliased table). */
  table: string;
  mode: RowLockMode;
  /**
   * The result column holding each locked row's key, as text: the primary
   * key, or for a composite key its columns cast to text and joined by "|".
   * Defaults to "id". "$1" (or "$2"…): every locked row's key is that
   * parameter, for a statement that locks one row by its key and keeps its
   * own select list. "-" for a statement that locks only rows it then
   * deletes or updates (DELETE … WHERE id IN (SELECT … FOR UPDATE SKIP
   * LOCKED)): the trace records those through the write itself.
   */
  key?: string;
}

/** The comment that tags a locking statement; parsed by the test harness. */
export function lockTag(tag: LockTag): string {
  return `/* varlatch-lock ${tag.table} ${tag.mode.replaceAll(" ", "-")} ${tag.key ?? "id"} */`;
}

/** Matches the tag {@link lockTag} writes. */
export const LOCK_TAG = /\/\* varlatch-lock (\S+) (key-share|share|no-key-update|update) (\S+) \*\//g;

/**
 * Runs `sql`, a statement whose locking clause takes `tag.mode` on rows of
 * `tag.table` and returns their keys in `tag.key`, tagged for the lock
 * trace. Rows come back, and are locked, in the statement's order.
 */
export async function lockedQuery(db: Querier, tag: LockTag, sql: string, params?: unknown[]): Promise<{ rows: unknown[] }> {
  return db.query(`${sql} ${lockTag(tag)}`, params);
}

/**
 * Locks rows of `table` by primary key `id`, in ascending id order, in one
 * mode. Returns the ids found.
 */
export async function lockRowsById(db: Querier, table: string, ids: readonly string[], mode: RowLockMode): Promise<string[]> {
  const sorted = [...new Set(ids)].sort();
  if (sorted.length === 0) return [];
  const res = await lockedQuery(
    db,
    { table, mode },
    `SELECT id FROM ${table} WHERE id = ANY($1) ORDER BY id ${lockClause(mode)}`,
    [sorted],
  );
  return (res.rows as { id: string }[]).map((r) => r.id);
}
