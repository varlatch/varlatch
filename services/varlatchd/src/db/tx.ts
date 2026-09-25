// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Querier } from "./migrate.js";

/** A Querier that can check out a dedicated connection (node-postgres Pool). */
export interface PoolQuerier extends Querier {
  connect: () => Promise<Querier & { release: (destroy?: boolean) => void }>;
}

function isPool(db: Querier): db is PoolQuerier {
  return typeof (db as PoolQuerier).connect === "function";
}

/**
 * Transaction helper. Single-connection Queriers (pglite, a checked-out pg
 * client) run BEGIN/COMMIT inline; pool Queriers check out a dedicated client
 * for the transaction. Nested calls reuse the open transaction.
 */
const inTx = new WeakSet<Querier>();

export async function withTx<T>(db: Querier, fn: (db: Querier) => Promise<T>): Promise<T> {
  if (inTx.has(db)) return fn(db);
  if (isPool(db)) {
    const client = await db.connect();
    try {
      return await withTx(client, fn);
    } finally {
      client.release();
    }
  }
  await db.query("BEGIN");
  inTx.add(db);
  try {
    const result = await fn(db);
    await db.query("COMMIT");
    return result;
  } catch (err) {
    await db.query("ROLLBACK");
    throw err;
  } finally {
    inTx.delete(db);
  }
}

/**
 * A read-only REPEATABLE READ transaction: every read in `fn` sees one
 * snapshot, taken by its first statement, and any write fails. `now` is the
 * transaction time, the one clock a retrieval uses. A read-only snapshot
 * never fails with a serialization conflict, whatever commits concurrently.
 * Nothing is written, so ending it with COMMIT or ROLLBACK is the same.
 */
export async function withSnapshot<T>(
  db: Querier,
  fn: (db: Querier, now: Date) => Promise<T>,
): Promise<T> {
  if (isPool(db)) {
    const client = await db.connect();
    try {
      return await withSnapshot(client, fn);
    } finally {
      client.release();
    }
  }
  if (inTx.has(db)) throw new Error("A snapshot cannot start inside a transaction");
  await db.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
  inTx.add(db);
  try {
    const row = (await db.query("SELECT now() AS now")).rows[0] as { now: Date | string };
    const result = await fn(db, new Date(row.now));
    await db.query("COMMIT");
    return result;
  } catch (err) {
    await db.query("ROLLBACK");
    throw err;
  } finally {
    inTx.delete(db);
  }
}
