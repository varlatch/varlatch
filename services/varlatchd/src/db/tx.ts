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
