// SPDX-License-Identifier: AGPL-3.0-or-later
import { AsyncLocalStorage } from "node:async_hooks";
import type { Querier } from "./migrate.js";

/** A Querier that can check out a dedicated connection (node-postgres Pool). */
export interface PoolQuerier extends Querier {
  connect: () => Promise<Querier & { release: (destroy?: boolean) => void }>;
}

function isPool(db: Querier): db is PoolQuerier {
  return typeof (db as PoolQuerier).connect === "function";
}

/**
 * A transaction open on a single-connection Querier, for the async flow
 * that opened it and the work that flow starts. Nesting is per flow: a
 * call from inside the transaction's flow joins it, while a call from
 * another flow on the same Querier is not nested. On a pool that call
 * would have its own client; on one shared connection (the test database)
 * it is that flow's own transaction.
 */
export interface TxScope {
  readonly db: Querier;
  readonly outer: TxScope | undefined;
  open: boolean;
}

const scopes = new AsyncLocalStorage<TxScope>();

/** The open transaction this async flow runs in on `db`, if any. */
export function openTxScope(db: Querier): TxScope | undefined {
  for (let s = scopes.getStore(); s; s = s.outer) if (s.open && s.db === db) return s;
  return undefined;
}

/** Runs `fn` as the flow of a transaction on `db`; the scope closes when it settles. */
function inScope<T>(db: Querier, fn: () => Promise<T>): Promise<T> {
  const scope: TxScope = { db, outer: scopes.getStore(), open: true };
  return scopes.run(scope, async () => {
    try {
      return await fn();
    } finally {
      scope.open = false;
    }
  });
}

/**
 * Transaction helper. Single-connection Queriers (pglite, a checked-out pg
 * client) run BEGIN/COMMIT inline; pool Queriers check out a dedicated client
 * for the transaction. Nested calls reuse the open transaction.
 */
export async function withTx<T>(db: Querier, fn: (db: Querier) => Promise<T>): Promise<T> {
  if (openTxScope(db)) return fn(db);
  if (isPool(db)) {
    const client = await db.connect();
    try {
      return await withTx(client, fn);
    } finally {
      client.release();
    }
  }
  return inScope(db, async () => {
    await db.query("BEGIN");
    try {
      const result = await fn(db);
      await db.query("COMMIT");
      return result;
    } catch (err) {
      await db.query("ROLLBACK");
      throw err;
    }
  });
}

/** PostgreSQL's serialization_failure and deadlock_detected: safe to retry whole. */
export function isSerializationFailure(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code;
  return code === "40001" || code === "40P01";
}

/** Thrown when every attempt of a serializable transaction failed to serialize. */
export class SerializationRetriesExhausted extends Error {
  constructor(readonly attempts: number) {
    super(`Transaction could not be serialized after ${attempts} attempts`);
  }
}

export const SERIALIZABLE_ATTEMPTS = 5;

/**
 * A SERIALIZABLE transaction that owns its connection (ADR-0052 Decision 2):
 * it never joins another transaction, so it refuses to start inside one
 * instead of silently weakening its isolation as a nested withTx would.
 * A serialization failure, at any statement or at COMMIT, runs `fn` again
 * from the start on a new snapshot, at most `attempts` times with jittered
 * backoff; then it throws SerializationRetriesExhausted and nothing has
 * changed. `fn` must therefore have no effect outside the database: send
 * signals and the like only after this returns.
 */
export async function withSerializableTx<T>(
  db: Querier,
  fn: (db: Querier) => Promise<T>,
  opts: { attempts?: number; backoffMs?: number } = {},
): Promise<T> {
  if (openTxScope(db)) throw new Error("A serializable transaction cannot start inside another transaction");
  if (isPool(db)) {
    const client = await db.connect();
    try {
      return await withSerializableTx(client, fn, opts);
    } finally {
      client.release();
    }
  }
  const attempts = opts.attempts ?? SERIALIZABLE_ATTEMPTS;
  const backoffMs = opts.backoffMs ?? 20;
  for (let attempt = 1; ; attempt++) {
    try {
      return await inScope(db, async () => {
        await db.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
        try {
          const result = await fn(db);
          await db.query("COMMIT");
          return result;
        } catch (err) {
          // After a failed COMMIT the transaction is already over; ROLLBACK
          // then only warns, and must not hide the original error.
          await db.query("ROLLBACK").catch(() => undefined);
          throw err;
        }
      });
    } catch (err) {
      if (!isSerializationFailure(err)) throw err;
      if (attempt >= attempts) throw new SerializationRetriesExhausted(attempts);
    }
    await new Promise((resolve) => setTimeout(resolve, backoffMs * attempt * (0.5 + Math.random())));
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
  if (openTxScope(db)) throw new Error("A snapshot cannot start inside a transaction");
  return inScope(db, async () => {
    await db.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    try {
      const row = (await db.query("SELECT now() AS now")).rows[0] as { now: Date | string };
      const result = await fn(db, new Date(row.now));
      await db.query("COMMIT");
      return result;
    } catch (err) {
      await db.query("ROLLBACK");
      throw err;
    }
  });
}
