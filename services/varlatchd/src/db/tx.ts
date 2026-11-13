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
 * Transaction helper. Single-connection Queriers (pglite, a checked-out pg
 * client) run BEGIN/COMMIT inline; pool Queriers check out a dedicated client
 * for the transaction. Nested calls reuse the open transaction.
 */
const inTx = new WeakSet<Querier>();

/**
 * Single connections that concurrent flows share (the test database, under
 * the lock-order check). On one of these, nesting is per async flow: a
 * call from inside the open transaction's flow joins it, and another
 * flow's call is that flow's own transaction, as on a connection of its
 * own. Every other Querier keeps the identity check above: a dedicated
 * client, wherever its callers run, is in a transaction while one is open
 * on it.
 */
const shared = new WeakSet<Querier>();

/** Registers a single connection that concurrent flows share (tests only). */
export function shareConnection(db: Querier): void {
  shared.add(db);
}

/** Wrappers of a shared connection, and the connection each wraps (tests only). */
const aliases = new WeakMap<Querier, Querier>();

/** Whether `db` is a shared connection (tests only). */
export function isSharedConnection(db: Querier): boolean {
  return shared.has(db);
}

/**
 * Registers `alias`, a wrapper of the shared connection `of` (a test's
 * statement recorder), as shared too: its transactions are scoped per
 * flow like the connection's, and the connection sees them as its own
 * (openTxScope). Tests only.
 */
export function shareConnectionAlias(alias: Querier, of: Querier): void {
  shared.add(alias);
  aliases.set(alias, of);
}

/** A transaction open on a shared connection, for the flow that opened it and the work that flow starts. */
export interface TxScope {
  readonly db: Querier;
  readonly outer: TxScope | undefined;
  open: boolean;
}

const scopes = new AsyncLocalStorage<TxScope>();

/**
 * One attempt of a transaction or snapshot: what code running inside it may
 * note for the attempt only (requestaccess.ts keeps the passkey-verification
 * decision it captured under the Organization lock here). A retry of a
 * serializable transaction is a new attempt that starts empty; a nested
 * withTx joins the attempt it runs in. Nothing here is read by the database
 * layer itself.
 */
export interface TxAttempt {
  readonly kind: "transaction" | "serializable" | "snapshot";
  readonly notes: Map<symbol, unknown>;
}

const attempts = new AsyncLocalStorage<TxAttempt>();

/** The transaction or snapshot attempt this async flow runs in, if any. */
export function currentTxAttempt(): TxAttempt | undefined {
  return attempts.getStore();
}

function inAttempt<T>(kind: TxAttempt["kind"], body: () => Promise<T>): Promise<T> {
  return attempts.run({ kind, notes: new Map() }, body);
}

/** The open transaction this async flow runs in on the shared connection `db`, if any. */
export function openTxScope(db: Querier): TxScope | undefined {
  for (let s = scopes.getStore(); s; s = s.outer) if (s.open && (s.db === db || aliases.get(s.db) === db)) return s;
  return undefined;
}

function nested(db: Querier): boolean {
  return shared.has(db) ? openTxScope(db) !== undefined : inTx.has(db);
}

/** Runs a transaction's body; on a shared connection, as the flow of a scope that closes when it settles. */
function scoped<T>(db: Querier, body: () => Promise<T>): Promise<T> {
  if (!shared.has(db)) return body();
  const scope: TxScope = { db, outer: scopes.getStore(), open: true };
  return scopes.run(scope, async () => {
    try {
      return await body();
    } finally {
      scope.open = false;
    }
  });
}

export async function withTx<T>(db: Querier, fn: (db: Querier) => Promise<T>): Promise<T> {
  if (nested(db)) return fn(db);
  if (isPool(db)) {
    const client = await db.connect();
    try {
      return await withTx(client, fn);
    } finally {
      client.release();
    }
  }
  return scoped(db, async () => {
    await db.query("BEGIN");
    inTx.add(db);
    try {
      const result = await inAttempt("transaction", () => fn(db));
      await db.query("COMMIT");
      return result;
    } catch (err) {
      await db.query("ROLLBACK");
      throw err;
    } finally {
      inTx.delete(db);
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
  if (nested(db)) throw new Error("A serializable transaction cannot start inside another transaction");
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
    const outcome = await scoped(db, async (): Promise<{ result: T } | { err: unknown }> => {
      await db.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
      inTx.add(db);
      try {
        const result = await inAttempt("serializable", () => fn(db));
        await db.query("COMMIT");
        return { result };
      } catch (err) {
        // After a failed COMMIT the transaction is already over; ROLLBACK
        // then only warns, and must not hide the original error.
        await db.query("ROLLBACK").catch(() => undefined);
        return { err };
      } finally {
        inTx.delete(db);
      }
    });
    if ("result" in outcome) return outcome.result;
    if (!isSerializationFailure(outcome.err)) throw outcome.err;
    if (attempt >= attempts) throw new SerializationRetriesExhausted(attempts);
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
  if (nested(db)) throw new Error("A snapshot cannot start inside a transaction");
  return scoped(db, async () => {
    await db.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    inTx.add(db);
    try {
      const row = (await db.query("SELECT now() AS now")).rows[0] as { now: Date | string };
      const result = await inAttempt("snapshot", () => fn(db, new Date(row.now)));
      await db.query("COMMIT");
      return result;
    } catch (err) {
      await db.query("ROLLBACK");
      throw err;
    } finally {
      inTx.delete(db);
    }
  });
}
