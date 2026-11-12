// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Querier } from "../src/db/migrate.js";
import { withSerializableTx, withSnapshot, withTx, type PoolQuerier } from "../src/db/tx.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * withTx nesting on a pool (src/db/tx.ts): the client a transaction checked
 * out is in that transaction for every caller handed it, whatever async
 * context the caller runs in. Here a pool-shaped adapter hands out one
 * PGlite connection as its client.
 */

let raw: Awaited<ReturnType<typeof migratedTestDb>>;
let pool: PoolQuerier;
let checkouts = 0;

beforeEach(async () => {
  raw = await migratedTestDb({ lockOrder: "off" });
  checkouts = 0;
  pool = {
    query: (text, params) => raw.query(text, params),
    connect: async () => {
      checkouts++;
      return { query: (text: string, params?: unknown[]) => raw.query(text, params), release: () => undefined };
    },
  };
});
afterEach(async () => {
  await raw.close();
});

const insertOrg = (q: Querier, id: string) =>
  q.query("INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ($1, $1, $1, '{}'::jsonb)", [id]);
const orgs = async () => ((await raw.query("SELECT id FROM organizations ORDER BY id")).rows as { id: string }[]).map((r) => r.id);

/** A continuation registered before the transaction began, outside its async context, that is handed its client. */
function handOff<T>(then: (client: Querier) => Promise<T>) {
  let give!: (client: Querier) => void;
  const given = new Promise<Querier>((r) => (give = r));
  const done = given.then(then);
  done.catch(() => undefined);
  return { give, done };
}

describe("withTx on a pool", () => {
  it("joins the open transaction from a callback outside its async context that is handed the client", async () => {
    const inner = handOff((client) => withTx(client, (q) => insertOrg(q, "org_inner")));
    await expect(withTx(pool, async (q) => {
      await insertOrg(q, "org_outer");
      inner.give(q);
      await inner.done;
      throw new Error("refused");
    })).rejects.toThrow("refused");
    // One transaction, rolled back whole: the inner call neither began nor committed one of its own.
    expect(await orgs()).toEqual([]);
    expect(checkouts).toBe(1);
  });

  it("refuses a serializable transaction or a snapshot on the client from such a callback", async () => {
    const serializable = handOff((client) => withSerializableTx(client, async () => undefined));
    const snapshot = handOff((client) => withSnapshot(client, async () => undefined));
    await withTx(pool, async (q) => {
      serializable.give(q);
      snapshot.give(q);
      await expect(serializable.done).rejects.toThrow(/cannot start inside another transaction/);
      await expect(snapshot.done).rejects.toThrow(/cannot start inside a transaction/);
    });
  });

  it("joins a nested call in the same flow, and refuses a serializable transaction or a snapshot there", async () => {
    await expect(withTx(pool, async (q) => {
      await withTx(q, (inner) => insertOrg(inner, "org_nested"));
      await expect(withSerializableTx(q, async () => undefined)).rejects.toThrow(/cannot start inside another transaction/);
      await expect(withSnapshot(q, async () => undefined)).rejects.toThrow(/cannot start inside a transaction/);
      throw new Error("refused");
    })).rejects.toThrow("refused");
    expect(await orgs()).toEqual([]);
  });

  it("commits what the transaction did once it ends", async () => {
    await withTx(pool, (q) => insertOrg(q, "org_kept"));
    expect(await orgs()).toEqual(["org_kept"]);
  });
});
