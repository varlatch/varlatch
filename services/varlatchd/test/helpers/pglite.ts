// SPDX-License-Identifier: AGPL-3.0-or-later
import { PGlite } from "@electric-sql/pglite";
import type { Querier } from "../../src/db/migrate.js";

/** In-memory Postgres for tests, adapted to the Querier surface. */
export async function testDb(): Promise<Querier & { close: () => Promise<void> }> {
  const pg = new PGlite();
  await pg.waitReady;
  return {
    query: async (text, params) => {
      const res = await pg.query(text, params as never[] | undefined);
      return { rows: res.rows as unknown[] };
    },
    exec: async (text) => {
      await pg.exec(text);
    },
    close: () => pg.close(),
  };
}
