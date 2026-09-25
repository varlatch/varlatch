// SPDX-License-Identifier: AGPL-3.0-or-later
import pg from "pg";
import type { Querier } from "./migrate.js";
import type { PoolQuerier } from "./tx.js";

/** node-postgres wiring for production; tests use pglite instead. */
export function createPgQuerier(databaseUrl: string): PoolQuerier & { end: () => Promise<void> } {
  const pool = new pg.Pool({ connectionString: databaseUrl, max: 10 });
  // Idle socket failures must not become unhandled EventEmitter errors.
  // The pool removes the failed client and reconnects on the next query.
  pool.on("error", () => console.error("PostgreSQL idle connection failed; reconnecting on next query"));
  return {
    query: async (text, params) => {
      const res = await pool.query(text, params as never[]);
      return { rows: res.rows as unknown[] };
    },
    connect: async () => {
      const client = await pool.connect();
      // Checked-out clients emit 'error' when their backend dies (e.g. the
      // database is replaced during a gated restore); without a listener that
      // is an unhandled EventEmitter error that kills the process.
      const onError = () => console.error("PostgreSQL connection failed; the holder's next query will reject");
      client.on("error", onError);
      const querier: Querier & { release: (destroy?: boolean) => void } = {
        query: async (text, params) => {
          const res = await client.query(text, params as never[]);
          return { rows: res.rows as unknown[] };
        },
        // `destroy` drops a connection known to be broken instead of pooling it.
        release: (destroy?: boolean) => { client.removeListener("error", onError); client.release(destroy); },
      };
      return querier;
    },
    end: () => pool.end(),
  };
}
