// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Querier } from "../db/migrate.js";
import type { Value } from "./canonical.js";
import type { ManifestColumn, ManifestTable, RowSource } from "./bundle.js";

/**
 * Reading the source installation for the migration's export (ADR-0059
 * step 7, go-step7 decisions 2, 3 and 6): every table in one read-only
 * REPEATABLE READ transaction on one connection, so every table, count and
 * digest is read from the same snapshot. At the barrier that snapshot is
 * the one the barrier exported (SET TRANSACTION SNAPSHOT), so two exports
 * at the same frozen point read the same state; in a dry run it is the
 * transaction's own.
 */

const ident = (name: string) => `"${name.replace(/"/g, '""')}"`;

/** A column's value as the canonical encoder takes it (canonical.ts Value). */
function selectExpression(c: ManifestColumn): string {
  const col = ident(c.source);
  // A left-out column is never read: its value never leaves the database.
  if (c.leftOut !== undefined) return "NULL";
  switch (c.type) {
    case "timestamp with time zone":
      // Exact microseconds: extract() is numeric from PostgreSQL 14.
      return `(extract(epoch from ${col}) * 1000000)::bigint::text`;
    case "integer":
    case "bigint":
    case "jsonb":
      return `${col}::text`;
    default:
      return col;
  }
}

/** ORDER BY for a table: the manifest's orderBy as SQLite sorts, or the physical order. */
export function orderClause(table: ManifestTable): string {
  if (table.physicalOrder) return "ctid";
  const types = new Map(table.columns.map((c) => [c.source, c.type]));
  const keys = table.orderBy ?? [];
  if (keys.length === 0) throw new Error(`export: the manifest gives ${table.source} no order`);
  return keys
    .map((k) => `${ident(k)}${types.get(k) === "text" ? ' COLLATE "C"' : ""} ASC NULLS FIRST`)
    .join(", ");
}

/** The SELECT that reads a table's rows for the bundle. */
export function selectRows(table: ManifestTable): string {
  // Each column aliased by its position: two expressions never share a name.
  return `SELECT ${table.columns.map((c, i) => `${selectExpression(c)} AS c${i}`).join(", ")} FROM ${ident(table.source)} ORDER BY ${orderClause(table)}`;
}

function convert(c: ManifestColumn, v: unknown): Value {
  if (v === null || v === undefined) return null;
  switch (c.type) {
    case "timestamp with time zone":
    case "integer":
    case "bigint":
      return BigInt(String(v));
    case "bytea":
      return v as Uint8Array;
    default:
      return v as Value;
  }
}

const BATCH = 500;

/**
 * The rows of every table, read inside the caller's transaction on client
 * (which must stay open until the bundle is written): counted first, then
 * streamed through a cursor, BATCH rows at a time.
 */
export function pgRowSource(client: Querier): RowSource {
  let n = 0;
  return async (table) => {
    const count = Number(((await client.query(`SELECT count(*)::text AS n FROM ${ident(table.source)}`)).rows[0] as { n: string }).n);
    const cursor = `export_${++n}`;
    async function* rows(): AsyncIterable<Value[]> {
      await client.query(`DECLARE ${cursor} NO SCROLL CURSOR FOR ${selectRows(table)}`);
      try {
        for (;;) {
          const batch = (await client.query(`FETCH ${BATCH} FROM ${cursor}`)).rows as Record<string, unknown>[];
          for (const row of batch) yield table.columns.map((c, i) => convert(c, row[`c${i}`]));
          if (batch.length < BATCH) return;
        }
      } finally {
        await client.query(`CLOSE ${cursor}`);
      }
    }
    return { count, rows: rows() };
  };
}
