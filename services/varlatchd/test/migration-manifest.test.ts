// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MIGRATIONS, manifestMigrations } from "../src/db/migrations/index.js";
import type { Querier } from "../src/db/migrate.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * The migration manifest (ADR-0059 Decision 9; go-step7.md 7.1) holds every
 * table and column of this release's schema: varlatchd's v1.json, the same
 * bytes (its manifest_test checks the copy and holds it to varlatchd's
 * schema). A migration that adds a table or a column fails here until the
 * manifest accounts for it.
 */

interface ManifestColumn {
  source: string;
  type: string;
}
interface Manifest {
  source: { release: string; schema: string; migrations: string[] };
  tables: { source: string; action: string; orderBy?: string[]; physicalOrder?: boolean; columns: ManifestColumn[] }[];
}

const manifest = JSON.parse(readFileSync(new URL("../src/migration/manifest-v1.json", import.meta.url), "utf8")) as Manifest;

type Schema = Map<string, { name: string; type: string }[]>;

/** The public schema's tables and their columns in order, with format_type's type names (as pgschema.mjs reads them). */
async function readSchema(db: Querier): Promise<Schema> {
  const res = await db.query(
    `SELECT c.relname AS table, a.attname AS name, format_type(a.atttypid, a.atttypmod) AS type
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
       JOIN pg_attribute a ON a.attrelid = c.oid
      WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND a.attnum > 0 AND NOT a.attisdropped
      ORDER BY c.relname, a.attnum`,
  );
  const schema: Schema = new Map();
  for (const row of res.rows as { table: string; name: string; type: string }[]) {
    const cols = schema.get(row.table) ?? [];
    cols.push({ name: row.name, type: row.type });
    schema.set(row.table, cols);
  }
  return schema;
}

/** Every difference between the manifest and the schema. */
function differences(m: Manifest, schema: Schema): string[] {
  const errs: string[] = [];
  const listed = new Map(m.tables.map((t) => [t.source, t]));
  for (const [table, cols] of schema) {
    const t = listed.get(table);
    if (!t) {
      errs.push(`table ${table}: not in the manifest`);
      continue;
    }
    const want = cols.map((c) => `${c.name} ${c.type}`);
    const got = t.columns.map((c) => `${c.source} ${c.type}`);
    for (const c of want.filter((w) => !got.includes(w))) errs.push(`table ${table}: column ${c} not in the manifest`);
    for (const c of got.filter((g) => !want.includes(g))) errs.push(`table ${table}: the manifest's column ${c} is not in the schema`);
    if (errs.length === 0 && want.join(",") !== got.join(",")) errs.push(`table ${table}: the columns are in another order`);
  }
  for (const table of listed.keys()) if (!schema.has(table)) errs.push(`table ${table}: in the manifest, not in the schema`);
  return errs;
}

describe("the migration manifest", () => {
  let db: Querier & { close: () => Promise<void> };
  beforeAll(async () => {
    db = await migratedTestDb({ lockOrder: "off" });
  });
  afterAll(async () => {
    await db.close();
  });

  it("names this release's migrations, but those of indexes only, which come after its last", () => {
    expect(manifest.source.migrations).toEqual(manifestMigrations());
    const last = MIGRATIONS.findIndex((m) => `${String(m.id).padStart(4, "0")}_${m.name}` === manifest.source.migrations.at(-1));
    expect(MIGRATIONS.slice(0, last + 1).every((m) => !m.indexesOnly)).toBe(true);
    expect(MIGRATIONS.slice(last + 1).every((m) => m.indexesOnly)).toBe(true);
  });

  it("holds every table and column of the schema, in order, with its type", async () => {
    expect(differences(manifest, await readSchema(db))).toEqual([]);
  });

  it("orders each copied or transformed table's rows by its primary key", async () => {
    const res = await db.query(
      `SELECT c.relname AS table, array_agg(a.attname ORDER BY k.ord)::text[] AS columns
         FROM pg_index i
         JOIN pg_class c ON c.oid = i.indrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
         CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord)
         JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
        WHERE n.nspname = 'public' AND i.indisprimary
        GROUP BY c.relname`,
    );
    const pk = new Map((res.rows as { table: string; columns: string[] }[]).map((r) => [r.table, r.columns]));
    for (const t of manifest.tables) {
      // A table left out has no order; audit_events goes by event_order and
      // requirements by its physical order (the manifest's notes).
      if (t.action === "leftOut" || t.physicalOrder || t.source === "audit_events") continue;
      expect([t.source, t.orderBy]).toEqual([t.source, pk.get(t.source)]);
    }
  });

  it("fails on a column or a table a migration adds", async () => {
    await db.query("ALTER TABLE grants ADD COLUMN added_later text");
    await db.query("CREATE TABLE added_table (id text PRIMARY KEY)");
    const errs = differences(manifest, await readSchema(db)).join("\n");
    expect(errs).toContain("added_later");
    expect(errs).toContain("added_table");
  });
});
