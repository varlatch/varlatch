#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Dumps the PostgreSQL schema of a TypeScript release as JSON, the input of
 * go/server/db's mapping test (ADR-0059 Decision 2, step 3.1).
 *
 *   node go/server/db/testdata/pgschema.mjs [--ref <git ref>] <out.json>
 *
 * It reads the migration runner and every migration of <ref> (v0.22.0 by
 * default) with `git show`, so the working tree's own migrations play no
 * part, runs them with the server's own runner (runMigrations) on an empty
 * PGlite database, and reads the result from the catalog: tables, columns
 * (type, nullability, default), constraints (primary key, foreign key,
 * unique and check, with their definitions), indexes (with predicates),
 * triggers and the functions they call, and how many rows the migrations
 * themselves insert per table (seed rows). Everything is sorted, so the same
 * ref always gives the same file.
 *
 * PGlite comes from services/varlatchd's dependencies (`pnpm install
 * --frozen-lockfile` at the repository root); its version is recorded in the
 * output. Migrations that act only when a deployment role exists (0003,
 * 0004, 0017, 0020) grant privileges, which PGlite has no role for; the
 * mapping covers them in prose (MAPPING.md, "Privileges").
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { findPackageJSON } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const DB_DIR = "services/varlatchd/src/db";

function args(argv) {
  let ref = "v0.22.0";
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--ref") ref = argv[++i];
    else rest.push(argv[i]);
  }
  if (rest.length !== 1 || !ref) {
    console.error("usage: pgschema.mjs [--ref <git ref>] <out.json>");
    process.exit(2);
  }
  return { ref, out: rest[0] };
}

const git = (...a) => execFileSync("git", ["-C", repoRoot, ...a], { encoding: "utf8" });

// The ref's migration runner and migrations, in a directory of their own,
// with their relative imports pointed at the .ts files.
async function loadRunner(ref) {
  const commit = git("rev-parse", `${ref}^{commit}`).trim();
  const dir = mkdtempSync(join(tmpdir(), "varlatch-pgschema-"));
  try {
    writeFileSync(join(dir, "package.json"), '{"type":"module"}\n');
    mkdirSync(join(dir, "migrations"));
    const files = git("ls-tree", "--name-only", `${commit}:${DB_DIR}/migrations`).split("\n").filter((f) => f.endsWith(".ts"));
    const fix = (text) => text.replace(/(from\s+"\.{1,2}\/[^"]+)\.js"/g, '$1.ts"');
    for (const f of files) writeFileSync(join(dir, "migrations", f), fix(git("show", `${commit}:${DB_DIR}/migrations/${f}`)));
    writeFileSync(join(dir, "migrate.ts"), fix(git("show", `${commit}:${DB_DIR}/migrate.ts`)));
    const runner = await import(pathToFileURL(join(dir, "migrate.ts")).href);
    const { MIGRATIONS } = await import(pathToFileURL(join(dir, "migrations", "index.ts")).href);
    return { commit, runner, migrations: MIGRATIONS };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// PGlite as services/varlatchd resolves it (its ESM entry point).
function pglite() {
  const base = pathToFileURL(join(repoRoot, "services/varlatchd/package.json")).href;
  const pkgPath = findPackageJSON("@electric-sql/pglite", base);
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
  const entry = pkg.exports?.["."]?.import?.default ?? pkg.exports?.["."]?.import ?? pkg.module;
  if (typeof entry !== "string") throw new Error("cannot find PGlite's ESM entry point");
  return { version: pkg.version, url: pathToFileURL(join(dirname(pkgPath), entry)).href };
}

const byName = (a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0);

async function dump(pg) {
  const q = async (text) => (await pg.query(text)).rows;
  const tables = await q(`
    SELECT c.oid, c.relname AS name
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
     ORDER BY c.relname`);
  const out = [];
  for (const t of tables) {
    const columns = await q(`
      SELECT a.attname AS name, a.attnum AS position, format_type(a.atttypid, a.atttypmod) AS type,
             a.attnotnull AS not_null, pg_get_expr(d.adbin, d.adrelid) AS default
        FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
       WHERE a.attrelid = ${t.oid} AND a.attnum > 0 AND NOT a.attisdropped
       ORDER BY a.attnum`);
    const constraints = await q(`
      SELECT c.conname AS name, c.contype AS type, pg_get_constraintdef(c.oid) AS definition,
             (SELECT array_agg(a.attname ORDER BY k.i) FROM unnest(c.conkey) WITH ORDINALITY AS k(n, i)
                JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.n) AS columns,
             f.relname AS ref_table,
             (SELECT array_agg(a.attname ORDER BY k.i) FROM unnest(c.confkey) WITH ORDINALITY AS k(n, i)
                JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.n) AS ref_columns,
             CASE WHEN c.contype = 'f' THEN c.confdeltype END AS on_delete,
             CASE WHEN c.contype = 'f' THEN c.confupdtype END AS on_update,
             i.relname AS index
        FROM pg_constraint c LEFT JOIN pg_class f ON f.oid = c.confrelid
             LEFT JOIN pg_class i ON i.oid = c.conindid AND c.contype IN ('p', 'u')
       WHERE c.conrelid = ${t.oid} AND c.contype IN ('p', 'f', 'u', 'c')
       ORDER BY c.conname`);
    const indexes = await q(`
      SELECT i.relname AS name, x.indisunique AS unique, x.indisprimary AS primary,
             EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conindid = x.indexrelid AND c.contype IN ('p', 'u')) AS from_constraint,
             (SELECT array_agg(pg_get_indexdef(x.indexrelid, k.i::int, true) ORDER BY k.i)
                FROM generate_series(1, x.indnkeyatts) AS k(i)) AS keys,
             (SELECT array_agg((x.indoption[k.i - 1] & 1) = 1 ORDER BY k.i)
                FROM generate_series(1, x.indnkeyatts) AS k(i)) AS descending,
             pg_get_expr(x.indpred, x.indrelid) AS predicate, pg_get_indexdef(x.indexrelid) AS definition
        FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid
       WHERE x.indrelid = ${t.oid}
       ORDER BY i.relname`);
    const triggers = await q(`
      SELECT g.tgname AS name, p.proname AS function, pg_get_triggerdef(g.oid) AS definition
        FROM pg_trigger g JOIN pg_proc p ON p.oid = g.tgfoid
       WHERE g.tgrelid = ${t.oid} AND NOT g.tgisinternal
       ORDER BY g.tgname`);
    out.push({
      name: t.name,
      columns: columns.map((c) => ({ name: c.name, position: c.position, type: c.type, notNull: c.not_null, default: c.default })),
      constraints: constraints.map((c) => ({
        name: c.name,
        type: { p: "primary key", f: "foreign key", u: "unique", c: "check" }[c.type],
        columns: c.columns ?? [],
        ...(c.type === "f" ? { refTable: c.ref_table, refColumns: c.ref_columns, onDelete: c.on_delete, onUpdate: c.on_update } : {}),
        ...(c.index ? { index: c.index } : {}),
        definition: c.definition,
      })),
      indexes: indexes.map((x) => ({
        name: x.name, unique: x.unique, primary: x.primary, fromConstraint: x.from_constraint,
        keys: x.keys.map((key, i) => ({ key, descending: x.descending[i] })), predicate: x.predicate, definition: x.definition,
      })),
      triggers,
    });
  }
  const functions = await q(`
    SELECT p.proname AS name, pg_get_functiondef(p.oid) AS definition
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'public'
     ORDER BY p.proname`);
  const sequences = await q(`
    SELECT c.relname AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind = 'S' ORDER BY c.relname`);
  const views = await q(`
    SELECT c.relname AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind IN ('v', 'm') ORDER BY c.relname`);
  // Rows a fresh installation starts with (the migrations' own inserts),
  // counted per table: their values can hold the time of the run.
  const seedRows = {};
  for (const t of tables) {
    const [{ n }] = await q(`SELECT count(*)::int AS n FROM public."${t.name}"`);
    if (n > 0 && t.name !== "varlatch_migrations") seedRows[t.name] = n;
  }
  return { tables: out.sort(byName), functions, sequences, views, seedRows };
}

async function main() {
  const { ref, out } = args(process.argv.slice(2));
  const { commit, runner, migrations } = await loadRunner(ref);
  const lite = pglite();
  const { PGlite } = await import(lite.url);
  const pg = new PGlite();
  await pg.waitReady;
  try {
    await runner.runMigrations({
      query: async (text, params) => ({ rows: (await pg.query(text, params)).rows }),
      exec: async (text) => {
        await pg.exec(text);
      },
    });
    const server = (await pg.query("SHOW server_version")).rows[0].server_version;
    const schema = await dump(pg);
    const result = {
      comment: "Generated by go/server/db/testdata/pgschema.mjs; do not edit. The PostgreSQL schema the TypeScript server's migrations create.",
      ref,
      commit,
      pglite: lite.version,
      postgres: server,
      migrations: migrations.map((m) => `${String(m.id).padStart(4, "0")}_${m.name}`),
      ...schema,
    };
    writeFileSync(out, JSON.stringify(result, null, 2) + "\n");
  } finally {
    await pg.close();
  }
}

await main();
