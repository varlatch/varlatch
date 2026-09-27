// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { inject } from "vitest";
import { runMigrations, type Querier } from "../../src/db/migrate.js";
import { asQuerier } from "./pglite-snapshots.js";

type TestDb = Querier & { close: () => Promise<void> };

/** In-memory Postgres for tests, adapted to the Querier surface: an empty cluster. */
export function testDb(): Promise<TestDb> {
  return load("fresh");
}

/** An in-memory Postgres already migrated to the current schema. */
export async function migratedTestDb(): Promise<TestDb> {
  const db = await load("migrated");
  // A no-op unless a migration was added since the snapshot (watch mode).
  await runMigrations(db);
  return db;
}

// Each instance loads a snapshot taken once per run (pglite-snapshots.ts)
// into its own memory, so tests stay as isolated as with a new cluster.
async function load(kind: "fresh" | "migrated"): Promise<TestDb> {
  const pg = new PGlite({ loadDataDir: await (snapshots[kind] ??= loadSnapshot(kind)) });
  await pg.waitReady;
  return { ...asQuerier(pg), close: () => pg.close() };
}

const snapshots: Partial<Record<"fresh" | "migrated", Promise<Blob>>> = {};

async function loadSnapshot(kind: "fresh" | "migrated"): Promise<Blob> {
  return new Blob([await readFile(inject("pgliteSnapshots")[kind])]);
}
