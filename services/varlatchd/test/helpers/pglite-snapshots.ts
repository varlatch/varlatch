// SPDX-License-Identifier: AGPL-3.0-or-later
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import type { TestProject } from "vitest/node";
import { runMigrations, type Querier } from "../../src/db/migrate.js";
import { installLockTrace, lockOrderMode } from "./lock-trace.js";

/**
 * Vitest global setup. Initializing a PGlite cluster costs most of a test's
 * setup time, and migrating it more; both happen once per run here, saved as
 * data-directory snapshots that the helpers in pglite.ts load into a fresh,
 * independent instance per test.
 */
export default async function setup(project: TestProject): Promise<() => Promise<void>> {
  const dir = await mkdtemp(join(tmpdir(), "varlatch-pglite-"));
  const pg = new PGlite();
  await pg.waitReady;
  const fresh = join(dir, "fresh.tar");
  await writeFile(fresh, await dump(pg));
  await runMigrations(asQuerier(pg));
  const migrated = join(dir, "migrated.tar");
  await writeFile(migrated, await dump(pg));
  // The lock-order check's trace (lock-trace.ts): a test-only schema,
  // installed into a third snapshot that migratedTestDb() loads.
  let traced = migrated;
  if (lockOrderMode() !== "off") {
    await installLockTrace(asQuerier(pg));
    traced = join(dir, "traced.tar");
    await writeFile(traced, await dump(pg));
  }
  await pg.close();
  project.provide("pgliteSnapshots", { fresh, migrated, traced });
  return () => rm(dir, { recursive: true, force: true });
}

async function dump(pg: PGlite): Promise<Buffer> {
  return Buffer.from(await (await pg.dumpDataDir("none")).arrayBuffer());
}

/** A PGlite instance adapted to the Querier surface. */
export function asQuerier(pg: PGlite): Required<Querier> {
  return {
    query: async (text, params) => {
      const res = await pg.query(text, params as never[] | undefined);
      return { rows: res.rows as unknown[] };
    },
    exec: async (text) => {
      await pg.exec(text);
    },
  };
}

declare module "vitest" {
  export interface ProvidedContext {
    pgliteSnapshots: { fresh: string; migrated: string; traced: string };
  }
}
