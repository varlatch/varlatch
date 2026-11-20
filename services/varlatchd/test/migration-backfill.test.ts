// SPDX-License-Identifier: AGPL-3.0-or-later
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";

/**
 * `varlatchd admin migration backfill` (go-step7 decision 18, slice 7.7b):
 * the backup converter's one-shot exposure backfill. A database brought
 * forward from before migration 36 has an unfinished backfill, which the
 * export's preflight refuses; the command finishes it in its own process,
 * as the daemon's loop would, and does nothing once it has finished.
 */
const url = process.env.VARLATCH_TEST_DATABASE_URL;
const cli = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
describe.skipIf(!url || !existsSync(cli))("admin migration backfill", () => {
  const database = `varlatch_backfill_${process.pid}`;
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let dir: string;
  let databaseUrl: string;
  beforeEach(async () => {
    admin = createPgQuerier(url!);
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${database}`);
    const u = new URL(url!);
    u.pathname = `/${database}`;
    databaseUrl = u.toString();
    db = createPgQuerier(databaseUrl);
    const c = await db.connect();
    try {
      await runMigrations(c);
    } finally {
      c.release();
    }
    dir = mkdtempSync(join(tmpdir(), "vl-bf-"));
  }, 120_000);
  afterEach(async () => {
    await db.end();
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.end();
    rmSync(dir, { recursive: true, force: true });
  }, 120_000);

  const backfill = () => spawnSync(process.execPath, [cli, "admin", "migration", "backfill"], {
    env: { PATH: process.env.PATH ?? "", VARLATCH_DATABASE_URL: databaseUrl, VARLATCH_STATE_DIR: dir }, encoding: "utf8",
  });
  const state = async () => (await db.query("SELECT finished_at IS NOT NULL AS finished, cursor::text, until_order::text FROM exposure_backfill")).rows[0] as { finished: boolean; cursor: string; until_order: string };

  it("finishes an unfinished backfill in one run, and then does nothing", async () => {
    // As migration 36 leaves a database that already holds audit events: unfinished, up to the last one.
    await db.query("INSERT INTO audit_events (id, event_type, decision, metadata) SELECT 'evt_bf_' || n, 'organization.created', 'allow', '{}'::jsonb FROM generate_series(1, 3) n");
    await db.query("UPDATE exposure_backfill SET finished_at = NULL, cursor = 0, until_order = (SELECT max(event_order) FROM audit_events)");
    expect((await state()).finished).toBe(false);
    const first = backfill();
    expect(first.status, first.stderr).toBe(0);
    expect(JSON.parse(first.stdout)).toMatchObject({ finished: true });
    const after = await state();
    expect(after.finished).toBe(true);
    expect(after.cursor).toBe(after.until_order);
    const second = backfill();
    expect(second.status, second.stderr).toBe(0);
    expect(JSON.parse(second.stdout)).toEqual({ finished: true, batches: 0, events: 0 });
  }, 120_000);

  it("takes no argument", () => {
    const r = spawnSync(process.execPath, [cli, "admin", "migration", "backfill", "--now"], {
      env: { PATH: process.env.PATH ?? "", VARLATCH_DATABASE_URL: databaseUrl, VARLATCH_STATE_DIR: dir }, encoding: "utf8",
    });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/varlatchd admin migration backfill/);
  });
});
