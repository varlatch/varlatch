// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Maintenance } from "@varlatch/backup";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import { ensureInstallation } from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { CAPTURE_EXCLUSION, OnlineCapture, withCaptureExclusion, type OnlineCaptureOptions } from "../src/backup/online.js";
import type { AppCtx } from "../src/domain/ctx.js";

// ADR-0036 D5 acceptance criteria, against a real PostgreSQL server: locks,
// exported snapshots and backend termination need concurrent connections.
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("online capture (ADR-0036)", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx & { db: ReturnType<typeof createPgQuerier> };
  let dir: string;
  const database = `varlatch_capture_${process.pid}`;
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const capture = (opts: OnlineCaptureOptions = {}) => new OnlineCapture(ctx, opts);
  const exclusionFree = async () => {
    const c = await db.connect();
    try {
      const got = (await c.query("SELECT pg_try_advisory_lock($1) AS a", [CAPTURE_EXCLUSION])).rows[0] as { a: boolean };
      if (got.a) await c.query("SELECT pg_advisory_unlock($1)", [CAPTURE_EXCLUSION]);
      return got.a;
    } finally { c.release(); }
  };

  beforeEach(async () => {
    admin = createPgQuerier(url!);
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${database}`);
    const target = new URL(url!); target.pathname = `/${database}`;
    db = createPgQuerier(target.toString());
    const c = await db.connect();
    try { await runMigrations(c); } finally { c.release(); }
    dir = mkdtempSync(join(tmpdir(), "varlatch-online-"));
    ctx = { db, rootKek: Buffer.alloc(32, 7), maintenance: new Maintenance(dir) };
    await ensureInstallation(ctx);
  });
  afterEach(async () => {
    await db.end();
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.end();
    rmSync(dir, { recursive: true, force: true });
  });

  it("dumps one exported snapshot while traffic is admitted, then releases the exclusion", async () => {
    const online = capture();
    const started = await online.begin(10_000);
    expect(started.metadata.requiredKeyVersions).toEqual([1]);
    // No gate: the Secret Plane keeps serving and accepting writes.
    const app = buildApp(ctx);
    expect((await app.request("/readyz")).status).toBe(200);
    expect((await app.request("/.well-known/jwks.json")).status).toBe(200);
    await db.query("INSERT INTO organizations(id, slug, name, wrapped_org_kek, root_kek_version) VALUES ('org_after','after','After','{}',1)");
    // The dump's view is the snapshot, taken before that write.
    const dump = await db.connect();
    try {
      await dump.query("BEGIN ISOLATION LEVEL REPEATABLE READ");
      await dump.query(`SET TRANSACTION SNAPSHOT '${started.snapshot}'`);
      expect((await dump.query("SELECT count(*)::int AS n FROM organizations")).rows[0]).toEqual({ n: 0 });
      await dump.query("COMMIT");
    } finally { dump.release(); }
    expect(await exclusionFree()).toBe(false);
    expect(await online.finish(started.id)).toEqual({ valid: true });
    expect(await exclusionFree()).toBe(true);
  });

  it("sees a rotation that commits while it waits for the exclusion, and refuses", async () => {
    const rotation = await db.connect();
    try {
      await rotation.query("SELECT pg_advisory_lock($1)", [CAPTURE_EXCLUSION]);
      await rotation.query("BEGIN");
      await rotation.query("UPDATE installation SET key_rotation_state = 'rewrapping'");
      const pending = capture().begin(10_000);
      await sleep(300); // the capture is now waiting for the exclusion
      await rotation.query("COMMIT");
      await rotation.query("SELECT pg_advisory_unlock($1)", [CAPTURE_EXCLUSION]);
      // Had the snapshot been taken before the lock, it would predate the
      // commit and the check would pass on stale state.
      await expect(pending).rejects.toThrow(/rotation/);
    } finally { rotation.release(); }
    expect(await exclusionFree()).toBe(true);
  });

  it("refuses excluded operations during a capture and admits them after", async () => {
    const online = capture();
    const started = await online.begin(10_000);
    await expect(withCaptureExclusion(db, 200, async () => "migrated")).rejects.toThrow(/backup capture/);
    await online.finish(started.id);
    await expect(withCaptureExclusion(db, 200, async () => "migrated")).resolves.toBe("migrated");
  });

  it("on lease expiry confirms the dump has exited before releasing the exclusion", async () => {
    const steps: string[] = [];
    const online = capture({ onStep: (s) => steps.push(s) });
    const started = await online.begin(1500);
    const dump = await db.connect();
    await dump.query(`SET application_name = '${started.application}'`);
    await dump.query("BEGIN ISOLATION LEVEL REPEATABLE READ");
    await dump.query(`SET TRANSACTION SNAPSHOT '${started.snapshot}'`);
    const dumping = dump.query("SELECT pg_sleep(60)").then(() => "finished", () => "terminated");
    // A would-be rotation polls for the exclusion; the moment it gets it, no
    // backend of this capture may still exist.
    const watcher = await db.connect();
    let dumpAliveAtRelease = -1;
    try {
      for (let i = 0; i < 400; i++) {
        const got = (await watcher.query("SELECT pg_try_advisory_lock($1) AS a", [CAPTURE_EXCLUSION])).rows[0] as { a: boolean };
        if (got.a) {
          dumpAliveAtRelease = ((await watcher.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE application_name = $1", [started.application])).rows[0] as { n: number }).n;
          await watcher.query("SELECT pg_advisory_unlock($1)", [CAPTURE_EXCLUSION]);
          break;
        }
        await sleep(20);
      }
    } finally { watcher.release(); }
    expect(await dumping).toBe("terminated");
    dump.release(true);
    expect(dumpAliveAtRelease).toBe(0);
    expect(steps).toEqual(["invalidated", "terminated", "snapshot-closed", "released"]);
    await expect(online.finish(started.id)).rejects.toThrow(/Unknown or lost/);
  });

  it("keeps the exclusion while termination cannot be confirmed", async () => {
    let attempts = 0;
    const steps: string[] = [];
    const online = capture({ terminate: async () => ++attempts > 2, onStep: (s) => steps.push(s) });
    const started = await online.begin(1000);
    await sleep(1300); // expired; first two termination attempts fail
    expect(steps.slice(0, 2)).toEqual(["invalidated", "termination-unconfirmed"]);
    expect(await exclusionFree()).toBe(false);
    for (let i = 0; i < 50 && !steps.includes("released"); i++) await sleep(100);
    expect(steps).toContain("released");
    expect(await exclusionFree()).toBe(true);
    await expect(online.finish(started.id)).rejects.toThrow();
  });

  it("never confirms a capture whose connection was lost", async () => {
    const online = capture();
    const started = await online.begin(10_000);
    const holder = (await admin.query(
      `SELECT l.pid FROM pg_locks l JOIN pg_database d ON d.oid = l.database
       WHERE l.locktype = 'advisory' AND l.objid = $1 AND l.granted AND d.datname = $2`, [CAPTURE_EXCLUSION, database],
    )).rows[0] as { pid: number };
    await admin.query("SELECT pg_terminate_backend($1, 5000)", [holder.pid]);
    await expect(online.finish(started.id)).rejects.toThrow(/lost its exclusion|expired/);
    expect(await exclusionFree()).toBe(true);
  });

  it("a restarted daemon knows no earlier capture", async () => {
    const before = capture();
    const started = await before.begin(10_000);
    await expect(capture().finish(started.id)).rejects.toThrow(/Unknown or lost/);
    await before.abort(started.id); // the old process's connection, in this test
  });
});
