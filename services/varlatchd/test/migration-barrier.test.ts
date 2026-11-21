// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { activeGate, Maintenance } from "@varlatch/backup";
import { control, migrationBarrier, startBackupControl } from "../src/backup/control.js";
import { generateKey } from "../src/crypto/aead.js";
import type { PoolQuerier } from "../src/db/tx.js";
import { ensureInstallation } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { buildApp } from "../src/http/app.js";
import { startMirrorLoop } from "../src/mirror/publisher.js";
import { startWebhookLoop } from "../src/domain/webhooks.js";
import { startAuditExportLoop } from "../src/domain/auditexport.js";
import { startExposureBackfillLoop } from "../src/domain/exposure.js";
import { startDeletionLoop } from "../src/domain/orgdeletion.js";
import { startRegistrationSweepLoop } from "../src/domain/githubapps.js";
import { startSecurityReportLoop } from "../src/domain/securityreport.js";
import { startSyncLoop } from "../src/domain/syncdelivery.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * The migration barrier and the migrated-out marker (ADR-0059 step 7,
 * internal docs/design/go-step7.md decisions 6 and 15, slice 7.2a).
 */

const dirs: string[] = [];
const directory = () => {
  const dir = mkdtempSync(join(tmpdir(), "varlatch-migration-"));
  dirs.push(dir);
  return dir;
};
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** A PGlite database as the pool varlatchd's drain takes connections from. */
function pool(db: Awaited<ReturnType<typeof migratedTestDb>>): PoolQuerier {
  return { query: db.query.bind(db), connect: async () => ({ query: db.query.bind(db), release() {} }) } as unknown as PoolQuerier;
}

/** Maintenance that records what tries to enter, by label. */
class Recording extends Maintenance {
  readonly tried = new Set<string>();
  override enter(label = "request") {
    this.tried.add(label);
    return super.enter(label);
  }
}

/** Every request kind the admission covers, with a body where it takes one. */
const REQUESTS: [string, string][] = [
  ["GET", "/v1/organizations"],
  ["POST", "/v1/organizations"],
  ["POST", "/v1/me/credentials/cli"],
  ["POST", "/v1/oidc/token"],
  ["POST", "/v1/auth/device"],
  ["POST", "/v1/auth/device/token"],
  ["POST", "/v1/tokens/convex"],
  ["POST", "/auth/varlatch-token"],
  ["POST", "/auth/passkey/sign-in/options"],
  ["GET", "/.well-known/jwks.json"],
];

describe("the admission", () => {
  let ctx: AppCtx & { close: () => Promise<void> };
  let dir: string;
  beforeEach(async () => {
    const db = await migratedTestDb();
    dir = directory();
    ctx = { db, rootKek: generateKey(), maintenance: new Maintenance(dir), close: db.close };
    await ensureInstallation(ctx);
  });
  afterEach(async () => ctx.close());

  it("answers every request kind 503 with Retry-After behind the barrier, and /readyz names it", async () => {
    const app = buildApp(ctx);
    ctx.maintenance!.beginMigration();
    for (const [method, path] of REQUESTS) {
      const res = await app.request(path, { method, headers: { "Content-Type": "application/json" }, ...(method === "POST" ? { body: "{}" } : {}) });
      expect(res.status, `${method} ${path}`).toBe(503);
      expect(res.headers.get("Retry-After"), `${method} ${path}`).toBe("5");
      expect((await res.json()).error.code).toBe("MAINTENANCE");
    }
    const ready = await app.request("/readyz");
    expect(ready.status).toBe(503);
    expect(await ready.json()).toEqual({ ready: false, checks: { maintenance: false }, state: "migration" });
    expect((await app.request("/healthz")).status).toBe(200);
  });

  it("refuses reads as well as writes once migrated out, saying so, and /readyz names it", async () => {
    const app = buildApp(ctx);
    const m = ctx.maintenance!;
    const gate = m.beginMigration();
    m.freezeMigration(gate.id, "1");
    m.markMigratedOut(gate.id);
    for (const [method, path] of REQUESTS) {
      const res = await app.request(path, { method, headers: { "Content-Type": "application/json" }, ...(method === "POST" ? { body: "{}" } : {}) });
      expect(res.status, `${method} ${path}`).toBe(503);
      expect((await res.json()).error.message).toMatch(/migrated to another server/);
    }
    expect(await (await app.request("/readyz")).json()).toEqual({ ready: false, checks: { maintenance: false }, state: "migrated-out" });
    // A restart keeps it: the gate is in the state directory.
    const restarted = buildApp({ ...ctx, maintenance: new Maintenance(dir) });
    expect((await restarted.request("/v1/organizations")).status).toBe(503);
  });

  it("answers as before without the migration: /readyz has no state, a capture's 503 its old message", async () => {
    const app = buildApp(ctx);
    const ready = await app.request("/readyz");
    expect(ready.status).toBe(200);
    expect(JSON.stringify(await ready.json())).not.toContain("state");
    ctx.maintenance!.beginCapture(10_000);
    const res = await app.request("/v1/organizations");
    expect(res.status).toBe(503);
    expect((await res.json()).error.message).toBe("Installation maintenance; retry later");
    expect(await (await app.request("/readyz")).json()).toEqual({ ready: false, checks: { maintenance: false } });
  });
});

describe("the background loops", () => {
  it("pauses each of the eight loops the daemon starts, by name, and none touches the database", async () => {
    let queries = 0;
    const db = { query: async () => { queries++; return { rows: [], rowCount: 0 }; }, connect: async () => { queries++; throw new Error("no connection"); } };
    const m = new Recording(directory());
    m.beginMigration();
    const ctx = { db, rootKek: generateKey(), maintenance: m } as unknown as AppCtx;
    const stops = [
      startMirrorLoop(ctx, { convexUrl: "http://127.0.0.1:9", issuer: "http://localhost" }, 20, 20),
      startWebhookLoop(ctx, 20),
      startAuditExportLoop(ctx, 20),
      startExposureBackfillLoop(ctx, { busyMs: 20, idleMs: 20 }),
      startDeletionLoop(ctx, 20),
      startRegistrationSweepLoop(ctx, 20),
      startSecurityReportLoop(ctx, 20),
      startSyncLoop(ctx, { intervalMs: 20 }),
    ];
    await sleep(200);
    for (const stop of stops) stop();
    expect([...m.tried].sort()).toEqual([
      "audit-export", "exposure-backfill", "github-app-sweep", "mirror", "organization-deletion", "security-report", "sync", "webhooks",
    ]);
    expect(queries).toBe(0);
    expect(m.busy).toBe(0);
  });
});

describe("the drain", () => {
  let db: Awaited<ReturnType<typeof migratedTestDb>>;
  let ctx: AppCtx;
  let m: Maintenance;
  beforeEach(async () => {
    db = await migratedTestDb();
    m = new Maintenance(directory());
    ctx = { db: pool(db), rootKek: generateKey(), maintenance: m };
    await ensureInstallation({ db, rootKek: ctx.rootKek });
  });
  afterEach(async () => db.close());

  const count = async () => Number(((await db.query("SELECT count(*)::int AS n FROM audit_events")).rows[0] as { n: number }).n);

  it("waits for what is in flight, names it, freezes the last audit position, and writes nothing", async () => {
    const before = await count();
    const last = ((await db.query("SELECT max(event_order)::text AS p FROM audit_events")).rows[0] as { p: string }).p;
    const webhook = m.enter("webhooks")!;
    const request = m.enter("request")!;
    const barrier = migrationBarrier(ctx, m, 10_000);
    await sleep(100);
    expect(m.gate).toMatchObject({ kind: "migration", phase: "draining" });
    expect(m.enter("sync")).toBeNull();
    webhook();
    request();
    const done = await barrier;
    expect(done.drained.waitedFor).toEqual({ webhooks: 1, request: 1 });
    expect(done.frozen.auditPosition).toBe(last);
    expect(done.gate).toMatchObject({ kind: "migration", phase: "paused", frozenPosition: last });
    expect(await count()).toBe(before);
  });

  it("keeps the barrier when the drain times out, naming what still runs, and continues it on a rerun", async () => {
    const sync = m.enter("sync")!;
    await expect(migrationBarrier(ctx, m, 150)).rejects.toThrow(/did not drain within .*still running: sync/);
    const held = m.gate!;
    expect(held).toMatchObject({ kind: "migration", phase: "draining" });
    sync();
    const done = await migrationBarrier(ctx, m, 1000);
    expect(done.gate.id).toBe(held.id);
    expect(done.gate.phase).toBe("paused");
  });
});

describe("the control socket and host commands", () => {
  it("refuses the host backup timer's capture behind the barrier, and drives the barrier and the marker", async () => {
    const db = await migratedTestDb();
    const dir = directory();
    try {
      const m = new Maintenance(dir);
      // One key: a capture checks the loaded KEK against the installation's canary.
      const rootKek = generateKey();
      await ensureInstallation({ db, rootKek });
      startBackupControl({ db: pool(db), rootKek }, m, null);
      await sleep(50);
      const barrier = (await control({ command: "migration-barrier", drainMs: 5_000 }, dir)) as { gate: { id: string; kind: string; phase: string } };
      expect(barrier.gate).toMatchObject({ kind: "migration", phase: "paused" });
      // The host timer (infra/host-backup/run.sh) runs `varlatch admin backup
      // create`, which begins a capture through this socket: refused.
      await expect(control({ command: "online-capture-begin", ttlMs: 60_000 }, dir)).rejects.toThrow("Installation maintenance is active; capture refused");
      await expect(control({ command: "capture-begin", ttlMs: 60_000 }, dir)).rejects.toThrow();
      // Host commands that write refuse under any gate (cli.ts), the
      // migration's included, whatever the clock says.
      expect(activeGate(dir, Number.MAX_SAFE_INTEGER)?.kind).toBe("migration");
      const status = (await control({ command: "migration-status" }, dir)) as { gate: { kind: string }; busy: number };
      expect(status).toMatchObject({ gate: { kind: "migration" }, busy: 0 });
      await expect(control({ command: "migration-release", id: "not-this-one" }, dir)).rejects.toThrow("ownership lost");
      const marked = (await control({ command: "migration-migrated-out", id: barrier.gate.id }, dir)) as { gate: { kind: string } };
      expect(marked.gate.kind).toBe("migrated-out");
      await expect(control({ command: "migration-release", id: barrier.gate.id }, dir)).rejects.toThrow("Only the migration barrier");
      expect(activeGate(dir, Number.MAX_SAFE_INTEGER)?.kind).toBe("migrated-out");
      // Behind the migrated-out marker the data is frozen: the online capture,
      // which only reads, is taken (the final archive of varlatch migrate
      // --finish --delete-old-data); the marker stays. The frozen capture,
      // which opens a gate of its own, is still refused.
      const capture = (await control({ command: "online-capture-begin", ttlMs: 60_000 }, dir)) as { id: string; snapshot: string };
      expect(capture.snapshot).toBeTruthy();
      // (Its finish checks the exclusion in pg_locks, which this test's
      // database does not keep; the rehearsal on a real installation
      // finishes one, go/test/rehearsal.)
      await expect(control({ command: "online-capture-abort", id: capture.id }, dir)).resolves.toMatchObject({ aborted: true });
      await expect(control({ command: "capture-begin", ttlMs: 60_000 }, dir)).rejects.toThrow();
      expect(activeGate(dir, Number.MAX_SAFE_INTEGER)?.kind).toBe("migrated-out");
    } finally {
      await db.close();
    }
  });
});

describe("the review's P3s", () => {
  it("answers the read-only commands while the barrier drains, and runs no other beside it", async () => {
    const db = await migratedTestDb();
    const dir = directory();
    try {
      const m = new Maintenance(dir);
      await ensureInstallation({ db, rootKek: generateKey() });
      startBackupControl({ db: pool(db), rootKek: generateKey() }, m, null);
      await sleep(50);
      const leave = m.enter("webhooks")!;
      const barrier = control({ command: "migration-barrier", drainMs: 10_000 }, dir);
      await sleep(150);
      const status = (await control({ command: "migration-status" }, dir)) as { gate: { kind: string; phase: string }; inFlight: Record<string, number> };
      expect(status).toMatchObject({ gate: { kind: "migration", phase: "draining" }, inFlight: { webhooks: 1 } });
      await expect(control({ command: "status" }, dir)).resolves.toBeTruthy();
      await expect(control({ command: "migration-release", id: status.gate.kind }, dir)).rejects.toThrow("Another control operation is running");
      leave();
      await expect(barrier).resolves.toMatchObject({ gate: { phase: "paused" } });
    } finally {
      await db.close();
    }
  });

  it("bounds the operator drain by the drain's time, naming an operator process, and keeps the barrier", async () => {
    // An operator process holds its lease: the exclusive lock is never free.
    const db = {
      query: async (sql: string) => ({ rows: [sql.includes("pg_try_advisory_lock") ? { acquired: false } : { p: "0" }], rowCount: 1 }),
      connect: async () => ({ query: async () => ({ rows: [{ acquired: false }], rowCount: 1 }), release() {} }),
    } as unknown as PoolQuerier;
    const m = new Maintenance(directory());
    await expect(migrationBarrier({ db, rootKek: generateKey(), maintenance: m }, m, 200)).rejects.toThrow(/did not drain within .*still running: an operator process/);
    expect(m.gate).toMatchObject({ kind: "migration", phase: "draining" });
  });

  it("calls only a missing or unanswered socket 'not running'; any other failure is an error", async () => {
    const none = directory();
    await expect(control({ command: "status" }, none)).rejects.toThrow("Backup supervisor is not running");
    const stale = directory();
    writeFileSync(join(stale, "backup.sock"), "");
    await expect(control({ command: "status" }, stale)).rejects.toThrow("Backup supervisor is not running");
    if (process.getuid?.() === 0) return; // root opens a socket whatever its mode
    const locked = directory();
    const server = createServer();
    await new Promise<void>((r) => server.listen(join(locked, "backup.sock"), () => r()));
    try {
      chmodSync(join(locked, "backup.sock"), 0o000);
      await expect(control({ command: "status" }, locked)).rejects.toThrow("Backup control socket failed (EACCES)");
    } finally {
      server.close();
    }
  });
});
