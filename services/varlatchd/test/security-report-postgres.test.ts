// SPDX-License-Identifier: AGPL-3.0-or-later
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Maintenance } from "@varlatch/backup";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { recordAuditEvent } from "../src/audit/events.js";
import { issueCredential } from "../src/auth/credentials.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import { withSerializableTx, withTx } from "../src/db/tx.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { lockLiveScope } from "../src/domain/liveness.js";
import {
  ACCESS_COUNTS,
  accessCountHooks,
  accessCountsPending,
  accessCountsSettled,
  countWouldBlock,
  emitDueSummaries,
  queueAccessCount,
  type PendingAccessReport,
  type WouldBlock,
} from "../src/domain/securityreport.js";
import { getEnvironment } from "../src/domain/environments.js";
import { getOrganization } from "../src/domain/orgs.js";
import { getProject } from "../src/domain/projects.js";
import { captureState, inSnapshot } from "../src/domain/retrieval.js";
import { discloseSecrets } from "../src/domain/values.js";
import { buildApp } from "../src/http/app.js";

/**
 * Report counters under concurrency, on real PostgreSQL (ADR-0054
 * Decision 9): several summary workers, or one that dies before
 * committing, produce each summary once; an increment whose bucket the
 * worker is emitting waits, sees it emitted and lands in the current
 * hour, without a deadlock, because it upserts its counters before its
 * first audit insert (the reverse order deadlocks, which the test shows);
 * under SERIALIZABLE the conflict fails the transaction with 40001 and
 * withSerializableTx runs it again, increment included, exactly once; and
 * mutations and workers running together lose and double nothing.
 */
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("report counters on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let orgId: string;
  let adminId: string;
  let cli: string;
  let app: ReturnType<typeof buildApp>;
  const database = `varlatch_secreport_test_${process.pid}`;

  const call = async (method: string, path: string, token: string, body?: unknown) => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await res.text();
    await accessCountsSettled();
    return { status: res.status, body: text ? JSON.parse(text) : null };
  };

  beforeEach(async () => {
    admin = createPgQuerier(url!);
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${database}`);
    const target = new URL(url!);
    target.pathname = `/${database}`;
    db = createPgQuerier(target.toString());
    const connection = await db.connect();
    try { await runMigrations(connection); } finally { connection.release(); }
    ctx = { db, rootKek: Buffer.alloc(32, 43) };
    await ensureInstallation(ctx);
    adminId = (await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" })).identityId;
    cli = (await issueCredential(db, { identityId: adminId, kind: "cli" })).token;
    app = buildApp(ctx);
    orgId = (await call("POST", "/v1/organizations", cli, { name: "Acme", slug: "acme" })).body.id;
  });
  afterEach(async () => {
    await db?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
      await admin.end();
    }
  });

  const deferred = () => {
    let resolve!: () => void;
    const promise = new Promise<void>((r) => { resolve = r; });
    return { promise, resolve };
  };
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const twoHoursAgo = () => new Date(Date.now() - 2 * 3600_000);
  const attempt = (operation: WouldBlock["operation"] = "grant.create", actorIdentityId = adminId): WouldBlock => ({
    control: "admin-step-up", configVersion: 1, operation, actorIdentityId, reason: "no-approval",
  });
  const count = (at?: Date, attempts = [attempt()]) => withTx(db, (tx) => countWouldBlock(tx, orgId, attempts, { at }));
  const rows = async () =>
    (await db.query(
      `SELECT operation, actor_identity_id, count::int AS count, emitted_at IS NOT NULL AS emitted,
              bucket_hour = date_trunc('hour', clock_timestamp(), 'UTC') AS current_hour
       FROM security_control_counters ORDER BY operation, actor_identity_id, bucket_hour`,
    )).rows as { operation: string; actor_identity_id: string; count: number; emitted: boolean; current_hour: boolean }[];
  const summaries = async () =>
    (await db.query(
      "SELECT actor_identity_id, metadata FROM audit_events WHERE event_type = 'security_control.would_block' ORDER BY event_order",
    )).rows as { actor_identity_id: string; metadata: { operation: string; count: number; bucketHour: string } }[];
  /** A protected write in the documented order: the Organization, the counter, then the audit insert. */
  const mutation = (at: Date | undefined, onCounted?: () => Promise<void>, attempts = [attempt()]) =>
    withTx(db, async (tx) => {
      await lockLiveScope(tx, { organizationId: orgId });
      await countWouldBlock(tx, orgId, attempts, { at });
      await onCounted?.();
      await recordAuditEvent(tx, { eventType: "group.created", decision: "info", actorIdentityId: adminId, organizationId: orgId });
    });

  it("emits each summary once across concurrent workers and after a worker dies before committing", async () => {
    // 300 closed buckets: one per (actor, operation) two hours ago.
    await db.query(
      `INSERT INTO security_control_counters
         (organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour, count, first_seen, last_seen)
       SELECT $1, 'admin-step-up', 1, 'grant.create', 'idn_' || lpad(n::text, 4, '0'), 'no-approval',
              date_trunc('hour', clock_timestamp() - interval '2 hours', 'UTC'), n, clock_timestamp(), clock_timestamp()
       FROM generate_series(1, 300) AS n`,
      [orgId],
    );
    // A worker that dies holding its rows: nothing it claimed is emitted.
    await expect(emitDueSummaries(ctx, { batch: 50, onClaimed: async () => { throw new Error("killed"); } })).rejects.toThrow("killed");
    expect(await summaries()).toEqual([]);
    // Each worker's first batch waits, holding its rows, until another
    // worker holds a batch too: SKIP LOCKED lets them claim side by side
    // (with a plain FOR UPDATE the second would wait for the first).
    let holding = 0;
    let waitedAlone = false;
    const together = deferred();
    const firstBatch = async () => {
      if (++holding >= 2) together.resolve();
      if (await Promise.race([together.promise.then(() => false), sleep(3000).then(() => true)])) waitedAlone = true;
    };
    const loop = async () => {
      let emitted = await emitDueSummaries(ctx, { batch: 20, onClaimed: firstBatch });
      for (let n = -1; n !== 0; emitted += n) n = await emitDueSummaries(ctx, { batch: 20 });
      return emitted;
    };
    const emitted = await Promise.all([loop(), loop(), loop(), loop()]);
    expect(emitted.reduce((a, b) => a + b, 0)).toBe(300);
    expect(holding).toBe(4);
    expect(waitedAlone).toBe(false);
    const all = await summaries();
    expect(all).toHaveLength(300);
    expect(new Set(all.map((s) => s.actor_identity_id)).size).toBe(300);
    for (const s of all) expect(s.metadata.count).toBe(Number(s.actor_identity_id.slice(4)));
    expect((await rows()).every((r) => r.emitted)).toBe(true);
    // The exclusive pass of the daemon's loop: one process at a time.
    const holder = await db.connect();
    try {
      await holder.query("BEGIN");
      await holder.query("SELECT pg_advisory_xact_lock(7330035)");
      await count(twoHoursAgo(), [attempt("role.create")]);
      expect(await emitDueSummaries(ctx, { exclusive: true })).toBe(0);
      await holder.query("COMMIT");
    } finally {
      holder.release();
    }
    expect(await emitDueSummaries(ctx, { exclusive: true })).toBe(1);
  }, 30_000);

  for (const order of ["counters before audit", "audit before counters (broken)"] as const) {
    it(`an increment for a bucket being emitted, ${order}`, async () => {
      await count(twoHoursAgo(), [attempt(), attempt()]);
      const claimed = deferred();
      const release = deferred();
      const worker = emitDueSummaries(ctx, {
        onClaimed: async () => {
          claimed.resolve();
          await release.promise;
        },
      });
      await claimed.promise;
      let done = false;
      const write =
        order === "counters before audit"
          ? mutation(twoHoursAgo()).then(() => { done = true; })
          : withTx(db, async (tx) => {
              await lockLiveScope(tx, { organizationId: orgId });
              await recordAuditEvent(tx, { eventType: "group.created", decision: "info", actorIdentityId: adminId, organizationId: orgId });
              await countWouldBlock(tx, orgId, [attempt()], { at: twoHoursAgo() });
            }).then(() => { done = true; });
      await sleep(300);
      // It waits for the worker's claim on its bucket.
      expect(done).toBe(false);
      release.resolve();
      const results = await Promise.allSettled([worker, write]);
      if (order === "counters before audit") {
        expect(results.map((r) => r.status)).toEqual(["fulfilled", "fulfilled"]);
        // The summary has the two counts it closed with; the late one is in the current hour.
        expect((await summaries()).map((s) => s.metadata.count)).toEqual([2]);
        expect((await rows()).map((r) => [r.count, r.emitted, r.current_hour])).toEqual([[2, true, false], [1, false, true]]);
      } else {
        // The worker holds the bucket and waits for the audit counter; the
        // write holds the counter and waits for the bucket.
        const failed = results.filter((r): r is PromiseRejectedResult => r.status === "rejected");
        expect(failed.map((r) => (r.reason as { code?: string }).code)).toEqual(["40P01"]);
      }
    }, 20_000);
  }

  it("under SERIALIZABLE, retries the whole mutation and counts the late increment once", { timeout: 30_000 }, async () => {
    await count(twoHoursAgo(), [attempt()]);
    let attempts = 0;
    await withSerializableTx(db, async (tx) => {
      attempts++;
      // The transaction's snapshot starts here.
      await tx.query("SELECT count(*) FROM security_control_counters");
      // Meanwhile, the first time, the worker emits the bucket and commits.
      if (attempts === 1) expect(await emitDueSummaries(ctx)).toBe(1);
      await lockLiveScope(tx, { organizationId: orgId });
      await countWouldBlock(tx, orgId, [attempt()], { at: twoHoursAgo() });
      await recordAuditEvent(tx, { eventType: "group.created", decision: "info", actorIdentityId: adminId, organizationId: orgId });
    });
    expect(attempts).toBe(2);
    expect((await summaries()).map((s) => s.metadata.count)).toEqual([1]);
    expect((await rows()).map((r) => [r.count, r.emitted, r.current_hour])).toEqual([[1, true, false], [1, false, true]]);
  });

  it("counts a member's removal (a SERIALIZABLE write) once, when it commits", { timeout: 30_000 }, async () => {
    const grant = await issueInviteGrant(ctx, { organizationId: orgId, role: "member", name: "Bob" }, adminId);
    const bob = (await consumeSetupGrant(ctx, grant.token, {})).identityId;
    expect((await call("PATCH", "/v1/organizations/acme/security/controls/admin-step-up", cli, { mode: "report", expectedVersion: 0 })).status).toBe(200);
    const removals = await Promise.all([1, 2, 3].map(() => call("DELETE", `/v1/organizations/acme/members/${bob}`, cli)));
    // One removal commits; the others find no membership left (or give up), and count nothing.
    expect(removals.filter((r) => r.status === 200)).toHaveLength(1);
    expect(removals.every((r) => r.status === 200 || r.status >= 400)).toBe(true);
    expect((await rows()).map((r) => [r.operation, r.count])).toEqual([["member.remove", 1]]);
  });

  describe("access counts are off the response path", () => {
    const passkeyRows = async () =>
      (await db.query("SELECT operation, count::int AS count FROM security_control_counters WHERE control = 'passkey-verification'")).rows as {
        operation: string; count: number;
      }[];
    const report = (): PendingAccessReport => ({
      organizationId: orgId, actorIdentityId: adminId, configVersion: 1, reason: "no-evidence", at: new Date(),
    });
    let stateDir: string;
    beforeEach(async () => {
      expect((await call("PATCH", "/v1/organizations/acme/security/controls/passkey-verification", cli, { mode: "report", expectedVersion: 0 })).status).toBe(200);
      await accessCountsSettled();
      stateDir = mkdtempSync(join(tmpdir(), "varlatch-access-counts-"));
    });
    afterEach(async () => {
      accessCountHooks.beforeCount = undefined;
      await accessCountsSettled();
      rmSync(stateDir, { recursive: true, force: true });
    });

    /** Hold `lock` in a transaction of its own until released. */
    const holding = async (lock: (tx: Awaited<ReturnType<typeof db.connect>>) => Promise<unknown>) => {
      const tx = await db.connect();
      await tx.query("BEGIN");
      await lock(tx);
      return async () => {
        await tx.query("COMMIT");
        tx.release();
      };
    };
    const read = async (on = app) => {
      const res = await on.request("/v1/organizations/acme", { headers: { Authorization: `Bearer ${cli}` } });
      await res.text();
      return res.status;
    };

    it("the response completes while its count is held back, and maintenance drains the count", { timeout: 30_000 }, async () => {
      const maintenance = new Maintenance(stateDir);
      const withMaintenance = { ...ctx, maintenance };
      const barrier = deferred();
      const started = deferred();
      accessCountHooks.beforeCount = async () => {
        started.resolve();
        await barrier.promise;
      };
      // The response arrives while the count cannot run.
      expect(await read(buildApp(withMaintenance))).toBe(200);
      await started.promise;
      expect(await passkeyRows()).toEqual([]);
      // The count holds maintenance admission: a capture's drain waits for it.
      expect(maintenance.busy).toBe(1);
      const gate = maintenance.beginCapture(60_000);
      await sleep(200);
      expect(maintenance.busy).toBe(1);
      barrier.resolve();
      await accessCountsSettled();
      expect(maintenance.busy).toBe(0);
      expect(await passkeyRows()).toEqual([{ operation: "organization.read", count: 1 }]);
      maintenance.finishCapture(gate.id);
    });

    it("a count queued while maintenance admission is closed is dropped, writing nothing", async () => {
      const maintenance = new Maintenance(stateDir);
      const gate = maintenance.beginCapture(60_000);
      let ran = false;
      accessCountHooks.beforeCount = async () => { ran = true; };
      queueAccessCount({ ...ctx, maintenance }, report(), "organization.read");
      await accessCountsSettled();
      expect(ran).toBe(false);
      expect(maintenance.busy).toBe(0);
      expect(await passkeyRows()).toEqual([]);
      maintenance.finishCapture(gate.id);
      // Admission open again: it counts.
      queueAccessCount({ ...ctx, maintenance }, report(), "organization.read");
      await accessCountsSettled();
      expect(await passkeyRows()).toEqual([{ operation: "organization.read", count: 1 }]);
    });

    it("a count whose maintenance admission throws is dropped, with no unhandled rejection", async () => {
      const unhandled: unknown[] = [];
      const onUnhandled = (reason: unknown) => { unhandled.push(reason); };
      process.on("unhandledRejection", onUnhandled);
      try {
        const throwing = {
          enter: () => { throw new Error("maintenance state unreadable"); },
          busy: 0,
        } as unknown as Maintenance;
        let ran = false;
        accessCountHooks.beforeCount = async () => { ran = true; };
        queueAccessCount({ ...ctx, maintenance: throwing }, report(), "organization.read");
        await accessCountsSettled();
        // Let any stray rejection surface before checking.
        await new Promise((resolve) => setImmediate(resolve));
        await new Promise((resolve) => setImmediate(resolve));
        expect(ran).toBe(false);
        expect(unhandled).toEqual([]);
        expect(await passkeyRows()).toEqual([]);
      } finally {
        process.off("unhandledRejection", onUnhandled);
      }
    });

    it("drops the count after the lock timeout while the Organization row or the counter row is locked", { timeout: 60_000 }, async () => {
      for (const lock of [
        (tx: Awaited<ReturnType<typeof db.connect>>) => tx.query("SELECT 1 FROM organizations WHERE id = $1 FOR UPDATE", [orgId]),
        // Another transaction counting the same bucket, not committed yet.
        (tx: Awaited<ReturnType<typeof db.connect>>) => countWouldBlock(tx, orgId, [{
          control: "passkey-verification", configVersion: 1, operation: "organization.read", actorIdentityId: adminId, reason: "no-evidence",
        }]),
      ]) {
        const release = await holding(lock);
        try {
          expect(await read()).toBe(200);
          const settling = Date.now();
          await accessCountsSettled();
          // Bounded by the lock and statement timeouts, the lock still held.
          expect(Date.now() - settling).toBeLessThan(20_000);
        } finally {
          await release();
        }
      }
      // Only the other transaction's count: both of these were dropped.
      expect(await passkeyRows()).toEqual([{ operation: "organization.read", count: 1 }]);
    });

    it("never has more connection requests waiting than counts may run at once", { timeout: 60_000 }, async () => {
      const target = new URL(url!);
      target.pathname = `/${database}`;
      // The daemon's arrangement: a pool of `concurrency` connections with an acquisition timeout.
      const pool = createPgQuerier(target.toString(), { max: ACCESS_COUNTS.concurrency, connectionTimeoutMillis: 500 });
      const held = await Promise.all(Array.from({ length: ACCESS_COUNTS.concurrency }, () => pool.connect()));
      let most = 0;
      let sampling = true;
      const sampler = (async () => {
        while (sampling) {
          most = Math.max(most, pool.stats().waiting);
          await sleep(5);
        }
      })();
      try {
        for (let i = 0; i < 20; i++) queueAccessCount({ ...ctx, accessCountDb: pool }, report(), "organization.read");
        await accessCountsSettled();
        expect(pool.stats().waiting).toBe(0);
      } finally {
        sampling = false;
        await sampler;
        for (const c of held) c.release();
      }
      expect(most).toBeGreaterThan(0);
      expect(most).toBeLessThanOrEqual(ACCESS_COUNTS.concurrency);
      // Every one timed out waiting for a connection: none counted.
      expect(await passkeyRows()).toEqual([]);
      await pool.end();

      // Without a pool of its own (ctx.db), a job keeps its slot until its
      // acquisition settles, so no more than `concurrency` wait either.
      const exhausted = await Promise.all(Array.from({ length: 10 }, () => db.connect()));
      most = 0;
      sampling = true;
      const sampler2 = (async () => {
        while (sampling) {
          most = Math.max(most, db.stats().waiting);
          await sleep(5);
        }
      })();
      for (let i = 0; i < 20; i++) queueAccessCount(ctx, report(), "organization.read");
      await sleep(500);
      expect(accessCountsPending()).toEqual({ running: ACCESS_COUNTS.concurrency, waiting: 20 - ACCESS_COUNTS.concurrency });
      for (const c of exhausted) c.release();
      await accessCountsSettled();
      sampling = false;
      await sampler2;
      expect(most).toBeLessThanOrEqual(ACCESS_COUNTS.concurrency);
      expect(await passkeyRows()).toEqual([{ operation: "organization.read", count: 20 }]);
    });
  });

  it("an export whose Organization is deleted after its snapshot discloses, and counts nothing", { timeout: 30_000 }, async () => {
    const P = "/v1/organizations/acme/projects/api";
    expect((await call("POST", "/v1/organizations/acme/projects", cli, { name: "API", slug: "api", contractAuthority: "managed" })).status).toBe(201);
    expect((await call("POST", `${P}/environments`, cli, { name: "production", tier: "production" })).status).toBe(201);
    const revision = (await call("POST", `${P}/contract/revisions`, cli, {
      contract: { schemaVersion: 1, items: [{ name: "DB_PASS", required: { kind: "never" }, sensitive: true, type: "string" }] },
    })).body;
    await call("POST", `${P}/contract/revisions/${revision.id}/activate`, cli, {});
    expect((await call("PUT", `${P}/environments/production/values/DB_PASS`, cli, { value: "hunter2-hunter2" })).status).toBe(200);
    expect((await call("PATCH", "/v1/organizations/acme/security/controls/admin-step-up", cli, { mode: "report", expectedVersion: 0 })).status).toBe(200);
    const exportOnce = async () => {
      // The export's snapshot, and what it decided there.
      const { state, at } = await inSnapshot(ctx, async (sctx, now) => {
        const org = await getOrganization(sctx, "acme");
        const project = await getProject(sctx, org.id, "api");
        const env = await getEnvironment(sctx, project.id, "production");
        return { state: await captureState(sctx, { org, project, env }, now, () => true), at: now };
      });
      return () => discloseSecrets(ctx, state, { scope: "all-authorized-secrets", purpose: "export" }, {
        actorIdentityId: adminId,
        report: { attempts: [attempt("secret.export")], at },
      });
    };
    // Live: counted with the disclosure.
    expect((await (await exportOnce())()).items.map((i) => i.value)).toEqual(["hunter2-hunter2"]);
    expect((await rows()).map((r) => [r.operation, r.count])).toEqual([["secret.export", 1]]);

    // Deleted after the snapshot: the deletion holds the Organization row,
    // removes its counters and commits while the export waits for the row.
    const disclose = await exportOnce();
    const deletion = await db.connect();
    await deletion.query("BEGIN");
    await deletion.query("SELECT 1 FROM organizations WHERE id = $1 FOR UPDATE", [orgId]);
    let done = false;
    const exported = disclose().then((r) => { done = true; return r; });
    await sleep(300);
    expect(done).toBe(false);
    await deletion.query("DELETE FROM security_control_counters WHERE organization_id = $1", [orgId]);
    await deletion.query("UPDATE organizations SET deleted_at = now(), wrapped_org_kek = NULL, org_kek_destroyed_at = now() WHERE id = $1", [orgId]);
    await deletion.query("COMMIT");
    deletion.release();
    // The authorized disclosure completes; nothing is counted after the deletion.
    expect((await exported).items.map((i) => i.value)).toEqual(["hunter2-hunter2"]);
    expect(await rows()).toEqual([]);
    expect(await emitDueSummaries(ctx)).toBe(0);
  });

  it("mutations and workers running together lose and double nothing, and never deadlock", async () => {
    const actors = ["idn_a", "idn_b", "idn_c"];
    const operations = ["grant.create", "role.create", "group.create"] as const;
    // Closed buckets for every pair, so workers and writes meet on them.
    for (const actor of actors) await count(twoHoursAgo(), operations.map((op) => attempt(op, actor)));
    const seeded = actors.length * operations.length;
    let writes = 0;
    let stop = false;
    const writer = async (i: number) => {
      for (let n = 0; n < 15; n++) {
        // Several counters per transaction, given in different orders: counted in key order.
        const mine = [attempt(operations[(i + n) % 3], actors[n % 3]), attempt(operations[(i + n + 1) % 3], actors[(n + 1) % 3])];
        await mutation(twoHoursAgo(), undefined, n % 2 ? mine : mine.reverse());
        writes += 2;
      }
    };
    const worker = async () => {
      while (!stop) {
        await emitDueSummaries(ctx, { batch: 2 });
        await sleep(1);
      }
    };
    const workers = [worker(), worker(), worker()];
    await Promise.all([writer(0), writer(1), writer(2), writer(3), writer(4)]);
    stop = true;
    await Promise.all(workers);
    while ((await emitDueSummaries(ctx)) > 0);
    const all = await rows();
    expect(all.reduce((n, r) => n + r.count, 0)).toBe(seeded + writes);
    const summarized = (await summaries()).reduce((n, s) => n + s.metadata.count, 0);
    expect(summarized).toBe(all.filter((r) => r.emitted).reduce((n, r) => n + r.count, 0));
    expect(all.filter((r) => !r.emitted).every((r) => r.current_hour)).toBe(true);
  }, 60_000);
});
