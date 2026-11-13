// SPDX-License-Identifier: AGPL-3.0-or-later
import { createServer, type Server } from "node:http";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  abandonExpiredDrains,
  commitPlan,
  createAuditExport,
  exportOnce,
  recordRestore,
  restartStream,
  setAuditExportTestHooks,
  type PlanRow,
  type WorkerBinding,
} from "../src/domain/auditexport.js";
import { createOrganization } from "../src/domain/orgs.js";
import { OutboundPolicy } from "../src/net/outbound.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";

/**
 * The audit export's fenced transactions racing on real PostgreSQL
 * (ADR-0056 Decisions 2, 3 and 5): two processes restarting one expired
 * plan restart it once and audit it once; a commit racing a restart either
 * lands before it or is refused; a restore racing a restart and the drain
 * deadline finishes without a deadlock. No object store: these
 * transactions send nothing (audit-export.test.ts covers the uploads
 * against MinIO).
 */

const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("audit export races on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let orgId: string;
  let identityId: string;
  const database = `varlatch_audit_export_test_${process.pid}`;

  const rows = async (sql: string, params: unknown[] = []) => (await db.query(sql, params)).rows as any[];

  /** An export with a pending batch plan whose retention ends within the hour. */
  async function exportWithExpiredPlan(id: string, state: "active" | "draining" = "active") {
    await db.query(
      `INSERT INTO audit_exports (id, organization_id, endpoint, region, bucket, prefix, path_style, credential_envelope,
         retention_mode, retention_days, stream_id, stream_started_at, cursor_order, state, created_by, drain_deadline)
       VALUES ($1, $2, 'https://s3.example.com', 'us-east-1', 'audit-bucket', '', true, '{"k":1}'::jsonb,
         'governance', 1, 'aes_old', now(), 0, $4, $3, CASE WHEN $4 = 'draining' THEN now() - interval '1 second' END)`,
      [id, orgId, identityId, state],
    );
    await db.query(
      `INSERT INTO audit_export_plans (id, export_id, export_version, stream_id, generation, kind, object_name, body, sha256, md5,
         content_type, format_version, retention_mode, retain_until, first_order, last_order, event_count, planned_at)
       VALUES ($1, $2, 1, 'aes_old', 0, 'batch', 'x', '\\x00', repeat('a', 64), repeat('b', 32), 'application/gzip', 1,
         'governance', now() + interval '10 minutes', 1, 5, 5, now() - interval '2 days')`,
      [`aep_${id}`, id],
    );
    return (await rows("SELECT * FROM audit_export_plans WHERE export_id = $1", [id]))[0] as PlanRow;
  }

  beforeEach(async () => {
    admin = createPgQuerier(url!);
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${database}`);
    const target = new URL(url!);
    target.pathname = `/${database}`;
    db = createPgQuerier(target.toString());
    const connection = await db.connect();
    try { await runMigrations(connection); } finally { connection.release(); }
    ctx = { db, rootKek: Buffer.alloc(32, 48) };
    await ensureInstallation(ctx);
    identityId = (await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" })).identityId;
    orgId = "org_acme";
    await db.query("INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ($1, 'acme', 'Acme', '{}')", [orgId]);
  });
  afterEach(async () => {
    await db?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
      await admin.end();
    }
  });

  it("two processes restart an expired plan once, and audit it once", async () => {
    const plan = await exportWithExpiredPlan("aex_1");
    const results = await Promise.all(Array.from({ length: 4 }, () => restartStream(ctx, "aex_1", plan.id, "plan_expired")));
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await rows("SELECT metadata->>'reason' AS reason FROM audit_events WHERE event_type = 'audit_export.stream_started'")).toEqual([{ reason: "plan_expired" }]);
    const row = (await rows("SELECT stream_id, cursor_order::text AS cursor, generation::int AS g FROM audit_exports WHERE id = 'aex_1'"))[0];
    expect(row).toMatchObject({ cursor: "0", g: 1 });
    expect(row.stream_id).not.toBe("aes_old");
    expect(await rows("SELECT kind FROM audit_export_plans WHERE export_id = 'aex_1'")).toEqual([{ kind: "manifest" }]);
  });

  it("a commit racing a restart lands before it or is refused, never both", async () => {
    for (let i = 0; i < 5; i++) {
      const id = `aex_c${i}`;
      const plan = await exportWithExpiredPlan(id);
      const binding: WorkerBinding = { exportId: id, organizationId: orgId, generation: "0", version: 1, streamId: "aes_old" };
      const [committed, restarted] = await Promise.all([
        commitPlan(ctx, binding, plan, null).then((r) => r === "committed"),
        restartStream(ctx, id, plan.id, "plan_expired"),
      ]);
      expect(committed !== restarted, `round ${i}`).toBe(true);
      const row = (await rows("SELECT cursor_order::text AS cursor, stream_id FROM audit_exports WHERE id = $1", [id]))[0];
      expect(row.cursor).toBe(committed ? "5" : "0");
      expect(row.stream_id === "aes_old").toBe(committed);
      await db.query("UPDATE audit_exports SET state = 'removed', removed_at = now(), credential_envelope = NULL WHERE id = $1", [id]);
    }
  });

  it("the deletion loop and two workers racing on one expired drain abandon it once", async () => {
    for (let i = 0; i < 5; i++) {
      const id = `aex_d${i}`;
      await db.query(`INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ($1, $2, 'D', '{}')`, [`org_d${i}`, `d${i}`]);
      orgId = `org_d${i}`;
      await exportWithExpiredPlan(id, "draining");
      const outcomes = await Promise.all([
        abandonExpiredDrains(db).then((ids) => (ids.includes(id) ? "abandoned" : "none")),
        exportOnce(ctx, id).then((r) => r.outcome),
        exportOnce(ctx, id).then((r) => r.outcome),
        abandonExpiredDrains(db).then((ids) => (ids.includes(id) ? "abandoned" : "none")),
      ]);
      expect(outcomes.filter((o) => o === "abandoned"), `round ${i}: ${outcomes.join(", ")}`).toHaveLength(1);
      expect(await rows("SELECT state, credential_envelope FROM audit_exports WHERE id = $1", [id])).toEqual([{ state: "abandoned", credential_envelope: null }]);
      expect(await rows("SELECT count(*)::int AS n FROM audit_export_plans WHERE export_id = $1", [id])).toEqual([{ n: 0 }]);
      expect(await rows("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'audit_export.abandoned' AND resource->>'exportId' = $1", [id])).toEqual([{ n: 1 }]);
    }
  });

  it("a worker that leased before the deadline commits while the deletion loop runs: the loop skips the locked row, the commit abandons it, once", async () => {
    // The worker's binding was taken before the deadline; the deadline passes before it commits.
    const plan = await exportWithExpiredPlan("aex_w", "draining");
    const binding: WorkerBinding = { exportId: "aex_w", organizationId: orgId, generation: "0", version: 1, streamId: "aes_old" };
    let swept: string[] | null = null;
    setAuditExportTestHooks({
      // The commit holds the export row FOR UPDATE: the loop's SKIP LOCKED passes it by.
      whileCommitLocked: async () => {
        swept = await abandonExpiredDrains(db);
      },
    });
    try {
      expect(await commitPlan(ctx, binding, plan, null)).toBe("abandoned");
    } finally {
      setAuditExportTestHooks(null);
    }
    expect(swept).toEqual([]);
    expect(await abandonExpiredDrains(db)).toEqual([]);
    expect(await rows("SELECT state, credential_envelope, cursor_order::text AS cursor FROM audit_exports WHERE id = 'aex_w'"))
      .toEqual([{ state: "abandoned", credential_envelope: null, cursor: "0" }]);
    expect(await rows("SELECT count(*)::int AS n FROM audit_export_plans WHERE export_id = 'aex_w'")).toEqual([{ n: 0 }]);
    expect(await rows("SELECT event_type FROM audit_events WHERE event_type LIKE 'audit_export.%' AND resource->>'exportId' = 'aex_w'"))
      .toEqual([{ event_type: "audit_export.abandoned" }]);
  });

  it("a commit and the deletion loop racing on an expired drain, unforced: one abandons it, never both, never a completion", async () => {
    for (let i = 0; i < 5; i++) {
      const id = `aex_r${i}`;
      await db.query(`INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ($1, $2, 'R', '{}')`, [`org_r${i}`, `r${i}`]);
      orgId = `org_r${i}`;
      const plan = await exportWithExpiredPlan(id, "draining");
      const binding: WorkerBinding = { exportId: id, organizationId: orgId, generation: "0", version: 1, streamId: "aes_old" };
      const [committed, swept] = await Promise.all([commitPlan(ctx, binding, plan, null), abandonExpiredDrains(db)]);
      // The loop first: the commit finds its binding gone. The commit first: it abandons, and the loop skips or finds nothing.
      const outcome = `round ${i}: commit ${committed}, loop [${swept.join(",")}]`;
      if (committed === "abandoned") expect(swept, outcome).toEqual([]);
      else expect({ committed, swept }, outcome).toEqual({ committed: "lost", swept: [id] });
      expect(await rows("SELECT event_type FROM audit_events WHERE event_type LIKE 'audit_export.%' AND resource->>'exportId' = $1", [id]))
        .toEqual([{ event_type: "audit_export.abandoned" }]);
    }
  });

  it("two creations at once: both probe, one export is created, the other answers export-exists, not an error", async () => {
    // A store that honours If-None-Match and refuses reads (a write-only key).
    const seen = new Set<string>();
    const server: Server = createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        const key = (req.url ?? "").split("?")[0]!;
        if (req.method === "PUT" && !seen.has(key)) {
          seen.add(key);
          res.writeHead(200, { ETag: '"0"' });
          res.end();
          return;
        }
        res.writeHead(req.method === "PUT" ? 412 : 403, { "content-type": "application/xml" });
        res.end(req.method === "HEAD" ? undefined : `<?xml version="1.0"?><Error><Code>${req.method === "PUT" ? "PreconditionFailed" : "AccessDenied"}</Code></Error>`);
      });
    });
    await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));
    try {
      const endpoint = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
      const cctx: AppCtx = { ...ctx, outbound: new OutboundPolicy("127.0.0.1/32:*") };
      const org = await createOrganization(cctx, { slug: "duo", name: "Duo" }, identityId);
      const credentialId = (await rows("SELECT id FROM credentials WHERE identity_id = $1 LIMIT 1", [identityId]))[0]?.id ?? "crd_none";
      const requester = { identityId, identityKind: "human", credentialId, credentialKind: "cli" } as const;
      // Both pass their probe before either writes.
      let arrived = 0;
      let release!: () => void;
      const together = new Promise<void>((done) => (release = done));
      setAuditExportTestHooks({
        afterCreateProbe: async () => {
          if (++arrived === 2) release();
          await together;
        },
      });
      const input = {
        destination: { endpoint, region: "us-east-1", bucket: "audit-bucket", prefix: "", pathStyle: true },
        credential: { accessKeyId: "AKIADUO", secretAccessKey: "duo-secret-duo" },
        retention: null,
        from: "now" as const,
      };
      const outcomes = await Promise.allSettled([createAuditExport(cctx, requester, org, input), createAuditExport(cctx, requester, org, input)]);
      expect(arrived).toBe(2);
      expect(outcomes.filter((o) => o.status === "fulfilled")).toHaveLength(1);
      const refused = outcomes.find((o) => o.status === "rejected") as PromiseRejectedResult;
      expect(refused.reason).toMatchObject({ code: "VALIDATION_FAILED", details: { reason: "export-exists" } });
      expect(await rows("SELECT state FROM audit_exports WHERE organization_id = $1", [org.id])).toEqual([{ state: "active" }]);
      expect(await rows("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'audit_export.created' AND organization_id = $1", [org.id])).toEqual([{ n: 1 }]);
    } finally {
      setAuditExportTestHooks(null);
      await new Promise<void>((done) => { server.closeAllConnections(); server.close(() => done()); });
    }
  });

  it("a restore, a restart and the drain deadline race without a deadlock", async () => {
    const a = await exportWithExpiredPlan("aex_a");
    await db.query("INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_b', 'b', 'B', '{}')");
    orgId = "org_b";
    await exportWithExpiredPlan("aex_b", "draining");
    await Promise.all([
      recordRestore(db, { eventType: "installation.restored", decision: "info", metadata: { archiveId: "x" } }),
      restartStream(ctx, "aex_a", a.id, "plan_expired"),
      abandonExpiredDrains(db),
    ]);
    const states = await rows("SELECT id, state FROM audit_exports ORDER BY id");
    expect(states.find((s) => s.id === "aex_a")?.state).toBe("active");
    expect(["draining", "abandoned"]).toContain(states.find((s) => s.id === "aex_b")?.state);
    expect(await rows("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'installation.restored'")).toEqual([{ n: 1 }]);
  });
});
