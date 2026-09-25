// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import { ensureInstallation, issueBootstrapGrant, consumeSetupGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { issueCredential } from "../src/auth/credentials.js";
import { buildApp } from "../src/http/app.js";
import { recordAuditEvent } from "../src/audit/events.js";
import { deliverWebhooksOnce } from "../src/domain/webhooks.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { completeEnrollment, enrollmentUser } from "../src/auth/humanauth.js";

// Always run in CI against a disposable database; never use an installation DB.
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("real PostgreSQL concurrency and cursors", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let app: ReturnType<typeof buildApp>;
  let token: string, identityId: string, orgId: string;
  const database = `varlatch_test_${process.pid}`;
  const base = "/v1/organizations/test/projects/api/environments/dev";
  const request = async (method: string, path: string, body?: unknown, bearer = token, extra = {}) => {
    const res = await app.request(path, { method,
      headers: { Authorization: `Bearer ${bearer}`, "Content-Type": "application/json", ...extra },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: res.status, body: await res.json().catch(() => null) };
  };
  beforeEach(async () => {
    admin = createPgQuerier(url!);
    await admin.query(`CREATE DATABASE ${database}`);
    const target = new URL(url!); target.pathname = `/${database}`;
    db = createPgQuerier(target.toString());
    const connection = await db.connect();
    try { await runMigrations(connection); } finally { connection.release(); }
    ctx = { db, rootKek: Buffer.alloc(32, 17) };
    await ensureInstallation(ctx);
    const setup = await issueBootstrapGrant(ctx);
    identityId = (await consumeSetupGrant(ctx, setup.token, {})).identityId;
    token = (await issueCredential(db, { identityId, kind: "cli" })).token;
    app = buildApp(ctx);
    orgId = (await request("POST", "/v1/organizations", { slug: "test", name: "Test" })).body.id;
    await request("POST", "/v1/organizations/test/projects", { slug: "api", name: "API", contractAuthority: "managed" });
    await request("POST", "/v1/organizations/test/projects/api/environments", { name: "dev", tier: "development" });
  });
  afterEach(async () => {
    await db?.end();
    if (admin) { await admin.query(`DROP DATABASE IF EXISTS ${database}`); await admin.end(); }
  });
  it("consumes an invitation exactly once and preserves rejection audit", async () => {
    const invite = await issueInviteGrant(ctx, { organizationId: orgId, name: "Human", role: "admin" }, identityId);
    const results = await Promise.allSettled(Array.from({ length: 8 }, () => consumeSetupGrant(ctx, invite.token, {})));
    expect(results.filter(r => r.status === "fulfilled")).toHaveLength(1);
    expect((await db.query("SELECT id FROM audit_events WHERE event_type='setup.grant_rejected'")).rows).toHaveLength(7);
  });
  it("completes one passkey enrollment per grant under racing verifications (#23)", async () => {
    const invite = await issueInviteGrant(ctx, { organizationId: orgId, name: "Racer", role: "member" }, identityId);
    const { id } = await enrollmentUser(ctx, invite.token);
    const results = await Promise.allSettled(Array.from({ length: 8 }, () => completeEnrollment(ctx, id, invite.token)));
    expect(results.filter(r => r.status === "fulfilled")).toHaveLength(1);
    expect((await db.query("SELECT id FROM identities WHERE name = 'Racer'")).rows).toHaveLength(1);
    expect((await db.query("SELECT a.identity_id FROM auth_user_links a JOIN identities i ON i.id = a.identity_id WHERE i.name = 'Racer'")).rows).toHaveLength(1);
  });
  it("exchanges a browser bearer exactly once", async () => {
    const browser = await issueCredential(db, { identityId, kind: "browser" });
    const results = await Promise.all(Array.from({ length: 8 }, () => request("POST", "/v1/me/credentials/cli", {}, browser.token)));
    expect(results.filter(r => r.status === 201)).toHaveLength(1);
    expect(results.filter(r => r.status === 401)).toHaveLength(7);
  });
  it("rejects simultaneous writes to one expected version", async () => {
    const initial = await request("PUT", `${base}/values/KEY`, { value: "initial" });
    const results = await Promise.all(Array.from({ length: 8 }, (_, i) => request("PUT", `${base}/values/KEY`, {
      value: `value-${i}`, expectedVersionId: initial.body.versionId,
    })));
    expect(results.filter(r => r.status === 200)).toHaveLength(1);
    expect(results.filter(r => r.body.error?.code === "VERSION_CONFLICT")).toHaveLength(7);
  });
  it("commits only one of concurrent reviewed change sets", async () => {
    const initial = await request("PUT", `${base}/values/KEY`, { value: "initial" });
    const results = await Promise.all(Array.from({ length: 8 }, (_, i) => request("POST", `${base}/changes`, {
      changes: [{ op: "set", item: "KEY", value: `value-${i}`, expectedVersionId: initial.body.versionId }],
    })));
    expect(results.filter(r => r.status === 200)).toHaveLength(1);
    expect(results.filter(r => r.body.error?.code === "VERSION_CONFLICT")).toHaveLength(7);
  });
  it("starts only one concurrent rotation", async () => {
    const initial = await request("PUT", `${base}/values/KEY`, { value: "initial" });
    const results = await Promise.all(Array.from({ length: 8 }, (_, i) => request("POST", `${base}/values/KEY/rotations`, {
      value: `value-${i}`, expectedVersionId: initial.body.versionId,
    })));
    expect(results.filter(r => r.status === 201)).toHaveLength(1);
    expect(results.filter(r => r.body.error?.code === "ROTATION_IN_PROGRESS")).toHaveLength(7);
  });
  it("serializes duplicate idempotent writes without storing guessable hashes", async () => {
    const results = await Promise.all(Array.from({ length: 8 }, () => request("PUT", `${base}/values/PIN`, { value: "1234" }, token, { "Idempotency-Key": "same" })));
    expect(results.every(r => r.status === 200)).toBe(true);
    expect(new Set(results.map(r => r.body.versionId)).size).toBe(1);
    const hashes = await db.query("SELECT body_hash FROM idempotency_keys");
    expect((hashes.rows[0] as { body_hash: string }).body_hash).toMatch(/^hmac-v1:/);
  });
  it("retains microseconds when paging audit events", async () => {
    await db.query(`INSERT INTO audit_events(id,event_type,organization_id,decision,occurred_at)
      VALUES ('page_a','test',$1,'info','2030-01-01 00:00:00.123456Z'),
             ('page_b','test',$1,'info','2030-01-01 00:00:00.123455Z')`, [orgId]);
    const first = await request("GET", "/v1/organizations/test/audit-events?limit=1");
    const second = await request("GET", `/v1/organizations/test/audit-events?limit=1&cursor=${encodeURIComponent(first.body.nextCursor)}`);
    expect(first.body.items[0].eventId).toBe("page_a");
    expect(second.body.items[0].eventId).toBe("page_b");
  });
  it("cannot advance delivery past an uncommitted audit event", async () => {
    await request("POST", "/v1/organizations/test/webhooks", { url: "https://example.invalid/hook", eventTypes: ["test.slow", "test.fast"] });
    const slow = await db.connect();
    const delivered: string[] = [];
    const receiver = (async (_url: unknown, opts: RequestInit) => {
      delivered.push(...JSON.parse(String(opts.body)).events.map((e: { eventType: string }) => e.eventType));
      return new Response(null, { status: 200 });
    }) as typeof fetch;
    await slow.query("BEGIN");
    try {
      await recordAuditEvent(slow, { eventType: "test.slow", decision: "info", organizationId: orgId });
      const fast = recordAuditEvent(db, { eventType: "test.fast", decision: "info", organizationId: orgId });
      await deliverWebhooksOnce(ctx, receiver);
      expect(delivered).toEqual([]);
      await slow.query("COMMIT");
      await fast;
      await deliverWebhooksOnce(ctx, receiver);
      await deliverWebhooksOnce(ctx, receiver);
      expect(delivered).toEqual(["test.slow", "test.fast"]);
    } finally { await slow.query("ROLLBACK"); slow.release(); }
  });
});
