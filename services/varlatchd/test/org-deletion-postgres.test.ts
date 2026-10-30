// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { runMigrations } from "../src/db/migrate.js";
import { createPgQuerier } from "../src/db/pg.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { finalizeDeletion } from "../src/domain/orgdeletion.js";
import { buildApp } from "../src/http/app.js";

/**
 * Organization deletion under real concurrency (ADR-0051 Decisions 1, 5
 * and 6): scheduling waits for writers in progress and later writers see
 * the freeze; two workers never run one deletion twice.
 */

// Always run in CI against a disposable database; never use an installation DB.
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("organization deletion on real PostgreSQL", () => {
  let server: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let app: ReturnType<typeof buildApp>;
  let adminId: string;
  let token: string;
  let orgId: string;
  const database = `varlatch_orgdel_${process.pid}`;
  const ORG = "/v1/organizations/test";
  const DEV = `${ORG}/projects/api/environments/development`;

  const call = async (method: string, path: string, body?: unknown) => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    return { status: res.status, body: await res.json().catch(() => null) };
  };

  let gate: { pattern: RegExp; reached: () => void; wait: Promise<void> } | null = null;
  const pauseAt = (pattern: RegExp) => {
    let release!: () => void;
    let reached!: () => void;
    const wait = new Promise<void>((r) => (release = r));
    const arrived = new Promise<void>((r) => (reached = r));
    gate = { pattern, reached, wait };
    return { arrived, release };
  };
  const gated = (pool: ReturnType<typeof createPgQuerier>): ReturnType<typeof createPgQuerier> => ({
    query: (text, params) => pool.query(text, params),
    end: () => pool.end(),
    connect: async () => {
      const client = await pool.connect();
      return {
        release: (destroy?: boolean) => client.release(destroy),
        query: async (text: string, params?: unknown[]) => {
          const g = gate;
          if (g && g.pattern.test(text)) {
            gate = null;
            g.reached();
            await g.wait;
          }
          return client.query(text, params);
        },
      };
    },
  });
  const settled = async <T>(p: Promise<T>, ms: number) =>
    Promise.race([p.then(() => true), new Promise<boolean>((r) => setTimeout(() => r(false), ms))]);

  beforeEach(async () => {
    server = createPgQuerier(url!);
    await server.query(`CREATE DATABASE ${database}`);
    const target = new URL(url!);
    target.pathname = `/${database}`;
    db = createPgQuerier(target.toString());
    const connection = await db.connect();
    try {
      await runMigrations(connection);
    } finally {
      connection.release();
    }
    gate = null;
    ctx = { db: gated(db), rootKek: Buffer.alloc(32, 3) };
    await ensureInstallation(ctx);
    const setup = await issueBootstrapGrant(ctx);
    adminId = (await consumeSetupGrant(ctx, setup.token, {})).identityId;
    token = (await issueCredential(db, { identityId: adminId, kind: "cli" })).token;
    app = buildApp(ctx);
    orgId = (await call("POST", "/v1/organizations", { slug: "test", name: "Test" })).body.id;
    await call("POST", `${ORG}/projects`, { slug: "api", name: "API", contractAuthority: "managed" });
    await call("POST", `${ORG}/projects/api/environments`, { name: "development", tier: "development" });
    const revision = await call("POST", `${ORG}/projects/api/contract/revisions`, {
      contract: { schemaVersion: 1, items: [{ name: "TOKEN", required: { kind: "never" }, sensitive: true, type: "string" }] },
    });
    await call("POST", `${ORG}/projects/api/contract/revisions/${revision.body.id}/activate`, {});
    expect((await call("PUT", `${DEV}/values/TOKEN`, { value: "token-value-0001" })).status).toBe(200);
  });
  afterEach(async () => {
    await db?.end();
    if (server) {
      await server.query(`DROP DATABASE IF EXISTS ${database}`);
      await server.end();
    }
  });

  it("scheduling waits for a write in progress; a write after it is refused", async () => {
    const paused = pauseAt(/^\s*INSERT INTO value_versions/);
    const write = call("PUT", `${DEV}/values/TOKEN`, { value: "token-value-0002" });
    await paused.arrived;
    const scheduling = call("POST", `${ORG}/deletion`, {});
    expect(await settled(scheduling, 500)).toBe(false);
    paused.release();
    expect((await write).status).toBe(200);
    expect((await scheduling).status).toBe(201);
    const late = await call("PUT", `${DEV}/values/TOKEN`, { value: "token-value-0003" });
    expect(late.status).toBe(409);
    expect(late.body.error.code).toBe("ORGANIZATION_DELETING");
  });

  it("an invitation accepted while the deletion is being scheduled is refused once it is", async () => {
    const invite = await issueInviteGrant(ctx, { organizationId: orgId, role: "member", name: "Late" }, adminId);
    // Scheduling holds the Organization; acceptance waits, then sees the freeze.
    const paused = pauseAt(/^\s*INSERT INTO audit_events/);
    const scheduling = call("POST", `${ORG}/deletion`, {});
    await paused.arrived;
    const accepting = consumeSetupGrant(ctx, invite.token, {}).then(
      () => "accepted",
      (err: unknown) => (err as { code?: string }).code ?? String(err),
    );
    expect(await settled(accepting, 500)).toBe(false);
    paused.release();
    expect((await scheduling).status).toBe(201);
    expect(await accepting).toBe("INVALID_CREDENTIAL");
    expect((await db.query("SELECT 1 FROM identities WHERE name = 'Late'")).rows).toEqual([]);
  });

  it("two workers never run one deletion twice", async () => {
    const scheduled = (await call("POST", `${ORG}/deletion`, {})).body;
    await db.query("UPDATE organization_deletions SET scheduled_at = now() - interval '8 days', run_after = now() - interval '1 minute'");
    const outcomes = await Promise.all([finalizeDeletion(ctx, scheduled.id, orgId), finalizeDeletion(ctx, scheduled.id, orgId)]);
    expect(outcomes.filter((o) => o !== null)).toHaveLength(1);
    expect((await db.query("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'organization.deleted'")).rows[0]).toEqual({ n: 1 });
    expect((await db.query("SELECT completed_at IS NOT NULL AS done FROM organization_deletions WHERE id = $1", [scheduled.id])).rows[0]).toEqual({ done: true });
  });
});
