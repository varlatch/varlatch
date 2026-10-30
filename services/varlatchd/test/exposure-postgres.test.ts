// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { runMigrations } from "../src/db/migrate.js";
import { createPgQuerier } from "../src/db/pg.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { buildApp } from "../src/http/app.js";

/**
 * The exposure index under real concurrency (ADR-0052 Decision 6): a
 * transaction locks every exposure row it updates before it takes the
 * audit counter, so two disclosures of the same values cannot deadlock.
 */

// Always run in CI against a disposable database; never use an installation DB.
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("exposure index on real PostgreSQL", () => {
  let server: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let app: ReturnType<typeof buildApp>;
  let admin: string;
  let bob: { id: string; token: string };
  const database = `varlatch_exposure_${process.pid}`;
  const PROD = "/v1/organizations/test/projects/api/environments/production";

  const call = async (method: string, path: string, body?: unknown, token = admin) => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    return { status: res.status, body: await res.json().catch(() => null) };
  };

  // Pauses the first transaction statement matching `pattern` until released.
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
    ctx = { db: gated(db), rootKek: Buffer.alloc(32, 9) };
    await ensureInstallation(ctx);
    const setup = await issueBootstrapGrant(ctx);
    const adminId = (await consumeSetupGrant(ctx, setup.token, {})).identityId;
    admin = (await issueCredential(db, { identityId: adminId, kind: "cli" })).token;
    app = buildApp(ctx);
    const orgId = (await call("POST", "/v1/organizations", { slug: "test", name: "Test" })).body.id;
    const projectId = (await call("POST", "/v1/organizations/test/projects", { slug: "api", name: "API", contractAuthority: "managed" })).body.id;
    await call("POST", "/v1/organizations/test/projects/api/environments", { name: "production", tier: "production" });
    const revision = await call("POST", "/v1/organizations/test/projects/api/contract/revisions", {
      contract: {
        schemaVersion: 1,
        items: [
          { name: "TOKEN", required: { kind: "never" }, sensitive: true, type: "string" },
          { name: "DB_HOST", required: { kind: "never" }, sensitive: false, type: "string" },
        ],
      },
    });
    await call("POST", `/v1/organizations/test/projects/api/contract/revisions/${revision.body.id}/activate`, {});
    await call("PUT", `${PROD}/values/TOKEN`, { value: "token-value-0001" });
    await call("PUT", `${PROD}/values/DB_HOST`, { value: "db.internal" });
    const invite = await issueInviteGrant(ctx, { organizationId: orgId, role: "member", name: "Bob" }, adminId);
    const bobId = (await consumeSetupGrant(ctx, invite.token, {})).identityId;
    bob = { id: bobId, token: (await issueCredential(db, { identityId: bobId, kind: "cli" })).token };
    await call("POST", "/v1/organizations/test/grants", {
      subjectIdentityId: bobId,
      scope: { kind: "project", projectId },
      actions: ["secret.reveal", "secret.use", "config.value.read", "config.metadata.read"],
    });
  });
  afterEach(async () => {
    await db?.end();
    if (server) {
      await server.query(`DROP DATABASE IF EXISTS ${database}`);
      await server.end();
    }
  });

  it("holds the Secret's exposure row before its first audit insert, so it never waits for one while holding the counter", async () => {
    // The rows exist; the next retrieval updates (locks) them.
    expect((await call("POST", `${PROD}/retrievals`, { mode: "strict" }, bob.token)).status).toBe(200);
    const paused = pauseAt(/^\s*INSERT INTO audit_events/);
    const retrieval = call("POST", `${PROD}/retrievals`, { mode: "strict" }, bob.token);
    await paused.arrived;
    const probe = await db.connect();
    let locked = false;
    try {
      await probe.query("BEGIN");
      try {
        await probe.query(
          "SELECT 1 FROM member_exposure WHERE identity_id = $1 AND item_name = 'TOKEN' AND way = 'delivered' FOR UPDATE NOWAIT",
          [bob.id],
        );
      } catch (err) {
        locked = (err as { code?: string }).code === "55P03";
      }
      await probe.query("ROLLBACK");
    } finally {
      probe.release();
    }
    paused.release();
    expect((await retrieval).status).toBe(200);
    expect(locked).toBe(true);
  });

  it("a rename does not hold up the backfill: it locks no key", async () => {
    expect((await call("POST", `${PROD}/disclosures`, { items: ["TOKEN"] }, bob.token)).status).toBe(200);
    await db.query("DELETE FROM member_exposure");
    await db.query("UPDATE exposure_backfill SET cursor = 0, until_order = (SELECT value FROM audit_position), finished_at = NULL");
    // The rename holds its Organization's row and waits, as for the audit counter.
    const paused = pauseAt(/^\s*INSERT INTO audit_events/);
    const rename = call("PATCH", "/v1/organizations/test", { name: "Renamed" });
    await paused.arrived;
    const { backfillExposureOnce } = await import("../src/domain/exposure.js");
    const outcome = await Promise.race([
      (async () => {
        while (!(await backfillExposureOnce(ctx)).done) {
          /* next batch */
        }
        return "finished";
      })(),
      new Promise((resolve) => setTimeout(() => resolve("blocked"), 3000)),
    ]);
    paused.release();
    expect((await rename).status).toBe(200);
    expect(outcome).toBe("finished");
    expect((await db.query("SELECT 1 FROM member_exposure WHERE identity_id = $1", [bob.id])).rows).toHaveLength(1);
  });

  it("a Connection change holds its integration row before it takes the audit counter", async () => {
    const connection = (
      await call("POST", "/v1/organizations/test/platform-connections", {
        platform: "coolify",
        baseIdentity: "https://coolify.example.com",
        name: "c",
        credential: "token-c-0001",
      })
    ).body;
    const paused = pauseAt(/^\s*INSERT INTO audit_events/);
    const replacing = call("POST", `/v1/organizations/test/platform-connections/${connection.id}/credential`, {
      credential: "token-c-0002",
      expectedVersion: connection.version,
    });
    await paused.arrived;
    const probe = await db.connect();
    let locked = false;
    try {
      await probe.query("BEGIN");
      try {
        await probe.query("SELECT 1 FROM member_integrations WHERE resource_id = $1 FOR UPDATE NOWAIT", [connection.id]);
      } catch (err) {
        locked = (err as { code?: string }).code === "55P03";
      }
      await probe.query("ROLLBACK");
    } finally {
      probe.release();
    }
    paused.release();
    expect((await replacing).status).toBe(200);
    expect(locked).toBe(true);
  });

  it("concurrent retrievals and scans of the same values all succeed", async () => {
    const results = await Promise.all(
      Array.from({ length: 12 }, (_, i) =>
        i % 2 === 0
          ? call("POST", `${PROD}/retrievals`, { mode: "strict" }, bob.token)
          : call("POST", `${PROD}/disclosures`, { scope: "all-authorized-secrets", purpose: "scan" }, bob.token),
      ),
    );
    expect(results.map((r) => r.status)).toEqual(Array(12).fill(200));
    const rows = await db.query("SELECT item_name, way FROM member_exposure WHERE identity_id = $1 ORDER BY 1, 2", [bob.id]);
    expect(rows.rows).toEqual([
      { item_name: "DB_HOST", way: "delivered" },
      { item_name: "TOKEN", way: "delivered" },
    ]);
  });
});
