// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { runMigrations } from "../src/db/migrate.js";
import { createPgQuerier } from "../src/db/pg.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { buildApp } from "../src/http/app.js";

/**
 * The writer protocol under real concurrency (ADR-0051 Decision 1): a
 * Project's deletion waits for the writers in progress, and writers that
 * come later see it deleted and refuse; writers of one Project never
 * deadlock each other.
 */

// Always run in CI against a disposable database; never use an installation DB.
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("project deletion on real PostgreSQL", () => {
  let server: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let app: ReturnType<typeof buildApp>;
  let token: string;
  let projectId: string;
  const database = `varlatch_projdel_${process.pid}`;
  const P = "/v1/organizations/test/projects/api";
  const DEV = `${P}/environments/development`;

  const call = async (method: string, path: string, body?: unknown) => {
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
    ctx = { db: gated(db), rootKek: Buffer.alloc(32, 5) };
    await ensureInstallation(ctx);
    const setup = await issueBootstrapGrant(ctx);
    const adminId = (await consumeSetupGrant(ctx, setup.token, {})).identityId;
    token = (await issueCredential(db, { identityId: adminId, kind: "cli" })).token;
    app = buildApp(ctx);
    await call("POST", "/v1/organizations", { slug: "test", name: "Test" });
    projectId = (await call("POST", "/v1/organizations/test/projects", { slug: "api", name: "API", contractAuthority: "managed" })).body.id;
    await call("POST", `${P}/environments`, { name: "development", tier: "development" });
    const revision = await call("POST", `${P}/contract/revisions`, {
      contract: { schemaVersion: 1, items: [{ name: "TOKEN", required: { kind: "never" }, sensitive: true, type: "string" }] },
    });
    await call("POST", `${P}/contract/revisions/${revision.body.id}/activate`, {});
    expect((await call("PUT", `${DEV}/values/TOKEN`, { value: "token-value-0001" })).status).toBe(200);
  });
  afterEach(async () => {
    await db?.end();
    if (server) {
      await server.query(`DROP DATABASE IF EXISTS ${database}`);
      await server.end();
    }
  });

  const intact = async () =>
    Number(
      (
        (await db.query(
          `SELECT count(*) AS n FROM value_versions v JOIN env_values ev ON ev.id = v.value_id
           JOIN environments e ON e.id = ev.environment_id WHERE e.project_id = $1 AND v.erased_at IS NULL`,
          [projectId],
        )).rows[0] as { n: string }
      ).n,
    );

  it("waits for a write in progress, then erases what it wrote", async () => {
    const paused = pauseAt(/^\s*INSERT INTO value_versions/);
    const write = call("PUT", `${DEV}/values/TOKEN`, { value: "token-value-0002" });
    await paused.arrived;
    const deletion = call("DELETE", P);
    // The write holds the Project: the deletion cannot take it yet.
    expect(await settled(deletion, 500)).toBe(false);
    paused.release();
    expect((await write).status).toBe(200);
    const deleted = await deletion;
    expect(deleted.status).toBe(200);
    expect(deleted.body.versionsErased).toBe(2);
    expect(await intact()).toBe(0);
  });

  it("refuses a write that comes after the deletion took the Project", async () => {
    const paused = pauseAt(/^\s*UPDATE environments SET deleted_at/);
    const deletion = call("DELETE", P);
    await paused.arrived;
    const write = call("PUT", `${DEV}/values/TOKEN`, { value: "token-value-0003" });
    expect(await settled(write, 500)).toBe(false);
    paused.release();
    expect((await deletion).status).toBe(200);
    expect((await write).status).toBe(404);
    expect(await intact()).toBe(0);
  });

  /**
   * Two Targets on one Connection whose creation and physical order run
   * opposite their ID order, as random IDs often do, and a third connection
   * holding the higher one, so each competing transaction queues on its
   * Target locks in turn.
   */
  async function contendedTargets() {
    const connection = (
      await call("POST", "/v1/organizations/test/platform-connections", {
        platform: "coolify",
        baseIdentity: "https://coolify.example.com",
        name: "c",
        credential: "token-c-0001",
      })
    ).body as { id: string; version: number };
    const created: string[] = [];
    for (const app of ["app1", "app2"]) {
      const t = await call("POST", `${DEV}/sync-targets`, { connectionId: connection.id, destination: { applicationUuid: app }, mapping: { kind: "wildcard" } });
      expect(t.status, JSON.stringify(t.body)).toBe(201);
      created.push(t.body.id as string);
    }
    const [low, high] = [...created].sort() as [string, string];
    await db.query("UPDATE sync_targets SET created_at = now() - interval '1 hour' WHERE id = $1", [high]);
    // A new row version of the lower one goes after the higher one physically.
    await db.query("UPDATE sync_targets SET created_at = now(), needs_sync = false WHERE id = $1", [low]);
    await db.query("UPDATE sync_targets SET needs_sync = false WHERE id = $1", [high]);
    const holder = await db.connect();
    await holder.query("BEGIN");
    await holder.query("SELECT id FROM sync_targets WHERE id = $1 FOR UPDATE", [high]);
    const release = async () => {
      await holder.query("ROLLBACK");
      holder.release();
    };
    return { connection, low, high, release };
  }
  const waiting = async (n: number) => {
    for (let i = 0; i < 150; i++) {
      const res = await db.query(
        "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'",
      );
      if ((res.rows[0] as { n: number }).n >= n) return;
      await new Promise((r) => setTimeout(r, 20));
    }
    throw new Error("not waiting");
  };

  it("a deletion and a credential replacement lock the same Targets in one order: no deadlock", async () => {
    const { connection, release } = await contendedTargets();
    const replacing = call("POST", `/v1/organizations/test/platform-connections/${connection.id}/credential`, {
      credential: "token-c-0002",
      expectedVersion: connection.version,
    });
    await waiting(1);
    const deleting = call("DELETE", P);
    await waiting(2);
    await release();
    const [replaced, deleted] = await Promise.all([replacing, deleting]);
    expect([replaced.status, deleted.status], JSON.stringify([replaced.body, deleted.body])).toEqual([200, 200]);
  });

  it("a deletion and a Connection's revocation lock the same Targets in one order: no deadlock", async () => {
    const { connection, release } = await contendedTargets();
    const revoking = call("DELETE", `/v1/organizations/test/platform-connections/${connection.id}`);
    await waiting(1);
    const deleting = call("DELETE", P);
    await waiting(2);
    await release();
    const [revoked, deleted] = await Promise.all([revoking, deleting]);
    expect([revoked.status, deleted.status], JSON.stringify([revoked.body, deleted.body])).toEqual([204, 200]);
  });

  it("a deletion and the sync trigger scan lock the same Targets in one order: no deadlock", async () => {
    const { scanSyncTriggers } = await import("../src/domain/syncdelivery.js");
    const { release } = await contendedTargets();
    // The scan reads the history again, the value writes in development included.
    await db.query("INSERT INTO sync_cursor (singleton, occurred_at, event_id, cursor_order) VALUES (true, now(), '', 0) ON CONFLICT (singleton) DO UPDATE SET cursor_order = 0");
    const scanning = scanSyncTriggers(ctx).then(() => "ok", (err: unknown) => String(err));
    await waiting(1);
    const deleting = call("DELETE", P);
    await waiting(2);
    await release();
    const [scanned, deleted] = await Promise.all([scanning, deleting]);
    expect([scanned, deleted.status], JSON.stringify(deleted.body)).toEqual(["ok", 200]);
  });

  it("two Contract activations and a rename of one Project never deadlock", async () => {
    const revisions = await Promise.all(
      [1, 2].map(async (n) =>
        (
          await call("POST", `${P}/contract/revisions`, {
            contract: { schemaVersion: 1, items: [{ name: `ITEM_${n}`, required: { kind: "never" }, sensitive: false, type: "string" }] },
          })
        ).body.id as string,
      ),
    );
    for (let round = 0; round < 5; round++) {
      const results = await Promise.all([
        call("POST", `${P}/contract/revisions/${revisions[0]}/activate`, {}),
        call("POST", `${P}/contract/revisions/${revisions[1]}/activate`, {}),
        call("PATCH", P, { name: `API ${round}` }),
      ]);
      expect(results.map((r) => r.status)).toEqual([200, 200, 200]);
    }
  });
});
