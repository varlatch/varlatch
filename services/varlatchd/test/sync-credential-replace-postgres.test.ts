// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { runMigrations } from "../src/db/migrate.js";
import { createPgQuerier } from "../src/db/pg.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { reconcileTarget } from "../src/domain/syncdelivery.js";
import { buildApp } from "../src/http/app.js";

/**
 * A credential replacement against a run of the same Connection, on real
 * PostgreSQL (#57). A run still using the old credential counts no failure,
 * even when its bookkeeping starts while the replacement holds the Target;
 * a run that read the new credential counts from the reset count, not from
 * the count its lease read.
 */

// Always run in CI against a disposable database; never use an installation DB.
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("credential replacement against a run, on real PostgreSQL", () => {
  let server: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let app: ReturnType<typeof buildApp>;
  let token: string;
  let connection: { id: string; version: number };
  let targetId: string;
  const database = `varlatch_credreplace_${process.pid}`;
  const ORG = "/v1/organizations/acme";
  const ENV = `${ORG}/projects/api/environments/development`;

  const call = async (method: string, path: string, body?: unknown) => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    return { status: res.status, body: await res.json().catch(() => null) };
  };

  // Each gate pauses the first query, on the pool or on a client, that matches it.
  let gates: { pattern: RegExp; reached: () => void; wait: Promise<void> }[] = [];
  const pauseAt = (pattern: RegExp) => {
    let release!: () => void;
    let reached!: () => void;
    const wait = new Promise<void>((r) => (release = r));
    const arrived = new Promise<void>((r) => (reached = r));
    gates.push({ pattern, reached, wait });
    return { arrived, release };
  };
  const hold = async (text: string) => {
    const g = gates.find((candidate) => candidate.pattern.test(text));
    if (g) {
      gates = gates.filter((candidate) => candidate !== g);
      g.reached();
      await g.wait;
    }
  };
  const gated = (pool: ReturnType<typeof createPgQuerier>): ReturnType<typeof createPgQuerier> => ({
    query: async (text, params) => {
      await hold(text);
      return pool.query(text, params);
    },
    end: () => pool.end(),
    connect: async () => {
      const client = await pool.connect();
      return {
        release: (destroy?: boolean) => client.release(destroy),
        query: async (text: string, params?: unknown[]) => {
          await hold(text);
          return client.query(text, params);
        },
      };
    },
  });
  const settled = async <T>(p: Promise<T>, ms: number) =>
    Promise.race([p.then(() => true), new Promise<boolean>((r) => setTimeout(() => r(false), ms))]);

  /** Coolify that lists no variables and refuses every write as an unknown token. */
  const refusing = (onWrite?: () => Promise<void>) =>
    (async (input: unknown, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      if (String(input).endsWith("/envs") && method === "GET") return new Response("[]", { status: 200 });
      await onWrite?.();
      return new Response(JSON.stringify({ message: "Unauthenticated." }), { status: 401 });
    }) as typeof fetch;

  const target = async () =>
    (await db.query("SELECT state, disabled_reason, failure_count FROM sync_targets WHERE id = $1", [targetId])).rows[0];
  const disabledEvents = async () =>
    (await db.query("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'sync.target_disabled'")).rows[0];

  beforeEach(async () => {
    server = createPgQuerier(url!);
    await server.query(`CREATE DATABASE ${database}`);
    const address = new URL(url!);
    address.pathname = `/${database}`;
    db = createPgQuerier(address.toString());
    const migrating = await db.connect();
    try {
      await runMigrations(migrating);
    } finally {
      migrating.release();
    }
    gates = [];
    ctx = { db: gated(db), rootKek: Buffer.alloc(32, 7) };
    await ensureInstallation(ctx);
    const adminId = (await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, {})).identityId;
    token = (await issueCredential(db, { identityId: adminId, kind: "cli" })).token;
    app = buildApp(ctx);
    await call("POST", "/v1/organizations", { slug: "acme", name: "Acme" });
    await call("POST", `${ORG}/projects`, { slug: "api", name: "API", contractAuthority: "git" });
    await call("POST", `${ORG}/projects/api/environments`, { name: "development", tier: "development" });
    expect((await call("PUT", `${ENV}/values/PORT`, { value: "8080" })).status).toBe(200);
    connection = (
      await call("POST", `${ORG}/platform-connections`, { platform: "coolify", baseIdentity: "https://coolify.example.com", name: "c", credential: "token-old" })
    ).body;
    targetId = (await call("POST", `${ENV}/sync-targets`, { connectionId: connection.id, destination: { applicationUuid: "app1" }, mapping: { kind: "wildcard" } })).body.id;
    // Nine failures with the old credential: one more would stop the Target.
    await db.query(
      "UPDATE sync_targets SET failure_count = 9, last_result = 'AdapterError: Coolify env update failed (401)', needs_sync = true, next_attempt_at = NULL WHERE id = $1",
      [targetId],
    );
  });
  afterEach(async () => {
    await db?.end();
    if (server) {
      await server.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
      await server.end();
    }
  });

  it("a late 401 of the old credential, counted while the replacement holds the Target, counts nothing", async () => {
    // The run stops at its failure bookkeeping, before its first statement.
    const bookkeeping = pauseAt(/SELECT version FROM platform_connections WHERE id = \$1 FOR SHARE|SET failure_count = \$2/);
    const running = reconcileTarget(ctx, targetId, { fetchImpl: refusing() });
    await bookkeeping.arrived;
    // The replacement locks the Connection and the Target, resets the
    // Target, and stops at its audit insert, before it commits.
    const replacement = pauseAt(/^\s*INSERT INTO audit_events/);
    const replacing = call("POST", `${ORG}/platform-connections/${connection.id}/credential`, { credential: "token-new", expectedVersion: connection.version });
    await replacement.arrived;
    // The bookkeeping starts now, and waits for the replacement.
    bookkeeping.release();
    expect(await settled(running, 500)).toBe(false);
    replacement.release();
    expect((await replacing).status).toBe(200);
    await running;
    expect(await target()).toEqual({ state: "active", disabled_reason: null, failure_count: 0 });
    expect(await disabledEvents()).toEqual({ n: 0 });
  });

  it("a run that read the new credential counts its failure from the reset count", async () => {
    // The run has its lease (nine failures, as it read them) and stops just
    // before it reads the credential; the replacement commits meanwhile.
    const paused = pauseAt(/c\.version AS connection_version/);
    const running = reconcileTarget(ctx, targetId, { fetchImpl: refusing() });
    await paused.arrived;
    expect((await call("POST", `${ORG}/platform-connections/${connection.id}/credential`, { credential: "token-new", expectedVersion: connection.version })).status).toBe(200);
    paused.release();
    await running;
    expect(await target()).toEqual({ state: "active", disabled_reason: null, failure_count: 1 });
    expect(await disabledEvents()).toEqual({ n: 0 });
  });
});
