// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
} from "../src/domain/bootstrap.js";
import { ledgerSet, reconcileTarget, runSyncOnce, scanSyncTriggers } from "../src/domain/syncdelivery.js";
import { mappingWidens } from "../src/domain/sync.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { traceLog, traced, type TraceLog } from "./helpers/trace.js";

/**
 * Sync Targets (ADR-0031): opt-in, audited, converge-to-current delivery of
 * an Environment's Effective Configuration to external platforms.
 */

// Decryptions are recorded in order with the SQL, so tests can show the
// audit event naming a version commits before that version is decrypted.
const hooks = vi.hoisted(() => ({ log: null as TraceLog | null }));
vi.mock("../src/crypto/hierarchy.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/crypto/hierarchy.js")>();
  return {
    ...actual,
    decryptValue: (...args: Parameters<typeof actual.decryptValue>) => {
      hooks.log?.decrypt(args[3]);
      return actual.decryptValue(...args);
    },
  };
});

let log: TraceLog;
let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;

const ENV_PATH = "/v1/organizations/acme/projects/api/environments/development";

beforeEach(async () => {
  log = traceLog();
  hooks.log = log;
  const db = traced(await migratedTestDb(), log);
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  adminToken = (await issueCredential(ctx.db, { identityId: consumed.identityId, kind: "cli" })).token;
  app = buildApp(ctx);
  await post("/v1/organizations", { name: "Acme", slug: "acme" });
  await post("/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "git" });
  await post(`/v1/organizations/acme/projects/api/environments`, { name: "development", tier: "development" });
  await put(`${ENV_PATH}/values/DATABASE_URL`, { value: "postgres://dev-db/main" });
  await put(`${ENV_PATH}/values/PORT`, { value: "8080" });
});
afterEach(async () => {
  await ctx.close();
});

function auth(token = adminToken): HeadersInit {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}
async function post(path: string, body: unknown, token = adminToken) {
  return app.request(path, { method: "POST", headers: auth(token), body: JSON.stringify(body) });
}
async function put(path: string, body: unknown, token = adminToken) {
  return app.request(path, { method: "PUT", headers: auth(token), body: JSON.stringify(body) });
}
async function patchReq(path: string, body: unknown, token = adminToken) {
  return app.request(path, { method: "PATCH", headers: auth(token), body: JSON.stringify(body) });
}
async function get(path: string, token = adminToken) {
  return app.request(path, { headers: auth(token) });
}
async function del(path: string, token = adminToken) {
  return app.request(path, { method: "DELETE", headers: auth(token) });
}

/** A fake Coolify instance: env store keyed by application uuid. */
function fakeCoolify() {
  const store = new Map<string, { uuid: string; key: string; value: string }>();
  const calls: { method: string; url: string; body?: unknown }[] = [];
  let nextUuid = 1;
  let restarts = 0; // deploy or restart actions, POST only (Coolify >= 4.3 rejects GET)
  let failWrites = false;
  const fetchImpl = (async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method, url, ...(body !== undefined ? { body } : {}) });
    const json = (payload: unknown, status = 200) =>
      new Response(JSON.stringify(payload), { status });
    if (url.endsWith("/envs") && method === "GET") return json([...store.values()]);
    if (url.endsWith("/envs") && (method === "POST" || method === "PATCH")) {
      if (failWrites) return json({ message: "boom" }, 500);
      const b = body as { key: string; value: string };
      const existing = [...store.values()].find((e) => e.key === b.key);
      const uuid = existing?.uuid ?? `env${nextUuid++}`;
      store.set(uuid, { uuid, key: b.key, value: b.value });
      return json({ uuid }, method === "POST" ? 201 : 200);
    }
    const deleteMatch = url.match(/\/envs\/([^/]+)$/);
    if (deleteMatch && method === "DELETE") {
      store.delete(deleteMatch[1] as string);
      return json({ message: "deleted" });
    }
    if (method === "POST" && (url.endsWith("/start?force=true") || url.endsWith("/restart"))) {
      restarts += 1;
      return json({ message: "queued" });
    }
    return json({ message: "not found" }, 404);
  }) as typeof fetch;
  return {
    fetchImpl,
    calls,
    values: () => new Map([...store.values()].map((e) => [e.key, e.value])),
    seed: (key: string, value: string) => {
      const uuid = `seed${nextUuid++}`;
      store.set(uuid, { uuid, key, value });
    },
    setFailWrites: (v: boolean) => {
      failWrites = v;
    },
    restarts: () => restarts,
  };
}

async function createConnection(body: Record<string, unknown> = {}) {
  const res = await post("/v1/organizations/acme/platform-connections", {
    platform: "coolify",
    baseIdentity: "https://coolify.example.com",
    name: "prod coolify",
    credential: "coolify-token-123",
    ...body,
  });
  return res;
}

async function createTarget(connectionId: string, body: Record<string, unknown> = {}) {
  return post(`${ENV_PATH}/sync-targets`, {
    connectionId,
    destination: { applicationUuid: "app1" },
    mapping: { kind: "wildcard" },
    ...body,
  });
}

function asJson<T>(v: unknown): T {
  return (typeof v === "string" ? JSON.parse(v) : v) as T;
}

async function targetRowFromDb() {
  const res = await ctx.db.query("SELECT * FROM sync_targets");
  return res.rows[0] as Record<string, unknown>;
}

describe("platform connections", () => {
  it("meta advertises the capability and the adapter allowlist", async () => {
    const meta = await (await app.request("/v1/meta")).json();
    expect(meta.capabilities).toContain("sync.targets");
    expect(meta.syncAdapters).toEqual(["github-actions", "coolify", "convex"]);
  });

  it("creates a connection; the credential is never returned and rests encrypted", async () => {
    const res = await createConnection();
    expect(res.status).toBe(201);
    const created = await res.json();
    expect(created.baseIdentity).toBe("https://coolify.example.com");
    expect(JSON.stringify(created)).not.toContain("coolify-token-123");
    const row = await ctx.db.query("SELECT credential_envelope FROM platform_connections");
    expect(JSON.stringify(row.rows[0])).not.toContain("coolify-token-123");
  });

  it("rejects unknown platforms and non-https Coolify origins", async () => {
    expect((await createConnection({ platform: "generic-url" })).status).toBe(422);
    expect(
      (await createConnection({ baseIdentity: "http://coolify.example.com" })).status,
    ).toBe(422);
  });

  it("base identity is immutable: no update surface exists for it", async () => {
    const created = await (await createConnection()).json();
    const res = await patchReq(
      `/v1/organizations/acme/platform-connections/${created.id}`,
      { baseIdentity: "https://other.example.com" },
    );
    expect(res.status).toBe(404); // no such route
  });
});

describe("sync target lifecycle", () => {
  it("creates a wildcard target and audits the disclosure gate provenance", async () => {
    const connection = await (await createConnection()).json();
    const res = await createTarget(connection.id);
    expect(res.status).toBe(201);
    const target = await res.json();
    expect(target.state).toBe("active");
    expect(target.mapping.kind).toBe("wildcard");
    const audit = await ctx.db.query(
      "SELECT authz, metadata FROM audit_events WHERE event_type = 'sync.target_created'",
    );
    const event = audit.rows[0] as { authz: unknown; metadata: unknown };
    const authz = asJson<Record<string, unknown>>(event.authz);
    // A wildcard discloses Secrets AND non-sensitive values: both actions gated.
    expect(Object.keys(authz).sort()).toEqual(["config.value.read", "secret.reveal"]);
    expect(JSON.stringify(event.metadata)).toContain("coolify:app1");
  });

  it("a destination has exactly one writer per installation", async () => {
    const connection = await (await createConnection()).json();
    expect((await createTarget(connection.id)).status).toBe(201);
    // Second target, same destination via a DIFFERENT connection to the
    // same instance: canonical destination identity conflicts.
    const other = await (
      await createConnection({ name: "second", credential: "other-token" })
    ).json();
    const dup = await createTarget(other.id);
    expect(dup.status).toBe(409);
    // Same application uuid on a different instance stays distinct.
    const elsewhere = await (
      await createConnection({ baseIdentity: "https://other.example.com", name: "other instance" })
    ).json();
    expect((await createTarget(elsewhere.id)).status).toBe(201);
    // Revocation releases the claim.
    const first = await (await get(`${ENV_PATH}/sync-targets`)).json();
    await del(`${ENV_PATH}/sync-targets/${first.items[0].id}`);
    expect((await createTarget(other.id)).status).toBe(201);
  });

  it("an actor without disclosure authority cannot create a wildcard target", async () => {
    const connection = await (await createConnection()).json();
    const svc = await (
      await post("/v1/organizations/acme/identities", { name: "runner", kind: "service" })
    ).json();
    // config.sync.manage alone is lifecycle authority, not disclosure.
    await post("/v1/organizations/acme/grants", {
      subjectIdentityId: svc.id,
      scope: { kind: "organization" },
      actions: ["config.sync.manage", "organization.read", "project.read", "environment.read"],
    });
    const res = await createTarget(connection.id, undefined);
    expect(res.status).toBe(201); // admin can
    await del(`${ENV_PATH}/sync-targets/${(await res.json()).id}`);
    const denied = await post(
      `${ENV_PATH}/sync-targets`,
      {
        connectionId: connection.id,
        destination: { applicationUuid: "app1" },
        mapping: { kind: "wildcard" },
      },
      svc.credential,
    );
    expect(denied.status).toBe(403);
  });

  it("revoking a connection disables its targets; resume demands a re-point", async () => {
    const connection = await (await createConnection()).json();
    const target = await (await createTarget(connection.id)).json();
    await del(`/v1/organizations/acme/platform-connections/${connection.id}`);
    const after = await (await get(`${ENV_PATH}/sync-targets/${target.id}`)).json();
    expect(after.state).toBe("disabled");
    expect(after.disabledReason).toBe("connection-revoked");
    const resume = await post(`${ENV_PATH}/sync-targets/${target.id}/resume`, {});
    expect(resume.status).toBe(422);
  });
});

describe("convergence", () => {
  async function activeTarget(extra: Record<string, unknown> = {}) {
    const connection = await (await createConnection()).json();
    const target = await (await createTarget(connection.id, extra)).json();
    return { connection, target };
  }

  it("pushes the effective output, then converges to no-op", async () => {
    const coolify = fakeCoolify();
    await activeTarget();
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.values().get("DATABASE_URL")).toBe("postgres://dev-db/main");
    expect(coolify.values().get("PORT")).toBe("8080");

    const row = await targetRowFromDb();
    expect(row.last_result).toBe("ok");
    expect(row.needs_sync).toBe(false);

    // Converged: the second pass makes no adapter calls at all.
    coolify.calls.length = 0;
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.calls).toHaveLength(0);
  });

  it("audit precedes disclosure: push_attempted enumerates names and versions before the wire", async () => {
    const coolify = fakeCoolify();
    await activeTarget();
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    const events = await ctx.db.query(
      "SELECT event_type, metadata FROM audit_events WHERE event_type LIKE 'sync.push%' ORDER BY occurred_at, id",
    );
    const types = (events.rows as { event_type: string }[]).map((r) => r.event_type);
    expect(types[0]).toBe("sync.push_attempted");
    expect(types).toContain("sync.push_result");
    const attempted = events.rows[0] as { metadata: unknown };
    const metadata = asJson<{ items: string; destination: string }>(attempted.metadata);
    expect(metadata.items).toMatch(/DATABASE_URL@ver_/);
    expect(metadata.destination).toBe("coolify:app1");
    // Never plaintext values in audit.
    expect(JSON.stringify(attempted.metadata)).not.toContain("postgres://dev-db");
  });

  /** Versions named by committed sync.values_decrypted inserts, and every version decrypted, in order. */
  function decryptionAudit() {
    const audited = new Set<string>();
    const unaudited: string[] = [];
    const decrypted: string[] = [];
    for (const entry of log.entries) {
      if (entry.kind === "decrypt") {
        decrypted.push(entry.versionId);
        if (!audited.has(entry.versionId)) unaudited.push(entry.versionId);
      } else if (/INSERT INTO audit_events/.test(entry.text) && entry.params[1] === "sync.values_decrypted") {
        const items = String(asJson<{ items: string }>(entry.params[13]).items);
        for (const item of items.split(",")) audited.add(item.split("@")[1] as string);
      }
    }
    return { audited, unaudited, decrypted };
  }

  it("audit precedes decryption, even when nothing is pushed, and never triggers a sync", async () => {
    const coolify = fakeCoolify();
    await activeTarget();
    log.reset();
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    const first = decryptionAudit();
    expect(first.decrypted.length).toBeGreaterThan(0);
    expect(first.unaudited).toEqual([]);

    // A repair pass that finds everything converged still decrypts, so it
    // still audits first, although no value leaves the process.
    await ctx.db.query("UPDATE sync_targets SET needs_sync = true");
    coolify.calls.length = 0;
    log.reset();
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.calls.filter((c) => c.method !== "GET")).toHaveLength(0);
    const repair = decryptionAudit();
    expect(repair.decrypted.length).toBeGreaterThan(0);
    expect(repair.unaudited).toEqual([]);
    const events = await ctx.db.query(
      "SELECT metadata FROM audit_events WHERE event_type = 'sync.values_decrypted' ORDER BY event_order",
    );
    expect(events.rows).toHaveLength(2);
    const metadata = asJson<Record<string, unknown>>((events.rows[1] as { metadata: unknown }).metadata);
    expect(metadata).toMatchObject({ purpose: "sync-reconcile", items: expect.stringMatching(/DATABASE_URL@ver_/) });
    expect(JSON.stringify(events.rows)).not.toContain("postgres://dev-db");

    // The decryption audit is a sync.* event: the trigger scan skips it.
    await scanSyncTriggers(ctx);
    expect((await targetRowFromDb()).needs_sync).toBe(false);
  });

  it("an audit failure stops the reconcile before anything is decrypted or pushed", async () => {
    const coolify = fakeCoolify();
    await activeTarget();
    await ctx.db.query(`
      CREATE FUNCTION refuse_sync_decryption() RETURNS trigger AS $$
      BEGIN
        IF NEW.event_type = 'sync.values_decrypted' THEN RAISE EXCEPTION 'audit unavailable'; END IF;
        RETURN NEW;
      END $$ LANGUAGE plpgsql`);
    await ctx.db.query(`
      CREATE TRIGGER refuse_sync_decryption BEFORE INSERT ON audit_events
        FOR EACH ROW EXECUTE FUNCTION refuse_sync_decryption()`);
    log.reset();
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(log.entries.filter((e) => e.kind === "decrypt")).toHaveLength(0);
    expect(coolify.values().size).toBe(0);
  });

  it("value writes trigger reconvergence through the audit cursor scan", async () => {
    const coolify = fakeCoolify();
    await activeTarget();
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    await put(`${ENV_PATH}/values/PORT`, { value: "9090" });
    await scanSyncTriggers(ctx);
    const row = await targetRowFromDb();
    expect(row.needs_sync).toBe(true);
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.values().get("PORT")).toBe("9090");
  });

  it("rotation pushes the new primary", async () => {
    const coolify = fakeCoolify();
    await activeTarget();
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    const rot = await post(`${ENV_PATH}/values/DATABASE_URL/rotations`, {
      value: "postgres://dev-db/rotated",
    });
    expect(rot.status).toBe(201);
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.values().get("DATABASE_URL")).toBe("postgres://dev-db/rotated");
  });

  it("renames apply; explicit mappings push only mapped items", async () => {
    const coolify = fakeCoolify();
    await activeTarget({
      mapping: { kind: "explicit", items: [{ name: "PORT", rename: "APP_PORT" }] },
    });
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.values().get("APP_PORT")).toBe("8080");
    expect(coolify.values().has("DATABASE_URL")).toBe(false);
  });

  it("wildcard exclusions: excluded names never push, future non-excluded items do", async () => {
    const coolify = fakeCoolify();
    await activeTarget({ mapping: { kind: "wildcard", exclude: ["DATABASE_*"] } });
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.values().get("PORT")).toBe("8080");
    expect(coolify.values().has("DATABASE_URL")).toBe(false);

    // Future items keep flowing (wildcard semantics)… unless excluded.
    await put(`${ENV_PATH}/values/NEW_KEY`, { value: "flows" });
    await put(`${ENV_PATH}/values/DATABASE_POOL`, { value: "never" });
    await scanSyncTriggers(ctx);
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.values().get("NEW_KEY")).toBe("flows");
    expect(coolify.values().has("DATABASE_POOL")).toBe(false);

    // Exclusion is silent narrowing, not a flagged failure.
    const row = await targetRowFromDb();
    expect(row.last_result).toBe("ok");
  });

  it("wildcard exclusions are validated, deduplicated, and sorted", async () => {
    const connection = await (await createConnection()).json();
    const bad = await createTarget(connection.id, {
      mapping: { kind: "wildcard", exclude: ["1BAD"] },
    });
    expect(bad.status).toBe(422);
    const bare = await createTarget(connection.id, {
      mapping: { kind: "wildcard", exclude: ["*"] },
    });
    expect(bare.status).toBe(422);
    const ok = await createTarget(connection.id, {
      mapping: { kind: "wildcard", exclude: ["ZZZ_*", "AAA", "ZZZ_*"] },
    });
    expect(ok.status).toBe(201);
    expect((await ok.json()).mapping).toEqual({ kind: "wildcard", exclude: ["AAA", "ZZZ_*"] });
  });

  it("removal is opt-in and tombstoned; a returning name clears the tombstone", async () => {
    const coolify = fakeCoolify();
    await activeTarget({ removeOrphans: true });
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.values().has("PORT")).toBe(true);

    await del(`${ENV_PATH}/values/PORT`);
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.values().has("PORT")).toBe(false);
    const ledger = await ctx.db.query(
      "SELECT state FROM sync_ledger WHERE dest_name = 'PORT'",
    );
    expect((ledger.rows[0] as { state: string }).state).toBe("tombstone");

    await put(`${ENV_PATH}/values/PORT`, { value: "7070" });
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.values().get("PORT")).toBe("7070");
  });

  it("without the opt-in, a removed name is left in place remotely", async () => {
    const coolify = fakeCoolify();
    await activeTarget();
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    await del(`${ENV_PATH}/values/PORT`);
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.values().get("PORT")).toBe("8080");
  });

  it("reference expansion draws only on the disclosure set", async () => {
    const coolify = fakeCoolify();
    await put(`${ENV_PATH}/values/URL`, { value: "https://x/${PORT}" });
    await activeTarget({
      mapping: { kind: "explicit", items: [{ name: "URL" }] },
    });
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    // PORT is outside the mapping: URL's push fails and the target is flagged.
    expect(coolify.values().has("URL")).toBe(false);
    const row = await targetRowFromDb();
    expect(String(row.last_result)).toContain("outside the disclosure set");

    // Mapping both expands the reference.
    const target = await (await get(`${ENV_PATH}/sync-targets`)).json();
    const patched = await patchReq(`${ENV_PATH}/sync-targets/${target.items[0].id}`, {
      expectedVersion: target.items[0].version,
      mapping: { kind: "explicit", items: [{ name: "URL" }, { name: "PORT" }] },
    });
    expect(patched.status).toBe(200);
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.values().get("URL")).toBe("https://x/8080");
  });

  it("withholds every dependent of a missing transitive reference", async () => {
    const coolify = fakeCoolify();
    await put(`${ENV_PATH}/values/URL`, { value: "${PORT}" });
    await put(`${ENV_PATH}/values/PORT`, { value: "${MISSING}" });
    await activeTarget({ mapping: { kind: "explicit", items: [{ name: "URL" }, { name: "PORT" }] } });
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.values().has("URL")).toBe(false);
    expect(coolify.values().has("PORT")).toBe(false);
    expect(String((await targetRowFromDb()).last_result)).toContain("MISSING");
  });

  it("failures back off and exhaust the failure budget into auto-disable", async () => {
    const coolify = fakeCoolify();
    await activeTarget();
    coolify.setFailWrites(true);
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    let row = await targetRowFromDb();
    expect(row.failure_count).toBe(1);
    expect(row.next_attempt_at).not.toBeNull();
    expect(String(row.last_result)).toContain("degraded");

    // Failure handling itself restores needs_sync; only fast-forward the
    // budget and the backoff clock.
    await ctx.db.query("UPDATE sync_targets SET failure_count = 9, next_attempt_at = NULL");
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    row = await targetRowFromDb();
    expect(row.state).toBe("disabled");
    expect(row.disabled_reason).toBe("failure-budget-exhausted");
    const audit = await ctx.db.query(
      "SELECT id FROM audit_events WHERE event_type = 'sync.target_disabled'",
    );
    expect(audit.rows).toHaveLength(1);

    // Disabled: pushes stop entirely until a human resumes.
    coolify.calls.length = 0;
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.calls).toHaveLength(0);

    coolify.setFailWrites(false);
    const target = await (await get(`${ENV_PATH}/sync-targets`)).json();
    const resumed = await post(`${ENV_PATH}/sync-targets/${target.items[0].id}/resume`, {});
    expect(resumed.status).toBe(200);
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect((await targetRowFromDb()).last_result).toBe("ok");
  });

  it("a failed push retries automatically once its backoff expires", async () => {
    const coolify = fakeCoolify();
    await activeTarget();
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect((await targetRowFromDb()).last_result).toBe("ok");

    // A triggered converge fails: the retry must be self-scheduled — no
    // further trigger, no repair pass, just the backoff expiring.
    await put(`${ENV_PATH}/values/PORT`, { value: "9090" });
    await scanSyncTriggers(ctx);
    coolify.setFailWrites(true);
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    const failed = await targetRowFromDb();
    expect(failed.failure_count).toBe(1);
    expect(failed.needs_sync).toBe(true);

    // Backoff not yet expired: nothing happens.
    coolify.setFailWrites(false);
    coolify.calls.length = 0;
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.calls).toHaveLength(0);

    // Backoff expired: the retry runs with no new trigger.
    await ctx.db.query("UPDATE sync_targets SET next_attempt_at = now() - interval '1 second'");
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.values().get("PORT")).toBe("9090");
    expect((await targetRowFromDb()).last_result).toBe("ok");
  });

  it("a destination change fences an in-flight run's ledger writes", async () => {
    const coolify = fakeCoolify();
    await activeTarget();
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    const before = await targetRowFromDb();
    const staleGeneration = Number(before.generation);

    const target = await (await get(`${ENV_PATH}/sync-targets`)).json();
    await patchReq(`${ENV_PATH}/sync-targets/${target.items[0].id}`, {
      expectedVersion: target.items[0].version,
      destination: { applicationUuid: "app2" },
    });
    const after = await targetRowFromDb();
    expect(Number(after.generation)).toBeGreaterThan(staleGeneration);

    // A run still holding the pre-change lease tries to record an
    // old-destination success against the fresh ledger: fenced out.
    await ledgerSet(ctx, String(before.id), staleGeneration, "PORT", "written", "stalefp", null);
    const ledger = await ctx.db.query("SELECT * FROM sync_ledger");
    expect(ledger.rows).toHaveLength(0);
  });

  it("a destination change between batch selection and lease acquisition is honored", async () => {
    const coolify = fakeCoolify();
    await activeTarget(); // aimed at app1, never pushed
    const target = await (await get(`${ENV_PATH}/sync-targets`)).json();
    const id = target.items[0].id as string;

    // The worker's batch has selected this target. Before it acquires the
    // lease, a destination change to app2 commits (ledger reset, new claim).
    const patched = await patchReq(`${ENV_PATH}/sync-targets/${id}`, {
      expectedVersion: target.items[0].version,
      destination: { applicationUuid: "app2" },
    });
    expect(patched.status).toBe(200);

    // The worker resumes: lease acquisition IS the configuration snapshot,
    // so the push must land at app2 — never at app1 under the fresh
    // generation, and never in app2's ledger as app1 successes.
    await reconcileTarget(ctx, id, { fetchImpl: coolify.fetchImpl });
    expect(coolify.calls.some((c) => c.url.includes("/applications/app1/"))).toBe(false);
    expect(
      coolify.calls.some(
        (c) =>
          c.url.includes("/applications/app2/envs") &&
          (c.method === "POST" || c.method === "PATCH"),
      ),
    ).toBe(true);
    const row = await targetRowFromDb();
    expect(row.last_result).toBe("ok");
    const generations = await ctx.db.query("SELECT DISTINCT generation FROM sync_ledger");
    expect(generations.rows.map((r) => Number((r as { generation: string | number }).generation))).toEqual([
      Number(row.generation),
    ]);
  });

  it("a run fenced mid-flight stops before the wire (intent precedes the wire)", async () => {
    const coolify = fakeCoolify();
    await activeTarget(); // aimed at app1
    const target = await (await get(`${ENV_PATH}/sync-targets`)).json();
    const id = target.items[0].id as string;

    // The run acquires its lease, then loses it to a destination change
    // while doing pre-write work (here: the read-back GET). Intent
    // recording is fenced, so the run must send nothing at all — a fenced
    // run may not put on the wire what it cannot record.
    let fencedOnce = false;
    const fetchImpl = (async (url: unknown, init?: RequestInit) => {
      if (!fencedOnce && String(url).endsWith("/envs") && (init?.method ?? "GET") === "GET") {
        fencedOnce = true;
        const res = await patchReq(`${ENV_PATH}/sync-targets/${id}`, {
          expectedVersion: target.items[0].version,
          destination: { applicationUuid: "app2" },
        });
        expect(res.status).toBe(200);
      }
      return coolify.fetchImpl(url as string, init);
    }) as typeof fetch;

    await reconcileTarget(ctx, id, { fetchImpl });
    expect(fencedOnce).toBe(true);
    expect(
      coolify.calls.filter((c) => c.method === "POST" || c.method === "PATCH" || c.method === "DELETE"),
    ).toHaveLength(0);
    const ledger = await ctx.db.query("SELECT * FROM sync_ledger");
    expect(ledger.rows).toHaveLength(0);

    // The successor converges cleanly to the new destination.
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.values().get("PORT")).toBe("8080");
    expect((await targetRowFromDb()).last_result).toBe("ok");
  });

  it("a mid-batch fence stops the remaining writes of an accepted batch", async () => {
    const coolify = fakeCoolify();
    await activeTarget(); // two items -> two writes in the first batch
    const target = await (await get(`${ENV_PATH}/sync-targets`)).json();
    const id = target.items[0].id as string;

    // Intents for BOTH names are accepted, the first write lands, and then
    // the destination changes. The per-request cancellation check must stop
    // the second write instead of letting the accepted batch keep sending.
    let writesSent = 0;
    const fetchImpl = (async (url: unknown, init?: RequestInit) => {
      const res = await coolify.fetchImpl(url as string, init);
      const method = init?.method ?? "GET";
      if (String(url).endsWith("/envs") && (method === "POST" || method === "PATCH")) {
        writesSent += 1;
        if (writesSent === 1) {
          const patched = await patchReq(`${ENV_PATH}/sync-targets/${id}`, {
            expectedVersion: target.items[0].version,
            destination: { applicationUuid: "app2" },
          });
          expect(patched.status).toBe(200);
        }
      }
      return res;
    }) as typeof fetch;

    await reconcileTarget(ctx, id, { fetchImpl });
    expect(writesSent).toBe(1);

    // The run recorded nothing after the fence and the successor converges
    // everything to the new destination.
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    const row = await targetRowFromDb();
    expect(row.last_result).toBe("ok");
    expect(coolify.values().get("DATABASE_URL")).toBe("postgres://dev-db/main");
    expect(coolify.values().get("PORT")).toBe("8080");
  });

  it("redeploy fires only on pushes that changed ledger content", async () => {
    const coolify = fakeCoolify();
    await activeTarget({ redeploy: true });
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.restarts()).toBe(1);
    // A converged pass changes nothing and must not restart the app.
    await ctx.db.query("UPDATE sync_targets SET needs_sync = true");
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.restarts()).toBe(1);
  });

  it("a failed redeploy shows in last_result without degrading the Target", async () => {
    const coolify = fakeCoolify();
    await activeTarget({ redeploy: true });
    // An instance that rejects the action (e.g. wrong token ability): the
    // values landed, so the push is ok — but the operator must see that the
    // running app was not redeployed.
    const fetchImpl = (async (url: unknown, init?: RequestInit) => {
      if (String(url).endsWith("/start?force=true")) {
        return new Response(JSON.stringify({ message: "nope" }), { status: 403 });
      }
      return coolify.fetchImpl(url as string, init);
    }) as typeof fetch;
    await runSyncOnce(ctx, { fetchImpl });
    const row = await targetRowFromDb();
    expect(row.last_result).toBe("ok; redeploy failed (Coolify deploy failed (403))");
    expect(row.failure_count).toBe(0);
    expect(coolify.values().get("PORT")).toBe("8080");
  });

  it("a fence during the batch's final write suppresses the redeploy", async () => {
    const coolify = fakeCoolify();
    await activeTarget({
      redeploy: true,
      mapping: { kind: "explicit", items: [{ name: "PORT" }] },
    });
    const target = await (await get(`${ENV_PATH}/sync-targets`)).json();
    const id = target.items[0].id as string;

    // The only write of the batch completes, and the destination changes in
    // its shadow: outcome counts look complete, so only the pre-redeploy
    // probe can notice — the old app must not be restarted.
    const fetchImpl = (async (url: unknown, init?: RequestInit) => {
      const res = await coolify.fetchImpl(url as string, init);
      const method = init?.method ?? "GET";
      if (String(url).endsWith("/envs") && (method === "POST" || method === "PATCH")) {
        const patched = await patchReq(`${ENV_PATH}/sync-targets/${id}`, {
          expectedVersion: target.items[0].version,
          destination: { applicationUuid: "app2" },
        });
        expect(patched.status).toBe(200);
      }
      return res;
    }) as typeof fetch;

    await reconcileTarget(ctx, id, { fetchImpl });
    expect(coolify.restarts()).toBe(0);
  });

  it("a failed fence probe reschedules the work instead of abandoning it", async () => {
    const coolify = fakeCoolify();
    await activeTarget();
    const target = await (await get(`${ENV_PATH}/sync-targets`)).json();
    const id = target.items[0].id as string;

    // The cancellation probe errors (db hiccup): the run must stop sending
    // — but the generation never moved, so no successor exists and the
    // work must be rescheduled, not silently dropped with needs_sync off.
    let flaky = true;
    const flakyCtx = {
      ...ctx,
      db: {
        query: (text: string, params?: unknown[]) =>
          flaky && text === "SELECT generation FROM sync_targets WHERE id = $1"
            ? Promise.reject(new Error("db hiccup"))
            : ctx.db.query(text, params),
      },
    };
    await reconcileTarget(flakyCtx, id, { fetchImpl: coolify.fetchImpl });
    expect(
      coolify.calls.filter((c) => c.method === "POST" || c.method === "PATCH"),
    ).toHaveLength(0);
    const row = await targetRowFromDb();
    expect(row.failure_count).toBe(1);
    expect(row.needs_sync).toBe(true);
    expect(row.last_result).toBe("interrupted mid-run; retrying");
    expect(row.next_attempt_at).not.toBeNull();

    // The rescheduled retry succeeds once the probe works again.
    flaky = false;
    await ctx.db.query("UPDATE sync_targets SET next_attempt_at = NULL");
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect((await targetRowFromDb()).last_result).toBe("ok");
    expect(coolify.values().get("PORT")).toBe("8080");
  });

  it("read-back repair adopts already-matching names into the ledger", async () => {
    const coolify = fakeCoolify();
    // The remote already holds exactly the desired values (a crashed run's
    // unconfirmed write, or an identical out-of-band copy).
    coolify.seed("DATABASE_URL", "postgres://dev-db/main");
    coolify.seed("PORT", "8080");
    await activeTarget({ removeOrphans: true });
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });

    // Nothing was written over the wire...
    expect(coolify.calls.filter((c) => c.method === "POST" || c.method === "PATCH")).toHaveLength(0);
    // ...but ownership is recorded, so later removal still applies.
    const ledger = await ctx.db.query("SELECT dest_name, state FROM sync_ledger ORDER BY dest_name");
    expect(ledger.rows).toEqual([
      { dest_name: "DATABASE_URL", state: "written" },
      { dest_name: "PORT", state: "written" },
    ]);

    await del(`${ENV_PATH}/values/PORT`);
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.values().has("PORT")).toBe(false);
  });

  it("an item that became a Secret leaves an explicit target's disclosure set", async () => {
    const coolify = fakeCoolify();
    await activeTarget({
      mapping: { kind: "explicit", items: [{ name: "PORT" }] },
    });
    // Simulate PORT having been mapped while non-sensitive (no contract =>
    // everything is sensitive, so force the stored affirmation off).
    await ctx.db.query(
      `UPDATE sync_targets SET mapping = '{"kind":"explicit","items":[{"name":"PORT","secretAffirmed":false}]}'`,
    );
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.values().has("PORT")).toBe(false);
    const row = await targetRowFromDb();
    expect(String(row.last_result)).toContain("re-affirmation required");

    // Re-affirming is a widening: PATCH with the same mapping under an
    // actor holding secret.reveal restores the pushes.
    const target = await (await get(`${ENV_PATH}/sync-targets`)).json();
    const res = await patchReq(`${ENV_PATH}/sync-targets/${target.items[0].id}`, {
      expectedVersion: target.items[0].version,
      mapping: { kind: "explicit", items: [{ name: "PORT" }] },
    });
    expect(res.status).toBe(200);
    expect((await res.json()).mapping.items[0].secretAffirmed).toBe(true);
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.values().get("PORT")).toBe("8080");
  });

  it("destination change resets the ledger and abandons the old copy", async () => {
    const coolify = fakeCoolify();
    await activeTarget();
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    const target = await (await get(`${ENV_PATH}/sync-targets`)).json();
    const res = await patchReq(`${ENV_PATH}/sync-targets/${target.items[0].id}`, {
      expectedVersion: target.items[0].version,
      destination: { applicationUuid: "app2" },
    });
    expect(res.status).toBe(200);
    const ledger = await ctx.db.query("SELECT * FROM sync_ledger");
    expect(ledger.rows).toHaveLength(0);
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    // Full write to the new destination even though values are identical.
    expect(
      coolify.calls.some(
        (c) =>
          c.url.includes("/applications/app2/envs") &&
          (c.method === "POST" || c.method === "PATCH"),
      ),
    ).toBe(true);
  });
});

describe("credential replacement", () => {
  it("re-authorizes every referencing target atomically and enqueues reconvergence", async () => {
    const connection = await (await createConnection()).json();
    await createTarget(connection.id);
    const replaced = await post(
      `/v1/organizations/acme/platform-connections/${connection.id}/credential`,
      { credential: "coolify-token-v2", expectedVersion: 1 },
    );
    expect(replaced.status).toBe(200);
    expect((await targetRowFromDb()).needs_sync).toBe(true);
    const audit = await ctx.db.query(
      "SELECT id FROM audit_events WHERE event_type = 'sync.connection_credential_replaced'",
    );
    expect(audit.rows).toHaveLength(1);
  });

  it("is refused wholesale when the actor lacks authority for any referencing target", async () => {
    const connection = await (await createConnection()).json();
    await createTarget(connection.id);
    const svc = await (
      await post("/v1/organizations/acme/identities", { name: "runner", kind: "service" })
    ).json();
    await post("/v1/organizations/acme/grants", {
      subjectIdentityId: svc.id,
      scope: { kind: "organization" },
      actions: ["config.sync.manage", "organization.read"],
    });
    const denied = await post(
      `/v1/organizations/acme/platform-connections/${connection.id}/credential`,
      { credential: "stolen", expectedVersion: 1 },
      svc.credential,
    );
    expect(denied.status).toBe(403);
    // Old credential intact.
    const row = await ctx.db.query("SELECT version FROM platform_connections");
    expect((row.rows[0] as { version: number }).version).toBe(1);
  });
});

describe("access check (ADR-0031 amendment 2026-10-09)", () => {
  const CHECK = "/v1/organizations/acme/platform-connections/check";

  /** A Coolify instance that knows one application and records who asked. */
  function fakeInstance() {
    const calls: { method: string; url: string; authorization: string }[] = [];
    const fetchImpl = (async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      const headers = (init?.headers ?? {}) as Record<string, string>;
      calls.push({ method: init?.method ?? "GET", url, authorization: headers.Authorization ?? "" });
      if (headers.Authorization === "Bearer wrong") return new Response(JSON.stringify({ message: "Unauthenticated." }), { status: 401 });
      if (url.endsWith("/api/v1/version")) return new Response("4.0.0", { status: 200 });
      if (url.endsWith("/api/v1/applications/app1")) return new Response(JSON.stringify({ uuid: "app1" }), { status: 200 });
      return new Response(JSON.stringify({ message: "Application not found" }), { status: 404 });
    }) as typeof fetch;
    return { fetchImpl, calls };
  }

  async function check(body: unknown, checkApp: ReturnType<typeof buildApp>, token = adminToken) {
    return checkApp.request(CHECK, { method: "POST", headers: auth(token), body: JSON.stringify(body) });
  }

  async function checkedEvents() {
    const res = await ctx.db.query(
      "SELECT resource, metadata FROM audit_events WHERE event_type = 'sync.connection_checked' ORDER BY event_order",
    );
    return res.rows.map((r) => ({
      resource: asJson<Record<string, string> | null>((r as { resource: unknown }).resource),
      metadata: asJson<Record<string, unknown>>((r as { metadata: unknown }).metadata),
    }));
  }

  it("checks a credential before it is saved, read-only, and audits the outcome without it", async () => {
    const instance = fakeInstance();
    const checkApp = buildApp(ctx, { syncFetch: instance.fetchImpl });
    const res = await check(
      {
        platform: "coolify",
        baseIdentity: "https://Coolify.example.com/",
        credential: "fresh-token",
        destination: { applicationUuid: "app1", buildTime: "true" },
      },
      checkApp,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect((await res.json()).status).toBe("ok");
    expect(instance.calls.map((c) => [c.method, c.url, c.authorization])).toEqual([
      ["GET", "https://coolify.example.com/api/v1/version", "Bearer fresh-token"],
      ["GET", "https://coolify.example.com/api/v1/applications/app1", "Bearer fresh-token"],
    ]);
    // Nothing is stored.
    expect((await ctx.db.query("SELECT id FROM platform_connections")).rows).toHaveLength(0);
    const events = await checkedEvents();
    expect(events).toHaveLength(1);
    expect(events[0]!.metadata).toMatchObject({
      platform: "coolify",
      baseIdentity: "https://coolify.example.com",
      destination: "coolify:app1",
      credential: "supplied",
      status: "ok",
    });
    expect(JSON.stringify(events)).not.toContain("fresh-token");
  });

  it("checks a stored credential, or a replacement for it, against the connection's own base", async () => {
    const instance = fakeInstance();
    const checkApp = buildApp(ctx, { syncFetch: instance.fetchImpl });
    const connection = await (await createConnection()).json();

    const stored = await check({ connectionId: connection.id, destination: { applicationUuid: "app1" } }, checkApp);
    expect((await stored.json()).status).toBe("ok");
    expect(instance.calls.every((c) => c.authorization === "Bearer coolify-token-123")).toBe(true);

    const replacement = await check({ connectionId: connection.id, credential: "wrong" }, checkApp);
    expect(await replacement.json()).toMatchObject({ status: "credential-rejected", httpStatus: 401 });
    expect(instance.calls.at(-1)!.url).toBe("https://coolify.example.com/api/v1/version");

    const events = await checkedEvents();
    expect(events.map((e) => [e.resource?.connectionId, e.metadata.credential, e.metadata.status])).toEqual([
      [connection.id, "stored", "ok"],
      [connection.id, "supplied", "credential-rejected"],
    ]);
  });

  it("reports what the platform found without failing the request", async () => {
    const checkApp = buildApp(ctx, { syncFetch: fakeInstance().fetchImpl });
    const res = await check(
      { platform: "coolify", baseIdentity: "https://coolify.example.com", credential: "tok", destination: { applicationUuid: "app9" } },
      checkApp,
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toMatchObject({ status: "not-found", httpStatus: 404 });
    expect(body.message).not.toContain("Application not found");
  });

  it("validates the request like creation does", async () => {
    const checkApp = buildApp(ctx, { syncFetch: fakeInstance().fetchImpl });
    const connection = await (await createConnection()).json();
    const statuses = await Promise.all(
      [
        { connectionId: connection.id, platform: "coolify", baseIdentity: "https://coolify.example.com" },
        { platform: "coolify", baseIdentity: "https://coolify.example.com" },
        { platform: "coolify", baseIdentity: "http://coolify.example.com", credential: "tok" },
        { platform: "generic-url", baseIdentity: "https://x.example.com", credential: "tok" },
        { connectionId: connection.id, destination: { applicationUuid: "../../etc" } },
      ].map(async (body) => (await check(body, checkApp)).status),
    );
    expect(statuses).toEqual([422, 422, 422, 422, 422]);
    expect((await check({ connectionId: "pcn_missing" }, checkApp)).status).toBe(404);
    expect(await checkedEvents()).toHaveLength(0);
  });

  it("needs config.sync.manage, a sync-enabled installation, and an allowed adapter", async () => {
    const instance = fakeInstance();
    const svc = await (await post("/v1/organizations/acme/identities", { name: "reader", kind: "service" })).json();
    await post("/v1/organizations/acme/grants", {
      subjectIdentityId: svc.id,
      scope: { kind: "organization" },
      actions: ["organization.read"],
    });
    const body = { platform: "coolify", baseIdentity: "https://coolify.example.com", credential: "tok" };
    expect((await check(body, buildApp(ctx, { syncFetch: instance.fetchImpl }), svc.credential)).status).toBe(403);
    expect((await check(body, buildApp(ctx, { sync: null, syncFetch: instance.fetchImpl }))).status).toBe(403);
    expect(
      (await check(body, buildApp(ctx, { sync: { adapters: ["github-actions"] }, syncFetch: instance.fetchImpl }))).status,
    ).toBe(422);
    expect(instance.calls).toHaveLength(0);
  });
});

describe("installation switch", () => {
  it("disabling sync hides the capability and blocks creation, not visibility", async () => {
    const offApp = buildApp(ctx, { sync: null });
    const meta = await (await offApp.request("/v1/meta")).json();
    expect(meta.capabilities).not.toContain("sync.targets");
    expect(meta.syncAdapters).toBeUndefined();
    const res = await offApp.request("/v1/organizations/acme/platform-connections", {
      method: "POST",
      headers: auth(),
      body: JSON.stringify({
        platform: "coolify",
        baseIdentity: "https://coolify.example.com",
        name: "x",
        credential: "tok",
      }),
    });
    expect(res.status).toBe(403);
    expect((await res.json()).error.message).toContain("CLI mode");
    const list = await offApp.request("/v1/organizations/acme/platform-connections", { headers: auth() });
    expect(list.status).toBe(200);
  });

  it("narrowing the adapter allowlist rejects other platforms at creation", async () => {
    const narrowApp = buildApp(ctx, { sync: { adapters: ["github-actions"] } });
    const meta = await (await narrowApp.request("/v1/meta")).json();
    expect(meta.syncAdapters).toEqual(["github-actions"]);
    const res = await narrowApp.request("/v1/organizations/acme/platform-connections", {
      method: "POST",
      headers: auth(),
      body: JSON.stringify({
        platform: "coolify",
        baseIdentity: "https://coolify.example.com",
        name: "x",
        credential: "tok",
      }),
    });
    expect(res.status).toBe(422);
  });
});

describe("wildcard exclusion widening (ADR-0031 amendment)", () => {
  const explicit = {
    kind: "explicit" as const,
    items: [{ name: "PORT", secretAffirmed: false }],
  };
  it("removing or rewriting an exclusion entry widens; adding narrows", () => {
    const base = { kind: "wildcard" as const, exclude: ["CONVEX_*", "SECRET_A"] };
    expect(mappingWidens(base, { kind: "wildcard", exclude: ["CONVEX_*"] })).toBe(true);
    expect(mappingWidens(base, { kind: "wildcard", exclude: ["CONVEX_*", "SECRET_A", "MORE"] })).toBe(false);
    expect(mappingWidens(base, { kind: "wildcard", exclude: ["CONVEX_X*", "SECRET_A"] })).toBe(true);
    expect(mappingWidens(base, { kind: "wildcard" })).toBe(true);
    expect(mappingWidens({ kind: "wildcard" }, base)).toBe(false);
  });
  it("kind transitions gate like plain wildcard", () => {
    expect(mappingWidens(explicit, { kind: "wildcard", exclude: ["CONVEX_*"] })).toBe(true);
    expect(mappingWidens({ kind: "wildcard", exclude: ["CONVEX_*"] }, explicit)).toBe(false);
  });
});
