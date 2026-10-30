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
import { recordAuditEvent } from "../src/audit/events.js";
import { SEND_CHECK_SQL, ledgerSet, reconcileTarget, runSyncOnce, scanSyncTriggers } from "../src/domain/syncdelivery.js";
import { mappingWidens, recordCredentialExpiry } from "../src/domain/sync.js";
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
  type Row = { uuid: string; key: string; value: string } & Record<string, unknown>;
  const store = new Map<string, Row>();
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
      const b = body as { key: string; value: string } & Record<string, unknown>;
      const existing = [...store.values()].find((e) => e.key === b.key);
      const uuid = existing?.uuid ?? `env${nextUuid++}`;
      // A PATCH keeps the flags it is not sent, as Coolify's does.
      store.set(uuid, { ...(existing ?? {}), ...b, uuid, key: b.key, value: b.value });
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
    seed: (key: string, value: string, flags: Record<string, boolean> = {}) => {
      const uuid = `seed${nextUuid++}`;
      store.set(uuid, { uuid, key, value, ...flags });
    },
    row: (key: string) => [...store.values()].find((e) => e.key === key),
    remove: (key: string) => {
      for (const [uuid, e] of store) if (e.key === key) store.delete(uuid);
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
    // The admin passed through the built-in role, with no Grant: the role is recorded, not just an empty list.
    expect(authz).toEqual({
      "secret.reveal": { role: "admin", grantIds: [], requirements: [] },
      "config.value.read": { role: "admin", grantIds: [], requirements: [] },
    });
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

  it("reads and validation mark no Target; a denied write neither; a write does (#59)", async () => {
    const coolify = fakeCoolify();
    // A Contract with a Secret and a plain item, so validation reports on both.
    const revision = await (
      await post("/v1/organizations/acme/projects/api/contract/revisions", {
        contract: {
          schemaVersion: 1,
          items: [
            { name: "DATABASE_URL", required: { kind: "never" }, sensitive: true, type: "string" },
            { name: "PORT", required: { kind: "never" }, sensitive: false, type: "string" },
          ],
        },
      })
    ).json();
    expect((await post(`/v1/organizations/acme/projects/api/contract/revisions/${revision.id}/activate`, {})).status).toBe(200);
    await activeTarget();
    await scanSyncTriggers(ctx);
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    await scanSyncTriggers(ctx);
    expect((await targetRowFromDb()).needs_sync).toBe(false);
    // Strict retrieval (value.disclosed and secret.disclosed), the
    // effective values read, and a validation verdict.
    expect((await post(`${ENV_PATH}/disclosures`, { items: ["DATABASE_URL", "PORT"] })).status).toBe(200);
    expect((await get(`${ENV_PATH}/effective-configuration?include=values`)).status).toBe(200);
    expect((await post(`${ENV_PATH}/validate`, {})).status).toBe(200);
    const reads = await ctx.db.query(
      "SELECT DISTINCT event_type FROM audit_events WHERE event_type IN ('value.disclosed', 'secret.disclosed', 'value.validated', 'secret.validated') ORDER BY event_type",
    );
    expect(reads.rows.map((r) => (r as { event_type: string }).event_type)).toEqual(["secret.disclosed", "secret.validated", "value.disclosed", "value.validated"]);
    await scanSyncTriggers(ctx);
    expect((await targetRowFromDb()).needs_sync).toBe(false);
    // A denied action changed nothing.
    const env = (await ctx.db.query("SELECT e.id, p.organization_id FROM environments e JOIN projects p ON p.id = e.project_id WHERE e.name = 'development'")).rows[0] as { id: string; organization_id: string };
    await recordAuditEvent(ctx.db, { eventType: "value.written", decision: "deny", organizationId: env.organization_id, resource: { environmentId: env.id } });
    await scanSyncTriggers(ctx);
    expect((await targetRowFromDb()).needs_sync).toBe(false);
    await put(`${ENV_PATH}/values/PORT`, { value: "9191" });
    await scanSyncTriggers(ctx);
    expect((await targetRowFromDb()).needs_sync).toBe(true);
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

  it("a pause mid-batch stops the remaining writes, records no result, and leaves the Target paused (ADR-0050)", async () => {
    const coolify = fakeCoolify();
    await activeTarget(); // two items -> two writes in the first batch
    const target = await (await get(`${ENV_PATH}/sync-targets`)).json();
    const id = target.items[0].id as string;

    let writesSent = 0;
    const fetchImpl = (async (url: unknown, init?: RequestInit) => {
      const res = await coolify.fetchImpl(url as string, init);
      const method = init?.method ?? "GET";
      if (String(url).endsWith("/envs") && (method === "POST" || method === "PATCH")) {
        writesSent += 1;
        if (writesSent === 1) expect((await post(`${ENV_PATH}/sync-targets/${id}/pause`, {})).status).toBe(200);
      }
      return res;
    }) as typeof fetch;

    await reconcileTarget(ctx, id, { fetchImpl });
    expect(writesSent).toBe(1);
    const events = await ctx.db.query(
      "SELECT event_type FROM audit_events WHERE event_type LIKE 'sync.%' ORDER BY event_order",
    );
    const types = events.rows.map((r) => (r as { event_type: string }).event_type);
    // Nothing the fenced run did is recorded after the pause.
    expect(types.slice(types.indexOf("sync.target_paused"))).toEqual(["sync.target_paused"]);
    const row = await targetRowFromDb();
    expect(row.state).toBe("paused");
    expect(row.failure_count).toBe(0);
  });

  it("a pause during the final write suppresses the result event and the redeploy", async () => {
    const coolify = fakeCoolify();
    await activeTarget({ redeploy: true, mapping: { kind: "explicit", items: [{ name: "PORT" }] } });
    const target = await (await get(`${ENV_PATH}/sync-targets`)).json();
    const id = target.items[0].id as string;
    const fetchImpl = (async (url: unknown, init?: RequestInit) => {
      const res = await coolify.fetchImpl(url as string, init);
      const method = init?.method ?? "GET";
      if (String(url).endsWith("/envs") && (method === "POST" || method === "PATCH")) {
        expect((await post(`${ENV_PATH}/sync-targets/${id}/pause`, {})).status).toBe(200);
      }
      return res;
    }) as typeof fetch;

    await reconcileTarget(ctx, id, { fetchImpl });
    expect(coolify.restarts()).toBe(0);
    const results = await ctx.db.query("SELECT 1 FROM audit_events WHERE event_type = 'sync.push_result'");
    expect(results.rows).toHaveLength(0);
  });

  it("revoking a Target fences a run in progress", async () => {
    const coolify = fakeCoolify();
    await activeTarget();
    const target = await (await get(`${ENV_PATH}/sync-targets`)).json();
    const id = target.items[0].id as string;
    let writesSent = 0;
    const fetchImpl = (async (url: unknown, init?: RequestInit) => {
      const res = await coolify.fetchImpl(url as string, init);
      const method = init?.method ?? "GET";
      if (String(url).endsWith("/envs") && (method === "POST" || method === "PATCH")) {
        writesSent += 1;
        if (writesSent === 1) expect((await del(`${ENV_PATH}/sync-targets/${id}`)).status).toBe(204);
      }
      return res;
    }) as typeof fetch;
    await reconcileTarget(ctx, id, { fetchImpl });
    expect(writesSent).toBe(1);
  });

  it("pausing a paused Target changes nothing, and a disabled Target cannot be paused", async () => {
    await activeTarget();
    const target = await (await get(`${ENV_PATH}/sync-targets`)).json();
    const id = target.items[0].id as string;
    expect((await post(`${ENV_PATH}/sync-targets/${id}/pause`, {})).status).toBe(200);
    const fenced = (await targetRowFromDb()).generation;
    expect((await post(`${ENV_PATH}/sync-targets/${id}/pause`, {})).status).toBe(200);
    expect((await targetRowFromDb()).generation).toBe(fenced);
    const pauses = await ctx.db.query("SELECT 1 FROM audit_events WHERE event_type = 'sync.target_paused'");
    expect(pauses.rows).toHaveLength(1);

    await ctx.db.query("UPDATE sync_targets SET state = 'disabled', disabled_reason = 'connection-revoked'");
    const refused = await post(`${ENV_PATH}/sync-targets/${id}/pause`, {});
    expect(refused.status).toBe(422);
    expect((await targetRowFromDb()).state).toBe("disabled");
  });

  it("registers each run with a deadline and removes it when the run ends (ADR-0050)", async () => {
    const coolify = fakeCoolify();
    await activeTarget();
    const id = ((await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0].id) as string;
    let live = 0;
    const fetchImpl = (async (url: unknown, init?: RequestInit) => {
      const rows = await ctx.db.query("SELECT 1 FROM sync_runs WHERE target_id = $1 AND deadline > now()", [id]);
      live = Math.max(live, rows.rows.length);
      return coolify.fetchImpl(url as string, init);
    }) as typeof fetch;
    await reconcileTarget(ctx, id, { fetchImpl });
    expect(live).toBe(1);
    expect((await ctx.db.query("SELECT 1 FROM sync_runs")).rows).toHaveLength(0);
    const listed = await (await get(`${ENV_PATH}/sync-targets`)).json();
    expect(listed.items[0]).toMatchObject({ drained: true, runStartedAt: null });
  });

  it("a run past its deadline sends no further request and yields without counting a failure", async () => {
    const coolify = fakeCoolify();
    await activeTarget(); // two items -> two writes
    const id = ((await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0].id) as string;
    let writesSent = 0;
    const fetchImpl = (async (url: unknown, init?: RequestInit) => {
      const res = await coolify.fetchImpl(url as string, init);
      const method = init?.method ?? "GET";
      if (String(url).endsWith("/envs") && (method === "POST" || method === "PATCH")) {
        writesSent += 1;
        // The budget runs out between the two writes (database clock).
        if (writesSent === 1) await ctx.db.query("UPDATE sync_runs SET deadline = now() - interval '1 second'");
      }
      return res;
    }) as typeof fetch;
    await reconcileTarget(ctx, id, { fetchImpl });
    expect(writesSent).toBe(1);
    const row = await targetRowFromDb();
    expect(row.failure_count).toBe(0);
    expect(row.needs_sync).toBe(true);
    expect(row.state).toBe("active");
    expect((await ctx.db.query("SELECT 1 FROM audit_events WHERE event_type = 'sync.push_result'")).rows).toHaveLength(0);

    // The follow-up run finishes the work.
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect((await targetRowFromDb()).last_result).toBe("ok");
    expect(coolify.values().get("PORT")).toBe("8080");
  });

  it("a run whose expired row was already cleaned up still yields, not fails", async () => {
    const coolify = fakeCoolify();
    await activeTarget();
    const id = ((await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0].id) as string;
    let writesSent = 0;
    const fetchImpl = (async (url: unknown, init?: RequestInit) => {
      const res = await coolify.fetchImpl(url as string, init);
      const method = init?.method ?? "GET";
      if (String(url).endsWith("/envs") && (method === "POST" || method === "PATCH")) {
        writesSent += 1;
        if (writesSent === 1) {
          // The budget runs out, and another process's tick removes the row
          // before this run classifies how it ended.
          await new Promise((resolve) => setTimeout(resolve, 400));
          await ctx.db.query("DELETE FROM sync_runs WHERE deadline <= now()");
        }
      }
      return res;
    }) as typeof fetch;
    await reconcileTarget(ctx, id, { fetchImpl, runBudgetSeconds: 0.3 });
    const row = await targetRowFromDb();
    expect(row.failure_count).toBe(0);
    expect(row.needs_sync).toBe(true);
    expect(row.next_attempt_at).toBeNull();
  });

  it("a forced repair larger than one budget completes over several runs (ADR-0050 repair cycles)", async () => {
    const coolify = fakeCoolify();
    await activeTarget(); // first sync is forced: no repair yet
    const id = ((await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0].id) as string;
    const written: string[] = [];
    let cutAfterFirst = true;
    const fetchImpl = (async (url: unknown, init?: RequestInit) => {
      const res = await coolify.fetchImpl(url as string, init);
      const method = init?.method ?? "GET";
      if (String(url).endsWith("/envs") && (method === "POST" || method === "PATCH")) {
        written.push(String((JSON.parse(String(init?.body)) as { key: string }).key));
        if (cutAfterFirst) {
          cutAfterFirst = false;
          await ctx.db.query("UPDATE sync_runs SET deadline = now() - interval '1 second'");
        }
      }
      return res;
    }) as typeof fetch;
    await reconcileTarget(ctx, id, { fetchImpl });
    expect(written).toHaveLength(1);
    let row = await targetRowFromDb();
    expect(row.repair_cycle_started_at).not.toBeNull();
    expect(row.last_repair_at).toBeNull();
    expect(row.failure_count).toBe(0);

    // The continuation writes only what the first run did not, and closes the cycle.
    await runSyncOnce(ctx, { fetchImpl });
    expect(written).toHaveLength(2);
    expect(new Set(written).size).toBe(2);
    row = await targetRowFromDb();
    expect(row.repair_cycle_started_at).toBeNull();
    expect(row.last_repair_at).not.toBeNull();
    expect(row.last_result).toBe("ok");
  });

  it("a value changed during an open repair cycle is still pushed by the next run", async () => {
    const coolify = fakeCoolify();
    await activeTarget();
    const id = ((await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0].id) as string;
    let cut = true;
    const fetchImpl = (async (url: unknown, init?: RequestInit) => {
      const res = await coolify.fetchImpl(url as string, init);
      const method = init?.method ?? "GET";
      if (cut && String(url).endsWith("/envs") && (method === "POST" || method === "PATCH")) {
        cut = false;
        await ctx.db.query("UPDATE sync_runs SET deadline = now() - interval '1 second'");
      }
      return res;
    }) as typeof fetch;
    await reconcileTarget(ctx, id, { fetchImpl });
    // Both names change while the cycle is open; the credited one too.
    await put(`${ENV_PATH}/values/PORT`, { value: "9090" });
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.values().get("PORT")).toBe("9090");
    expect((await targetRowFromDb()).repair_cycle_started_at).toBeNull();
  });

  it("counts a run as live until its deadline, and the sync loop removes expired rows", async () => {
    await activeTarget();
    const id = ((await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0].id) as string;
    await ctx.db.query(
      "INSERT INTO sync_runs (target_id, generation, deadline) VALUES ($1, 999, now() + interval '1 hour')",
      [id],
    );
    let listed = await (await get(`${ENV_PATH}/sync-targets`)).json();
    expect(listed.items[0].drained).toBe(false);
    expect(listed.items[0].runStartedAt).not.toBeNull();
    // A process that died mid-run: its row stops counting at its deadline.
    await ctx.db.query("UPDATE sync_runs SET deadline = now() - interval '1 second'");
    listed = await (await get(`${ENV_PATH}/sync-targets`)).json();
    expect(listed.items[0]).toMatchObject({ drained: true, runStartedAt: null });
    await runSyncOnce(ctx, { fetchImpl: fakeCoolify().fetchImpl });
    expect((await ctx.db.query("SELECT 1 FROM sync_runs")).rows).toHaveLength(0);
  });

  it("pause?wait=true answers once the Target is drained", async () => {
    await activeTarget();
    const id = ((await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0].id) as string;
    await ctx.db.query(
      "INSERT INTO sync_runs (target_id, generation, deadline) VALUES ($1, 999, now() + interval '700 milliseconds')",
      [id],
    );
    const started = Date.now();
    const res = await post(`${ENV_PATH}/sync-targets/${id}/pause?wait=true`, {});
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ state: "paused", drained: true });
    expect(Date.now() - started).toBeGreaterThanOrEqual(400);
    // Asked again, with nothing running: at once, and still paused.
    const again = await post(`${ENV_PATH}/sync-targets/${id}/pause?wait=true`, {});
    expect(await again.json()).toMatchObject({ state: "paused", drained: true });
  });

  it("revoking a Connection fences the runs of the Targets it disables", async () => {
    await activeTarget();
    const target = (await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0];
    const before = Number((await targetRowFromDb()).generation);
    expect((await del(`/v1/organizations/acme/platform-connections/${target.connectionId}`)).status).toBe(204);
    const row = await targetRowFromDb();
    expect(row.state).toBe("disabled");
    expect(Number(row.generation)).toBe(before + 1);
    expect(row.lease_expires_at).toBeNull();
  });

  describe("owed redeploys (ADR-0050 Decision 4)", () => {
    const debt = async () => {
      const row = await targetRowFromDb();
      return { owed: Number(row.redeploy_owed), paid: Number(row.redeploy_paid) };
    };
    const cutAfterWrite = (coolify: ReturnType<typeof fakeCoolify>, which: number) => {
      let writes = 0;
      return (async (url: unknown, init?: RequestInit) => {
        const res = await coolify.fetchImpl(url as string, init);
        const method = init?.method ?? "GET";
        if (String(url).endsWith("/envs") && (method === "POST" || method === "PATCH")) {
          writes += 1;
          if (writes === which) await ctx.db.query("UPDATE sync_runs SET deadline = now() - interval '1 second'");
        }
        return res;
      }) as typeof fetch;
    };

    it("a run cut off after a changing write still gets its redeploy, from the next run", async () => {
      const coolify = fakeCoolify();
      await activeTarget({ redeploy: true });
      const id = ((await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0].id) as string;
      await reconcileTarget(ctx, id, { fetchImpl: cutAfterWrite(coolify, 1) });
      expect(coolify.restarts()).toBe(0);
      expect((await debt()).owed).toBeGreaterThan((await debt()).paid);
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      expect(coolify.restarts()).toBe(1);
      const after = await debt();
      expect(after.paid).toBe(after.owed);
    });

    it("a redeploy aborted by the deadline sends nothing and stays owed", async () => {
      const coolify = fakeCoolify();
      await activeTarget({ redeploy: true });
      const id = ((await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0].id) as string;
      // Both writes land, then the budget runs out before the redeploy.
      await reconcileTarget(ctx, id, { fetchImpl: cutAfterWrite(coolify, 2) });
      expect(coolify.restarts()).toBe(0);
      expect((await targetRowFromDb()).failure_count).toBe(0);
      // A later run with nothing to write pays it.
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      expect(coolify.restarts()).toBe(1);
      await ctx.db.query("UPDATE sync_targets SET needs_sync = true");
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      expect(coolify.restarts()).toBe(1);
    });

    it("a refused redeploy stays owed and is tried again", async () => {
      const coolify = fakeCoolify();
      await activeTarget({ redeploy: true });
      let refuse = true;
      const fetchImpl = (async (url: unknown, init?: RequestInit) => {
        if (refuse && String(url).endsWith("/start?force=true")) return new Response("{}", { status: 403 });
        return coolify.fetchImpl(url as string, init);
      }) as typeof fetch;
      await runSyncOnce(ctx, { fetchImpl });
      expect((await targetRowFromDb()).last_result).toMatch(/redeploy failed/);
      expect((await debt()).owed).toBeGreaterThan((await debt()).paid);
      refuse = false;
      await ctx.db.query("UPDATE sync_targets SET needs_sync = true");
      await runSyncOnce(ctx, { fetchImpl });
      expect(coolify.restarts()).toBe(1);
      const after = await debt();
      expect(after.paid).toBe(after.owed);
    });

    it("a destination change or turning redeploy off settles the debt without paying it", async () => {
      const coolify = fakeCoolify();
      await activeTarget({ redeploy: true });
      const target = (await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0];
      await reconcileTarget(ctx, target.id, { fetchImpl: cutAfterWrite(coolify, 1) });
      expect((await debt()).owed).toBeGreaterThan((await debt()).paid);
      const off = await patchReq(`${ENV_PATH}/sync-targets/${target.id}`, { expectedVersion: target.version, redeploy: false });
      expect(off.status).toBe(200);
      const settled = await debt();
      expect(settled.paid).toBe(settled.owed);
    });

    it("a change that failed once still owes its redeploy when the retry lands", async () => {
      const coolify = fakeCoolify();
      await activeTarget({ redeploy: true, mapping: { kind: "explicit", items: [{ name: "PORT" }] } });
      let fail = true;
      const fetchImpl = (async (url: unknown, init?: RequestInit) => {
        const method = init?.method ?? "GET";
        if (fail && String(url).endsWith("/envs") && (method === "POST" || method === "PATCH")) {
          return new Response("{}", { status: 500 });
        }
        return coolify.fetchImpl(url as string, init);
      }) as typeof fetch;
      await runSyncOnce(ctx, { fetchImpl });
      expect(coolify.restarts()).toBe(0);
      fail = false;
      await ctx.db.query("UPDATE sync_targets SET next_attempt_at = NULL");
      await runSyncOnce(ctx, { fetchImpl });
      expect(coolify.values().get("PORT")).toBe("8080");
      expect(coolify.restarts()).toBe(1);
    });

    it("a run cut off before its first write leaves the change owing its redeploy", async () => {
      const coolify = fakeCoolify();
      await activeTarget({ redeploy: true });
      const id = ((await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0].id) as string;
      // The budget runs out while the run reads the destination, before any write.
      let cut = true;
      const fetchImpl = (async (url: unknown, init?: RequestInit) => {
        if (cut && (init?.method ?? "GET") === "GET") {
          cut = false;
          await ctx.db.query("UPDATE sync_runs SET deadline = now() - interval '1 second'");
        }
        return coolify.fetchImpl(url as string, init);
      }) as typeof fetch;
      await reconcileTarget(ctx, id, { fetchImpl });
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      expect(coolify.values().get("PORT")).toBe("8080");
      expect(coolify.restarts()).toBe(1);
    });

    it("turning redeploy off during a push fences it: no new debt, no redeploy", async () => {
      const coolify = fakeCoolify();
      await activeTarget({ redeploy: true });
      const target = (await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0];
      let toggled = false;
      const fetchImpl = (async (url: unknown, init?: RequestInit) => {
        const res = await coolify.fetchImpl(url as string, init);
        const method = init?.method ?? "GET";
        if (!toggled && String(url).endsWith("/envs") && (method === "POST" || method === "PATCH")) {
          toggled = true;
          const off = await patchReq(`${ENV_PATH}/sync-targets/${target.id}`, { expectedVersion: target.version, redeploy: false });
          expect(off.status).toBe(200);
        }
        return res;
      }) as typeof fetch;
      await reconcileTarget(ctx, target.id, { fetchImpl });
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      expect(coolify.restarts()).toBe(0);
      const after = await debt();
      expect(after.paid).toBe(after.owed);
    });

    it("a payment settles only the debt it read; a newer one stays owed", async () => {
      const coolify = fakeCoolify();
      await activeTarget({ redeploy: true });
      let bumped = false;
      const fetchImpl = (async (url: unknown, init?: RequestInit) => {
        if (!bumped && String(url).endsWith("/start?force=true")) {
          bumped = true;
          // Another change is confirmed while the redeploy is on its way.
          await ctx.db.query("UPDATE sync_targets SET redeploy_owed = redeploy_owed + 1");
        }
        return coolify.fetchImpl(url as string, init);
      }) as typeof fetch;
      await runSyncOnce(ctx, { fetchImpl });
      expect(coolify.restarts()).toBe(1);
      expect((await debt()).owed).toBe((await debt()).paid + 1);
      await ctx.db.query("UPDATE sync_targets SET needs_sync = true");
      await runSyncOnce(ctx, { fetchImpl });
      expect(coolify.restarts()).toBe(2);
      const after = await debt();
      expect(after.paid).toBe(after.owed);
    });

    it("an owed redeploy survives a pause and is paid after the resume", async () => {
      const coolify = fakeCoolify();
      await activeTarget({ redeploy: true });
      const id = ((await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0].id) as string;
      await reconcileTarget(ctx, id, { fetchImpl: cutAfterWrite(coolify, 2) });
      expect((await debt()).owed).toBeGreaterThan((await debt()).paid);
      expect((await post(`${ENV_PATH}/sync-targets/${id}/pause`, {})).status).toBe(200);
      expect((await post(`${ENV_PATH}/sync-targets/${id}/resume`, {})).status).toBe(200);
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      expect(coolify.restarts()).toBe(1);
    });

    it("owes nothing when the Target does not redeploy", async () => {
      const coolify = fakeCoolify();
      await activeTarget({ redeploy: false });
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      expect(await debt()).toEqual({ owed: 0, paid: 0 });
    });
  });

  describe("drift events (ADR-0050 part B)", () => {
    const repairDue = () =>
      ctx.db.query("UPDATE sync_targets SET last_repair_at = now() - interval '7 hours', needs_sync = true");
    const syncEvents = async () =>
      (await ctx.db.query("SELECT event_type, metadata FROM audit_events WHERE event_type LIKE 'sync.%' ORDER BY event_order")).rows.map(
        (r) => r as { event_type: string; metadata: Record<string, unknown> | string },
      );
    const meta = (m: Record<string, unknown> | string) => (typeof m === "string" ? (JSON.parse(m) as Record<string, unknown>) : m);

    it("names a value changed on the platform before putting it back, names only", async () => {
      const coolify = fakeCoolify();
      await activeTarget();
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      (coolify.row("PORT") as { value: string }).value = "1111";
      await repairDue();
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      expect(coolify.values().get("PORT")).toBe("8080");
      const events = await syncEvents();
      const at = events.findIndex((e) => e.event_type === "sync.drift_detected");
      expect(at).toBeGreaterThan(-1);
      const drift = meta(events[at]!.metadata);
      expect(drift).toMatchObject({ items: "PORT", changed: "PORT", removed: "", recreated: "", count: 1 });
      expect(JSON.stringify(drift)).not.toContain("1111");
      // Recorded before the push that puts it back, and counted in its result.
      expect(events[at + 1]?.event_type).toBe("sync.push_attempted");
      const result = events.filter((e) => e.event_type === "sync.push_result").at(-1)!;
      expect(meta(result.metadata)).toMatchObject({ driftRepaired: 1, driftFailed: 0 });
      const listed = await (await get(`${ENV_PATH}/sync-targets`)).json();
      expect(listed.items[0].lastDrift).toMatchObject({ count: 1, names: ["PORT"] });
    });

    it("names a value removed on the platform, and a deleted name the platform has again", async () => {
      const coolify = fakeCoolify();
      await activeTarget();
      const id = ((await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0].id) as string;
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      coolify.remove("DATABASE_URL");
      await ctx.db.query(
        "INSERT INTO sync_ledger (target_id, dest_name, fingerprint, state, generation) VALUES ($1, 'OLD_KEY', NULL, 'tombstone', 0)",
        [id],
      );
      coolify.seed("OLD_KEY", "back-again", { is_literal: true, is_multiline: true });
      await repairDue();
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      const drift = meta((await syncEvents()).find((e) => e.event_type === "sync.drift_detected")!.metadata);
      expect(drift).toMatchObject({ removed: "DATABASE_URL", recreated: "OLD_KEY", items: "DATABASE_URL", count: 2 });
      expect(coolify.values().get("DATABASE_URL")).toBe("postgres://dev-db/main");
      expect(coolify.values().has("OLD_KEY")).toBe(false);
    });

    it("does not call a first write, a change Varlatch is making, or a converged repair drift", async () => {
      const coolify = fakeCoolify();
      await activeTarget();
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl }); // first writes
      await repairDue();
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl }); // converged repair
      // Varlatch changes PORT, and the platform happens to differ too.
      await put(`${ENV_PATH}/values/PORT`, { value: "9090" });
      (coolify.row("PORT") as { value: string }).value = "1111";
      await repairDue();
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      expect(coolify.values().get("PORT")).toBe("9090");
      expect((await syncEvents()).some((e) => e.event_type === "sync.drift_detected")).toBe(false);
      expect((await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0].lastDrift).toBeNull();
    });

    it("a repair that fails to put drift back reports it as failed, and the drift stays named", async () => {
      const coolify = fakeCoolify();
      await activeTarget();
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      (coolify.row("PORT") as { value: string }).value = "1111";
      coolify.setFailWrites(true);
      await repairDue();
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      const result = (await syncEvents()).filter((e) => e.event_type === "sync.push_result").at(-1)!;
      expect(meta(result.metadata)).toMatchObject({ driftRepaired: 0, driftFailed: 1 });
      expect(coolify.values().get("PORT")).toBe("1111");
      expect((await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0].lastDrift).toMatchObject({ names: ["PORT"] });
    });

    it("a value stored in another form is drift only when the value itself differs", async () => {
      const coolify = fakeCoolify();
      await activeTarget();
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      // Same value, flags lost on the platform: a rewrite, not drift.
      Object.assign(coolify.row("PORT") as object, { is_literal: false, is_multiline: false });
      await repairDue();
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      expect((await syncEvents()).some((e) => e.event_type === "sync.drift_detected")).toBe(false);
      // Flags lost and the value changed: drift.
      Object.assign(coolify.row("PORT") as object, { is_literal: false, is_multiline: false, value: "1111" });
      await repairDue();
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      const drift = (await syncEvents()).find((e) => e.event_type === "sync.drift_detected");
      expect(meta(drift!.metadata)).toMatchObject({ changed: "PORT", count: 1 });
    });

    it("a yielded repair does not report the names it already put back again", async () => {
      const coolify = fakeCoolify();
      await activeTarget();
      const id = ((await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0].id) as string;
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      (coolify.row("PORT") as { value: string }).value = "1111";
      (coolify.row("DATABASE_URL") as { value: string }).value = "postgres://elsewhere";
      await repairDue();
      // The run reports both, puts one back, and runs out of budget.
      let writes = 0;
      const cut = (async (url: unknown, init?: RequestInit) => {
        const res = await coolify.fetchImpl(url as string, init);
        const method = init?.method ?? "GET";
        if (String(url).endsWith("/envs") && (method === "POST" || method === "PATCH") && ++writes === 1) {
          await ctx.db.query("UPDATE sync_runs SET deadline = now() - interval '1 second'");
        }
        return res;
      }) as typeof fetch;
      await reconcileTarget(ctx, id, { fetchImpl: cut });
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      const reports = (await syncEvents()).filter((e) => e.event_type === "sync.drift_detected").map((e) => meta(e.metadata));
      // Reported once, by the run that found it. The continuation does not
      // report it again: the name put back is credited, and the one the cut
      // run had started is ambiguous (intent), which is rewritten without
      // being called drift (ADR-0050 Decision 8).
      expect(reports).toHaveLength(1);
      expect(reports[0]).toMatchObject({ count: 2 });
      expect(coolify.values().get("PORT")).toBe("8080");
      expect(coolify.values().get("DATABASE_URL")).toBe("postgres://dev-db/main");
    });

    it("putting drift back owes a redeploy", async () => {
      const coolify = fakeCoolify();
      await activeTarget({ redeploy: true });
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      expect(coolify.restarts()).toBe(1);
      (coolify.row("PORT") as { value: string }).value = "1111";
      await repairDue();
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      expect(coolify.restarts()).toBe(2);
    });

    it("a destination change clears the last drift", async () => {
      const coolify = fakeCoolify();
      await activeTarget();
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      (coolify.row("PORT") as { value: string }).value = "1111";
      await repairDue();
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
      const target = (await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0];
      expect(target.lastDrift).not.toBeNull();
      const moved = await patchReq(`${ENV_PATH}/sync-targets/${target.id}`, {
        expectedVersion: target.version,
        destination: { applicationUuid: "app2" },
      });
      expect(moved.status).toBe(200);
      expect((await moved.json()).lastDrift).toBeNull();
    });
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
          flaky && text === SEND_CHECK_SQL
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
    const target = await targetRowFromDb();
    expect(target.needs_sync).toBe(true);
    const audit = await ctx.db.query(
      "SELECT id, authz FROM audit_events WHERE event_type = 'sync.connection_credential_replaced'",
    );
    expect(audit.rows).toHaveLength(1);
    // Each re-authorized Target's gate, as it decided.
    const authz = (audit.rows[0] as { authz: { reauthorizedTargets: Record<string, Record<string, { grantIds: string[] }>> } }).authz;
    expect(Object.keys(authz.reauthorizedTargets)).toEqual([target.id]);
    // The admin passed each Target's gate through the built-in role, with no Grant: that is what is recorded.
    expect(authz.reauthorizedTargets[target.id as string]).toEqual({
      "secret.reveal": { role: "admin", grantIds: [], requirements: [] },
      "config.value.read": { role: "admin", grantIds: [], requirements: [] },
    });
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

describe("destination listing (ADR-0031 amendment 2026-10-09)", () => {
  const LIST = "/v1/organizations/acme/platform-connections/destinations";

  /** A Coolify instance with two applications and a service, recording who asked. */
  function fakeInstance() {
    const calls: { method: string; url: string; authorization: string }[] = [];
    const fetchImpl = (async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      const headers = (init?.headers ?? {}) as Record<string, string>;
      calls.push({ method: init?.method ?? "GET", url, authorization: headers.Authorization ?? "" });
      if (headers.Authorization === "Bearer wrong") return new Response(JSON.stringify({ message: "Unauthenticated." }), { status: 401 });
      if (url.endsWith("/api/v1/applications")) {
        return new Response(
          JSON.stringify([
            { uuid: "web123", name: "web", fqdn: "https://web.example.com", http_basic_auth_password: "hunter2" },
            { uuid: "api123", name: "api", fqdn: null },
          ]),
          { status: 200 },
        );
      }
      if (url.endsWith("/api/v1/services")) {
        return new Response(JSON.stringify([{ uuid: "svc123", name: "convex", docker_compose_raw: "KEY: sk_live_x" }]), { status: 200 });
      }
      return new Response("{}", { status: 404 });
    }) as typeof fetch;
    return { fetchImpl, calls };
  }

  async function list(body: unknown, listApp: ReturnType<typeof buildApp>, token = adminToken) {
    return listApp.request(LIST, { method: "POST", headers: auth(token), body: JSON.stringify(body) });
  }

  async function listedEvents() {
    const res = await ctx.db.query(
      "SELECT resource, metadata FROM audit_events WHERE event_type = 'sync.destinations_listed' ORDER BY event_order",
    );
    return res.rows.map((r) => ({
      resource: asJson<Record<string, string> | null>((r as { resource: unknown }).resource),
      metadata: asJson<Record<string, unknown>>((r as { metadata: unknown }).metadata),
    }));
  }

  it("lists with a supplied credential, read-only, and audits the count, never the names", async () => {
    const instance = fakeInstance();
    const listApp = buildApp(ctx, { syncFetch: instance.fetchImpl });
    const res = await list({ platform: "coolify", baseIdentity: "https://coolify.example.com", credential: "fresh-token" }, listApp);
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = await res.json();
    expect(body).toEqual({
      check: expect.objectContaining({ status: "ok" }),
      items: [
        { destination: { applicationUuid: "api123" }, label: "api" },
        { destination: { serviceUuid: "svc123" }, label: "convex", detail: "service" },
        { destination: { applicationUuid: "web123" }, label: "web", detail: "web.example.com" },
      ],
      truncated: false,
    });
    expect(JSON.stringify(body)).not.toMatch(/hunter2|sk_live/);
    expect(instance.calls.map((c) => [c.method, c.url, c.authorization])).toEqual([
      ["GET", "https://coolify.example.com/api/v1/applications", "Bearer fresh-token"],
      ["GET", "https://coolify.example.com/api/v1/services", "Bearer fresh-token"],
    ]);
    expect((await ctx.db.query("SELECT id FROM platform_connections")).rows).toHaveLength(0);
    const events = await listedEvents();
    expect(events).toHaveLength(1);
    expect(events[0]!.metadata).toMatchObject({ platform: "coolify", credential: "supplied", status: "ok", count: 3, truncated: false });
    expect(JSON.stringify(events)).not.toMatch(/fresh-token|web123|api123|svc123|"web"|"api"|convex/);
  });

  it("lists with a connection's stored credential, and reports a rejected one as an outcome", async () => {
    const instance = fakeInstance();
    const listApp = buildApp(ctx, { syncFetch: instance.fetchImpl });
    const connection = await (await createConnection()).json();
    const stored = await (await list({ connectionId: connection.id }, listApp)).json();
    expect(stored.items).toHaveLength(3);
    expect(instance.calls[0]!.authorization).toBe("Bearer coolify-token-123");

    const rejected = await list({ connectionId: connection.id, credential: "wrong" }, listApp);
    expect(rejected.status).toBe(200);
    expect(await rejected.json()).toEqual({ check: expect.objectContaining({ status: "credential-rejected" }), items: [], truncated: false });
    expect((await listedEvents()).map((e) => [e.resource?.connectionId, e.metadata.credential, e.metadata.status])).toEqual([
      [connection.id, "stored", "ok"],
      [connection.id, "supplied", "credential-rejected"],
    ]);
  });

  it("refuses a platform whose base identity is the destination, and validates like a check", async () => {
    const instance = fakeInstance();
    const listApp = buildApp(ctx, { syncFetch: instance.fetchImpl });
    const convex = await list({ platform: "convex", baseIdentity: "https://happy-animal-123.convex.cloud", credential: "key" }, listApp);
    expect(convex.status).toBe(422);
    expect((await convex.json()).error.message).toContain("no destinations to list");
    expect((await list({ platform: "coolify", baseIdentity: "https://coolify.example.com" }, listApp)).status).toBe(422);
    expect((await list({ connectionId: "pcn_missing" }, listApp)).status).toBe(404);
    expect(instance.calls).toHaveLength(0);
    expect(await listedEvents()).toHaveLength(0);
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
    expect((await list(body, buildApp(ctx, { syncFetch: instance.fetchImpl }), svc.credential)).status).toBe(403);
    expect((await list(body, buildApp(ctx, { sync: null, syncFetch: instance.fetchImpl }))).status).toBe(403);
    expect((await list(body, buildApp(ctx, { sync: { adapters: ["github-actions"] }, syncFetch: instance.fetchImpl }))).status).toBe(422);
    expect(instance.calls).toHaveLength(0);
  });
});

describe("credential expiry (ADR-0031 amendment 2026-10-09)", () => {
  const CHECK = "/v1/organizations/acme/platform-connections/check";
  const LIST = "/v1/organizations/acme/platform-connections/destinations";

  /** GitHub, answering every request with the token's expiry header. */
  function fakeGitHub() {
    const state = { expiry: "2026-11-08 09:30:00 UTC" };
    const key = Buffer.alloc(32, 7).toString("base64");
    const fetchImpl = (async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      const headers = { "Content-Type": "application/json", "github-authentication-token-expiration": state.expiry };
      const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers });
      if (url.endsWith("/users/acme")) return json({ login: "acme", type: "Organization" });
      if (url.endsWith("/public-key")) return json({ key_id: "k1", key });
      if (url.includes("/orgs/acme/repos")) return json([{ name: "api", owner: { login: "acme" }, private: true }]);
      if (method === "PUT" || method === "DELETE") return new Response(null, { status: 204, headers });
      return json({ message: "Not Found" }, 404);
    }) as typeof fetch;
    return { fetchImpl, state };
  }

  const githubConnection = async (credential = "ghp_old") =>
    (await createConnection({ platform: "github-actions", baseIdentity: "acme", name: "GitHub", credential })).json();
  const stored = async (id: string) => (await get(`/v1/organizations/acme/platform-connections/${id}`)).json();

  it("a push records when GitHub says the token expires, without changing the connection", async () => {
    const github = fakeGitHub();
    const connection = await githubConnection();
    expect(connection).toMatchObject({ credentialExpiresAt: null, credentialExpirySeenAt: null });
    expect((await createTarget(connection.id, { destination: { repo: "api" } })).status).toBe(201);
    await runSyncOnce(ctx, { fetchImpl: github.fetchImpl });
    const after = await stored(connection.id);
    expect(after.credentialExpiresAt).toBe("2026-11-08T09:30:00.000Z");
    expect(after.credentialExpirySeenAt).not.toBeNull();
    expect(after).toMatchObject({ version: connection.version, updatedAt: null });
  });

  it("a check or listing records it for the stored token, and only reports it for a supplied one", async () => {
    const github = fakeGitHub();
    const checkApp = buildApp(ctx, { syncFetch: github.fetchImpl });
    const post = (path: string, body: unknown) =>
      checkApp.request(path, { method: "POST", headers: auth(), body: JSON.stringify(body) });

    const fresh = await (await post(CHECK, { platform: "github-actions", baseIdentity: "acme", credential: "ghp_new" })).json();
    expect(fresh).toMatchObject({ status: "ok", credentialExpiresAt: "2026-11-08T09:30:00.000Z" });

    const connection = await githubConnection();
    await post(CHECK, { connectionId: connection.id });
    expect((await stored(connection.id)).credentialExpiresAt).toBe("2026-11-08T09:30:00.000Z");

    github.state.expiry = "2026-12-01 00:00:00 UTC";
    const candidate = await (await post(CHECK, { connectionId: connection.id, credential: "ghp_candidate" })).json();
    expect(candidate.credentialExpiresAt).toBe("2026-12-01T00:00:00.000Z");
    expect((await stored(connection.id)).credentialExpiresAt).toBe("2026-11-08T09:30:00.000Z");

    await post(LIST, { connectionId: connection.id });
    expect((await stored(connection.id)).credentialExpiresAt).toBe("2026-12-01T00:00:00.000Z");
  });

  it("replacing the credential clears it, and a late report about the old token never lands", async () => {
    const github = fakeGitHub();
    const checkApp = buildApp(ctx, { syncFetch: github.fetchImpl });
    const connection = await githubConnection();
    await checkApp.request(CHECK, { method: "POST", headers: auth(), body: JSON.stringify({ connectionId: connection.id }) });
    expect((await stored(connection.id)).credentialExpiresAt).not.toBeNull();

    const replaced = await post(`/v1/organizations/acme/platform-connections/${connection.id}/credential`, {
      credential: "ghp_rotated",
      expectedVersion: connection.version,
    });
    expect(replaced.status).toBe(200);
    expect(await replaced.json()).toMatchObject({ credentialExpiresAt: null, credentialExpirySeenAt: null });

    // A push that read the old token reports after the replacement: dropped.
    await recordCredentialExpiry(ctx.db, connection.id, connection.version, "2026-11-08T09:30:00.000Z");
    expect((await stored(connection.id)).credentialExpiresAt).toBeNull();
    await recordCredentialExpiry(ctx.db, connection.id, connection.version + 1, "2027-01-01T00:00:00.000Z");
    expect((await stored(connection.id)).credentialExpiresAt).toBe("2027-01-01T00:00:00.000Z");
  });

  it("records the expiry even when the push throws (a refused public-key fetch)", async () => {
    const connection = await githubConnection();
    expect((await createTarget(connection.id, { destination: { repo: "api" } })).status).toBe(201);
    const refusing = (async () =>
      new Response(JSON.stringify({ message: "Forbidden" }), {
        status: 403,
        headers: { "github-authentication-token-expiration": "2026-11-08 09:30:00 UTC" },
      })) as typeof fetch;
    await runSyncOnce(ctx, { fetchImpl: refusing });
    expect((await targetRowFromDb()).failure_count).toBe(1);
    expect((await stored(connection.id)).credentialExpiresAt).toBe("2026-11-08T09:30:00.000Z");
  });

  it("a stored token's known expiry stands in when GitHub does not repeat it; a supplied one never borrows it", async () => {
    const github = fakeGitHub();
    const checkApp = buildApp(ctx, { syncFetch: github.fetchImpl });
    const post = (path: string, body: unknown) =>
      checkApp.request(path, { method: "POST", headers: auth(), body: JSON.stringify(body) });
    const connection = await githubConnection();
    await recordCredentialExpiry(ctx.db, connection.id, connection.version, "2026-10-12T09:30:00.000Z");
    github.state.expiry = "";

    const check = await (await post(CHECK, { connectionId: connection.id, destination: { repo: "api" } })).json();
    expect(check).toMatchObject({ status: "ok", credentialExpiresAt: "2026-10-12T09:30:00.000Z" });
    const listing = await (await post(LIST, { connectionId: connection.id })).json();
    expect(listing.check.credentialExpiresAt).toBe("2026-10-12T09:30:00.000Z");
    expect((await stored(connection.id)).credentialExpiresAt).toBe("2026-10-12T09:30:00.000Z");

    const candidate = await (await post(CHECK, { connectionId: connection.id, credential: "ghp_candidate" })).json();
    expect(candidate.status).toBe("ok");
    expect(candidate).not.toHaveProperty("credentialExpiresAt");
  });

  it("says nothing for a token GitHub reports no expiry for", async () => {
    const github = fakeGitHub();
    github.state.expiry = "";
    const checkApp = buildApp(ctx, { syncFetch: github.fetchImpl });
    const connection = await githubConnection();
    const check = await (
      await checkApp.request(CHECK, { method: "POST", headers: auth(), body: JSON.stringify({ connectionId: connection.id }) })
    ).json();
    expect(check).not.toHaveProperty("credentialExpiresAt");
    expect(await stored(connection.id)).toMatchObject({ credentialExpiresAt: null, credentialExpirySeenAt: null });
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

describe("Coolify value fidelity on repair (ADR-0031 amendment 2026-10-21)", () => {
  async function appTarget(extra: Record<string, unknown> = {}) {
    const connection = await (await createConnection()).json();
    return (await createTarget(connection.id, extra)).json();
  }

  it("rewrites a matching value stored without the literal flags, then leaves it", async () => {
    const coolify = fakeCoolify();
    // An existing application row, written before values went literal.
    coolify.seed("PORT", "8080", { is_literal: false, is_multiline: false, is_buildtime: false, is_runtime: true });
    await appTarget();
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.row("PORT")).toMatchObject({ value: "8080", is_literal: true, is_multiline: true });
    expect(coolify.calls.filter((c) => c.method === "PATCH").map((c) => (c.body as { key: string }).key)).toContain("PORT");

    coolify.calls.length = 0;
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl, repairIntervalMs: 0 });
    expect(coolify.calls.filter((c) => c.method === "PATCH" || c.method === "POST")).toHaveLength(0);
    // A form-only rewrite is not drift (ADR-0050 Decision 8).
    expect((await ctx.db.query("SELECT 1 FROM audit_events WHERE event_type = 'sync.drift_detected'")).rows).toHaveLength(0);
  });

  it("holds a value Coolify cannot carry even when the platform already has it, and never deletes it", async () => {
    await put(`${ENV_PATH}/values/QUOTED`, { value: "it's" });
    const coolify = fakeCoolify();
    coolify.seed("QUOTED", "it's", { is_literal: true, is_multiline: true });
    await appTarget({ removeOrphans: true });
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    const row = await targetRowFromDb();
    expect(row.last_result).toContain("held: QUOTED: Coolify writes values in single quotes");
    // Held, not failed (ADR-0031 amendment 2026-10-22); listing the name
    // would not help a quote, so no fix is offered.
    expect(row.failure_count).toBe(0);
    expect(asJson(row.last_notes)).toEqual([{ code: "held", name: "QUOTED", reason: expect.stringContaining("single quotes") }]);
    // Not adopted as converged, not written, not removed as an orphan.
    const ledger = await ctx.db.query("SELECT dest_name FROM sync_ledger WHERE dest_name = 'QUOTED'");
    expect(ledger.rows).toEqual([]);
    expect(coolify.calls.some((c) => c.method === "DELETE")).toBe(false);
    expect(coolify.values().get("QUOTED")).toBe("it's");
  });
});

describe("Coolify value fidelity: a written name whose value becomes undeliverable", () => {
  it("keeps the last delivered value instead of deleting the name as an orphan", async () => {
    await put(`${ENV_PATH}/values/QUOTED`, { value: "fine" });
    const coolify = fakeCoolify();
    const connection = await (await createConnection()).json();
    await createTarget(connection.id, { removeOrphans: true });
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.values().get("QUOTED")).toBe("fine");

    await put(`${ENV_PATH}/values/QUOTED`, { value: "it's" });
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl, repairIntervalMs: 0 });
    expect(coolify.calls.some((c) => c.method === "DELETE")).toBe(false);
    expect(coolify.values().get("QUOTED")).toBe("fine");
    expect((await targetRowFromDb()).last_result).toContain("QUOTED: Coolify writes values in single quotes");
  });
});

describe("Coolify services (ADR-0031 amendment 2026-10-21)", () => {
  /**
   * A fake Coolify service: the env store of fakeCoolify on the service's
   * routes, plus the service record, whose compose files the test sets. With
   * `sensitive: false` the token reads neither values nor compose files, as
   * a token without Coolify's read:sensitive.
   */
  function fakeService(opts: { compose?: string; containers?: string[]; sensitive?: boolean } = {}) {
    const coolify = fakeCoolify();
    const state = {
      compose: opts.compose ?? "services:\n  web:\n    image: x\n",
      sensitive: opts.sensitive ?? true,
    };
    const containers = opts.containers ?? ["web"];
    const generated = () => `services:\n${containers.map((c) => `  ${c}:\n    env_file:\n      - .env\n`).join("")}`;
    const fetchImpl = (async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/v1/services/svc1") && (init?.method ?? "GET") === "GET") {
        coolify.calls.push({ method: "GET", url });
        return new Response(
          JSON.stringify({
            uuid: "svc1",
            name: "convex",
            compose_parsing_version: 5,
            applications: containers.map((name) => ({ name })),
            ...(state.sensitive ? { docker_compose_raw: state.compose, docker_compose: generated() } : {}),
          }),
          { status: 200 },
        );
      }
      const res = await coolify.fetchImpl(input as string, init);
      if (!state.sensitive && url.endsWith("/envs") && (init?.method ?? "GET") === "GET") {
        const rows = (await res.json()) as Record<string, unknown>[];
        return new Response(JSON.stringify(rows.map(({ value: _hidden, ...rest }) => rest)), { status: 200 });
      }
      return res;
    }) as typeof fetch;
    return { ...coolify, fetchImpl, state };
  }

  async function serviceTarget(extra: Record<string, unknown> = {}) {
    const connection = await (await createConnection()).json();
    const res = await createTarget(connection.id, { destination: { serviceUuid: "svc1" }, ...extra });
    return { connection, res, target: res.status === 201 ? await res.json() : undefined };
  }

  it("claims a service apart from an application with the same uuid, and pushes to its routes", async () => {
    const service = fakeService();
    const { connection, res } = await serviceTarget();
    expect(res.status).toBe(201);
    const created = await ctx.db.query("SELECT metadata FROM audit_events WHERE event_type = 'sync.target_created'");
    expect(JSON.stringify((created.rows[0] as { metadata: unknown }).metadata)).toContain("coolify:service:svc1");
    // An application uuid "svc1" is another destination.
    expect((await createTarget(connection.id, { destination: { applicationUuid: "svc1" } })).status).toBe(201);

    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl });
    const writes = service.calls.filter((c) => c.method === "POST" || c.method === "PATCH");
    expect(writes.length).toBeGreaterThan(0);
    expect(writes.some((c) => c.url.includes("/api/v1/services/svc1/envs"))).toBe(true);
    expect(writes.filter((c) => c.url.includes("/services/")).every((c) => (c.body as Record<string, unknown>).is_literal === true)).toBe(true);
  });

  it("refuses names Coolify sets on a service, at creation and when a destination becomes a service", async () => {
    const connection = await (await createConnection()).json();
    const owned = { kind: "explicit", items: [{ name: "PORT", rename: "SERVICE_URL_WEB" }] };
    const refused = await createTarget(connection.id, { destination: { serviceUuid: "svc1" }, mapping: owned });
    expect(refused.status).toBe(422);
    expect(JSON.stringify(await refused.json())).toContain("Coolify sets this name itself");

    // The same mapping is fine on an application, but not once it points at a service.
    const app = await (await createTarget(connection.id, { destination: { applicationUuid: "app1" }, mapping: owned })).json();
    const moved = await patchReq(`${ENV_PATH}/sync-targets/${app.id}`, { expectedVersion: app.version, destination: { serviceUuid: "svc1" } });
    expect(moved.status).toBe(422);
  });

  it("holds a wildcard name Coolify owns and neither writes nor deletes it", async () => {
    await put(`${ENV_PATH}/values/COOLIFY_URL`, { value: "https://mine.example.com" });
    const service = fakeService();
    await serviceTarget({ removeOrphans: true });
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl });
    expect(service.values().has("COOLIFY_URL")).toBe(false);
    expect(service.values().get("PORT")).toBe("8080");
    const row = await targetRowFromDb();
    expect(row.last_result).toContain("held: COOLIFY_URL: Coolify sets this name itself");
    expect(row.failure_count).toBe(0);
    expect(asJson(row.last_notes)).toContainEqual({ code: "held", name: "COOLIFY_URL", reason: expect.stringContaining("sets this name itself") });
  });

  it("keeps a name the compose file binds to a Coolify value out of writes and deletes", async () => {
    const service = fakeService({ compose: "services:\n  web:\n    environment:\n      PORT: ${SERVICE_URL_WEB}\n" });
    service.seed("PORT", "${SERVICE_URL_WEB}");
    await serviceTarget({ removeOrphans: true });
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl });
    expect(service.values().get("PORT")).toBe("${SERVICE_URL_WEB}");
    expect(service.values().get("DATABASE_URL")).toBe("postgres://dev-db/main");
    const row = await targetRowFromDb();
    expect(row.last_result).toContain("PORT: the platform sets this name itself");

    // Removing the item never deletes Coolify's own row.
    await del(`${ENV_PATH}/values/PORT`);
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl, repairIntervalMs: 0 });
    expect(service.values().get("PORT")).toBe("${SERVICE_URL_WEB}");
    expect(service.calls.some((c) => c.method === "DELETE")).toBe(false);
  });

  it("never deletes a name Varlatch wrote once the compose file hands it to Coolify", async () => {
    const service = fakeService();
    await serviceTarget({ removeOrphans: true });
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl });
    expect(service.values().get("PORT")).toBe("8080");
    // The compose file now binds PORT to a Coolify value: Coolify owns it.
    service.state.compose = "services:\n  web:\n    environment:\n      PORT: ${SERVICE_URL_WEB}\n";
    await ctx.db.query("UPDATE sync_targets SET needs_sync = true");
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl, repairIntervalMs: 0 });
    // Neither written over nor removed as an orphan: Coolify's row now.
    expect(service.calls.some((c) => c.method === "DELETE")).toBe(false);
    expect(service.values().get("PORT")).toBe("8080");
    expect((await targetRowFromDb()).last_result).toContain("PORT: the platform sets this name itself");
  });

  it("stores usage notes, replaces them on every inspecting run, and clears an application's", async () => {
    const service = fakeService({ compose: "services:\n  web:\n    environment:\n      DATABASE_URL: postgres://fixed/db\n" });
    await serviceTarget();
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl });
    let row = await targetRowFromDb();
    expect(row.last_result).toBe("ok");
    expect(asJson(row.last_notes)).toEqual([{ code: "shadowed", name: "DATABASE_URL", containers: ["web"] }]);
    const listed = await (await get(`${ENV_PATH}/sync-targets`)).json();
    expect(listed.items[0].lastNotes).toEqual([{ code: "shadowed", name: "DATABASE_URL", containers: ["web"] }]);

    // The compose file now reads the stored value: the note clears.
    service.state.compose = "services:\n  web:\n    environment:\n      DATABASE_URL: ${DATABASE_URL}\n";
    await ctx.db.query("UPDATE sync_targets SET needs_sync = true");
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl });
    row = await targetRowFromDb();
    expect(asJson(row.last_notes)).toEqual([]);

    // A token that cannot read the compose file: one note says so.
    service.state.sensitive = false;
    await ctx.db.query("UPDATE sync_targets SET needs_sync = true");
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl });
    row = await targetRowFromDb();
    expect(asJson<{ code: string; reason: string }[]>(row.last_notes)).toEqual([
      { code: "usage-unchecked", reason: expect.stringContaining("read:sensitive") },
    ]);

    await ctx.db.query("DELETE FROM sync_ledger");
    await ctx.db.query("DELETE FROM sync_targets");
    const coolify = fakeCoolify();
    const connection = await (await createConnection()).json();
    await createTarget(connection.id);
    expect((await targetRowFromDb()).last_notes).toBeNull();
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    // An application has no usage notes; a run that held nothing stores none.
    expect(asJson((await targetRowFromDb()).last_notes)).toEqual([]);
  });

  it("deletes a re-created name once, then never fights Coolify for it (nor restarts for it)", async () => {
    const service = fakeService({ compose: "services:\n  web:\n    environment:\n      PORT: ${PORT:-80}\n" });
    await serviceTarget({ removeOrphans: true, redeploy: true });
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl });
    expect(service.restarts()).toBe(1);

    await del(`${ENV_PATH}/values/PORT`);
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl });
    expect(service.values().has("PORT")).toBe(false);
    expect(service.restarts()).toBe(2);
    expect(asJson(( await targetRowFromDb()).last_notes)).toEqual([{ code: "kept-by-platform", name: "PORT" }]);

    // Coolify's next parse re-creates it with the compose default.
    service.seed("PORT", "80");
    for (let i = 0; i < 2; i++) {
      await runSyncOnce(ctx, { fetchImpl: service.fetchImpl, repairIntervalMs: 0 });
    }
    expect(service.values().get("PORT")).toBe("80");
    expect(service.calls.filter((c) => c.method === "DELETE")).toHaveLength(1);
    expect(service.restarts()).toBe(2);
  });

  it("does not re-delete when usage cannot be read either", async () => {
    const service = fakeService({ sensitive: false });
    await serviceTarget({ removeOrphans: true });
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl });
    await del(`${ENV_PATH}/values/PORT`);
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl });
    expect(service.values().has("PORT")).toBe(false);
    service.seed("PORT", "80");
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl, repairIntervalMs: 0 });
    expect(service.values().get("PORT")).toBe("80");
    expect(service.calls.filter((c) => c.method === "DELETE")).toHaveLength(1);
  });

  it("rewrites unreadable values on repair without restarting the service", async () => {
    const service = fakeService({ sensitive: false });
    await serviceTarget({ redeploy: true });
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl });
    expect(service.restarts()).toBe(1);
    service.calls.length = 0;
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl, repairIntervalMs: 0 });
    // The values could not be compared, so they were written again...
    expect(service.calls.filter((c) => c.method === "PATCH").length).toBeGreaterThan(0);
    // ...as the same content: no restart, and no drift.
    expect(service.restarts()).toBe(1);
    expect((await targetRowFromDb()).last_result).toBe("ok");
    expect((await ctx.db.query("SELECT 1 FROM audit_events WHERE event_type = 'sync.drift_detected'")).rows).toHaveLength(0);
  });

  it("restarts the service, not a deploy, after a changing push", async () => {
    const service = fakeService();
    await serviceTarget({ redeploy: true });
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl });
    expect(service.calls.filter((c) => c.method === "POST" && !c.url.endsWith("/envs")).map((c) => c.url)).toEqual([
      "https://coolify.example.com/api/v1/services/svc1/restart",
    ]);
  });

  it("holds a $ value while the token cannot read the compose file", async () => {
    await put(`${ENV_PATH}/values/DOLLAR`, { value: "pa$word" });
    const service = fakeService({ sensitive: false });
    await serviceTarget();
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl });
    expect(service.values().has("DOLLAR")).toBe(false);
    expect(service.values().get("PORT")).toBe("8080");
    expect((await targetRowFromDb()).last_result).toContain("DOLLAR: Varlatch could not check whether the service's compose file copies this value");
    // Once the compose file can be read and does not copy it, it goes.
    service.state.sensitive = true;
    await ctx.db.query("UPDATE sync_targets SET needs_sync = true, next_attempt_at = NULL");
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl });
    expect(service.values().get("DOLLAR")).toBe("pa$word");
  });

  it("keeps the notes of a completed inspection when the run fails later", async () => {
    const service = fakeService({ compose: "services:\n  web:\n    environment:\n      DATABASE_URL: postgres://fixed/db\n" });
    await serviceTarget();
    const failing = (async (input: unknown, init?: RequestInit) => {
      if (String(input).endsWith("/envs")) return new Response(JSON.stringify({ message: "boom" }), { status: 500 });
      return service.fetchImpl(input as string, init);
    }) as typeof fetch;
    await runSyncOnce(ctx, { fetchImpl: failing });
    const row = await targetRowFromDb();
    expect(row.failure_count).toBe(1);
    expect(asJson(row.last_notes)).toEqual([{ code: "shadowed", name: "DATABASE_URL", containers: ["web"] }]);
  });

  it("replaces stale notes when the run fails while adopting matching values", async () => {
    const service = fakeService({ compose: "services:\n  web:\n    environment:\n      DATABASE_URL: postgres://fixed/db\n" });
    service.seed("DATABASE_URL", "postgres://dev-db/main", { is_literal: true, is_multiline: true });
    service.seed("PORT", "8080", { is_literal: true, is_multiline: true });
    await serviceTarget();
    await ctx.db.query(`UPDATE sync_targets SET last_notes = '[{"code":"not-delivered","name":"STALE"}]'`);
    // The first ledger write (an adoption: the remote already matches) fails once.
    const query = ctx.db.query.bind(ctx.db);
    let failed = false;
    ctx.db.query = (async (sql: string, params?: unknown[]) => {
      if (!failed && /INSERT INTO sync_ledger/.test(sql)) {
        failed = true;
        throw new Error("ledger write failed");
      }
      return query(sql, params);
    }) as typeof ctx.db.query;
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl });
    ctx.db.query = query;
    expect(failed).toBe(true);
    const row = await targetRowFromDb();
    expect(row.failure_count).toBe(1);
    expect(asJson(row.last_notes)).toEqual([{ code: "shadowed", name: "DATABASE_URL", containers: ["web"] }]);
  });

  it("drops the notes when the destination changes", async () => {
    const service = fakeService({ compose: "services:\n  web:\n    environment:\n      DATABASE_URL: postgres://fixed/db\n" });
    const { target } = await serviceTarget();
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl });
    expect(asJson((await targetRowFromDb()).last_notes)).toHaveLength(1);
    const moved = await patchReq(`${ENV_PATH}/sync-targets/${target.id}`, { expectedVersion: target.version, destination: { applicationUuid: "app9" } });
    expect(moved.status).toBe(200);
    expect((await moved.json()).lastNotes).toBeNull();
    expect((await targetRowFromDb()).last_notes).toBeNull();
  });

  it("refuses a value Coolify would change, and says why", async () => {
    await put(`${ENV_PATH}/values/QUOTED`, { value: "it's" });
    const service = fakeService();
    await serviceTarget();
    await runSyncOnce(ctx, { fetchImpl: service.fetchImpl });
    expect(service.values().has("QUOTED")).toBe(false);
    expect(service.values().get("PORT")).toBe("8080");
    const row = await targetRowFromDb();
    expect(row.last_result).toContain("QUOTED: Coolify writes values in single quotes");
    expect(JSON.stringify(row)).not.toContain("it's");
  });
});

describe("held names and names Coolify resolves (ADR-0031 amendment 2026-10-22)", () => {
  async function appTarget(extra: Record<string, unknown> = {}) {
    const connection = await (await createConnection()).json();
    const res = await createTarget(connection.id, extra);
    expect(res.status).toBe(201);
    return res.json();
  }

  it("holds a Coolify reference without spending the failure budget or scheduling a retry", async () => {
    await put(`${ENV_PATH}/values/GITHUB_TOKEN`, { value: "{{team.GITHUB_TOKEN}}" });
    const coolify = fakeCoolify();
    coolify.seed("GITHUB_TOKEN", "{{team.GITHUB_TOKEN}}", { is_literal: false, is_multiline: false, is_buildtime: true, is_runtime: true });
    await appTarget({ removeOrphans: true });
    for (let i = 0; i < 12; i++) {
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl, repairIntervalMs: 0 });
    }
    const row = await targetRowFromDb();
    expect(row.state).toBe("active");
    expect(row.failure_count).toBe(0);
    expect(row.next_attempt_at).toBeNull();
    expect(row.needs_sync).toBe(false);
    expect(row.last_result).toMatch(/^(converged|ok); held: GITHUB_TOKEN: Coolify replaces \{\{team/);
    expect(asJson(row.last_notes)).toEqual([
      { code: "held", name: "GITHUB_TOKEN", reason: expect.stringContaining("shared variables"), fix: "platform-expands" },
    ]);
    // The operator's row is left exactly as it was: never written, never deleted.
    expect(coolify.row("GITHUB_TOKEN")).toMatchObject({ value: "{{team.GITHUB_TOKEN}}", is_literal: false, is_multiline: false });
    expect(coolify.calls.some((c) => c.method !== "GET" && JSON.stringify(c.body ?? "").includes("GITHUB_TOKEN"))).toBe(false);
    expect(coolify.calls.some((c) => c.method === "DELETE")).toBe(false);
    // Other values still flow.
    expect(coolify.values().get("PORT")).toBe("8080");
    const results = await ctx.db.query("SELECT metadata FROM audit_events WHERE event_type = 'sync.push_result'");
    expect((results.rows as { metadata: unknown }[]).map((r) => asJson<{ held: number }>(r.metadata).held)).toContain(1);
  });

  it("without a run in between, a held-only run leaves a concurrent change's needs_sync set", async () => {
    await put(`${ENV_PATH}/values/GITHUB_TOKEN`, { value: "{{team.GITHUB_TOKEN}}" });
    const coolify = fakeCoolify();
    await appTarget();
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    // A change lands while the next run is under way (here: as it reads the platform).
    const during = (async (input: unknown, init?: RequestInit) => {
      if ((init?.method ?? "GET") === "GET") await ctx.db.query("UPDATE sync_targets SET needs_sync = true");
      return coolify.fetchImpl(input as string, init);
    }) as typeof fetch;
    await runSyncOnce(ctx, { fetchImpl: during, repairIntervalMs: 0 });
    const row = await targetRowFromDb();
    expect(row.last_result).toContain("held: GITHUB_TOKEN");
    expect(row.needs_sync).toBe(true);
  });

  it("still fails a run that also failed a write, and lists what it held", async () => {
    await put(`${ENV_PATH}/values/GITHUB_TOKEN`, { value: "{{team.GITHUB_TOKEN}}" });
    const coolify = fakeCoolify();
    coolify.setFailWrites(true);
    await appTarget();
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    const row = await targetRowFromDb();
    expect(row.failure_count).toBe(1);
    expect(row.last_result).toMatch(/^degraded: .*HTTP 500.*; held: GITHUB_TOKEN: /);
  });

  it("lets Coolify resolve a listed name: adopts the operator's row, never rewrites it literal", async () => {
    await put(`${ENV_PATH}/values/GITHUB_TOKEN`, { value: "{{team.GITHUB_TOKEN}}" });
    await put(`${ENV_PATH}/values/VITE_BUILD_SHA`, { value: "$SOURCE_COMMIT" });
    const coolify = fakeCoolify();
    const operator = { is_literal: false, is_multiline: false, is_buildtime: true, is_runtime: true };
    coolify.seed("GITHUB_TOKEN", "{{team.GITHUB_TOKEN}}", operator);
    coolify.seed("VITE_BUILD_SHA", "$SOURCE_COMMIT", operator);
    coolify.seed("PORT", "8080", { is_literal: true, is_multiline: true, is_runtime: true });
    coolify.seed("DATABASE_URL", "postgres://dev-db/main", { is_literal: true, is_multiline: true, is_runtime: true });
    const target = await appTarget({ destination: { applicationUuid: "app1", platformExpands: ["VITE_BUILD_SHA", "GITHUB_TOKEN"] } });
    expect(target.destination).toEqual({ applicationUuid: "app1", platformExpands: "GITHUB_TOKEN,VITE_BUILD_SHA" });
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    const row = await targetRowFromDb();
    expect(row.last_result).toBe("converged");
    expect(asJson(row.last_notes)).toEqual([]);
    expect(coolify.calls.filter((c) => c.method !== "GET")).toEqual([]);
    expect(coolify.row("VITE_BUILD_SHA")).toMatchObject({ value: "$SOURCE_COMMIT", ...operator });
    const created = await ctx.db.query("SELECT metadata FROM audit_events WHERE event_type = 'sync.target_created'");
    expect(asJson<{ platformExpands: string }>((created.rows[0] as { metadata: unknown }).metadata).platformExpands).toBe("GITHUB_TOKEN,VITE_BUILD_SHA");
  });

  it("without the listing, a repair stores a $ value literal; listing it later restores Coolify's form at the next repair", async () => {
    await put(`${ENV_PATH}/values/VITE_BUILD_SHA`, { value: "$SOURCE_COMMIT" });
    const coolify = fakeCoolify();
    coolify.seed("VITE_BUILD_SHA", "$SOURCE_COMMIT", { is_literal: false, is_multiline: false, is_buildtime: true, is_runtime: true });
    const target = await appTarget();
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    // Literal is the default: nothing is inferred from the $.
    expect(coolify.row("VITE_BUILD_SHA")).toMatchObject({ is_literal: true, is_multiline: true });

    const res = await patchReq(`${ENV_PATH}/sync-targets/${target.id}`, {
      expectedVersion: target.version,
      destination: { applicationUuid: "app1", platformExpands: "VITE_BUILD_SHA" },
    });
    expect(res.status).toBe(200);
    // The option alone changes no fingerprint: the triggered run converges...
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    expect(coolify.row("VITE_BUILD_SHA")).toMatchObject({ is_literal: true });
    // ...and the next repair stores it as Coolify's own variable again.
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl, repairIntervalMs: 0 });
    expect(coolify.row("VITE_BUILD_SHA")).toMatchObject({ value: "$SOURCE_COMMIT", is_literal: false, is_multiline: false, is_buildtime: true, is_runtime: true });
    expect((await targetRowFromDb()).last_result).toBe("ok");
    const updated = await ctx.db.query("SELECT metadata FROM audit_events WHERE event_type = 'sync.target_updated'");
    expect(asJson<{ platformExpands: string }>((updated.rows[0] as { metadata: unknown }).metadata).platformExpands).toBe("VITE_BUILD_SHA");
  });

  it("refuses the option on a service, and an invalid list", async () => {
    const connection = await (await createConnection()).json();
    const svc = await createTarget(connection.id, { destination: { serviceUuid: "svc1", platformExpands: ["A"] } });
    expect(svc.status).toBe(422);
    const bad = await createTarget(connection.id, { destination: { applicationUuid: "app1", platformExpands: ["1A"] } });
    expect(bad.status).toBe(422);
  });

  /** Make the next `times` queries matching `sql` fail, then answer normally. */
  function failQuery(sql: string, times = 1) {
    const query = ctx.db.query.bind(ctx.db);
    let left = times;
    ctx.db.query = (async (text: string, params?: unknown[]) => {
      if (left > 0 && text.trim() === sql) {
        left -= 1;
        throw new Error("probe failed");
      }
      return query(text, params);
    }) as typeof ctx.db.query;
    return () => {
      ctx.db.query = query as typeof ctx.db.query;
    };
  }

  it("keeps the held notes when a run is interrupted mid-run without losing its lease", async () => {
    await put(`${ENV_PATH}/values/GITHUB_TOKEN`, { value: "{{team.GITHUB_TOKEN}}" });
    const coolify = fakeCoolify();
    await appTarget();
    // The send-time fence probe fails: the write is not sent, and the run ends
    // as interrupted, at its own generation.
    const restore = failQuery(SEND_CHECK_SQL);
    try {
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    } finally {
      restore();
    }
    const row = await targetRowFromDb();
    expect(row.last_result).toBe("interrupted mid-run; retrying");
    expect(row.failure_count).toBe(1);
    expect(asJson(row.last_notes)).toEqual([
      { code: "held", name: "GITHUB_TOKEN", reason: expect.stringContaining("shared variables"), fix: "platform-expands" },
    ]);
    expect(coolify.calls.filter((c) => c.method === "POST" || c.method === "PATCH")).toEqual([]);
  });

  it("leaves the notes when a run fails before the value check", async () => {
    await put(`${ENV_PATH}/values/GITHUB_TOKEN`, { value: "{{team.GITHUB_TOKEN}}" });
    const coolify = fakeCoolify();
    await appTarget();
    await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    const held = asJson((await targetRowFromDb()).last_notes);
    expect(held).toHaveLength(1);
    // The next run throws before it renders anything.
    await ctx.db.query("UPDATE sync_targets SET needs_sync = true");
    const restore = failQuery("SELECT * FROM projects WHERE id = $1 AND deleted_at IS NULL");
    try {
      await runSyncOnce(ctx, { fetchImpl: coolify.fetchImpl });
    } finally {
      restore();
    }
    const row = await targetRowFromDb();
    expect(row.last_result).toContain("probe failed");
    expect(asJson(row.last_notes)).toEqual(held);
  });

  it("bounds held notes first, with a count of the rest", async () => {
    const { boundNotes } = await import("../src/domain/sync.js");
    const held = Array.from({ length: 60 }, (_, i) => ({ code: "held" as const, name: `N${i}`, reason: "r" }));
    const notes = boundNotes([{ code: "shadowed", name: "S", containers: ["web"] }, ...held]);
    expect(notes).toHaveLength(50);
    expect(notes.slice(0, 49).every((n) => n.code === "held")).toBe(true);
    expect(notes[49]).toEqual({ code: "held-more", count: 11 });
    const few = boundNotes([{ code: "shadowed", name: "S" }, { code: "held", name: "H", reason: "r", fix: "platform-expands" }]);
    expect(few).toEqual([{ code: "held", name: "H", reason: "r", fix: "platform-expands" }, { code: "shadowed", name: "S" }]);
  });
});

describe("repair cycles (ADR-0050 Decision 4)", () => {
  /** GitHub Actions: no read-back, so a forced repair writes and deletes everything. */
  function fakeGitHub() {
    const key = Buffer.alloc(32, 7).toString("base64");
    const sent: { method: string; name: string }[] = [];
    let cutOn: string | null = null;
    const fetchImpl = (async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      const json = (body: unknown, status = 200) =>
        new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
      if (url.endsWith("/users/acme")) return json({ login: "acme", type: "Organization" });
      if (url.endsWith("/public-key")) return json({ key_id: "k1", key });
      if (method === "PUT" || method === "DELETE") {
        sent.push({ method, name: decodeURIComponent(url.split("/").pop() ?? "") });
        if (cutOn === method) {
          // The run's budget runs out right after this request.
          cutOn = null;
          await ctx.db.query("UPDATE sync_runs SET deadline = now() - interval '1 second'");
        }
        return new Response(null, { status: 204 });
      }
      return json({ message: "Not Found" }, 404);
    }) as typeof fetch;
    return { fetchImpl, sent, cutAfterNext: (method: "PUT" | "DELETE") => (cutOn = method) };
  }
  const githubTarget = async () => {
    const connection = await (await createConnection({ platform: "github-actions", baseIdentity: "acme", name: "GitHub", credential: "ghp_x" })).json();
    expect((await createTarget(connection.id, { destination: { repo: "api" } })).status).toBe(201);
    return ((await (await get(`${ENV_PATH}/sync-targets`)).json()).items[0].id) as string;
  };

  it("a forced first sync to GitHub larger than one budget finishes over several runs, writing each name once", async () => {
    const github = fakeGitHub();
    const id = await githubTarget();
    github.cutAfterNext("PUT");
    await reconcileTarget(ctx, id, { fetchImpl: github.fetchImpl });
    expect(github.sent).toHaveLength(1);
    expect((await targetRowFromDb()).repair_cycle_started_at).not.toBeNull();
    await runSyncOnce(ctx, { fetchImpl: github.fetchImpl });
    const puts = github.sent.filter((s) => s.method === "PUT").map((s) => s.name);
    expect(puts.sort()).toEqual(["DATABASE_URL", "PORT"]);
    const row = await targetRowFromDb();
    expect(row.repair_cycle_started_at).toBeNull();
    expect(row.last_repair_at).not.toBeNull();
    expect(row.failure_count).toBe(0);
    // GitHub Actions cannot redeploy: nothing is ever owed.
    expect(Number(row.redeploy_owed)).toBe(0);
  });

  it("re-deleting many tombstones also resumes instead of starting over", async () => {
    const github = fakeGitHub();
    const id = await githubTarget();
    await runSyncOnce(ctx, { fetchImpl: github.fetchImpl }); // first sync, cycle closed
    // Three names Varlatch deleted earlier, and a repair due.
    for (const name of ["OLD_A", "OLD_B", "OLD_C"]) {
      await ctx.db.query(
        "INSERT INTO sync_ledger (target_id, dest_name, fingerprint, state, generation) VALUES ($1, $2, NULL, 'tombstone', 0)",
        [id, name],
      );
    }
    await ctx.db.query("UPDATE sync_targets SET last_repair_at = NULL, needs_sync = true");
    github.sent.length = 0;
    // The forced run rewrites both values, deletes one tombstone, and runs out.
    github.cutAfterNext("DELETE");
    await reconcileTarget(ctx, id, { fetchImpl: github.fetchImpl });
    expect(github.sent.filter((s) => s.method === "DELETE")).toHaveLength(1);
    const cut = github.sent.length;
    await runSyncOnce(ctx, { fetchImpl: github.fetchImpl });
    const after = github.sent.slice(cut);
    // The continuation neither rewrites the values nor repeats the deletion.
    expect(after.filter((s) => s.method === "PUT")).toEqual([]);
    const deletes = github.sent.filter((s) => s.method === "DELETE").map((s) => s.name);
    expect(deletes.sort()).toEqual(["OLD_A", "OLD_B", "OLD_C"]);
    expect((await targetRowFromDb()).repair_cycle_started_at).toBeNull();
  });

  it("a rendering flag does not keep a finished cycle open", async () => {
    const github = fakeGitHub();
    await put(`${ENV_PATH}/values/BROKEN`, { value: "${DOES_NOT_EXIST}" });
    await githubTarget();
    await runSyncOnce(ctx, { fetchImpl: github.fetchImpl });
    const row = await targetRowFromDb();
    expect(row.last_result).toMatch(/flagged|degraded/);
    expect(row.repair_cycle_started_at).toBeNull();
    expect(row.last_repair_at).not.toBeNull();
  });
});
