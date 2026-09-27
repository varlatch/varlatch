// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
} from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let adminId: string;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  adminId = consumed.identityId;
  const cred = await issueCredential(ctx.db, { identityId: adminId, kind: "cli" });
  adminToken = cred.token;
  app = buildApp(ctx);
});
afterEach(async () => {
  await ctx.close();
});

function auth(token = adminToken): HeadersInit {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}

async function post(path: string, body: unknown, token = adminToken, extra: Record<string, string> = {}) {
  return app.request(path, {
    method: "POST",
    headers: { ...auth(token), ...extra },
    body: JSON.stringify(body),
  });
}

async function put(path: string, body: unknown, extra: Record<string, string> = {}) {
  return app.request(path, {
    method: "PUT",
    headers: { ...auth(), ...extra },
    body: JSON.stringify(body),
  });
}

async function setupOrgProject() {
  const orgRes = await post("/v1/organizations", { name: "Acme", slug: "acme" });
  expect(orgRes.status).toBe(201);
  const prjRes = await post("/v1/organizations/acme/projects", {
    name: "API",
    slug: "api",
    contractAuthority: "git",
  });
  expect(prjRes.status).toBe(201);
  const devRes = await post("/v1/organizations/acme/projects/api/environments", {
    name: "development",
    tier: "development",
  });
  expect(devRes.status).toBe(201);
  return { org: await orgRes.json(), project: await prjRes.json(), dev: await devRes.json() };
}

describe("plumbing", () => {
  it("healthz is unauthenticated and low-information", async () => {
    const res = await app.request("/healthz");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok" });
  });

  it("readyz verifies schema + KEK + installation", async () => {
    const res = await app.request("/readyz");
    expect(res.status).toBe(200);
    const wrong = buildApp({ db: ctx.db, rootKek: generateKey() });
    const bad = await wrong.request("/readyz");
    expect(bad.status).toBe(503);
    expect((await bad.json()).checks.kek).toBe(false);
  });

  it("meta is public; everything else requires a bearer", async () => {
    const meta = await app.request("/v1/meta");
    expect(meta.status).toBe(200);
    expect((await meta.json()).apiMajor).toBe(1);
    const res = await app.request("/v1/organizations");
    expect(res.status).toBe(401);
    expect((await res.json()).error.code).toBe("AUTHENTICATION_REQUIRED");
    // Cookies never authenticate /v1 (ADR-0018 §6).
    const cookie = await app.request("/v1/organizations", {
      headers: { Cookie: "session=whatever" },
    });
    expect(cookie.status).toBe(401);
  });

  it("invalid credentials get INVALID_CREDENTIAL and an audit event", async () => {
    const res = await app.request("/v1/organizations", {
      headers: { Authorization: "Bearer vlt_cli_bogus" },
    });
    expect(res.status).toBe(401);
    expect((await res.json()).error.code).toBe("INVALID_CREDENTIAL");
    const audit = await ctx.db.query(
      "SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'authentication.failed'",
    );
    expect((audit.rows[0] as { n: number }).n).toBe(1);
  });

  it("responses carry a request id", async () => {
    const res = await app.request("/v1/meta");
    expect(res.headers.get("X-Request-Id")).toMatch(/^req_/);
  });
});

describe("core loop over HTTP", () => {
  it("org -> project -> environment -> value -> effective configuration", async () => {
    await setupOrgProject();
    const putRes = await put(
      "/v1/organizations/acme/projects/api/environments/development/values/DATABASE_URL",
      { value: "postgres://dev" },
    );
    expect(putRes.status).toBe(200);
    const version = await putRes.json();
    expect(version.versionId).toMatch(/^ver_/);
    // Uncontracted item defaults to sensitive.
    expect(version.sensitive).toBe(true);

    // Uncontracted items are sensitive: include=values never returns them
    // (design R2 — Secrets require the explicit disclosure operation).
    const eff = await app.request(
      "/v1/organizations/acme/projects/api/environments/development/effective-configuration?include=values",
      { headers: auth() },
    );
    expect(eff.status).toBe(200);
    const body = await eff.json();
    expect(body.items).toEqual([
      expect.objectContaining({ name: "DATABASE_URL", value: null, sensitive: true }),
    ]);

    const disclosure = await post(
      "/v1/organizations/acme/projects/api/environments/development/disclosures",
      { items: ["DATABASE_URL", "NOT_A_REAL_ITEM"] },
    );
    expect(disclosure.status).toBe(200);
    expect(disclosure.headers.get("Cache-Control")).toBe("no-store");
    const disclosed = await disclosure.json();
    expect(disclosed.items).toEqual([
      expect.objectContaining({ name: "DATABASE_URL", value: "postgres://dev" }),
    ]);
    expect(disclosed.withheld).toEqual(["NOT_A_REAL_ITEM"]);
    const audit = await ctx.db.query(
      "SELECT metadata FROM audit_events WHERE event_type = 'secret.disclosed'",
    );
    expect(audit.rows.length).toBe(1);
  });

  it("change sets are atomic with expected-version guards on sets and deletes", async () => {
    await setupOrgProject();
    const base = "/v1/organizations/acme/projects/api/environments/development";
    const v1 = await (await put(`${base}/values/ALPHA`, { value: "1" })).json();
    await put(`${base}/values/BETA`, { value: "1" });

    // Stale guard on one item rejects the whole set; nothing written.
    const conflict = await post(`${base}/changes`, {
      changes: [
        { op: "set", item: "ALPHA", value: "2", expectedVersionId: "ver_stale" },
        { op: "set", item: "GAMMA", value: "new" },
      ],
    });
    expect(conflict.status).toBe(409);
    expect((await conflict.json()).error.code).toBe("VERSION_CONFLICT");
    const gamma = await app.request(`${base}/effective-configuration`, { headers: auth() });
    expect((await gamma.json()).items.map((i: { name: string }) => i.name)).toEqual(["ALPHA", "BETA"]);

    // Valid set + guarded delete commits atomically with a shared changeSetId.
    const ok = await post(`${base}/changes`, {
      changes: [
        { op: "set", item: "ALPHA", value: "2", expectedVersionId: v1.versionId },
        { op: "delete", item: "BETA" },
        { op: "set", item: "GAMMA", value: "new" },
      ],
    });
    expect(ok.status).toBe(200);
    const result = await ok.json();
    expect(result.changeSetId).toMatch(/^cs_/);
    expect(result.results.length).toBe(3);
    const after = await app.request(`${base}/effective-configuration`, { headers: auth() });
    expect((await after.json()).items.map((i: { name: string }) => i.name)).toEqual(["ALPHA", "GAMMA"]);
    const audit = await ctx.db.query(
      "SELECT metadata FROM audit_events WHERE metadata::text LIKE '%' || $1 || '%'",
      [result.changeSetId],
    );
    expect(audit.rows.length).toBe(3);
  });

  it("contract push + activate + validate over HTTP", async () => {
    await setupOrgProject();
    const contract = {
      schemaVersion: 1,
      items: [
        { name: "DATABASE_URL", required: { kind: "always" }, sensitive: true, type: "url" },
      ],
    };
    const push = await post("/v1/organizations/acme/projects/api/contract/revisions", { contract });
    expect(push.status).toBe(201);
    const revision = await push.json();
    const activate = await post(
      `/v1/organizations/acme/projects/api/contract/revisions/${revision.id}/activate`,
      {},
    );
    expect(activate.status).toBe(200);
    expect((await activate.json()).active).toBe(true);

    const report = await post(
      "/v1/organizations/acme/projects/api/environments/development/validate",
      {},
    );
    expect(report.status).toBe(200);
    expect(await report.json()).toMatchObject({ valid: false, missing: ["DATABASE_URL"] });
  });

  it("idempotency: same key replays, different body conflicts", async () => {
    await setupOrgProject();
    const path = "/v1/organizations/acme/projects/api/environments/development/values/PORT";
    const first = await put(path, { value: "1" }, { "Idempotency-Key": "k1" });
    const v1 = await first.json();
    const replay = await put(path, { value: "1" }, { "Idempotency-Key": "k1" });
    expect((await replay.json()).versionId).toBe(v1.versionId);
    const conflict = await put(path, { value: "2" }, { "Idempotency-Key": "k1" });
    expect(conflict.status).toBe(409);
    expect((await conflict.json()).error.code).toBe("IDEMPOTENCY_CONFLICT");
  });

  it("optimistic concurrency over HTTP", async () => {
    await setupOrgProject();
    const path = "/v1/organizations/acme/projects/api/environments/development/values/PORT";
    const v1 = await (await put(path, { value: "1" })).json();
    await put(path, { value: "2", expectedVersionId: v1.versionId });
    const stale = await put(path, { value: "3", expectedVersionId: v1.versionId });
    expect(stale.status).toBe(409);
    expect((await stale.json()).error.code).toBe("VERSION_CONFLICT");
  });
});

describe("authorization over HTTP", () => {
  it("hides organizations from outsiders as 404", async () => {
    await setupOrgProject();
    const grant = null;
    void grant;
    // A second human with no membership.
    const outsider = await ctx.db.query(
      "INSERT INTO identities (id, kind, name) VALUES ('idn_outsider','human','Mallory') RETURNING id",
    );
    void outsider;
    const cred = await issueCredential(ctx.db, { identityId: "idn_outsider", kind: "cli" });
    const res = await app.request("/v1/organizations/acme", { headers: auth(cred.token) });
    expect(res.status).toBe(404);
    expect((await res.json()).error.code).toBe("RESOURCE_NOT_FOUND");
  });

  it("service identity with a tier grant can read values; without one cannot", async () => {
    await setupOrgProject();
    const created = await post("/v1/organizations/acme/identities", {
      name: "deploy",
      kind: "service",
    });
    expect(created.status).toBe(201);
    const svc = await created.json();
    expect(svc.credential).toMatch(/^vlt_svc_/);

    // Machine identity, zero grants: metadata denied -> PERMISSION_DENIED
    // (it can see the org exists since it belongs to it).
    const before = await app.request(
      "/v1/organizations/acme/projects/api/environments/development/effective-configuration?include=values",
      { headers: auth(svc.credential) },
    );
    expect(before.status).toBe(403);

    const grantRes = await post("/v1/organizations/acme/grants", {
      subjectIdentityId: svc.id,
      scope: {
        kind: "environments",
        projectId: (await (await app.request("/v1/organizations/acme/projects/api", { headers: auth() })).json()).id,
        selector: { kind: "tier", tier: "development" },
      },
      actions: ["config.metadata.read", "config.value.read", "secret.reveal"],
    });
    expect(grantRes.status).toBe(201);

    await put(
      "/v1/organizations/acme/projects/api/environments/development/values/DATABASE_URL",
      { value: "postgres://dev" },
    );
    const after = await app.request(
      "/v1/organizations/acme/projects/api/environments/development/effective-configuration?include=values",
      { headers: auth(svc.credential) },
    );
    expect(after.status).toBe(200);
    // Uncontracted DATABASE_URL is a Secret: the granted identity retrieves
    // it through the explicit disclosure operation.
    const disclosure = await app.request(
      "/v1/organizations/acme/projects/api/environments/development/disclosures",
      {
        method: "POST",
        headers: auth(svc.credential),
        body: JSON.stringify({ scope: "all-authorized-secrets" }),
      },
    );
    expect(disclosure.status).toBe(200);
    expect((await disclosure.json()).items[0]).toMatchObject({
      name: "DATABASE_URL",
      value: "postgres://dev",
    });
  });

  it("audit list paginates and export streams NDJSON", async () => {
    await setupOrgProject();
    const list = await app.request("/v1/organizations/acme/audit-events?limit=2", {
      headers: auth(),
    });
    expect(list.status).toBe(200);
    const page = await list.json();
    expect(page.items.length).toBe(2);
    expect(page.nextCursor).toBeTruthy();
    const page2 = await app.request(
      `/v1/organizations/acme/audit-events?limit=50&cursor=${page.nextCursor}`,
      { headers: auth() },
    );
    const body2 = await page2.json();
    expect(body2.items.length).toBeGreaterThan(0);
    // No overlap.
    const ids1 = new Set(page.items.map((i: { eventId: string }) => i.eventId));
    for (const item of body2.items) expect(ids1.has(item.eventId)).toBe(false);

    const exportRes = await app.request("/v1/organizations/acme/audit-events/export", {
      headers: auth(),
    });
    expect(exportRes.headers.get("Content-Type")).toContain("application/x-ndjson");
    const lines = (await exportRes.text()).trim().split("\n");
    expect(lines.length).toBeGreaterThan(2);
    for (const line of lines) {
      const event = JSON.parse(line);
      expect(event.schemaVersion).toBe(1);
      expect(event.eventId).toMatch(/^evt_/);
    }
  });
});

describe("environment-name mapping endpoints (removed)", () => {
  it("are gone: every method answers 404", async () => {
    await setupOrgProject();
    for (const [method, path] of [
      ["GET", "/v1/organizations/acme/projects/api/varlock-mapping"],
      ["PUT", "/v1/organizations/acme/projects/api/varlock-mapping/dev"],
      ["DELETE", "/v1/organizations/acme/projects/api/varlock-mapping/dev"],
    ] as const) {
      const res = await app.request(path, {
        method,
        headers: auth(),
        ...(method === "PUT" ? { body: JSON.stringify({ environmentId: "env_x" }) } : {}),
      });
      expect(res.status, `${method} ${path}`).toBe(404);
    }
  });
});

it("rejects oversized streamed bodies before JSON parsing", async () => {
  const body = new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode("x".repeat(1024 * 1024 + 1))); c.close(); } });
  const res = await app.request("/v1/organizations", { method: "POST", headers: auth(), body, duplex: "half" } as RequestInit);
  expect(res.status).toBe(413);
});

it("bounds request work without trusting forwarding headers", async () => {
  for (let i = 0; i < 600; i++) {
    const res = await app.request("/v1/organizations", { headers: { "X-Forwarded-For": `client-${i}` } });
    expect(res.status).toBe(401);
  }
  const res = await app.request("/v1/organizations");
  expect(res.status).toBe(429);
  expect(res.headers.get("Retry-After")).toBeTruthy();
  expect((await app.request("/healthz")).status).toBe(200);
});

it("streams multiple audit batches and redacts historical webhook URLs", async () => {
  const created = await post("/v1/organizations", { name: "Acme", slug: "acme" });
  const org = await created.json();
  await ctx.db.query(`INSERT INTO audit_events (id,event_type,organization_id,decision,metadata)
    SELECT 'export_' || n, 'webhook.created', $1, 'info', '{"url":"https://host.example/old-secret?token=old-token"}'::jsonb
    FROM generate_series(1,601) n`, [org.id]);
  const res = await app.request("/v1/organizations/acme/audit-events/export", { headers: auth() });
  expect(res.status).toBe(200);
  const lines = (await res.text()).trim().split("\n");
  const exported = lines.map(line => JSON.parse(line)).filter(row => row.eventId.startsWith("export_"));
  expect(exported).toHaveLength(601);
  expect(new Set(exported.map(row => row.eventId)).size).toBe(601);
  expect(JSON.stringify(exported)).not.toMatch(/old-secret|old-token/);
});
