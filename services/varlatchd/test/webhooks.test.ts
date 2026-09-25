// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { runMigrations } from "../src/db/migrate.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
} from "../src/domain/bootstrap.js";
import { deliverWebhooksOnce, SIGNATURE_HEADER } from "../src/domain/webhooks.js";
import { buildApp } from "../src/http/app.js";
import { testDb } from "./helpers/pglite.js";

/**
 * Audit webhooks: signed, ordered, at-least-once delivery of an org's audit
 * stream to an operator-registered endpoint, starting at registration.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;

const ENV_PATH = "/v1/organizations/acme/projects/api/environments/development";

beforeEach(async () => {
  const db = await testDb();
  await runMigrations(db);
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  const cred = await issueCredential(ctx.db, { identityId: consumed.identityId, kind: "cli" });
  adminToken = cred.token;
  app = buildApp(ctx);
  await post("/v1/organizations", { name: "Acme", slug: "acme" });
  await post("/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "git" });
  await post("/v1/organizations/acme/projects/api/environments", { name: "development", tier: "development" });
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
async function get(path: string, token = adminToken) {
  return app.request(path, { headers: auth(token) });
}
async function del(path: string, token = adminToken) {
  return app.request(path, { method: "DELETE", headers: auth(token) });
}

interface Delivery {
  url: string;
  body: string;
  header: string;
}

function fakeFetch(deliveries: Delivery[], status = 200): typeof fetch {
  return (async (url: unknown, init?: RequestInit) => {
    deliveries.push({
      url: String(url),
      body: String(init?.body),
      header: (init?.headers as Record<string, string>)[SIGNATURE_HEADER],
    });
    return new Response(null, { status });
  }) as typeof fetch;
}

async function register(body: Record<string, unknown> = {}) {
  const res = await post("/v1/organizations/acme/webhooks", {
    url: "https://sink.example/hook",
    ...body,
  });
  expect(res.status).toBe(201);
  expect(res.headers.get("Cache-Control")).toBe("no-store");
  return res.json();
}

describe("registration", () => {
  it("meta advertises the capability", async () => {
    const meta = await (await app.request("/v1/meta")).json();
    expect(meta.capabilities).toContain("webhooks.audit");
  });

  it("returns the signing secret exactly once and never again", async () => {
    const created = await register();
    expect(created.secret).toMatch(/^vlt_whsec_/);
    const listed = await (await get("/v1/organizations/acme/webhooks")).json();
    expect(listed.items).toHaveLength(1);
    expect(JSON.stringify(listed)).not.toContain(created.secret);
  });

  it("stores the secret encrypted, never plaintext at rest", async () => {
    const created = await register();
    const row = await ctx.db.query("SELECT secret_envelope FROM webhooks");
    expect(JSON.stringify(row.rows[0])).not.toContain(created.secret);
  });

  it("rejects non-http(s) URLs", async () => {
    const res = await post("/v1/organizations/acme/webhooks", { url: "ftp://x" });
    expect(res.status).toBe(422);
  });

  it("audits registration and revocation", async () => {
    const created = await register();
    await del(`/v1/organizations/acme/webhooks/${created.id}`);
    const res = await ctx.db.query(
      "SELECT event_type FROM audit_events WHERE event_type LIKE 'webhook.%' ORDER BY occurred_at",
    );
    expect(res.rows.map((r) => (r as { event_type: string }).event_type)).toEqual([
      "webhook.created",
      "webhook.revoked",
    ]);
  });
});

describe("delivery", () => {
  it("delivers only post-registration events, signed and verifiable", async () => {
    const created = await register();
    await put(`${ENV_PATH}/values/APP_NAME`, { value: "acme" });

    const deliveries: Delivery[] = [];
    await deliverWebhooksOnce(ctx, fakeFetch(deliveries));
    expect(deliveries).toHaveLength(1);
    const { body, header, url } = deliveries[0];
    expect(url).toBe("https://sink.example/hook");

    const match = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(header);
    expect(match).toBeTruthy();
    const [, t, v1] = match as unknown as [string, string, string];
    const expected = createHmac("sha256", created.secret).update(`${t}.${body}`).digest("hex");
    expect(v1).toBe(expected);

    const payload = JSON.parse(body);
    expect(payload.webhookId).toBe(created.id);
    const types = payload.events.map((e: { eventType: string }) => e.eventType);
    // Registration precedes the cursor start; only later events arrive.
    expect(types).not.toContain("webhook.created");
    expect(types).toContain("value.written");
  });

  it("advances the cursor on success and does not redeliver", async () => {
    await register();
    await put(`${ENV_PATH}/values/APP_NAME`, { value: "acme" });
    const first: Delivery[] = [];
    await deliverWebhooksOnce(ctx, fakeFetch(first));
    expect(first).toHaveLength(1);
    const again: Delivery[] = [];
    await deliverWebhooksOnce(ctx, fakeFetch(again));
    expect(again).toHaveLength(0);
  });

  it("keeps the cursor on failure and retries the same batch", async () => {
    await register();
    await put(`${ENV_PATH}/values/APP_NAME`, { value: "acme" });
    const failed: Delivery[] = [];
    await deliverWebhooksOnce(ctx, fakeFetch(failed, 500));
    expect(failed).toHaveLength(1);
    const retried: Delivery[] = [];
    await deliverWebhooksOnce(ctx, fakeFetch(retried));
    expect(retried).toHaveLength(1);
    expect(JSON.parse(retried[0].body).events.length).toBeGreaterThan(0);
    const row = await (await get("/v1/organizations/acme/webhooks")).json();
    expect(row.items[0].lastStatus).toBe("200");
  });

  it("honors the event-type filter", async () => {
    await register({ eventTypes: ["value.written"] });
    await put(`${ENV_PATH}/values/APP_NAME`, { value: "acme" });
    await post("/v1/organizations/acme/projects", { name: "Web", slug: "web", contractAuthority: "git" });
    const deliveries: Delivery[] = [];
    await deliverWebhooksOnce(ctx, fakeFetch(deliveries));
    const types = JSON.parse(deliveries[0].body).events.map(
      (e: { eventType: string }) => e.eventType,
    );
    expect(new Set(types)).toEqual(new Set(["value.written"]));
  });

  it("revoked webhooks receive nothing", async () => {
    const created = await register();
    await del(`/v1/organizations/acme/webhooks/${created.id}`);
    await put(`${ENV_PATH}/values/APP_NAME`, { value: "acme" });
    const deliveries: Delivery[] = [];
    await deliverWebhooksOnce(ctx, fakeFetch(deliveries));
    expect(deliveries).toHaveLength(0);
  });
});

describe("authorization", () => {
  it("service identities cannot manage webhooks", async () => {
    const svc = await (
      await post("/v1/organizations/acme/identities", { name: "svc", kind: "service" })
    ).json();
    const res = await post(
      "/v1/organizations/acme/webhooks",
      { url: "https://sink.example/hook" },
      svc.credential,
    );
    expect([403, 404]).toContain(res.status);
  });
});
