// SPDX-License-Identifier: AGPL-3.0-or-later
import { execFileSync } from "node:child_process";
import { createSign, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { clearJwksCache } from "../src/auth/oidc.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import { clearRefusedBackoff, reconcileTarget, runSyncOnce } from "../src/domain/syncdelivery.js";
import { deliverWebhooksOnce } from "../src/domain/webhooks.js";
import { buildApp } from "../src/http/app.js";
import { OutboundPolicy, type Resolver } from "../src/net/outbound.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * Every caller of the outbound policy (ADR-0057): save-time refusals with
 * the class's wording, connection-time refusals that lose nothing, and the
 * audit event. DNS comes from each test's resolver; refused requests never
 * open a socket, and allowed ones reach local test servers.
 */

const resolverOf =
  (answers: Record<string, string[]>): Resolver =>
  async (name) => {
    const list = answers[name];
    if (!list) throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${name}`), { code: "ENOTFOUND" });
    return list.map((address) => ({ address, family: address.includes(":") ? (6 as const) : (4 as const) }));
  };

const ANSWERS: Record<string, string[]> = {
  "hooks.lan": ["127.0.0.1"],
  "private.lan": ["10.0.0.5"],
  "coolify.lan": ["127.0.0.1"],
  "coolify.private": ["10.0.0.5"],
  "sink.example": ["93.184.215.14"],
  "mixed.example": ["93.184.215.14", "10.0.0.7"],
  "issuer.lan": ["10.0.0.8"],
  "ci.example": ["93.184.215.14"],
  "api.github.com": ["10.0.0.1"],
};

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
const policies: OutboundPolicy[] = [];
const servers: { close: () => void }[] = [];

function policy(spec: string, extra: Record<string, unknown> = {}): OutboundPolicy {
  const p = new OutboundPolicy(spec, { resolve: resolverOf(ANSWERS), log: () => {}, ...extra });
  policies.push(p);
  return p;
}

const ENV_PATH = "/v1/organizations/acme/projects/api/environments/development";

beforeEach(async () => {
  clearJwksCache();
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close, outbound: policy("") };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  adminToken = (await issueCredential(ctx.db, { identityId: consumed.identityId, kind: "cli" })).token;
  app = buildApp(ctx);
  await post("/v1/organizations", { name: "Acme", slug: "acme" });
  await post("/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "git" });
  await post("/v1/organizations/acme/projects/api/environments", { name: "development", tier: "development" });
  await put(`${ENV_PATH}/values/PORT`, { value: "8080" });
});
afterEach(async () => {
  for (const s of servers.splice(0)) s.close();
  for (const p of policies.splice(0)) await p.close();
  await ctx.close();
});

const auth = (): HeadersInit => ({ Authorization: `Bearer ${adminToken}`, "Content-Type": "application/json" });
const post = (path: string, body: unknown) => app.request(path, { method: "POST", headers: auth(), body: JSON.stringify(body) });
const put = (path: string, body: unknown) => app.request(path, { method: "PUT", headers: auth(), body: JSON.stringify(body) });
const patch = (path: string, body: unknown) => app.request(path, { method: "PATCH", headers: auth(), body: JSON.stringify(body) });

async function refusals(): Promise<{ resource: Record<string, string>; metadata: Record<string, unknown>; decision: string }[]> {
  const res = await ctx.db.query("SELECT resource, metadata, decision FROM audit_events WHERE event_type = 'outbound.refused' ORDER BY event_order");
  const parse = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v);
  return (res.rows as { resource: unknown; metadata: unknown; decision: string }[]).map((r) => ({ resource: parse(r.resource), metadata: parse(r.metadata), decision: r.decision }));
}

async function httpServer(handler: http.RequestListener): Promise<number> {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  servers.push({ close: () => server.close() });
  return (server.address() as AddressInfo).port;
}

describe("webhooks", () => {
  it("refuses a private, loopback or plain-http URL at create and PATCH, in the class's words, audited", async () => {
    const created = await post("/v1/organizations/acme/webhooks", { url: "https://private.lan/hook?token=secret" });
    expect(created.status).toBe(422);
    const body = await created.json();
    expect(body.error.message).toMatch(/private network.*VARLATCH_OUTBOUND_ALLOW/);
    expect(JSON.stringify(body)).not.toContain("10.0.0.5");
    expect((await post("/v1/organizations/acme/webhooks", { url: "https://hooks.lan/hook" })).status).toBe(422);
    const http80 = await post("/v1/organizations/acme/webhooks", { url: "http://sink.example/hook" });
    expect((await http80.json()).error.message).toMatch(/Plain http is allowed only/);
    const mixed = await post("/v1/organizations/acme/webhooks", { url: "https://mixed.example/hook" });
    expect((await mixed.json()).error.message).toMatch(/several addresses/);
    // A name that does not resolve is saved: delivery decides.
    expect((await post("/v1/organizations/acme/webhooks", { url: "https://unknown.example/hook" })).status).toBe(201);
    const ok = await (await post("/v1/organizations/acme/webhooks", { url: "https://sink.example/hook" })).json();
    const changed = await patch(`/v1/organizations/acme/webhooks/${ok.webhook?.id ?? ok.id}`, { expectedVersion: 1, url: "https://private.lan/x" });
    expect(changed.status).toBe(422);

    const events = await refusals();
    expect(events.map((e) => [e.metadata.reason, e.metadata.phase, e.metadata.purpose])).toEqual([
      ["private_address", "configuration", "webhook"],
      ["host_only_address", "configuration", "webhook"],
      ["scheme", "configuration", "webhook"],
      ["mixed_answers", "configuration", "webhook"],
      ["private_address", "configuration", "webhook"],
    ]);
    expect(events[0]?.decision).toBe("deny");
    expect(events[0]?.metadata).toEqual({ purpose: "webhook", phase: "configuration", scheme: "https", host: "private.lan", port: 443, reason: "private_address" });
    const all = JSON.stringify(events);
    for (const leak of ["10.0.0.5", "127.0.0.1", "token", "secret", "/hook"]) expect(all).not.toContain(leak);
  });

  it("holds the cursor while delivery is refused, then delivers everything once the host allows it", async () => {
    const received: string[] = [];
    const port = await httpServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += String(c)));
      req.on("end", () => {
        received.push(body);
        res.end();
      });
    });
    // Configured before the upgrade, when the host allowed it.
    ctx.outbound = policy("127.0.0.1/32:*");
    const hook = await (await post("/v1/organizations/acme/webhooks", { url: `http://hooks.lan:${port}/hook` })).json();
    const webhookId = hook.webhook?.id ?? hook.id;
    await put(`${ENV_PATH}/values/A`, { value: "1" });
    // The new release, started without the allow list.
    ctx.outbound = policy("");
    for (let i = 0; i < 3; i++) await deliverWebhooksOnce(ctx);
    expect(received).toHaveLength(0);
    const held = (await ctx.db.query("SELECT last_status, cursor_order, revoked_at FROM webhooks WHERE id = $1", [webhookId])).rows[0] as Record<string, unknown>;
    expect(held).toMatchObject({ last_status: "outbound_refused", revoked_at: null });
    // One connection-phase event for three refusals (the hourly bound).
    const connection = (await refusals()).filter((e) => e.metadata.phase === "connection");
    expect(connection).toHaveLength(1);
    expect(connection[0]).toMatchObject({ resource: { webhookId }, metadata: { purpose: "webhook", reason: "host_only_address", host: "hooks.lan", port } });
    // Restarted with the allow list: the backlog goes out.
    ctx.outbound = policy("127.0.0.1/32:*");
    await deliverWebhooksOnce(ctx);
    expect(received).toHaveLength(1);
    expect(JSON.parse(received[0] as string).events.map((e: { eventType: string }) => e.eventType)).toContain("value.written");
    const after = (await ctx.db.query("SELECT last_status, cursor_order FROM webhooks WHERE id = $1", [webhookId])).rows[0] as Record<string, unknown>;
    expect(after.last_status).toBe("200");
    expect(Number(after.cursor_order)).toBeGreaterThan(Number(held.cursor_order));
  });
});

/** A Coolify API on a local TLS server, with a certificate for coolify.lan. */
async function localCoolify(): Promise<{ port: number; ca: string; values: Map<string, string> }> {
  const dir = mkdtempSync(join(tmpdir(), "outbound-coolify-"));
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
    "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem"), "-days", "2",
    "-subj", "/CN=coolify.lan", "-addext", "subjectAltName=DNS:coolify.lan",
  ], { stdio: "ignore" });
  const cert = readFileSync(join(dir, "cert.pem"), "utf8");
  const values = new Map<string, string>();
  let next = 1;
  const server = https.createServer({ key: readFileSync(join(dir, "key.pem"), "utf8"), cert }, (req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += String(c)));
    req.on("end", () => {
      const json = (payload: unknown, status = 200) => {
        res.writeHead(status, { "Content-Type": "application/json" });
        res.end(JSON.stringify(payload));
      };
      const url = req.url ?? "";
      if (url.endsWith("/envs") && req.method === "GET") return json([...values].map(([key, value]) => ({ uuid: key, key, value, is_literal: true })));
      if (url.endsWith("/envs") && (req.method === "POST" || req.method === "PATCH")) {
        const b = JSON.parse(raw) as { key: string; value: string };
        values.set(b.key, b.value);
        return json({ uuid: `env${next++}` }, req.method === "POST" ? 201 : 200);
      }
      if (req.method === "POST" && (url.endsWith("/restart") || url.endsWith("/start?force=true"))) return json({ message: "queued" });
      return json({ message: "not found" }, 404);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  servers.push({ close: () => server.close() });
  return { port: (server.address() as AddressInfo).port, ca: cert, values };
}

describe("Coolify and Convex Connections", () => {
  it("refuses a private base at create, and reports check and listing as unreachable in the policy's words", async () => {
    const create = await post("/v1/organizations/acme/platform-connections", { platform: "coolify", baseIdentity: "https://coolify.private", name: "lan", credential: "tok" });
    expect(create.status).toBe(422);
    expect((await create.json()).error.message).toMatch(/private network/);
    const check = await (await post("/v1/organizations/acme/platform-connections/check", { platform: "coolify", baseIdentity: "https://coolify.private", credential: "tok" })).json();
    expect(check).toMatchObject({ status: "unreachable" });
    expect(check.message).toMatch(/private network/);
    expect(check.message).not.toMatch(/could not reach/);
    const listing = await (await post("/v1/organizations/acme/platform-connections/destinations", { platform: "coolify", baseIdentity: "https://coolify.private", credential: "tok" })).json();
    expect(listing.check).toMatchObject({ status: "unreachable" });
    expect(listing.items).toEqual([]);
    const convex = await post("/v1/organizations/acme/platform-connections", { platform: "convex", baseIdentity: "https://coolify.private:3210", name: "c", credential: "tok" });
    expect(convex.status).toBe(422);
    expect((await refusals()).map((e) => e.metadata.purpose)).toEqual(["sync_check", "sync_check", "sync_listing", "sync_check"]);
  });

  it("words a connection-time refusal inside an adapter as the policy's, never 'could not reach'", async () => {
    // Saved while the name answered public; it answers private when checked.
    let calls = 0;
    ctx.outbound = new OutboundPolicy("", { log: () => {}, resolve: async () => [{ address: calls++ === 0 ? "93.184.215.14" : "10.0.0.5", family: 4 }] });
    policies.push(ctx.outbound);
    const check = await (await post("/v1/organizations/acme/platform-connections/check", { platform: "coolify", baseIdentity: "https://moving.example", credential: "tok" })).json();
    expect(check.status).toBe("unreachable");
    expect(check.message).toMatch(/private network/);
    expect((await refusals()).map((e) => [e.metadata.purpose, e.metadata.phase])).toEqual([["sync_check", "connection"]]);
  });

  it("never disables a refused Target nor spends its failure budget, and delivers after a restart with the allow list", async () => {
    const coolify = await localCoolify();
    ctx.outbound = policy("127.0.0.1/32:*", { tls: { ca: coolify.ca } });
    const base = `https://coolify.lan:${coolify.port}`;
    const connection = await (await post("/v1/organizations/acme/platform-connections", { platform: "coolify", baseIdentity: base, name: "local", credential: "tok" })).json();
    expect(connection.id).toBeDefined();
    const target = await (await post(`${ENV_PATH}/sync-targets`, { connectionId: connection.id, destination: { applicationUuid: "app1" }, mapping: { kind: "wildcard" } })).json();
    expect(target.id).toBeDefined();
    // Upgraded: no allow list.
    ctx.outbound = policy("", { tls: { ca: coolify.ca } });
    for (let i = 0; i < 12; i++) await reconcileTarget(ctx, target.id, {});
    const row = (await ctx.db.query("SELECT state, failure_count, needs_sync, last_result, next_attempt_at FROM sync_targets WHERE id = $1", [target.id])).rows[0] as Record<string, unknown>;
    expect(row).toMatchObject({ state: "active", failure_count: 0, needs_sync: true, last_result: "outbound_refused: host_only_address" });
    expect(new Date(row.next_attempt_at as string).getTime()).toBeGreaterThan(Date.now() + 50 * 60_000);
    expect(coolify.values.size).toBe(0);
    const connectionEvents = (await refusals()).filter((e) => e.metadata.purpose === "sync_delivery");
    expect(connectionEvents).toHaveLength(1);
    expect(connectionEvents[0]).toMatchObject({ resource: { targetId: target.id }, metadata: { phase: "connection", host: "coolify.lan" } });
    // Restarted with the allow list: the backoff is cleared at startup and the Target converges.
    ctx.outbound = policy("127.0.0.1/32:*", { tls: { ca: coolify.ca } });
    await clearRefusedBackoff(ctx);
    await runSyncOnce(ctx, {});
    expect(coolify.values.get("PORT")).toBe("8080");
    const done = (await ctx.db.query("SELECT state, failure_count, last_result FROM sync_targets WHERE id = $1", [target.id])).rows[0] as Record<string, unknown>;
    expect(done).toMatchObject({ state: "active", failure_count: 0, last_result: "ok" });
  });
});

describe("GitHub", () => {
  it("goes through the policy, and reports a refusal as unreachable in its words", async () => {
    const spy = vi.spyOn(ctx.outbound as OutboundPolicy, "fetch");
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const res = await post("/v1/organizations/acme/github-app/import", { appId: 1, privateKey: privateKey.export({ type: "pkcs1", format: "pem" }).toString() });
    const body = await res.json();
    expect(spy).toHaveBeenCalledWith("github", expect.objectContaining({ organizationId: expect.any(String) }));
    expect(body).toMatchObject({ outcome: "failed", status: "unreachable" });
    expect(body.message).toMatch(/private network/);
    expect((await refusals()).at(-1)?.metadata).toMatchObject({ purpose: "github", phase: "connection", host: "api.github.com", reason: "private_address" });
  });
});

describe("OIDC", () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  function token(iss: string): string {
    const now = Math.floor(Date.now() / 1000);
    const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const h = b64({ alg: "RS256", kid: "k1" });
    const p = b64({ iss, aud: "varlatch", sub: "repo:acme/api", exp: now + 300 });
    const s = createSign("RSA-SHA256");
    s.update(`${h}.${p}`);
    return `${h}.${p}.${s.sign(privateKey).toString("base64url")}`;
  }

  it("refuses a binding to a private issuer", async () => {
    const ci = await (await post("/v1/organizations/acme/identities", { name: "ci", kind: "ci" })).json();
    const res = await post(`/v1/organizations/acme/identities/${ci.id}/oidc-bindings`, { issuer: "https://issuer.lan", audience: "varlatch", subject: "x" });
    expect(res.status).toBe(422);
    expect((await res.json()).error.message).toMatch(/private network/);
    expect((await refusals())[0]?.metadata).toMatchObject({ purpose: "oidc", phase: "configuration", reason: "private_address" });
  });

  it("refuses a private jwks_uri at exchange with the generic failure, audited", async () => {
    const ci = await (await post("/v1/organizations/acme/identities", { name: "ci", kind: "ci" })).json();
    const issuer = "https://ci.example";
    expect((await post(`/v1/organizations/acme/identities/${ci.id}/oidc-bindings`, { issuer, audience: "varlatch", subject: "repo:acme/api" })).status).toBe(201);
    // Discovery answers (from a stub); the JWKS fetch goes through the real policy.
    const governed = (ctx.outbound as OutboundPolicy).fetch("oidc");
    const oidcFetch = (async (url: unknown, init?: RequestInit) =>
      String(url) === `${issuer}/.well-known/openid-configuration`
        ? Response.json({ issuer, jwks_uri: "https://issuer.lan/jwks" })
        : governed(String(url), init)) as typeof fetch;
    app = buildApp(ctx, { oidcFetch });
    const res = await app.request("/v1/oidc/token", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ organization: "acme", token: token(issuer) }) });
    expect(res.status).toBe(401);
    expect((await res.json()).error.message).toBe("OIDC token was not accepted");
    const events = await refusals();
    expect(events.at(-1)).toMatchObject({ metadata: { purpose: "oidc", phase: "connection", reason: "private_address", host: "issuer.lan" } });
  });
});
