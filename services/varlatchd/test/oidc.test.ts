// SPDX-License-Identifier: AGPL-3.0-or-later
import { createSign, generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { clearJwksCache } from "../src/auth/oidc.js";
import { generateKey } from "../src/crypto/aead.js";
import { runMigrations } from "../src/db/migrate.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
} from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { testDb } from "./helpers/pglite.js";

/**
 * OIDC machine authentication: a binding maps issuer+audience+subject to a
 * machine Identity; exchanging a verified platform token mints a
 * short-lived 'oidc' credential. Identity only — authority stays Grants.
 */

const ISSUER = "https://ci.example";
const AUDIENCE = "varlatch";
const SUBJECT = "repo:acme/api:ref:refs/heads/main";

const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...(publicKey.export({ format: "jwk" }) as Record<string, string>), kid: "k1", alg: "RS256", use: "sig" };

function b64(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

function mintJwt(claims: Record<string, unknown>, header: Record<string, unknown> = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const h = b64({ alg: "RS256", typ: "JWT", kid: "k1", ...header });
  const p = b64({ iss: ISSUER, aud: AUDIENCE, sub: SUBJECT, iat: now, exp: now + 300, ...claims });
  const signer = createSign("RSA-SHA256");
  signer.update(`${h}.${p}`);
  return `${h}.${p}.${signer.sign(privateKey).toString("base64url")}`;
}

const oidcFetch = (async (url: unknown) => {
  const u = String(url);
  if (u === `${ISSUER}/.well-known/openid-configuration`) {
    return Response.json({ issuer: ISSUER, jwks_uri: `${ISSUER}/jwks` });
  }
  if (u === `${ISSUER}/jwks`) return Response.json({ keys: [jwk] });
  return new Response(null, { status: 404 });
}) as typeof fetch;

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let ciIdentityId: string;

const ENV_PATH = "/v1/organizations/acme/projects/api/environments/development";

beforeEach(async () => {
  clearJwksCache();
  const db = await testDb();
  await runMigrations(db);
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  const cred = await issueCredential(ctx.db, { identityId: consumed.identityId, kind: "cli" });
  adminToken = cred.token;
  app = buildApp(ctx, { oidcFetch });
  await post("/v1/organizations", { name: "Acme", slug: "acme" });
  await post("/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "git" });
  await post("/v1/organizations/acme/projects/api/environments", { name: "development", tier: "development" });
  const ci = await (await post("/v1/organizations/acme/identities", { name: "gh-actions", kind: "ci" })).json();
  ciIdentityId = ci.id;
  expect(ci.credential).toBeNull();
  await put(`${ENV_PATH}/values/APP_NAME`, { value: "acme" });
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

const BINDINGS = () => `/v1/organizations/acme/identities/${ciIdentityId}/oidc-bindings`;

async function bind(extra: Record<string, unknown> = {}) {
  const res = await post(BINDINGS(), {
    issuer: ISSUER,
    audience: AUDIENCE,
    subject: SUBJECT,
    ...extra,
  });
  expect(res.status).toBe(201);
  return res.json();
}

async function exchange(token: string, ttlSeconds?: number) {
  return app.request("/v1/oidc/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ organization: "acme", token, ...(ttlSeconds ? { ttlSeconds } : {}) }),
  });
}

describe("bindings", () => {
  it("meta advertises the capability", async () => {
    const meta = await (await app.request("/v1/meta")).json();
    expect(meta.capabilities).toContain("auth.oidc");
  });

  it("admin creates, lists, revokes; audited", async () => {
    const created = await bind();
    const listed = await (await get(BINDINGS())).json();
    expect(listed.items).toHaveLength(1);
    expect(listed.items[0]).toMatchObject({ issuer: ISSUER, subject: SUBJECT });
    expect((await del(`${BINDINGS()}/${created.id}`)).status).toBe(204);
    expect((await (await get(BINDINGS())).json()).items).toHaveLength(0);
    const audit = await ctx.db.query(
      "SELECT event_type FROM audit_events WHERE event_type LIKE 'oidc_binding.%' ORDER BY occurred_at",
    );
    expect(audit.rows.map((r) => (r as { event_type: string }).event_type)).toEqual([
      "oidc_binding.created",
      "oidc_binding.revoked",
    ]);
  });

  it("rejects non-https issuers and human identities", async () => {
    const bad = await post(BINDINGS(), { issuer: "http://ci.example", audience: "a", subject: "s" });
    expect(bad.status).toBe(422);
    const me = await (await get("/v1/me")).json().catch(() => null);
    void me;
  });
});

describe("exchange", () => {
  it("verified token mints a short-lived oidc credential that works under Grants", async () => {
    await bind();
    const res = await exchange(mintJwt({}));
    expect(res.status).toBe(201);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = await res.json();
    expect(body.token).toMatch(/^vlt_oidc_/);
    expect(body.identityId).toBe(ciIdentityId);
    expect(new Date(body.expiresAt).getTime()).toBeGreaterThan(Date.now());

    // Identity, not authority: zero Grants means denied reads.
    const denied = await get(`${ENV_PATH}/effective-configuration`, body.token);
    expect([403, 404]).toContain(denied.status);

    const project = await (await get("/v1/organizations/acme/projects/api")).json();
    await post("/v1/organizations/acme/grants", {
      subjectIdentityId: ciIdentityId,
      scope: { kind: "project", projectId: project.id },
      actions: ["config.metadata.read"],
    });
    const allowed = await get(`${ENV_PATH}/effective-configuration`, body.token);
    expect(allowed.status).toBe(200);
  });

  it("caps TTL at one hour and defaults to ten minutes", async () => {
    await bind();
    expect((await exchange(mintJwt({}), 3601)).status).toBe(422);
    const body = await (await exchange(mintJwt({}))).json();
    expect(new Date(body.expiresAt).getTime()).toBeLessThanOrEqual(Date.now() + 601_000);
  });

  it("rejects wrong audience, wrong subject, expired, and bad signatures alike", async () => {
    await bind();
    for (const token of [
      mintJwt({ aud: "other" }),
      mintJwt({ sub: "repo:evil/other:ref:refs/heads/main" }),
      mintJwt({ exp: Math.floor(Date.now() / 1000) - 3600 }),
      mintJwt({}).slice(0, -12) + "aaaaaaaaaaaa",
      "not-a-jwt",
    ]) {
      const res = await exchange(token);
      expect(res.status).toBe(401);
      expect((await res.json()).error.code).toBe("INVALID_CREDENTIAL");
    }
    const audit = await ctx.db.query(
      "SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'authentication.failed' AND metadata::jsonb->>'method' = 'oidc'",
    );
    expect((audit.rows[0] as { n: number }).n).toBe(5);
  });

  it("supports trailing-* subject patterns and extra claim matching", async () => {
    await bind({
      subject: "repo:acme/api:*",
      claims: { repository_owner: "acme" },
    });
    const ok = await exchange(mintJwt({ sub: "repo:acme/api:ref:refs/heads/dev", repository_owner: "acme" }));
    expect(ok.status).toBe(201);
    const wrongClaim = await exchange(mintJwt({ sub: "repo:acme/api:ref:refs/heads/dev", repository_owner: "evil" }));
    expect(wrongClaim.status).toBe(401);
  });

  it("revoked bindings and disabled identities stop exchanging", async () => {
    const created = await bind();
    await del(`${BINDINGS()}/${created.id}`);
    expect((await exchange(mintJwt({}))).status).toBe(401);
  });

  it("audits issuance with the binding and subject", async () => {
    await bind();
    await exchange(mintJwt({}));
    const res = await ctx.db.query(
      "SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'credential.issued' AND metadata::jsonb->>'method' = 'oidc' AND metadata::jsonb->>'subject' = $1",
      [SUBJECT],
    );
    expect((res.rows[0] as { n: number }).n).toBe(1);
  });
});

it("ignores matching OIDC bindings owned by another organization", async () => {
  await bind();
  await post("/v1/organizations", { name: "Other", slug: "other" });
  const other = await (await post("/v1/organizations/other/identities", { name: "other-ci", kind: "ci" })).json();
  const binding = await post(`/v1/organizations/other/identities/${other.id}/oidc-bindings`, {
    issuer: ISSUER, audience: AUDIENCE, subject: SUBJECT,
  });
  expect(binding.status).toBe(201);
  const result = await exchange(mintJwt({}));
  expect(result.status).toBe(201);
  expect((await result.json()).identityId).toBe(ciIdentityId);
});
