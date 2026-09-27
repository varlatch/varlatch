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

/**
 * Cross-project Config Item name search (ADR-0030): names only, literal
 * substring, entitlement-filtered before matching. A hit the caller may not
 * see is indistinguishable from no hit; hidden candidates never affect
 * counts, page boundaries, or cursors.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let svcId: string;
let svcToken: string;
let devEnvId: string;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  adminToken = (await issueCredential(ctx.db, { identityId: consumed.identityId, kind: "cli" })).token;
  app = buildApp(ctx);

  await post("/v1/organizations", { name: "Acme", slug: "acme" });
  await post("/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "git" });
  await post("/v1/organizations/acme/projects/api/environments", { name: "development", tier: "development" });
  await post("/v1/organizations/acme/projects/api/environments", { name: "production", tier: "production" });
  await put("/v1/organizations/acme/projects/api/environments/development/values/DATABASE_URL", {
    value: "postgres://dev",
  });
  await put("/v1/organizations/acme/projects/api/environments/production/values/DATABASE_URL", {
    value: "postgres://prod",
  });
  await put("/v1/organizations/acme/projects/api/environments/production/values/STRIPE_SECRET_KEY", {
    value: "sk_live_x",
  });

  const envs = await (await get("/v1/organizations/acme/projects/api/environments")).json();
  devEnvId = envs.items.find((e: { name: string }) => e.name === "development").id;

  const svc = await (await post("/v1/organizations/acme/identities", { name: "runner", kind: "service" })).json();
  svcId = svc.id;
  svcToken = svc.credential;
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
async function put(path: string, body: unknown) {
  return app.request(path, { method: "PUT", headers: auth(), body: JSON.stringify(body) });
}
async function get(path: string, token = adminToken) {
  return app.request(path, { headers: auth(token) });
}
const search = (params: string, token = adminToken) =>
  get(`/v1/organizations/acme/config-items?${params}`, token);

describe("config item search", () => {
  it("matches a literal case-insensitive substring and groups environments", async () => {
    const res = await search("q=database");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.items).toHaveLength(1);
    const hit = body.items[0];
    expect(hit.name).toBe("DATABASE_URL");
    expect(hit.project.slug).toBe("api");
    expect(hit.sensitive).toBe(true); // no contract: default sensitive
    expect(hit.environments.map((e: { name: string }) => e.name).sort()).toEqual([
      "development",
      "production",
    ]);
    expect(body.nextCursor).toBeNull();
  });

  it("treats underscores as literal characters, never wildcards", async () => {
    // "SE_U" occurs literally in DATABASE_URL; "S_U" does not (an ILIKE
    // wildcard underscore would make it match).
    const literal = await (await search("q=se_u")).json();
    expect(literal.items.map((i: { name: string }) => i.name)).toEqual(["DATABASE_URL"]);
    const wildcard = await (await search("q=s_url")).json();
    expect(wildcard.items).toHaveLength(0);
  });

  it("rejects a missing or empty q — never list-all", async () => {
    expect((await search("")).status).toBe(422);
    expect((await search("q=")).status).toBe(422);
    expect((await search("q=x&limit=0")).status).toBe(422);
    expect((await search("q=x&limit=101")).status).toBe(422);
    expect((await search("q=x&cursor=%%%")).status).toBe(422);
  });

  it("leaks nothing to a caller with zero grants — existing matches are indistinguishable from none", async () => {
    // A machine identity is inherently aware of its own organization
    // (authorize() semantics), so the shape is an empty page, not a 404.
    const res = await search("q=database", svcToken);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.items).toHaveLength(0);
    expect(body.nextCursor).toBeNull();
  });

  it("shows only environments the caller may read metadata in — a production-only name does not exist for a development-only caller", async () => {
    await post("/v1/organizations/acme/grants", {
      subjectIdentityId: svcId,
      scope: {
        kind: "environments",
        projectId: (await (await get("/v1/organizations/acme/projects/api")).json()).id,
        selector: { kind: "environments", environmentIds: [devEnvId] },
      },
      actions: ["config.metadata.read"],
    });

    // DATABASE_URL exists in development: visible, but only that environment.
    const dbHit = await (await search("q=database", svcToken)).json();
    expect(dbHit.items).toHaveLength(1);
    expect(dbHit.items[0].environments.map((e: { name: string }) => e.name)).toEqual(["development"]);

    // STRIPE_SECRET_KEY exists only in production: indistinguishable from no hit.
    const stripe = await (await search("q=stripe", svcToken)).json();
    expect(stripe.items).toHaveLength(0);
    expect(stripe.nextCursor).toBeNull();
  });

  it("paginates grouped results deterministically with an opaque cursor", async () => {
    for (const name of ["A_TOKEN", "B_TOKEN", "C_TOKEN"]) {
      await put(`/v1/organizations/acme/projects/api/environments/development/values/${name}`, {
        value: "v",
      });
    }
    const first = await (await search("q=token&limit=2")).json();
    expect(first.items.map((i: { name: string }) => i.name)).toEqual(["A_TOKEN", "B_TOKEN"]);
    expect(first.nextCursor).not.toBeNull();
    const second = await (
      await search(`q=token&limit=2&cursor=${encodeURIComponent(first.nextCursor)}`)
    ).json();
    expect(second.items.map((i: { name: string }) => i.name)).toEqual(["C_TOKEN"]);
    expect(second.nextCursor).toBeNull();
  });

  it("never returns values or value-derived fields", async () => {
    const body = await (await search("q=database")).json();
    const serialized = JSON.stringify(body);
    expect(serialized).not.toContain("postgres://");
    expect(body.items[0]).not.toHaveProperty("value");
    expect(body.items[0]).not.toHaveProperty("versionId");
  });
});
