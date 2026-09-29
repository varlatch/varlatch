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
 * Project rename (capability projects.rename): display name only, the slug
 * never changes; project.manage; existence-hiding; audited with both names.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let svcToken: string;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  adminToken = (await issueCredential(ctx.db, { identityId: consumed.identityId, kind: "cli" })).token;
  app = buildApp(ctx);
  await post("/v1/organizations", { name: "Acme", slug: "acme" });
  const svc = await (
    await post("/v1/organizations/acme/identities", { name: "runner-01", kind: "service" })
  ).json();
  svcToken = svc.credential;
});
afterEach(async () => {
  await ctx.close();
});

function auth(token = adminToken): HeadersInit {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}
async function post(path: string, body?: unknown, token = adminToken) {
  return app.request(path, {
    method: "POST",
    headers: auth(token),
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}
async function patch(path: string, body: unknown, token = adminToken) {
  return app.request(path, { method: "PATCH", headers: auth(token), body: JSON.stringify(body) });
}
async function get(path: string, token = adminToken) {
  return app.request(path, { headers: auth(token) });
}

describe("project rename", () => {
  it("renames the display name, keeps the slug, and audits both names", async () => {
    const created = await post("/v1/organizations/acme/projects", { slug: "gateway", name: "--org", contractAuthority: "git" });
    expect(created.status).toBe(201);
    const res = await patch("/v1/organizations/acme/projects/gateway", { name: "AI subscription gateway" });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ slug: "gateway", name: "AI subscription gateway" });
    const fetched = await (await get("/v1/organizations/acme/projects/gateway")).json();
    expect(fetched).toMatchObject({ slug: "gateway", name: "AI subscription gateway" });
    const evt = await ctx.db.query(
      "SELECT metadata, resource FROM audit_events WHERE event_type = 'project.renamed'",
    );
    const row = evt.rows[0] as { metadata: unknown; resource: unknown };
    const parse = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v) as Record<string, unknown>;
    expect(parse(row.metadata)).toEqual({ previousName: "--org", name: "AI subscription gateway" });
    expect(parse(row.resource)).toMatchObject({ projectSlug: "gateway" });
    const meta = await (await get("/v1/meta")).json();
    expect(meta.capabilities).toContain("projects.rename");
  });

  it("validates the name, needs project.manage, and hides unknown projects", async () => {
    await post("/v1/organizations/acme/projects", { slug: "gateway", name: "gateway", contractAuthority: "git" });
    expect((await patch("/v1/organizations/acme/projects/gateway", { name: "" })).status).toBe(422);
    expect((await patch("/v1/organizations/acme/projects/gateway", { name: "x".repeat(201) })).status).toBe(422);
    expect((await patch("/v1/organizations/acme/projects/nope", { name: "x" })).status).toBe(404);
    // A machine identity of the org without project.manage is refused (it
    // knows its own organization, so the refusal is not hidden as not found).
    expect((await patch("/v1/organizations/acme/projects/gateway", { name: "x" }, svcToken)).status).toBe(403);
    const unchanged = await (await get("/v1/organizations/acme/projects/gateway")).json();
    expect(unchanged.name).toBe("gateway");
  });
});
