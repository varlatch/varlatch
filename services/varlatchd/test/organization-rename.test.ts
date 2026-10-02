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
import {
  latestEventCursor,
  syncAllMirrors,
  syncNewMirrorEvents,
  type MirrorConfig,
} from "../src/mirror/publisher.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * Organization rename (capability organizations.rename): display name only,
 * the slug never changes; organization.manage; existence-hiding; audited
 * with both names; mirrored through the change signal and the full sync.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminId: string;
let adminToken: string;
let orgId: string;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  adminId = (await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" })).identityId;
  adminToken = (await issueCredential(ctx.db, { identityId: adminId, kind: "cli" })).token;
  app = buildApp(ctx);
  const created = await call("POST", "/v1/organizations", { name: "--org", slug: "acme" });
  expect(created.status).toBe(201);
  orgId = created.body.id;
});
afterEach(async () => {
  await ctx.close();
});

async function call(method: string, path: string, body?: unknown, token = adminToken) {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : undefined };
}

const rename = (name: unknown, token = adminToken, org = "acme") =>
  call("PATCH", `/v1/organizations/${org}`, { name }, token);

async function tokenFor(role: "admin" | "member", org = "acme"): Promise<string> {
  const invite = await call("POST", `/v1/organizations/${org}/invitations`, { name: `A ${role}`, role });
  const { identityId } = await consumeSetupGrant(ctx, invite.body.token, {});
  return (await issueCredential(ctx.db, { identityId, kind: "cli" })).token;
}

describe("organization rename", () => {
  it("renames the display name, trimmed, keeps the slug, and audits both names", async () => {
    const res = await rename("  Acme Robotics  ");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ id: orgId, slug: "acme", name: "Acme Robotics", createdAt: expect.any(String) });
    // By slug and by ID alike.
    expect((await call("GET", "/v1/organizations/acme")).body).toMatchObject({ slug: "acme", name: "Acme Robotics" });
    expect((await call("GET", `/v1/organizations/${orgId}`)).body.name).toBe("Acme Robotics");
    expect((await call("GET", "/v1/organizations")).body.items[0]).toMatchObject({ slug: "acme", name: "Acme Robotics" });

    const evt = await ctx.db.query(
      "SELECT actor_identity_id, organization_id, action, decision, resource, metadata FROM audit_events WHERE event_type = 'organization.renamed'",
    );
    const parse = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v);
    const row = evt.rows[0] as Record<string, unknown>;
    expect({ ...row, resource: parse(row.resource), metadata: parse(row.metadata) }).toEqual({
      actor_identity_id: adminId,
      organization_id: orgId,
      action: "organization.manage",
      decision: "info",
      resource: { organizationSlug: "acme" },
      metadata: { previousName: "--org", name: "Acme Robotics" },
    });
    const meta = await app.request("/v1/meta").then((r) => r.json() as Promise<{ capabilities: string[] }>);
    expect(meta.capabilities).toContain("organizations.rename");
  });

  it("validates the name and never changes the slug", async () => {
    for (const name of ["", "   ", "x".repeat(201), ` ${"x".repeat(201)} `, 42, null]) {
      expect((await rename(name)).status, JSON.stringify(name)).toBe(422);
    }
    expect((await call("PATCH", "/v1/organizations/acme", { name: "Fine", slug: "other" })).body).toMatchObject({
      slug: "acme",
      name: "Fine",
    });
    expect((await rename(` ${"x".repeat(200)} `)).status).toBe(200);
    const renames = await ctx.db.query("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'organization.renamed'");
    expect((renames.rows[0] as { n: number }).n).toBe(2);
  });

  it("needs organization.manage and hides the organization from outsiders", async () => {
    // A second Organization Admin may rename it.
    expect((await rename("By another admin", await tokenFor("admin"))).status).toBe(200);
    // A Member sees the organization but may not administer it.
    expect((await rename("By a member", await tokenFor("member"))).status).toBe(403);
    // A machine identity of the org without organization.manage is refused, not hidden.
    const svc = await call("POST", "/v1/organizations/acme/identities", { name: "runner", kind: "service" });
    expect((await rename("By a machine", svc.body.credential)).status).toBe(403);
    // A human of another organization learns nothing; nor does an unknown slug.
    await call("POST", "/v1/organizations", { name: "Other", slug: "other" });
    expect((await rename("By an outsider", await tokenFor("admin", "other"))).status).toBe(404);
    expect((await rename("Nobody", adminToken, "nope")).status).toBe(404);
    expect((await call("GET", "/v1/organizations/acme")).body.name).toBe("By another admin");
    const denied = await ctx.db.query(
      "SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'authorization.denied' AND action = 'organization.manage'",
    );
    // The member, the machine, and the outsider (hidden from them, still audited).
    expect((denied.rows[0] as { n: number }).n).toBe(3);
  });

  it("reaches the Mirror: an organization change signal, then the new name on the full sync", async () => {
    const config: MirrorConfig = { convexUrl: "https://convex.test", issuer: "http://localhost" };
    const upserts: { kind: string; resourceId: string; data: Record<string, unknown> }[] = [];
    const fetchImpl = (async (_url: unknown, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { path: string; args: (typeof upserts)[number] };
      if (body.path === "mirror:upsert") upserts.push(body.args);
      return new Response(JSON.stringify({ status: "success" }), { status: 200 });
    }) as typeof fetch;

    const cursor = await latestEventCursor(ctx);
    expect((await rename("Acme Robotics")).status).toBe(200);
    await syncNewMirrorEvents(ctx, config, cursor, fetchImpl);
    const signal = upserts.find((u) => u.kind === "changeSignal" && u.resourceId === orgId);
    expect(signal?.data.domains).toContain("organization");

    await syncAllMirrors(ctx, config, fetchImpl);
    const mirrored = upserts.find((u) => u.kind === "organization" && u.resourceId === orgId);
    expect(mirrored?.data).toMatchObject({ slug: "acme", name: "Acme Robotics" });
  });
});
