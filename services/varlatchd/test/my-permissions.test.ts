// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * The caller's own organization-level permissions (GET
 * /v1/organizations/:org/me/permissions): what the dashboard uses to show
 * only what the caller may read. A member reads it without any refusal;
 * custom organization-wide Grants count, project Grants do not; an outsider
 * sees nothing.
 */

const ORG = "/v1/organizations/acme";
const PERMISSIONS = `${ORG}/me/permissions`;
const ALL = [
  "organization.read", "organization.manage", "project.read", "project.manage",
  "identity.read", "identity.manage", "policy.read", "policy.manage", "audit.read",
];

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let orgId: string;
let otherId: string;
let admin: { id: string; cli: string };

async function call(method: string, path: string, token: string, body?: unknown) {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null, headers: res.headers };
}

async function invite(name: string, role: "admin" | "member", organizationId = orgId) {
  const grant = await issueInviteGrant(ctx, { organizationId, role, name }, admin.id);
  const { identityId } = await consumeSetupGrant(ctx, grant.token, {});
  return { id: identityId, cli: (await issueCredential(ctx.db, { identityId, kind: "cli" })).token };
}

async function grant(subjectIdentityId: string, actions: string[], scope: Record<string, unknown> = { kind: "organization" }) {
  const res = await call("POST", `${ORG}/grants`, admin.cli, { subjectIdentityId, scope, actions });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
}

async function permissions(token: string) {
  const res = await call("GET", PERMISSIONS, token);
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  return res.body as { organizationId: string; role: string | null; actions: string[] };
}

const denials = async () =>
  ((await ctx.db.query("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'authorization.denied'")).rows[0] as { n: number }).n;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const { identityId } = await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" });
  app = buildApp(ctx);
  admin = { id: identityId, cli: (await issueCredential(ctx.db, { identityId, kind: "cli" })).token };
  orgId = (await call("POST", "/v1/organizations", admin.cli, { name: "Acme", slug: "acme" })).body.id;
  otherId = (await call("POST", "/v1/organizations", admin.cli, { name: "Other", slug: "other" })).body.id;
});
afterEach(async () => {
  await ctx.close();
});

describe("my organization permissions", () => {
  it("is advertised as a capability", async () => {
    expect((await call("GET", "/v1/meta", admin.cli)).body.capabilities).toContain("organizations.permissions");
  });

  it("gives an admin every organization-level action", async () => {
    expect(await permissions(admin.cli)).toEqual({ organizationId: orgId, role: "admin", actions: ALL });
  });

  it("gives a plain member what the member bundle allows, and records no refusal", async () => {
    const bob = await invite("Bob", "member");
    const before = await denials();
    expect(await permissions(bob.cli)).toEqual({ organizationId: orgId, role: "member", actions: ["organization.read", "project.read"] });
    expect(await denials()).toBe(before);
  });

  it("counts a member's organization-wide Grants, not project ones", async () => {
    const bob = await invite("Bob", "member");
    await grant(bob.id, ["identity.manage", "policy.read"]);
    const project = await call("POST", `${ORG}/projects`, admin.cli, { name: "Web", slug: "web", contractAuthority: "managed" });
    expect(project.status, JSON.stringify(project.body)).toBe(201);
    await grant(bob.id, ["project.manage"], { kind: "project", projectId: project.body.id });
    expect((await permissions(bob.cli)).actions).toEqual(["organization.read", "project.read", "identity.manage", "policy.read"]);
  });

  it("answers a machine with its organization-wide Grants and no role", async () => {
    const svc = await call("POST", `${ORG}/identities`, admin.cli, { name: "svc", kind: "service" });
    expect(svc.status).toBe(201);
    await grant(svc.body.id, ["organization.read", "audit.read"]);
    expect(await permissions(svc.body.credential)).toEqual({ organizationId: orgId, role: null, actions: ["organization.read", "audit.read"] });
  });

  it("hides the organization from an outsider, and is not cached", async () => {
    const outsider = await invite("Outsider", "member", otherId);
    expect((await call("GET", PERMISSIONS, outsider.cli)).status).toBe(404);
    expect((await call("GET", "/v1/organizations/nope/me/permissions", admin.cli)).status).toBe(404);
    expect((await call("GET", PERMISSIONS, admin.cli)).headers.get("cache-control")).toBe("no-store");
  });
});
