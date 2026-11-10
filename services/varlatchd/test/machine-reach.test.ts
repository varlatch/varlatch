// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { scheduleDeletion } from "../src/domain/orgdeletion.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * Machine reach (ADR-0054 Decision 8): a machine's Grants per Project and
 * Environment, with the Tailnet Requirements that would constrain each
 * action shown as conditions, never as denials. Read-only, on request.
 */

const ORG = "/v1/organizations/acme";
const P = `${ORG}/projects/api`;
const REACH = (id: string, org = ORG) => `${org}/identities/${id}/reach`;

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let admin: { id: string; token: string };
let orgId: string;
let projectId: string;
let prodId: string;
let previewId: string;
let devId: string;
let deployer: { id: string; token: string };
let groupId: string;
let direct: string;
let viaGroup: string;
let requirementId: string;

async function call(method: string, path: string, body?: unknown, token = admin.token) {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

async function machine(name: string, kind = "service", org = ORG) {
  const res = await call("POST", `${org}/identities`, { name, kind });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return { id: res.body.id as string, token: res.body.credential as string };
}

async function grant(body: Record<string, unknown>) {
  const res = await call("POST", `${ORG}/grants`, body);
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return res.body.id as string;
}

type Reach = {
  identity: { id: string; name: string; kind: string; state: string; disabledReason: string | null; liveCredentials: number };
  organizationActions: { action: string }[];
  projects: {
    id: string;
    slug: string;
    actions: { action: string }[];
    environments: {
      id: string;
      name: string;
      parentEnvironmentId: string | null;
      actions: { action: string; grants: { grantId: string; viaGroupId: string | null; roleId: string | null }[]; conditions: string[] }[];
    }[];
  }[];
  requirements: { id: string; condition: string; target: unknown }[];
  notes: string[];
};

async function reach(id: string, token = admin.token): Promise<Reach> {
  const res = await call("GET", REACH(id), undefined, token);
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  return res.body as Reach;
}

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const setup = await issueBootstrapGrant(ctx);
  const { identityId } = await consumeSetupGrant(ctx, setup.token, { adminName: "Admin" });
  admin = { id: identityId, token: (await issueCredential(ctx.db, { identityId, kind: "cli" })).token };
  app = buildApp(ctx);
  orgId = (await call("POST", "/v1/organizations", { name: "Acme", slug: "acme" })).body.id;
  projectId = (await call("POST", `${ORG}/projects`, { name: "API", slug: "api", contractAuthority: "managed" })).body.id;
  prodId = (await call("POST", `${P}/environments`, { name: "production", tier: "production" })).body.id;
  await call("POST", `${P}/environments`, { name: "staging", tier: "staging" });
  devId = (await call("POST", `${P}/environments`, { name: "development", tier: "development" })).body.id;
  previewId = (await call("POST", `${P}/environments`, { name: "production/pr-1", kind: "preview", parentEnvironmentId: prodId })).body.id;

  deployer = await machine("deployer");
  groupId = (await call("POST", `${ORG}/groups`, { name: "ops" })).body.id;
  expect((await call("POST", `${ORG}/groups/${groupId}/members`, { identityId: deployer.id })).status).toBe(204);
  // Direct: production by ID (so its derived preview too); through the
  // group: the development tier.
  direct = await grant({
    subjectIdentityId: deployer.id,
    scope: { kind: "environments", projectId, selector: { kind: "environments", environmentIds: [prodId] } },
    actions: ["config.metadata.read", "secret.use"],
  });
  viaGroup = await grant({
    subjectGroupId: groupId,
    scope: { kind: "environments", projectId, selector: { kind: "tier", tier: "development" } },
    actions: ["config.value.read", "config.value.write"],
  });
  const req = await call("POST", `${ORG}/requirements`, {
    kind: "tailnet",
    target: { kind: "environments", environmentIds: [prodId] },
    selector: { tailnet: "example.ts.net", tags: ["tag:prod"] },
  });
  expect(req.status, JSON.stringify(req.body)).toBe(201);
  requirementId = req.body.id;
});
afterEach(async () => {
  await ctx.close();
});

describe("machine reach", () => {
  it("is advertised in /v1/meta", async () => {
    expect((await call("GET", "/v1/meta")).body.capabilities).toContain("identity.reach");
  });

  it("lists direct and group Grants per environment, a Requirement as a condition, never a denial", async () => {
    const r = await reach(deployer.id);
    expect(r.identity).toEqual({ id: deployer.id, name: "deployer", kind: "service", state: "live", disabledReason: null, liveCredentials: 1 });
    expect(r.organizationActions).toEqual([]);
    expect(r.projects).toHaveLength(1);
    const project = r.projects[0]!;
    expect(project).toMatchObject({ id: projectId, slug: "api", actions: [] });
    const envs = Object.fromEntries(project.environments.map((e) => [e.name, e]));
    // Staging: nothing allowed, so not listed.
    expect(Object.keys(envs).sort()).toEqual(["development", "production", "production/pr-1"]);

    expect(envs.production!.actions).toEqual([
      { action: "config.metadata.read", grants: [{ grantId: direct, viaGroupId: null, roleId: null }], conditions: [] },
      { action: "secret.use", grants: [{ grantId: direct, viaGroupId: null, roleId: null }], conditions: [requirementId] },
    ]);
    // The derived environment is decided with its root: the root's Grant
    // and the root's Requirement both cover it.
    expect(envs["production/pr-1"]).toMatchObject({ id: previewId, parentEnvironmentId: prodId });
    expect(envs["production/pr-1"]!.actions).toEqual(envs.production!.actions);

    expect(envs.development).toMatchObject({ id: devId });
    expect(envs.development!.actions).toEqual([
      { action: "config.value.read", grants: [{ grantId: viaGroup, viaGroupId: groupId, roleId: null }], conditions: [] },
      { action: "config.value.write", grants: [{ grantId: viaGroup, viaGroupId: groupId, roleId: null }], conditions: [] },
    ]);

    expect(r.requirements).toEqual([
      {
        id: requirementId,
        version: expect.any(Number),
        target: { kind: "environments", environmentIds: [prodId] },
        selector: { tailnet: "example.ts.net", tags: ["tag:prod"] },
        condition: "needs tailnet example.ts.net: tag:prod",
      },
    ]);
    expect(r.notes).toEqual([]);
    expect(JSON.stringify(r)).not.toMatch(/denied|requirement-failed/);
  });

  it("lists Organization-wide and Project actions, and leaves out Requirements nothing it holds would meet", async () => {
    await grant({ subjectIdentityId: deployer.id, scope: { kind: "organization" }, actions: ["audit.read"] });
    await grant({ subjectIdentityId: deployer.id, scope: { kind: "project", projectId }, actions: ["contract.read"] });
    // A Requirement on the development tier constrains value reads there.
    const dev = await call("POST", `${ORG}/requirements`, {
      kind: "tailnet",
      target: { kind: "tier", tier: "development" },
      selector: { tailnet: "my tailnet", users: ["ci@example.com"], nodes: ["nAbc1"] },
    });
    // One on staging, where the machine reaches nothing, is not listed.
    await call("POST", `${ORG}/requirements`, {
      kind: "tailnet",
      target: { kind: "tier", tier: "staging" },
      selector: { tailnet: "example.ts.net", tags: ["tag:staging"] },
    });
    const r = await reach(deployer.id);
    expect(r.organizationActions.map((a) => a.action)).toEqual(["audit.read"]);
    expect(r.projects[0]!.actions.map((a) => a.action)).toEqual(["contract.read"]);
    const devEnv = r.projects[0]!.environments.find((e) => e.name === "development")!;
    expect(devEnv.actions.find((a) => a.action === "config.value.read")!.conditions).toEqual([dev.body.id]);
    expect(devEnv.actions.find((a) => a.action === "config.value.write")!.conditions).toEqual([]);
    expect(r.requirements.map((q) => q.id).sort()).toEqual([dev.body.id, requirementId].sort());
    expect(r.requirements.find((q) => q.id === dev.body.id)!.condition).toBe(
      'needs tailnet "my tailnet": user:ci@example.com or node:nAbc1',
    );
  });

  it("says when a machine is retired, keeping the Grants it would have", async () => {
    expect((await call("POST", `${ORG}/identities/${deployer.id}/retire`)).status).toBe(200);
    const r = await reach(deployer.id);
    expect(r.identity).toMatchObject({ state: "retired", disabledReason: null, liveCredentials: 0 });
    expect(r.projects[0]!.environments.length).toBe(3);
    expect(r.notes.join(" ")).toContain("retired");
  });

  it("says when a machine is suspended by the Organization's deletion", async () => {
    await scheduleDeletion(ctx, orgId, { id: admin.id, kind: "human" }, {});
    const r = await reach(deployer.id);
    expect(r.identity).toMatchObject({ state: "disabled", disabledReason: "organization-deletion" });
  });

  it("notes a Broker's Capabilities", async () => {
    const broker = await machine("broker-1", "broker");
    const r = await reach(broker.id);
    expect(r.projects).toEqual([]);
    expect(r.notes.join(" ")).toContain("Capabilities");
  });

  it("refuses a person, and hides another Organization's machine and unknown IDs", async () => {
    const human = await call("GET", REACH(admin.id));
    expect(human.status).toBe(422);
    expect(human.body.error).toMatchObject({ code: "VALIDATION_FAILED", details: { reason: "human-identity" } });
    await call("POST", "/v1/organizations", { name: "Other", slug: "other" });
    const foreign = await machine("theirs", "service", "/v1/organizations/other");
    expect((await call("GET", REACH(foreign.id))).status).toBe(404);
    expect((await call("GET", REACH(deployer.id, "/v1/organizations/other"))).status).toBe(404);
    expect((await call("GET", REACH("idn_nope"))).status).toBe(404);
  });

  it("needs identity.read and policy.read, checked before the identity is looked up", async () => {
    const bob = await issueInviteGrant(ctx, { organizationId: orgId, role: "member", name: "Bob" }, admin.id);
    const { identityId: bobId } = await consumeSetupGrant(ctx, bob.token, {});
    const bobToken = (await issueCredential(ctx.db, { identityId: bobId, kind: "cli" })).token;
    // A member holds neither in the built-in bundle.
    expect((await call("GET", REACH(deployer.id), undefined, bobToken)).status).toBe(403);
    expect((await call("GET", REACH("idn_nope"), undefined, bobToken)).status).toBe(403);
    // identity.read alone is not enough: reach reveals Grants and Requirements.
    const auditor = await machine("auditor");
    await grant({ subjectIdentityId: auditor.id, scope: { kind: "organization" }, actions: ["identity.read"] });
    expect((await call("GET", REACH(deployer.id), undefined, auditor.token)).status).toBe(403);
    await grant({ subjectIdentityId: auditor.id, scope: { kind: "organization" }, actions: ["policy.read"] });
    const allowed = await call("GET", REACH(deployer.id), undefined, auditor.token);
    expect(allowed.status).toBe(200);
    expect(allowed.body.identity.id).toBe(deployer.id);
    // The machine itself, without them, cannot read its own reach.
    expect((await call("GET", REACH(deployer.id), undefined, deployer.token)).status).toBe(403);
  });

  it("writes nothing", async () => {
    const before = (await ctx.db.query("SELECT count(*)::int AS n FROM audit_events")).rows[0] as { n: number };
    await reach(deployer.id);
    const after = (await ctx.db.query("SELECT count(*)::int AS n FROM audit_events")).rows[0] as { n: number };
    expect(after.n).toBe(before.n);
  });
});
