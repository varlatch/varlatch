// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * Environment responses carry tailnetRequired (capability
 * environments.tailnet-required), derived from the active Requirements with
 * authorization's own targeting; the covering Requirement IDs only for
 * callers holding policy.read.
 */
describe("environment tailnetRequired", () => {
  let ctx: AppCtx & { close: () => Promise<void> };
  let app: ReturnType<typeof buildApp>;
  let adminToken: string;
  let readerToken: string;

  const auth = (token: string) => ({ Authorization: `Bearer ${token}`, "Content-Type": "application/json" });
  const post = (path: string, body: unknown, token = adminToken) =>
    app.request(path, { method: "POST", headers: auth(token), body: JSON.stringify(body) });
  const get = (path: string, token = adminToken) => app.request(path, { headers: auth(token) });
  type Env = { id: string; name: string; tailnetRequired?: boolean; tailnetRequirementIds?: string[] };
  const listed = async (token = adminToken): Promise<Record<string, Env>> => {
    const res = await get("/v1/organizations/acme/projects/api/environments", token);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { items: Env[] };
    return Object.fromEntries(body.items.map((e) => [e.name, e]));
  };
  const requirement = async (target: unknown) => {
    const res = await post("/v1/organizations/acme/requirements", {
      kind: "tailnet",
      target,
      selector: { tailnet: "example.ts.net", nodes: ["nApproved1"] },
    });
    expect(res.status).toBe(201);
    return ((await res.json()) as { id: string }).id;
  };

  beforeEach(async () => {
    const db = await migratedTestDb();
    ctx = { db, rootKek: generateKey(), close: db.close };
    await ensureInstallation(ctx);
    const grant = await issueBootstrapGrant(ctx);
    const { identityId } = await consumeSetupGrant(ctx, grant.token, {});
    adminToken = (await issueCredential(ctx.db, { identityId, kind: "cli" })).token;
    app = buildApp(ctx);
    await post("/v1/organizations", { name: "Acme", slug: "acme" });
    await post("/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "managed" });
    await post("/v1/organizations/acme/projects/api/environments", { name: "production", tier: "production" });
    await post("/v1/organizations/acme/projects/api/environments", { name: "staging", tier: "staging" });
    await post("/v1/organizations/acme/projects/api/environments", { name: "development", tier: "development" });
    const envs = await listed();
    await post("/v1/organizations/acme/projects/api/environments", {
      name: "staging/pr-1",
      kind: "preview",
      parentEnvironmentId: envs.staging!.id,
    });
    // A machine that can see the project but not its policy.
    const reader = (await (await post("/v1/organizations/acme/identities", { name: "reader", kind: "service" })).json()) as {
      id: string;
      credential: string;
    };
    readerToken = reader.credential;
    await post("/v1/organizations/acme/grants", {
      subjectIdentityId: reader.id,
      scope: { kind: "organization" },
      actions: ["organization.read", "project.read", "environment.read"],
    });
  });
  afterEach(async () => {
    await ctx.close();
  });

  it("is advertised and false while no Requirement exists", async () => {
    const meta = (await (await app.request("/v1/meta")).json()) as { capabilities: string[] };
    expect(meta.capabilities).toContain("environments.tailnet-required");
    for (const env of Object.values(await listed())) {
      expect(env.tailnetRequired).toBe(false);
      expect(env.tailnetRequirementIds).toBeUndefined();
    }
  });

  it("follows tier, environment, and root targeting, as authorization does", async () => {
    const envs = await listed();
    const tierReq = await requirement({ kind: "tier", tier: "production" });
    // Targeting the root staging Environment also covers what derives from it.
    const rootReq = await requirement({ kind: "environments", environmentIds: [envs.staging!.id] });

    const after = await listed();
    expect(after.production).toMatchObject({ tailnetRequired: true, tailnetRequirementIds: [tierReq] });
    expect(after.staging).toMatchObject({ tailnetRequired: true, tailnetRequirementIds: [rootReq] });
    expect(after["staging/pr-1"]).toMatchObject({ tailnetRequired: true, tailnetRequirementIds: [rootReq] });
    expect(after.development).toMatchObject({ tailnetRequired: false });
    expect(after.development!.tailnetRequirementIds).toBeUndefined();

    // The flag agrees with enforcement on the ordinary listener.
    for (const [name, env] of Object.entries(after)) {
      const read = await get(`/v1/organizations/acme/projects/api/environments/${encodeURIComponent(name)}/effective-configuration?include=values`);
      expect(read.status, name).toBe(env.tailnetRequired ? 403 : 200);
    }

    // Single-environment reads carry it too.
    const one = (await (await get(`/v1/organizations/acme/projects/api/environments/${encodeURIComponent("staging/pr-1")}`)).json()) as Env;
    expect(one).toMatchObject({ tailnetRequired: true, tailnetRequirementIds: [rootReq] });
  });

  it("shows the flag to anyone who sees the environment, the Requirement IDs only with policy.read", async () => {
    await requirement({ kind: "tier", tier: "production" });
    const asReader = await listed(readerToken);
    expect(asReader.production!.tailnetRequired).toBe(true);
    expect(asReader.production!.tailnetRequirementIds).toBeUndefined();
    const one = (await (await get("/v1/organizations/acme/projects/api/environments/production", readerToken)).json()) as Env;
    expect(one.tailnetRequired).toBe(true);
    expect(one.tailnetRequirementIds).toBeUndefined();
  });

  it("covers a newly created environment in a constrained tier", async () => {
    const tierReq = await requirement({ kind: "tier", tier: "production" });
    const created = await post("/v1/organizations/acme/projects/api/environments", { name: "production-eu", tier: "production" });
    expect(created.status).toBe(201);
    expect(await created.json()).toMatchObject({ tailnetRequired: true, tailnetRequirementIds: [tierReq] });
  });

  it("clears when the Requirement is removed", async () => {
    const id = await requirement({ kind: "tier", tier: "production" });
    await app.request(`/v1/organizations/acme/requirements/${id}`, { method: "DELETE", headers: auth(adminToken) });
    expect((await listed()).production!.tailnetRequired).toBe(false);
  });
});
