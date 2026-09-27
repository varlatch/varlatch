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
 * Roles, Groups, Teams (ADR-0028): reuse over the flat Grant model. Each
 * compiles to the Grants the evaluator already decides — default-deny holds.
 * We assert real authorization outcomes for a service identity, not just CRUD.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let svcId: string;
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
  await post("/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "git" });
  await post("/v1/organizations/acme/projects/api/environments", { name: "development", tier: "development" });
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
async function del(path: string, token = adminToken) {
  return app.request(path, { method: "DELETE", headers: auth(token) });
}
async function get(path: string, token = adminToken) {
  return app.request(path, { headers: auth(token) });
}
const canReadProjects = async () =>
  (await get("/v1/organizations/acme/projects", svcToken)).status === 200;
async function projectId() {
  return (await (await get("/v1/organizations/acme/projects/api")).json()).id as string;
}

describe("custom roles", () => {
  it("a grant citing a role authorizes the role's actions; a revoked role authorizes nothing", async () => {
    expect(await canReadProjects()).toBe(false); // default-deny

    const role = await (
      await post("/v1/organizations/acme/roles", {
        name: "reader",
        actions: ["organization.read", "project.read"],
      })
    ).json();
    const grant = await (
      await post("/v1/organizations/acme/grants", {
        subjectIdentityId: svcId,
        scope: { kind: "organization" },
        roleId: role.id,
      })
    ).json();
    expect(await canReadProjects()).toBe(true);

    // Deleting the role collapses the grant to zero actions (default-deny).
    expect((await del(`/v1/organizations/acme/roles/${role.id}`)).status).toBe(204);
    expect(await canReadProjects()).toBe(false);
    expect(grant.roleId).toBe(role.id);
  });

  it("rejects a grant with neither actions nor a role, or both", async () => {
    const role = await (
      await post("/v1/organizations/acme/roles", { name: "r", actions: ["project.read"] })
    ).json();
    const neither = await post("/v1/organizations/acme/grants", {
      subjectIdentityId: svcId,
      scope: { kind: "organization" },
    });
    expect(neither.status).toBe(422);
    const both = await post("/v1/organizations/acme/grants", {
      subjectIdentityId: svcId,
      scope: { kind: "organization" },
      actions: ["project.read"],
      roleId: role.id,
    });
    expect(both.status).toBe(422);
  });
});

describe("groups", () => {
  it("a member inherits grants targeting the group; removing membership revokes access", async () => {
    const group = await (await post("/v1/organizations/acme/groups", { name: "deployers" })).json();
    await post("/v1/organizations/acme/grants", {
      subjectGroupId: group.id,
      scope: { kind: "organization" },
      actions: ["organization.read", "project.read"],
    });
    // Not a member yet.
    expect(await canReadProjects()).toBe(false);

    expect((await post(`/v1/organizations/acme/groups/${group.id}/members`, { identityId: svcId })).status).toBe(204);
    expect(await canReadProjects()).toBe(true);

    expect((await del(`/v1/organizations/acme/groups/${group.id}/members/${svcId}`)).status).toBe(204);
    expect(await canReadProjects()).toBe(false);
  });

  it("expands a role through group membership (both reuse constructs at once)", async () => {
    const role = await (
      await post("/v1/organizations/acme/roles", {
        name: "org-reader",
        actions: ["organization.read", "project.read"],
      })
    ).json();
    const group = await (await post("/v1/organizations/acme/groups", { name: "viewers" })).json();
    await post(`/v1/organizations/acme/groups/${group.id}/members`, { identityId: svcId });
    await post("/v1/organizations/acme/grants", {
      subjectGroupId: group.id,
      scope: { kind: "organization" },
      roleId: role.id,
    });
    expect(await canReadProjects()).toBe(true);
  });

  it("rejects a grant naming both an identity and a group subject", async () => {
    const group = await (await post("/v1/organizations/acme/groups", { name: "g" })).json();
    const res = await post("/v1/organizations/acme/grants", {
      subjectIdentityId: svcId,
      subjectGroupId: group.id,
      scope: { kind: "organization" },
      actions: ["project.read"],
    });
    expect(res.status).toBe(422);
  });
});

describe("teams", () => {
  it("a team-scoped grant reaches the team's owned projects only", async () => {
    // A second project the team will not own.
    await post("/v1/organizations/acme/projects", { name: "Web", slug: "web", contractAuthority: "git" });
    const apiId = await projectId();

    const team = await (await post("/v1/organizations/acme/teams", { name: "backend" })).json();
    await post(`/v1/organizations/acme/teams/${team.id}/members`, { identityId: svcId });
    await post(`/v1/organizations/acme/teams/${team.id}/projects`, { projectId: apiId });
    await post("/v1/organizations/acme/grants", {
      subjectGroupId: team.id,
      scope: { kind: "team", teamId: team.id },
      actions: ["project.read", "environment.read", "config.metadata.read"],
    });

    // Owned project: readable. Non-owned project: denied.
    const owned = await get("/v1/organizations/acme/projects/api/environments", svcToken);
    expect(owned.status).toBe(200);
    const other = await get("/v1/organizations/acme/projects/web/environments", svcToken);
    expect(other.status).not.toBe(200);
  });
});
