// SPDX-License-Identifier: AGPL-3.0-or-later
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
import { buildApp } from "../src/http/app.js";
import { testDb } from "./helpers/pglite.js";

/**
 * In-place access-entity updates and Grant replacement (ADR-0029). Roles,
 * Groups, Teams, Webhooks, and Requirements PATCH in place under optimistic
 * concurrency; edits take effect on the next authorization decision. Grants
 * keep immutable declarations: the only edit is atomic revoke-and-replace.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let svcId: string;
let svcToken: string;

beforeEach(async () => {
  const db = await testDb();
  await runMigrations(db);
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  adminToken = (await issueCredential(ctx.db, { identityId: consumed.identityId, kind: "cli" })).token;
  app = buildApp(ctx);

  await post("/v1/organizations", { name: "Acme", slug: "acme" });
  await post("/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "git" });
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
async function patch(path: string, body: unknown, extraHeaders: Record<string, string> = {}) {
  return app.request(path, {
    method: "PATCH",
    headers: { ...auth(), ...extraHeaders },
    body: JSON.stringify(body),
  });
}
async function get(path: string, token = adminToken) {
  return app.request(path, { headers: auth(token) });
}
const canReadProjects = async () =>
  (await get("/v1/organizations/acme/projects", svcToken)).status === 200;

describe("role updates", () => {
  it("re-points every grant citing the role with no revoke window", async () => {
    const role = await (
      await post("/v1/organizations/acme/roles", { name: "reader", actions: ["environment.read"] })
    ).json();
    expect(role.version).toBe(1);
    await post("/v1/organizations/acme/grants", {
      subjectIdentityId: svcId,
      scope: { kind: "organization" },
      roleId: role.id,
    });
    expect(await canReadProjects()).toBe(false);

    const res = await patch(`/v1/organizations/acme/roles/${role.id}`, {
      expectedVersion: 1,
      actions: ["organization.read", "project.read"],
    });
    expect(res.status).toBe(200);
    const updated = await res.json();
    expect(updated.version).toBe(2);
    expect(updated.updatedAt).not.toBeNull();
    // Same grant, new actions: the edit took effect on the next decision.
    expect(await canReadProjects()).toBe(true);
  });

  it("rejects a stale expectedVersion with VERSION_CONFLICT", async () => {
    const role = await (
      await post("/v1/organizations/acme/roles", { name: "r", actions: ["project.read"] })
    ).json();
    await patch(`/v1/organizations/acme/roles/${role.id}`, { expectedVersion: 1, name: "r2" });
    const stale = await patch(`/v1/organizations/acme/roles/${role.id}`, { expectedVersion: 1, name: "r3" });
    expect(stale.status).toBe(409);
    expect((await stale.json()).error.code).toBe("VERSION_CONFLICT");
  });

  it("a patch that changes nothing does not bump the version", async () => {
    const role = await (
      await post("/v1/organizations/acme/roles", { name: "same", actions: ["project.read"] })
    ).json();
    const res = await patch(`/v1/organizations/acme/roles/${role.id}`, {
      expectedVersion: 1,
      name: "same",
      actions: ["project.read"],
    });
    expect(res.status).toBe(200);
    expect((await res.json()).version).toBe(1);
  });

  it("rejects renaming onto an existing active role name", async () => {
    await post("/v1/organizations/acme/roles", { name: "taken", actions: ["project.read"] });
    const role = await (
      await post("/v1/organizations/acme/roles", { name: "other", actions: ["project.read"] })
    ).json();
    const res = await patch(`/v1/organizations/acme/roles/${role.id}`, { expectedVersion: 1, name: "taken" });
    expect(res.status).toBe(422);
  });

  it("a revoked role cannot be revived by PATCH", async () => {
    const role = await (
      await post("/v1/organizations/acme/roles", { name: "gone", actions: ["project.read"] })
    ).json();
    await app.request(`/v1/organizations/acme/roles/${role.id}`, { method: "DELETE", headers: auth() });
    const res = await patch(`/v1/organizations/acme/roles/${role.id}`, { expectedVersion: 1, name: "back" });
    expect(res.status).toBe(404);
  });
});

describe("group and team renames", () => {
  it("renames in place with a version bump; membership does not bump", async () => {
    const group = await (await post("/v1/organizations/acme/groups", { name: "deployers" })).json();
    expect(group.version).toBe(1);
    const res = await patch(`/v1/organizations/acme/groups/${group.id}`, { expectedVersion: 1, name: "shippers" });
    expect((await res.json()).version).toBe(2);

    await post(`/v1/organizations/acme/groups/${group.id}/members`, { identityId: svcId });
    const listed = await (await get("/v1/organizations/acme/groups")).json();
    const row = listed.items.find((g: { id: string }) => g.id === group.id);
    expect(row.name).toBe("shippers");
    expect(row.version).toBe(2); // join mutation did not bump
  });

  it("a team PATCH does not reach plain groups and vice versa", async () => {
    const group = await (await post("/v1/organizations/acme/groups", { name: "plain" })).json();
    const asTeam = await patch(`/v1/organizations/acme/teams/${group.id}`, { expectedVersion: 1, name: "x" });
    expect(asTeam.status).toBe(404);
  });
});

describe("requirement updates", () => {
  it("edits target/selector in place; kind is immutable; stale version conflicts", async () => {
    const req = await (
      await post("/v1/organizations/acme/requirements", {
        kind: "tailnet",
        target: { kind: "tier", tier: "production" },
        selector: { tailnet: "corp.ts.net", tags: ["tag:prod"] },
      })
    ).json();
    expect(req.version).toBe(1);

    const res = await patch(`/v1/organizations/acme/requirements/${req.id}`, {
      expectedVersion: 1,
      selector: { tailnet: "corp.ts.net", tags: ["tag:prod", "tag:ci"] },
    });
    expect(res.status).toBe(200);
    const updated = await res.json();
    expect(updated.version).toBe(2);
    expect(updated.selector.tags).toEqual(["tag:prod", "tag:ci"]);
    expect(updated.target).toEqual({ kind: "tier", tier: "production" });

    const stale = await patch(`/v1/organizations/acme/requirements/${req.id}`, {
      expectedVersion: 1,
      target: { kind: "tier", tier: "staging" },
    });
    expect(stale.status).toBe(409);
  });

  it("rejects a selector naming no tag, user, or node", async () => {
    const req = await (
      await post("/v1/organizations/acme/requirements", {
        kind: "tailnet",
        target: { kind: "tier", tier: "production" },
        selector: { tailnet: "corp.ts.net", tags: ["tag:prod"] },
      })
    ).json();
    const res = await patch(`/v1/organizations/acme/requirements/${req.id}`, {
      expectedVersion: 1,
      selector: { tailnet: "corp.ts.net" },
    });
    expect(res.status).toBe(422);
  });
});

describe("webhook updates", () => {
  it("updates URL and filter in place; rejects userinfo URLs", async () => {
    const hook = await (
      await post("/v1/organizations/acme/webhooks", { url: "https://sink.example/hooks" })
    ).json();
    expect(hook.version).toBe(1);

    const res = await patch(`/v1/organizations/acme/webhooks/${hook.id}`, {
      expectedVersion: 1,
      url: "https://sink.example/v2/hooks",
      eventTypes: ["grant.created"],
    });
    expect(res.status).toBe(200);
    const updated = await res.json();
    expect(updated.version).toBe(2);
    expect(updated.url).toBe("https://sink.example/v2/hooks");
    expect(updated.eventTypes).toEqual(["grant.created"]);
    expect(updated).not.toHaveProperty("secret");

    // null clears the filter back to all events.
    const cleared = await patch(`/v1/organizations/acme/webhooks/${hook.id}`, {
      expectedVersion: 2,
      eventTypes: null,
    });
    expect((await cleared.json()).eventTypes).toBeNull();

    const userinfo = await patch(`/v1/organizations/acme/webhooks/${hook.id}`, {
      expectedVersion: 3,
      url: "https://token@sink.example/hooks",
    });
    expect(userinfo.status).toBe(422);
  });
});

describe("grant replacement", () => {
  it("atomically revokes the original and creates the successor", async () => {
    const grant = await (
      await post("/v1/organizations/acme/grants", {
        subjectIdentityId: svcId,
        scope: { kind: "organization" },
        actions: ["environment.read"],
      })
    ).json();
    expect(await canReadProjects()).toBe(false);

    const res = await post(`/v1/organizations/acme/grants/${grant.id}/replace`, {
      subjectIdentityId: svcId,
      scope: { kind: "organization" },
      actions: ["organization.read", "project.read"],
    });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.replacedGrantId).toBe(grant.id);
    expect(body.grant.id).not.toBe(grant.id);
    expect(await canReadProjects()).toBe(true);

    // The original is gone; only the successor is active.
    const listed = await (await get("/v1/organizations/acme/grants")).json();
    const ids = listed.items.map((g: { id: string }) => g.id);
    expect(ids).not.toContain(grant.id);
    expect(ids).toContain(body.grant.id);
  });

  it("an already-replaced grant is VERSION_CONFLICT — no forked successors", async () => {
    const grant = await (
      await post("/v1/organizations/acme/grants", {
        subjectIdentityId: svcId,
        scope: { kind: "organization" },
        actions: ["project.read"],
      })
    ).json();
    const declaration = {
      subjectIdentityId: svcId,
      scope: { kind: "organization" },
      actions: ["organization.read"],
    };
    expect((await post(`/v1/organizations/acme/grants/${grant.id}/replace`, declaration)).status).toBe(201);
    const second = await post(`/v1/organizations/acme/grants/${grant.id}/replace`, declaration);
    expect(second.status).toBe(409);
    expect((await second.json()).error.code).toBe("VERSION_CONFLICT");
  });

  it("an Idempotency-Key retry returns the original replacement", async () => {
    const grant = await (
      await post("/v1/organizations/acme/grants", {
        subjectIdentityId: svcId,
        scope: { kind: "organization" },
        actions: ["project.read"],
      })
    ).json();
    const declaration = {
      subjectIdentityId: svcId,
      scope: { kind: "organization" },
      actions: ["organization.read"],
    };
    const headers = { ...auth(), "Idempotency-Key": "replace-once" };
    const first = await app.request(`/v1/organizations/acme/grants/${grant.id}/replace`, {
      method: "POST",
      headers,
      body: JSON.stringify(declaration),
    });
    const retry = await app.request(`/v1/organizations/acme/grants/${grant.id}/replace`, {
      method: "POST",
      headers,
      body: JSON.stringify(declaration),
    });
    expect(retry.status).toBe(201);
    expect((await retry.json()).grant.id).toBe((await first.json()).grant.id);
  });
});

it("adds an organization human to groups and teams", async () => {
  const me = await ctx.db.query("SELECT identity_id FROM org_memberships LIMIT 1");
  const identityId = (me.rows[0] as { identity_id: string }).identity_id;
  for (const kind of ["groups", "teams"]) {
    const collection = `/v1/organizations/acme/${kind}`;
    const group = await (await post(collection, { name: `human-${kind}` })).json();
    const result = await post(`${collection}/${group.id}/members`, { identityId });
    expect(result.status).toBe(204);
  }
});

it("keeps webhook credentials in paths and queries out of creation and update audits", async () => {
  const hook = await (await post("/v1/organizations/acme/webhooks", { url: "https://sink.example/path-secret?token=query-secret#fragment-secret" })).json();
  expect(hook.id).toBeTruthy();
  await patch(`/v1/organizations/acme/webhooks/${hook.id}`, { expectedVersion: 1, url: "https://sink.example/new-path-secret?token=new-query-secret" });
  const rows = await ctx.db.query("SELECT metadata FROM audit_events WHERE event_type LIKE 'webhook.%'");
  expect(JSON.stringify(rows.rows)).not.toMatch(/path-secret|query-secret|fragment-secret/);
});
