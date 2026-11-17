// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { newId } from "../src/db/ids.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * A route inside a Project or an environment answers a principal that
 * cannot see the Organization (no role, no Grant, not one of its
 * machines) as an unknown Organization, before it looks the Project or
 * the environment up: the same answer whether they exist or not. A member
 * whose only authority is a Grant scoped to a Project (no action on the
 * Organization) still gets through.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
const tokens: Record<string, string> = {};
const ids: Record<string, string> = {};

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId: admin } = await consumeSetupGrant(ctx, grant.token, { adminName: "Admin" });
  tokens.admin = (await issueCredential(ctx.db, { identityId: admin, kind: "cli" })).token;
  app = buildApp(ctx);
  for (const slug of ["acme", "beta"]) expect((await call("POST", "/v1/organizations", "admin", { name: slug, slug })).status).toBe(201);
  const project = await (await call("POST", "/v1/organizations/acme/projects", "admin", { slug: "web", name: "Web", contractAuthority: "managed" })).json();
  ids.project = project.id;
  expect((await call("POST", "/v1/organizations/acme/projects/web/environments", "admin", { name: "dev", tier: "development" })).status).toBe(201);
  // carol: a person in no Organization. erin: a member of acme whose only
  // authority is a Grant scoped to the Project. beta's runner: a machine of
  // another Organization.
  for (const name of ["carol", "erin"]) {
    const id = newId("identity");
    await db.query("INSERT INTO identities (id, kind, name, created_at) VALUES ($1, 'human', $2, '2026-01-01T00:00:00.000Z')", [id, name]);
    tokens[name] = (await issueCredential(ctx.db, { identityId: id, kind: "cli" })).token;
    ids[name] = id;
  }
  await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) SELECT id, $1, 'member' FROM organizations WHERE slug = 'acme'", [ids.erin]);
  const granted = await call("POST", "/v1/organizations/acme/grants", "admin", {
    subjectIdentityId: ids.erin, scope: { kind: "project", projectId: ids.project }, actions: ["project.read"],
  });
  expect(granted.status).toBe(201);
  const runner = await (await call("POST", "/v1/organizations/beta/identities", "admin", { name: "runner", kind: "service" })).json();
  tokens.runner = runner.credential;
});
afterEach(async () => {
  await ctx.close();
});

async function call(method: string, path: string, who: string, body?: unknown) {
  return app.request(path, {
    method,
    headers: { Authorization: `Bearer ${tokens[who]}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

/** The answer without its request id: what tells two answers apart. */
async function answer(res: Response) {
  const body = (await res.json()) as { error?: { requestId?: string } };
  if (body.error) delete body.error.requestId;
  return { status: res.status, body };
}

async function denials(who: string) {
  const res = await ctx.db.query(
    "SELECT action, resource FROM audit_events WHERE event_type = 'authorization.denied' AND actor_identity_id = $1 ORDER BY event_order",
    [who],
  );
  return res.rows.map((r) => ({ action: r.action, resource: typeof r.resource === "string" ? JSON.parse(r.resource) : r.resource }));
}

// Each route as [method, path with the Project and environment, body]; the
// path is asked with them as they exist and as they do not.
const ROUTES: [string, (p: string, e: string) => string, unknown?][] = [
  ["GET", (p) => `/v1/organizations/acme/projects/${p}`],
  ["PATCH", (p) => `/v1/organizations/acme/projects/${p}`, { name: "x" }],
  ["GET", (p) => `/v1/organizations/acme/projects/${p}/environments`],
  ["POST", (p) => `/v1/organizations/acme/projects/${p}/environments`, { name: "", tier: "development" }],
  ["GET", (p, e) => `/v1/organizations/acme/projects/${p}/environments/${e}`],
  ["GET", (p) => `/v1/organizations/acme/projects/${p}/contract`],
  ["GET", (p, e) => `/v1/organizations/acme/projects/${p}/environments/${e}/effective-configuration`],
  ["GET", (p, e) => `/v1/organizations/acme/projects/${p}/environments/${e}/capabilities`],
  ["POST", (p, e) => `/v1/organizations/acme/projects/${p}/environments/${e}/capabilities`, {}],
];

describe("a scoped route for a principal that cannot see the Organization", () => {
  for (const who of ["carol", "runner"]) {
    it(`answers ${who} the same for an existing and a missing Project or environment`, async () => {
      for (const [method, path, body] of ROUTES) {
        const existing = await answer(await call(method, path("web", "dev"), who, body));
        expect(existing, `${method} ${path("web", "dev")}`).toEqual({
          status: 404, body: { error: { code: "RESOURCE_NOT_FOUND", message: "Organization not found" } },
        });
        for (const [p, e] of [["nope", "dev"], ["web", "nope"]] as const) {
          expect(await answer(await call(method, path(p, e), who, body)), `${method} ${path(p, e)}`).toEqual(existing);
        }
      }
    });
  }

  it("audits a person's refusal the same way for both, with no action decided", async () => {
    await call("GET", "/v1/organizations/acme/projects/web", "carol");
    await call("GET", "/v1/organizations/acme/projects/nope", "carol");
    const events = await denials(ids.carol!);
    expect(events).toEqual([
      { action: null, resource: { projectId: null, environmentId: null } },
      { action: null, resource: { projectId: null, environmentId: null } },
    ]);
  });

  it("lets a member whose only authority is a Project-scoped Grant through", async () => {
    const project = await call("GET", "/v1/organizations/acme/projects/web", "erin");
    expect(project.status).toBe(200);
    expect(await project.json()).toMatchObject({ slug: "web" });
    // Visible, so a missing Project is that Project's own answer.
    expect(await answer(await call("GET", "/v1/organizations/acme/projects/nope", "erin"))).toEqual({
      status: 404, body: { error: { code: "RESOURCE_NOT_FOUND", message: "Project not found" } },
    });
  });
});
