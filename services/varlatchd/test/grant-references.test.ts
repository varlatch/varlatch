// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { evaluate } from "../src/authz/evaluate.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { ForeignGrantReference, requireOwnGrantReferences } from "../src/domain/policy.js";
import { buildApp } from "../src/http/app.js";
import { loadGrants } from "../src/http/support.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * A Grant names only its Organization's groups and roles. Creating or
 * replacing one that names another Organization's is refused as naming one
 * that does not exist is (the insert's foreign key: 500, the same body),
 * so the answer does not tell the two apart; and the Grants the evaluator
 * reads join only the Organization's own groups and roles, so a row naming
 * another's grants nothing.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminId: string;
let adminToken: string;
let acmeId: string;
let otherId: string;
let bobId: string;
let theirGroup: string;
let theirRole: string;
let ownGroup: string;

type Answer = { status: number; contentType: string | null; body: string };

async function call(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<Answer> {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${adminToken}`, "Content-Type": "application/json", ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, contentType: res.headers.get("Content-Type"), body: await res.text() };
}

async function created(path: string, body: unknown): Promise<string> {
  const res = await call("POST", path, body);
  expect(res.status, res.body).toBe(201);
  return (JSON.parse(res.body) as { id: string }).id;
}

const exec = (sql: string, params: unknown[] = []) => ctx.db.query(sql, params);
const crossOrganization = async () =>
  ((await exec(
    `SELECT (SELECT count(*)::int FROM grants g JOIN groups x ON x.id = g.subject_group_id WHERE x.organization_id <> g.organization_id) +
            (SELECT count(*)::int FROM grants g JOIN roles x ON x.id = g.role_id WHERE x.organization_id <> g.organization_id) AS n`,
  )).rows[0] as { n: number }).n;
const liveGrants = async () =>
  ((await exec("SELECT count(*)::int AS n FROM grants WHERE organization_id = $1 AND revoked_at IS NULL", [acmeId])).rows[0] as { n: number }).n;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  adminId = (await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Alice" })).identityId;
  adminToken = (await issueCredential(ctx.db, { identityId: adminId, kind: "cli" })).token;
  app = buildApp(ctx);
  acmeId = await created("/v1/organizations", { name: "Acme", slug: "acme" });
  otherId = await created("/v1/organizations", { name: "Other", slug: "other" });
  // Bob, a member of both.
  bobId = (await consumeSetupGrant(ctx, (await issueInviteGrant(ctx, { organizationId: acmeId, role: "member", name: "Bob" }, adminId)).token, {})).identityId;
  await exec("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, $2, 'member')", [otherId, bobId]);
  theirGroup = await created("/v1/organizations/other/groups", { name: "devs" });
  theirRole = await created("/v1/organizations/other/roles", { name: "reader", actions: ["project.read"] });
  ownGroup = await created("/v1/organizations/acme/groups", { name: "devs" });
});
afterEach(async () => {
  await ctx.close();
});

describe("requireOwnGrantReferences", () => {
  it("refuses another Organization's group or role, and leaves an unknown or own one to the insert", async () => {
    await expect(requireOwnGrantReferences(ctx.db, acmeId, { subjectGroupId: theirGroup })).rejects.toBeInstanceOf(ForeignGrantReference);
    await expect(requireOwnGrantReferences(ctx.db, acmeId, { roleId: theirRole })).rejects.toBeInstanceOf(ForeignGrantReference);
    await expect(requireOwnGrantReferences(ctx.db, acmeId, { subjectGroupId: ownGroup, roleId: theirRole })).rejects.toBeInstanceOf(ForeignGrantReference);
    await expect(requireOwnGrantReferences(ctx.db, acmeId, { subjectGroupId: ownGroup })).resolves.toBeUndefined();
    await expect(requireOwnGrantReferences(ctx.db, acmeId, { subjectGroupId: "grp_unknown", roleId: "rol_unknown" })).resolves.toBeUndefined();
    await expect(requireOwnGrantReferences(ctx.db, acmeId, {})).resolves.toBeUndefined();
    // A revoked group or role of this Organization is still its own.
    await exec("UPDATE groups SET revoked_at = now() WHERE id = $1", [ownGroup]);
    await expect(requireOwnGrantReferences(ctx.db, acmeId, { subjectGroupId: ownGroup })).resolves.toBeUndefined();
    // Another Organization's group is foreign whatever its state.
    await exec("UPDATE groups SET revoked_at = now() WHERE id = $1", [theirGroup]);
    await expect(requireOwnGrantReferences(ctx.db, acmeId, { subjectGroupId: theirGroup })).rejects.toBeInstanceOf(ForeignGrantReference);
  });
});

describe("loadGrants and the evaluator", () => {
  const reads = async () =>
    evaluate({
      action: "project.read",
      resource: { organizationId: acmeId, projectId: "prj_any" },
      orgRole: null,
      grants: await loadGrants(ctx, acmeId, bobId),
      requirements: [],
      tailnetContext: null,
    }).allowed;

  it("join only the Organization's own groups and roles", async () => {
    await exec("INSERT INTO group_members (group_id, identity_id) VALUES ($1, $3), ($2, $3)", [theirGroup, ownGroup, bobId]);
    await exec(
      `INSERT INTO grants (id, organization_id, subject_group_id, scope, actions) VALUES ('grt_theirgroup', $1, $2, '{"kind":"organization"}', $3)`,
      [acmeId, theirGroup, ["project.read"]],
    );
    await exec(
      `INSERT INTO grants (id, organization_id, subject_identity_id, scope, role_id) VALUES ('grt_theirrole', $1, $2, '{"kind":"organization"}', $3)`,
      [acmeId, bobId, theirRole],
    );
    expect(await loadGrants(ctx, acmeId, bobId)).toEqual([]);
    expect(await reads()).toBe(false);

    await exec(
      `INSERT INTO grants (id, organization_id, subject_group_id, scope, actions) VALUES ('grt_owngroup', $1, $2, '{"kind":"organization"}', $3)`,
      [acmeId, ownGroup, ["project.read"]],
    );
    expect((await loadGrants(ctx, acmeId, bobId)).map((g) => g.id)).toEqual(["grt_owngroup"]);
    expect(await reads()).toBe(true);
  });
});

describe("the Grant routes", () => {
  const scope = { kind: "organization" };
  const requestId = (body: string) => body.replace(/"requestId":"[^"]*"/, '"requestId":"-"');

  it("answer a Grant naming another Organization's group or role exactly as one naming an unknown id, on create and on replace", async () => {
    const keep = await created("/v1/organizations/acme/grants", { subjectIdentityId: bobId, scope, actions: ["project.read"] });
    const cases = [
      { name: "create, a group", path: "grants", foreign: { subjectGroupId: theirGroup, scope, actions: ["project.read"] }, unknown: { subjectGroupId: "grp_unknownaaaaaaaaaaaaaaaaaaa", scope, actions: ["project.read"] } },
      { name: "create, a role", path: "grants", foreign: { subjectIdentityId: bobId, scope, roleId: theirRole }, unknown: { subjectIdentityId: bobId, scope, roleId: "rol_unknownaaaaaaaaaaaaaaaaaaa" } },
      { name: "replace, a group", path: `grants/${keep}/replace`, foreign: { subjectGroupId: theirGroup, scope, actions: ["project.read"] }, unknown: { subjectGroupId: "grp_unknownaaaaaaaaaaaaaaaaaaa", scope, actions: ["project.read"] } },
      { name: "replace, a role", path: `grants/${keep}/replace`, foreign: { subjectIdentityId: bobId, scope, roleId: theirRole }, unknown: { subjectIdentityId: bobId, scope, roleId: "rol_unknownaaaaaaaaaaaaaaaaaaa" } },
    ];
    for (const [i, c] of cases.entries()) {
      // A replacement is sent without and with an Idempotency-Key.
      for (const key of c.path.endsWith("replace") ? [null, `k${i}`] : [null]) {
        const headers = (kind: string): Record<string, string> => (key ? { "Idempotency-Key": `${key}-${kind}` } : {});
        const foreign = await call("POST", `/v1/organizations/acme/${c.path}`, c.foreign, headers("foreign"));
        const unknown = await call("POST", `/v1/organizations/acme/${c.path}`, c.unknown, headers("unknown"));
        expect({ ...foreign, body: requestId(foreign.body) }, c.name).toEqual({ ...unknown, body: requestId(unknown.body) });
        expect(foreign.status, c.name).toBe(500);
        expect(requestId(foreign.body), c.name).toBe('{"error":{"code":"INTERNAL","message":"Internal error","requestId":"-"}}');
      }
    }
    expect(await crossOrganization()).toBe(0);
    // The Grant replaced in vain is still the one live Grant, and nothing was audited.
    expect(await liveGrants()).toBe(1);
    expect(
      ((await exec("SELECT count(*)::int AS n FROM audit_events WHERE organization_id = $1 AND event_type IN ('grant.created', 'grant.revoked')", [acmeId])).rows[0] as { n: number }).n,
    ).toBe(1);
  });

  it("still take the Organization's own group and role", async () => {
    const ownRole = await created("/v1/organizations/acme/roles", { name: "reader", actions: ["project.read"] });
    const grant = await created("/v1/organizations/acme/grants", { subjectGroupId: ownGroup, scope, roleId: ownRole });
    const replaced = await call("POST", `/v1/organizations/acme/grants/${grant}/replace`, { subjectIdentityId: bobId, scope, roleId: ownRole });
    expect(replaced.status, replaced.body).toBe(201);
    expect(await liveGrants()).toBe(1);
  });
});
