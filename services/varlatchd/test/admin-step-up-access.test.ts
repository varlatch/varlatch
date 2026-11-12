// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { withSerializableTx, withTx } from "../src/db/tx.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { grantReplaceBinding, roleCreateBinding } from "../src/domain/accessstepup.js";
import { labelWithId } from "../src/domain/approvallabels.js";
import type { Querier } from "../src/db/migrate.js";
import { withApproval, type Requester } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { DomainError } from "../src/domain/errors.js";
import { prepareProtectedOperation } from "../src/domain/protected.js";
import { ENFORCEABLE_CONTROLS, resetControls } from "../src/domain/securitycontrols.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * admin-step-up for the access structure (ADR-0054 step 4.6), on PGlite
 * under the lock-order check (test/helpers/lock-trace.ts): Grants (create,
 * replace, revoke), roles, groups and teams (create, change, delete),
 * their memberships and Team-Project links. The API still refuses
 * `enforce` for admin-step-up (it is unlocked in step 4.9), so these tests
 * set it directly in the database. With every control off nothing
 * changes; report mode counts and refuses nothing; under enforce each
 * operation needs the requester's approval bound to exactly that request,
 * as the binding catalogue says, and a machine credential is refused
 * without an intent. The races of a deletion with an edit and of a
 * membership added while it is removed run on real PostgreSQL in
 * admin-step-up-postgres.test.ts.
 */

const ORG = "/v1/organizations/acme";
const CONTROLS = `${ORG}/security/controls`;

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let orgId: string;
let admin: Person;

interface Person {
  id: string;
  cli: string;
  cliId: string;
  web: string;
  key: SoftAuthenticator;
}

type Answer = { status: number; body: any };

async function call(method: string, path: string, token: string, body?: unknown, headers: Record<string, string> = {}): Promise<Answer> {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

async function ok(method: string, path: string, token: string, body?: unknown, headers: Record<string, string> = {}): Promise<any> {
  const res = await call(method, path, token, body, headers);
  expect(res.status, `${method} ${path}: ${JSON.stringify(res.body)}`).toBeLessThan(300);
  return res.body;
}

const rows = async (sql: string, params: unknown[] = []) => (await ctx.db.query(sql, params)).rows as any[];
const count = async (sql: string, params: unknown[] = []) => ((await rows(sql, params))[0] as { n: number }).n;
const intents = () => count("SELECT count(*)::int AS n FROM approval_intents");
const counters = () => count("SELECT count(*)::int AS n FROM security_control_counters");
const claims = () => count("SELECT count(*)::int AS n FROM idempotency_keys");
const header = (approval?: string) => (approval ? { "Varlatch-Approval": approval } : {});
/** How a summary names an item: its name in JSON quotes, then its id, always. */
const named = (name: string, id: string) => `${JSON.stringify(name)} (${id})`;

async function person(identityId: string): Promise<Person> {
  const cli = await issueCredential(ctx.db, { identityId, kind: "cli", name: "test cli" });
  const key = await registerSoftPasskey(ctx.db, identityId, { ...RP, trust: "trusted" });
  const sessionId = `session-${identityId}`;
  await ctx.db.query(
    `INSERT INTO "session" (id, "expiresAt", token, "userId")
     SELECT $1, now() + interval '1 day', $1, better_auth_user_id FROM auth_user_links WHERE identity_id = $2`,
    [sessionId, identityId],
  );
  const web = await issueCredential(ctx.db, {
    identityId,
    kind: "browser",
    expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
    authSessionId: sessionId,
  });
  return { id: identityId, cli: cli.token, cliId: cli.credentialId, web: web.token, key };
}

async function invite(name: string, role: "admin" | "member"): Promise<Person> {
  const grant = await issueInviteGrant(ctx, { organizationId: orgId, role, name }, admin.id);
  const { identityId } = await consumeSetupGrant(ctx, grant.token, {});
  return person(identityId);
}

async function controlOf(control: string) {
  return (await ok("GET", CONTROLS, admin.cli)).items.find((i: { control: string }) => i.control === control);
}

const setMode = async (control: string, mode: string, config?: unknown) =>
  call("PATCH", `${CONTROLS}/${control}`, admin.cli, { mode, ...(config === undefined ? {} : { config }), expectedVersion: (await controlOf(control)).version });

/**
 * admin-step-up at enforce, written directly: the API refuses it until
 * ADR-0054 step 4.9 unlocks the control (CONTROL_MODE_UNAVAILABLE).
 */
async function enforceAdminStepUp() {
  await ctx.db.query(
    `INSERT INTO security_controls (organization_id, control, mode, config, version, changed_by, changed_at)
     VALUES ($1, 'admin-step-up', 'enforce', NULL, 1, $2, now())
     ON CONFLICT (organization_id, control) DO UPDATE SET mode = 'enforce', version = security_controls.version + 1`,
    [orgId, admin.id],
  );
}

/** The pending approval of a STEP_UP_REQUIRED answer. */
function stepUp(res: Answer) {
  expect(res.status, JSON.stringify(res.body)).toBe(403);
  expect(res.body.error.code).toBe("STEP_UP_REQUIRED");
  return res.body.error.details.approval as { id: string; operation: string; organization: any; summary: { title: string; changes: any[] }; state: string };
}

/** Approve in the dashboard, with the person's trusted passkey. */
async function approve(p: Person, approvalId: string) {
  const started = await call("POST", `/v1/me/approvals/${approvalId}/options`, p.web);
  expect(started.status, JSON.stringify(started.body)).toBe(200);
  const approved = await call("POST", `/v1/me/approvals/${approvalId}/approve`, p.web, {
    assertion: p.key.assert(started.body.publicKey.challenge, { userVerified: true }),
  });
  expect(approved.status, JSON.stringify(approved.body)).toBe(200);
}

/** Ask, approve, and return the approval id. */
async function approved(p: Person, res: Answer) {
  const asked = stepUp(res);
  await approve(p, asked.id);
  return asked.id;
}

const invalid = (res: Answer, reason: string) => {
  expect(res.status, JSON.stringify(res.body)).toBe(409);
  expect(res.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason } });
};

// The operations, as their routes take them.
type Body = Record<string, unknown>;
const createGrant = (token: string, body: Body, approval?: string) => call("POST", `${ORG}/grants`, token, body, header(approval));
const replaceGrant = (token: string, id: string, body: Body, approval?: string, extra: Record<string, string> = {}) =>
  call("POST", `${ORG}/grants/${id}/replace`, token, body, { ...header(approval), ...extra });
const revokeGrant = (token: string, id: string, approval?: string) => call("DELETE", `${ORG}/grants/${id}`, token, undefined, header(approval));
const createRole = (token: string, body: Body, approval?: string) => call("POST", `${ORG}/roles`, token, body, header(approval));
const updateRole = (token: string, id: string, body: Body, approval?: string, extra: Record<string, string> = {}) =>
  call("PATCH", `${ORG}/roles/${id}`, token, body, { ...header(approval), ...extra });
const deleteRole = (token: string, id: string, approval?: string) => call("DELETE", `${ORG}/roles/${id}`, token, undefined, header(approval));
/** `kind` is the route's: "groups" or "teams". */
const createGroup = (kind: string, token: string, name: string, approval?: string) => call("POST", `${ORG}/${kind}`, token, { name }, header(approval));
const updateGroup = (kind: string, token: string, id: string, body: Body, approval?: string, extra: Record<string, string> = {}) =>
  call("PATCH", `${ORG}/${kind}/${id}`, token, body, { ...header(approval), ...extra });
const deleteGroup = (kind: string, token: string, id: string, approval?: string) => call("DELETE", `${ORG}/${kind}/${id}`, token, undefined, header(approval));
const addMember = (kind: string, token: string, id: string, identityId: string, approval?: string) =>
  call("POST", `${ORG}/${kind}/${id}/members`, token, { identityId }, header(approval));
const removeMember = (kind: string, token: string, id: string, identityId: string, approval?: string) =>
  call("DELETE", `${ORG}/${kind}/${id}/members/${identityId}`, token, undefined, header(approval));
const addProject = (token: string, teamId: string, projectId: string, approval?: string) =>
  call("POST", `${ORG}/teams/${teamId}/projects`, token, { projectId }, header(approval));
const removeProject = (token: string, teamId: string, projectId: string, approval?: string) =>
  call("DELETE", `${ORG}/teams/${teamId}/projects/${projectId}`, token, undefined, header(approval));

async function events(eventType: string) {
  const parse = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v) as Record<string, any> | null;
  return (await rows("SELECT actor_identity_id, metadata FROM audit_events WHERE event_type = $1 ORDER BY event_order", [eventType]))
    .map((r) => ({ actor: r.actor_identity_id as string, metadata: parse(r.metadata) ?? {} }));
}

const liveGrants = () => count("SELECT count(*)::int AS n FROM grants WHERE revoked_at IS NULL");
const roleRow = async (id: string) => (await rows("SELECT name, actions, version, revoked_at IS NOT NULL AS deleted FROM roles WHERE id = $1", [id]))[0];
const groupRow = async (id: string) => (await rows("SELECT name, kind, version, revoked_at IS NOT NULL AS deleted FROM groups WHERE id = $1", [id]))[0];
const isMember = async (groupId: string, identityId: string) =>
  (await count("SELECT count(*)::int AS n FROM group_members WHERE group_id = $1 AND identity_id = $2", [groupId, identityId])) === 1;
const isLinked = async (teamId: string, projectId: string) =>
  (await count("SELECT count(*)::int AS n FROM team_projects WHERE team_id = $1 AND project_id = $2", [teamId, projectId])) === 1;

/**
 * Made while every control is off: a project with two environments, a
 * service identity, a member (Bob), a role, a group, a team with Bob and
 * the project, and a Grant of the role to the group on the project.
 */
async function fixtures() {
  const project = await ok("POST", `${ORG}/projects`, admin.cli, { name: "API", slug: "api", contractAuthority: "managed" });
  const qa1 = await ok("POST", `${ORG}/projects/api/environments`, admin.cli, { name: "qa1", tier: "staging" });
  const qa2 = await ok("POST", `${ORG}/projects/api/environments`, admin.cli, { name: "qa2", tier: "staging" });
  const svc = await ok("POST", `${ORG}/identities`, admin.cli, { name: "api-svc", kind: "service" });
  const bob = await invite("Bob", "member");
  const role = await ok("POST", `${ORG}/roles`, admin.cli, { name: "reader", actions: ["config.value.read", "project.read"] });
  const group = await ok("POST", `${ORG}/groups`, admin.cli, { name: "oncall" });
  const team = await ok("POST", `${ORG}/teams`, admin.cli, { name: "platform" });
  await ok("POST", `${ORG}/teams/${team.id}/members`, admin.cli, { identityId: bob.id });
  await ok("POST", `${ORG}/teams/${team.id}/projects`, admin.cli, { projectId: project.id });
  const grant = await ok("POST", `${ORG}/grants`, admin.cli, { subjectGroupId: group.id, scope: { kind: "project", projectId: project.id }, roleId: role.id });
  return {
    project: project.id as string,
    qa1: qa1.id as string,
    qa2: qa2.id as string,
    svc: svc.id as string,
    bob,
    role: role.id as string,
    group: group.id as string,
    team: team.id as string,
    grant: grant.id as string,
  };
}
type Fixtures = Awaited<ReturnType<typeof fixtures>>;

/** A machine identity of the Organization that holds policy.manage. */
async function robot() {
  const created = await ok("POST", `${ORG}/identities`, admin.cli, { name: "robot", kind: "service" });
  await ok("POST", `${ORG}/grants`, admin.cli, { subjectIdentityId: created.id, scope: { kind: "organization" }, actions: ["policy.manage"] });
  return { id: created.id as string, token: created.credential as string };
}

/** Each of the 18 operations once, by `token`, without an approval. Returns their answers in catalogue order. */
async function everyOperation(token: string, f: Fixtures, tag: string) {
  const out: Answer[] = [];
  const grant = await createGrant(token, { subjectIdentityId: f.svc, scope: { kind: "project", projectId: f.project }, actions: ["project.read"] });
  out.push(grant);
  const replaced = await replaceGrant(token, grant.body.id, { subjectIdentityId: f.svc, scope: { kind: "project", projectId: f.project }, actions: ["project.read", "config.value.read"] });
  out.push(replaced);
  out.push(await revokeGrant(token, replaced.body.grant.id));
  const role = await createRole(token, { name: `role-${tag}`, actions: ["project.read"] });
  out.push(role);
  out.push(await updateRole(token, role.body.id, { expectedVersion: 1, actions: ["project.read", "config.value.read"] }));
  out.push(await deleteRole(token, role.body.id));
  const group = await createGroup("groups", token, `group-${tag}`);
  out.push(group);
  out.push(await updateGroup("groups", token, group.body.id, { expectedVersion: 1, name: `group-${tag}-2` }));
  out.push(await addMember("groups", token, group.body.id, f.svc));
  out.push(await removeMember("groups", token, group.body.id, f.svc));
  out.push(await deleteGroup("groups", token, group.body.id));
  const team = await createGroup("teams", token, `team-${tag}`);
  out.push(team);
  out.push(await updateGroup("teams", token, team.body.id, { expectedVersion: 1, name: `team-${tag}-2` }));
  out.push(await addMember("teams", token, team.body.id, f.bob.id));
  out.push(await removeMember("teams", token, team.body.id, f.bob.id));
  out.push(await addProject(token, team.body.id, f.project));
  out.push(await removeProject(token, team.body.id, f.project));
  out.push(await deleteGroup("teams", token, team.body.id));
  return out;
}

const OPERATIONS = [
  "grant.create", "grant.replace", "grant.revoke",
  "role.create", "role.update", "role.delete",
  "group.create", "group.update", "group.member_add", "group.member_remove", "group.delete",
  "team.create", "team.update", "team.member_add", "team.member_remove", "team.project_add", "team.project_remove", "team.delete",
];

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const { identityId } = await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" });
  app = buildApp(ctx, { publicUrl: PUBLIC_URL, clientAddress: () => "203.0.113.7" });
  admin = await person(identityId);
  orgId = (await ok("POST", "/v1/organizations", admin.cli, { name: "Acme", slug: "acme" })).id;
});
afterEach(async () => {
  await ctx.close();
});

describe("admin-step-up's enforce stays unavailable", () => {
  it("is refused by the API with CONTROL_MODE_UNAVAILABLE", async () => {
    expect(ENFORCEABLE_CONTROLS.has("admin-step-up")).toBe(false);
    const res = await setMode("admin-step-up", "enforce");
    expect(res.status).toBe(422);
    expect(res.body.error).toMatchObject({ code: "CONTROL_MODE_UNAVAILABLE", details: { control: "admin-step-up", mode: "enforce" } });
    expect(await count("SELECT count(*)::int AS n FROM security_controls")).toBe(0);
  });
});

describe("with every control off", () => {
  it("runs all 18 operations as before: no approval, no count, no intent, audit as before", async () => {
    const f = await fixtures();
    for (const [i, res] of (await everyOperation(admin.cli, f, "off")).entries()) expect(res.status, OPERATIONS[i]).toBeLessThan(300);
    expect(await intents()).toBe(0);
    expect(await counters()).toBe(0);
    const [created] = await events("role.created");
    expect(created!.metadata).toEqual({ name: "reader", actions: "config.value.read,project.read" });
    for (const type of [
      "grant.created", "grant.revoked", "role.created", "role.updated", "role.deleted", "group.created", "group.updated", "group.deleted",
      "group.member_added", "group.member_removed", "team.created", "team.updated", "team.deleted", "team.member_added", "team.member_removed",
      "team.project_added", "team.project_removed",
    ]) {
      const list = await events(type);
      expect(list.length, type).toBeGreaterThan(0);
      for (const e of list) expect(e.metadata, type).not.toHaveProperty("approvalId");
    }
  });

  it("ignores a malformed Varlatch-Approval header, as before, Idempotency-Key included", async () => {
    const f = await fixtures();
    expect((await createRole(admin.cli, { name: "x", actions: ["project.read"] }, "invalid")).status).toBe(201);
    expect((await revokeGrant(admin.cli, f.grant, "invalid")).status).toBe(204);
    expect((await updateRole(admin.cli, f.role, { expectedVersion: 1, name: "reader-2" }, "invalid", { "Idempotency-Key": "k1" })).status).toBe(200);
    expect((await addMember("groups", admin.cli, f.group, f.svc, "invalid")).status).toBe(204);
    expect((await addProject(admin.cli, f.team, f.project, "invalid")).status).toBe(204);
    expect(await intents()).toBe(0);
  });
});

describe("in report mode", () => {
  it("refuses nothing and counts each operation, by a person and by a machine", async () => {
    const f = await fixtures();
    const bot = await robot();
    expect((await setMode("admin-step-up", "report")).status).toBe(200);
    for (const [i, res] of (await everyOperation(admin.cli, f, "person")).entries()) expect(res.status, OPERATIONS[i]).toBeLessThan(300);
    for (const [i, res] of (await everyOperation(bot.token, f, "bot")).entries()) expect(res.status, OPERATIONS[i]).toBeLessThan(300);
    expect(await intents()).toBe(0);
    const counted = await rows(
      "SELECT operation, reason, actor_identity_id, count::int AS count FROM security_control_counters WHERE control = 'admin-step-up' ORDER BY operation, reason",
    );
    const expected = OPERATIONS.flatMap((operation) => [
      { operation, reason: "machine-credential", actor_identity_id: bot.id, count: 1 },
      { operation, reason: "no-approval", actor_identity_id: admin.id, count: 1 },
    ]).sort((a, b) => (a.operation < b.operation ? -1 : a.operation > b.operation ? 1 : 0));
    expect(counted).toEqual(expected);
  });

  it("does not count a request that changes nothing: a current member, a linked project, the same Grant, a reordered role", async () => {
    const f = await fixtures();
    expect((await setMode("admin-step-up", "report")).status).toBe(200);
    expect((await addMember("teams", admin.cli, f.team, f.bob.id)).status).toBe(204);
    expect((await addProject(admin.cli, f.team, f.project)).status).toBe(204);
    // The same declaration again: replaced, but no access changes.
    expect((await replaceGrant(admin.cli, f.grant, { subjectGroupId: f.group, scope: { kind: "project", projectId: f.project }, roleId: f.role })).status).toBe(201);
    // The same set of actions in another order: written (a new version), but no access changes.
    const reordered = await updateRole(admin.cli, f.role, { expectedVersion: 1, actions: ["project.read", "config.value.read"] });
    expect(reordered.status).toBe(200);
    expect(reordered.body.version).toBe(2);
    expect(await counters()).toBe(0);
  });
});

describe("under enforce", () => {
  let f: Fixtures;
  let bot: Awaited<ReturnType<typeof robot>>;
  beforeEach(async () => {
    f = await fixtures();
    bot = await robot();
    await enforceAdminStepUp();
  });

  it("asks for an approval for each operation, with its summary, and changes nothing without one", async () => {
    // Each pending approval is dropped once read: a credential holds at most 5 open ones.
    const shown = async (res: Answer) => {
      const asked = stepUp(res);
      await ctx.db.query("DELETE FROM approval_intents WHERE id = $1", [asked.id]);
      return asked;
    };
    const grantsBefore = await liveGrants();
    const envs = [named("api/qa1", f.qa1), named("api/qa2", f.qa2)].sort().join(", ");
    const g = await shown(await createGrant(admin.cli, { subjectIdentityId: f.svc, scope: { kind: "environments", projectId: f.project, selector: { kind: "environments", environmentIds: [f.qa2, f.qa1] } }, actions: ["project.read", "config.value.read"] }));
    expect(g).toMatchObject({ operation: "grant.create", organization: { id: orgId, slug: "acme" }, state: "pending" });
    expect(g.summary).toEqual({
      title: `Grant config.value.read, project.read on environments ${envs} to ${named("api-svc", f.svc)}`,
      changes: [
        { field: "subject", from: null, to: named("api-svc", f.svc), loosens: false },
        { field: "scope", from: null, to: `environments ${envs}`, loosens: false },
        { field: "permission", from: null, to: "config.value.read, project.read", loosens: false },
      ],
    });
    const r = await shown(await replaceGrant(admin.web, f.grant, { subjectGroupId: f.team, scope: { kind: "team", teamId: f.team }, roleId: f.role }));
    expect(r).toMatchObject({ operation: "grant.replace" });
    expect(r.summary).toEqual({
      title: `Change the Grant of role ${named("reader", f.role)} on project ${named("api", f.project)} to group ${named("oncall", f.group)}`,
      changes: [
        { field: "subject", from: `group ${named("oncall", f.group)}`, to: `team ${named("platform", f.team)}`, loosens: false },
        { field: "scope", from: `project ${named("api", f.project)}`, to: `the projects of team ${named("platform", f.team)}`, loosens: false },
      ],
    });
    expect((await shown(await revokeGrant(admin.cli, f.grant))).summary).toEqual({ title: `Revoke the Grant of role ${named("reader", f.role)} on project ${named("api", f.project)} to group ${named("oncall", f.group)}`, changes: [] });

    expect((await shown(await createRole(admin.cli, { name: "writer", actions: ["project.read", "config.value.write"] }))).summary).toEqual({
      title: 'Create role "writer": config.value.write, project.read',
      changes: [
        { field: "name", from: null, to: '"writer"', loosens: false },
        { field: "actions", from: null, to: "config.value.write, project.read", loosens: false },
      ],
    });
    expect((await shown(await updateRole(admin.cli, f.role, { expectedVersion: 1, name: "readers", actions: ["project.read", "config.value.write"] }))).summary).toEqual({
      title: `Change role ${named("reader", f.role)}, which 1 Grant uses`,
      changes: [
        { field: "name", from: '"reader"', to: '"readers"', loosens: false },
        { field: "actionsAdded", from: null, to: "config.value.write", loosens: true },
        { field: "actionsRemoved", from: "config.value.read", to: null, loosens: false },
      ],
    });
    expect((await shown(await deleteRole(admin.cli, f.role))).summary).toEqual({ title: `Delete role ${named("reader", f.role)}`, changes: [] });

    expect((await shown(await createGroup("groups", admin.cli, "sre"))).summary.title).toBe('Create group "sre"');
    expect((await shown(await createGroup("teams", admin.cli, "web"))).summary.title).toBe('Create team "web"');
    expect((await shown(await updateGroup("teams", admin.cli, f.team, { expectedVersion: 1, name: "platform-2" }))).summary).toEqual({
      title: `Rename team ${named("platform", f.team)} to "platform-2"`,
      changes: [{ field: "name", from: '"platform"', to: '"platform-2"', loosens: false }],
    });
    const del = await shown(await deleteGroup("teams", admin.cli, f.team));
    expect(del).toMatchObject({ operation: "team.delete", summary: { title: `Delete team ${named("platform", f.team)}. Its 1 member loses what its Grants gave them` } });
    expect(await shown(await addMember("groups", admin.cli, f.group, f.bob.id))).toMatchObject({ operation: "group.member_add", summary: { title: `Add ${named("Bob", f.bob.id)} to group ${named("oncall", f.group)}` } });
    expect(await shown(await removeMember("teams", admin.cli, f.team, f.bob.id))).toMatchObject({ operation: "team.member_remove", summary: { title: `Remove ${named("Bob", f.bob.id)} from team ${named("platform", f.team)}` } });
    expect(await shown(await removeProject(admin.cli, f.team, f.project))).toMatchObject({ operation: "team.project_remove", summary: { title: `Take the project ${named("api", f.project)} from team ${named("platform", f.team)}` } });
    const team2 = await ok("POST", `${ORG}/teams`, admin.cli, { name: "web" }, header(await approved(admin, await createGroup("teams", admin.cli, "web"))));
    expect(await shown(await addProject(admin.cli, team2.id, f.project))).toMatchObject({ operation: "team.project_add", summary: { title: `Give team ${named("web", team2.id)} the project ${named("api", f.project)}` } });

    expect(await liveGrants()).toBe(grantsBefore);
    expect(await roleRow(f.role)).toMatchObject({ name: "reader", version: 1, deleted: false });
    expect(await groupRow(f.team)).toMatchObject({ name: "platform", version: 1, deleted: false });
    expect(await isMember(f.team, f.bob.id)).toBe(true);
    expect(await isMember(f.group, f.bob.id)).toBe(false);
    expect(await isLinked(f.team, f.project)).toBe(true);
    expect(await isLinked(team2.id, f.project)).toBe(false);
    expect(await count("SELECT count(*)::int AS n FROM roles WHERE name = 'writer'")).toBe(0);
    expect(await count("SELECT count(*)::int AS n FROM groups WHERE name = 'sre'")).toBe(0);
    // Nothing is counted under enforce.
    expect(await counters()).toBe(0);
  });

  it("runs each operation with its approval, once, and records the approval in the audit", async () => {
    const run = async (send: (approval?: string) => Promise<Answer>) => {
      const res = await send(await approved(admin, await send()));
      expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
      return res;
    };
    const grant = await run((a) => createGrant(admin.cli, { subjectIdentityId: f.svc, scope: { kind: "organization" }, actions: ["project.read"] }, a));
    const replaced = await run((a) => replaceGrant(admin.cli, grant.body.id, { subjectIdentityId: f.svc, scope: { kind: "organization" }, actions: ["project.read", "config.value.read"] }, a));
    await run((a) => revokeGrant(admin.cli, replaced.body.grant.id, a));
    const role = await run((a) => createRole(admin.cli, { name: "writer", actions: ["config.value.write"] }, a));
    await run((a) => updateRole(admin.cli, role.body.id, { expectedVersion: 1, name: "writers" }, a));
    await run((a) => deleteRole(admin.cli, role.body.id, a));
    const group = await run((a) => createGroup("groups", admin.cli, "sre", a));
    await run((a) => updateGroup("groups", admin.cli, group.body.id, { expectedVersion: 1, name: "sre-2" }, a));
    await run((a) => addMember("groups", admin.cli, group.body.id, f.bob.id, a));
    // The dashboard's own approval: asked and repeated by the browser bearer.
    await run((a) => removeMember("groups", admin.web, group.body.id, f.bob.id, a));
    await run((a) => deleteGroup("groups", admin.cli, group.body.id, a));
    const team = await run((a) => createGroup("teams", admin.cli, "web", a));
    await run((a) => updateGroup("teams", admin.cli, team.body.id, { expectedVersion: 1, name: "web-2" }, a));
    await run((a) => addMember("teams", admin.cli, team.body.id, f.svc, a));
    await run((a) => removeMember("teams", admin.cli, team.body.id, f.svc, a));
    await run((a) => addProject(admin.cli, team.body.id, f.project, a));
    await run((a) => removeProject(admin.cli, team.body.id, f.project, a));
    await run((a) => deleteGroup("teams", admin.cli, team.body.id, a));

    expect(await count("SELECT count(*)::int AS n FROM approval_intents WHERE consumed_at IS NOT NULL")).toBe(18);
    expect(await rows("SELECT DISTINCT operation FROM approval_intents ORDER BY operation")).toEqual([...OPERATIONS].sort().map((operation) => ({ operation })));
    for (const type of [
      "grant.revoked", "role.created", "role.updated", "role.deleted", "group.created", "group.updated", "group.deleted",
      "group.member_added", "group.member_removed", "team.created", "team.updated", "team.deleted", "team.member_added", "team.member_removed",
      "team.project_added", "team.project_removed",
    ]) {
      expect((await events(type)).at(-1)!.metadata, type).toMatchObject({ approvalId: expect.any(String), approvalUserVerified: true });
    }
    // The replacement's two events carry its one approval.
    const created = (await events("grant.created")).filter((e) => e.metadata.replaces);
    expect(created.at(-1)!.metadata.approvalId).toBe((await events("grant.revoked")).find((e) => e.metadata.replacedBy)!.metadata.approvalId);
    expect(await counters()).toBe(0);
  });

  it("grant.create binds the subject, the scope and the permission; sets bind in any order", async () => {
    const decl = { subjectIdentityId: f.svc, scope: { kind: "environments", projectId: f.project, selector: { kind: "environments", environmentIds: [f.qa1, f.qa2] } }, actions: ["project.read", "config.value.read"] };
    const asked = await approved(admin, await createGrant(admin.cli, decl));
    invalid(await createGrant(admin.cli, { ...decl, subjectIdentityId: f.bob.id }, asked), "mismatch");
    invalid(await createGrant(admin.cli, { ...decl, scope: { kind: "project", projectId: f.project } }, asked), "mismatch");
    invalid(await createGrant(admin.cli, { ...decl, scope: { ...decl.scope, selector: { kind: "environments", environmentIds: [f.qa1] } } }, asked), "mismatch");
    invalid(await createGrant(admin.cli, { ...decl, actions: ["project.read"] }, asked), "mismatch");
    invalid(await createGrant(admin.cli, { subjectIdentityId: f.svc, scope: decl.scope, roleId: f.role }, asked), "mismatch");
    // Another operation with the same approval.
    invalid(await revokeGrant(admin.cli, f.grant, asked), "mismatch");
    const before = await liveGrants();
    // The environments and the actions in another order, with duplicates: the same Grant.
    const same = { ...decl, scope: { ...decl.scope, selector: { kind: "environments", environmentIds: [f.qa2, f.qa1, f.qa2] } }, actions: ["config.value.read", "project.read", "project.read"] };
    expect((await createGrant(admin.cli, same, asked)).status).toBe(201);
    invalid(await createGrant(admin.cli, same, asked), "consumed");
    expect(await liveGrants()).toBe(before + 1);
    // A subject outside the Organization is refused before any approval is asked for.
    const intentsBefore = await intents();
    expect((await createGrant(admin.cli, { ...decl, subjectIdentityId: "idn_nope" })).status).toBe(404);
    expect(await intents()).toBe(intentsBefore);
  });

  it("grant.replace binds the old Grant and the complete replacement; an identical one needs none", async () => {
    const other = await ok("POST", `${ORG}/grants`, admin.cli, { subjectIdentityId: f.svc, scope: { kind: "organization" }, actions: ["project.read"] },
      header(await approved(admin, await createGrant(admin.cli, { subjectIdentityId: f.svc, scope: { kind: "organization" }, actions: ["project.read"] }))));
    const next = { subjectGroupId: f.group, scope: { kind: "project", projectId: f.project }, actions: ["project.read", "config.value.read"] };
    const asked = await approved(admin, await replaceGrant(admin.cli, f.grant, next));
    invalid(await replaceGrant(admin.cli, other.id, next, asked), "mismatch");
    invalid(await replaceGrant(admin.cli, f.grant, { ...next, actions: ["project.read"] }, asked), "mismatch");
    invalid(await replaceGrant(admin.cli, f.grant, { ...next, subjectGroupId: f.team }, asked), "mismatch");
    expect((await replaceGrant(admin.cli, f.grant, { ...next, actions: ["config.value.read", "project.read"] }, asked)).status).toBe(201);
    // Replaced: refused before any approval is asked for, by the stored state.
    const before = await intents();
    expect((await replaceGrant(admin.cli, f.grant, next)).body.error.code).toBe("VERSION_CONFLICT");
    expect(await intents()).toBe(before);
    // An identical replacement (the same set of actions, with a duplicate) changes no access: no approval.
    const decl = { subjectIdentityId: f.svc, scope: { kind: "organization" }, actions: ["project.read", "project.read"] };
    expect((await replaceGrant(admin.cli, other.id, decl)).status).toBe(201);
    expect(await intents()).toBe(before);
  });

  it("grant.revoke binds the Grant", async () => {
    const other = await ok("POST", `${ORG}/grants`, admin.cli, { subjectIdentityId: f.svc, scope: { kind: "organization" }, actions: ["project.read"] },
      header(await approved(admin, await createGrant(admin.cli, { subjectIdentityId: f.svc, scope: { kind: "organization" }, actions: ["project.read"] }))));
    const asked = await approved(admin, await revokeGrant(admin.cli, f.grant));
    invalid(await revokeGrant(admin.cli, other.id, asked), "mismatch");
    expect((await revokeGrant(admin.cli, f.grant, asked)).status).toBe(204);
    const before = await intents();
    expect((await revokeGrant(admin.cli, f.grant)).status).toBe(404);
    expect(await intents()).toBe(before);
  });

  it("role.create binds the name and the set of actions; a taken name is refused first", async () => {
    const asked = await approved(admin, await createRole(admin.cli, { name: "writer", actions: ["project.read", "config.value.write"] }));
    invalid(await createRole(admin.cli, { name: "writer2", actions: ["project.read", "config.value.write"] }, asked), "mismatch");
    invalid(await createRole(admin.cli, { name: "writer", actions: ["project.read"] }, asked), "mismatch");
    expect((await createRole(admin.cli, { name: "writer", actions: ["config.value.write", "project.read"] }, asked)).status).toBe(201);
    const before = await intents();
    expect((await createRole(admin.cli, { name: "reader", actions: ["project.read"] })).body.error.code).toBe("VALIDATION_FAILED");
    expect(await intents()).toBe(before);
  });

  it("role.update binds the resulting state and the expected version; absence binds the current value; a reordering needs none", async () => {
    const asked = await approved(admin, await updateRole(admin.cli, f.role, { expectedVersion: 1, name: "readers" }));
    // Leaving the actions out and sending the current ones (in any order) bind the same.
    invalid(await updateRole(admin.cli, f.role, { expectedVersion: 1, name: "readers", actions: ["project.read"] }, asked), "mismatch");
    invalid(await updateRole(admin.cli, f.role, { expectedVersion: 1, name: "readers-2" }, asked), "mismatch");
    expect((await updateRole(admin.cli, f.role, { expectedVersion: 1, name: "readers", actions: ["project.read", "config.value.read"] }, asked)).status).toBe(200);
    expect(await roleRow(f.role)).toMatchObject({ name: "readers", version: 2 });
    // The version: one approved at version 2 is stale for a request at version 3.
    const at2 = await approved(admin, await updateRole(admin.cli, f.role, { expectedVersion: 2, actions: ["project.read"] }));
    await ctx.db.query("UPDATE roles SET version = 3 WHERE id = $1", [f.role]);
    invalid(await updateRole(admin.cli, f.role, { expectedVersion: 3, actions: ["project.read"] }, at2), "stale");
    // A stale expected version is refused before any approval is asked for.
    const before = await intents();
    expect((await updateRole(admin.cli, f.role, { expectedVersion: 2, actions: ["project.read"] })).body.error.code).toBe("VERSION_CONFLICT");
    // The same set of actions in another order, or the same name: no approval.
    expect((await updateRole(admin.cli, f.role, { expectedVersion: 3, actions: ["config.value.read", "project.read"] })).status).toBe(200);
    expect((await updateRole(admin.cli, f.role, { expectedVersion: 4, name: "readers" })).status).toBe(200);
    expect(await intents()).toBe(before);
  });

  it("role.delete binds the role and the version the server read", async () => {
    const asked = await approved(admin, await deleteRole(admin.cli, f.role));
    // Changed since (version 2): the approval is stale.
    await ctx.db.query("UPDATE roles SET version = 2 WHERE id = $1", [f.role]);
    invalid(await deleteRole(admin.cli, f.role, asked), "stale");
    expect(await roleRow(f.role)).toMatchObject({ deleted: false });
    const again = await approved(admin, await deleteRole(admin.cli, f.role));
    expect((await deleteRole(admin.cli, f.role, again)).status).toBe(204);
    expect(await roleRow(f.role)).toMatchObject({ deleted: true });
  });

  it("role.update and role.delete bind the role: another role's request does not fit", async () => {
    const other = await ok("POST", `${ORG}/roles`, admin.cli, { name: "writer", actions: ["config.value.read", "project.read"] },
      header(await approved(admin, await createRole(admin.cli, { name: "writer", actions: ["config.value.read", "project.read"] }))));
    // The same resulting state and version, on another role.
    const update = await approved(admin, await updateRole(admin.cli, f.role, { expectedVersion: 1, actions: ["project.read"] }));
    invalid(await updateRole(admin.cli, other.id, { expectedVersion: 1, actions: ["project.read"] }, update), "mismatch");
    const removal = await approved(admin, await deleteRole(admin.cli, f.role));
    invalid(await deleteRole(admin.cli, other.id, removal), "mismatch");
    expect(await roleRow(other.id)).toMatchObject({ actions: ["config.value.read", "project.read"], version: 1, deleted: false });
    expect((await updateRole(admin.cli, f.role, { expectedVersion: 1, actions: ["project.read"] }, update)).status).toBe(200);
    // The edit moved the role to version 2: the deletion approved at version 1 is stale.
    invalid(await deleteRole(admin.cli, f.role, removal), "stale");
  });

  it("group.update and group.delete bind the version: a group changed since makes the approval stale", async () => {
    const rename = await approved(admin, await updateGroup("groups", admin.cli, f.group, { expectedVersion: 1, name: "oncall-2" }));
    const removal = await approved(admin, await deleteGroup("groups", admin.cli, f.group));
    // Changed since (version 2), with the same name.
    await ctx.db.query("UPDATE groups SET version = 2 WHERE id = $1", [f.group]);
    invalid(await updateGroup("groups", admin.cli, f.group, { expectedVersion: 2, name: "oncall-2" }, rename), "stale");
    invalid(await deleteGroup("groups", admin.cli, f.group, removal), "stale");
    expect(await groupRow(f.group)).toMatchObject({ name: "oncall", version: 2, deleted: false });
    // The same for a team.
    const teamRemoval = await approved(admin, await deleteGroup("teams", admin.cli, f.team));
    await ctx.db.query("UPDATE groups SET version = 2 WHERE id = $1", [f.team]);
    invalid(await deleteGroup("teams", admin.cli, f.team, teamRemoval), "stale");
    expect(await groupRow(f.team)).toMatchObject({ deleted: false });
  });

  it("group and team create, rename and delete bind the stored kind; a rename keeping the name needs none", async () => {
    const asked = await approved(admin, await createGroup("groups", admin.cli, "sre"));
    invalid(await createGroup("teams", admin.cli, "sre", asked), "mismatch");
    invalid(await createGroup("groups", admin.cli, "sre-2", asked), "mismatch");
    expect((await createGroup("groups", admin.cli, "sre", asked)).status).toBe(201);
    // A taken name (of any kind) is refused first.
    const before = await intents();
    expect((await createGroup("teams", admin.cli, "oncall")).body.error.code).toBe("VALIDATION_FAILED");
    // Leaving the name out, or sending the current one, changes nothing.
    expect((await updateGroup("groups", admin.cli, f.group, { expectedVersion: 1 })).status).toBe(200);
    expect((await updateGroup("groups", admin.cli, f.group, { expectedVersion: 1, name: "oncall" })).status).toBe(200);
    expect(await intents()).toBe(before);
    const rename = await approved(admin, await updateGroup("groups", admin.cli, f.group, { expectedVersion: 1, name: "oncall-2" }));
    invalid(await updateGroup("groups", admin.cli, f.group, { expectedVersion: 1, name: "oncall-3" }, rename), "mismatch");
    expect((await updateGroup("groups", admin.cli, f.group, { expectedVersion: 1, name: "oncall-2" }, rename)).status).toBe(200);
    // A team deleted through a /groups/ route is team.delete.
    const del = stepUp(await deleteGroup("groups", admin.cli, f.team));
    expect(del.operation).toBe("team.delete");
    await approve(admin, del.id);
    invalid(await deleteGroup("groups", admin.cli, f.group, del.id), "mismatch");
    expect((await deleteGroup("teams", admin.cli, f.team, del.id)).status).toBe(204);
    expect(await groupRow(f.team)).toMatchObject({ deleted: true });
  });

  it("memberships bind the group and the identity; a current member needs none; a team through /groups/ is team.member_add", async () => {
    const asked = stepUp(await addMember("groups", admin.cli, f.team, f.svc));
    expect(asked.operation).toBe("team.member_add");
    await approve(admin, asked.id);
    invalid(await addMember("groups", admin.cli, f.group, f.svc, asked.id), "mismatch");
    invalid(await addMember("groups", admin.cli, f.team, admin.id, asked.id), "mismatch");
    invalid(await removeMember("groups", admin.cli, f.team, f.bob.id, asked.id), "mismatch");
    expect((await addMember("teams", admin.cli, f.team, f.svc, asked.id)).status).toBe(204);
    expect(await isMember(f.team, f.svc)).toBe(true);
    // A current member: nothing changes, no approval, even with a used one.
    const before = await intents();
    expect((await addMember("teams", admin.cli, f.team, f.bob.id)).status).toBe(204);
    expect((await addMember("teams", bot.token, f.team, f.bob.id)).status).toBe(204);
    expect((await addMember("teams", admin.cli, f.team, f.svc, asked.id)).status).toBe(204);
    // Not a member, or not in the Organization: refused first.
    expect((await removeMember("groups", admin.cli, f.group, f.bob.id)).status).toBe(404);
    expect((await addMember("groups", admin.cli, f.group, "idn_nope")).status).toBe(404);
    expect(await intents()).toBe(before);
    const removal = await approved(admin, await removeMember("teams", admin.cli, f.team, f.bob.id));
    invalid(await removeMember("teams", admin.cli, f.team, f.svc, removal), "mismatch");
    expect((await removeMember("teams", admin.cli, f.team, f.bob.id, removal)).status).toBe(204);
    expect(await isMember(f.team, f.bob.id)).toBe(false);
  });

  it("Team-Project links bind the team and the project; a linked project needs none", async () => {
    const other = await ok("POST", `${ORG}/projects`, admin.cli, { name: "Web", slug: "web", contractAuthority: "managed" });
    const asked = await approved(admin, await removeProject(admin.cli, f.team, f.project));
    invalid(await addProject(admin.cli, f.team, other.id, asked), "mismatch");
    expect((await removeProject(admin.cli, f.team, f.project, asked)).status).toBe(204);
    const add = await approved(admin, await addProject(admin.cli, f.team, f.project));
    invalid(await addProject(admin.cli, f.team, other.id, add), "mismatch");
    expect((await addProject(admin.cli, f.team, f.project, add)).status).toBe(204);
    const before = await intents();
    expect((await addProject(admin.cli, f.team, f.project)).status).toBe(204);
    expect((await addProject(admin.cli, f.team, "prj_nope")).status).toBe(404);
    expect((await removeProject(admin.cli, f.team, other.id)).status).toBe(404);
    expect(await intents()).toBe(before);
  });

  it("names every item with its quoted name and its id: two identities named Bob read apart in every summary", async () => {
    // A machine also named Bob, beside the person Bob.
    const machine = await ok("POST", `${ORG}/identities`, admin.cli, { name: "Bob", kind: "service" },
      header(await approved(admin, await call("POST", `${ORG}/identities`, admin.cli, { name: "Bob", kind: "service" }))));
    const person = named("Bob", f.bob.id);
    const robotBob = named("Bob", machine.id);
    const api = `project ${named("api", f.project)}`;
    const decl = (subjectIdentityId: string) => ({ subjectIdentityId, scope: { kind: "project", projectId: f.project }, actions: ["project.read"] });
    const toPerson = stepUp(await createGrant(admin.cli, decl(f.bob.id)));
    expect(toPerson.summary.title).toBe(`Grant project.read on ${api} to ${person}`);
    await approve(admin, toPerson.id);
    const grant = (await createGrant(admin.cli, decl(f.bob.id), toPerson.id)).body;
    // The same scope and permission, the other Bob: the subject change is listed, with both ids.
    const swap = stepUp(await replaceGrant(admin.cli, grant.id, decl(machine.id)));
    expect(swap.summary).toEqual({
      title: `Change the Grant of project.read on ${api} to ${person}`,
      changes: [{ field: "subject", from: person, to: robotBob, loosens: false }],
    });
    // Memberships name the Bob they mean.
    expect(stepUp(await addMember("groups", admin.cli, f.group, machine.id)).summary.title).toBe(`Add ${robotBob} to group ${named("oncall", f.group)}`);
    expect(stepUp(await removeMember("teams", admin.cli, f.team, f.bob.id)).summary.title).toBe(`Remove ${person} from team ${named("platform", f.team)}`);
  });

  it("a name that imitates another's label, or differs only by whitespace, never reads the same", async () => {
    // Codex's scenario: a machine whose literal name is the person Bob's label, both in the group.
    const impostor = await ok("POST", `${ORG}/identities`, admin.cli, { name: `Bob (${f.bob.id})`, kind: "service" },
      header(await approved(admin, await call("POST", `${ORG}/identities`, admin.cli, { name: `Bob (${f.bob.id})`, kind: "service" }))));
    await ctx.db.query("INSERT INTO group_members (group_id, identity_id) VALUES ($1, $2), ($1, $3)", [f.group, f.bob.id, impostor.id]);
    const removeBob = stepUp(await removeMember("groups", admin.cli, f.group, f.bob.id)).summary.title;
    const removeImpostor = stepUp(await removeMember("groups", admin.cli, f.group, impostor.id)).summary.title;
    expect(removeBob).toBe(`Remove "Bob" (${f.bob.id}) from group "oncall" (${f.group})`);
    expect(removeImpostor).toBe(`Remove "Bob (${f.bob.id})" (${impostor.id}) from group "oncall" (${f.group})`);
    expect(removeImpostor).not.toBe(removeBob);

    // Codex's scenario: roles "reader" and "reader " (a trailing space), a Grant moved from one to the other.
    const spaced = await ok("POST", `${ORG}/roles`, admin.cli, { name: "reader ", actions: ["project.read"] },
      header(await approved(admin, await createRole(admin.cli, { name: "reader ", actions: ["project.read"] }))));
    const moved = stepUp(await replaceGrant(admin.cli, f.grant, { subjectGroupId: f.group, scope: { kind: "project", projectId: f.project }, roleId: spaced.id }));
    expect(moved.summary.changes).toEqual([
      { field: "permission", from: `role "reader" (${f.role})`, to: `role "reader " (${spaced.id})`, loosens: false },
    ]);
  });

  it("never hides an environment or a Project moved to a reused slug", async () => {
    const prodA = (await ok("POST", `${ORG}/projects/api/environments`, admin.cli, { name: "prod", tier: "production" })).id as string;
    const envDecl = (projectId: string, environmentIds: string[]) =>
      ({ subjectIdentityId: f.svc, scope: { kind: "environments", projectId, selector: { kind: "environments", environmentIds } }, actions: ["project.read"] });
    const projectDecl = (projectId: string) => ({ subjectIdentityId: f.svc, scope: { kind: "project", projectId }, actions: ["config.value.read"] });
    const make = async (decl: Body) => (await createGrant(admin.cli, decl, await approved(admin, await createGrant(admin.cli, decl)))).body.id as string;
    const envGrant = await make(envDecl(f.project, [prodA]));
    const projectGrant = await make(projectDecl(f.project));
    // Project A (slug api) deleted; Project B takes the slug, with its own prod and staging.
    expect((await call("DELETE", `${ORG}/projects/api`, admin.cli)).status).toBe(200);
    const projectB = (await ok("POST", `${ORG}/projects`, admin.cli, { name: "API", slug: "api", contractAuthority: "managed" })).id as string;
    const prodB = (await ok("POST", `${ORG}/projects/api/environments`, admin.cli, { name: "prod", tier: "production" })).id as string;
    const stagingB = (await ok("POST", `${ORG}/projects/api/environments`, admin.cli, { name: "staging", tier: "staging" })).id as string;

    // prod moved Projects under the same slug/name: each prod carries its id.
    const moved = stepUp(await replaceGrant(admin.cli, envGrant, envDecl(projectB, [prodB, stagingB])));
    expect(moved.summary.changes).toEqual([
      {
        field: "scope",
        from: `environments ${named("api/prod", prodA)}`,
        to: `environments ${[named("api/prod", prodB), named("api/staging", stagingB)].sort().join(", ")}`,
        loosens: false,
      },
    ]);
    // The Project-level analogue: the deleted and the live Project with the same slug read apart.
    const project = stepUp(await replaceGrant(admin.cli, projectGrant, projectDecl(projectB)));
    expect(project.summary.changes).toEqual([
      { field: "scope", from: `project ${named("api", f.project)}`, to: `project ${named("api", projectB)}`, loosens: false },
    ]);
  });

  it("decides a Grant change on what is bound, not on its labels", async () => {
    // A store whose every row is named "Bob": the change is still listed, and each side carries its id.
    const db = { query: async (_sql: string, params: unknown[] = []) => ({ rows: (params[0] as string[]).map((id) => ({ id, name: "Bob", slug: "Bob", kind: "group" })) }) } as unknown as Querier;
    const old = { id: "grt_old", revoked: false, subjectIdentityId: "idn_a", scope: { kind: "organization" as const }, actions: ["project.read"] };
    const binding = await grantReplaceBinding(db, { id: orgId }, old, { ...old, subjectIdentityId: "idn_b" });
    expect(binding.summary.changes).toEqual([
      { field: "subject", from: '"Bob" (idn_a)', to: '"Bob" (idn_b)', loosens: false },
    ]);
    // A role in place of another, both named "Bob": listed too.
    const role = await grantReplaceBinding(db, { id: orgId }, { ...old, actions: null, roleId: "rol_a" }, { ...old, actions: null, roleId: "rol_b" });
    expect(role.summary.changes).toEqual([{ field: "permission", from: 'role "Bob" (rol_a)', to: 'role "Bob" (rol_b)', loosens: false }]);
    // One environment of two swapped, all named "Bob": each reads apart, item by item.
    const envs = (environmentIds: string[]) => ({ ...old, scope: { kind: "environments" as const, projectId: "prj_a", selector: { kind: "environments" as const, environmentIds } } });
    const scope = await grantReplaceBinding(db, { id: orgId }, { ...envs(["env_a", "env_b"]), id: "grt_old", revoked: false }, envs(["env_a", "env_c"]));
    expect(scope.summary.changes).toEqual([
      { field: "scope", from: 'environments "Bob" (env_a), "Bob" (env_b)', to: 'environments "Bob" (env_a), "Bob" (env_c)', loosens: false },
    ]);
  });

  it("labels quote the name: a name with an id-like suffix, quotes or trailing whitespace stays distinct", () => {
    expect(labelWithId(null, "Bob", "idn_a")).toBe('"Bob" (idn_a)');
    expect(labelWithId("role", "reader ", "rol_b")).toBe('role "reader " (rol_b)');
    // Text that imitates a label cannot end the quoted name early.
    const fake = labelWithId(null, 'Bob" (idn_a)', "idn_b");
    expect(fake).toBe('"Bob\\" (idn_a)" (idn_b)');
    expect(fake.endsWith("(idn_b)")).toBe(true);
    expect(labelWithId(null, "Bob (idn_a)", "idn_b")).not.toBe(labelWithId(null, "Bob", "idn_a"));
    expect(labelWithId(null, "Bob\n", "idn_c")).toBe('"Bob\\n" (idn_c)');
  });

  it("refuses another person's approval: even an admin finds nothing", async () => {
    const eve = await invite("Eve", "admin");
    const asked = await approved(admin, await createRole(admin.cli, { name: "writer", actions: ["project.read"] }));
    invalid(await createRole(eve.cli, { name: "writer", actions: ["project.read"] }, asked), "not-found");
    const revoke = await approved(admin, await revokeGrant(admin.cli, f.grant));
    invalid(await revokeGrant(eve.cli, f.grant, revoke), "not-found");
    expect(await count("SELECT count(*)::int AS n FROM roles WHERE name = 'writer'")).toBe(0);
    expect(await count("SELECT count(*)::int AS n FROM grants WHERE id = $1 AND revoked_at IS NULL", [f.grant])).toBe(1);
  });

  it("refuses a machine credential outright, without an intent, for all 18 operations", async () => {
    // Targets each operation would change: a member of the group, and a project the team does not own yet.
    await ctx.db.query("INSERT INTO group_members (group_id, identity_id) VALUES ($1, $2)", [f.group, f.svc]);
    const unlinked = await ok("POST", `${ORG}/projects`, admin.cli, { name: "Web", slug: "web", contractAuthority: "managed" });
    const answers = [
      await createGrant(bot.token, { subjectIdentityId: f.svc, scope: { kind: "organization" }, actions: ["project.read"] }),
      await replaceGrant(bot.token, f.grant, { subjectGroupId: f.group, scope: { kind: "organization" }, roleId: f.role }),
      await revokeGrant(bot.token, f.grant),
      await createRole(bot.token, { name: "x", actions: ["project.read"] }),
      await updateRole(bot.token, f.role, { expectedVersion: 1, name: "x" }),
      await deleteRole(bot.token, f.role),
      await createGroup("groups", bot.token, "x"),
      await updateGroup("groups", bot.token, f.group, { expectedVersion: 1, name: "x" }),
      await deleteGroup("groups", bot.token, f.group),
      await addMember("groups", bot.token, f.group, f.bob.id),
      await removeMember("groups", bot.token, f.group, f.svc),
      await removeMember("teams", bot.token, f.team, f.bob.id),
      await createGroup("teams", bot.token, "y"),
      await updateGroup("teams", bot.token, f.team, { expectedVersion: 1, name: "y" }),
      await deleteGroup("teams", bot.token, f.team),
      await addMember("teams", bot.token, f.team, f.svc),
      await addProject(bot.token, f.team, unlinked.id),
      await removeProject(bot.token, f.team, f.project),
    ];
    expect(answers).toHaveLength(18);
    for (const res of answers) {
      expect(res.status, JSON.stringify(res.body)).toBe(403);
      expect(res.body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "machine-credential" } });
    }
    expect(await intents()).toBe(0);
    expect(await roleRow(f.role)).toMatchObject({ name: "reader", deleted: false });
    expect(await groupRow(f.team)).toMatchObject({ name: "platform", deleted: false });
    expect(await isMember(f.team, f.bob.id)).toBe(true);
    expect(await isMember(f.group, f.svc)).toBe(true);
    expect(await isMember(f.group, f.bob.id)).toBe(false);
    expect(await isLinked(f.team, f.project)).toBe(true);
    expect(await isLinked(f.team, unlinked.id)).toBe(false);
  });

  it("rolls the consumption back with a failed mutation: the approval stays usable", async () => {
    const asked = await approved(admin, await createRole(admin.cli, { name: "writer", actions: ["project.read"] }));
    await ctx.db.query(`CREATE FUNCTION fail_role_insert() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'injected failure'; END $$`);
    await ctx.db.query("CREATE TRIGGER fail_role_insert BEFORE INSERT ON roles FOR EACH ROW EXECUTE FUNCTION fail_role_insert()");
    expect((await createRole(admin.cli, { name: "writer", actions: ["project.read"] }, asked)).status).toBeGreaterThanOrEqual(400);
    expect((await rows("SELECT approved_at IS NOT NULL AS approved, consumed_at FROM approval_intents WHERE id = $1", [asked]))[0])
      .toEqual({ approved: true, consumed_at: null });
    await ctx.db.query("DROP TRIGGER fail_role_insert ON roles");
    expect((await createRole(admin.cli, { name: "writer", actions: ["project.read"] }, asked)).status).toBe(201);
  });

  it("asks under an Idempotency-Key without leaving a claim; the approved repeat claims it once", async () => {
    for (const [send, check] of [
      [
        (approval?: string) => updateRole(admin.cli, f.role, { expectedVersion: 1, name: "readers" }, approval, { "Idempotency-Key": "role-1" }),
        async () => expect(await roleRow(f.role)).toMatchObject({ name: "readers", version: 2 }),
      ],
      [
        (approval?: string) => updateGroup("teams", admin.cli, f.team, { expectedVersion: 1, name: "platform-2" }, approval, { "Idempotency-Key": "team-1" }),
        async () => expect(await groupRow(f.team)).toMatchObject({ name: "platform-2", version: 2 }),
      ],
      [
        (approval?: string) => replaceGrant(admin.cli, f.grant, { subjectGroupId: f.group, scope: { kind: "organization" }, roleId: f.role }, approval, { "Idempotency-Key": "grant-1" }),
        async () => expect(await count("SELECT count(*)::int AS n FROM grants WHERE id = $1 AND revoked_at IS NOT NULL", [f.grant])).toBe(1),
      ],
    ] as const) {
      const claimsBefore = await claims();
      const asked = stepUp(await send());
      expect(await claims()).toBe(claimsBefore);
      await approve(admin, asked.id);
      const done = await send(asked.id);
      expect(done.status, JSON.stringify(done.body)).toBeLessThan(300);
      expect(await claims()).toBe(claimsBefore + 1);
      // A replay answers from the stored response, approval or not, and changes nothing.
      expect(await send()).toEqual(done);
      await check();
    }
    // An empty header is still a header: the requester is locked FOR UPDATE
    // before the claim, never KEY SHARE first and upgraded (the lock-order
    // check fails the test otherwise).
    const empty = await updateRole(admin.cli, f.role, { expectedVersion: 2, name: "x" }, undefined, { "Varlatch-Approval": "", "Idempotency-Key": "role-empty" });
    expect(empty.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "not-found" } });
  });

  it("refuses a malformed Varlatch-Approval header once an approval is needed, without asking for one", async () => {
    invalid(await createRole(admin.cli, { name: "x", actions: ["project.read"] }, "invalid"), "not-found");
    invalid(await revokeGrant(admin.cli, f.grant, "invalid"), "not-found");
    expect(await intents()).toBe(0);
  });

  it("lets ApprovalNeeded escape a serializable transaction without a retry", async () => {
    const requester: Requester = { identityId: admin.id, identityKind: "human", credentialId: admin.cliId, credentialKind: "cli" };
    let attempts = 0;
    const run = withApproval(ctx, { requester, approvalId: null, publicUrl: PUBLIC_URL }, (gate) =>
      withSerializableTx(ctx.db, async (db) => {
        attempts++;
        await prepareProtectedOperation(db, gate, {
          scope: { organizationId: orgId, people: [admin.id] },
          checks: [{ control: "admin-step-up", operation: "role.create" }],
          binding: async () => roleCreateBinding({ id: orgId }, { name: "x", actions: ["project.read"] }),
        });
      }));
    await expect(run).rejects.toMatchObject({ code: "STEP_UP_REQUIRED" });
    expect(attempts).toBe(1);
    expect(await rows("SELECT operation FROM approval_intents")).toEqual([{ operation: "role.create" }]);
  });

  it("refuses a second consumption of one approval", async () => {
    const asked = stepUp(await createRole(admin.cli, { name: "x", actions: ["project.read"] }));
    await approve(admin, asked.id);
    const requester: Requester = { identityId: admin.id, identityKind: "human", credentialId: admin.cliId, credentialKind: "cli" };
    const prepare = () =>
      withApproval(ctx, { requester, approvalId: asked.id, publicUrl: PUBLIC_URL }, (gate) =>
        withTx(ctx.db, async (db) => prepareProtectedOperation(db, gate, {
          scope: { organizationId: orgId, people: [admin.id] },
          checks: [{ control: "admin-step-up", operation: "role.create" }],
          binding: async () => roleCreateBinding({ id: orgId }, { name: "x", actions: ["project.read"] }),
        })));
    expect((await prepare()).approval).toMatchObject({ id: asked.id, userVerified: true });
    const again = await prepare().catch((err: unknown) => err);
    expect(again).toBeInstanceOf(DomainError);
    expect(again).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "consumed" } });
  });

  it("is turned off by the operator's reset, which closes the open approvals of these operations", async () => {
    const asked = stepUp(await createRole(admin.cli, { name: "writer", actions: ["project.read"] }));
    const revoke = stepUp(await revokeGrant(admin.cli, f.grant));
    const link = stepUp(await removeProject(admin.cli, f.team, f.project));
    const outcome = await resetControls(ctx, { organization: "acme", controls: ["admin-step-up"] });
    expect(outcome.approvalsClosed).toBe(3);
    expect(await rows("SELECT id, close_reason FROM approval_intents ORDER BY id")).toEqual(
      [asked.id, revoke.id, link.id].sort().map((id) => ({ id, close_reason: "reset" })),
    );
    expect((await createRole(admin.cli, { name: "writer", actions: ["project.read"] })).status).toBe(201);
  });

  it("the incident freeze: refused operations answer it first; revoking a Grant is recovery and still asks", async () => {
    const pending = await approved(admin, await createRole(admin.cli, { name: "writer", actions: ["project.read"] }));
    expect((await call("POST", `${ORG}/incident-freeze`, admin.cli, { reason: "A CI token leaked" })).status).toBe(201);
    expect((await rows("SELECT close_reason FROM approval_intents WHERE id = $1", [pending]))[0].close_reason).toBe("frozen");

    const before = await intents();
    expect((await createRole(admin.cli, { name: "writer", actions: ["project.read"] })).body.error.code).toBe("ORGANIZATION_FROZEN");
    expect((await createRole(admin.cli, { name: "writer", actions: ["project.read"] }, pending)).body.error.code).toBe("ORGANIZATION_FROZEN");
    expect((await createGrant(admin.cli, { subjectIdentityId: f.svc, scope: { kind: "organization" }, actions: ["project.read"] })).body.error.code).toBe("ORGANIZATION_FROZEN");
    expect((await removeMember("teams", admin.cli, f.team, f.bob.id)).body.error.code).toBe("ORGANIZATION_FROZEN");
    expect((await removeProject(admin.cli, f.team, f.project)).body.error.code).toBe("ORGANIZATION_FROZEN");
    expect(await intents()).toBe(before);

    // Recovery: revoking the Grant is allowed while frozen, and admin-step-up still asks for it.
    const revoke = stepUp(await revokeGrant(admin.cli, f.grant));
    expect(revoke.operation).toBe("grant.revoke");
    await approve(admin, revoke.id);
    expect((await revokeGrant(admin.cli, f.grant, revoke.id)).status).toBe(204);
    expect(await count("SELECT count(*)::int AS n FROM grants WHERE id = $1 AND revoked_at IS NULL", [f.grant])).toBe(0);
  });
});
