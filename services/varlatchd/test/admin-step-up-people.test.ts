// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { OPERATIONS_DURING_FREEZE, withApproval, type Requester } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { changeMemberRole } from "../src/domain/members.js";
import { ENFORCEABLE_CONTROLS, resetControls } from "../src/domain/securitycontrols.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * admin-step-up for people (ADR-0054 step 4.7), on PGlite under the
 * lock-order check (test/helpers/lock-trace.ts): inviting someone as an
 * admin, promoting a member, demoting an admin and removing a member, with
 * the last-admin rule. The API still refuses `enforce` for admin-step-up
 * (it is unlocked in step 4.9), so these tests set it directly in the
 * database. With every control off nothing changes; report mode counts
 * and refuses nothing; under enforce each operation needs the requester's
 * approval bound to exactly that request, as the binding catalogue says,
 * and a machine credential is refused without an intent. Leaving and
 * inviting a member stay exempt. The races (two admins demoting each
 * other, a removal against a demotion) run on real PostgreSQL in
 * admin-step-up-people-postgres.test.ts.
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
const header = (approval?: string) => (approval ? { "Varlatch-Approval": approval } : {});

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

const lastAdmin = (res: Answer) => {
  expect(res.status, JSON.stringify(res.body)).toBe(422);
  expect(res.body.error).toMatchObject({ code: "VALIDATION_FAILED", details: { reason: "last-admin" } });
};

// The operations, as their routes take them.
const inviteAs = (token: string, name: string, role: "admin" | "member", approval?: string) =>
  call("POST", `${ORG}/invitations`, token, { name, role }, header(approval));
const setRole = (token: string, member: string, role: "admin" | "member", approval?: string) =>
  call("PATCH", `${ORG}/members/${member}`, token, { role }, header(approval));
const remove = (token: string, member: string, approval?: string) => call("DELETE", `${ORG}/members/${member}`, token, undefined, header(approval));

async function events(eventType: string) {
  const parse = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v) as Record<string, any> | null;
  return (await rows("SELECT actor_identity_id, metadata FROM audit_events WHERE event_type = $1 ORDER BY event_order", [eventType]))
    .map((r) => ({ actor: r.actor_identity_id as string, metadata: parse(r.metadata) ?? {} }));
}

const roleOf = async (identityId: string) =>
  ((await rows("SELECT role, removed_at IS NOT NULL AS removed FROM org_memberships WHERE organization_id = $1 AND identity_id = $2", [orgId, identityId]))[0]) as
    | { role: string; removed: boolean }
    | undefined;
const versionOf = async (identityId: string) =>
  Number((await rows("SELECT version FROM org_memberships WHERE organization_id = $1 AND identity_id = $2", [orgId, identityId]))[0].version);
const invitations = (name: string) => count("SELECT count(*)::int AS n FROM setup_grants WHERE kind = 'invite' AND invite_name = $1", [name]);

/**
 * Made while every control is off: Carol, a second admin; Bob, a member
 * with a direct Grant of identity.manage, in one group, who issued one
 * pending invitation; Dave, a member.
 */
async function fixtures() {
  const carol = await invite("Carol", "admin");
  const bob = await invite("Bob", "member");
  const dave = await invite("Dave", "member");
  await ok("POST", `${ORG}/grants`, admin.cli, { subjectIdentityId: bob.id, scope: { kind: "organization" }, actions: ["identity.manage"] });
  const group = await ok("POST", `${ORG}/groups`, admin.cli, { name: "oncall" });
  await ok("POST", `${ORG}/groups/${group.id}/members`, admin.cli, { identityId: bob.id });
  await ok("POST", `${ORG}/invitations`, bob.cli, { name: "Guest", role: "member" });
  return { carol, bob, dave, group: group.id as string };
}
type Fixtures = Awaited<ReturnType<typeof fixtures>>;

/** A machine identity of the Organization that holds identity.manage. */
async function robot() {
  const created = await ok("POST", `${ORG}/identities`, admin.cli, { name: "robot", kind: "service" });
  await ok("POST", `${ORG}/grants`, admin.cli, { subjectIdentityId: created.id, scope: { kind: "organization" }, actions: ["identity.manage"] });
  return { id: created.id as string, token: created.credential as string };
}

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
  it("runs the four operations and leaving as before: no approval, no count, no intent, audit as before", async () => {
    const f = await fixtures();
    expect((await inviteAs(admin.cli, "Zoe", "admin")).status).toBe(201);
    expect((await setRole(admin.cli, f.dave.id, "admin")).body).toEqual({ identityId: f.dave.id, role: "admin", previousRole: "member" });
    expect((await setRole(admin.cli, f.dave.id, "member")).body).toEqual({ identityId: f.dave.id, role: "member", previousRole: "admin" });
    expect((await remove(admin.cli, f.bob.id)).body).toMatchObject({ identityId: f.bob.id, role: "member", left: false, grantsRevoked: 1, groupsLeft: 1, invitationsRevoked: 1 });
    expect((await remove(admin.cli, f.carol.id)).body).toMatchObject({ role: "admin", left: false });
    expect((await remove(f.dave.cli, "me")).body).toMatchObject({ identityId: f.dave.id, left: true });
    expect(await intents()).toBe(0);
    expect(await counters()).toBe(0);
    expect((await events("invitation.issued")).at(-1)!.metadata).toEqual({ role: "admin", inviteeName: "Zoe", expiresAt: expect.any(String) });
    expect((await events("membership.role_changed")).map((e) => e.metadata)).toEqual([
      { previousRole: "member", role: "admin" },
      { previousRole: "admin", role: "member" },
    ]);
    expect((await events("membership.removed")).map((e) => e.metadata)).toEqual([
      { role: "member", left: false, grantsRevoked: 1, groupsLeft: 1, invitationsRevoked: 1 },
      { role: "admin", left: false, grantsRevoked: 0, groupsLeft: 0, invitationsRevoked: 0 },
      { role: "member", left: true, grantsRevoked: 0, groupsLeft: 0, invitationsRevoked: 0 },
    ]);
  });

  it("ignores a malformed Varlatch-Approval header, as before", async () => {
    const f = await fixtures();
    expect((await inviteAs(admin.cli, "Zoe", "admin", "invalid")).status).toBe(201);
    expect((await setRole(admin.cli, f.dave.id, "admin", "invalid")).status).toBe(200);
    expect((await remove(admin.cli, f.dave.id, "invalid")).status).toBe(200);
    expect(await intents()).toBe(0);
  });

  it("keeps the last-admin rule", async () => {
    lastAdmin(await setRole(admin.cli, "me", "member"));
    lastAdmin(await remove(admin.cli, "me"));
    expect(await roleOf(admin.id)).toEqual({ role: "admin", removed: false });
  });
});

describe("in report mode", () => {
  it("refuses nothing and counts each operation, by a person and by a machine; leaving, a member's invitation and the same role are not counted", async () => {
    const f = await fixtures();
    const bot = await robot();
    expect((await setMode("admin-step-up", "report")).status).toBe(200);
    expect((await inviteAs(admin.cli, "Zoe", "admin")).status).toBe(201);
    expect((await inviteAs(bot.token, "Yann", "admin")).status).toBe(201);
    expect((await inviteAs(admin.cli, "Guest2", "member")).status).toBe(201);
    expect((await setRole(admin.cli, f.dave.id, "admin")).status).toBe(200);
    expect((await setRole(admin.cli, f.dave.id, "admin")).status).toBe(200);
    expect((await setRole(admin.web, f.dave.id, "member")).status).toBe(200);
    expect((await remove(admin.cli, f.bob.id)).status).toBe(200);
    expect((await remove(f.dave.cli, "me")).status).toBe(200);
    expect(await intents()).toBe(0);
    expect(
      await rows("SELECT operation, reason, actor_identity_id, count::int AS count FROM security_control_counters WHERE control = 'admin-step-up' ORDER BY operation, reason"),
    ).toEqual([
      { operation: "member.demote", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
      { operation: "member.invite_admin", reason: "machine-credential", actor_identity_id: bot.id, count: 1 },
      { operation: "member.invite_admin", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
      { operation: "member.promote", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
      { operation: "member.remove", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
    ]);
  });

  it("does not count a refused request: the last admin's demotion", async () => {
    expect((await setMode("admin-step-up", "report")).status).toBe(200);
    lastAdmin(await setRole(admin.cli, "me", "member"));
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
    const inv = stepUp(await inviteAs(admin.cli, "Zoe", "admin"));
    expect(inv).toMatchObject({ operation: "member.invite_admin", organization: { id: orgId, slug: "acme" }, state: "pending" });
    expect(inv.summary).toEqual({
      title: "Invite Zoe as an Organization Admin",
      changes: [
        { field: "name", from: null, to: "Zoe", loosens: false },
        { field: "role", from: null, to: "admin", loosens: false },
      ],
    });
    const promote = stepUp(await setRole(admin.cli, f.dave.id, "admin"));
    expect(promote).toMatchObject({ operation: "member.promote" });
    expect(promote.summary).toEqual({ title: "Make Dave an Organization Admin", changes: [{ field: "role", from: "member", to: "admin", loosens: false }] });
    const demote = stepUp(await setRole(admin.web, f.carol.id, "member"));
    expect(demote).toMatchObject({ operation: "member.demote" });
    expect(demote.summary).toEqual({ title: "Make Carol a member instead of an admin", changes: [{ field: "role", from: "admin", to: "member", loosens: false }] });
    const removal = stepUp(await remove(admin.cli, f.bob.id));
    expect(removal).toMatchObject({ operation: "member.remove" });
    expect(removal.summary).toEqual({ title: "Remove Bob (member) from Acme: 1 direct Grant revoked, 1 group left, 1 invitation revoked", changes: [] });
    expect(stepUp(await remove(admin.cli, f.carol.id)).summary.title).toBe("Remove Carol (admin) from Acme: 0 direct Grants revoked, 0 groups left, 0 invitations revoked");

    expect(await invitations("Zoe")).toBe(0);
    expect(await roleOf(f.dave.id)).toEqual({ role: "member", removed: false });
    expect(await roleOf(f.carol.id)).toEqual({ role: "admin", removed: false });
    expect(await roleOf(f.bob.id)).toEqual({ role: "member", removed: false });
    // Nothing is counted under enforce.
    expect(await counters()).toBe(0);
  });

  it("needs no approval to invite a member, to leave, or for the same role again", async () => {
    expect((await inviteAs(admin.cli, "Guest2", "member")).status).toBe(201);
    expect((await setRole(admin.cli, f.carol.id, "admin")).body).toEqual({ identityId: f.carol.id, role: "admin", previousRole: "admin" });
    expect((await setRole(admin.cli, f.dave.id, "member")).body).toEqual({ identityId: f.dave.id, role: "member", previousRole: "member" });
    expect((await remove(f.dave.cli, "me")).body).toMatchObject({ identityId: f.dave.id, left: true });
    expect((await remove(f.carol.cli, "me")).body).toMatchObject({ identityId: f.carol.id, role: "admin", left: true });
    expect(await intents()).toBe(0);
    expect(await counters()).toBe(0);
  });

  it("runs each operation with its approval, once, and records the approval in the audit", async () => {
    const run = async (send: (approval?: string) => Promise<Answer>) => {
      const res = await send(await approved(admin, await send()));
      expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
      return res;
    };
    const zoe = await run((a) => inviteAs(admin.cli, "Zoe", "admin", a));
    expect(zoe.body).toMatchObject({ id: expect.any(String), token: expect.stringMatching(/^vlt_invite_/) });
    await run((a) => setRole(admin.cli, f.dave.id, "admin", a));
    // The dashboard's own approval: asked and repeated by the browser bearer.
    await run((a) => setRole(admin.web, f.dave.id, "member", a));
    const removed = await run((a) => remove(admin.cli, f.bob.id, a));
    expect(removed.body).toMatchObject({ identityId: f.bob.id, role: "member", left: false, grantsRevoked: 1, groupsLeft: 1, invitationsRevoked: 1 });

    expect(await invitations("Zoe")).toBe(1);
    expect(await roleOf(f.dave.id)).toEqual({ role: "member", removed: false });
    expect(await roleOf(f.bob.id)).toEqual({ role: "member", removed: true });
    expect(await count("SELECT count(*)::int AS n FROM approval_intents WHERE consumed_at IS NOT NULL")).toBe(4);
    expect(await rows("SELECT DISTINCT operation FROM approval_intents ORDER BY operation")).toEqual(
      ["member.demote", "member.invite_admin", "member.promote", "member.remove"].map((operation) => ({ operation })),
    );
    expect((await events("invitation.issued")).at(-1)!.metadata).toMatchObject({ role: "admin", inviteeName: "Zoe", approvalId: expect.any(String), approvalUserVerified: true });
    for (const e of (await events("membership.role_changed")).slice(-2)) expect(e.metadata).toMatchObject({ approvalId: expect.any(String), approvalUserVerified: true });
    expect((await events("membership.removed")).at(-1)!.metadata).toMatchObject({ role: "member", left: false, approvalId: expect.any(String), approvalUserVerified: true });
    expect(await counters()).toBe(0);
  });

  it("member.invite_admin binds the Organization and the name", async () => {
    const asked = await approved(admin, await inviteAs(admin.cli, "Zoe", "admin"));
    invalid(await inviteAs(admin.cli, "Zed", "admin", asked), "mismatch");
    // A member's invitation needs no approval, and ignores the one it carries.
    expect((await inviteAs(admin.cli, "Zoe", "member", asked)).status).toBe(201);
    expect((await rows("SELECT consumed_at FROM approval_intents WHERE id = $1", [asked]))[0].consumed_at).toBeNull();
    expect((await inviteAs(admin.cli, "Zoe", "admin", asked)).status).toBe(201);
    const [intent] = await rows("SELECT target, expected_version FROM approval_intents WHERE id = $1", [asked]);
    expect(typeof intent.target === "string" ? JSON.parse(intent.target) : intent.target).toEqual({ organizationId: orgId });
    expect(intent.expected_version).toBeNull();
  });

  it("member.promote and member.demote bind the person, the role and the membership's version; `me` is resolved", async () => {
    const promote = await approved(admin, await setRole(admin.cli, f.dave.id, "admin"));
    // Another person, another operation: refused.
    invalid(await setRole(admin.cli, f.bob.id, "admin", promote), "mismatch");
    invalid(await setRole(admin.cli, f.carol.id, "member", promote), "mismatch");
    const version = await versionOf(f.dave.id);
    expect((await rows("SELECT expected_version FROM approval_intents WHERE id = $1", [promote]))[0].expected_version).toBe(version);
    // Dave's membership moves (adding him to a group pins it): the approval is stale.
    const join = (approval?: string) => call("POST", `${ORG}/groups/${f.group}/members`, admin.cli, { identityId: f.dave.id }, header(approval));
    expect((await join(await approved(admin, await join()))).status).toBe(204);
    expect(await versionOf(f.dave.id)).toBe(version + 1);
    invalid(await setRole(admin.cli, f.dave.id, "admin", promote), "stale");
    expect(await roleOf(f.dave.id)).toEqual({ role: "member", removed: false });

    // Self-demotion is member.demote, through `me` or the id alike.
    const self = await approved(admin, await setRole(admin.cli, "me", "member"));
    const [intent] = await rows("SELECT operation, target FROM approval_intents WHERE id = $1", [self]);
    expect(intent.operation).toBe("member.demote");
    expect(typeof intent.target === "string" ? JSON.parse(intent.target) : intent.target).toEqual({ identityId: admin.id });
    expect((await setRole(admin.cli, admin.id, "member", self)).body).toEqual({ identityId: admin.id, role: "member", previousRole: "admin" });
  });

  it("member.remove binds the person and the membership's version: stale once the person was demoted", async () => {
    const removal = await approved(admin, await remove(admin.cli, f.carol.id));
    invalid(await remove(admin.cli, f.dave.id, removal), "mismatch");
    // Demoting Carol needs its own approval and moves her membership's version.
    const demote = await approved(admin, await setRole(admin.cli, f.carol.id, "member"));
    expect((await setRole(admin.cli, f.carol.id, "member", demote)).status).toBe(200);
    invalid(await remove(admin.cli, f.carol.id, removal), "stale");
    expect(await roleOf(f.carol.id)).toEqual({ role: "member", removed: false });
    // A fresh approval names her new role.
    const fresh = stepUp(await remove(admin.cli, f.carol.id));
    expect(fresh.summary.title).toContain("Remove Carol (member) from Acme");
    await approve(admin, fresh.id);
    expect((await remove(admin.cli, f.carol.id, fresh.id)).status).toBe(200);
  });

  it("refuses by the last-admin rule before asking for an approval, and again when it is used", async () => {
    // Carol leaves (exempt): Admin is the last admin.
    expect((await remove(f.carol.cli, "me")).status).toBe(200);
    const before = await intents();
    lastAdmin(await setRole(admin.cli, "me", "member"));
    expect(await intents()).toBe(before);

    // With two admins, Admin's self-demotion is asked for and approved; then
    // Dave, promoted meanwhile, is demoted again: the approval is refused by
    // the rule when it is used, and stays unconsumed.
    const promote = await approved(admin, await setRole(admin.cli, f.dave.id, "admin"));
    expect((await setRole(admin.cli, f.dave.id, "admin", promote)).status).toBe(200);
    const self = await approved(admin, await setRole(admin.cli, "me", "member"));
    const demoteDave = await approved(admin, await setRole(admin.cli, f.dave.id, "member"));
    expect((await setRole(admin.cli, f.dave.id, "member", demoteDave)).status).toBe(200);
    lastAdmin(await setRole(admin.cli, "me", "member", self));
    expect((await rows("SELECT consumed_at FROM approval_intents WHERE id = $1", [self]))[0].consumed_at).toBeNull();
    expect(await roleOf(admin.id)).toEqual({ role: "admin", removed: false });
  });

  it("refuses requests local checks would refuse before asking: not an admin, not a member", async () => {
    const before = await intents();
    const notAdmin = await setRole(f.bob.cli, f.dave.id, "admin");
    expect(notAdmin.status).toBe(403);
    expect(notAdmin.body.error.code).toBe("PERMISSION_DENIED");
    expect((await remove(f.bob.cli, f.dave.id)).status).toBe(403);
    expect((await setRole(admin.cli, "idn_nobody", "admin")).status).toBe(404);
    expect((await remove(admin.cli, "idn_nobody")).status).toBe(404);
    expect(await intents()).toBe(before);
  });

  it("refuses another person's approval: even an admin finds nothing", async () => {
    const asked = await approved(admin, await setRole(admin.cli, f.dave.id, "admin"));
    invalid(await setRole(f.carol.cli, f.dave.id, "admin", asked), "not-found");
    const inv = await approved(admin, await inviteAs(admin.cli, "Zoe", "admin"));
    invalid(await inviteAs(f.carol.cli, "Zoe", "admin", inv), "not-found");
    expect(await roleOf(f.dave.id)).toEqual({ role: "member", removed: false });
    expect(await invitations("Zoe")).toBe(0);
  });

  it("refuses a machine credential outright, without an intent", async () => {
    const res = await inviteAs(bot.token, "Zoe", "admin");
    expect(res.status, JSON.stringify(res.body)).toBe(403);
    expect(res.body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "machine-credential" } });
    // A machine has no admin membership: role changes and removals are refused as before.
    for (const answer of [await setRole(bot.token, f.dave.id, "admin"), await remove(bot.token, f.bob.id)]) {
      expect(answer.status).toBe(403);
      expect(answer.body.error.code).toBe("PERMISSION_DENIED");
    }
    expect(await intents()).toBe(0);
    expect(await invitations("Zoe")).toBe(0);
    // Inviting a member is not protected.
    expect((await inviteAs(bot.token, "Guest2", "member")).status).toBe(201);
  });

  it("refuses a second consumption of one approval", async () => {
    const asked = await approved(admin, await inviteAs(admin.cli, "Zoe", "admin"));
    expect((await inviteAs(admin.cli, "Zoe", "admin", asked)).status).toBe(201);
    invalid(await inviteAs(admin.cli, "Zoe", "admin", asked), "consumed");
    expect(await invitations("Zoe")).toBe(1);
  });

  it("rolls the consumption back with a failed mutation: the approval stays usable", async () => {
    const asked = await approved(admin, await remove(admin.cli, f.bob.id));
    await ctx.db.query(`CREATE FUNCTION fail_removal_insert() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'injected failure'; END $$`);
    await ctx.db.query("CREATE TRIGGER fail_removal_insert BEFORE INSERT ON membership_removals FOR EACH ROW EXECUTE FUNCTION fail_removal_insert()");
    expect((await remove(admin.cli, f.bob.id, asked)).status).toBeGreaterThanOrEqual(400);
    expect((await rows("SELECT approved_at IS NOT NULL AS approved, consumed_at FROM approval_intents WHERE id = $1", [asked]))[0])
      .toEqual({ approved: true, consumed_at: null });
    await ctx.db.query("DROP TRIGGER fail_removal_insert ON membership_removals");
    expect((await remove(admin.cli, f.bob.id, asked)).status).toBe(200);
  });

  it("refuses a malformed Varlatch-Approval header once an approval is needed, without asking for one", async () => {
    invalid(await inviteAs(admin.cli, "Zoe", "admin", "invalid"), "not-found");
    invalid(await setRole(admin.cli, f.dave.id, "admin", "invalid"), "not-found");
    invalid(await remove(admin.cli, f.bob.id, "invalid"), "not-found");
    expect(await intents()).toBe(0);
  });

  it("lets ApprovalNeeded escape the role change's serializable transaction without a retry", async () => {
    const requester: Requester = { identityId: admin.id, identityKind: "human", credentialId: admin.cliId, credentialKind: "cli" };
    const query = vi.spyOn(ctx.db, "query");
    const run = withApproval(ctx, { requester, approvalId: null, publicUrl: PUBLIC_URL }, (gate) => changeMemberRole(ctx, gate, orgId, f.dave.id, "admin"));
    await expect(run).rejects.toMatchObject({ code: "STEP_UP_REQUIRED" });
    const begins = query.mock.calls.filter(([sql]) => typeof sql === "string" && sql.startsWith("BEGIN ISOLATION LEVEL SERIALIZABLE"));
    query.mockRestore();
    expect(begins).toHaveLength(1);
    expect(await rows("SELECT operation FROM approval_intents")).toEqual([{ operation: "member.promote" }]);
  });

  it("is turned off by the operator's reset, which closes the open approvals of these operations", async () => {
    const asked = [
      stepUp(await inviteAs(admin.cli, "Zoe", "admin")),
      stepUp(await setRole(admin.cli, f.dave.id, "admin")),
      stepUp(await setRole(admin.cli, f.carol.id, "member")),
      stepUp(await remove(admin.cli, f.bob.id)),
    ];
    const outcome = await resetControls(ctx, { organization: "acme", controls: ["admin-step-up"] });
    expect(outcome.approvalsClosed).toBe(4);
    expect(await rows("SELECT id, close_reason FROM approval_intents ORDER BY id")).toEqual(
      asked.map((a) => a.id).sort().map((id) => ({ id, close_reason: "reset" })),
    );
    expect((await setRole(admin.cli, f.dave.id, "admin")).status).toBe(200);
  });

  it("the incident freeze: promotion and an admin invitation answer it first; removal and demotion are recovery and still ask", async () => {
    expect(OPERATIONS_DURING_FREEZE.has("member.remove")).toBe(true);
    expect(OPERATIONS_DURING_FREEZE.has("member.demote")).toBe(true);
    expect(OPERATIONS_DURING_FREEZE.has("member.promote")).toBe(false);
    expect(OPERATIONS_DURING_FREEZE.has("member.invite_admin")).toBe(false);
    const pending = await approved(admin, await setRole(admin.cli, f.dave.id, "admin"));
    expect((await call("POST", `${ORG}/incident-freeze`, admin.cli, { reason: "A CI token leaked" })).status).toBe(201);
    expect((await rows("SELECT close_reason FROM approval_intents WHERE id = $1", [pending]))[0].close_reason).toBe("frozen");

    const before = await intents();
    expect((await setRole(admin.cli, f.dave.id, "admin")).body.error.code).toBe("ORGANIZATION_FROZEN");
    expect((await setRole(admin.cli, f.dave.id, "admin", pending)).body.error.code).toBe("ORGANIZATION_FROZEN");
    expect((await inviteAs(admin.cli, "Zoe", "admin")).body.error.code).toBe("ORGANIZATION_FROZEN");
    expect(await intents()).toBe(before);

    // Recovery: demoting Carol and removing Bob are allowed while frozen, and admin-step-up still asks for both.
    const demote = stepUp(await setRole(admin.cli, f.carol.id, "member"));
    expect(demote.operation).toBe("member.demote");
    await approve(admin, demote.id);
    expect((await setRole(admin.cli, f.carol.id, "member", demote.id)).status).toBe(200);
    const removal = stepUp(await remove(admin.cli, f.bob.id));
    expect(removal.operation).toBe("member.remove");
    await approve(admin, removal.id);
    expect((await remove(admin.cli, f.bob.id, removal.id)).status).toBe(200);
    // Leaving stays exempt, frozen or not.
    expect((await remove(f.dave.cli, "me")).status).toBe(200);
    expect(await roleOf(f.carol.id)).toEqual({ role: "member", removed: false });
    expect(await roleOf(f.bob.id)).toEqual({ role: "member", removed: true });
  });
});
