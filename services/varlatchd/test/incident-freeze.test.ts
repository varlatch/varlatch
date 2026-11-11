// SPDX-License-Identifier: AGPL-3.0-or-later
import { createSign, generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { clearJwksCache } from "../src/auth/oidc.js";
import { generateKey } from "../src/crypto/aead.js";
import { createApproval } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { captureExercise } from "../src/domain/capabilities.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { getEnvironment } from "../src/domain/environments.js";
import { freezeOrganization, operatorUnfreeze, parseUnfreezeArgs, unfreezeReportLines } from "../src/domain/freeze.js";
import { completeRegistration } from "../src/domain/githubapps.js";
import { lockLiveScope } from "../src/domain/liveness.js";
import { runDueDeletions } from "../src/domain/orgdeletion.js";
import { getOrganization } from "../src/domain/orgs.js";
import { getProject } from "../src/domain/projects.js";
import { captureState, inSnapshot } from "../src/domain/retrieval.js";
import { resetControls, resetReportLines } from "../src/domain/securitycontrols.js";
import { reconcileTarget } from "../src/domain/syncdelivery.js";
import { deliverWebhooksOnce } from "../src/domain/webhooks.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { checkTrace } from "./helpers/lock-trace.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * The incident freeze (ADR-0055), on PGlite under the lock-order check
 * (lock-trace.ts enforces freezeOrganization, liftFreeze and
 * operatorUnfreeze): freezing and lifting, the approval the lift always
 * needs, the host operator's lift, what is refused and what passes under a
 * named exception, the deletion freeze alongside, the workers (sync,
 * deletion, webhooks), the Convex token and the refusals' audit. Races
 * with the freeze, a snapshot that began before it, and the end-to-end
 * lift from signed out (Better Auth) run on real PostgreSQL in
 * incident-freeze-postgres.test.ts. Every route's exception:
 * organization-entry.test.ts.
 */

const ORG = "/v1/organizations/acme";
const FREEZE = `${ORG}/incident-freeze`;
const E = `${ORG}/projects/api/environments/development`;

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let orgId: string;
let admin: Person;

interface Person {
  id: string;
  cli: string;
  web: string;
  key: SoftAuthenticator;
}

type Answer = { status: number; body: any; headers: Headers };

async function call(method: string, path: string, token: string, body?: unknown, headers: Record<string, string> = {}): Promise<Answer> {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null, headers: res.headers };
}

async function ok(method: string, path: string, token: string, body?: unknown, status?: number) {
  const res = await call(method, path, token, body);
  expect(res.status, `${method} ${path}: ${JSON.stringify(res.body)}`).toBe(status ?? (method === "POST" ? 201 : method === "DELETE" ? 204 : 200));
  return res.body;
}

const rows = async (sql: string, params: unknown[] = []) => (await ctx.db.query(sql, params)).rows as any[];
const parse = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v) as Record<string, any>;

async function events(eventType: string) {
  return (await rows("SELECT actor_identity_id, credential_id, organization_id, resource, metadata FROM audit_events WHERE event_type = $1 ORDER BY event_order", [eventType]))
    .map((r) => ({ actor: r.actor_identity_id, credential: r.credential_id, org: r.organization_id, resource: parse(r.resource), metadata: parse(r.metadata) }));
}

const frozenRefusals = async () => (await events("authorization.denied")).filter((e) => e.metadata?.reason === "organization_frozen");

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
  return { id: identityId, cli: cli.token, web: web.token, key };
}

async function invite(name: string, role: "admin" | "member", organizationId = orgId): Promise<Person> {
  const grant = await issueInviteGrant(ctx, { organizationId, role, name }, admin.id);
  const { identityId } = await consumeSetupGrant(ctx, grant.token, {});
  return person(identityId);
}

/** A machine identity of acme with these actions Organization-wide. */
async function machine(name: string, actions: string[], kind = "service") {
  const created = await ok("POST", `${ORG}/identities`, admin.cli, { name, kind });
  await ok("POST", `${ORG}/grants`, admin.cli, { subjectIdentityId: created.id, scope: { kind: "organization" }, actions });
  return { id: created.id as string, token: created.credential as string };
}

const freeze = (token = admin.cli, reason = "A CI token leaked") => call("POST", FREEZE, token, { reason });

async function frozen(token = admin.cli): Promise<string> {
  const res = await freeze(token);
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return res.body.id as string;
}

/** Approve in the dashboard: start, sign the challenge, approve. */
async function approve(p: Person, approvalId: string, token = p.web) {
  const started = await call("POST", `/v1/me/approvals/${approvalId}/options`, token);
  expect(started.status, JSON.stringify(started.body)).toBe(200);
  return call("POST", `/v1/me/approvals/${approvalId}/approve`, token, {
    assertion: p.key.assert(started.body.publicKey.challenge, { userVerified: true }),
  });
}

const lift = (token: string, freezeId: string, approval?: string) =>
  call("POST", `${FREEZE}/${freezeId}/lift`, token, undefined, approval ? { "Varlatch-Approval": approval } : {});

/** The whole lift by approval: STEP_UP_REQUIRED, approve, repeat. */
async function liftByApproval(p: Person, freezeId: string, token = p.cli) {
  const asked = await lift(token, freezeId);
  expect(asked.status, JSON.stringify(asked.body)).toBe(403);
  expect(asked.body.error.code).toBe("STEP_UP_REQUIRED");
  const approval = asked.body.error.details.approval;
  expect((await approve(p, approval.id)).status).toBe(200);
  const done = await lift(token, freezeId, approval.id);
  expect(done.status, JSON.stringify(done.body)).toBe(200);
  return { done: done.body, approval };
}

const expectFrozen = (res: Answer) => {
  expect(res.status, JSON.stringify(res.body)).toBe(409);
  expect(res.body.error.code).toBe("ORGANIZATION_FROZEN");
};

async function domainError(run: Promise<unknown>): Promise<string> {
  try {
    await run;
  } catch (err) {
    return (err as { code?: string }).code ?? String(err);
  }
  return "ok";
}

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const { identityId } = await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" });
  app = buildApp(ctx, { publicUrl: PUBLIC_URL, clientAddress: () => "203.0.113.7" });
  admin = await person(identityId);
  orgId = (await ok("POST", "/v1/organizations", admin.cli, { name: "Acme", slug: "acme" })).id;
  await ok("POST", `${ORG}/projects`, admin.cli, { name: "API", slug: "api", contractAuthority: "git" });
  await ok("POST", `${ORG}/projects/api/environments`, admin.cli, { name: "development", tier: "development" });
  await ok("PUT", `${E}/values/DATABASE_URL`, admin.cli, { value: "postgres://dev-db/main" }, 200);
});
afterEach(async () => {
  await ctx.close();
});

describe("freezing", () => {
  it("is advertised, audited without the reason, shown to members, and only one is open", async () => {
    expect((await call("GET", "/v1/meta", admin.cli)).body.capabilities).toContain("organizations.incident-freeze");
    const member = await invite("Member", "member");
    const id = await frozen();
    expect(id).toMatch(/^ofz_/);
    const state = await ok("GET", FREEZE, member.cli);
    expect(state.freeze).toMatchObject({ id, reason: "A CI token leaked", frozenBy: { id: admin.id, name: "Admin" }, liftedAt: null });
    expect(state.history.map((f: { id: string }) => f.id)).toEqual([id]);
    expect((await ok("GET", ORG, member.cli)).incidentFreeze).toMatchObject({ id, reason: "A CI token leaked" });
    expect(await events("organization.frozen")).toEqual([
      { actor: admin.id, credential: expect.any(String), org: orgId, resource: { freezeId: id }, metadata: { freezeId: id, reasonGiven: true, approvalsClosed: 0 } },
    ]);
    expect(JSON.stringify(await rows("SELECT * FROM audit_events"))).not.toContain("CI token leaked");
    const again = await freeze();
    expect(again.status).toBe(409);
    expect(again.body.error.code).toBe("STATE_CHANGED");
  });

  it("needs organization.manage and a person's credential; the reason is 1 to 200 characters", async () => {
    const member = await invite("Member", "member");
    expect((await freeze(member.cli)).status).toBe(403);
    const bot = await machine("bot", ["organization.manage"]);
    const byBot = await freeze(bot.token);
    expect(byBot.status).toBe(403);
    expect(byBot.body.error.details).toEqual({ reason: "machine-credential" });
    expect((await freeze(admin.cli, "   ")).status).toBe(422);
    expect((await freeze(admin.cli, "x".repeat(201))).status).toBe(422);
    expect(await rows("SELECT id FROM organization_freezes")).toEqual([]);
  });

  it("closes every open Approval Intent of the Organization", async () => {
    await ok("PATCH", `${ORG}/security/controls/admin-step-up`, admin.cli, { mode: "report", expectedVersion: 0 }, 200);
    const asked = await call("PATCH", `${ORG}/security/controls/admin-step-up`, admin.cli, { mode: "off", expectedVersion: 1 });
    expect(asked.body.error.code).toBe("STEP_UP_REQUIRED");
    const intent = asked.body.error.details.approval.id as string;
    expect((await approve(admin, intent)).status).toBe(200);
    await frozen();
    const view = await ok("GET", `/v1/me/approvals/${intent}`, admin.web);
    expect(view).toMatchObject({ state: "closed", closeReason: "frozen" });
    expect((await events("organization.frozen"))[0]!.metadata.approvalsClosed).toBe(1);
    // Approved before the freeze, it can never be used after it.
    const used = await call("PATCH", `${ORG}/security/controls/admin-step-up`, admin.cli, { mode: "off", expectedVersion: 1 }, { "Varlatch-Approval": intent });
    expect(used.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "closed" } });
  });
});

describe("lifting with an approval", () => {
  it("always asks a step-up approval, bound to the freeze, then lifts; any admin may lift", async () => {
    const other = await invite("Other admin", "admin");
    const id = await frozen();
    const { done, approval } = await liftByApproval(other, id);
    expect(approval).toMatchObject({ operation: "organization.unfreeze", organization: { slug: "acme" } });
    expect(approval.summary.title).toBe("Lift the incident freeze of Acme");
    expect(done.freeze).toMatchObject({ id, liftMethod: "approval", liftedBy: { id: other.id } });
    expect(done.resumingTargets).toEqual([]);
    const [unfrozen] = await events("organization.unfrozen");
    expect(unfrozen).toMatchObject({ actor: other.id, org: orgId, resource: { freezeId: id } });
    expect(unfrozen!.metadata).toMatchObject({ freezeId: id, method: "approval", approvalId: approval.id, approvalUserVerified: true, targetsResuming: 0 });
    expect(typeof unfrozen!.metadata.durationSeconds).toBe("number");
    // Writes work again; the lift undid nothing.
    await ok("PUT", `${E}/values/PORT`, admin.cli, { value: "8080" }, 200);
    expect((await ok("GET", FREEZE, admin.cli)).freeze).toBeNull();
    expect((await ok("GET", ORG, admin.cli)).incidentFreeze).toBeNull();
  });

  it("is refused for a machine, with another person's approval, and with an approval for an earlier freeze", async () => {
    const other = await invite("Other admin", "admin");
    const bot = await machine("bot", ["organization.manage"]);
    const first = await frozen();
    const byBot = await lift(bot.token, first);
    expect(byBot.status).toBe(403);
    expect(byBot.body.error.details).toEqual({ reason: "machine-credential" });
    // The admin's approval, presented by another admin.
    const asked = await lift(admin.cli, first);
    const theirs = asked.body.error.details.approval.id as string;
    expect((await approve(admin, theirs)).status).toBe(200);
    const stolen = await lift(other.cli, first, theirs);
    expect(stolen.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "not-found" } });
    // Lifted by the other admin; frozen again: the first approval cannot lift the second freeze.
    await liftByApproval(other, first);
    const second = await frozen();
    const reused = await lift(admin.cli, second, theirs);
    expect(reused.body.error.code).toBe("APPROVAL_INVALID");
    expect((await lift(admin.cli, first)).body.error.code).toBe("STATE_CHANGED");
    expect((await lift(admin.cli, "ofz_nope")).status).toBe(404);
    expect((await ok("GET", FREEZE, admin.cli)).freeze.id).toBe(second);
  });

  it("is refused without organization.manage", async () => {
    const member = await invite("Member", "member");
    const id = await frozen();
    expect((await lift(member.cli, id)).status).toBe(403);
  });
});

describe("Approval Intents while frozen", () => {
  it("refuses an Organization-bound intent for another operation; the lift's and a control change's work", async () => {
    await ok("PATCH", `${ORG}/security/controls/admin-step-up`, admin.cli, { mode: "report", expectedVersion: 0 }, 200);
    await frozen();
    const requester = {
      identityId: admin.id,
      identityKind: "human",
      credentialId: (await rows("SELECT id FROM credentials WHERE identity_id = $1 AND kind = 'cli'", [admin.id]))[0].id,
      credentialKind: "cli",
    };
    const other = createApproval(ctx, requester, {
      // Any operation outside the lift and recovery, bound to the Organization.
      operation: "passkey.remove",
      organizationId: orgId,
      target: { passkeyId: "pk" },
      body: {},
      query: {},
      expectedVersion: null,
      summary: { title: "x", changes: [] },
    }, PUBLIC_URL);
    expect(await domainError(other)).toBe("ORGANIZATION_FROZEN");
    // A control change is recovery: its approval is created, given and used.
    const asked = await call("PATCH", `${ORG}/security/controls/admin-step-up`, admin.cli, { mode: "off", expectedVersion: 1 });
    expect(asked.body.error.code).toBe("STEP_UP_REQUIRED");
    const intent = asked.body.error.details.approval.id as string;
    expect((await approve(admin, intent)).status).toBe(200);
    const changed = await call("PATCH", `${ORG}/security/controls/admin-step-up`, admin.cli, { mode: "off", expectedVersion: 1 }, { "Varlatch-Approval": intent });
    expect(changed.status, JSON.stringify(changed.body)).toBe(200);
  });
});

describe("the host operator", () => {
  it("lifts with admin unfreeze: no actor, open lift approvals closed; the reset never lifts", async () => {
    await ok("PATCH", `${ORG}/security/controls/admin-step-up`, admin.cli, { mode: "report", expectedVersion: 0 }, 200);
    const id = await frozen();
    const asked = await lift(admin.cli, id);
    const pending = asked.body.error.details.approval.id as string;

    const reset = await resetControls(ctx, { organization: "acme", controls: "all" });
    expect(reset.stillFrozen).toBe(true);
    expect(resetReportLines(reset).at(-1)).toContain("acme is still frozen for an incident: a reset never lifts a freeze");
    expect((await ok("GET", FREEZE, admin.cli)).freeze.id).toBe(id);

    expect(await domainError(operatorUnfreeze(ctx, { organization: "acme", confirm: "acm" }))).toBe("VALIDATION_FAILED");
    const outcome = await operatorUnfreeze(ctx, { organization: "acme", confirm: "acme" });
    expect(outcome).toMatchObject({ organization: { slug: "acme" }, approvalsClosed: 1, deletionPending: false, freeze: { id, liftMethod: "operator", liftedBy: null } });
    expect(unfreezeReportLines(outcome)[0]).toBe(`Incident freeze of acme [${orgId}] lifted by the host operator.`);
    expect(await ok("GET", `/v1/me/approvals/${pending}`, admin.web)).toMatchObject({ state: "closed", closeReason: "reset" });
    const [unfrozen] = await events("organization.unfrozen");
    expect(unfrozen).toMatchObject({ actor: null, resource: { freezeId: id } });
    expect(unfrozen!.metadata).toMatchObject({ method: "operator", operator: true, approvalsClosed: 1 });
    expect(await domainError(operatorUnfreeze(ctx, { organization: "acme", confirm: "acme" }))).toBe("STATE_CHANGED");
    const after = await resetControls(ctx, { organization: "acme", controls: "all" });
    expect(after.stillFrozen).toBe(false);
  });

  it("parses admin unfreeze's arguments", () => {
    expect(parseUnfreezeArgs(["--org", "acme", "--confirm", "acme", "--json"])).toEqual({ organization: "acme", confirm: "acme", json: true });
    expect(parseUnfreezeArgs(["--org", "acme"])).toHaveProperty("error");
    expect(parseUnfreezeArgs(["--org", "acme", "--confirm", "acme", "--all"])).toHaveProperty("error");
  });
});

describe("refusals", () => {
  it("refuses a member's reads and writes with Retry-After, audited once each; an outsider gets the usual answer", async () => {
    const member = await invite("Member", "member");
    await ok("POST", `${ORG}/grants`, admin.cli, { subjectIdentityId: member.id, scope: { kind: "organization" }, actions: ["config.value.read", "config.metadata.read"] });
    const outsider = await invite("Outsider", "member", (await ok("POST", "/v1/organizations", admin.cli, { name: "Beta", slug: "beta" })).id);
    const outsiderBefore = await call("GET", `${ORG}/projects`, outsider.cli);
    const id = await frozen();

    const read = await call("GET", `${E}/effective-configuration`, member.cli);
    expectFrozen(read);
    expect(read.headers.get("Retry-After")).toBe("300");
    expect(read.body.error.details).toEqual({ freezeId: id, frozenAt: expect.any(String) });
    expect(read.body.error.message).toMatch(/^This Organization is frozen for an incident since .+\. Nothing was read, changed or sent\. An Organization Admin can lift the freeze with a passkey approval\.$/);
    expectFrozen(await call("PUT", `${E}/values/PORT`, admin.cli, { value: "1" }));
    expectFrozen(await call("GET", `${ORG}/projects`, admin.cli));

    const refusals = await frozenRefusals();
    expect(refusals).toHaveLength(3);
    expect(refusals[0]).toMatchObject({ actor: member.id, org: orgId, resource: { freezeId: id }, metadata: { reason: "organization_frozen", freezeId: id, method: "GET" } });
    expect(refusals[0]!.credential).not.toBeNull();

    const outsiderDuring = await call("GET", `${ORG}/projects`, outsider.cli);
    expect(outsiderDuring.status).toBe(outsiderBefore.status);
    expect(outsiderDuring.body.error.code).toBe(outsiderBefore.body.error.code);
    expect(await frozenRefusals()).toHaveLength(3);
  });

  it("refuses effective configuration, disclosure, retrieval, validation and exercise, at entry and in the snapshot", async () => {
    const bot = await machine("bot", ["config.value.read", "config.metadata.read", "secret.reveal"]);
    await frozen();
    expectFrozen(await call("GET", `${E}/effective-configuration`, bot.token));
    expectFrozen(await call("POST", `${E}/disclosures`, bot.token, { items: ["DATABASE_URL"] }));
    expectFrozen(await call("POST", `${E}/retrievals`, bot.token, { mode: "strict" }));
    expectFrozen(await call("POST", `${E}/validate`, bot.token, { items: { DATABASE_URL: "x" } }));
    expectFrozen(await call("POST", `${E}/capabilities/cap_x/exercises`, bot.token, {}));
    // In the snapshot, for a path that resolved its Organization another way.
    const org = await getOrganization(ctx, "acme");
    const project = await getProject(ctx, org.id, "api");
    const env = await getEnvironment(ctx, project.id, "development");
    expect(await domainError(inSnapshot(ctx, (sctx, now) => captureState(sctx, { org, project, env }, now, () => true)))).toBe("ORGANIZATION_FROZEN");
    expect(await domainError(inSnapshot(ctx, (sctx, now) => captureExercise(sctx, { org, project, env }, now, "cap_x", null)))).toBe("ORGANIZATION_FROZEN");
    expect(await frozenRefusals()).toHaveLength(5);
  });

  it("lets recovery through: revoking a Grant, a credential, retiring, removing a member, a new Requirement, cancelling", async () => {
    const member = await invite("Member", "member");
    const bot = await machine("bot", ["config.metadata.read"]);
    const grant = (await ok("GET", `${ORG}/grants`, admin.cli)).items.find((g: { subjectIdentityId: string }) => g.subjectIdentityId === bot.id);
    const other = await machine("other", ["config.metadata.read"]);
    await frozen();
    await ok("DELETE", `${ORG}/grants/${grant.id}`, admin.cli);
    const creds = await ok("GET", `${ORG}/identities/${other.id}/credentials`, admin.cli);
    await ok("DELETE", `${ORG}/identities/${other.id}/credentials/${creds.items[0].id}`, admin.cli);
    await ok("POST", `${ORG}/identities/${bot.id}/retire`, admin.cli, undefined, 200);
    await ok("POST", `${ORG}/requirements`, admin.cli, { kind: "tailnet", target: { kind: "tier", tier: "production" }, selector: { tailnet: "example.ts.net", tags: ["tag:prod"] } });
    await ok("DELETE", `${ORG}/members/${member.id}`, admin.cli, undefined, 200);
    // Not recovery: refused.
    expectFrozen(await call("POST", `${ORG}/grants`, admin.cli, { subjectIdentityId: other.id, scope: { kind: "organization" }, actions: ["config.metadata.read"] }));
    expectFrozen(await call("POST", `${ORG}/identities`, admin.cli, { name: "new", kind: "service" }));
    expectFrozen(await call("POST", `${ORG}/webhooks`, admin.cli, { url: "https://sink.example/hook" }));
  });
});

describe("with Organization deletion", () => {
  it("freezes during a pending deletion; scheduling and approving are refused while frozen, cancelling passes", async () => {
    const second = await invite("Second admin", "admin");
    const scheduled = await ok("POST", `${ORG}/deletion`, admin.cli, {});
    expect(scheduled.approvalRequired).toBe(true);
    const id = await frozen();
    expectFrozen(await call("POST", `${ORG}/deletion/${scheduled.id}/approve`, second.cli));
    await ok("POST", `${ORG}/deletion/${scheduled.id}/cancel`, admin.cli, undefined, 200);
    expectFrozen(await call("POST", `${ORG}/deletion`, admin.cli, {}));
    await liftByApproval(admin, id);
    await ok("POST", `${ORG}/deletion`, admin.cli, {});
  });

  it("lifts while a deletion stays pending, by approval and by admin unfreeze; the deletion freeze still refuses writes", async () => {
    await ok("POST", `${ORG}/deletion`, admin.cli, {});
    const first = await frozen();
    expectFrozen(await call("PUT", `${E}/values/PORT`, admin.cli, { value: "1" }));
    await liftByApproval(admin, first);
    const write = await call("PUT", `${E}/values/PORT`, admin.cli, { value: "1" });
    expect(write.body.error.code).toBe("ORGANIZATION_DELETING");
    await frozen();
    const outcome = await operatorUnfreeze(ctx, { organization: "acme", confirm: "acme" });
    expect(outcome.deletionPending).toBe(true);
    expect(unfreezeReportLines(outcome)).toContain("A deletion of this Organization is still pending: writes stay refused until it is cancelled.");
    expect((await call("PUT", `${E}/values/PORT`, admin.cli, { value: "1" })).body.error.code).toBe("ORGANIZATION_DELETING");
  });

  it("the worker skips a frozen Organization and runs after the lift", async () => {
    const scheduled = await ok("POST", `${ORG}/deletion`, admin.cli, { afterDays: 1 });
    const id = await frozen();
    await ctx.db.query("UPDATE organization_deletions SET scheduled_at = now() - interval '2 days', run_after = now() - interval '1 second' WHERE id = $1", [scheduled.id]);
    expect(await runDueDeletions(ctx)).toEqual([]);
    expect((await rows("SELECT deleted_at FROM organizations WHERE id = $1", [orgId]))[0].deleted_at).toBeNull();
    await liftByApproval(admin, id);
    expect((await runDueDeletions(ctx)).map((d) => d.organizationId)).toEqual([orgId]);
    // The freeze rows stay with the tombstone.
    expect(await rows("SELECT id FROM organization_freezes WHERE organization_id = $1", [orgId])).toEqual([{ id }]);
  });
});

describe("outside /v1/organizations/:org", () => {
  it("refuses invitation acceptance, the GitHub App callback and agent-run issuance", async () => {
    const grant = await issueInviteGrant(ctx, { organizationId: orgId, role: "member", name: "Late" }, admin.id);
    const agent = await ok("POST", `${ORG}/identities`, admin.cli, { name: "agent", kind: "agent" });
    const broker = await ok("POST", `${ORG}/identities`, admin.cli, { name: "broker", kind: "broker" });
    const id = await frozen();
    // The person accepting is not a member yet: the invitation is refused
    // like a dead one, as during a deletion, and nothing tells them why.
    expect(await domainError(consumeSetupGrant(ctx, grant.token, {}))).toBe("INVALID_CREDENTIAL");
    const org = await getOrganization(ctx, "acme");
    expect(await domainError(completeRegistration(ctx, org, { state: "s", code: "c" }, admin.id))).toBe("ORGANIZATION_FROZEN");
    expectFrozen(await call("POST", `${ORG}/identities/${agent.id}/credentials`, broker.credential, { ttlSeconds: 60 }));
    // Not consumed: it works after the lift.
    await liftByApproval(admin, id);
    expect(await domainError(consumeSetupGrant(ctx, grant.token, {}))).toBe("ok");
  });

  it("refuses the OIDC exchange", async () => {
    clearJwksCache();
    const issuer = "https://ci.example";
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const jwk = { ...(publicKey.export({ format: "jwk" }) as Record<string, string>), kid: "k1", alg: "RS256", use: "sig" };
    const oidcFetch = (async (url: unknown) => {
      const u = String(url);
      if (u === `${issuer}/.well-known/openid-configuration`) return Response.json({ issuer, jwks_uri: `${issuer}/jwks` });
      if (u === `${issuer}/jwks`) return Response.json({ keys: [jwk] });
      return new Response(null, { status: 404 });
    }) as typeof fetch;
    app = buildApp(ctx, { publicUrl: PUBLIC_URL, oidcFetch });
    const ci = await ok("POST", `${ORG}/identities`, admin.cli, { name: "gh", kind: "ci" });
    await ok("POST", `${ORG}/identities/${ci.id}/oidc-bindings`, admin.cli, { issuer, audience: "varlatch", subject: "repo:acme/api" });
    const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const now = Math.floor(Date.now() / 1000);
    const head = `${b64({ alg: "RS256", typ: "JWT", kid: "k1" })}.${b64({ iss: issuer, aud: "varlatch", sub: "repo:acme/api", iat: now, exp: now + 300 })}`;
    const signer = createSign("RSA-SHA256");
    signer.update(head);
    const token = `${head}.${signer.sign(privateKey).toString("base64url")}`;
    const exchange = () => app.request("/v1/oidc/token", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ organization: "acme", token }) });
    expect((await exchange()).status).toBe(201);
    await frozen();
    const res = await exchange();
    expect(res.status).toBe(409);
    expect(((await res.json()) as any).error.code).toBe("ORGANIZATION_FROZEN");
    expect((await frozenRefusals()).map((r) => r.actor)).toEqual([null]);
  });

  it("leaves the frozen Organization out of the Convex token, for a person and a machine", async () => {
    const bot = await machine("bot", ["organization.read"]);
    const beta = (await ok("POST", "/v1/organizations", admin.cli, { name: "Beta", slug: "beta" })).id as string;
    const orgIdsOf = async (token: string) => {
      const minted = await ok("POST", "/v1/tokens/convex", token, undefined, 200);
      return (JSON.parse(Buffer.from(minted.token.split(".")[1], "base64url").toString()) as { orgIds: string[] }).orgIds.sort();
    };
    expect(await orgIdsOf(admin.cli)).toEqual([orgId, beta].sort());
    expect(await orgIdsOf(bot.token)).toEqual([orgId]);
    await frozen();
    expect(await orgIdsOf(admin.cli)).toEqual([beta]);
    expect(await orgIdsOf(bot.token)).toEqual([]);
  });
});

describe("workers", () => {
  /** A fake Coolify: records each request; GETs list nothing. */
  function coolify(onFirst?: () => Promise<void>) {
    const calls: string[] = [];
    let first = true;
    const fetchImpl = (async (input: unknown, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      calls.push(`${method} ${String(input)}`);
      if (first && onFirst) {
        first = false;
        await onFirst();
      }
      if (method === "GET") return new Response("[]", { status: 200 });
      return new Response(JSON.stringify({ uuid: "env1" }), { status: 201 });
    }) as typeof fetch;
    return { fetchImpl, calls };
  }

  async function targets() {
    const connection = await ok("POST", `${ORG}/platform-connections`, admin.cli, {
      platform: "coolify", baseIdentity: "https://coolify.example.com", name: "coolify", credential: "coolify-token",
    });
    const make = async (uuid: string) => (await ok("POST", `${E}/sync-targets`, admin.cli, {
      connectionId: connection.id, destination: { applicationUuid: uuid }, mapping: { kind: "wildcard" },
    })).id as string;
    return { a: await make("app-a"), b: await make("app-b") };
  }

  const targetRow = async (id: string) =>
    (await rows("SELECT state, failure_count, needs_sync, revoked_at FROM sync_targets WHERE id = $1", [id]))[0];

  it("takes no lease while frozen; a paused Target stays paused after the lift, the others resume and are listed", async () => {
    const { a, b } = await targets();
    const id = await frozen();
    const fake = coolify();
    await reconcileTarget(ctx, a, { fetchImpl: fake.fetchImpl });
    expect(fake.calls).toEqual([]);
    expect(await targetRow(a)).toMatchObject({ state: "active", failure_count: 0, needs_sync: true });
    // Pausing is recovery; resuming is not.
    await ok("POST", `${E}/sync-targets/${b}/pause`, admin.cli, undefined, 200);
    expectFrozen(await call("POST", `${E}/sync-targets/${b}/resume`, admin.cli));
    const listed = await ok("GET", FREEZE, admin.cli);
    expect(listed.resumingTargets.map((t: { id: string }) => t.id)).toEqual([a]);
    const asked = await lift(admin.cli, id);
    expect(asked.body.error.details.approval.summary.changes).toEqual([
      { field: "freeze", from: "frozen", to: "lifted", loosens: true },
      { field: "Sync Target api/development (coolify)", from: "held", to: "resumes pushing", loosens: true },
    ]);
    const approval = asked.body.error.details.approval.id;
    await approve(admin, approval);
    const done = await lift(admin.cli, id, approval);
    expect(done.body.resumingTargets.map((t: { id: string }) => t.id)).toEqual([a]);
    await reconcileTarget(ctx, a, { fetchImpl: fake.fetchImpl });
    expect(fake.calls.length).toBeGreaterThan(0);
    expect((await targetRow(b)).state).toBe("paused");
  });

  it("stops a running run at its next send check, without counting a failure", async () => {
    const { a } = await targets();
    const fake = coolify(async () => {
      await freezeOrganization(ctx, {
        organizationId: orgId, actor: { id: admin.id, kind: "human" }, credentialKind: "cli", reason: "mid-run", requestId: "req_test", authorizeIn: async () => undefined,
      });
    });
    await reconcileTarget(ctx, a, { fetchImpl: fake.fetchImpl });
    // The first request (before the freeze committed) went out; nothing after it.
    expect(fake.calls.filter((c) => !c.startsWith("GET"))).toEqual([]);
    expect(await targetRow(a)).toMatchObject({ state: "active", failure_count: 0, needs_sync: true });
  });

  it("webhooks deliver during the freeze, organization.frozen included", async () => {
    await ok("POST", `${ORG}/webhooks`, admin.cli, { url: "https://sink.example/hook" });
    await frozen();
    expectFrozen(await call("GET", `${E}/effective-configuration`, admin.cli));
    const delivered: string[] = [];
    await deliverWebhooksOnce(ctx, (async (_url: unknown, init?: RequestInit) => {
      delivered.push(...(String(init?.body ?? "").match(/"eventType":"[a-z_.]+"/g) ?? []));
      return new Response(null, { status: 204 });
    }) as typeof fetch);
    expect(delivered).toContain('"eventType":"organization.frozen"');
    expect(delivered).toContain('"eventType":"authorization.denied"');
  });
});

describe("lock order (ADR-0054 amendment E)", () => {
  it("a writer refused while frozen takes only the Organization row, in order", async () => {
    await frozen();
    const db = ctx.db;
    await db.query("BEGIN");
    try {
      expect(await domainError(lockLiveScope(db, { organizationId: orgId, people: [admin.id], projectId: "prj_x" }))).toBe("ORGANIZATION_FROZEN");
      const trace = (await db.query(
        "SELECT seq::int AS seq, tbl, key, mode, kind FROM varlatch_lock_trace.trace WHERE txid = txid_current() ORDER BY seq",
      )).rows as Parameters<typeof checkTrace>[0];
      expect(trace.map((r) => [r.tbl, r.key, r.mode])).toEqual([["organizations", orgId, "key share"]]);
      expect(checkTrace(trace)).toEqual([]);
    } finally {
      await db.query("ROLLBACK");
    }
  });
});
