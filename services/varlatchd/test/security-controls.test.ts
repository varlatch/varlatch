// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { withTx } from "../src/db/tx.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import {
  APPROVALS,
  approvalHash,
  canonicalJson,
  consumeApproval,
  type ApprovalBinding,
  type Requester,
} from "../src/domain/approvals.js";

/**
 * Consumption as a protected operation does it: its requester locked FOR
 * UPDATE at step 2 first (domain/liveness.ts); consumeApproval takes no
 * person lock of its own, and the lock-order check holds it to that.
 */
const consumeAsOperation: typeof consumeApproval = async (db, key, requester, approvalId, binding) => {
  await lockPerson(db, requester.identityId, "update");
  return consumeApproval(db, key, requester, approvalId, binding);
};
import { lockPerson } from "../src/domain/personlocks.js";
import { classifyChange, parseResetArgs, resetControls, resetReportLines } from "../src/domain/securitycontrols.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * Security Controls and step-up approvals (ADR-0054 Decisions 1 to 4 and
 * 10), on PGlite: the controls API, loosening classification, the whole
 * approval lifecycle (creation, the person-only view, approval with a
 * trusted passkey and user verification, consumption bound to the exact
 * request, expiry on the live clock, bounds), passkey.remove under a
 * directly inserted enforce row, and the host operator's reset. The lock
 * order against protected writes runs on real PostgreSQL in
 * security-controls-postgres.test.ts.
 */

const ORG = "/v1/organizations/acme";
const CONTROLS = `${ORG}/security/controls`;

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let orgId: string;
let admin: Person;

interface Person {
  id: string;
  /** A CLI credential. */
  cli: string;
  cliId: string;
  /** A dashboard bearer for one Better Auth session. */
  web: string;
  webId: string;
  session: (sessionId: string) => Promise<string>;
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

const rows = async (sql: string, params: unknown[] = []) => (await ctx.db.query(sql, params)).rows as any[];

/** A person with a CLI credential, a dashboard session and a passkey (trusted unless said otherwise). */
/** A live Better Auth session of the person (registerSoftPasskey links their Better Auth user). */
async function betterAuthSession(identityId: string, sessionId: string) {
  await ctx.db.query(
    `INSERT INTO "session" (id, "expiresAt", token, "userId")
     SELECT $1, now() + interval '1 day', $1, better_auth_user_id FROM auth_user_links WHERE identity_id = $2
     ON CONFLICT (id) DO NOTHING`,
    [sessionId, identityId],
  );
}

async function person(identityId: string, trust: "trusted" | "unconfirmed" = "trusted"): Promise<Person> {
  const cli = await issueCredential(ctx.db, { identityId, kind: "cli", name: "test cli" });
  const key = await registerSoftPasskey(ctx.db, identityId, { ...RP, trust });
  const session = async (sessionId: string) => {
    await betterAuthSession(identityId, sessionId);
    return (await issueCredential(ctx.db, {
      identityId,
      kind: "browser",
      expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      authSessionId: sessionId,
    })).token;
  };
  await betterAuthSession(identityId, `session-${identityId}`);
  const web = await issueCredential(ctx.db, {
    identityId,
    kind: "browser",
    expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
    authSessionId: `session-${identityId}`,
  });
  return { id: identityId, cli: cli.token, cliId: cli.credentialId, web: web.token, webId: web.credentialId, session, key };
}

async function invite(name: string, role: "admin" | "member", trust: "trusted" | "unconfirmed" = "trusted"): Promise<Person> {
  const grant = await issueInviteGrant(ctx, { organizationId: orgId, role, name }, admin.id);
  const { identityId } = await consumeSetupGrant(ctx, grant.token, {});
  return person(identityId, trust);
}

const set = (token: string, control: string, body: Record<string, unknown>, approval?: string) =>
  call("PATCH", `${CONTROLS}/${control}`, token, body, approval ? { "Varlatch-Approval": approval } : {});

async function controlOf(control: string, token = admin.cli) {
  const res = await call("GET", CONTROLS, token);
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  return res.body.items.find((i: { control: string }) => i.control === control);
}

/** Approve in the dashboard: start, sign the challenge with `key`, approve. */
async function approve(p: Person, approvalId: string, opts: { key?: SoftAuthenticator; token?: string; userVerified?: boolean } = {}) {
  const token = opts.token ?? p.web;
  const started = await call("POST", `/v1/me/approvals/${approvalId}/options`, token);
  if (started.status !== 200) return started;
  return call("POST", `/v1/me/approvals/${approvalId}/approve`, token, {
    assertion: (opts.key ?? p.key).assert(started.body.publicKey.challenge, { userVerified: opts.userVerified ?? true }),
  });
}

/** Ask for a loosening change and return its pending approval. */
async function stepUp(token: string, control: string, body: Record<string, unknown>) {
  const res = await set(token, control, body);
  expect(res.status, JSON.stringify(res.body)).toBe(403);
  expect(res.body.error.code).toBe("STEP_UP_REQUIRED");
  return res.body.error.details.approval as { id: string; state: string; url: string; expiresAt: string; createdAt: string; summary: any; operation: string; organization: any; interval: number };
}

async function events(eventType: string) {
  const parse = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v) as Record<string, any>;
  return (await rows("SELECT actor_identity_id, organization_id, resource, metadata FROM audit_events WHERE event_type = $1 ORDER BY event_order", [eventType]))
    .map((r) => ({ actor: r.actor_identity_id, org: r.organization_id, resource: parse(r.resource), metadata: parse(r.metadata) }));
}

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const { identityId } = await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" });
  app = buildApp(ctx, { publicUrl: PUBLIC_URL, clientAddress: () => "203.0.113.7" });
  admin = await person(identityId);
  orgId = (await call("POST", "/v1/organizations", admin.cli, { name: "Acme", slug: "acme" })).body.id;
});
afterEach(async () => {
  await ctx.close();
});

describe("reading the controls", () => {
  it("lists all four off at version 0, offers off and report (and enforce where unlocked), and is advertised", async () => {
    expect((await call("GET", "/v1/meta", admin.cli)).body.capabilities).toContain("security.controls");
    const res = await call("GET", CONTROLS, admin.cli);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      availableModes: ["off", "report"],
      items: ["requirement-protection", "admin-step-up", "passkey-verification", "credential-lifetime"].map((control) => ({
        control, mode: "off", config: null, version: 0, changedAt: null, changedBy: null,
        availableModes: control === "requirement-protection" || control === "passkey-verification" ? ["off", "report", "enforce"] : ["off", "report"],
      })),
    });
  });

  it("is open to members, and not found for outsiders", async () => {
    const member = await invite("Member", "member");
    expect((await call("GET", CONTROLS, member.cli)).status).toBe(200);
    const outsider = await person((await consumeSetupGrant(ctx, (await issueInviteGrant(ctx, {
      organizationId: (await call("POST", "/v1/organizations", admin.cli, { name: "Other", slug: "other" })).body.id,
      role: "member",
      name: "Outsider",
    }, admin.id)).token, {})).identityId);
    expect((await call("GET", CONTROLS, outsider.cli)).status).toBe(404);
  });
});

describe("changing a control", () => {
  it("tightens without an approval and records security_control.changed", async () => {
    const res = await set(admin.cli, "requirement-protection", { mode: "report", expectedVersion: 0 });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body).toMatchObject({ changed: true, loosened: false, control: { control: "requirement-protection", mode: "report", version: 1, changedBy: { id: admin.id, name: "Admin" } } });
    expect(await rows("SELECT count(*)::int AS n FROM approval_intents")).toEqual([{ n: 0 }]);
    const [event] = await events("security_control.changed");
    expect(event).toMatchObject({
      actor: admin.id,
      org: orgId,
      resource: { control: "requirement-protection" },
      metadata: { control: "requirement-protection", fromMode: "off", fromVersion: 0, toMode: "report", toVersion: 1, loosened: false, loosenedFields: "", approvalId: null },
    });
  });

  it("refuses enforce for a control this release cannot enforce, with CONTROL_MODE_UNAVAILABLE, and stores nothing", async () => {
    const res = await set(admin.cli, "admin-step-up", { mode: "enforce", expectedVersion: 0 });
    expect(res.status).toBe(422);
    expect(res.body.error).toMatchObject({ code: "CONTROL_MODE_UNAVAILABLE", details: { control: "admin-step-up", mode: "enforce", availableModes: ["off", "report"] } });
    expect(await rows("SELECT count(*)::int AS n FROM security_controls")).toEqual([{ n: 0 }]);
    expect(await rows("SELECT count(*)::int AS n FROM approval_intents")).toEqual([{ n: 0 }]);
  });

  it("refuses a stale expectedVersion", async () => {
    expect((await set(admin.cli, "admin-step-up", { mode: "report", expectedVersion: 0 })).status).toBe(200);
    const res = await set(admin.cli, "admin-step-up", { mode: "report", expectedVersion: 0 });
    expect(res.status).toBe(409);
    expect(res.body.error).toMatchObject({ code: "VERSION_CONFLICT", details: { currentVersion: 1 } });
  });

  it("answers an unchanged request without recording anything", async () => {
    const res = await set(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 0 });
    expect(res.body).toMatchObject({ changed: false, loosened: false, control: { version: 0 } });
    expect(await events("security_control.changed")).toEqual([]);
  });

  it("validates the configuration", async () => {
    expect((await set(admin.cli, "admin-step-up", { mode: "report", config: { defaultTtlSeconds: 1, maxTtlSeconds: 2 }, expectedVersion: 0 })).status).toBe(422);
    expect((await set(admin.cli, "credential-lifetime", { mode: "report", config: { defaultTtlSeconds: 20, maxTtlSeconds: 10 }, expectedVersion: 0 })).status).toBe(422);
    expect((await set(admin.cli, "credential-lifetime", { mode: "report", expectedVersion: 0 })).status).toBe(422);
    expect((await set(admin.cli, "no-such-control", { mode: "report", expectedVersion: 0 })).status).toBe(404);
    expect((await set(admin.cli, "admin-step-up", { mode: "report", expectedVersion: 0, extra: 1 })).status).toBe(422);
  });

  it("needs organization.manage, and machine credentials can never change a control", async () => {
    const member = await invite("Member", "member");
    expect((await set(member.cli, "admin-step-up", { mode: "report", expectedVersion: 0 })).status).toBe(403);
    const machine = await call("POST", `${ORG}/identities`, admin.cli, { name: "deployer", kind: "service" });
    expect(machine.status).toBe(201);
    const granted = await call("POST", `${ORG}/grants`, admin.cli, {
      subjectIdentityId: machine.body.id, scope: { kind: "organization" }, actions: ["organization.manage", "organization.read"],
    });
    expect(granted.status, JSON.stringify(granted.body)).toBe(201);
    // Tightening and loosening alike; no approval is ever created for a machine.
    const tighten = await set(machine.body.credential, "admin-step-up", { mode: "report", expectedVersion: 0 });
    expect(tighten.status).toBe(403);
    expect(tighten.body.error.message).toMatch(/machine credentials never can/);
    expect((await set(admin.cli, "admin-step-up", { mode: "report", expectedVersion: 0 })).status).toBe(200);
    expect((await set(machine.body.credential, "admin-step-up", { mode: "off", expectedVersion: 1 })).status).toBe(403);
    expect(await rows("SELECT count(*)::int AS n FROM approval_intents")).toEqual([{ n: 0 }]);
    expect((await controlOf("admin-step-up")).mode).toBe("report");
  });
});

describe("loosening needs an approval", () => {
  beforeEach(async () => {
    expect((await set(admin.cli, "credential-lifetime", { mode: "report", config: { defaultTtlSeconds: 3600, maxTtlSeconds: 86_400 }, expectedVersion: 0 })).status).toBe(200);
    expect((await set(admin.cli, "admin-step-up", { mode: "report", expectedVersion: 0 })).status).toBe(200);
  });

  it("refuses report to off without one, from the CLI and the dashboard, and changes nothing", async () => {
    const fromCli = await stepUp(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    expect(fromCli).toMatchObject({
      operation: "security_control.change",
      state: "pending",
      organization: { id: orgId, slug: "acme", name: "Acme" },
      url: `${PUBLIC_URL}/approve/${fromCli.id}`,
      interval: 5,
      requestedBy: { credentialKind: "cli" },
      summary: { title: "Turn off the admin-step-up security control of Acme", changes: [{ field: "mode", from: "report", to: "off", loosens: true }] },
    });
    expect(Date.parse(fromCli.expiresAt) - Date.parse(fromCli.createdAt)).toBe(APPROVALS.cliLifetimeSeconds * 1000);
    const fromWeb = await stepUp(admin.web, "admin-step-up", { mode: "off", expectedVersion: 1 });
    expect(Date.parse(fromWeb.expiresAt) - Date.parse(fromWeb.createdAt)).toBe(APPROVALS.dashboardLifetimeSeconds * 1000);
    expect((await controlOf("admin-step-up")).mode).toBe("report");
    // A person without organization.manage gets a refusal, not an approval.
    const member = await invite("Member", "member");
    expect((await set(member.cli, "admin-step-up", { mode: "off", expectedVersion: 1 })).status).toBe(403);
    expect(await rows("SELECT count(*)::int AS n FROM approval_intents")).toEqual([{ n: 2 }]);
  });

  it("classifies field by field: a mixed edit with any weakening needs one, tightening the lifetimes does not", async () => {
    const mixed = await stepUp(admin.cli, "credential-lifetime", { config: { defaultTtlSeconds: 1800, maxTtlSeconds: 172_800 }, expectedVersion: 1 });
    expect(mixed.summary.changes).toEqual([
      { field: "defaultTtlSeconds", from: "3600", to: "1800", loosens: false },
      { field: "maxTtlSeconds", from: "86400", to: "172800", loosens: true },
    ]);
    const tighter = await set(admin.cli, "credential-lifetime", { config: { defaultTtlSeconds: 1800, maxTtlSeconds: 43_200 }, expectedVersion: 1 });
    expect(tighter.body).toMatchObject({ changed: true, loosened: false });
    // Clearing the configuration removes both bounds.
    expect((await set(admin.cli, "credential-lifetime", { mode: "off", expectedVersion: 2 })).status).toBe(403);
    const cleared = await stepUp(admin.cli, "credential-lifetime", { mode: "off", config: null, expectedVersion: 2 });
    expect(cleared.summary.changes.map((c: { field: string; loosens: boolean }) => [c.field, c.loosens])).toEqual([
      ["mode", true], ["defaultTtlSeconds", true], ["maxTtlSeconds", true],
    ]);
  });

  it("runs the whole lifecycle: approve with a trusted passkey, repeat with the header, used once", async () => {
    const approval = await stepUp(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    // The CLI polls it; the dashboard reads it.
    expect((await call("GET", `/v1/me/approvals/${approval.id}`, admin.cli)).body.state).toBe("pending");
    expect((await call("GET", `/v1/me/approvals/${approval.id}`, admin.web)).body.state).toBe("pending");
    // Before approval the header is refused as pending.
    const early = await set(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 }, approval.id);
    expect(early.status).toBe(409);
    expect(early.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "pending", approvalId: approval.id } });
    const approved = await approve(admin, approval.id);
    expect(approved.status, JSON.stringify(approved.body)).toBe(200);
    expect(approved.body).toMatchObject({ state: "approved", expiresAt: approval.expiresAt });
    const done = await set(admin.cli, "admin-step-up", { expectedVersion: 1, mode: "off" }, approval.id);
    expect(done.status, JSON.stringify(done.body)).toBe(200);
    expect(done.body).toMatchObject({ changed: true, loosened: true, control: { mode: "off", version: 2 } });
    const changed = (await events("security_control.changed")).at(-1)!;
    expect(changed.metadata).toMatchObject({
      fromMode: "report", toMode: "off", loosened: true, loosenedFields: "mode", approvalId: approval.id,
      approvalPasskeyId: admin.key.passkeyId, approvalUserVerified: true,
    });
    expect((await call("GET", `/v1/me/approvals/${approval.id}`, admin.web)).body.state).toBe("consumed");
    // Used: it can never approve anything again.
    expect((await set(admin.cli, "admin-step-up", { mode: "report", expectedVersion: 2 })).status).toBe(200);
    const again = await set(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 3 }, approval.id);
    expect(again.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "consumed" } });
    expect((await approve(admin, approval.id)).body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "consumed" } });
  });

  it("binds the approval to the person: another person, even an admin, finds nothing and cannot use it", async () => {
    const other = await invite("Other admin", "admin");
    const approval = await stepUp(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    for (const path of [`/v1/me/approvals/${approval.id}`]) expect((await call("GET", path, other.web)).status).toBe(404);
    expect((await call("POST", `/v1/me/approvals/${approval.id}/options`, other.web)).status).toBe(404);
    expect((await call("POST", `/v1/me/approvals/${approval.id}/approve`, other.web, { assertion: { id: "x" } })).status).toBe(404);
    expect((await call("POST", `/v1/me/approvals/${approval.id}/cancel`, other.cli)).status).toBe(404);
    // Approved by its person, it still cannot carry another person's request.
    expect((await approve(admin, approval.id)).status).toBe(200);
    const foreign = await set(other.cli, "admin-step-up", { mode: "off", expectedVersion: 1 }, approval.id);
    expect(foreign.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "not-found" } });
    // Nor a request of the same person from another credential.
    const otherCredential = await set(admin.web, "admin-step-up", { mode: "off", expectedVersion: 1 }, approval.id);
    expect(otherCredential.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "mismatch" } });
    // A header that cannot be an approval id is not found.
    expect((await set(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 }, "nonsense")).body.error.details.reason).toBe("not-found");
  });

  it("binds a dashboard approval to its Better Auth session: a refreshed bearer of that session uses it, another session cannot", async () => {
    const approval = await stepUp(admin.web, "admin-step-up", { mode: "off", expectedVersion: 1 });
    expect(approval.requestedBy.credentialKind).toBe("browser");
    expect(await rows("SELECT origin, auth_session_id, credential_id FROM approval_intents WHERE id = $1", [approval.id]))
      .toEqual([{ origin: "dashboard", auth_session_id: `session-${admin.id}`, credential_id: admin.webId }]);
    expect((await approve(admin, approval.id)).status).toBe(200);
    // Another session of the same person, and a CLI credential carrying the same session, cannot use it.
    const otherSession = await admin.session("another-session");
    const fromOtherSession = await set(otherSession, "admin-step-up", { mode: "off", expectedVersion: 1 }, approval.id);
    expect(fromOtherSession.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "mismatch" } });
    const handoff = await issueCredential(ctx.db, { identityId: admin.id, kind: "cli", authSessionId: `session-${admin.id}` });
    const fromCli = await set(handoff.token, "admin-step-up", { mode: "off", expectedVersion: 1 }, approval.id);
    expect(fromCli.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "mismatch" } });
    // The dashboard re-minted its bearer from the same session (a silent refresh): it still fits.
    const refreshed = await admin.session(`session-${admin.id}`);
    const done = await set(refreshed, "admin-step-up", { mode: "off", expectedVersion: 1 }, approval.id);
    expect(done.status, JSON.stringify(done.body)).toBe(200);
    expect(done.body).toMatchObject({ changed: true, loosened: true });
  });

  it("refuses a dashboard approval once its session ended: signed out, or expired", async () => {
    const control = async () => (await controlOf("admin-step-up")).mode;
    // Signed out: Better Auth deletes the session, which revokes the bearers minted from it (migration 43),
    // so the dashboard's bearer can no longer even make the request.
    const signedOut = await stepUp(admin.web, "admin-step-up", { mode: "off", expectedVersion: 1 });
    expect((await approve(admin, signedOut.id)).status).toBe(200);
    await ctx.db.query(`DELETE FROM "session" WHERE id = $1`, [`session-${admin.id}`]);
    const afterSignOut = await set(admin.web, "admin-step-up", { mode: "off", expectedVersion: 1 }, signedOut.id);
    expect(afterSignOut.status).toBe(401);
    expect(afterSignOut.body.error).toMatchObject({ code: "INVALID_CREDENTIAL" });
    expect(await control()).toBe("report");
    expect((await call("GET", `/v1/me/approvals/${signedOut.id}`, admin.cli)).body.state).toBe("approved");
    // Expired: the session row is still there, past its expiry.
    const sessionB = await admin.session("session-b");
    const expired = await stepUp(sessionB, "admin-step-up", { mode: "off", expectedVersion: 1 });
    expect((await approve(admin, expired.id, { token: sessionB })).status).toBe(200);
    await ctx.db.query(`UPDATE "session" SET "expiresAt" = now() - interval '1 second' WHERE id = 'session-b'`);
    const afterExpiry = await set(sessionB, "admin-step-up", { mode: "off", expectedVersion: 1 }, expired.id);
    expect(afterExpiry.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "session-ended" } });
    expect(await control()).toBe("report");
    // A session that is not the requesting person's does not count either.
    const sessionC = await admin.session("session-c");
    const foreign = await stepUp(sessionC, "admin-step-up", { mode: "off", expectedVersion: 1 });
    expect((await approve(admin, foreign.id, { token: sessionC })).status).toBe(200);
    const other = await invite("Other admin", "admin");
    await ctx.db.query(
      `UPDATE "session" SET "userId" = (SELECT better_auth_user_id FROM auth_user_links WHERE identity_id = $1) WHERE id = 'session-c'`,
      [other.id],
    );
    const crossed = await set(sessionC, "admin-step-up", { mode: "off", expectedVersion: 1 }, foreign.id);
    expect(crossed.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "session-ended" } });
    expect(await control()).toBe("report");
  });

  it("refuses a dashboard approval when the refreshed bearer is revoked at use", async () => {
    const approval = await stepUp(admin.web, "admin-step-up", { mode: "off", expectedVersion: 1 });
    expect((await approve(admin, approval.id)).status).toBe(200);
    const refreshed = await issueCredential(ctx.db, {
      identityId: admin.id, kind: "browser", authSessionId: `session-${admin.id}`,
      expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
    });
    await ctx.db.query("UPDATE credentials SET revoked_at = now() WHERE id = $1", [refreshed.credentialId]);
    const requester: Requester = {
      identityId: admin.id, identityKind: "human", credentialId: refreshed.credentialId, credentialKind: "browser", authSessionId: `session-${admin.id}`,
    };
    await expect(withTx(ctx.db, (db) => consumeAsOperation(db, ctx.rootKek, requester, approval.id, {
      operation: "security_control.change", organizationId: orgId, target: { control: "admin-step-up" },
      body: { mode: "off", config: null, expectedVersion: 1 }, query: {}, expectedVersion: 1, summary: { title: "", changes: [] },
    }))).rejects.toMatchObject({ code: "INVALID_CREDENTIAL" });
    expect((await call("GET", `/v1/me/approvals/${approval.id}`, admin.web)).body.state).toBe("approved");
  });

  it("refuses an approval for another target or body, and a stale version", async () => {
    const approval = await stepUp(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    expect((await approve(admin, approval.id)).status).toBe(200);
    const otherTarget = await set(admin.cli, "credential-lifetime", { mode: "off", expectedVersion: 1 }, approval.id);
    expect(otherTarget.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "mismatch" } });
    const lifetime = await stepUp(admin.cli, "credential-lifetime", { config: { defaultTtlSeconds: 3600, maxTtlSeconds: 90_000 }, expectedVersion: 1 });
    expect((await approve(admin, lifetime.id)).status).toBe(200);
    const otherBody = await set(admin.cli, "credential-lifetime", { config: { defaultTtlSeconds: 3600, maxTtlSeconds: 99_000 }, expectedVersion: 1 }, lifetime.id);
    expect(otherBody.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "mismatch" } });
    // The control moved on meanwhile: the approved request now has a stale version, and nothing was used.
    expect((await set(admin.cli, "admin-step-up", { mode: "report", expectedVersion: 1 })).body.changed).toBe(false);
    const other = await invite("Other admin", "admin");
    expect((await set(other.cli, "credential-lifetime", { config: { defaultTtlSeconds: 1800, maxTtlSeconds: 86_400 }, expectedVersion: 1 })).status).toBe(200);
    const stale = await set(admin.cli, "credential-lifetime", { config: { defaultTtlSeconds: 3600, maxTtlSeconds: 90_000 }, expectedVersion: 1 }, lifetime.id);
    expect(stale.body.error).toMatchObject({ code: "VERSION_CONFLICT" });
    expect((await call("GET", `/v1/me/approvals/${lifetime.id}`, admin.web)).body.state).toBe("approved");
    // Both still unused; the original admin-step-up one still works for its exact request.
    expect((await set(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 }, approval.id)).status).toBe(200);
  });

  it("expires by the live clock, approved or not, and approval never extends it", async () => {
    const pending = await stepUp(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    const approved = await stepUp(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    expect((await approve(admin, approved.id)).status).toBe(200);
    const start = await call("POST", `/v1/me/approvals/${pending.id}/options`, admin.web);
    expect(start.status).toBe(200);
    await ctx.db.query(
      "UPDATE approval_intents SET created_at = clock_timestamp() - interval '11 minutes', expires_at = clock_timestamp() - interval '1 second'",
    );
    expect((await call("GET", `/v1/me/approvals/${pending.id}`, admin.web)).body.state).toBe("expired");
    const late = await call("POST", `/v1/me/approvals/${pending.id}/approve`, admin.web, { assertion: admin.key.assert(start.body.publicKey.challenge) });
    expect(late.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "expired" } });
    const used = await set(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 }, approved.id);
    expect(used.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "expired" } });
    expect((await controlOf("admin-step-up")).mode).toBe("report");
  });

  it("is not used up by an operation that fails: consumption and mutation roll back together", async () => {
    const approval = await stepUp(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    expect((await approve(admin, approval.id)).status).toBe(200);
    const requester: Requester = { identityId: admin.id, identityKind: "human", credentialId: admin.cliId, credentialKind: "cli" };
    const binding: ApprovalBinding = {
      operation: "security_control.change",
      organizationId: orgId,
      target: { control: "admin-step-up" },
      body: { mode: "off", config: null, expectedVersion: 1 },
      query: {},
      expectedVersion: 1,
      summary: { title: "", changes: [] },
    };
    await expect(withTx(ctx.db, async (db) => {
      expect((await consumeAsOperation(db, ctx.rootKek, requester, approval.id, binding)).id).toBe(approval.id);
      throw new Error("the mutation failed");
    })).rejects.toThrow("the mutation failed");
    expect((await call("GET", `/v1/me/approvals/${approval.id}`, admin.web)).body.state).toBe("approved");
    // Another query, though the same body, does not fit either.
    await expect(withTx(ctx.db, (db) => consumeAsOperation(db, ctx.rootKek, requester, approval.id, { ...binding, query: { force: "1" } })))
      .rejects.toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "mismatch" } });
    // Two consumptions of one approval: the second is refused.
    await withTx(ctx.db, (db) => consumeAsOperation(db, ctx.rootKek, requester, approval.id, binding));
    await expect(withTx(ctx.db, (db) => consumeAsOperation(db, ctx.rootKek, requester, approval.id, binding)))
      .rejects.toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "consumed" } });
  });

  it("revalidates the credential at consumption", async () => {
    const approval = await stepUp(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    expect((await approve(admin, approval.id)).status).toBe(200);
    const requester: Requester = { identityId: admin.id, identityKind: "human", credentialId: admin.cliId, credentialKind: "cli" };
    await ctx.db.query("UPDATE credentials SET revoked_at = now() WHERE id = $1", [admin.cliId]);
    await expect(withTx(ctx.db, (db) => consumeAsOperation(db, ctx.rootKek, requester, approval.id, {
      operation: "security_control.change", organizationId: orgId, target: { control: "admin-step-up" },
      body: { mode: "off", config: null, expectedVersion: 1 }, query: {}, expectedVersion: 1, summary: { title: "", changes: [] },
    }))).rejects.toMatchObject({ code: "INVALID_CREDENTIAL" });
    expect((await call("GET", `/v1/me/approvals/${approval.id}`, admin.web)).body.state).toBe("approved");
  });

  it("can be cancelled by its person, from any of their credentials", async () => {
    const approval = await stepUp(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    const cancelled = await call("POST", `/v1/me/approvals/${approval.id}/cancel`, admin.cli);
    expect(cancelled.body).toMatchObject({ state: "closed", closeReason: "cancelled" });
    expect((await approve(admin, approval.id)).body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "closed" } });
    expect((await call("POST", `/v1/me/approvals/${approval.id}/cancel`, admin.web)).body.error.details.reason).toBe("closed");
  });
});

describe("who may approve", () => {
  beforeEach(async () => {
    expect((await set(admin.cli, "admin-step-up", { mode: "report", expectedVersion: 0 })).status).toBe(200);
  });

  it("needs a trusted passkey: an unconfirmed one cannot approve, even turning reporting off", async () => {
    const newcomer = await invite("Newcomer", "admin", "unconfirmed");
    const approval = await stepUp(newcomer.cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    const started = await call("POST", `/v1/me/approvals/${approval.id}/options`, newcomer.web);
    expect(started.status).toBe(403);
    expect(started.body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "no-trusted-passkey" } });
    // With a trusted key too, the options name only the trusted one, and the unconfirmed one is refused.
    const trusted = await registerSoftPasskey(ctx.db, newcomer.id, { ...RP, trust: "trusted" });
    const options = await call("POST", `/v1/me/approvals/${approval.id}/options`, newcomer.web);
    expect(options.body.publicKey.allowCredentials.map((c: { id: string }) => c.id)).toEqual([trusted.credentialId]);
    expect(options.body.publicKey.userVerification).toBe("required");
    const refused = await call("POST", `/v1/me/approvals/${approval.id}/approve`, newcomer.web, {
      assertion: newcomer.key.assert(options.body.publicKey.challenge),
    });
    expect(refused.body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "unknown-passkey" } });
    expect((await events("authentication.failed")).at(-1)).toMatchObject({
      actor: newcomer.id, resource: { approvalId: approval.id }, metadata: { method: "step-up-approval", reason: "unknown-passkey" },
    });
    // The refused challenge is used up; a new one with the trusted key works.
    expect((await approve(newcomer, approval.id, { key: trusted })).status).toBe(200);
  });

  it("requires user verification", async () => {
    const approval = await stepUp(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    const refused = await approve(admin, approval.id, { userVerified: false });
    expect(refused.body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "user-verification-required" } });
    expect((await call("GET", `/v1/me/approvals/${approval.id}`, admin.web)).body.state).toBe("pending");
  });

  it("binds the challenge to the browser session that started it, and approving takes a dashboard session", async () => {
    const approval = await stepUp(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    const started = await call("POST", `/v1/me/approvals/${approval.id}/options`, admin.web);
    const otherSession = await admin.session("another-session");
    const refused = await call("POST", `/v1/me/approvals/${approval.id}/approve`, otherSession, {
      assertion: admin.key.assert(started.body.publicKey.challenge),
    });
    expect(refused.body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "challenge" } });
    // The CLI itself cannot approve.
    expect((await call("POST", `/v1/me/approvals/${approval.id}/options`, admin.cli)).status).toBe(403);
    expect((await approve(admin, approval.id, { token: otherSession })).status).toBe(200);
  });
});

describe("bounds", () => {
  beforeEach(async () => {
    expect((await set(admin.cli, "admin-step-up", { mode: "report", expectedVersion: 0 })).status).toBe(200);
  });

  it("allows 5 open approvals per credential", async () => {
    for (let i = 0; i < APPROVALS.openPerCredential; i++) await stepUp(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    const sixth = await set(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    expect(sixth.status).toBe(429);
    expect(sixth.body.error).toMatchObject({ code: "RATE_LIMITED", details: { cap: "open-per-credential" } });
    // Cancelling one frees a place.
    const open = await rows("SELECT id FROM approval_intents ORDER BY created_at LIMIT 1");
    await call("POST", `/v1/me/approvals/${open[0].id}/cancel`, admin.cli);
    await stepUp(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
  });

  it("allows 30 per person per 10 minutes, across credentials", async () => {
    for (let i = 0; i < APPROVALS.createdPerPerson; i++) {
      const cli = (await issueCredential(ctx.db, { identityId: admin.id, kind: "cli" })).token;
      await stepUp(cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    }
    const cli = (await issueCredential(ctx.db, { identityId: admin.id, kind: "cli" })).token;
    const refused = await set(cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    expect(refused.body.error).toMatchObject({ code: "RATE_LIMITED", details: { cap: "per-person" } });
    expect(typeof refused.body.error.details.retryAt).toBe("string");
  });

  it("slows down polls by the requesting credential, as device sign-in does", async () => {
    const approval = await stepUp(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    expect((await call("GET", `/v1/me/approvals/${approval.id}`, admin.cli)).status).toBe(200);
    const tooSoon = await call("GET", `/v1/me/approvals/${approval.id}`, admin.cli);
    expect(tooSoon.status).toBe(429);
    expect(tooSoon.body.error).toMatchObject({ code: "SLOW_DOWN", details: { interval: 10 } });
    expect(tooSoon.headers.get("Retry-After")).toBe("10");
    // The dashboard's reads do not count.
    expect((await call("GET", `/v1/me/approvals/${approval.id}`, admin.web)).status).toBe(200);
    expect((await call("GET", `/v1/me/approvals/${approval.id}`, admin.web)).body.interval).toBe(10);
    await ctx.db.query("UPDATE approval_intents SET last_polled_at = clock_timestamp() - interval '11 seconds'");
    expect((await call("GET", `/v1/me/approvals/${approval.id}`, admin.cli)).status).toBe(200);
  });

  it("caps approval challenges per person", async () => {
    const approval = await stepUp(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    for (let i = 0; i < APPROVALS.challengesPerPerson; i++) {
      expect((await call("POST", `/v1/me/approvals/${approval.id}/options`, admin.web)).status).toBe(200);
    }
    const refused = await call("POST", `/v1/me/approvals/${approval.id}/options`, admin.web);
    expect(refused.body.error).toMatchObject({ code: "RATE_LIMITED" });
  });

  it("refuses to ask for an approval nobody could give without a public URL", async () => {
    app = buildApp(ctx, { clientAddress: () => "203.0.113.7" });
    const res = await set(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    expect(res.body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "approvals-unavailable" } });
    expect((await controlOf("admin-step-up")).mode).toBe("report");
  });
});

describe("removing a passkey", () => {
  const remove = (p: Person, passkeyId: string, approval?: string) =>
    call("DELETE", `/v1/me/passkeys/${passkeyId}`, p.web, undefined, approval ? { "Varlatch-Approval": approval } : {});
  const passkeyExists = async (id: string) => (await rows("SELECT 1 FROM passkey WHERE id = $1", [id])).length === 1;

  it("needs no approval while no Organization of the person enforces a control", async () => {
    expect((await set(admin.cli, "admin-step-up", { mode: "report", expectedVersion: 0 })).status).toBe(200);
    const spare = await registerSoftPasskey(ctx.db, admin.id, { ...RP, trust: "trusted" });
    expect((await remove(admin, spare.passkeyId)).status).toBe(204);
    expect(await passkeyExists(spare.passkeyId)).toBe(false);
  });

  it("needs one for a trusted passkey when an Organization of the person enforces any control, never for an unconfirmed one", async () => {
    // Inserted directly, as the API stores it. requirement-protection, which
    // leaves this test's own sign-in free to use the organization (enforced
    // passkey-verification would refuse it: passkey-verification.test.ts).
    await ctx.db.query(
      "INSERT INTO security_controls (organization_id, control, mode, version, changed_by) VALUES ($1, 'requirement-protection', 'enforce', 1, $2)",
      [orgId, admin.id],
    );
    const unconfirmed = await registerSoftPasskey(ctx.db, admin.id, { ...RP, trust: "unconfirmed" });
    expect((await remove(admin, unconfirmed.passkeyId)).status).toBe(204);

    const spare = await registerSoftPasskey(ctx.db, admin.id, { ...RP, trust: "trusted" });
    const asked = await remove(admin, spare.passkeyId);
    expect(asked.status).toBe(403);
    const approval = asked.body.error.details.approval;
    expect(approval).toMatchObject({ operation: "passkey.remove", organization: null, state: "pending", requestedBy: { credentialKind: "browser" } });
    expect(approval.summary.title).toBe('Remove your trusted passkey "test passkey"');
    expect(await passkeyExists(spare.passkeyId)).toBe(true);
    // Approved with the very key being removed: allowed.
    expect((await approve(admin, approval.id, { key: spare })).status).toBe(200);
    // It does not fit another passkey; an approval for another operation does not fit this one.
    const other = await registerSoftPasskey(ctx.db, admin.id, { ...RP, trust: "trusted" });
    expect((await remove(admin, other.passkeyId, approval.id)).body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "mismatch" } });
    expect((await set(admin.web, "admin-step-up", { mode: "report", expectedVersion: 0 })).status).toBe(200);
    const controlApproval = await stepUp(admin.web, "admin-step-up", { mode: "off", expectedVersion: 1 });
    expect((await approve(admin, controlApproval.id)).status).toBe(200);
    expect((await remove(admin, spare.passkeyId, controlApproval.id)).body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "mismatch" } });
    expect((await remove(admin, spare.passkeyId, approval.id)).status).toBe(204);
    expect(await passkeyExists(spare.passkeyId)).toBe(false);
  });

  it("is not restricted by an Organization the person left, or one that was deleted", async () => {
    const member = await invite("Member", "member");
    await ctx.db.query(
      "INSERT INTO security_controls (organization_id, control, mode, version) VALUES ($1, 'admin-step-up', 'enforce', 1)",
      [orgId],
    );
    const spare = await registerSoftPasskey(ctx.db, member.id, { ...RP, trust: "trusted" });
    expect((await remove(member, spare.passkeyId)).status).toBe(403);
    await ctx.db.query("UPDATE org_memberships SET removed_at = now() WHERE identity_id = $1", [member.id]);
    expect((await remove(member, spare.passkeyId)).status).toBe(204);
  });
});

describe("the host operator's reset", () => {
  it("sets only the named controls to off and closes only their open approvals", async () => {
    expect((await set(admin.cli, "admin-step-up", { mode: "report", expectedVersion: 0 })).status).toBe(200);
    expect((await set(admin.cli, "credential-lifetime", { mode: "report", config: { defaultTtlSeconds: 60, maxTtlSeconds: 600 }, expectedVersion: 0 })).status).toBe(200);
    const stepUpApproval = await stepUp(admin.cli, "admin-step-up", { mode: "off", expectedVersion: 1 });
    const lifetimeApproval = await stepUp(admin.cli, "credential-lifetime", { mode: "off", expectedVersion: 1 });
    expect((await approve(admin, lifetimeApproval.id)).status).toBe(200);
    await ctx.db.query(
      "INSERT INTO security_controls (organization_id, control, mode, version) VALUES ($1, 'passkey-verification', 'enforce', 1)",
      [orgId],
    );
    const before = await rows("SELECT * FROM organization_deletions");
    const grantsBefore = await rows("SELECT id, revoked_at FROM grants ORDER BY id");

    const outcome = await resetControls(ctx, { organization: "acme", controls: ["credential-lifetime", "passkey-verification"] });
    expect(outcome).toEqual({
      organization: { id: orgId, slug: "acme" },
      reset: [
        { control: "passkey-verification", from: "enforce", version: 2 },
        { control: "credential-lifetime", from: "report", version: 2 },
      ],
      approvalsClosed: 1,
      stillFrozen: false,
    });
    const controls = (await call("GET", CONTROLS, admin.cli)).body.items;
    expect(controls.map((c: { control: string; mode: string; version: number; changedBy: unknown }) => [c.control, c.mode, c.version, c.changedBy])).toEqual([
      ["requirement-protection", "off", 0, null],
      ["admin-step-up", "report", 1, { id: admin.id, name: "Admin" }],
      ["passkey-verification", "off", 2, null],
      ["credential-lifetime", "off", 2, null],
    ]);
    // Its configuration stays.
    expect(controls[3].config).toEqual({ defaultTtlSeconds: 60, maxTtlSeconds: 600 });
    expect((await call("GET", `/v1/me/approvals/${lifetimeApproval.id}`, admin.web)).body).toMatchObject({ state: "closed", closeReason: "reset" });
    expect((await call("GET", `/v1/me/approvals/${stepUpApproval.id}`, admin.web)).body.state).toBe("pending");
    expect((await set(admin.cli, "credential-lifetime", { mode: "off", expectedVersion: 1 }, lifetimeApproval.id)).body.error.code).toBe("VERSION_CONFLICT");
    const reset = await events("security_control.reset");
    expect(reset.map((e) => [e.actor, e.org, e.metadata.control, e.metadata.fromMode, e.metadata.toMode, e.metadata.operator])).toEqual([
      [null, orgId, "passkey-verification", "enforce", "off", true],
      [null, orgId, "credential-lifetime", "report", "off", true],
    ]);
    // Never the deletion state or Grants.
    expect(await rows("SELECT * FROM organization_deletions")).toEqual(before);
    expect(await rows("SELECT id, revoked_at FROM grants ORDER BY id")).toEqual(grantsBefore);
    expect(resetReportLines(outcome)[1]).toBe("  passkey-verification: enforce -> off (version 2)");
  });

  it("resets all, works during a deletion freeze, and says when a control was already off", async () => {
    expect((await call("POST", `${ORG}/deletion`, admin.cli, { afterDays: 7 })).status).toBe(201);
    const outcome = await resetControls(ctx, { organization: orgId, controls: "all" });
    expect(outcome.reset.map((r) => [r.control, r.from, r.version])).toEqual([
      ["requirement-protection", "off", 0], ["admin-step-up", "off", 0], ["passkey-verification", "off", 0], ["credential-lifetime", "off", 0],
    ]);
    expect(resetReportLines(outcome)[1]).toBe("  requirement-protection: already off");
    expect(await rows("SELECT count(*)::int AS n FROM organization_deletions WHERE cancelled_at IS NULL AND completed_at IS NULL")).toEqual([{ n: 1 }]);
    await expect(resetControls(ctx, { organization: "nope", controls: "all" })).rejects.toMatchObject({ code: "RESOURCE_NOT_FOUND" });
  });

  it("parses its arguments", () => {
    expect(parseResetArgs(["--org", "acme", "--control", "admin-step-up", "--control", "admin-step-up", "--json"]))
      .toEqual({ organization: "acme", controls: ["admin-step-up"], json: true });
    expect(parseResetArgs(["--org", "acme", "--all"])).toEqual({ organization: "acme", controls: "all", json: false });
    for (const bad of [[], ["--org", "acme"], ["--org", "acme", "--all", "--control", "admin-step-up"], ["--org", "acme", "--control", "nope"], ["--all"], ["--org", "a", "--all", "--force"]]) {
      expect(parseResetArgs(bad)).toHaveProperty("error");
    }
  });
});

describe("change classification", () => {
  const lifetime = (d: number, m: number) => ({ defaultTtlSeconds: d, maxTtlSeconds: m });
  it("loosens towards off, when a lifetime grows or a bound is removed, and nowhere else", () => {
    expect(classifyChange({ mode: "enforce", config: null }, { mode: "report", config: null }).loosened).toEqual(["mode"]);
    expect(classifyChange({ mode: "report", config: null }, { mode: "off", config: null }).loosened).toEqual(["mode"]);
    expect(classifyChange({ mode: "off", config: null }, { mode: "report", config: null }).loosened).toEqual([]);
    expect(classifyChange({ mode: "report", config: null }, { mode: "report", config: lifetime(10, 20) }).loosened).toEqual([]);
    expect(classifyChange({ mode: "report", config: lifetime(10, 20) }, { mode: "report", config: lifetime(5, 20) }).loosened).toEqual([]);
    expect(classifyChange({ mode: "report", config: lifetime(10, 20) }, { mode: "report", config: lifetime(10, 30) }).loosened).toEqual(["maxTtlSeconds"]);
    expect(classifyChange({ mode: "report", config: lifetime(10, 20) }, { mode: "enforce", config: lifetime(15, 20) }).loosened).toEqual(["defaultTtlSeconds"]);
    expect(classifyChange({ mode: "off", config: lifetime(10, 20) }, { mode: "off", config: null }).loosened).toEqual(["defaultTtlSeconds", "maxTtlSeconds"]);
  });

  it("hashes normalized requests whatever their key order", () => {
    expect(canonicalJson({ b: 1, a: { d: [1, { y: 2, x: 1 }], c: null } })).toBe('{"a":{"c":null,"d":[1,{"x":1,"y":2}]},"b":1}');
    const key = generateKey();
    expect(approvalHash(key, "body", { mode: "off", expectedVersion: 1 })).toBe(approvalHash(key, "body", { expectedVersion: 1, mode: "off" }));
    expect(approvalHash(key, "body", {})).not.toBe(approvalHash(key, "query", {}));
  });
});
