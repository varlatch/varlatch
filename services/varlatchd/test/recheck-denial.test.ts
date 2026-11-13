// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { getOrgRole } from "../src/domain/orgs.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * ADR-0054 follow-up (f): freezing, lifting a freeze and changing a
 * security control recheck the requester's organization.manage inside
 * their transaction, after the Organization row FOR UPDATE, whatever the
 * controls' modes. A denial there rolls the transaction back.
 *
 * - While at least one control is at report or enforce, in the state the
 *   decision was made on, the denial is audited once after the rollback,
 *   exactly as an ordinary denial (follow-up (a)'s mechanism).
 * - With every control off, nothing observable changes from main: the same
 *   answer and no audit event at all.
 * - A control change decides on the state before the change: off to report
 *   from all off audits nothing; report to off audits the denial.
 *
 * The race on PGlite (one connection): Carol is an admin for the route's
 * own check and a member once the operation's transaction holds the
 * Organization FOR UPDATE (getOrgRole mocked). The same races with a real
 * concurrent demotion run on PostgreSQL in recheck-denial-postgres.test.ts.
 */

vi.mock("../src/domain/orgs.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/domain/orgs.js")>();
  return { ...actual, getOrgRole: vi.fn(actual.getOrgRole) };
});
const orgRole = vi.mocked(getOrgRole);

const ORG = "/v1/organizations/acme";
const FREEZE = `${ORG}/incident-freeze`;
const control = (name: string) => `${ORG}/security/controls/${name}`;

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let orgId: string;
let admin: Person;
let carol: Person;

interface Person {
  id: string;
  cli: string;
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

const rows = async (sql: string, params: unknown[] = []) => (await ctx.db.query(sql, params)).rows as any[];
const parse = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v) as Record<string, any>;

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

/** Approve in the dashboard: start, sign the challenge, approve. */
async function approve(p: Person, approvalId: string) {
  const started = await call("POST", `/v1/me/approvals/${approvalId}/options`, p.web);
  expect(started.status, JSON.stringify(started.body)).toBe(200);
  const done = await call("POST", `/v1/me/approvals/${approvalId}/approve`, p.web, {
    assertion: p.key.assert(started.body.publicKey.challenge, { userVerified: true }),
  });
  expect(done.status, JSON.stringify(done.body)).toBe(200);
}

/** The approval a request asks for (STEP_UP_REQUIRED), approved by `p`. */
async function approved(p: Person, ask: () => Promise<Answer>): Promise<string> {
  const asked = await ask();
  expect(asked.status, JSON.stringify(asked.body)).toBe(403);
  expect(asked.body.error.code).toBe("STEP_UP_REQUIRED");
  const id = asked.body.error.details.approval.id as string;
  await approve(p, id);
  return id;
}

/** Set a control through the API, as the admin (tightening needs no approval). */
async function turnOn(name: string, mode: "report" | "enforce") {
  const current = (await rows("SELECT version FROM security_controls WHERE organization_id = $1 AND control = $2", [orgId, name]))[0];
  const res = await call("PATCH", control(name), admin.cli, { mode, expectedVersion: current ? Number(current.version) : 0 });
  expect(res.status, JSON.stringify(res.body)).toBe(200);
}

const freeze = (token: string) => call("POST", FREEZE, token, { reason: "A CI token leaked" });
const lift = (token: string, freezeId: string, approval?: string) =>
  call("POST", `${FREEZE}/${freezeId}/lift`, token, undefined, approval ? { "Varlatch-Approval": approval } : {});
const change = (token: string, name: string, mode: string, expectedVersion: number, approval?: string) =>
  call("PATCH", control(name), token, { mode, expectedVersion }, approval ? { "Varlatch-Approval": approval } : {});

async function frozen(): Promise<string> {
  const res = await freeze(admin.cli);
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return res.body.id as string;
}

/**
 * Runs `send` with Carol an admin until an operation's transaction takes
 * the Organization row FOR UPDATE, and a member from then on in that
 * transaction: the recheck, never the route's own check, sees the demotion.
 */
async function demotedInTransaction(send: () => Promise<Answer>) {
  const actual = await vi.importActual<typeof import("../src/domain/orgs.js")>("../src/domain/orgs.js");
  const original = ctx.db.query.bind(ctx.db);
  let inside = false;
  let locked = false;
  let demoted = 0;
  ctx.db.query = (async (text: string, params?: unknown[]) => {
    if (text.trim() === "BEGIN") inside = true;
    if (inside && /FROM organizations WHERE id = \$1 FOR UPDATE/.test(text)) locked = true;
    const res = await original(text, params);
    if (text.trim() === "ROLLBACK" || text.trim() === "COMMIT") inside = locked = false;
    return res;
  }) as typeof ctx.db.query;
  orgRole.mockImplementation(async (c, organizationId, identityId) => {
    if (inside && locked && identityId === carol.id) {
      demoted++;
      return "member";
    }
    return actual.getOrgRole(c, organizationId, identityId);
  });
  try {
    const res = await send();
    expect(demoted, "the recheck ran in the transaction").toBeGreaterThan(0);
    return res;
  } finally {
    ctx.db.query = original;
    orgRole.mockImplementation(actual.getOrgRole);
  }
}

const denials = async () =>
  (await rows(
    `SELECT event_type, decision, actor_identity_id, credential_id, organization_id, action, resource, authz, metadata
     FROM audit_events WHERE event_type = 'authorization.denied' AND actor_identity_id = $1 ORDER BY event_order`,
    [carol.id],
  )).map((r) => ({ ...r, resource: parse(r.resource), authz: parse(r.authz), metadata: parse(r.metadata) }));
const auditCount = async () => Number((await rows("SELECT count(*)::int AS n FROM audit_events"))[0].n);
const withoutRequestId = (a: Answer) => ({ status: a.status, error: { ...a.body.error, requestId: undefined } });

/** The route's own denial of the same request, with Carol demoted for real: what main records. */
async function ordinaryDenial(send: () => Promise<Answer>) {
  await ctx.db.query("UPDATE org_memberships SET role = 'member' WHERE organization_id = $1 AND identity_id = $2", [orgId, carol.id]);
  try {
    const res = await send();
    expect(res.body.error.code).toBe("PERMISSION_DENIED");
    return { res, event: (await denials()).at(-1)! };
  } finally {
    await ctx.db.query("UPDATE org_memberships SET role = 'admin' WHERE organization_id = $1 AND identity_id = $2", [orgId, carol.id]);
  }
}

/**
 * The race for `send`: refused with PERMISSION_DENIED. With `audited`, one
 * authorization.denied for Carol, equal to the route's ordinary denial of
 * the same request; without, no audit event of any kind.
 */
async function race(send: () => Promise<Answer>, audited: boolean): Promise<Answer> {
  const before = await denials();
  const total = await auditCount();
  const res = await demotedInTransaction(send);
  expect(res.status, JSON.stringify(res.body)).toBe(403);
  expect(res.body.error.code).toBe("PERMISSION_DENIED");
  const after = await denials();
  if (!audited) {
    expect(after).toEqual(before);
    expect(await auditCount()).toBe(total);
    return res;
  }
  expect(after).toHaveLength(before.length + 1);
  expect(await auditCount()).toBe(total + 1);
  const deferred = after.at(-1)!;
  expect(deferred).toMatchObject({ decision: "deny", organization_id: orgId, action: "organization.manage" });
  const { res: ordinary, event } = await ordinaryDenial(send);
  expect(deferred).toEqual(event);
  expect(withoutRequestId(res)).toEqual(withoutRequestId(ordinary));
  return res;
}

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const { identityId } = await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" });
  app = buildApp(ctx, { publicUrl: PUBLIC_URL, clientAddress: () => "203.0.113.7" });
  admin = await person(identityId);
  const created = await call("POST", "/v1/organizations", admin.cli, { name: "Acme", slug: "acme" });
  expect(created.status).toBe(201);
  orgId = created.body.id;
  const grant = await issueInviteGrant(ctx, { organizationId: orgId, role: "admin", name: "Carol" }, admin.id);
  carol = await person((await consumeSetupGrant(ctx, grant.token, {})).identityId);
});
afterEach(async () => {
  await ctx.close();
});

describe("freezing, when the recheck in its transaction denies", () => {
  it("with a control on: refused, nothing frozen, the denial audited once as an ordinary one", async () => {
    await turnOn("admin-step-up", "report");
    await race(() => freeze(carol.cli), true);
    expect(await rows("SELECT id FROM organization_freezes")).toEqual([]);
  });

  it("with every control off: the same answer as main, no audit event", async () => {
    const off = await race(() => freeze(carol.cli), false);
    expect(await rows("SELECT id FROM organization_freezes")).toEqual([]);
    // The answer a control does not change: the same as with one on.
    await turnOn("requirement-protection", "report");
    expect(withoutRequestId(await race(() => freeze(carol.cli), true))).toEqual(withoutRequestId(off));
  });
});

describe("lifting a freeze, when the recheck in its transaction denies", () => {
  it("with a control on: refused, still frozen, the approval unused, the denial audited once", async () => {
    await turnOn("requirement-protection", "report");
    const id = await frozen();
    const approval = await approved(carol, () => lift(carol.cli, id));
    await race(() => lift(carol.cli, id, approval), true);
    expect((await rows("SELECT lifted_at FROM organization_freezes WHERE id = $1", [id]))[0].lifted_at).toBeNull();
    expect((await rows("SELECT consumed_at FROM approval_intents WHERE id = $1", [approval]))[0].consumed_at).toBeNull();
  });

  it("with every control off (the lift still needs its approval): no audit event, the approval unused", async () => {
    const id = await frozen();
    const approval = await approved(carol, () => lift(carol.cli, id));
    await race(() => lift(carol.cli, id, approval), false);
    expect((await rows("SELECT lifted_at FROM organization_freezes WHERE id = $1", [id]))[0].lifted_at).toBeNull();
    expect((await rows("SELECT consumed_at FROM approval_intents WHERE id = $1", [approval]))[0].consumed_at).toBeNull();
  });
});

describe("changing a control, when the recheck in its transaction denies", () => {
  const modes = async () =>
    Object.fromEntries((await rows("SELECT control, mode, version FROM security_controls ORDER BY control")).map((r) => [r.control, `${r.mode}@${r.version}`]));

  it("with another control on: refused, nothing changed, the denial audited once", async () => {
    await turnOn("requirement-protection", "report");
    const before = await modes();
    await race(() => change(carol.cli, "admin-step-up", "report", 0), true);
    expect(await modes()).toEqual(before);
  });

  it("from every control off, off to report: decided on the state before the change, so no audit event", async () => {
    const off = await race(() => change(carol.cli, "admin-step-up", "report", 0), false);
    expect(await modes()).toEqual({});
    // The same request with a control on answers the same, audited.
    await turnOn("requirement-protection", "report");
    expect(withoutRequestId(await race(() => change(carol.cli, "admin-step-up", "report", 0), true))).toEqual(withoutRequestId(off));
  });

  it("report to off, turning the last control off: the state before the change has it on, so the denial is audited", async () => {
    await turnOn("admin-step-up", "report");
    const approval = await approved(carol, () => change(carol.cli, "admin-step-up", "off", 1));
    await race(() => change(carol.cli, "admin-step-up", "off", 1, approval), true);
    expect(await modes()).toEqual({ "admin-step-up": "report@1" });
    expect((await rows("SELECT consumed_at FROM approval_intents WHERE id = $1", [approval]))[0].consumed_at).toBeNull();
  });
});
