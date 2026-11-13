// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { OPERATIONS_DURING_FREEZE } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { finalizeDeletion } from "../src/domain/orgdeletion.js";
import { ENFORCEABLE_CONTROLS, resetControls } from "../src/domain/securitycontrols.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * admin-step-up for deletion and export (ADR-0054 step 4.9, amendments B
 * and C), on PGlite under the lock-order check (test/helpers/lock-trace.ts):
 * deleting a Project, scheduling the Organization's deletion, and a Secret
 * disclosure with purpose "export". These tests set admin-step-up's
 * enforce directly in the database (written before the unlock); setting
 * it through the API is tested in admin-step-up-catalogue.test.ts.
 *
 * - With every control off nothing changes; report mode counts and refuses
 *   nothing; under enforce each needs the requester's approval bound as the
 *   binding catalogue says, and a machine credential is refused without an
 *   intent.
 * - Deletion: the step-up neither shortens the waiting period nor replaces
 *   the second admin; `afterDays` is bound, not a timestamp.
 * - Export: nothing is written inside the retrieval snapshot; a stale
 *   capture (a rotation started or completed, a child override created or
 *   removed, a retiring version past its deadline, a new Contract Revision)
 *   is refused with STATE_CHANGED before the commit and before any
 *   decryption, and the approval stays usable; an "all authorized" set that
 *   grew needs a new approval. The state is changed between the snapshot
 *   and phase 2 by a hook on the snapshot's COMMIT (PGlite has one
 *   connection). The races with a concurrent value write run on real
 *   PostgreSQL in admin-step-up-deletion-export-postgres.test.ts.
 */

const ORG = "/v1/organizations/acme";
const P = `${ORG}/projects/api`;
const PROD = `${P}/environments/production`;
const PREVIEW = `${P}/environments/${encodeURIComponent("production/pr-1")}`;

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let orgId: string;
let projectId: string;
let prodId: string;
let previewId: string;
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
const parse = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v) as Record<string, any> | null;

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

/** A new person of the Organization; an admin is made one in the database (inviting one is itself protected). */
async function invite(name: string, role: "admin" | "member"): Promise<Person> {
  const grant = await issueInviteGrant(ctx, { organizationId: orgId, role: "member", name }, admin.id);
  const { identityId } = await consumeSetupGrant(ctx, grant.token, {});
  if (role === "admin") {
    await ctx.db.query("UPDATE org_memberships SET role = 'admin' WHERE organization_id = $1 AND identity_id = $2", [orgId, identityId]);
  }
  return person(identityId);
}

const controlOf = async (control: string) =>
  (await ok("GET", `${ORG}/security/controls`, admin.cli)).items.find((i: { control: string }) => i.control === control);
const setMode = async (control: string, mode: string) =>
  call("PATCH", `${ORG}/security/controls/${control}`, admin.cli, { mode, expectedVersion: (await controlOf(control)).version });

/** admin-step-up at enforce, written directly in the database (the API accepts it since step 4.9). */
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

async function approve(p: Person, approvalId: string) {
  const started = await call("POST", `/v1/me/approvals/${approvalId}/options`, p.web);
  expect(started.status, JSON.stringify(started.body)).toBe(200);
  const approved = await call("POST", `/v1/me/approvals/${approvalId}/approve`, p.web, {
    assertion: p.key.assert(started.body.publicKey.challenge, { userVerified: true }),
  });
  expect(approved.status, JSON.stringify(approved.body)).toBe(200);
}

async function approved(p: Person, res: Answer) {
  const asked = stepUp(res);
  await approve(p, asked.id);
  return asked.id;
}

const invalid = (res: Answer, reason: string) => {
  expect(res.status, JSON.stringify(res.body)).toBe(409);
  expect(res.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason } });
};

const intentState = async (id: string) =>
  (await rows("SELECT approved_at IS NOT NULL AS approved, consumed_at IS NOT NULL AS consumed, close_reason FROM approval_intents WHERE id = $1", [id]))[0];

async function events(eventType: string) {
  return (await rows("SELECT actor_identity_id, metadata FROM audit_events WHERE event_type = $1 ORDER BY event_order", [eventType]))
    .map((r) => ({ actor: r.actor_identity_id as string, metadata: parse(r.metadata) ?? {} }));
}

// The operations, as their routes take them.
const deleteProject = (token: string, approval?: string, project = "api") =>
  call("DELETE", `${ORG}/projects/${project}`, token, undefined, header(approval));
const schedule = (token: string, body: { afterDays?: number }, approval?: string) => call("POST", `${ORG}/deletion`, token, body, header(approval));
const exportFrom = (path: string, token: string, body: Record<string, unknown>, approval?: string) =>
  call("POST", `${path}/disclosures`, token, { purpose: "export", ...body }, header(approval));

const item = (name: string, sensitive: boolean) => ({ name, required: { kind: "never" }, sensitive, type: "string" });
const CONTRACT = { schemaVersion: 1, items: [item("HOST", false), item("DB_PASS", true), item("TOKEN", true), item("API_KEY", true), item("NEW_SECRET", true)] };

/** The SQL of the next retrieval snapshot, from its BEGIN ... READ ONLY to its COMMIT. */
function recordSnapshot() {
  const original = ctx.db.query.bind(ctx.db);
  const seen: string[] = [];
  let state: "before" | "in" | "ended" = "before";
  ctx.db.query = (async (text: string, params?: unknown[]) => {
    if (state === "before" && text.startsWith("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")) state = "in";
    else if (state === "in" && text.trim() === "COMMIT") state = "ended";
    else if (state === "in") seen.push(text);
    return original(text, params);
  }) as typeof ctx.db.query;
  return { statements: seen, restore: () => { ctx.db.query = original; } };
}

const SNAPSHOT_BEGIN = (text: string) => text.startsWith("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");

/**
 * Runs `request`, pausing it at one statement: after the COMMIT of its
 * retrieval snapshot (`"snapshot"`, before its phase 2), or before its
 * first plain BEGIN (`"transaction"`). Meanwhile `change` runs, from this
 * test's own flow, as a concurrent writer that commits between the two
 * would on a connection of its own (PGlite has one, shared by flows:
 * db/tx.ts). Then the request goes on.
 */
async function interleave<T>(at: "snapshot" | "transaction", request: () => Promise<T>, change: () => Promise<unknown>): Promise<T> {
  const original = ctx.db.query.bind(ctx.db);
  let reached!: () => void;
  const reachedP = new Promise<void>((r) => (reached = r));
  let release!: () => void;
  const releaseP = new Promise<void>((r) => (release = r));
  let inSnapshot = false;
  ctx.db.query = (async (text: string, params?: unknown[]) => {
    if (at === "transaction" && text.trim() === "BEGIN") {
      ctx.db.query = original;
      reached();
      await releaseP;
      return original(text, params);
    }
    if (at === "snapshot" && SNAPSHOT_BEGIN(text)) inSnapshot = true;
    const res = await original(text, params);
    if (inSnapshot && text.trim() === "COMMIT") {
      ctx.db.query = original;
      reached();
      await releaseP;
    }
    return res;
  }) as typeof ctx.db.query;
  const running = request();
  try {
    await Promise.race([reachedP, running]);
    await change();
  } finally {
    ctx.db.query = original;
    release();
  }
  return running;
}

const WRITE = /^\s*(INSERT|UPDATE|DELETE|MERGE|SELECT\s+nextval|SELECT[^]*FOR\s+(UPDATE|NO KEY UPDATE|SHARE|KEY SHARE))/i;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const { identityId } = await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" });
  app = buildApp(ctx, { publicUrl: PUBLIC_URL, clientAddress: () => "203.0.113.7" });
  admin = await person(identityId);
  orgId = (await ok("POST", "/v1/organizations", admin.cli, { name: "Acme", slug: "acme" })).id;
  projectId = (await ok("POST", `${ORG}/projects`, admin.cli, { name: "API", slug: "api", contractAuthority: "managed" })).id;
  prodId = (await ok("POST", `${P}/environments`, admin.cli, { name: "production", tier: "production" })).id;
  previewId = (await ok("POST", `${P}/environments`, admin.cli, { name: "production/pr-1", kind: "preview", parentEnvironmentId: prodId })).id;
  const revision = await ok("POST", `${P}/contract/revisions`, admin.cli, { contract: CONTRACT });
  await ok("POST", `${P}/contract/revisions/${revision.id}/activate`, admin.cli, {});
  for (const [name, value] of [["HOST", "db.internal"], ["DB_PASS", "hunter2"], ["TOKEN", "tok-old"], ["API_KEY", "key-prod"]]) {
    await ok("PUT", `${PROD}/values/${name}`, admin.cli, { value });
  }
  // The preview overrides API_KEY; DB_PASS and TOKEN come from production.
  await ok("PUT", `${PREVIEW}/values/API_KEY`, admin.cli, { value: "key-preview" });
});
afterEach(async () => {
  await ctx.close();
});

describe("admin-step-up's enforce, set through the API (unlocked in step 4.9)", () => {
  it("is accepted as tightening, without an approval; project.delete then asks for one", async () => {
    expect(ENFORCEABLE_CONTROLS.has("admin-step-up")).toBe(true);
    const res = await setMode("admin-step-up", "enforce");
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body).toMatchObject({ changed: true, loosened: false, control: { mode: "enforce" } });
    expect(stepUp(await deleteProject(admin.cli)).operation).toBe("project.delete");
  });
});

describe("with every control off", () => {
  it("exports, deletes a Project and schedules the deletion as before: no approval, no count, no intent, audit as before", async () => {
    const exported = await exportFrom(PREVIEW, admin.web, { scope: "all-authorized-secrets" });
    expect(exported.status).toBe(200);
    expect(exported.body.items.map((i: { name: string; value: string }) => [i.name, i.value])).toEqual([
      ["API_KEY", "key-preview"], ["DB_PASS", "hunter2"], ["TOKEN", "tok-old"],
    ]);
    expect(Object.keys((await events("secret.disclosed")).at(-1)!.metadata).sort()).toEqual(["items", "mode", "purpose", "withheld"]);

    const deleted = await ok("DELETE", `${ORG}/projects/api`, admin.cli);
    expect(deleted).toEqual({ projectId, slug: "api", environments: 2, values: 5, versionsErased: 5, capabilitiesRevoked: 0, targetsRevoked: 0, teamLinksRemoved: 0 });
    expect((await events("project.deleted")).at(-1)!.metadata).not.toHaveProperty("approvalId");

    const scheduled = await call("POST", `${ORG}/deletion`, admin.cli, {});
    expect(scheduled.status).toBe(201);
    expect(scheduled.body).toMatchObject({ approvalRequired: false, approvedBy: null });
    expect(Object.keys((await events("organization.deletion_scheduled")).at(-1)!.metadata).sort()).toEqual(
      ["approvalRequired", "identitiesSuspended", "invitationsRevoked", "runAfter", "targetsPaused", "webhooksSuspended"],
    );
    expect(await intents()).toBe(0);
    expect(await counters()).toBe(0);
  });

  it("ignores a malformed Varlatch-Approval header, as before", async () => {
    expect((await exportFrom(PROD, admin.web, { items: ["DB_PASS"] }, "invalid")).status).toBe(200);
    expect((await deleteProject(admin.cli, "invalid")).status).toBe(200);
    expect((await schedule(admin.cli, {}, "invalid")).status).toBe(201);
    expect(await intents()).toBe(0);
  });
});

describe("in report mode", () => {
  it("refuses nothing and counts each operation, by a person and by a machine; other disclosures are not counted", async () => {
    const bot = await ok("POST", `${ORG}/identities`, admin.cli, { name: "robot", kind: "service" });
    await ok("POST", `${ORG}/grants`, admin.cli, { subjectIdentityId: bot.id, scope: { kind: "project", projectId }, actions: ["secret.reveal", "project.manage"] });
    expect((await setMode("admin-step-up", "report")).status).toBe(200);
    expect((await exportFrom(PROD, admin.web, { items: ["DB_PASS"] })).status).toBe(200);
    expect((await exportFrom(PROD, bot.credential, { items: ["DB_PASS"] })).status).toBe(200);
    expect((await call("POST", `${PROD}/disclosures`, admin.cli, { items: ["DB_PASS"] })).status).toBe(200);
    expect((await call("POST", `${PROD}/disclosures`, admin.cli, { items: ["DB_PASS"], purpose: "scan" })).status).toBe(200);
    expect((await deleteProject(admin.cli)).status).toBe(200);
    expect((await schedule(admin.cli, { afterDays: 3 })).status).toBe(201);
    // Refused (already being deleted): not counted.
    expect((await schedule(admin.cli, {})).status).toBe(409);
    expect(await intents()).toBe(0);
    expect(
      await rows("SELECT operation, reason, actor_identity_id, count::int AS count FROM security_control_counters WHERE control = 'admin-step-up' ORDER BY operation, reason"),
    ).toEqual([
      { operation: "organization.delete", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
      { operation: "project.delete", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
      { operation: "secret.export", reason: "machine-credential", actor_identity_id: bot.id, count: 1 },
      { operation: "secret.export", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
    ]);
  });
});

describe("under enforce", () => {
  beforeEach(async () => {
    await enforceAdminStepUp();
  });

  it("asks for an approval for each operation, with its summary, and changes nothing without one", async () => {
    const del = stepUp(await deleteProject(admin.cli));
    expect(del).toMatchObject({ operation: "project.delete", organization: { id: orgId, slug: "acme" }, state: "pending" });
    expect(del.summary).toEqual({
      title: `Delete the project "API" (${projectId}), slug "api", now: 2 environments and their values erased. This cannot be undone`,
      changes: [],
    });
    const org = stepUp(await schedule(admin.cli, { afterDays: 3 }));
    expect(org).toMatchObject({ operation: "organization.delete" });
    expect(org.summary).toEqual({
      title: `Schedule the deletion of organization "Acme" (${orgId}) in 3 days`,
      changes: [{ field: "afterDays", from: null, to: "3 days", loosens: false }],
    });
    const exp = stepUp(await exportFrom(PREVIEW, admin.web, { scope: "all-authorized-secrets" }));
    expect(exp).toMatchObject({ operation: "secret.export" });
    expect(exp.summary).toEqual({
      title: `Export 3 Secrets of project "API" (${projectId}) / environment "production/pr-1" (${previewId}) to a file: ["API_KEY", "DB_PASS", "TOKEN"]`,
      changes: [
        { field: "selection", from: null, to: "every Secret you may reveal", loosens: false },
        { field: "disclosed", from: null, to: '["API_KEY", "DB_PASS", "TOKEN"]', loosens: false },
      ],
    });
    const items = stepUp(await exportFrom(PROD, admin.cli, { items: ["TOKEN", "HOST", "DB_PASS", "TOKEN"] }));
    expect(items.summary).toEqual({
      title: `Export 2 Secrets of project "API" (${projectId}) / environment "production" (${prodId}) to a file: ["DB_PASS", "TOKEN"]`,
      changes: [
        { field: "selection", from: null, to: "the Secrets requested", loosens: false },
        { field: "requested", from: null, to: '["DB_PASS", "HOST", "TOKEN"]', loosens: false },
        { field: "disclosed", from: null, to: '["DB_PASS", "TOKEN"]', loosens: false },
      ],
    });
    // Nothing happened: no deletion, no disclosure, nothing counted.
    expect(await count("SELECT count(*)::int AS n FROM projects WHERE deleted_at IS NULL")).toBe(1);
    expect(await count("SELECT count(*)::int AS n FROM organization_deletions")).toBe(0);
    expect(await events("secret.disclosed")).toEqual([]);
    expect(await counters()).toBe(0);
  });

  it("names the Organization's other admin in the deletion's summary", async () => {
    await invite("Carol", "admin");
    expect(stepUp(await schedule(admin.cli, {})).summary.title).toBe(
      `Schedule the deletion of organization "Acme" (${orgId}) in 7 days. Another admin must approve it before it can run`,
    );
  });

  it("runs each operation with its approval, once, and records the approval in the audit", async () => {
    const exportAsk = (approval?: string) => exportFrom(PREVIEW, admin.web, { scope: "all-authorized-secrets" }, approval);
    const exported = await exportAsk(await approved(admin, await exportAsk()));
    expect(exported.status, JSON.stringify(exported.body)).toBe(200);
    expect(exported.body.items.map((i: { name: string; value: string }) => [i.name, i.value])).toEqual([
      ["API_KEY", "key-preview"], ["DB_PASS", "hunter2"], ["TOKEN", "tok-old"],
    ]);
    expect((await events("secret.disclosed")).at(-1)!.metadata).toMatchObject({ purpose: "export", approvalId: expect.any(String), approvalUserVerified: true });

    // Used once: a second use is refused.
    const again = exportAsk((await rows("SELECT id FROM approval_intents WHERE operation = 'secret.export'"))[0].id);
    invalid(await again, "consumed");

    const del = await approved(admin, await deleteProject(admin.cli));
    expect((await deleteProject(admin.cli, del)).status).toBe(200);
    expect((await events("project.deleted")).at(-1)!.metadata).toMatchObject({ approvalId: del, approvalUserVerified: true });

    const org = await approved(admin, await schedule(admin.cli, {}));
    expect((await schedule(admin.cli, {}, org)).status).toBe(201);
    expect((await events("organization.deletion_scheduled")).at(-1)!.metadata).toMatchObject({ approvalId: org });
    expect(await count("SELECT count(*)::int AS n FROM approval_intents WHERE consumed_at IS NOT NULL")).toBe(3);
    expect(await counters()).toBe(0);
  });

  it("project.delete binds the Project: another one refuses it", async () => {
    await ok("POST", `${ORG}/projects`, admin.cli, { name: "Web", slug: "web", contractAuthority: "managed" });
    const asked = await approved(admin, await deleteProject(admin.cli));
    invalid(await deleteProject(admin.cli, asked, "web"), "mismatch");
    expect((await intentState(asked)).consumed).toBe(false);
    const [intent] = await rows("SELECT target, expected_version FROM approval_intents WHERE id = $1", [asked]);
    expect(parse(intent.target)).toEqual({ projectId });
    expect(intent.expected_version).toBeNull();
  });

  it("project.delete checks project.manage again once the approval is consumed: refused, the approval unused", async () => {
    const bob = await invite("Bob", "member");
    await ctx.db.query("UPDATE security_controls SET mode = 'off' WHERE organization_id = $1", [orgId]);
    const grant = await ok("POST", `${ORG}/grants`, admin.cli, { subjectIdentityId: bob.id, scope: { kind: "project", projectId }, actions: ["project.manage"] });
    await enforceAdminStepUp();
    const asked = await approved(bob, await deleteProject(bob.cli));
    // The Grant is revoked after the route's own check, before the
    // deletion's transaction: the recheck after the consumption sees it.
    const res = await interleave("transaction", () => deleteProject(bob.cli, asked), () =>
      ctx.db.query("UPDATE grants SET revoked_at = now() WHERE id = $1", [grant.id]));
    expect([403, 404], JSON.stringify(res.body)).toContain(res.status);
    expect((await intentState(asked)).consumed).toBe(false);
    expect(await count("SELECT count(*)::int AS n FROM projects WHERE deleted_at IS NULL")).toBe(1);
  });

  it("organization.delete binds afterDays: a left-out one binds 7, another number refuses it", async () => {
    const seven = await approved(admin, await schedule(admin.cli, {}));
    invalid(await schedule(admin.cli, { afterDays: 3 }, seven), "mismatch");
    const [intent] = await rows("SELECT target, expected_version FROM approval_intents WHERE id = $1", [seven]);
    expect(parse(intent.target)).toEqual({ organizationId: orgId });
    expect(intent.expected_version).toBeNull();
    // The same approval, with afterDays sent explicitly as 7.
    expect((await schedule(admin.cli, { afterDays: 7 }, seven)).status).toBe(201);
  });

  it("organization.delete: the step-up neither shortens the waiting period nor replaces the second admin, and afterDays is not a timestamp", async () => {
    const carol = await invite("Carol", "admin");
    const asked = await approved(admin, await schedule(admin.cli, { afterDays: 2 }));
    // The approval is used a while after it was asked for: the waiting
    // period still starts when the scheduling commits.
    await ctx.db.query("UPDATE approval_intents SET created_at = created_at - interval '8 minutes' WHERE id = $1", [asked]);
    const scheduled = await schedule(admin.cli, { afterDays: 2 }, asked);
    expect(scheduled.status, JSON.stringify(scheduled.body)).toBe(201);
    expect(scheduled.body).toMatchObject({ approvalRequired: true, approvedBy: null });
    const [row] = await rows(
      `SELECT extract(epoch FROM d.run_after - d.scheduled_at)::int AS wait, d.run_after > a.created_at + interval '2 days' AS after_intent
       FROM organization_deletions d, approval_intents a WHERE a.id = $1`,
      [asked],
    );
    expect(row).toEqual({ wait: 2 * 86_400, after_intent: true });
    // Not due: the worker does nothing, approved or not.
    expect(await finalizeDeletion(ctx, scheduled.body.id, orgId)).toBeNull();
    // The requester's step-up is not the second admin's approval.
    const self = await call("POST", `${ORG}/deletion/${scheduled.body.id}/approve`, admin.cli);
    expect(self.status).toBe(403);
    // The second admin approves with no step-up of their own.
    const before = await intents();
    expect((await call("POST", `${ORG}/deletion/${scheduled.body.id}/approve`, carol.cli)).status).toBe(200);
    expect(await intents()).toBe(before);
    expect(await finalizeDeletion(ctx, scheduled.body.id, orgId)).toBeNull();
    // Cancelling needs no step-up either.
    expect((await call("POST", `${ORG}/deletion/${scheduled.body.id}/cancel`, admin.cli)).status).toBe(200);
    expect(await intents()).toBe(before);
  });

  it("refuses an open deletion and a non-admin before asking for an approval", async () => {
    const bob = await invite("Bob", "member");
    const before = await intents();
    expect((await schedule(bob.cli, {})).status).toBe(403);
    expect(await intents()).toBe(before);
    // Scheduled directly while the control was off, then asked again.
    await ctx.db.query("UPDATE security_controls SET mode = 'off' WHERE organization_id = $1", [orgId]);
    expect((await schedule(admin.cli, {})).status).toBe(201);
    await enforceAdminStepUp();
    expect((await schedule(admin.cli, {})).body.error.code).toBe("STATE_CHANGED");
    // A Project of a deleting Organization cannot be deleted: refused first.
    expect((await deleteProject(admin.cli)).body.error.code).toBe("ORGANIZATION_DELETING");
    expect(await intents()).toBe(before);
  });

  it("refuses a machine credential outright, without an intent; its other disclosures stay exempt", async () => {
    await ctx.db.query("UPDATE security_controls SET mode = 'off' WHERE organization_id = $1", [orgId]);
    const bot = await ok("POST", `${ORG}/identities`, admin.cli, { name: "robot", kind: "service" });
    await ok("POST", `${ORG}/grants`, admin.cli, { subjectIdentityId: bot.id, scope: { kind: "project", projectId }, actions: ["secret.reveal", "project.manage"] });
    await enforceAdminStepUp();
    for (const res of [await exportFrom(PROD, bot.credential, { items: ["DB_PASS"] }), await deleteProject(bot.credential)]) {
      expect(res.status, JSON.stringify(res.body)).toBe(403);
      expect(res.body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "machine-credential" } });
    }
    expect(await events("secret.disclosed")).toEqual([]);
    expect((await call("POST", `${PROD}/disclosures`, bot.credential, { items: ["DB_PASS"] })).status).toBe(200);
    expect(await intents()).toBe(0);
  });

  it("exempts other disclosures, an export that discloses no Secret, and the export's non-sensitive read", async () => {
    expect((await call("POST", `${PROD}/disclosures`, admin.cli, { items: ["DB_PASS"] })).status).toBe(200);
    expect((await call("POST", `${PROD}/disclosures`, admin.cli, { items: ["DB_PASS"], purpose: "scan" })).status).toBe(200);
    expect((await exportFrom(PROD, admin.cli, { items: ["HOST"] })).body).toMatchObject({ items: [], withheld: ["HOST"] });
    expect((await call("GET", `${PROD}/effective-configuration?include=values&purpose=export`, admin.web)).status).toBe(200);
    expect(await intents()).toBe(0);
  });

  it("secret.export binds the environment, the selection mode, the requested names and the exact disclosed set", async () => {
    const asked = await approved(admin, await exportFrom(PROD, admin.cli, { items: ["TOKEN", "DB_PASS"] }));
    const [intent] = await rows("SELECT target, expected_version FROM approval_intents WHERE id = $1", [asked]);
    expect(parse(intent.target)).toEqual({ projectId, environmentId: prodId });
    // Another environment, another selection mode with the same names, other names: refused.
    invalid(await exportFrom(PREVIEW, admin.cli, { items: ["TOKEN", "DB_PASS"] }, asked), "mismatch");
    await ctx.db.query("UPDATE env_values SET deleted_at = now(), current_version_id = NULL WHERE item_name = 'API_KEY'");
    invalid(await exportFrom(PROD, admin.cli, { scope: "all-authorized-secrets" }, asked), "mismatch");
    invalid(await exportFrom(PROD, admin.cli, { items: ["DB_PASS"] }, asked), "mismatch");
    // Without the purpose it is no export: no approval needed, and this one stays unused.
    expect((await call("POST", `${PROD}/disclosures`, admin.cli, { items: ["DB_PASS", "TOKEN"] }, header(asked))).status).toBe(200);
    expect((await intentState(asked)).consumed).toBe(false);
    // Reordered and repeated names bind the same.
    const res = await exportFrom(PROD, admin.cli, { items: ["DB_PASS", "TOKEN", "DB_PASS"] }, asked);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect((await intentState(asked)).consumed).toBe(true);
  });

  it("an 'all authorized' set that grew after the intent needs a new approval, as does a requested name that became disclosable", async () => {
    const all = await approved(admin, await exportFrom(PROD, admin.cli, { scope: "all-authorized-secrets" }));
    const some = await approved(admin, await exportFrom(PROD, admin.cli, { items: ["DB_PASS", "NEW_SECRET"] }));
    await ok("PUT", `${PROD}/values/NEW_SECRET`, admin.cli, { value: "fresh" });
    invalid(await exportFrom(PROD, admin.cli, { scope: "all-authorized-secrets" }, all), "mismatch");
    invalid(await exportFrom(PROD, admin.cli, { items: ["DB_PASS", "NEW_SECRET"] }, some), "mismatch");
    const fresh = stepUp(await exportFrom(PROD, admin.cli, { scope: "all-authorized-secrets" }));
    expect(fresh.summary.title).toContain('["API_KEY", "DB_PASS", "NEW_SECRET", "TOKEN"]');
  });

  it("writes nothing inside the retrieval snapshot, asking or approved: the intent is created after it", async () => {
    const asking = recordSnapshot();
    const asked = stepUp(await exportFrom(PROD, admin.web, { items: ["DB_PASS"] }));
    asking.restore();
    expect(asking.statements.length).toBeGreaterThan(0);
    expect(asking.statements.filter((s) => WRITE.test(s))).toEqual([]);
    await approve(admin, asked.id);
    const using = recordSnapshot();
    expect((await exportFrom(PROD, admin.web, { items: ["DB_PASS"] }, asked.id)).status).toBe(200);
    using.restore();
    expect(using.statements.filter((s) => WRITE.test(s))).toEqual([]);
  });

  describe("a stale capture: refused with STATE_CHANGED before the commit and any decryption, the approval still usable", () => {
    /**
     * Ask and approve an export, change the state between its snapshot and
     * its phase 2, check the refusal, then repeat with the same approval:
     * a fresh capture of the same names is disclosed.
     */
    async function staleThenFresh(path: string, body: Record<string, unknown>, change: () => Promise<unknown>) {
      const asked = await approved(admin, await exportFrom(path, admin.web, body));
      const disclosedBefore = (await events("secret.disclosed")).length;
      const stale = await interleave("snapshot", () => exportFrom(path, admin.web, body, asked), change);
      expect(stale.status, JSON.stringify(stale.body)).toBe(409);
      expect(stale.body.error).toMatchObject({ code: "STATE_CHANGED", details: { reason: "stale-capture", approvalId: asked } });
      expect(stale.body).not.toHaveProperty("items");
      expect((await events("secret.disclosed")).length).toBe(disclosedBefore);
      expect(await intentState(asked)).toEqual({ approved: true, consumed: false, close_reason: null });
      const fresh = await exportFrom(path, admin.web, body, asked);
      expect(fresh.status, JSON.stringify(fresh.body)).toBe(200);
      expect((await intentState(asked)).consumed).toBe(true);
      return fresh.body.items as { name: string; value: string; retiring?: { value: string } }[];
    }

    it("a rotation started", async () => {
      const items = await staleThenFresh(PROD, { items: ["TOKEN"] }, () => ok("POST", `${PROD}/values/TOKEN/rotations`, admin.cli, { value: "tok-new" }));
      expect(items).toEqual([expect.objectContaining({ name: "TOKEN", value: "tok-new", retiring: expect.objectContaining({ value: "tok-old" }) })]);
    });

    it("a rotation completed", async () => {
      await ok("POST", `${PROD}/values/TOKEN/rotations`, admin.cli, { value: "tok-new" });
      const items = await staleThenFresh(PROD, { items: ["TOKEN"] }, () => ok("POST", `${PROD}/values/TOKEN/rotations/complete`, admin.cli, {}));
      expect(items).toEqual([expect.objectContaining({ name: "TOKEN", value: "tok-new" })]);
      expect(items[0]).not.toHaveProperty("retiring");
    });

    it("a retiring version whose deadline passed", async () => {
      await ok("POST", `${PROD}/values/TOKEN/rotations`, admin.cli, { value: "tok-new" });
      const items = await staleThenFresh(PROD, { items: ["TOKEN"] }, () =>
        ctx.db.query("UPDATE env_values SET rotation_deadline = now() - interval '1 second' WHERE item_name = 'TOKEN'"));
      expect(items[0]).not.toHaveProperty("retiring");
    });

    it("a child override of a parent's value created", async () => {
      const items = await staleThenFresh(PREVIEW, { items: ["DB_PASS"] }, () => ok("PUT", `${PREVIEW}/values/DB_PASS`, admin.cli, { value: "preview-pass" }));
      expect(items).toEqual([expect.objectContaining({ name: "DB_PASS", value: "preview-pass" })]);
    });

    it("a child override removed", async () => {
      const items = await staleThenFresh(PREVIEW, { items: ["API_KEY"] }, () => call("DELETE", `${PREVIEW}/values/API_KEY`, admin.cli));
      expect(items).toEqual([expect.objectContaining({ name: "API_KEY", value: "key-prod" })]);
    });

    it("a new Contract Revision", async () => {
      const items = await staleThenFresh(PROD, { items: ["DB_PASS"] }, async () => {
        const revision = await ok("POST", `${P}/contract/revisions`, admin.cli, { contract: { ...CONTRACT, items: [...CONTRACT.items, item("EXTRA", false)] } });
        await ok("POST", `${P}/contract/revisions/${revision.id}/activate`, admin.cli, {});
      });
      expect(items).toEqual([expect.objectContaining({ name: "DB_PASS", value: "hunter2" })]);
    });

    it("a new value", async () => {
      const items = await staleThenFresh(PROD, { items: ["DB_PASS"] }, () => ok("PUT", `${PROD}/values/DB_PASS`, admin.cli, { value: "changed" }));
      expect(items).toEqual([expect.objectContaining({ name: "DB_PASS", value: "changed" })]);
    });
  });

  it("decides secret.reveal again in phase 2: a revocation after the snapshot refuses, the approval unused", async () => {
    const bob = await invite("Bob", "member");
    await ctx.db.query("UPDATE security_controls SET mode = 'off' WHERE organization_id = $1", [orgId]);
    const grant = await ok("POST", `${ORG}/grants`, admin.cli, { subjectIdentityId: bob.id, scope: { kind: "project", projectId }, actions: ["secret.reveal", "config.metadata.read"] });
    await enforceAdminStepUp();
    const asked = await approved(bob, await exportFrom(PROD, bob.web, { items: ["DB_PASS"] }));
    const res = await interleave("snapshot", () => exportFrom(PROD, bob.web, { items: ["DB_PASS"] }, asked), () =>
      ctx.db.query("UPDATE grants SET revoked_at = now() WHERE id = $1", [grant.id]));
    expect([403, 404]).toContain(res.status);
    expect(res.body).not.toHaveProperty("items");
    expect((await intentState(asked)).consumed).toBe(false);
    expect(await events("secret.disclosed")).toEqual([]);
  });

  it("decides passkey-verification again in phase 2, under the Organization lock: turned on after the snapshot, it refuses, the approval unused and no intent created", async () => {
    const enforceVerification = () =>
      ctx.db.query(
        `INSERT INTO security_controls (organization_id, control, mode, config, version, changed_by, changed_at)
         VALUES ($1, 'passkey-verification', 'enforce', NULL, 1, $2, now())
         ON CONFLICT (organization_id, control) DO UPDATE SET mode = 'enforce', version = security_controls.version + 1`,
        [orgId, admin.id],
      );
    const refused = (res: Answer) => {
      expect(res.status, JSON.stringify(res.body)).toBe(403);
      expect(res.body.error.code).toBe("PASSKEY_VERIFICATION_REQUIRED");
      expect(res.body).not.toHaveProperty("items");
    };
    // With an approval: refused before its consumption.
    const asked = await approved(admin, await exportFrom(PROD, admin.web, { items: ["DB_PASS"] }));
    refused(await interleave("snapshot", () => exportFrom(PROD, admin.web, { items: ["DB_PASS"] }, asked), enforceVerification));
    expect(await intentState(asked)).toEqual({ approved: true, consumed: false, close_reason: null });
    // Without one: refused before the binding, so no intent is created.
    await ctx.db.query("UPDATE security_controls SET mode = 'off' WHERE organization_id = $1 AND control = 'passkey-verification'", [orgId]);
    const before = await intents();
    refused(await interleave("snapshot", () => exportFrom(PROD, admin.web, { items: ["DB_PASS"] }), enforceVerification));
    expect(await intents()).toBe(before);
    expect(await events("secret.disclosed")).toEqual([]);
  });

  it("is turned off by the operator's reset, which closes the open approvals of these operations", async () => {
    const asked = [
      stepUp(await deleteProject(admin.cli)),
      stepUp(await schedule(admin.cli, {})),
      stepUp(await exportFrom(PROD, admin.cli, { items: ["DB_PASS"] })),
    ];
    const outcome = await resetControls(ctx, { organization: "acme", controls: ["admin-step-up"] });
    expect(outcome.approvalsClosed).toBe(3);
    expect(await rows("SELECT id, close_reason FROM approval_intents ORDER BY id")).toEqual(
      asked.map((a) => a.id).sort().map((id) => ({ id, close_reason: "reset" })),
    );
    expect((await exportFrom(PROD, admin.cli, { items: ["DB_PASS"] })).status).toBe(200);
  });

  it("the incident freeze: all three answer it first, with no intent, and a pending approval is closed", async () => {
    for (const op of ["project.delete", "organization.delete", "secret.export"] as const) expect(OPERATIONS_DURING_FREEZE.has(op)).toBe(false);
    const pending = await approved(admin, await exportFrom(PROD, admin.cli, { items: ["DB_PASS"] }));
    expect((await call("POST", `${ORG}/incident-freeze`, admin.cli, { reason: "A CI token leaked" })).status).toBe(201);
    expect((await intentState(pending)).close_reason).toBe("frozen");
    const before = await intents();
    for (const res of [
      await deleteProject(admin.cli),
      await schedule(admin.cli, {}),
      await exportFrom(PROD, admin.cli, { items: ["DB_PASS"] }),
      await exportFrom(PROD, admin.cli, { items: ["DB_PASS"] }, pending),
    ]) {
      expect(res.body.error.code, JSON.stringify(res.body)).toBe("ORGANIZATION_FROZEN");
    }
    expect(await intents()).toBe(before);
  });

  it("exports during a pending deletion, which still allows reads, with an approval", async () => {
    await ctx.db.query("UPDATE security_controls SET mode = 'off' WHERE organization_id = $1", [orgId]);
    expect((await schedule(admin.cli, {})).status).toBe(201);
    await enforceAdminStepUp();
    const asked = await approved(admin, await exportFrom(PROD, admin.web, { items: ["DB_PASS"] }));
    expect((await exportFrom(PROD, admin.web, { items: ["DB_PASS"] }, asked)).status).toBe(200);
  });
});
