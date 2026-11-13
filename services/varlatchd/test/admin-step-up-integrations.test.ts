// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { CONTROL_APPROVAL_OPERATIONS, OPERATIONS_DURING_FREEZE } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { sweepExpiredRegistrations } from "../src/domain/githubapps.js";
import { labelWithId } from "../src/domain/approvallabels.js";
import { ENFORCEABLE_CONTROLS, resetControls } from "../src/domain/securitycontrols.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { fakeGitHubApps } from "./helpers/fake-github-app.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * admin-step-up for integrations (ADR-0054 step 4.8), on PGlite under the
 * lock-order check (test/helpers/lock-trace.ts): webhooks, Platform
 * Connections and every GitHub App path, registration's staged attachment
 * and the secret-bearing requests included. The API still refuses
 * `enforce` for admin-step-up (it is unlocked in step 4.9), so these tests
 * set it directly in the database. With every control off nothing
 * changes; report mode counts and refuses nothing; under enforce each
 * operation needs the requester's approval bound to exactly that request,
 * as the binding catalogue says, and a machine credential is refused
 * without an intent. GitHub is a fake: import, key replacement and an App
 * Connection must not call it before the precheck. The races of
 * attachment with discard and the expiry sweep run on real PostgreSQL in
 * admin-step-up-integrations-postgres.test.ts.
 */

const ORG = "/v1/organizations/acme";
const CONTROLS = `${ORG}/security/controls`;
const HOOK = "https://sink.example/services/T000/hook-secret-token-1";
const HOOK_2 = "https://sink.example/services/T000/hook-secret-token-2";
const CREDENTIAL = "ghp_secretcredential000000000000000001";
const CREDENTIAL_2 = "ghp_secretcredential000000000000000002";
const OWNER = { login: "acme-gh", id: 1009, type: "Organization" as const };
const PERMISSIONS = { secrets: "write", environments: "write", metadata: "read" };

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let orgId: string;
let admin: Person;
let github: ReturnType<typeof fakeGitHubApps>;
/** Codes GitHub's conversion endpoint was called with: the callback's one-use artifact. */
let conversions: string[];
/** The PEM each converted App's key has, by GitHub App id. */
let convertedKeys: Map<number, string>;
let nextAppId: number;
/** Runs when GitHub hands over an App, before the answer returns (a test hook). */
let onConversion: (() => Promise<void>) | null;

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
const json = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v);

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

async function controlOf(control: string) {
  return (await ok("GET", CONTROLS, admin.cli)).items.find((i: { control: string }) => i.control === control);
}
const setMode = async (control: string, mode: string) =>
  call("PATCH", `${CONTROLS}/${control}`, admin.cli, { mode, expectedVersion: (await controlOf(control)).version });

/** admin-step-up at enforce, written directly: the API refuses it until step 4.9. */
async function enforceAdminStepUp() {
  await ctx.db.query(
    `INSERT INTO security_controls (organization_id, control, mode, config, version, changed_by, changed_at)
     VALUES ($1, 'admin-step-up', 'enforce', NULL, 1, $2, now())
     ON CONFLICT (organization_id, control) DO UPDATE SET mode = 'enforce', version = security_controls.version + 1`,
    [orgId, admin.id],
  );
}

function stepUp(res: Answer) {
  expect(res.status, JSON.stringify(res.body)).toBe(403);
  expect(res.body.error.code).toBe("STEP_UP_REQUIRED");
  return res.body.error.details.approval as { id: string; operation: string; summary: { title: string; changes: any[] }; state: string };
}

async function approve(p: Person, approvalId: string) {
  const started = await call("POST", `/v1/me/approvals/${approvalId}/options`, p.web);
  expect(started.status, JSON.stringify(started.body)).toBe(200);
  const approvedRes = await call("POST", `/v1/me/approvals/${approvalId}/approve`, p.web, {
    assertion: p.key.assert(started.body.publicKey.challenge, { userVerified: true }),
  });
  expect(approvedRes.status, JSON.stringify(approvedRes.body)).toBe(200);
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

const unconsumed = async (approvalId: string) =>
  expect((await rows("SELECT approved_at IS NOT NULL AS approved, consumed_at FROM approval_intents WHERE id = $1", [approvalId]))[0])
    .toEqual({ approved: true, consumed_at: null });

// ---- The operations, as their routes take them.
const createHook = (token: string, body: Record<string, unknown> = { url: HOOK }, approval?: string) =>
  call("POST", `${ORG}/webhooks`, token, body, header(approval));
const patchHook = (token: string, id: string, body: Record<string, unknown>, approval?: string, extra: Record<string, string> = {}) =>
  call("PATCH", `${ORG}/webhooks/${id}`, token, body, { ...header(approval), ...extra });
const deleteHook = (token: string, id: string, approval?: string) => call("DELETE", `${ORG}/webhooks/${id}`, token, undefined, header(approval));
const createConnection = (token: string, body: Record<string, unknown> = {}, approval?: string) =>
  call("POST", `${ORG}/platform-connections`, token, { platform: "github-actions", baseIdentity: "Acme", name: "GitHub", credential: CREDENTIAL, ...body }, header(approval));
const replaceCredential = (token: string, id: string, credential: string, expectedVersion: number, approval?: string) =>
  call("POST", `${ORG}/platform-connections/${id}/credential`, token, { credential, expectedVersion }, header(approval));
const revokeConnection = (token: string, id: string, approval?: string) =>
  call("DELETE", `${ORG}/platform-connections/${id}`, token, undefined, header(approval));
const createAppConnection = (token: string, installationId: number, name = "App", approval?: string) =>
  call("POST", `${ORG}/platform-connections`, token, { credentialKind: "github-app", installationId, name }, header(approval));
const importApp = (token: string, appId: number, privateKey: string, approval?: string) =>
  call("POST", `${ORG}/github-app/import`, token, { appId, privateKey }, header(approval));
const replaceKey = (token: string, privateKey: string, expectedVersion: number, approval?: string) =>
  call("POST", `${ORG}/github-app/key`, token, { privateKey, expectedVersion }, header(approval));
const removeApp = (token: string, appId: string, approval?: string) =>
  call("DELETE", `${ORG}/github-app?appId=${encodeURIComponent(appId)}`, token, undefined, header(approval));
const startRegistration = (token: string) =>
  ok("POST", `${ORG}/github-app/registrations`, token, { account: { login: OWNER.login, type: "organization" } }) as Promise<{ id: string; state: string }>;
const completeRegistration = (token: string, state: string, code = "code-1", approval?: string) =>
  call("POST", `${ORG}/github-app/registrations/complete`, token, { state, code }, header(approval));
const attach = (token: string, registrationId: string, approval?: string) =>
  call("POST", `${ORG}/github-app/registrations/${registrationId}/attach`, token, undefined, header(approval));
const discard = (token: string, registrationId: string) => call("DELETE", `${ORG}/github-app/registrations/${registrationId}`, token);

async function events(eventType: string) {
  return (await rows("SELECT actor_identity_id, metadata FROM audit_events WHERE event_type = $1 ORDER BY event_order", [eventType]))
    .map((r) => ({ actor: r.actor_identity_id as string | null, metadata: (json(r.metadata) as Record<string, any> | null) ?? {} }));
}
const liveApp = async () => (await rows("SELECT id, github_app_id, version FROM github_apps WHERE organization_id = $1 AND removed_at IS NULL", [orgId]))[0];
const registration = async (id: string) =>
  (await rows("SELECT converted_at IS NOT NULL AS converted, ended_at IS NOT NULL AS ended, end_reason, pending_key_envelope IS NOT NULL AS has_key FROM github_app_registrations WHERE id = $1", [id]))[0];
/** GitHub calls other than the conversion. */
const githubCalls = () => github.calls.filter((c) => !c.path.startsWith("/app-manifests/")).length;

/** An App registered on GitHub, ready to import: its id and first key. */
function githubApp(id = 7_000_001) {
  const pem = github.addApp({ id, slug: `imported-${id}`, clientId: `Iv1.imported${id}`, owner: OWNER, permissions: PERMISSIONS });
  return { id, pem };
}

/** A machine identity of the Organization holding the integration actions. */
async function robot() {
  // Set up with the control off, as an earlier step would have.
  const mode = (await rows("SELECT mode FROM security_controls WHERE organization_id = $1 AND control = 'admin-step-up'", [orgId]))[0]?.mode;
  await ctx.db.query("UPDATE security_controls SET mode = 'off' WHERE organization_id = $1", [orgId]);
  try {
    return await makeRobot();
  } finally {
    if (mode) await ctx.db.query("UPDATE security_controls SET mode = $2 WHERE organization_id = $1 AND control = 'admin-step-up'", [orgId, mode]);
  }
}
async function makeRobot() {
  const created = await ok("POST", `${ORG}/identities`, admin.cli, { name: "robot", kind: "service" });
  await ok("POST", `${ORG}/grants`, admin.cli, {
    subjectIdentityId: created.id,
    scope: { kind: "organization" },
    actions: ["organization.manage", "config.sync.manage"],
  });
  return { id: created.id as string, token: created.credential as string };
}

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const { identityId } = await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" });
  github = fakeGitHubApps();
  conversions = [];
  convertedKeys = new Map();
  nextAppId = 5_254_113;
  onConversion = null;
  // GitHub's manifest conversion: each code hands over a new App on acme-gh,
  // which the fake then knows (its key answers GET /app).
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const m = url.pathname.match(/^\/app-manifests\/([^/]+)\/conversions$/);
    if (m && init?.method === "POST") {
      github.calls.push({ method: "POST", path: url.pathname });
      conversions.push(decodeURIComponent(m[1]!));
      await onConversion?.();
      const id = nextAppId++;
      const pem = github.addApp({ id, slug: `varlatch-acme-${id}`, clientId: `Iv23li${id}`, owner: OWNER, permissions: PERMISSIONS });
      convertedKeys.set(id, pem);
      return Response.json({ id, slug: `varlatch-acme-${id}`, client_id: `Iv23li${id}`, client_secret: "not-kept", pem, owner: OWNER, permissions: PERMISSIONS }, { status: 201 });
    }
    return github.fetchImpl(input, init);
  }) as typeof fetch;
  app = buildApp(ctx, { publicUrl: PUBLIC_URL, clientAddress: () => "203.0.113.7", syncFetch: fetchImpl });
  admin = await person(identityId);
  orgId = (await ok("POST", "/v1/organizations", admin.cli, { name: "Acme", slug: "acme" })).id;
});
afterEach(async () => {
  await ctx.close();
});

/** Register an App through the manifest flow while no approval is needed. */
async function registerApp() {
  const started = await startRegistration(admin.cli);
  const res = await completeRegistration(admin.cli, started.state, `code-${started.id}`);
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return res.body.app as { id: string; githubAppId: number; version: number; slug: string };
}

describe("admin-step-up's enforce stays unavailable", () => {
  it("is refused by the API with CONTROL_MODE_UNAVAILABLE", async () => {
    expect(ENFORCEABLE_CONTROLS.has("admin-step-up")).toBe(false);
    const res = await setMode("admin-step-up", "enforce");
    expect(res.status).toBe(422);
    expect(res.body.error).toMatchObject({ code: "CONTROL_MODE_UNAVAILABLE" });
  });

  it("names the ten integration operations among those the operator's reset closes", () => {
    expect(CONTROL_APPROVAL_OPERATIONS["admin-step-up"]).toEqual(expect.arrayContaining([
      "webhook.create", "webhook.update", "webhook.delete",
      "connection.create", "connection.replace_credential", "connection.delete",
      "github_app.register", "github_app.import", "github_app.replace_key", "github_app.remove",
    ]));
  });
});

describe("with every control off", () => {
  it("runs every operation as before: no approval, no count, no intent, audit as before, registration in one request", async () => {
    const hook = (await createHook(admin.cli, { url: HOOK, eventTypes: ["grant.created"] })).body;
    expect(hook).toMatchObject({ url: HOOK, eventTypes: ["grant.created"], secret: expect.stringMatching(/^vlt_whsec_/) });
    expect((await patchHook(admin.cli, hook.id, { expectedVersion: 1, url: HOOK_2, eventTypes: null })).body).toMatchObject({ url: HOOK_2, eventTypes: null, version: 2 });
    expect((await deleteHook(admin.cli, hook.id)).status).toBe(204);
    const connection = (await createConnection(admin.cli)).body;
    expect(connection).toMatchObject({ platform: "github-actions", baseIdentity: "acme", name: "GitHub" });
    expect((await replaceCredential(admin.cli, connection.id, CREDENTIAL_2, 1)).body).toMatchObject({ version: 2 });
    expect((await revokeConnection(admin.cli, connection.id)).status).toBe(204);

    const registered = await registerApp();
    expect(conversions).toHaveLength(1);
    const installation = github.install(registered.githubAppId, OWNER);
    expect((await createAppConnection(admin.cli, installation)).status).toBe(201);
    const newKey = github.addKey(registered.githubAppId);
    expect((await replaceKey(admin.cli, newKey, registered.version)).body).toMatchObject({ outcome: "rotated" });
    const current = await liveApp();
    expect((await removeApp(admin.cli, current.id)).status).toBe(204);
    const imported = githubApp();
    expect((await importApp(admin.cli, imported.id, imported.pem)).body).toMatchObject({ outcome: "registered" });

    expect(await intents()).toBe(0);
    expect(await counters()).toBe(0);
    for (const type of ["webhook.created", "webhook.updated", "webhook.revoked", "sync.connection_created", "sync.connection_credential_replaced",
      "sync.connection_revoked", "sync.github_app_registered", "sync.github_app_key_rotated", "sync.github_app_removed"]) {
      const list = await events(type);
      expect(list.length, type).toBeGreaterThan(0);
      for (const e of list) expect(e.metadata, type).not.toHaveProperty("approvalId");
    }
    // The registration ended attached, its pending key deleted.
    expect(await rows("SELECT end_reason, pending_key_envelope FROM github_app_registrations")).toEqual([{ end_reason: "attached", pending_key_envelope: null }]);
    expect(await events("sync.github_app_registration_abandoned")).toEqual([]);
  });
});

describe("a replayed callback", () => {
  it("with every control off, answers CONSUMED as before: no details", async () => {
    const started = await startRegistration(admin.cli);
    expect((await completeRegistration(admin.cli, started.state, "code-once")).status).toBe(201);
    const replay = await completeRegistration(admin.cli, started.state, "code-once");
    expect(replay.status).toBe(410);
    expect(replay.body.error.code).toBe("CONSUMED");
    expect(replay.body.error).not.toHaveProperty("details");
    expect(conversions).toEqual(["code-once"]);
  });

  it("while a conversion is pending, names it, and spends nothing", async () => {
    await enforceAdminStepUp();
    const started = await startRegistration(admin.cli);
    stepUp(await completeRegistration(admin.cli, started.state, "code-once"));
    const replay = await completeRegistration(admin.cli, started.state, "code-once");
    expect(replay.body.error).toMatchObject({ code: "CONSUMED", details: { registrationId: started.id, pending: true } });
    expect(conversions).toEqual(["code-once"]);
    expect(await registration(started.id)).toMatchObject({ ended: false, has_key: true });
  });
});

describe("in report mode", () => {
  it("refuses nothing and counts each operation, by a person and by a machine; an unchanged webhook patch is not counted", async () => {
    const bot = await robot();
    expect((await setMode("admin-step-up", "report")).status).toBe(200);
    const hook = (await createHook(admin.cli)).body;
    expect((await patchHook(admin.cli, hook.id, { expectedVersion: 1, url: HOOK })).status).toBe(200);
    expect((await patchHook(admin.cli, hook.id, { expectedVersion: 1, eventTypes: ["grant.created"] })).status).toBe(200);
    expect((await deleteHook(admin.cli, hook.id)).status).toBe(204);
    const connection = (await createConnection(bot.token)).body;
    expect((await replaceCredential(admin.cli, connection.id, CREDENTIAL_2, 1)).status).toBe(200);
    expect((await revokeConnection(admin.cli, connection.id)).status).toBe(204);
    const registered = await registerApp();
    expect((await createAppConnection(admin.cli, github.install(registered.githubAppId, OWNER))).status).toBe(201);
    expect((await replaceKey(admin.cli, github.addKey(registered.githubAppId), registered.version)).status).toBe(200);
    expect((await removeApp(admin.cli, (await liveApp()).id)).status).toBe(204);
    const imported = githubApp();
    expect((await importApp(admin.cli, imported.id, imported.pem)).status).toBe(201);
    expect(await intents()).toBe(0);
    expect(
      await rows("SELECT operation, reason, actor_identity_id, count::int AS count FROM security_control_counters WHERE control = 'admin-step-up' ORDER BY operation, reason"),
    ).toEqual([
      { operation: "connection.create", reason: "machine-credential", actor_identity_id: bot.id, count: 1 },
      { operation: "connection.create", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
      { operation: "connection.delete", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
      { operation: "connection.replace_credential", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
      { operation: "github_app.import", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
      { operation: "github_app.register", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
      { operation: "github_app.remove", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
      { operation: "github_app.replace_key", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
      { operation: "webhook.create", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
      { operation: "webhook.delete", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
      { operation: "webhook.update", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
    ]);
  });
});

describe("under enforce", () => {
  beforeEach(async () => {
    await enforceAdminStepUp();
  });

  it("asks for each operation with a summary that shows every bound id and never a secret, and changes nothing without one", async () => {
    const hook = stepUp(await createHook(admin.cli, { url: HOOK, eventTypes: ["grant.created", "grant.revoked", "grant.created"] }));
    expect(hook).toMatchObject({ operation: "webhook.create", state: "pending" });
    expect(hook.summary).toEqual({
      title: `Send the audit events of organization "Acme" (${orgId}) to "https://sink.example/[redacted]" (event types ["grant.created", "grant.revoked"])`,
      changes: [
        { field: "url", from: null, to: '"https://sink.example/[redacted]"', loosens: false },
        { field: "eventTypes", from: null, to: 'event types ["grant.created", "grant.revoked"]', loosens: false },
      ],
    });
    const conn = stepUp(await createConnection(admin.cli));
    expect(conn.summary.title).toBe('Add connection "GitHub" on platform "github-actions" for base identity "acme", with a new credential');
    expect(conn.summary.changes).toContainEqual({ field: "credential", from: null, to: "a new value (not shown)", loosens: false });
    const imported = githubApp();
    const imp = stepUp(await importApp(admin.cli, imported.id, imported.pem));
    expect(imp.summary).toEqual({
      title: `Import GitHub App ${imported.id} with a private key`,
      changes: [
        { field: "appId", from: null, to: String(imported.id), loosens: false },
        { field: "privateKey", from: null, to: "a new value (not shown)", loosens: false },
      ],
    });
    expect(await count("SELECT count(*)::int AS n FROM webhooks")).toBe(0);
    expect(await count("SELECT count(*)::int AS n FROM platform_connections")).toBe(0);
    expect(await count("SELECT count(*)::int AS n FROM github_apps")).toBe(0);
    expect(githubCalls()).toBe(0);
    expect(await counters()).toBe(0);

    // No plaintext secret anywhere an intent, a counter or an audit event lives.
    const stored = JSON.stringify([
      await rows("SELECT * FROM approval_intents"),
      await rows("SELECT * FROM security_control_counters"),
      await rows("SELECT * FROM audit_events"),
    ]);
    for (const secret of ["hook-secret-token", CREDENTIAL, "PRIVATE KEY", imported.pem.slice(40, 80)]) expect(stored).not.toContain(secret);
  });

  it("runs each operation with its approval, once, and records the approval in the audit", async () => {
    const run = async (send: (approval?: string) => Promise<Answer>) => {
      const res = await send(await approved(admin, await send()));
      expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
      return res.body;
    };
    const hook = await run((a) => createHook(admin.cli, { url: HOOK }, a));
    await run((a) => patchHook(admin.cli, hook.id, { expectedVersion: 1, eventTypes: ["grant.created"] }, a));
    await run((a) => deleteHook(admin.web, hook.id, a));
    const connection = await run((a) => createConnection(admin.cli, {}, a));
    await run((a) => replaceCredential(admin.cli, connection.id, CREDENTIAL_2, 1, a));
    await run((a) => revokeConnection(admin.cli, connection.id, a));
    const imported = githubApp();
    await run((a) => importApp(admin.cli, imported.id, imported.pem, a));
    const appRow = await liveApp();
    const installation = github.install(imported.id, OWNER);
    await run((a) => createAppConnection(admin.cli, installation, "App", a));
    const newKey = github.addKey(imported.id);
    await run((a) => replaceKey(admin.cli, newKey, appRow.version, a));
    await run((a) => removeApp(admin.cli, appRow.id, a));

    expect(await count("SELECT count(*)::int AS n FROM approval_intents WHERE consumed_at IS NOT NULL")).toBe(10);
    for (const type of ["webhook.created", "webhook.updated", "webhook.revoked", "sync.connection_created", "sync.connection_credential_replaced",
      "sync.connection_revoked", "sync.github_app_registered", "sync.github_app_key_rotated", "sync.github_app_removed"]) {
      for (const e of await events(type)) expect(e.metadata, type).toMatchObject({ approvalId: expect.stringMatching(/^apr_/), approvalUserVerified: true });
    }
    expect(await counters()).toBe(0);
  });

  it("webhook.update binds the resulting state: absence and the current value alike, null clears, a reordering needs none", async () => {
    // Created while the control is off for this setup.
    await ctx.db.query("UPDATE security_controls SET mode = 'off' WHERE organization_id = $1", [orgId]);
    const hook = (await createHook(admin.cli, { url: HOOK, eventTypes: ["grant.created", "grant.revoked"] })).body;
    await enforceAdminStepUp();
    // A reordering, or the same URL again, changes nothing: no approval.
    expect((await patchHook(admin.cli, hook.id, { expectedVersion: 1, eventTypes: ["grant.revoked", "grant.created"] })).status).toBe(200);
    expect((await patchHook(admin.cli, hook.id, { expectedVersion: 2, url: HOOK })).status).toBe(200);
    const v = (await ok("GET", `${ORG}/webhooks`, admin.cli)).items[0].version as number;
    expect(await intents()).toBe(0);

    // Clearing the filter: absence of url and the current url bind the same.
    const cleared = await approved(admin, await patchHook(admin.cli, hook.id, { expectedVersion: v, eventTypes: null }));
    const [intent] = await rows("SELECT target, expected_version, summary FROM approval_intents WHERE id = $1", [cleared]);
    expect(json(intent.target)).toEqual({ webhookId: hook.id });
    expect(intent.expected_version).toBe(v);
    expect(json(intent.summary)).toEqual({
      title: `Change ${labelWithId("webhook", "https://sink.example/[redacted]", hook.id)} to "https://sink.example/[redacted]"`,
      changes: [{ field: "eventTypes", from: 'event types ["grant.created", "grant.revoked"]', to: "every event", loosens: false }],
    });
    // Another URL with this approval: refused, nothing changed.
    invalid(await patchHook(admin.cli, hook.id, { expectedVersion: v, eventTypes: null, url: HOOK_2 }, cleared), "mismatch");
    expect((await patchHook(admin.cli, hook.id, { expectedVersion: v, url: HOOK, eventTypes: null }, cleared)).body).toMatchObject({ eventTypes: null });

    // A changed token that redacts the same is still listed, without showing it.
    const moved = stepUp(await patchHook(admin.cli, hook.id, { expectedVersion: v + 1, url: HOOK_2 }));
    expect(moved.summary.changes).toEqual([
      {
        field: "url",
        from: '"https://sink.example/[redacted]" (current)',
        to: '"https://sink.example/[redacted]" (another URL: the part that changed is not shown)',
        loosens: false,
      },
    ]);
    expect(JSON.stringify(moved)).not.toContain("hook-secret-token");
  });

  it("an Idempotency-Key on a webhook patch leaves no claim behind with STEP_UP_REQUIRED, and the repeat may send it again", async () => {
    await ctx.db.query("UPDATE security_controls SET mode = 'off' WHERE organization_id = $1", [orgId]);
    const hook = (await createHook(admin.cli)).body;
    await enforceAdminStepUp();
    const key = { "Idempotency-Key": "patch-1" };
    const asked = await approved(admin, await patchHook(admin.cli, hook.id, { expectedVersion: 1, url: HOOK_2 }, undefined, key));
    expect(await count("SELECT count(*)::int AS n FROM idempotency_keys")).toBe(0);
    expect((await patchHook(admin.cli, hook.id, { expectedVersion: 1, url: HOOK_2 }, asked, key)).status).toBe(200);
    // The replay answers from the stored response.
    expect((await patchHook(admin.cli, hook.id, { expectedVersion: 1, url: HOOK_2 }, asked, key)).status).toBe(200);
  });

  it("webhook.delete binds the version the server reads: stale once the webhook changed", async () => {
    await ctx.db.query("UPDATE security_controls SET mode = 'off' WHERE organization_id = $1", [orgId]);
    const hook = (await createHook(admin.cli)).body;
    await enforceAdminStepUp();
    const removal = await approved(admin, await deleteHook(admin.cli, hook.id));
    expect((await rows("SELECT expected_version FROM approval_intents WHERE id = $1", [removal]))[0].expected_version).toBe(1);
    const patched = await approved(admin, await patchHook(admin.cli, hook.id, { expectedVersion: 1, eventTypes: ["grant.created"] }));
    expect((await patchHook(admin.cli, hook.id, { expectedVersion: 1, eventTypes: ["grant.created"] }, patched)).status).toBe(200);
    invalid(await deleteHook(admin.cli, hook.id, removal), "stale");
    expect(await count("SELECT count(*)::int AS n FROM webhooks WHERE revoked_at IS NULL")).toBe(1);
  });

  it("connection.create binds the canonical base identity and the credential itself: a changed secret with the same approval is refused", async () => {
    const asked = await approved(admin, await createConnection(admin.cli, { baseIdentity: "Acme" }));
    // GitHub's base identity is canonicalized: the same Connection.
    invalid(await createConnection(admin.cli, { baseIdentity: "Acme", credential: CREDENTIAL_2 }, asked), "mismatch");
    invalid(await createConnection(admin.cli, { baseIdentity: "Acme", name: "Other" }, asked), "mismatch");
    await unconsumed(asked);
    expect((await createConnection(admin.cli, { baseIdentity: "acme" }, asked)).status).toBe(201);
    expect(await count("SELECT count(*)::int AS n FROM platform_connections")).toBe(1);
  });

  it("connection.replace_credential binds the credential and the requested version; connection.delete the version it reads", async () => {
    await ctx.db.query("UPDATE security_controls SET mode = 'off' WHERE organization_id = $1", [orgId]);
    const connection = (await createConnection(admin.cli)).body;
    await enforceAdminStepUp();
    const replace = stepUp(await replaceCredential(admin.cli, connection.id, CREDENTIAL_2, 1));
    expect(replace.summary).toEqual({
      title: `Replace the credential of ${labelWithId("connection", "GitHub", connection.id)} on platform "github-actions" for base identity "acme". 0 Sync Targets will push with it`,
      changes: [{ field: "credential", from: "the current value", to: "a new value (not shown)", loosens: false }],
    });
    await approve(admin, replace.id);
    const revoke = stepUp(await revokeConnection(admin.cli, connection.id));
    expect(revoke.summary.title).toBe(`Revoke ${labelWithId("connection", "GitHub", connection.id)}. 0 Sync Targets are disabled`);
    await approve(admin, revoke.id);
    invalid(await replaceCredential(admin.cli, connection.id, "ghp_secretcredential000000000000000003", 1, replace.id), "mismatch");
    expect((await replaceCredential(admin.cli, connection.id, CREDENTIAL_2, 1, replace.id)).status).toBe(200);
    // The credential's replacement moved the Connection's version: the revocation's approval is stale.
    invalid(await revokeConnection(admin.cli, connection.id, revoke.id), "stale");
    expect(await count("SELECT count(*)::int AS n FROM platform_connections WHERE revoked_at IS NULL")).toBe(1);
  });

  it("refuses requests local checks would refuse before asking: unknown targets, a stale version, an App Connection's credential", async () => {
    const before = await intents();
    expect((await revokeConnection(admin.cli, "pcn_nothing")).status).toBe(404);
    expect((await deleteHook(admin.cli, "whk_nothing")).status).toBe(404);
    expect((await patchHook(admin.cli, "whk_nothing", { expectedVersion: 1, url: HOOK })).status).toBe(404);
    expect((await createHook(admin.cli, { url: "ftp://x" })).status).toBe(422);
    expect((await removeApp(admin.cli, "gha_nothing")).status).toBe(404);
    expect((await replaceKey(admin.cli, githubApp().pem, 1)).status).toBe(404);
    expect(await intents()).toBe(before);
    expect(githubCalls()).toBe(0);
  });

  it("refuses another person's approval and a machine credential outright, without an intent", async () => {
    const bot = await robot();
    const res = await createConnection(bot.token);
    expect(res.status).toBe(403);
    expect(res.body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "machine-credential" } });
    const imported = githubApp();
    const machineImport = await importApp(bot.token, imported.id, imported.pem);
    expect(machineImport.body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "machine-credential" } });
    expect(githubCalls()).toBe(0);
    expect(await intents()).toBe(0);
    const asked = await approved(admin, await createHook(admin.cli));
    // Another admin, even one of this Organization, finds nothing.
    await ctx.db.query("UPDATE security_controls SET mode = 'off' WHERE organization_id = $1", [orgId]);
    const grant = await issueInviteGrant(ctx, { organizationId: orgId, role: "admin", name: "Carol" }, admin.id);
    const carol = await person((await consumeSetupGrant(ctx, grant.token, {})).identityId);
    await enforceAdminStepUp();
    invalid(await createHook(carol.cli, { url: HOOK }, asked), "not-found");
    // The same person's dashboard is another requester for a CLI intent.
    invalid(await createHook(admin.web, { url: HOOK }, asked), "mismatch");
    expect(await count("SELECT count(*)::int AS n FROM webhooks")).toBe(0);
  });

  it("is turned off by the operator's reset, which closes the open approvals of these operations", async () => {
    const asked = [stepUp(await createHook(admin.cli)), stepUp(await createConnection(admin.cli))];
    const outcome = await resetControls(ctx, { organization: "acme", controls: ["admin-step-up"] });
    expect(outcome.approvalsClosed).toBe(2);
    expect(await rows("SELECT id, close_reason FROM approval_intents ORDER BY id")).toEqual(
      asked.map((a) => a.id).sort().map((id) => ({ id, close_reason: "reset" })),
    );
    expect((await createHook(admin.cli)).status).toBe(201);
  });

  it("the incident freeze: revoking a Connection is recovery and still asks; webhook and GitHub App changes are refused", async () => {
    expect(OPERATIONS_DURING_FREEZE.has("connection.delete")).toBe(true);
    for (const op of ["webhook.create", "webhook.update", "webhook.delete", "connection.create", "connection.replace_credential",
      "github_app.register", "github_app.import", "github_app.replace_key", "github_app.remove"] as const) {
      expect(OPERATIONS_DURING_FREEZE.has(op), op).toBe(false);
    }
    await ctx.db.query("UPDATE security_controls SET mode = 'off' WHERE organization_id = $1", [orgId]);
    const hook = (await createHook(admin.cli)).body;
    const connection = (await createConnection(admin.cli)).body;
    await enforceAdminStepUp();
    expect((await call("POST", `${ORG}/incident-freeze`, admin.cli, { reason: "A token leaked" })).status).toBe(201);
    const before = await intents();
    expect((await deleteHook(admin.cli, hook.id)).body.error.code).toBe("ORGANIZATION_FROZEN");
    expect((await createConnection(admin.cli)).body.error.code).toBe("ORGANIZATION_FROZEN");
    expect(await intents()).toBe(before);
    const revoke = stepUp(await revokeConnection(admin.cli, connection.id));
    expect(revoke.operation).toBe("connection.delete");
    await approve(admin, revoke.id);
    expect((await revokeConnection(admin.cli, connection.id, revoke.id)).status).toBe(204);
  });
});

describe("GitHub App calls before the approval boundary (amendment D)", () => {
  beforeEach(async () => {
    await enforceAdminStepUp();
  });

  it("import calls GitHub only after the precheck found an approved intent for exactly this key", async () => {
    const imported = githubApp();
    const asked = stepUp(await importApp(admin.cli, imported.id, imported.pem));
    expect(githubCalls()).toBe(0);
    // Not yet approved: the precheck refuses, GitHub is not called.
    invalid(await importApp(admin.cli, imported.id, imported.pem, asked.id), "pending");
    expect(githubCalls()).toBe(0);
    await approve(admin, asked.id);
    // Another key with this approval: refused before GitHub.
    const other = github.addKey(imported.id);
    invalid(await importApp(admin.cli, imported.id, other, asked.id), "mismatch");
    expect(githubCalls()).toBe(0);
    expect((await importApp(admin.cli, imported.id, imported.pem, asked.id)).body).toMatchObject({ outcome: "registered" });
    expect(github.calls.filter((c) => c.path === "/app")).toHaveLength(1);
  });

  it("a key GitHub refuses after the precheck leaves the approval unconsumed", async () => {
    const imported = githubApp();
    const asked = await approved(admin, await importApp(admin.cli, imported.id, imported.pem));
    github.deleteKey(imported.id, imported.pem);
    expect((await importApp(admin.cli, imported.id, imported.pem, asked)).body).toMatchObject({ outcome: "failed" });
    await unconsumed(asked);
    expect(await liveApp()).toBeUndefined();
  });

  it("key replacement and an App Connection do not call GitHub before the precheck", async () => {
    await ctx.db.query("UPDATE security_controls SET mode = 'off' WHERE organization_id = $1", [orgId]);
    const registered = await registerApp();
    await enforceAdminStepUp();
    const calls = githubCalls();
    const newKey = github.addKey(registered.githubAppId);
    const key = stepUp(await replaceKey(admin.cli, newKey, registered.version));
    expect(key.summary.title).toBe(`Replace the private key of ${labelWithId("GitHub App", registered.slug, registered.id)}. 0 Sync Targets will push with it`);
    const installation = github.install(registered.githubAppId, OWNER);
    const conn = stepUp(await createAppConnection(admin.cli, installation));
    expect(conn.summary.title).toBe(`Add connection "App" on installation ${installation} of ${labelWithId("GitHub App", registered.slug, registered.id)}`);
    const [intent] = await rows("SELECT target, body_hash FROM approval_intents WHERE id = $1", [conn.id]);
    expect(json(intent.target)).toEqual({ organizationId: orgId, githubAppId: registered.id });
    expect(githubCalls()).toBe(calls);
    await approve(admin, key.id);
    await approve(admin, conn.id);
    expect((await createAppConnection(admin.cli, installation, "Other", conn.id)).body.error.details.reason).toBe("mismatch");
    expect(githubCalls()).toBe(calls);
    expect((await createAppConnection(admin.cli, installation, "App", conn.id)).status).toBe(201);
    expect((await replaceKey(admin.cli, newKey, registered.version, key.id)).body).toMatchObject({ outcome: "rotated" });
  });
});

describe("GitHub App registration, staged (amendment D)", () => {
  beforeEach(async () => {
    await enforceAdminStepUp();
  });

  it("asks for the approval after conversion; the attachment is repeated with it, the callback never", async () => {
    const started = await startRegistration(admin.web);
    expect(started.id).toMatch(/^ghr_/);
    const res = await completeRegistration(admin.web, started.state, "code-a");
    const asked = stepUp(res);
    expect(res.body.error.details.registrationId).toBe(started.id);
    expect(asked.operation).toBe("github_app.register");
    const appId = 5_254_113;
    const appText = `GitHub App "varlatch-acme-${appId}" (GitHub App id ${appId}, client id "Iv23li${appId}")`;
    const ownerText = 'GitHub organization "acme-gh" (GitHub id 1009)';
    expect(asked.summary).toEqual({
      title: `Attach ${appText}, owned by ${ownerText}, to ${labelWithId("organization", "Acme", orgId)}, from registration ${started.id}`,
      changes: [
        { field: "app", from: null, to: appText, loosens: false },
        { field: "owner", from: null, to: ownerText, loosens: false },
      ],
    });
    const [intent] = await rows("SELECT target FROM approval_intents WHERE id = $1", [asked.id]);
    expect(json(intent.target)).toEqual({ registrationId: started.id });
    // The conversion is pending, its key kept; nothing is attached.
    expect(await registration(started.id)).toEqual({ converted: true, ended: false, end_reason: null, has_key: true });
    expect(await liveApp()).toBeUndefined();
    expect(conversions).toEqual(["code-a"]);

    // The callback is never repeated: its state is spent, and it says the registration waits.
    const again = await completeRegistration(admin.web, started.state, "code-a");
    expect(again.body.error).toMatchObject({ code: "CONSUMED", details: { registrationId: started.id, pending: true } });
    expect(conversions).toEqual(["code-a"]);

    // Another person finds nothing; an attachment without the approval asks again.
    await approve(admin, asked.id);
    const attached = await attach(admin.web, started.id, asked.id);
    expect(attached.status, JSON.stringify(attached.body)).toBe(201);
    expect(attached.body).toMatchObject({ outcome: "registered", app: { githubAppId: appId } });
    expect(await registration(started.id)).toEqual({ converted: true, ended: true, end_reason: "attached", has_key: false });
    expect((await events("sync.github_app_registered")).at(-1)!.metadata).toMatchObject({ via: "manifest", appId, approvalId: asked.id });
    // Attached once: a second attachment is a terminal refusal that changes nothing.
    // An attachment repeated after a lost answer must not send anyone to delete the App that works.
    const twice = await attach(admin.web, started.id);
    expect(twice.body).toMatchObject({ outcome: "refused", reason: "registration-ended", deleteUrl: null });
    expect(Number((await liveApp()).github_app_id)).toBe(appId);
    expect(conversions).toEqual(["code-a"]);
  });

  it("STEP_UP_REQUIRED and a transient failure keep the pending key", async () => {
    const started = await startRegistration(admin.cli);
    const asked = await approved(admin, await completeRegistration(admin.cli, started.state));
    // A repeat without the approval asks again and keeps it.
    stepUp(await attach(admin.cli, started.id));
    expect(await registration(started.id)).toMatchObject({ ended: false, has_key: true });
    // A failure of the final transaction rolls back, consumption included.
    await ctx.db.query(`CREATE FUNCTION fail_app_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected failure'; END $$`);
    await ctx.db.query("CREATE TRIGGER fail_app_insert BEFORE INSERT ON github_apps FOR EACH ROW EXECUTE FUNCTION fail_app_insert()");
    expect((await attach(admin.cli, started.id, asked)).status).toBeGreaterThanOrEqual(500);
    await unconsumed(asked);
    expect(await registration(started.id)).toMatchObject({ ended: false, has_key: true });
    await ctx.db.query("DROP TRIGGER fail_app_insert ON github_apps");
    expect((await attach(admin.cli, started.id, asked)).status).toBe(201);
  });

  it("only the person who started it may attach or discard it", async () => {
    const started = await startRegistration(admin.cli);
    stepUp(await completeRegistration(admin.cli, started.state));
    const bot = await robot();
    expect((await attach(bot.token, started.id)).status).toBe(404);
    expect((await discard(bot.token, started.id)).status).toBe(404);
    expect(await registration(started.id)).toMatchObject({ ended: false, has_key: true });
  });

  it("a terminal refusal (the Organization got another App) deletes the pending key and audits, with the approval unconsumed", async () => {
    const started = await startRegistration(admin.cli);
    const asked = await approved(admin, await completeRegistration(admin.cli, started.state));
    const imported = githubApp();
    const imp = await approved(admin, await importApp(admin.cli, imported.id, imported.pem));
    expect((await importApp(admin.cli, imported.id, imported.pem, imp)).status).toBe(201);
    const res = await attach(admin.cli, started.id, asked);
    expect(res.body).toMatchObject({ outcome: "refused", reason: "organization-has-app", deleteUrl: expect.stringContaining("/settings/apps/varlatch-acme-") });
    await unconsumed(asked);
    expect(await registration(started.id)).toEqual({ converted: true, ended: true, end_reason: "refused", has_key: false });
    expect((await events("sync.github_app_registration_refused")).map((e) => e.metadata.reason)).toEqual(["organization-has-app"]);
  });

  it("a terminal refusal found before an approval is asked for: no new intent, the key deleted", async () => {
    const started = await startRegistration(admin.cli);
    stepUp(await completeRegistration(admin.cli, started.state));
    const imported = githubApp();
    const imp = await approved(admin, await importApp(admin.cli, imported.id, imported.pem));
    expect((await importApp(admin.cli, imported.id, imported.pem, imp)).status).toBe(201);
    const before = await intents();
    expect((await attach(admin.cli, started.id)).body).toMatchObject({ outcome: "refused", reason: "organization-has-app" });
    expect(await intents()).toBe(before);
    expect(await registration(started.id)).toEqual({ converted: true, ended: true, end_reason: "refused", has_key: false });
  });

  it("an expired pending key is deleted and audited, by an attachment and by the sweep", async () => {
    const first = await startRegistration(admin.cli);
    const asked = await approved(admin, await completeRegistration(admin.cli, first.state, "code-1"));
    const second = await startRegistration(admin.cli);
    stepUp(await completeRegistration(admin.cli, second.state, "code-2"));
    // An hour passes (written directly: pending material is otherwise never updated).
    await ctx.db.query("ALTER TABLE github_app_registrations DISABLE TRIGGER github_app_registrations_pending_once");
    await ctx.db.query("UPDATE github_app_registrations SET pending_expires_at = converted_at + interval '1 millisecond'");
    await ctx.db.query("ALTER TABLE github_app_registrations ENABLE TRIGGER github_app_registrations_pending_once");
    expect((await attach(admin.cli, first.id, asked)).body).toMatchObject({ outcome: "refused", reason: "expired" });
    await unconsumed(asked);
    expect(await registration(first.id)).toEqual({ converted: true, ended: true, end_reason: "expired", has_key: false });
    expect(await sweepExpiredRegistrations(ctx)).toBe(1);
    expect(await registration(second.id)).toEqual({ converted: true, ended: true, end_reason: "expired", has_key: false });
    expect(await sweepExpiredRegistrations(ctx)).toBe(0);
    const abandoned = await events("sync.github_app_registration_abandoned");
    expect(abandoned.map((e) => [e.actor, e.metadata.reason, e.metadata.registrationId])).toEqual([
      [admin.id, "expired", first.id],
      [null, "expired", second.id],
    ]);
    for (const e of abandoned) expect(e.metadata).toMatchObject({ appId: expect.any(Number), slug: expect.stringMatching(/^varlatch-acme-/) });
  });

  it("a discarded pending key is deleted and audited; the App stays on GitHub", async () => {
    const started = await startRegistration(admin.cli);
    const asked = await approved(admin, await completeRegistration(admin.cli, started.state));
    const res = await discard(admin.cli, started.id);
    expect(res.body).toEqual({ discarded: true, deleteUrl: expect.stringContaining("/organizations/acme-gh/settings/apps/varlatch-acme-") });
    expect(await registration(started.id)).toEqual({ converted: true, ended: true, end_reason: "discarded", has_key: false });
    expect((await events("sync.github_app_registration_abandoned")).map((e) => e.metadata.reason)).toEqual(["discarded"]);
    expect((await attach(admin.cli, started.id, asked)).body).toMatchObject({ outcome: "refused", reason: "registration-ended" });
    expect((await discard(admin.cli, started.id)).body).toMatchObject({ discarded: false });
  });
});

describe("GitHub App registration, staged: more terminal cases (amendment D)", () => {
  beforeEach(async () => {
    await enforceAdminStepUp();
  });

  it("app-in-use: another Organization imported the App meanwhile; the key is deleted, the refusal audited, the approval unconsumed", async () => {
    const started = await startRegistration(admin.cli);
    const asked = await approved(admin, await completeRegistration(admin.cli, started.state, "code-x"));
    const appId = [...convertedKeys.keys()][0]!;
    // Another Organization (every control off there) imports the same App.
    await ok("POST", "/v1/organizations", admin.cli, { name: "Beta", slug: "beta" });
    expect((await call("POST", "/v1/organizations/beta/github-app/import", admin.cli, { appId, privateKey: convertedKeys.get(appId) })).status).toBe(201);
    const res = await attach(admin.cli, started.id, asked);
    expect(res.body).toMatchObject({ outcome: "refused", reason: "app-in-use", deleteUrl: expect.stringContaining(`varlatch-acme-${appId}`) });
    await unconsumed(asked);
    expect(await registration(started.id)).toEqual({ converted: true, ended: true, end_reason: "refused", has_key: false });
    expect((await events("sync.github_app_registration_refused")).map((e) => e.metadata.reason)).toEqual(["app-in-use"]);
    expect(await liveApp()).toBeUndefined();
  });

  it("an import of an App another Organization uses is refused before an approval is asked for or GitHub is called", async () => {
    const imported = githubApp();
    await ok("POST", "/v1/organizations", admin.cli, { name: "Beta", slug: "beta" });
    expect((await call("POST", "/v1/organizations/beta/github-app/import", admin.cli, { appId: imported.id, privateKey: imported.pem })).status).toBe(201);
    const calls = githubCalls();
    const before = await intents();
    const res = await importApp(admin.cli, imported.id, imported.pem);
    expect(res.body.error).toMatchObject({ code: "STATE_CHANGED" });
    expect(await intents()).toBe(before);
    expect(githubCalls()).toBe(calls);
  });

  it("scheduling the Organization's deletion deletes a pending registration and its key", async () => {
    const started = await startRegistration(admin.cli);
    const asked = await approved(admin, await completeRegistration(admin.cli, started.state, "code-d"));
    expect((await call("POST", `${ORG}/deletion`, admin.cli, {})).status).toBe(201);
    expect(await rows("SELECT id FROM github_app_registrations WHERE organization_id = $1", [orgId])).toEqual([]);
    expect((await attach(admin.cli, started.id, asked)).body.error.code).toBe("ORGANIZATION_DELETING");
    await unconsumed(asked);
    expect(await liveApp()).toBeUndefined();
  });

  it("a machine completing a callback is refused before the state is claimed or GitHub is called", async () => {
    const bot = await robot();
    const started = await startRegistration(bot.token);
    const res = await completeRegistration(bot.token, started.state, "code-m");
    expect(res.status).toBe(403);
    expect(res.body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "machine-credential" } });
    expect(conversions).toEqual([]);
    expect(await intents()).toBe(0);
    expect((await rows("SELECT consumed_at, converted_at FROM github_app_registrations WHERE id = $1", [started.id]))[0])
      .toEqual({ consumed_at: null, converted_at: null });
  });

  it("a machine whose control was enforced after the early check: its pending key is deleted at once and audited", async () => {
    const bot = await robot();
    const started = await startRegistration(bot.token);
    // Off at the early check; enforced while GitHub answers, before the attachment.
    await ctx.db.query("UPDATE security_controls SET mode = 'off' WHERE organization_id = $1", [orgId]);
    onConversion = enforceAdminStepUp;
    const res = await completeRegistration(bot.token, started.state, "code-late");
    expect(res.body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "machine-credential" } });
    expect(conversions).toEqual(["code-late"]);
    expect(await intents()).toBe(0);
    expect(await registration(started.id)).toEqual({ converted: true, ended: true, end_reason: "refused", has_key: false });
    expect((await events("sync.github_app_registration_abandoned")).map((e) => [e.actor, e.metadata.reason])).toEqual([[bot.id, "machine-credential"]]);
  });
});
