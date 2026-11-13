// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { withSerializableTx, withTx } from "../src/db/tx.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { withApproval, type Requester } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { DomainError } from "../src/domain/errors.js";
import { identityCreateBinding } from "../src/domain/identitystepup.js";
import { prepareProtectedOperation } from "../src/domain/protected.js";
import { ENFORCEABLE_CONTROLS, resetControls } from "../src/domain/securitycontrols.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * admin-step-up for machine identities, credentials and OIDC bindings
 * (ADR-0054 step 4.5), on PGlite under the lock-order check
 * (test/helpers/lock-trace.ts): identity.create, credential.issue,
 * identity.reactivate, oidc_binding.create and oidc_binding.delete. These tests set admin-step-up's
 * enforce directly in the database (written before the unlock); setting
 * it through the API is tested in admin-step-up-catalogue.test.ts. With every control
 * off nothing changes; report mode counts and refuses nothing; under
 * enforce each operation needs the requester's approval bound to exactly
 * that request, as the binding catalogue says, and a machine credential is
 * refused without an intent; the controls compose with credential-lifetime,
 * requirement-protection, the incident freeze and the operator's reset.
 * The races of a reactivation with a retirement and with another
 * reactivation run on real PostgreSQL in admin-step-up-postgres.test.ts.
 */

const ORG = "/v1/organizations/acme";
const CONTROLS = `${ORG}/security/controls`;
const IDS = `${ORG}/identities`;
const ISSUER = "https://ci.example";

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

/**
 * A new person of the Organization. An admin is invited as a member and
 * made one in the database: inviting an admin is itself protected by
 * admin-step-up (step 4.7), which these tests may have at enforce.
 */
async function invite(name: string, role: "admin" | "member"): Promise<Person> {
  const grant = await issueInviteGrant(ctx, { organizationId: orgId, role: "member", name }, admin.id);
  const { identityId } = await consumeSetupGrant(ctx, grant.token, {});
  if (role === "admin") {
    await ctx.db.query("UPDATE org_memberships SET role = 'admin' WHERE organization_id = $1 AND identity_id = $2", [orgId, identityId]);
  }
  return person(identityId);
}

async function controlOf(control: string) {
  return (await ok("GET", CONTROLS, admin.cli)).items.find((i: { control: string }) => i.control === control);
}

const setMode = async (control: string, mode: string, config?: unknown) =>
  call("PATCH", `${CONTROLS}/${control}`, admin.cli, { mode, ...(config === undefined ? {} : { config }), expectedVersion: (await controlOf(control)).version });

/**
 * admin-step-up at enforce, written directly in the database (the API
 * accepts it since ADR-0054 step 4.9 unlocked the control).
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

// The five operations, as their routes take them.
const createMachine = (token: string, body: Record<string, unknown>, approval?: string) => call("POST", IDS, token, body, header(approval));
const issue = (token: string, identityId: string, body: Record<string, unknown>, approval?: string) =>
  call("POST", `${IDS}/${identityId}/credentials`, token, body, header(approval));
const reactivate = (token: string, identityId: string, approval?: string) => call("POST", `${IDS}/${identityId}/reactivate`, token, undefined, header(approval));
const retire = (token: string, identityId: string) => ok("POST", `${IDS}/${identityId}/retire`, token);
const addBinding = (token: string, identityId: string, body: Record<string, unknown>, approval?: string) =>
  call("POST", `${IDS}/${identityId}/oidc-bindings`, token, body, header(approval));
const removeBinding = (token: string, identityId: string, bindingId: string, approval?: string) =>
  call("DELETE", `${IDS}/${identityId}/oidc-bindings/${bindingId}`, token, undefined, header(approval));
const ciBinding = (subject = "repo:acme/api:ref:refs/heads/main", extra: Record<string, unknown> = {}) => ({ issuer: ISSUER, audience: "varlatch", subject, ...extra });

const identity = async (id: string) => (await rows("SELECT name, kind, disabled FROM identities WHERE id = $1", [id]))[0] as { name: string; kind: string; disabled: boolean };
const machinesNamed = (name: string) => count("SELECT count(*)::int AS n FROM identities WHERE name = $1", [name]);
const credentialsOf = (id: string) => count("SELECT count(*)::int AS n FROM credentials WHERE identity_id = $1", [id]);
const liveBindings = (id: string) => count("SELECT count(*)::int AS n FROM oidc_bindings WHERE identity_id = $1 AND revoked_at IS NULL", [id]);

async function events(eventType: string) {
  const parse = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v) as Record<string, any> | null;
  return (await rows("SELECT actor_identity_id, metadata FROM audit_events WHERE event_type = $1 ORDER BY event_order", [eventType]))
    .map((r) => ({ actor: r.actor_identity_id as string, metadata: parse(r.metadata) ?? {} }));
}

/** A service identity, a ci identity with an OIDC binding, and a retired workload: made while every control is off. */
async function fixtures() {
  const svc = await ok("POST", IDS, admin.cli, { name: "api", kind: "service" });
  const ci = await ok("POST", IDS, admin.cli, { name: "deploy", kind: "ci" });
  const binding = await ok("POST", `${IDS}/${ci.id}/oidc-bindings`, admin.cli, ciBinding());
  const old = await ok("POST", IDS, admin.cli, { name: "old-worker", kind: "workload" });
  await retire(admin.cli, old.id);
  return { svc: svc.id as string, ci: ci.id as string, binding: binding.id as string, old: old.id as string };
}

/** A machine identity of the Organization that holds identity.manage. */
async function robot() {
  const created = await ok("POST", IDS, admin.cli, { name: "robot", kind: "service" });
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

describe("admin-step-up's enforce, set through the API (unlocked in step 4.9)", () => {
  it("is advertised and accepted as tightening, without an approval; identity.create then asks for one", async () => {
    expect(ENFORCEABLE_CONTROLS.has("admin-step-up")).toBe(true);
    expect((await controlOf("admin-step-up")).availableModes).toEqual(["off", "report", "enforce"]);
    const meta = (await call("GET", "/v1/meta", admin.cli)).body.capabilities as string[];
    expect(meta).toContain("security.enforce.admin-step-up");
    const res = await setMode("admin-step-up", "enforce");
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body).toMatchObject({ changed: true, loosened: false, control: { control: "admin-step-up", mode: "enforce", version: 1 } });
    expect(await intents()).toBe(0);
    expect(stepUp(await createMachine(admin.cli, { name: "billing", kind: "service" })).operation).toBe("identity.create");
  });
});

describe("with every control off", () => {
  it("creates, issues, reactivates, binds and unbinds as before: no approval, no count, no intent, audit as before", async () => {
    const f = await fixtures();
    expect((await issue(admin.cli, f.svc, { name: "second", ttlSeconds: 3600 })).status).toBe(201);
    expect((await reactivate(admin.cli, f.old)).status).toBe(200);
    expect((await identity(f.old)).disabled).toBe(false);
    expect((await removeBinding(admin.cli, f.ci, f.binding)).status).toBe(204);
    expect(await intents()).toBe(0);
    expect(await counters()).toBe(0);
    const [created] = await events("identity.created");
    expect(created!.metadata).toEqual({ kind: "service" });
    for (const type of ["credential.issued", "identity.reactivated", "oidc_binding.created", "oidc_binding.revoked"]) {
      for (const e of await events(type)) expect(e.metadata, type).not.toHaveProperty("approvalId");
    }
  });

  it("ignores a malformed Varlatch-Approval header, as before", async () => {
    const f = await fixtures();
    expect((await createMachine(admin.cli, { name: "x", kind: "service" }, "invalid")).status).toBe(201);
    expect((await issue(admin.cli, f.svc, { name: "y" }, "invalid")).status).toBe(201);
    expect((await reactivate(admin.cli, f.old, "invalid")).status).toBe(200);
    const b = await addBinding(admin.cli, f.ci, ciBinding("repo:acme/web:*"), "invalid");
    expect(b.status).toBe(201);
    expect((await removeBinding(admin.cli, f.ci, b.body.id, "invalid")).status).toBe(204);
    expect(await intents()).toBe(0);
  });
});

describe("in report mode", () => {
  it("refuses nothing and counts each operation, by a person and by a machine; an enabled identity's reactivation is not counted", async () => {
    const f = await fixtures();
    const bot = await robot();
    expect((await setMode("admin-step-up", "report")).status).toBe(200);
    expect((await createMachine(admin.cli, { name: "a", kind: "agent" })).status).toBe(201);
    expect((await createMachine(bot.token, { name: "b", kind: "service" })).status).toBe(201);
    expect((await issue(admin.cli, f.svc, { name: "c" })).status).toBe(201);
    expect((await issue(bot.token, f.svc, { name: "d" })).status).toBe(201);
    expect((await reactivate(bot.token, f.old)).status).toBe(200);
    expect((await reactivate(admin.cli, f.old)).status).toBe(200); // already enabled: changes nothing
    const b = await addBinding(bot.token, f.ci, ciBinding("repo:acme/web:*"));
    expect(b.status).toBe(201);
    expect((await removeBinding(admin.cli, f.ci, b.body.id)).status).toBe(204);
    expect(await intents()).toBe(0);
    expect(await rows(
      "SELECT control, operation, reason, actor_identity_id, count::int AS count FROM security_control_counters ORDER BY operation, reason",
    )).toEqual([
      { control: "admin-step-up", operation: "credential.issue", reason: "machine-credential", actor_identity_id: bot.id, count: 1 },
      { control: "admin-step-up", operation: "credential.issue", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
      { control: "admin-step-up", operation: "identity.create", reason: "machine-credential", actor_identity_id: bot.id, count: 1 },
      { control: "admin-step-up", operation: "identity.create", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
      { control: "admin-step-up", operation: "identity.reactivate", reason: "machine-credential", actor_identity_id: bot.id, count: 1 },
      { control: "admin-step-up", operation: "oidc_binding.create", reason: "machine-credential", actor_identity_id: bot.id, count: 1 },
      { control: "admin-step-up", operation: "oidc_binding.delete", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
    ]);
  });
});

describe("under enforce", () => {
  let f: Awaited<ReturnType<typeof fixtures>>;
  let bot: Awaited<ReturnType<typeof robot>>;
  beforeEach(async () => {
    f = await fixtures();
    bot = await robot();
    await enforceAdminStepUp();
  });

  it("asks for an approval for each operation, with its summary, and changes nothing without one", async () => {
    const create = stepUp(await createMachine(admin.cli, { name: "billing", kind: "service", credentialTtlSeconds: 86_400, credentialMaxUses: 5 }));
    expect(create).toMatchObject({ operation: "identity.create", organization: { id: orgId, slug: "acme" }, state: "pending" });
    expect(create.summary).toEqual({
      title: 'Create machine identity "billing" (service), with a credential that expires after 1 day (as requested)',
      changes: [
        { field: "name", from: null, to: '"billing"', loosens: false },
        { field: "kind", from: null, to: "service", loosens: false },
        { field: "credentialExpiry", from: null, to: "after 1 day (as requested)", loosens: false },
        { field: "credentialUses", from: null, to: "5 uses", loosens: false },
      ],
    });
    expect(stepUp(await createMachine(admin.web, { name: "runner", kind: "ci" })).summary).toEqual({
      title: 'Create machine identity "runner" (ci). It gets no credential',
      changes: [
        { field: "name", from: null, to: '"runner"', loosens: false },
        { field: "kind", from: null, to: "ci", loosens: false },
      ],
    });
    const issuing = stepUp(await issue(admin.cli, f.svc, { name: "backup job" }));
    expect(issuing).toMatchObject({ operation: "credential.issue", organization: { id: orgId } });
    expect(issuing.summary.title).toBe(`Issue credential "backup job" for service "api" (${f.svc}), never expiring (none was requested), unlimited`);
    const reactivating = stepUp(await reactivate(admin.cli, f.old));
    expect(reactivating).toMatchObject({ operation: "identity.reactivate", summary: { title: `Reactivate machine identity "old-worker" (${f.old}). It has no working credential until one is issued`, changes: [] } });
    const binding = stepUp(await addBinding(admin.cli, f.ci, ciBinding("repo:acme/web:*", { claims: { ref: "refs/heads/main", environment: "prod" } })));
    expect(binding).toMatchObject({ operation: "oidc_binding.create" });
    expect(binding.summary).toEqual({
      title: `Let tokens from "${ISSUER}" with subject "repo:acme/web:*" act as "deploy" (${f.ci})`,
      changes: [
        { field: "issuer", from: null, to: `"${ISSUER}"`, loosens: false },
        { field: "audience", from: null, to: '"varlatch"', loosens: false },
        { field: "subject", from: null, to: '"repo:acme/web:*"', loosens: false },
        { field: "claims", from: null, to: '{"environment": "prod", "ref": "refs/heads/main"}', loosens: false },
      ],
    });
    const unbinding = stepUp(await removeBinding(admin.web, f.ci, f.binding));
    expect(unbinding).toMatchObject({
      operation: "oidc_binding.delete",
      summary: { title: `Remove the OIDC binding ${f.binding} (issuer "${ISSUER}", subject "repo:acme/api:ref:refs/heads/main", audience "varlatch") from "deploy" (${f.ci})`, changes: [] },
    });

    expect(await machinesNamed("billing")).toBe(0);
    expect(await machinesNamed("runner")).toBe(0);
    expect(await credentialsOf(f.svc)).toBe(1);
    expect((await identity(f.old)).disabled).toBe(true);
    expect(await liveBindings(f.ci)).toBe(1);
    // Nothing is counted under enforce.
    expect(await counters()).toBe(0);
  });

  it("runs each operation with its approval, once, and records the approval in the audit", async () => {
    const made = await createMachine(admin.cli, { name: "billing", kind: "service" }, await approved(admin, await createMachine(admin.cli, { name: "billing", kind: "service" })));
    expect(made.status, JSON.stringify(made.body)).toBe(201);
    expect(made.body.credential).toEqual(expect.any(String));
    const created = (await events("identity.created")).at(-1)!;
    expect(created.metadata).toMatchObject({ kind: "service", approvalId: expect.any(String), approvalUserVerified: true });
    // The first credential's event names the same approval.
    const first = (await rows(
      "SELECT metadata FROM audit_events WHERE event_type = 'credential.issued' AND resource ->> 'identityId' = $1",
      [made.body.id],
    )).map((r) => (typeof r.metadata === "string" ? JSON.parse(r.metadata) : r.metadata));
    expect(first).toEqual([expect.objectContaining({
      approvalId: created.metadata.approvalId,
      approvalPasskeyId: created.metadata.approvalPasskeyId,
      approvalUserVerified: true,
    })]);

    const issued = await issue(admin.cli, f.svc, { name: "job", ttlSeconds: 600 }, await approved(admin, await issue(admin.cli, f.svc, { name: "job", ttlSeconds: 600 })));
    expect(issued.status, JSON.stringify(issued.body)).toBe(201);
    expect((await events("credential.issued")).at(-1)!.metadata).toMatchObject({ name: "job", approvalId: expect.any(String) });

    const back = await reactivate(admin.cli, f.old, await approved(admin, await reactivate(admin.cli, f.old)));
    expect(back.status).toBe(200);
    expect((await identity(f.old)).disabled).toBe(false);
    expect((await events("identity.reactivated")).at(-1)!.metadata).toMatchObject({ approvalId: expect.any(String) });

    const bound = await addBinding(admin.cli, f.ci, ciBinding("repo:acme/web:*"), await approved(admin, await addBinding(admin.cli, f.ci, ciBinding("repo:acme/web:*"))));
    expect(bound.status).toBe(201);
    expect((await events("oidc_binding.created")).at(-1)!.metadata).toMatchObject({ subject: "repo:acme/web:*", approvalId: expect.any(String) });

    // The dashboard's own approval: asked and repeated by the browser bearer.
    const removal = await approved(admin, await removeBinding(admin.web, f.ci, bound.body.id));
    expect((await removeBinding(admin.web, f.ci, bound.body.id, removal)).status).toBe(204);
    expect((await events("oidc_binding.revoked")).at(-1)!.metadata).toMatchObject({ approvalId: removal });

    expect(await count("SELECT count(*)::int AS n FROM approval_intents WHERE consumed_at IS NOT NULL")).toBe(5);
    expect(await counters()).toBe(0);
  });

  it("identity.create binds the name, the kind, the requested limits and the effective TTL", async () => {
    const asked = await approved(admin, await createMachine(admin.cli, { name: "billing", kind: "service" }));
    // Another name, another kind, a TTL or a use budget given: another request.
    invalid(await createMachine(admin.cli, { name: "billing2", kind: "service" }, asked), "mismatch");
    invalid(await createMachine(admin.cli, { name: "billing", kind: "workload" }, asked), "mismatch");
    invalid(await createMachine(admin.cli, { name: "billing", kind: "service", credentialTtlSeconds: 3600 }, asked), "mismatch");
    invalid(await createMachine(admin.cli, { name: "billing", kind: "service", credentialMaxUses: 1 }, asked), "mismatch");
    expect(await machinesNamed("billing")).toBe(0);
    expect((await createMachine(admin.cli, { name: "billing", kind: "service" }, asked)).status).toBe(201);
    // Used: never again, even for the very same request.
    invalid(await createMachine(admin.cli, { name: "billing", kind: "service" }, asked), "consumed");
    expect(await machinesNamed("billing")).toBe(1);

    // A ci identity gets no credential: its credential fields bind null,
    // so sending them changes nothing the approval covers.
    const ci = await approved(admin, await createMachine(admin.cli, { name: "runner", kind: "ci" }));
    expect((await createMachine(admin.cli, { name: "runner", kind: "ci", credentialTtlSeconds: 60, credentialMaxUses: 3 }, ci)).status).toBe(201);
  });

  it("credential.issue binds the identity, the name and the limits", async () => {
    const other = (await ok("POST", "/v1/organizations/acme/identities", admin.cli, { name: "api-2", kind: "service" }, header(await approved(admin, await createMachine(admin.cli, { name: "api-2", kind: "service" }))))).id as string;
    const asked = await approved(admin, await issue(admin.cli, f.svc, { name: "job", maxUses: 3 }));
    invalid(await issue(admin.cli, other, { name: "job", maxUses: 3 }, asked), "mismatch");
    invalid(await issue(admin.cli, f.svc, { name: "job2", maxUses: 3 }, asked), "mismatch");
    invalid(await issue(admin.cli, f.svc, { name: "job" }, asked), "mismatch");
    invalid(await issue(admin.cli, f.svc, { name: "job", maxUses: 3, ttlSeconds: 60 }, asked), "mismatch");
    // Another operation with the same approval.
    invalid(await createMachine(admin.cli, { name: "job", kind: "service" }, asked), "mismatch");
    expect(await credentialsOf(f.svc)).toBe(1);
    expect((await issue(admin.cli, f.svc, { name: "job", maxUses: 3 }, asked)).status).toBe(201);
    expect(await credentialsOf(f.svc)).toBe(2);
    // A ci identity, a retired one and an unknown one are refused before any approval is asked for.
    const before = await intents();
    expect((await issue(admin.cli, f.ci, { name: "x" })).status).toBe(404);
    expect((await issue(admin.cli, f.old, { name: "x" })).status).toBe(404);
    expect((await issue(admin.cli, "idn_nope", { name: "x" })).status).toBe(404);
    expect(await intents()).toBe(before);
  });

  it("identity.reactivate binds the identity; an enabled identity needs no approval", async () => {
    const second = await ok("POST", IDS, admin.cli, { name: "w2", kind: "workload" }, header(await approved(admin, await createMachine(admin.cli, { name: "w2", kind: "workload" }))));
    await retire(admin.cli, second.id);
    const asked = await approved(admin, await reactivate(admin.cli, f.old));
    invalid(await reactivate(admin.cli, second.id, asked), "mismatch");
    expect((await identity(second.id)).disabled).toBe(true);
    expect((await reactivate(admin.cli, f.old, asked)).status).toBe(200);
    // Enabled now: reactivating again changes nothing, needs nothing, and
    // ignores the used approval, by a person or a machine.
    const before = await intents();
    expect((await reactivate(admin.cli, f.old)).status).toBe(200);
    expect((await reactivate(bot.token, f.old)).status).toBe(200);
    expect((await reactivate(admin.cli, f.svc, asked)).status).toBe(200);
    expect(await intents()).toBe(before);
  });

  it("oidc_binding.create binds the identity, issuer, audience, subject and claims; left-out claims bind {}", async () => {
    const asked = await approved(admin, await addBinding(admin.cli, f.ci, ciBinding("repo:acme/web:*")));
    invalid(await addBinding(admin.cli, f.svc, ciBinding("repo:acme/web:*"), asked), "mismatch");
    invalid(await addBinding(admin.cli, f.ci, ciBinding("repo:acme/web:ref:refs/heads/main"), asked), "mismatch");
    invalid(await addBinding(admin.cli, f.ci, { ...ciBinding("repo:acme/web:*"), audience: "other" }, asked), "mismatch");
    invalid(await addBinding(admin.cli, f.ci, ciBinding("repo:acme/web:*", { claims: { ref: "refs/heads/main" } }), asked), "mismatch");
    expect(await liveBindings(f.ci)).toBe(1);
    // An empty claims object matches the same tokens as none: the approval fits.
    expect((await addBinding(admin.cli, f.ci, ciBinding("repo:acme/web:*", { claims: {} }), asked)).status).toBe(201);
    // Claims bind as a map: their order does not matter.
    const claims = await approved(admin, await addBinding(admin.cli, f.ci, ciBinding("repo:acme/docs:*", { claims: { a: "1", b: "2" } })));
    expect((await addBinding(admin.cli, f.ci, ciBinding("repo:acme/docs:*", { claims: { b: "2", a: "1" } }), claims)).status).toBe(201);
    // An issuer the validation refuses is refused before any approval is asked for.
    const before = await intents();
    expect((await addBinding(admin.cli, f.ci, { ...ciBinding(), issuer: "http://ci.example" })).body.error.code).toBe("VALIDATION_FAILED");
    expect(await intents()).toBe(before);
  });

  it("oidc_binding.delete binds the identity and the binding", async () => {
    const second = await addBinding(admin.cli, f.ci, ciBinding("repo:acme/web:*"), await approved(admin, await addBinding(admin.cli, f.ci, ciBinding("repo:acme/web:*"))));
    const asked = await approved(admin, await removeBinding(admin.cli, f.ci, f.binding));
    invalid(await removeBinding(admin.cli, f.ci, second.body.id, asked), "mismatch");
    expect(await liveBindings(f.ci)).toBe(2);
    expect((await removeBinding(admin.cli, f.ci, f.binding, asked)).status).toBe(204);
    // Gone: an unknown binding is not found before any approval is asked for.
    const before = await intents();
    expect((await removeBinding(admin.cli, f.ci, f.binding)).status).toBe(404);
    expect(await intents()).toBe(before);
  });

  it("oidc_binding.delete names the binding by its id and audience: two bindings alike but for the audience read apart", async () => {
    const other = await addBinding(admin.cli, f.ci, { ...ciBinding(), audience: "other" }, await approved(admin, await addBinding(admin.cli, f.ci, { ...ciBinding(), audience: "other" })));
    expect(other.status).toBe(201);
    const first = stepUp(await removeBinding(admin.cli, f.ci, f.binding)).summary.title;
    const second = stepUp(await removeBinding(admin.cli, f.ci, other.body.id)).summary.title;
    expect(first).toBe(`Remove the OIDC binding ${f.binding} (issuer "${ISSUER}", subject "repo:acme/api:ref:refs/heads/main", audience "varlatch") from "deploy" (${f.ci})`);
    expect(second).toBe(`Remove the OIDC binding ${other.body.id} (issuer "${ISSUER}", subject "repo:acme/api:ref:refs/heads/main", audience "other") from "deploy" (${f.ci})`);
  });

  it("oidc_binding.create writes claims as a map: two claims never read like one claim holding a comma", async () => {
    // Codex's scenario.
    const two = stepUp(await addBinding(admin.cli, f.ci, ciBinding("repo:acme/x:*", { claims: { ref: "main", repo: "acme/api" } }))).summary;
    const one = stepUp(await addBinding(admin.cli, f.ci, ciBinding("repo:acme/x:*", { claims: { ref: "main, repo=acme/api" } }))).summary;
    expect(two.changes.at(-1)).toEqual({ field: "claims", from: null, to: '{"ref": "main", "repo": "acme/api"}', loosens: false });
    expect(one.changes.at(-1)).toEqual({ field: "claims", from: null, to: '{"ref": "main, repo=acme/api"}', loosens: false });
  });

  it("refuses another person's approval: even an admin finds nothing", async () => {
    const bob = await invite("Bob", "admin");
    const asked = await approved(admin, await createMachine(admin.cli, { name: "billing", kind: "service" }));
    invalid(await createMachine(bob.cli, { name: "billing", kind: "service" }, asked), "not-found");
    const removal = await approved(admin, await removeBinding(admin.cli, f.ci, f.binding));
    invalid(await removeBinding(bob.cli, f.ci, f.binding, removal), "not-found");
    expect(await machinesNamed("billing")).toBe(0);
    expect(await liveBindings(f.ci)).toBe(1);
  });

  it("refuses a machine credential outright, without an intent", async () => {
    for (const res of [
      await createMachine(bot.token, { name: "x", kind: "service" }),
      await issue(bot.token, f.svc, { name: "x" }),
      await reactivate(bot.token, f.old),
      await addBinding(bot.token, f.ci, ciBinding("repo:acme/web:*")),
      await removeBinding(bot.token, f.ci, f.binding),
    ]) {
      expect(res.status).toBe(403);
      expect(res.body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "machine-credential" } });
    }
    expect(await intents()).toBe(0);
    expect(await machinesNamed("x")).toBe(0);
    expect(await credentialsOf(f.svc)).toBe(1);
    expect((await identity(f.old)).disabled).toBe(true);
    expect(await liveBindings(f.ci)).toBe(1);
  });

  it("rolls the consumption back with a failed mutation: the approval stays usable", async () => {
    const asked = await approved(admin, await addBinding(admin.cli, f.ci, ciBinding("repo:acme/web:*")));
    await ctx.db.query(`CREATE FUNCTION fail_oidc_insert() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'injected failure'; END $$`);
    await ctx.db.query("CREATE TRIGGER fail_oidc_insert BEFORE INSERT ON oidc_bindings FOR EACH ROW EXECUTE FUNCTION fail_oidc_insert()");
    expect((await addBinding(admin.cli, f.ci, ciBinding("repo:acme/web:*"), asked)).status).toBe(500);
    expect((await rows("SELECT approved_at IS NOT NULL AS approved, consumed_at FROM approval_intents WHERE id = $1", [asked]))[0])
      .toEqual({ approved: true, consumed_at: null });
    await ctx.db.query("DROP TRIGGER fail_oidc_insert ON oidc_bindings");
    expect((await addBinding(admin.cli, f.ci, ciBinding("repo:acme/web:*"), asked)).status).toBe(201);
  });

  it("refuses a malformed Varlatch-Approval header once an approval is needed, without asking for one", async () => {
    invalid(await createMachine(admin.cli, { name: "x", kind: "service" }, "invalid"), "not-found");
    invalid(await removeBinding(admin.cli, f.ci, f.binding, "invalid"), "not-found");
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
          checks: [{ control: "admin-step-up", operation: "identity.create" }],
          binding: async () => identityCreateBinding({ id: orgId }, { name: "x", kind: "ci" }, false, undefined),
        });
      }));
    await expect(run).rejects.toMatchObject({ code: "STEP_UP_REQUIRED" });
    expect(attempts).toBe(1);
    expect(await rows("SELECT operation FROM approval_intents")).toEqual([{ operation: "identity.create" }]);
  });

  it("refuses a second consumption of one approval", async () => {
    const asked = stepUp(await createMachine(admin.cli, { name: "x", kind: "ci" }));
    await approve(admin, asked.id);
    const requester: Requester = { identityId: admin.id, identityKind: "human", credentialId: admin.cliId, credentialKind: "cli" };
    const prepare = () =>
      withApproval(ctx, { requester, approvalId: asked.id, publicUrl: PUBLIC_URL }, (gate) =>
        withTx(ctx.db, async (db) => prepareProtectedOperation(db, gate, {
          scope: { organizationId: orgId, people: [admin.id] },
          checks: [{ control: "admin-step-up", operation: "identity.create" }],
          binding: async () => identityCreateBinding({ id: orgId }, { name: "x", kind: "ci" }, false, undefined),
        })));
    expect((await prepare()).approval).toMatchObject({ id: asked.id, userVerified: true });
    const again = await prepare().catch((err: unknown) => err);
    expect(again).toBeInstanceOf(DomainError);
    expect(again).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "consumed" } });
  });

  it("is turned off by the operator's reset, which closes the open approvals of these operations", async () => {
    const asked = stepUp(await createMachine(admin.cli, { name: "billing", kind: "service" }));
    const removal = stepUp(await removeBinding(admin.cli, f.ci, f.binding));
    const outcome = await resetControls(ctx, { organization: "acme", controls: ["admin-step-up"] });
    expect(outcome.approvalsClosed).toBe(2);
    expect(await rows("SELECT id, close_reason FROM approval_intents ORDER BY id")).toEqual(
      [{ id: asked.id, close_reason: "reset" }, { id: removal.id, close_reason: "reset" }].sort((a, b) => (a.id < b.id ? -1 : 1)),
    );
    expect((await createMachine(admin.cli, { name: "billing", kind: "service" })).status).toBe(201);
  });
});

describe("with the other controls", () => {
  beforeEach(enforceAdminStepUp);

  it("credential-lifetime: an over-long TTL is refused first; the default is what the approval binds", async () => {
    expect((await setMode("credential-lifetime", "enforce", { defaultTtlSeconds: 3600, maxTtlSeconds: 86_400 })).status).toBe(200);
    const tooLong = await createMachine(admin.cli, { name: "billing", kind: "service", credentialTtlSeconds: 86_401 });
    expect(tooLong.body.error.code).toBe("CREDENTIAL_LIFETIME_EXCEEDED");
    expect(await intents()).toBe(0);

    const asked = stepUp(await createMachine(admin.cli, { name: "billing", kind: "service" }));
    expect(asked.summary.title).toBe('Create machine identity "billing" (service), with a credential that expires after 1 hour (the organization\'s default, since none was requested)');
    await approve(admin, asked.id);
    // An explicit TTL equal to the default is another request: it binds what was asked for.
    invalid(await createMachine(admin.cli, { name: "billing", kind: "service", credentialTtlSeconds: 3600 }, asked.id), "mismatch");
    // and its summary says the lifetime was asked for, not defaulted (follow-up e).
    expect(stepUp(await createMachine(admin.cli, { name: "billing", kind: "service", credentialTtlSeconds: 3600 })).summary).toMatchObject({
      title: 'Create machine identity "billing" (service), with a credential that expires after 1 hour (as requested)',
      changes: expect.arrayContaining([{ field: "credentialExpiry", from: null, to: "after 1 hour (as requested)", loosens: false }]),
    });
    // A new default (tightening needs no approval) changes the effective TTL: the approval no longer fits.
    expect((await setMode("credential-lifetime", "enforce", { defaultTtlSeconds: 1800, maxTtlSeconds: 86_400 })).status).toBe(200);
    invalid(await createMachine(admin.cli, { name: "billing", kind: "service" }, asked.id), "mismatch");
    expect(await machinesNamed("billing")).toBe(0);

    // One approval covers both controls.
    const again = await approved(admin, await createMachine(admin.cli, { name: "billing", kind: "service" }));
    const made = await createMachine(admin.cli, { name: "billing", kind: "service" }, again);
    expect(made.status).toBe(201);
    const expiresIn = (Date.parse(made.body.credentialExpiresAt) - Date.now()) / 1000;
    expect(expiresIn).toBeGreaterThan(1700);
    expect(expiresIn).toBeLessThanOrEqual(1800);
    const [issued] = (await events("credential.issued")).filter((e) => e.metadata.lifetimeDefaulted);
    expect(issued).toBeDefined();
  });

  it("credential-lifetime, for credential.issue: an over-long TTL is refused first; the default is what the approval binds", async () => {
    const svc = (await ok("POST", IDS, admin.cli, { name: "api", kind: "service" }, header(await approved(admin, await createMachine(admin.cli, { name: "api", kind: "service" }))))).id as string;
    expect((await setMode("credential-lifetime", "enforce", { defaultTtlSeconds: 3600, maxTtlSeconds: 86_400 })).status).toBe(200);
    const before = await intents();
    expect((await issue(admin.cli, svc, { name: "job", ttlSeconds: 86_401 })).body.error.code).toBe("CREDENTIAL_LIFETIME_EXCEEDED");
    expect(await intents()).toBe(before);

    const asked = stepUp(await issue(admin.cli, svc, { name: "job" }));
    expect(asked.summary.title).toBe(`Issue credential "job" for service "api" (${svc}), expiring after 1 hour (the organization's default, since none was requested), unlimited`);
    await approve(admin, asked.id);
    // An explicit TTL equal to the default is another request.
    invalid(await issue(admin.cli, svc, { name: "job", ttlSeconds: 3600 }, asked.id), "mismatch");
    expect(stepUp(await issue(admin.cli, svc, { name: "job", ttlSeconds: 3600 })).summary).toMatchObject({
      title: `Issue credential "job" for service "api" (${svc}), expiring after 1 hour (as requested), unlimited`,
      changes: expect.arrayContaining([{ field: "credentialExpiry", from: null, to: "after 1 hour (as requested)", loosens: false }]),
    });
    // A new default changes the effective TTL: the approval no longer fits.
    expect((await setMode("credential-lifetime", "enforce", { defaultTtlSeconds: 1800, maxTtlSeconds: 86_400 })).status).toBe(200);
    invalid(await issue(admin.cli, svc, { name: "job" }, asked.id), "mismatch");
    expect(await credentialsOf(svc)).toBe(1);

    // A fresh approval binds the new default, and the credential gets it.
    const again = await approved(admin, await issue(admin.cli, svc, { name: "job" }));
    const issued = await issue(admin.cli, svc, { name: "job" }, again);
    expect(issued.status, JSON.stringify(issued.body)).toBe(201);
    const expiresIn = (Date.parse(issued.body.expiresAt) - Date.now()) / 1000;
    expect(expiresIn).toBeGreaterThan(1700);
    expect(expiresIn).toBeLessThanOrEqual(1800);
    expect((await events("credential.issued")).at(-1)!.metadata).toMatchObject({ name: "job", lifetimeDefaulted: true, approvalId: again });
  });

  it("requirement-protection: each control asks for its own operations; one's approval never fits the other's", async () => {
    expect((await setMode("requirement-protection", "enforce")).status).toBe(200);
    const req = await ok("POST", `${ORG}/requirements`, admin.cli, { kind: "tailnet", target: { kind: "tier", tier: "staging" }, selector: { tailnet: "example.ts.net", tags: ["tag:ci"] } });
    const revoke = await approved(admin, await call("DELETE", `${ORG}/requirements/${req.id}`, admin.cli));
    invalid(await createMachine(admin.cli, { name: "billing", kind: "service" }, revoke), "mismatch");
    const create = await approved(admin, await createMachine(admin.cli, { name: "billing", kind: "service" }));
    invalid(await call("DELETE", `${ORG}/requirements/${req.id}`, admin.cli, undefined, header(create)), "mismatch");
    expect((await call("DELETE", `${ORG}/requirements/${req.id}`, admin.cli, undefined, header(revoke))).status).toBe(204);
    expect((await createMachine(admin.cli, { name: "billing", kind: "service" }, create)).status).toBe(201);
  });

  it("the incident freeze: refused operations answer it first; removing an OIDC binding is recovery and still asks", async () => {
    // Fixtures made before the freeze, with approvals.
    const ci = await ok("POST", IDS, admin.cli, { name: "deploy", kind: "ci" }, header(await approved(admin, await createMachine(admin.cli, { name: "deploy", kind: "ci" }))));
    const binding = await ok("POST", `${IDS}/${ci.id}/oidc-bindings`, admin.cli, ciBinding(), header(await approved(admin, await addBinding(admin.cli, ci.id, ciBinding()))));
    const pending = await approved(admin, await createMachine(admin.cli, { name: "billing", kind: "service" }));
    expect((await call("POST", `${ORG}/incident-freeze`, admin.cli, { reason: "A CI token leaked" })).status).toBe(201);
    expect((await rows("SELECT close_reason FROM approval_intents WHERE id = $1", [pending]))[0].close_reason).toBe("frozen");

    const before = await intents();
    expect((await createMachine(admin.cli, { name: "billing", kind: "service" })).body.error.code).toBe("ORGANIZATION_FROZEN");
    expect((await createMachine(admin.cli, { name: "billing", kind: "service" }, pending)).body.error.code).toBe("ORGANIZATION_FROZEN");
    expect((await addBinding(admin.cli, ci.id, ciBinding("repo:acme/web:*"))).body.error.code).toBe("ORGANIZATION_FROZEN");
    expect(await intents()).toBe(before);

    // Recovery: revoking the binding is allowed while frozen, and admin-step-up still asks for it.
    const removal = stepUp(await removeBinding(admin.cli, ci.id, binding.id));
    expect(removal.operation).toBe("oidc_binding.delete");
    await approve(admin, removal.id);
    expect((await removeBinding(admin.cli, ci.id, binding.id, removal.id)).status).toBe(204);
    expect(await liveBindings(ci.id)).toBe(0);
  });
});
