// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { createMachineIdentity, issueMachineCredential } from "../src/domain/identities.js";
import { ENFORCEABLE_CONTROLS, SECURITY_CONTROLS, resetControls } from "../src/domain/securitycontrols.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { personGate } from "./helpers/gates.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * credential-lifetime enforced (ADR-0054 Decision 5, step 4.3), on PGlite
 * under the lock-order check (test/helpers/lock-trace.ts). Its two
 * operations are machine-credential issuance: creating a service, workload
 * or broker identity with its first credential (identity.create) and
 * issuing another one (credential.issue). Under enforce, a request without
 * a TTL gets the Organization's default and one above the maximum is
 * refused with CREDENTIAL_LIFETIME_EXCEEDED before anything is created; at
 * the maximum it is accepted. With the control off nothing changes; report
 * mode is covered in security-report.test.ts. People's credentials,
 * agent-run credentials and identities that get no credential are never
 * affected. The incident freeze answers first; the operator's reset turns
 * it off; loosening its lifetimes needs an approval.
 */

const ORG = "/v1/organizations/acme";
const CONTROLS = `${ORG}/security/controls`;
const DEFAULT = 3600;
const MAX = 86_400;

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
  return { id: identityId, cli: cli.token, web: web.token, key };
}

async function controlOf(control: string) {
  return (await ok("GET", CONTROLS, admin.cli)).items.find((i: { control: string }) => i.control === control);
}

const change = async (body: Record<string, unknown>, approval?: string) =>
  call("PATCH", `${CONTROLS}/credential-lifetime`, admin.cli, { ...body, expectedVersion: (await controlOf("credential-lifetime")).version },
    approval ? { "Varlatch-Approval": approval } : {});

async function enforce(config = { defaultTtlSeconds: DEFAULT, maxTtlSeconds: MAX }) {
  const res = await change({ mode: "enforce", config });
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  expect(res.body).toMatchObject({ changed: true, control: { mode: "enforce", config } });
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

const createIdentity = (token: string, body: Record<string, unknown>) => call("POST", `${ORG}/identities`, token, body);
const issue = (token: string, identityId: string, body: Record<string, unknown>) => call("POST", `${ORG}/identities/${identityId}/credentials`, token, body);

/** Seconds from now until `iso`, rounded to the nearest second. */
const secondsUntil = (iso: string) => Math.round((Date.parse(iso) - Date.now()) / 1000);

/** Assert an expiry `ttl` seconds from now, within a minute of slack. */
function expiresIn(iso: string | null, ttl: number) {
  expect(iso).not.toBeNull();
  const left = secondsUntil(iso as string);
  expect(left).toBeGreaterThan(ttl - 60);
  expect(left).toBeLessThanOrEqual(ttl);
}

const issuedEvents = async () =>
  (await rows("SELECT metadata FROM audit_events WHERE event_type = 'credential.issued' AND organization_id = $1 ORDER BY event_order", [orgId]))
    .map((r) => parse(r.metadata) ?? {});
const counters = () => count("SELECT count(*)::int AS n FROM security_control_counters");
const identities = () => count("SELECT count(*)::int AS n FROM identities WHERE organization_id = $1", [orgId]);
const serviceCredentials = () => count("SELECT count(*)::int AS n FROM credentials WHERE kind = 'service'");

function exceeded(res: Answer, requested: number, max = MAX) {
  expect(res.status, JSON.stringify(res.body)).toBe(422);
  expect(res.body.error).toMatchObject({
    code: "CREDENTIAL_LIFETIME_EXCEEDED",
    details: { control: "credential-lifetime", requestedTtlSeconds: requested, maxTtlSeconds: max },
  });
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

describe("unlocking credential-lifetime", () => {
  it("advertises security.enforce.credential-lifetime and accepts enforce, as tightening, with its lifetimes", async () => {
    const meta = (await call("GET", "/v1/meta", admin.cli)).body.capabilities as string[];
    expect(meta).toContain("security.enforce.credential-lifetime");
    expect((await controlOf("credential-lifetime")).availableModes).toEqual(["off", "report", "enforce"]);
    // Lifetimes are required unless off.
    const bare = await change({ mode: "enforce" });
    expect(bare.status).toBe(422);
    expect(bare.body.error.code).toBe("VALIDATION_FAILED");
    expect((await change({ mode: "enforce", config: { defaultTtlSeconds: MAX, maxTtlSeconds: DEFAULT } })).status).toBe(422);
    expect((await change({ mode: "enforce", config: { defaultTtlSeconds: 0, maxTtlSeconds: DEFAULT } })).status).toBe(422);
    await enforce();
    expect(await count("SELECT count(*)::int AS n FROM approval_intents")).toBe(0);
    // The other locked controls still refuse enforce.
    for (const control of SECURITY_CONTROLS.filter((c) => !ENFORCEABLE_CONTROLS.has(c))) {
      const res = await call("PATCH", `${CONTROLS}/${control}`, admin.cli, { mode: "enforce", expectedVersion: 0 });
      expect(res.status, control).toBe(422);
      expect(res.body.error.code).toBe("CONTROL_MODE_UNAVAILABLE");
    }
    expect([...ENFORCEABLE_CONTROLS].sort()).toEqual(["credential-lifetime", "passkey-verification", "requirement-protection"]);
  });

  it("classifies lifetime changes under enforce: shorter is free, longer or turned down needs an approval, which then applies", async () => {
    await enforce();
    const tighter = await change({ config: { defaultTtlSeconds: 1800, maxTtlSeconds: 43_200 } });
    expect(tighter.body).toMatchObject({ changed: true, loosened: false });
    const longer = await change({ config: { defaultTtlSeconds: 1800, maxTtlSeconds: MAX } });
    expect(longer.status).toBe(403);
    expect(longer.body.error.code).toBe("STEP_UP_REQUIRED");
    const asked = longer.body.error.details.approval as { id: string; summary: { changes: { field: string; loosens: boolean }[] } };
    expect(asked.summary.changes).toEqual([expect.objectContaining({ field: "maxTtlSeconds", loosens: true })]);
    // Still the tighter maximum until it is approved.
    const machine = await ok("POST", `${ORG}/identities`, admin.cli, { name: "m", kind: "service", credentialTtlSeconds: 43_200 });
    exceeded(await issue(admin.cli, machine.id, { name: "long", ttlSeconds: MAX }), MAX, 43_200);
    await approve(admin, asked.id);
    expect((await change({ config: { defaultTtlSeconds: 1800, maxTtlSeconds: MAX } }, asked.id)).body).toMatchObject({ changed: true, loosened: true });
    expect((await issue(admin.cli, machine.id, { name: "long", ttlSeconds: MAX })).status).toBe(201);
    // enforce to report is loosening too.
    expect((await change({ mode: "report" })).body.error.code).toBe("STEP_UP_REQUIRED");
    expect((await controlOf("credential-lifetime")).mode).toBe("enforce");
  });
});

describe("with the control off", () => {
  it("issues exactly as before: no expiry without a TTL, any TTL up to the server's cap, no count, no new audit field", async () => {
    const none = await ok("POST", `${ORG}/identities`, admin.cli, { name: "none", kind: "service" });
    expect(none.credentialExpiresAt).toBeNull();
    const long = await ok("POST", `${ORG}/identities`, admin.cli, { name: "long", kind: "workload", credentialTtlSeconds: 315_360_000 });
    expiresIn(long.credentialExpiresAt, 315_360_000);
    const again = await ok("POST", `${ORG}/identities/${none.id}/credentials`, admin.cli, { name: "again" });
    expect(again.expiresAt).toBeNull();
    expect(await count("SELECT count(*)::int AS n FROM credentials WHERE kind = 'service' AND expires_at IS NULL")).toBe(2);
    expect(await counters()).toBe(0);
    expect(await count("SELECT count(*)::int AS n FROM security_controls")).toBe(0);
    for (const metadata of await issuedEvents()) expect(metadata).not.toHaveProperty("lifetimeDefaulted");
    // The same with the control turned on and off again.
    await enforce();
    await resetControls(ctx, { organization: "acme", controls: ["credential-lifetime"] });
    expect((await ok("POST", `${ORG}/identities/${none.id}/credentials`, admin.cli, { name: "after" })).expiresAt).toBeNull();
  });
});

describe("credential-lifetime at enforce", () => {
  it("identity.create: the default without a TTL, the TTL asked for up to the maximum, a refusal above it with nothing created", async () => {
    await enforce();
    const defaulted = await ok("POST", `${ORG}/identities`, admin.cli, { name: "defaulted", kind: "service" });
    expiresIn(defaulted.credentialExpiresAt, DEFAULT);
    expect((await rows("SELECT expires_at FROM credentials WHERE identity_id = $1", [defaulted.id]))[0].expires_at).not.toBeNull();
    const short = await ok("POST", `${ORG}/identities`, admin.cli, { name: "short", kind: "workload", credentialTtlSeconds: 120 });
    expiresIn(short.credentialExpiresAt, 120);
    const atMax = await ok("POST", `${ORG}/identities`, admin.cli, { name: "at-max", kind: "broker", credentialTtlSeconds: MAX });
    expiresIn(atMax.credentialExpiresAt, MAX);
    const [machines, creds, events] = [await identities(), await serviceCredentials(), (await issuedEvents()).length];
    exceeded(await createIdentity(admin.cli, { name: "too-long", kind: "service", credentialTtlSeconds: MAX + 1 }), MAX + 1);
    expect([await identities(), await serviceCredentials(), (await issuedEvents()).length]).toEqual([machines, creds, events]);
    expect(await count("SELECT count(*)::int AS n FROM identities WHERE name = 'too-long'")).toBe(0);
    // Only the defaulted credential says so in its audit event.
    expect((await issuedEvents()).map((m) => m.lifetimeDefaulted ?? false)).toEqual([true, false, false]);
    // Enforce refuses or changes; it never counts.
    expect(await counters()).toBe(0);
  });

  it("identity.create of a kind that gets no credential is not affected, whatever TTL it carries", async () => {
    await enforce();
    for (const kind of ["ci", "agent"]) {
      const created = await ok("POST", `${ORG}/identities`, admin.cli, { name: kind, kind, credentialTtlSeconds: MAX * 10 });
      expect(created).toMatchObject({ credential: null, credentialExpiresAt: null });
    }
  });

  it("credential.issue: the default without a TTL, at the maximum accepted, above it refused with nothing issued", async () => {
    const machine = await ok("POST", `${ORG}/identities`, admin.cli, { name: "m", kind: "service" });
    await enforce();
    const defaulted = await ok("POST", `${ORG}/identities/${machine.id}/credentials`, admin.cli, { name: "defaulted" });
    expiresIn(defaulted.expiresAt, DEFAULT);
    const atMax = await ok("POST", `${ORG}/identities/${machine.id}/credentials`, admin.cli, { name: "at-max", ttlSeconds: MAX, maxUses: 5 });
    expect(atMax).toMatchObject({ maxUses: 5 });
    expiresIn(atMax.expiresAt, MAX);
    const before = await serviceCredentials();
    exceeded(await issue(admin.cli, machine.id, { name: "too-long", ttlSeconds: MAX + 1 }), MAX + 1);
    expect(await serviceCredentials()).toBe(before);
    const metadata = await issuedEvents();
    expect(metadata.at(-2)).toMatchObject({ name: "defaulted", lifetimeDefaulted: true, expiresAt: defaulted.expiresAt });
    expect(metadata.at(-1)).toMatchObject({ name: "at-max", expiresAt: atMax.expiresAt });
    expect(metadata.at(-1)).not.toHaveProperty("lifetimeDefaulted");
    // An unknown identity is not found, whatever its TTL.
    expect((await issue(admin.cli, "idn_missing", { name: "x", ttlSeconds: MAX + 1 })).status).toBe(404);
    // The credential it issued keeps the expiry it got: existing credentials never change.
    await resetControls(ctx, { organization: "acme", controls: ["credential-lifetime"] });
    expect((await rows("SELECT expires_at FROM credentials WHERE name = 'defaulted'"))[0].expires_at).not.toBeNull();
  });

  it("never changes a credential that existed before it was enforced", async () => {
    const machine = await ok("POST", `${ORG}/identities`, admin.cli, { name: "m", kind: "service" });
    await enforce({ defaultTtlSeconds: 60, maxTtlSeconds: 60 });
    expect(await count("SELECT count(*)::int AS n FROM credentials WHERE identity_id = $1 AND expires_at IS NULL", [machine.id])).toBe(1);
    expect((await call("GET", "/v1/me", machine.credential)).status).toBe(200);
  });

  it("applies to a machine credential that issues, as to a person", async () => {
    const robot = await ok("POST", `${ORG}/identities`, admin.cli, { name: "robot", kind: "service" });
    await ok("POST", `${ORG}/grants`, admin.cli, { subjectIdentityId: robot.id, scope: { kind: "organization" }, actions: ["identity.manage"] });
    await enforce();
    const made = await ok("POST", `${ORG}/identities`, robot.credential, { name: "made-by-robot", kind: "service" });
    expiresIn(made.credentialExpiresAt, DEFAULT);
    exceeded(await createIdentity(robot.credential, { name: "too-long", kind: "service", credentialTtlSeconds: MAX * 2 }), MAX * 2);
    const issued = await ok("POST", `${ORG}/identities/${made.id}/credentials`, robot.credential, { name: "again" });
    expiresIn(issued.expiresAt, DEFAULT);
    exceeded(await issue(robot.credential, made.id, { name: "too-long", ttlSeconds: MAX * 2 }), MAX * 2);
    // No approval is involved, for a machine or a person.
    expect(await count("SELECT count(*)::int AS n FROM approval_intents")).toBe(0);
  });

  it("covers direct callers of the domain functions too", async () => {
    await enforce();
    const made = await createMachineIdentity(ctx, personGate(admin.id), orgId, { name: "direct", kind: "service" });
    expiresIn(made.credentialExpiresAt, DEFAULT);
    await expect(createMachineIdentity(ctx, personGate(admin.id), orgId, { name: "direct-long", kind: "service", credentialTtlSeconds: MAX + 1 }))
      .rejects.toMatchObject({ code: "CREDENTIAL_LIFETIME_EXCEEDED" });
    // A direct caller's 0 would mean "never expires": refused, as are a
    // negative and a fractional lifetime, for both domain functions.
    for (const ttl of [0, -1, 1.5]) {
      await expect(createMachineIdentity(ctx, personGate(admin.id), orgId, { name: `direct-${ttl}`, kind: "service", credentialTtlSeconds: ttl }))
        .rejects.toMatchObject({ code: "VALIDATION_FAILED" });
      await expect(issueMachineCredential(ctx, personGate(admin.id), orgId, made.identity.id, { name: `c-${ttl}`, ttlSeconds: ttl }))
        .rejects.toMatchObject({ code: "VALIDATION_FAILED" });
    }
  });

  it("leaves people's credentials and agent-run credentials alone", async () => {
    await enforce({ defaultTtlSeconds: 60, maxTtlSeconds: 60 });
    // A person's CLI credential from the dashboard handoff: its own bounds (up to 24 hours).
    const handoff = await ok("POST", "/v1/me/credentials/cli", admin.web, { ttlSeconds: 86_400 });
    expiresIn(handoff.expiresAt, 86_400);
    // An agent-run credential minted by a broker: its own cap (an hour).
    const broker = await ok("POST", `${ORG}/identities`, admin.cli, { name: "broker", kind: "broker", credentialTtlSeconds: 60 });
    const agent = await ok("POST", `${ORG}/identities`, admin.cli, { name: "agent", kind: "agent" });
    const run = await ok("POST", `${ORG}/identities/${agent.id}/credentials`, broker.credential, { ttlSeconds: 600 });
    expiresIn(run.expiresAt, 600);
  });

  it("answers the incident freeze first", async () => {
    const machine = await ok("POST", `${ORG}/identities`, admin.cli, { name: "m", kind: "service" });
    await enforce();
    expect((await call("POST", `${ORG}/incident-freeze`, admin.cli, { reason: "A CI token leaked" })).status).toBe(201);
    expect((await createIdentity(admin.cli, { name: "late", kind: "service", credentialTtlSeconds: MAX + 1 })).body.error.code).toBe("ORGANIZATION_FROZEN");
    expect((await issue(admin.cli, machine.id, { name: "late", ttlSeconds: MAX + 1 })).body.error.code).toBe("ORGANIZATION_FROZEN");
    expect((await issue(admin.cli, machine.id, { name: "late" })).body.error.code).toBe("ORGANIZATION_FROZEN");
  });

  it("makes removing a trusted passkey need an approval, as any enforced control does", async () => {
    const grant = await issueInviteGrant(ctx, { organizationId: orgId, role: "member", name: "Member" }, admin.id);
    const member = await person((await consumeSetupGrant(ctx, grant.token, {})).identityId);
    const spare = await registerSoftPasskey(ctx.db, member.id, { ...RP, trust: "trusted" });
    await enforce();
    const res = await call("DELETE", `/v1/me/passkeys/${spare.passkeyId}`, member.web);
    expect(res.status).toBe(403);
    expect(res.body.error).toMatchObject({ code: "STEP_UP_REQUIRED", details: { approval: { operation: "passkey.remove" } } });
    await resetControls(ctx, { organization: "acme", controls: ["credential-lifetime"] });
    expect((await call("DELETE", `/v1/me/passkeys/${spare.passkeyId}`, member.web)).status).toBe(204);
  });

  it("is turned off by the operator's reset: issuance is as before again", async () => {
    const machine = await ok("POST", `${ORG}/identities`, admin.cli, { name: "m", kind: "service" });
    await enforce();
    exceeded(await issue(admin.cli, machine.id, { name: "long", ttlSeconds: MAX + 1 }), MAX + 1);
    await resetControls(ctx, { organization: "acme", controls: ["credential-lifetime"] });
    expect((await issue(admin.cli, machine.id, { name: "long", ttlSeconds: MAX + 1 })).status).toBe(201);
    expect((await issue(admin.cli, machine.id, { name: "none" })).body.expiresAt).toBeNull();
  });
});
