// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CAPABILITIES } from "@varlatch/protocol";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { withSerializableTx, withTx } from "../src/db/tx.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { withApproval, type Requester } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { DomainError } from "../src/domain/errors.js";
import { prepareProtectedOperation } from "../src/domain/protected.js";
import { readRequirement, requirementRevokeBinding } from "../src/domain/requirementprotection.js";
import { ENFORCEABLE_CONTROLS, SECURITY_CONTROLS, enforceCapability, resetControls } from "../src/domain/securitycontrols.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * requirement-protection enforced, and the shared enforcement it is built
 * on (ADR-0054 step 4.2, prepareProtectedOperation), on PGlite under the
 * lock-order check (test/helpers/lock-trace.ts): only unlocked controls
 * accept enforce; with every control off or in report mode nothing is
 * refused; under enforce, editing and revoking a Tailnet Requirement need
 * the requester's step-up approval bound to exactly that request (person,
 * target, body, version), creating one does not; a machine credential is
 * refused without an intent; ApprovalNeeded escapes a serializable
 * transaction and an Idempotency-Key claim without a retry or a claim left
 * behind; consumption rolls back with a failed mutation; the incident
 * freeze answers first; the operator's reset; and the passkey.remove
 * restriction, now reachable through the API. The live Better Auth paths
 * (removing a trusted passkey, the native delete path, host recovery) run
 * on real PostgreSQL in passkey-evidence-postgres.test.ts.
 */

const ORG = "/v1/organizations/acme";
const CONTROLS = `${ORG}/security/controls`;
const REQS = `${ORG}/requirements`;

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
const withApprovalHeader = (approval?: string) => (approval ? { "Varlatch-Approval": approval } : {});

async function person(identityId: string, trust: "trusted" | "unconfirmed" = "trusted"): Promise<Person> {
  const cli = await issueCredential(ctx.db, { identityId, kind: "cli", name: "test cli" });
  const key = await registerSoftPasskey(ctx.db, identityId, { ...RP, trust });
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

/** A machine identity of the Organization with these actions everywhere. */
async function machine(actions: string[]) {
  const created = await ok("POST", `${ORG}/identities`, admin.cli, { name: "robot", kind: "service" });
  await ok("POST", `${ORG}/grants`, admin.cli, { subjectIdentityId: created.id, scope: { kind: "organization" }, actions });
  return { id: created.id as string, token: created.credential as string };
}

async function controlOf(control: string) {
  return (await ok("GET", CONTROLS, admin.cli)).items.find((i: { control: string }) => i.control === control);
}

const setMode = async (control: string, mode: string) =>
  call("PATCH", `${CONTROLS}/${control}`, admin.cli, { mode, expectedVersion: (await controlOf(control)).version });

async function enforce() {
  const res = await setMode("requirement-protection", "enforce");
  expect(res.status, JSON.stringify(res.body)).toBe(200);
}

async function requirement(tier = "staging", tags = ["tag:ci"]) {
  return (await ok("POST", REQS, admin.cli, { kind: "tailnet", target: { kind: "tier", tier }, selector: { tailnet: "example.ts.net", tags } })) as { id: string };
}

const edit = (token: string, id: string, body: Record<string, unknown>, approval?: string, headers: Record<string, string> = {}) =>
  call("PATCH", `${REQS}/${id}`, token, body, { ...withApprovalHeader(approval), ...headers });
const revoke = (token: string, id: string, approval?: string) => call("DELETE", `${REQS}/${id}`, token, undefined, withApprovalHeader(approval));
const tags = (expectedVersion: number, list: string[]) => ({ expectedVersion, selector: { tailnet: "example.ts.net", tags: list } });

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

const versionOf = async (id: string) => (await rows("SELECT version, revoked_at FROM requirements WHERE id = $1", [id]))[0] as { version: number; revoked_at: unknown };

async function events(eventType: string) {
  const parse = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v) as Record<string, any> | null;
  return (await rows("SELECT actor_identity_id, metadata FROM audit_events WHERE event_type = $1 ORDER BY event_order", [eventType]))
    .map((r) => ({ actor: r.actor_identity_id, metadata: parse(r.metadata) ?? {} }));
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

describe("which controls can enforce", () => {
  it("advertises security.enforce.<control> for the unlocked controls, and offers enforce for them only", async () => {
    const meta = (await call("GET", "/v1/meta", admin.cli)).body.capabilities as string[];
    expect(meta.filter((c) => c.startsWith("security.enforce."))).toEqual([
      "security.enforce.requirement-protection",
      "security.enforce.credential-lifetime",
      "security.enforce.passkey-verification",
      "security.enforce.admin-step-up",
    ]);
    // The release's list and the capabilities say the same.
    expect(CAPABILITIES.filter((c) => c.startsWith("security.enforce."))).toEqual([...ENFORCEABLE_CONTROLS].map(enforceCapability));
    const list = (await ok("GET", CONTROLS, admin.cli)) as { items: { control: string; availableModes: string[] }[]; availableModes: string[] };
    expect(list.availableModes).toEqual(["off", "report"]);
    expect(Object.fromEntries(list.items.map((i) => [i.control, i.availableModes]))).toEqual({
      "requirement-protection": ["off", "report", "enforce"],
      "admin-step-up": ["off", "report", "enforce"],
      "passkey-verification": ["off", "report", "enforce"],
      "credential-lifetime": ["off", "report", "enforce"],
    });
  });

  it("accepts enforce only for an unlocked control; turning it on is tightening, turning it down needs an approval", async () => {
    for (const control of SECURITY_CONTROLS.filter((c) => !ENFORCEABLE_CONTROLS.has(c))) {
      const res = await setMode(control, "enforce");
      expect(res.status, control).toBe(422);
      expect(res.body.error).toMatchObject({ code: "CONTROL_MODE_UNAVAILABLE", details: { control, mode: "enforce", availableModes: ["off", "report"] } });
    }
    expect(await count("SELECT count(*)::int AS n FROM security_controls")).toBe(0);
    const on = await setMode("requirement-protection", "enforce");
    expect(on.status).toBe(200);
    expect(on.body).toMatchObject({ changed: true, loosened: false, control: { mode: "enforce", version: 1 } });
    expect(await intents()).toBe(0);
    const down = stepUp(await setMode("requirement-protection", "report"));
    expect(down.operation).toBe("security_control.change");
    expect((await controlOf("requirement-protection")).mode).toBe("enforce");
  });
});

describe("with every control off", () => {
  it("edits and revokes as before: no approval, no count, no intent, and audit as before", async () => {
    const r = await requirement();
    expect((await edit(admin.cli, r.id, tags(1, ["tag:prod"]))).status).toBe(200);
    expect((await revoke(admin.cli, r.id)).status).toBe(204);
    expect(await intents()).toBe(0);
    expect(await count("SELECT count(*)::int AS n FROM security_control_counters")).toBe(0);
    const [updated] = await events("requirement.updated");
    expect(Object.keys(updated!.metadata).sort()).toEqual(["newSelector", "newTarget", "oldSelector", "oldTarget", "version"]);
    const [revoked] = await events("requirement.revoked");
    expect(revoked!.metadata).not.toHaveProperty("approvalId");
  });

  it("ignores a malformed Varlatch-Approval header, as before: edit, revoke and a cached replay", async () => {
    const r = await requirement();
    const key = { "Idempotency-Key": "edit-off" };
    const done = await edit(admin.cli, r.id, tags(1, ["tag:prod"]), "invalid", key);
    expect(done.status, JSON.stringify(done.body)).toBe(200);
    const replay = await edit(admin.cli, r.id, tags(1, ["tag:prod"]), "invalid", key);
    expect(replay).toEqual(done);
    expect(await versionOf(r.id)).toEqual({ version: 2, revoked_at: null });
    expect((await revoke(admin.cli, r.id, "invalid")).status).toBe(204);
    expect(await intents()).toBe(0);
  });
});

describe("in report mode", () => {
  it("refuses nothing and counts each edit and revocation, by a person and by a machine", async () => {
    expect((await setMode("requirement-protection", "report")).status).toBe(200);
    const robot = await machine(["policy.manage"]);
    const r = await requirement();
    expect((await edit(admin.cli, r.id, tags(1, ["tag:prod"]))).status).toBe(200);
    expect((await edit(robot.token, r.id, tags(2, ["tag:dev"]))).status).toBe(200);
    expect((await revoke(robot.token, r.id)).status).toBe(204);
    expect(await intents()).toBe(0);
    const counted = await rows(
      "SELECT operation, reason, actor_identity_id, count::int AS count FROM security_control_counters ORDER BY operation, reason",
    );
    expect(counted).toEqual([
      { operation: "requirement.revoke", reason: "machine-credential", actor_identity_id: robot.id, count: 1 },
      { operation: "requirement.update", reason: "machine-credential", actor_identity_id: robot.id, count: 1 },
      { operation: "requirement.update", reason: "no-approval", actor_identity_id: admin.id, count: 1 },
    ]);
  });
});

describe("under enforce", () => {
  beforeEach(enforce);

  it("creating needs no approval; editing and revoking do, and change nothing without one", async () => {
    const r = await requirement();
    expect(await intents()).toBe(0);
    const editing = stepUp(await edit(admin.cli, r.id, tags(1, ["tag:ci", "tag:prod"])));
    expect(editing).toMatchObject({ operation: "requirement.update", organization: { id: orgId, slug: "acme" }, state: "pending" });
    expect(editing.summary).toEqual({
      title: `Change the Tailnet Requirement ${r.id} on the staging tier`,
      changes: [{ field: "selector", from: 'tailnet "example.ts.net": tags ["tag:ci"]', to: 'tailnet "example.ts.net": tags ["tag:ci", "tag:prod"]', loosens: true }],
    });
    const revoking = stepUp(await revoke(admin.cli, r.id));
    expect(revoking).toMatchObject({ operation: "requirement.revoke", organization: { id: orgId } });
    expect(revoking.summary.title).toBe(
      `Remove the Tailnet Requirement ${r.id} on the staging tier (tailnet "example.ts.net": tags ["tag:ci"]). What it constrained is no longer constrained`,
    );
    expect(await versionOf(r.id)).toEqual({ version: 1, revoked_at: null });
    expect(await events("requirement.updated")).toEqual([]);
    expect(await events("requirement.revoked")).toEqual([]);
    // Nothing is counted under enforce.
    expect(await count("SELECT count(*)::int AS n FROM security_control_counters")).toBe(0);
  });

  it("says when an edit only restricts: fewer tags, another environment added", async () => {
    const r = await requirement("staging", ["tag:ci", "tag:prod"]);
    const narrower = stepUp(await edit(admin.cli, r.id, tags(1, ["tag:ci"])));
    expect(narrower.summary.changes).toEqual([
      { field: "selector", from: 'tailnet "example.ts.net": tags ["tag:ci", "tag:prod"]', to: 'tailnet "example.ts.net": tags ["tag:ci"]', loosens: false },
    ]);
    const moved = stepUp(await edit(admin.cli, r.id, { expectedVersion: 1, target: { kind: "tier", tier: "production" } }));
    expect(moved.summary.changes).toEqual([{ field: "target", from: "the staging tier", to: "the production tier", loosens: true }]);
  });

  it("names the Requirement by its id: two alike in target and selector read apart; selector parts are quoted", async () => {
    const a = await requirement();
    const b = await requirement();
    const revokeA = stepUp(await revoke(admin.cli, a.id)).summary.title;
    const revokeB = stepUp(await revoke(admin.cli, b.id)).summary.title;
    expect(revokeA).toContain(`Requirement ${a.id} on`);
    expect(revokeB).toContain(`Requirement ${b.id} on`);
    expect(revokeA).not.toBe(revokeB);
    const editA = stepUp(await edit(admin.cli, a.id, tags(1, ["tag:ci", "tag:prod"]))).summary;
    const editB = stepUp(await edit(admin.cli, b.id, tags(1, ["tag:ci", "tag:prod"]))).summary;
    expect(editA.title).toBe(`Change the Tailnet Requirement ${a.id} on the staging tier`);
    expect(editB.title).toBe(`Change the Tailnet Requirement ${b.id} on the staging tier`);
    // A tag holding a comma is one tag, not two.
    const r = await requirement("production", ["tag:a"]);
    const comma = stepUp(await edit(admin.cli, r.id, tags(1, ["tag:a, tag:b"]))).summary;
    expect(comma.changes).toEqual([{ field: "selector", from: 'tailnet "example.ts.net": tags ["tag:a"]', to: 'tailnet "example.ts.net": tags ["tag:a, tag:b"]', loosens: true }]);
  });

  it("runs the whole flow: approve, repeat with the header, used once, recorded with the approval", async () => {
    const r = await requirement();
    const asked = stepUp(await edit(admin.cli, r.id, tags(1, ["tag:prod"])));
    await approve(admin, asked.id);
    const done = await edit(admin.cli, r.id, tags(1, ["tag:prod"]), asked.id);
    expect(done.status, JSON.stringify(done.body)).toBe(200);
    expect(done.body).toMatchObject({ version: 2, selector: { tags: ["tag:prod"] } });
    const [updated] = await events("requirement.updated");
    expect(updated!.metadata).toMatchObject({ approvalId: asked.id, approvalUserVerified: true, version: 2 });
    expect((await rows("SELECT consumed_at IS NOT NULL AS used FROM approval_intents WHERE id = $1", [asked.id]))[0].used).toBe(true);

    const removal = stepUp(await revoke(admin.cli, r.id));
    await approve(admin, removal.id);
    expect((await revoke(admin.cli, r.id, removal.id)).status).toBe(204);
    expect((await versionOf(r.id)).revoked_at).not.toBeNull();
    const [revoked] = await events("requirement.revoked");
    expect(revoked!.metadata).toMatchObject({ approvalId: removal.id });
  });

  it("binds the approval to the person, the target, the body, the operation and the version", async () => {
    const bob = await invite("Bob", "admin");
    const r = await requirement();
    const other = await requirement("development");
    const asked = stepUp(await edit(admin.cli, r.id, tags(1, ["tag:prod"])));
    await approve(admin, asked.id);
    // Another person, even an admin, finds nothing.
    expect((await edit(bob.cli, r.id, tags(1, ["tag:prod"]), asked.id)).body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "not-found" } });
    // Another target, another body, another operation.
    expect((await edit(admin.cli, other.id, tags(1, ["tag:prod"]), asked.id)).body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "mismatch" } });
    expect((await edit(admin.cli, r.id, tags(1, ["tag:dev"]), asked.id)).body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "mismatch" } });
    expect((await revoke(admin.cli, r.id, asked.id)).body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "mismatch" } });
    // A left-out list and a reordered set bind the same: the approval still fits.
    expect((await edit(admin.cli, r.id, { expectedVersion: 1, selector: { tailnet: "example.ts.net", tags: ["tag:prod", "tag:prod"], users: [] } }, asked.id)).status).toBe(200);
    expect(await versionOf(r.id)).toEqual({ version: 2, revoked_at: null });

    // The version the server read for a revocation: an edit since makes the approval stale.
    const removal = stepUp(await revoke(admin.cli, other.id));
    await approve(admin, removal.id);
    const change = stepUp(await edit(admin.cli, other.id, tags(1, ["tag:dev"])));
    await approve(admin, change.id);
    expect((await edit(admin.cli, other.id, tags(1, ["tag:dev"]), change.id)).status).toBe(200);
    expect((await revoke(admin.cli, other.id, removal.id)).body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "stale" } });
    expect((await versionOf(other.id)).revoked_at).toBeNull();
  });

  it("needs no approval for an edit that changes nothing, and refuses first what would be refused anyway", async () => {
    const r = await requirement();
    expect((await edit(admin.cli, r.id, { expectedVersion: 1 })).status).toBe(200);
    // The same selector in another key order, with a duplicate: written as
    // before (a new version), and it needed no approval.
    expect((await edit(admin.cli, r.id, { expectedVersion: 1, selector: { tags: ["tag:ci", "tag:ci"], tailnet: "example.ts.net" } })).status).toBe(200);
    expect((await edit(admin.cli, r.id, tags(1, ["tag:prod"]))).body.error.code).toBe("VERSION_CONFLICT");
    expect((await edit(admin.cli, "req_nope", tags(1, ["tag:prod"]))).status).toBe(404);
    expect((await revoke(admin.cli, "req_nope")).status).toBe(404);
    expect(await intents()).toBe(0);
  });

  it("refuses a machine credential outright, without an intent", async () => {
    const robot = await machine(["policy.manage"]);
    const r = await requirement();
    for (const res of [await edit(robot.token, r.id, tags(1, ["tag:prod"])), await revoke(robot.token, r.id)]) {
      expect(res.status).toBe(403);
      expect(res.body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "machine-credential" } });
    }
    expect(await intents()).toBe(0);
    expect(await versionOf(r.id)).toEqual({ version: 1, revoked_at: null });
  });

  it("rolls the consumption back with a failed mutation: the approval stays usable", async () => {
    const r = await requirement();
    const removal = stepUp(await revoke(admin.cli, r.id));
    await approve(admin, removal.id);
    await ctx.db.query(`CREATE FUNCTION fail_requirement_update() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'injected failure'; END $$`);
    await ctx.db.query("CREATE TRIGGER fail_requirement_update BEFORE UPDATE ON requirements FOR EACH ROW EXECUTE FUNCTION fail_requirement_update()");
    expect((await revoke(admin.cli, r.id, removal.id)).status).toBe(500);
    expect((await rows("SELECT approved_at IS NOT NULL AS approved, consumed_at FROM approval_intents WHERE id = $1", [removal.id]))[0])
      .toEqual({ approved: true, consumed_at: null });
    await ctx.db.query("DROP TRIGGER fail_requirement_update ON requirements");
    expect((await revoke(admin.cli, r.id, removal.id)).status).toBe(204);
  });

  it("refuses a malformed Varlatch-Approval header once an approval is needed, without asking for one", async () => {
    const r = await requirement();
    expect((await edit(admin.cli, r.id, tags(1, ["tag:prod"]), "invalid")).body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "not-found" } });
    expect((await revoke(admin.cli, r.id, "invalid")).body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "not-found" } });
    expect(await intents()).toBe(0);
    expect(await versionOf(r.id)).toEqual({ version: 1, revoked_at: null });
    // An empty header is still a header: the requester is locked FOR UPDATE
    // before the Idempotency-Key claim, never KEY SHARE first and upgraded
    // (the lock-order check fails the test otherwise).
    const empty = await edit(admin.cli, r.id, tags(1, ["tag:prod"]), undefined, { "Varlatch-Approval": "", "Idempotency-Key": "edit-empty" });
    expect(empty.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "not-found" } });
    expect(await count("SELECT count(*)::int AS n FROM idempotency_keys")).toBe(0);
  });

  it("asks under an Idempotency-Key without leaving a claim; the approved repeat claims it once", async () => {
    const r = await requirement();
    const key = { "Idempotency-Key": "edit-1" };
    const asked = stepUp(await edit(admin.cli, r.id, tags(1, ["tag:prod"]), undefined, key));
    expect(await count("SELECT count(*)::int AS n FROM idempotency_keys")).toBe(0);
    await approve(admin, asked.id);
    const done = await edit(admin.cli, r.id, tags(1, ["tag:prod"]), asked.id, key);
    expect(done.status, JSON.stringify(done.body)).toBe(200);
    expect(await count("SELECT count(*)::int AS n FROM idempotency_keys")).toBe(1);
    // A replay answers from the stored response, approval or not, and changes nothing.
    const replay = await edit(admin.cli, r.id, tags(1, ["tag:prod"]), undefined, key);
    expect(replay).toEqual(done);
    expect(await versionOf(r.id)).toEqual({ version: 2, revoked_at: null });
    expect(await events("requirement.updated")).toHaveLength(1);
  });

  it("lets ApprovalNeeded escape a serializable transaction without a retry", async () => {
    const r = await requirement();
    const requester: Requester = { identityId: admin.id, identityKind: "human", credentialId: admin.cliId, credentialKind: "cli" };
    let attempts = 0;
    const run = withApproval(ctx, { requester, approvalId: null, publicUrl: PUBLIC_URL }, (gate) =>
      withSerializableTx(ctx.db, async (db) => {
        attempts++;
        await prepareProtectedOperation(db, gate, {
          scope: { organizationId: orgId, people: [admin.id] },
          checks: [{ control: "requirement-protection", operation: "requirement.revoke" }],
          binding: async (db) => requirementRevokeBinding(db, { id: orgId }, (await readRequirement(db, orgId, r.id))!),
        });
      }));
    await expect(run).rejects.toMatchObject({ code: "STEP_UP_REQUIRED" });
    expect(attempts).toBe(1);
    expect(await rows("SELECT operation, state FROM (SELECT operation, CASE WHEN approved_at IS NULL THEN 'pending' END AS state FROM approval_intents) x"))
      .toEqual([{ operation: "requirement.revoke", state: "pending" }]);
  });

  it("refuses a second consumption of one approval", async () => {
    const r = await requirement();
    const asked = stepUp(await revoke(admin.cli, r.id));
    await approve(admin, asked.id);
    const requester: Requester = { identityId: admin.id, identityKind: "human", credentialId: admin.cliId, credentialKind: "cli" };
    const prepare = () =>
      withApproval(ctx, { requester, approvalId: asked.id, publicUrl: PUBLIC_URL }, (gate) =>
        withTx(ctx.db, async (db) => prepareProtectedOperation(db, gate, {
          scope: { organizationId: orgId, people: [admin.id] },
          checks: [{ control: "requirement-protection", operation: "requirement.revoke" }],
          binding: async (db) => requirementRevokeBinding(db, { id: orgId }, (await readRequirement(db, orgId, r.id))!),
        })));
    expect((await prepare()).approval).toMatchObject({ id: asked.id, userVerified: true });
    const again = await prepare().catch((err: unknown) => err);
    expect(again).toBeInstanceOf(DomainError);
    expect(again).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "consumed" } });
  });

  it("answers the incident freeze first, and the freeze closes an approval given before it", async () => {
    const r = await requirement();
    const asked = stepUp(await edit(admin.cli, r.id, tags(1, ["tag:prod"])));
    await approve(admin, asked.id);
    expect((await call("POST", `${ORG}/incident-freeze`, admin.cli, { reason: "A CI token leaked" })).status).toBe(201);
    expect((await rows("SELECT close_reason FROM approval_intents WHERE id = $1", [asked.id]))[0].close_reason).toBe("frozen");
    const before = await intents();
    expect((await edit(admin.cli, r.id, tags(1, ["tag:dev"]))).body.error.code).toBe("ORGANIZATION_FROZEN");
    expect((await revoke(admin.cli, r.id)).body.error.code).toBe("ORGANIZATION_FROZEN");
    expect((await edit(admin.cli, r.id, tags(1, ["tag:prod"]), asked.id)).body.error.code).toBe("ORGANIZATION_FROZEN");
    expect(await intents()).toBe(before);
    // Adding a Requirement only restricts: recovery, and no approval.
    expect((await call("POST", REQS, admin.cli, { kind: "tailnet", target: { kind: "tier", tier: "production" }, selector: { tailnet: "example.ts.net", tags: ["tag:prod"] } })).status).toBe(201);
  });

  it("is turned off by the operator's reset, which closes the open requirement approvals", async () => {
    const r = await requirement();
    const asked = stepUp(await edit(admin.cli, r.id, tags(1, ["tag:prod"])));
    const outcome = await resetControls(ctx, { organization: "acme", controls: ["requirement-protection"] });
    expect(outcome.approvalsClosed).toBe(1);
    expect((await rows("SELECT close_reason FROM approval_intents WHERE id = $1", [asked.id]))[0].close_reason).toBe("reset");
    expect((await edit(admin.cli, r.id, tags(1, ["tag:prod"]))).status).toBe(200);
  });
});

describe("removing a passkey once requirement-protection enforces", () => {
  const remove = (p: Person, passkeyId: string, approval?: string) =>
    call("DELETE", `/v1/me/passkeys/${passkeyId}`, p.web, undefined, withApprovalHeader(approval));

  it("is restricted only while a live membership's Organization enforces, for a trusted passkey, members included", async () => {
    const member = await invite("Member", "member");
    const spare = await registerSoftPasskey(ctx.db, member.id, { ...RP, trust: "trusted" });
    // report restricts nothing.
    expect((await setMode("requirement-protection", "report")).status).toBe(200);
    const early = await registerSoftPasskey(ctx.db, member.id, { ...RP, trust: "trusted" });
    expect((await remove(member, early.passkeyId)).status).toBe(204);

    await enforce();
    const unconfirmed = await registerSoftPasskey(ctx.db, member.id, { ...RP, trust: "unconfirmed" });
    expect((await remove(member, unconfirmed.passkeyId)).status).toBe(204);
    const asked = stepUp(await remove(member, spare.passkeyId));
    expect(asked).toMatchObject({ operation: "passkey.remove", organization: null });
    await approve(member, asked.id);
    expect((await remove(member, spare.passkeyId, asked.id)).status).toBe(204);

    // The reset turns enforce off: nothing restricts removal any more.
    const later = await registerSoftPasskey(ctx.db, member.id, { ...RP, trust: "trusted" });
    expect(stepUp(await remove(member, later.passkeyId)).operation).toBe("passkey.remove");
    await resetControls(ctx, { organization: "acme", controls: ["requirement-protection"] });
    expect((await remove(member, later.passkeyId)).status).toBe(204);
  });
});
