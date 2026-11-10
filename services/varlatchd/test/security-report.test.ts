// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { withTx } from "../src/db/tx.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { accessCountsSettled, countWouldBlock, deleteExpiredCounters, emitDueSummaries, runSecurityReportWorker } from "../src/domain/securityreport.js";
import { buildApp } from "../src/http/app.js";
import { RP } from "./helpers/device-sign-in.js";
import { fakeGitHubApps } from "./helpers/fake-github-app.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { registerSoftPasskey } from "./helpers/soft-authenticator.js";

/**
 * Report mode (ADR-0054 Decisions 5, 7 and 9), on PGlite: with every
 * control off nothing is counted and no outcome changes; in report mode
 * nothing is refused or changed, and each control counts what it would
 * have done, per key and hour, under the control's version at decision
 * time: admin-step-up and requirement-protection per operation done
 * without an approval, credential-lifetime's would-default and
 * would-refuse, and passkey-verification for people's accesses without
 * trusted, user-verified sign-in evidence, through routes, retrievals,
 * validation and the Convex token. A write is counted only when it
 * committed, an access only when it was authorized and succeeded. The
 * summary worker, late increments and retention are here too; their
 * concurrency runs on real PostgreSQL in security-report-postgres.test.ts.
 */

const ORG = "/v1/organizations/acme";
const P = `${ORG}/projects/api`;
const E = `${P}/environments/production`;

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let github: ReturnType<typeof fakeGitHubApps>;
let orgId: string;
let adminId: string;
let admin: string;
let projectId: string;

type Answer = { status: number; body: any };

async function call(method: string, path: string, token: string, body?: unknown): Promise<Answer> {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  // Access counts run after the response; wait for them, so the next step
  // finds them done (and never shares PGlite's one connection with them).
  await accessCountsSettled();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

async function ok(method: string, path: string, token: string, body?: unknown): Promise<any> {
  const res = await call(method, path, token, body);
  expect(res.status, `${method} ${path}: ${JSON.stringify(res.body)}`).toBeLessThan(300);
  return res.body;
}

const rows = async (sql: string, params: unknown[] = []) => (await ctx.db.query(sql, params)).rows as any[];

/** Every counter row, as plain values. */
async function counters() {
  return (await rows(
    `SELECT control, config_version, operation, actor_identity_id, reason, count::int AS count,
            bucket_hour = date_trunc('hour', clock_timestamp(), 'UTC') AS current_hour, emitted_at IS NOT NULL AS emitted
     FROM security_control_counters ORDER BY control, operation, reason, actor_identity_id, config_version, bucket_hour`,
  )) as { control: string; config_version: number; operation: string; actor_identity_id: string; reason: string; count: number; current_hour: boolean; emitted: boolean }[];
}

/** The counted operations of one control, with their counts. */
async function counted(control: string) {
  const out: Record<string, number> = {};
  for (const r of await counters()) if (r.control === control) out[`${r.operation}/${r.reason}`] = (out[`${r.operation}/${r.reason}`] ?? 0) + r.count;
  return out;
}

async function setMode(control: string, mode: "off" | "report", config?: { defaultTtlSeconds: number; maxTtlSeconds: number }) {
  const current = (await ok("GET", `${ORG}/security/controls`, admin)).items.find((i: { control: string }) => i.control === control);
  if (mode === "off") {
    // Turning report off needs an approval; the tests set it directly.
    await ctx.db.query("UPDATE security_controls SET mode = 'off', version = version + 1 WHERE organization_id = $1 AND control = $2", [orgId, control]);
    return;
  }
  await ok("PATCH", `${ORG}/security/controls/${control}`, admin, { mode, ...(config ? { config } : {}), expectedVersion: current.version });
}

async function person(name: string, role: "admin" | "member", organizationId = orgId) {
  const grant = await issueInviteGrant(ctx, { organizationId, role, name }, adminId);
  const { identityId } = await consumeSetupGrant(ctx, grant.token, {});
  return { id: identityId, cli: (await issueCredential(ctx.db, { identityId, kind: "cli" })).token };
}

/** A dashboard bearer for a session whose sign-in left this evidence (none: a sign-in from before the upgrade). */
async function browser(identityId: string, evidence: { userVerified: boolean; trust: "trusted" | "unconfirmed" } | null) {
  const key = await registerSoftPasskey(ctx.db, identityId, { ...RP, trust: evidence?.trust ?? "trusted" });
  const sessionId = `session-${identityId}-${Math.random().toString(36).slice(2)}`;
  await ctx.db.query(
    `INSERT INTO "session" (id, "expiresAt", token, "userId")
     SELECT $1, now() + interval '1 day', $1, better_auth_user_id FROM auth_user_links WHERE identity_id = $2`,
    [sessionId, identityId],
  );
  if (evidence) {
    await ctx.db.query(
      "INSERT INTO auth_session_evidence (session_id, ceremony, user_verified, passkey_id) VALUES ($1, 'sign-in', $2, $3)",
      [sessionId, evidence.userVerified, key.passkeyId],
    );
  }
  return (await issueCredential(ctx.db, {
    identityId,
    kind: "browser",
    expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
    authSessionId: sessionId,
  })).token;
}

/** A machine identity of the Organization with these actions everywhere. */
async function machine(name: string, actions: string[], kind = "service") {
  const created = await ok("POST", `${ORG}/identities`, admin, { name, kind });
  await ok("POST", `${ORG}/grants`, admin, { subjectIdentityId: created.id, scope: { kind: "organization" }, actions });
  return { id: created.id as string, token: created.credential as string };
}

const wouldBlockEvents = async () =>
  (await rows("SELECT actor_identity_id, organization_id, metadata FROM audit_events WHERE event_type = 'security_control.would_block' ORDER BY event_order"))
    .map((r) => ({ actor: r.actor_identity_id, org: r.organization_id, metadata: typeof r.metadata === "string" ? JSON.parse(r.metadata) : r.metadata }));

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  adminId = (await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" })).identityId;
  admin = (await issueCredential(ctx.db, { identityId: adminId, kind: "cli" })).token;
  github = fakeGitHubApps();
  app = buildApp(ctx, { syncFetch: github.fetchImpl });
  orgId = (await ok("POST", "/v1/organizations", admin, { name: "Acme", slug: "acme" })).id;
  projectId = (await ok("POST", `${ORG}/projects`, admin, { name: "API", slug: "api", contractAuthority: "managed" })).id;
  await ok("POST", `${P}/environments`, admin, { name: "production", tier: "production" });
  const revision = await ok("POST", `${P}/contract/revisions`, admin, {
    contract: { schemaVersion: 1, items: [{ name: "DB_PASS", required: { kind: "never" }, sensitive: true, type: "string" }] },
  });
  await ok("POST", `${P}/contract/revisions/${revision.id}/activate`, admin, {});
  await ok("PUT", `${E}/values/DB_PASS`, admin, { value: "hunter2-hunter2" });
});
afterEach(async () => {
  await ctx.close();
});

/**
 * Most of Decision 5's operations, one each, by `token`. Returns the
 * operations it performed, as admin-step-up names them.
 */
async function adminOperations(token: string, bob: { id: string }) {
  const svc = await ok("POST", `${ORG}/identities`, token, { name: "svc", kind: "service" });
  await ok("POST", `${ORG}/identities/${svc.id}/credentials`, token, { name: "second" });
  await ok("POST", `${ORG}/identities/${svc.id}/retire`, token, {});
  await ok("POST", `${ORG}/identities/${svc.id}/reactivate`, token, {});
  const ci = await ok("POST", `${ORG}/identities`, token, { name: "ci", kind: "ci" });
  const binding = await ok("POST", `${ORG}/identities/${ci.id}/oidc-bindings`, token, {
    issuer: "https://token.actions.githubusercontent.com",
    audience: "varlatch",
    subject: "repo:acme/api:ref:refs/heads/main",
  });
  await ok("DELETE", `${ORG}/identities/${ci.id}/oidc-bindings/${binding.id}`, token);
  const grant = await ok("POST", `${ORG}/grants`, token, { subjectIdentityId: svc.id, scope: { kind: "organization" }, actions: ["project.read"] });
  const replaced = await ok("POST", `${ORG}/grants/${grant.id}/replace`, token, {
    subjectIdentityId: svc.id, scope: { kind: "organization" }, actions: ["project.read", "environment.read"],
  });
  await ok("DELETE", `${ORG}/grants/${replaced.grant.id}`, token);
  const role = await ok("POST", `${ORG}/roles`, token, { name: "reader", actions: ["project.read"] });
  await ok("PATCH", `${ORG}/roles/${role.id}`, token, { expectedVersion: 1, name: "readers" });
  await ok("DELETE", `${ORG}/roles/${role.id}`, token);
  const group = await ok("POST", `${ORG}/groups`, token, { name: "ops" });
  await ok("PATCH", `${ORG}/groups/${group.id}`, token, { expectedVersion: 1, name: "operations" });
  await ok("POST", `${ORG}/groups/${group.id}/members`, token, { identityId: svc.id });
  await ok("DELETE", `${ORG}/groups/${group.id}/members/${svc.id}`, token);
  await ok("DELETE", `${ORG}/groups/${group.id}`, token);
  const team = await ok("POST", `${ORG}/teams`, token, { name: "platform" });
  await ok("PATCH", `${ORG}/teams/${team.id}`, token, { expectedVersion: 1, name: "platform team" });
  await ok("POST", `${ORG}/teams/${team.id}/members`, token, { identityId: svc.id });
  await ok("DELETE", `${ORG}/teams/${team.id}/members/${svc.id}`, token);
  await ok("POST", `${ORG}/teams/${team.id}/projects`, token, { projectId });
  await ok("DELETE", `${ORG}/teams/${team.id}/projects/${projectId}`, token);
  await ok("DELETE", `${ORG}/teams/${team.id}`, token);
  await ok("POST", `${ORG}/invitations`, token, { name: "Carol", role: "admin" });
  await ok("PATCH", `${ORG}/members/${bob.id}`, token, { role: "admin" });
  await ok("PATCH", `${ORG}/members/${bob.id}`, token, { role: "member" });
  await ok("DELETE", `${ORG}/members/${bob.id}`, token);
  const hook = await ok("POST", `${ORG}/webhooks`, token, { url: "https://hooks.example.com/a" });
  await ok("PATCH", `${ORG}/webhooks/${hook.id}`, token, { expectedVersion: 1, url: "https://hooks.example.com/b" });
  await ok("DELETE", `${ORG}/webhooks/${hook.id}`, token);
  const connection = await ok("POST", `${ORG}/platform-connections`, token, {
    platform: "coolify", baseIdentity: "https://coolify.example.com", name: "prod", credential: "coolify-token-1",
  });
  await ok("POST", `${ORG}/platform-connections/${connection.id}/credential`, token, { credential: "coolify-token-2", expectedVersion: 1 });
  await ok("DELETE", `${ORG}/platform-connections/${connection.id}`, token);
  await ok("POST", `${ORG}/projects`, token, { name: "Old", slug: "old", contractAuthority: "git" });
  await ok("DELETE", `${ORG}/projects/old`, token);
  await ok("POST", `${E}/disclosures`, token, { scope: "all-authorized-secrets", purpose: "export" });
  return [
    "identity.create", "credential.issue", "identity.reactivate", "identity.create", "oidc_binding.create", "oidc_binding.delete",
    "grant.create", "grant.replace", "grant.revoke", "role.create", "role.update", "role.delete",
    "group.create", "group.update", "group.member_add", "group.member_remove", "group.delete",
    "team.create", "team.update", "team.member_add", "team.member_remove", "team.project_add", "team.project_remove", "team.delete",
    "member.invite_admin", "member.promote", "member.demote", "member.remove",
    "webhook.create", "webhook.update", "webhook.delete",
    "connection.create", "connection.replace_credential", "connection.delete",
    "project.delete", "secret.export",
  ];
}

describe("with every control off", () => {
  it("counts nothing, records no summary and changes no outcome", async () => {
    const bob = await person("Bob", "member");
    await adminOperations(admin, bob);
    // Issuance as before: no TTL, no expiry; a long one is kept.
    const plain = await ok("POST", `${ORG}/identities`, admin, { name: "plain", kind: "service" });
    expect(plain.credentialExpiresAt).toBeNull();
    const long = await ok("POST", `${ORG}/identities`, admin, { name: "long", kind: "service", credentialTtlSeconds: 315_360_000 });
    expect(Date.parse(long.credentialExpiresAt) - Date.now()).toBeGreaterThan(315_000_000_000);
    const requirement = await ok("POST", `${ORG}/requirements`, admin, {
      kind: "tailnet", target: { kind: "tier", tier: "staging" }, selector: { tailnet: "example.ts.net", tags: ["tag:ci"] },
    });
    await ok("PATCH", `${ORG}/requirements/${requirement.id}`, admin, { expectedVersion: 1, selector: { tailnet: "example.ts.net", tags: ["tag:prod"] } });
    await ok("DELETE", `${ORG}/requirements/${requirement.id}`, admin);
    // A person without sign-in evidence, through a route, a retrieval and the Convex token.
    await ok("GET", ORG, admin);
    await ok("POST", `${E}/retrievals`, admin, { mode: "strict" });
    await ok("POST", "/v1/tokens/convex", admin);
    await ok("POST", `${ORG}/deletion`, admin, {});
    expect(await counters()).toEqual([]);
    expect(await wouldBlockEvents()).toEqual([]);
    expect(await runSecurityReportWorker(ctx)).toEqual({ emitted: 0, deleted: 0 });
    expect((await rows("SELECT count(*)::int AS n FROM audit_events WHERE event_type LIKE 'security_control.%'"))[0].n).toBe(0);
  });
});

describe("admin-step-up in report mode", () => {
  it("counts each listed operation done without an approval, once, and refuses or changes nothing", async () => {
    const bob = await person("Bob", "member");
    await setMode("admin-step-up", "report");
    const operations = await adminOperations(admin, bob);
    await ok("POST", `${ORG}/deletion`, admin, {});
    const expected: Record<string, number> = {};
    for (const op of [...operations, "organization.delete"]) expected[`${op}/no-approval`] = (expected[`${op}/no-approval`] ?? 0) + 1;
    expect(await counted("admin-step-up")).toEqual(expected);
    for (const row of await counters()) {
      expect(row).toMatchObject({ control: "admin-step-up", config_version: 1, actor_identity_id: adminId, current_hour: true, emitted: false });
    }
    // Nothing refused, nothing else changed: the export still disclosed.
    const disclosed = await rows("SELECT metadata FROM audit_events WHERE event_type = 'secret.disclosed'");
    expect(disclosed).toHaveLength(1);
    // Nothing is summarized while the hour runs.
    expect(await emitDueSummaries(ctx)).toBe(0);
  });

  it("counts the GitHub App's registration, import, key replacement and removal", async () => {
    await setMode("admin-step-up", "report");
    const APP = {
      id: 5254113,
      slug: "varlatch-acme",
      clientId: "Iv23liCheck1009",
      owner: { login: "acme-gh", id: 1009, type: "Organization" as const },
      permissions: { secrets: "write", environments: "write", metadata: "read" },
    };
    const pem = github.addApp(APP);
    // The manifest flow: GitHub converts the code into the App and its key.
    app = buildApp(ctx, {
      publicUrl: "https://varlatch.test",
      syncFetch: (async (input: RequestInfo | URL, init?: RequestInit) =>
        /\/app-manifests\/[^/]+\/conversions$/.test(String(input))
          ? Response.json({
              id: APP.id, slug: APP.slug, node_id: "A_kw", client_id: APP.clientId, client_secret: "x", webhook_secret: null, pem,
              name: "Varlatch acme", owner: APP.owner, permissions: APP.permissions, events: [],
            }, { status: 201 })
          : github.fetchImpl(input, init)) as typeof fetch,
    });
    const started = await ok("POST", `${ORG}/github-app/registrations`, admin, { account: { login: "acme-gh", type: "organization" } });
    const registered = await ok("POST", `${ORG}/github-app/registrations/complete`, admin, { state: started.state, code: "code-1" });
    expect(registered.outcome).toBe("registered");
    await ok("DELETE", `${ORG}/github-app?appId=${registered.app.id}`, admin);
    const imported = await ok("POST", `${ORG}/github-app/import`, admin, { appId: APP.id, privateKey: pem });
    expect(imported.outcome).toBe("registered");
    const rotated = await ok("POST", `${ORG}/github-app/key`, admin, { privateKey: github.addKey(APP.id), expectedVersion: 1 });
    expect(rotated.outcome).toBe("rotated");
    await ok("DELETE", `${ORG}/github-app?appId=${imported.app.id}`, admin);
    expect(await counted("admin-step-up")).toEqual({
      "github_app.register/no-approval": 1,
      "github_app.remove/no-approval": 2,
      "github_app.import/no-approval": 1,
      "github_app.replace_key/no-approval": 1,
    });
  });

  it("tells machine credentials apart, and never counts a refused, failed, rolled-back or empty attempt", async () => {
    const bot = await machine("bot", ["policy.manage", "identity.manage"]);
    const bob = await person("Bob", "member");
    const dave = await person("Dave", "member");
    await setMode("admin-step-up", "report");
    // A machine credential can never pass an approval: its own reason.
    await ok("POST", `${ORG}/groups`, bot.token, { name: "bots" });
    // Refused before anything is written.
    expect((await call("POST", `${ORG}/groups`, bob.cli, { name: "nope" })).status).toBe(403);
    // Failed inside the transaction, which rolls back with its count.
    await ok("POST", `${ORG}/roles`, admin, { name: "dup", actions: ["project.read"] });
    expect((await call("POST", `${ORG}/roles`, admin, { name: "dup", actions: ["project.read"] })).status).toBe(422);
    const grant = await ok("POST", `${ORG}/grants`, admin, { subjectIdentityId: bot.id, scope: { kind: "organization" }, actions: ["project.read"] });
    await ok("DELETE", `${ORG}/grants/${grant.id}`, admin);
    expect((await call("POST", `${ORG}/grants/${grant.id}/replace`, admin, {
      subjectIdentityId: bot.id, scope: { kind: "organization" }, actions: ["project.read"],
    })).status).toBe(409);
    // Changing nothing writes nothing and counts nothing.
    const group = await ok("POST", `${ORG}/groups`, admin, { name: "same" });
    await ok("PATCH", `${ORG}/groups/${group.id}`, admin, { expectedVersion: 1, name: "same" });
    await ok("PATCH", `${ORG}/members/${bob.id}`, admin, { role: "member" });
    // Not on the list: inviting a member, a person leaving.
    await ok("POST", `${ORG}/invitations`, admin, { name: "Erin", role: "member" });
    await ok("DELETE", `${ORG}/members/me`, dave.cli);
    // An export refused for lack of secret.reveal, and other purposes.
    expect((await call("POST", `${E}/disclosures`, bob.cli, { scope: "all-authorized-secrets", purpose: "export" })).status).toBe(403);
    await ok("POST", `${E}/disclosures`, admin, { scope: "all-authorized-secrets", purpose: "scan" });
    await ok("POST", `${E}/disclosures`, admin, { scope: "all-authorized-secrets" });
    // The same idempotent request again replays its answer; it committed once.
    const key = { "Idempotency-Key": "replace-1" };
    const g2 = await ok("POST", `${ORG}/grants`, admin, { subjectIdentityId: bot.id, scope: { kind: "organization" }, actions: ["project.read"] });
    for (let i = 0; i < 2; i++) {
      const res = await app.request(`${ORG}/grants/${g2.id}/replace`, {
        method: "POST",
        headers: { Authorization: `Bearer ${admin}`, "Content-Type": "application/json", ...key },
        body: JSON.stringify({ subjectIdentityId: bot.id, scope: { kind: "organization" }, actions: ["environment.read"] }),
      });
      expect(res.status).toBe(201);
    }
    expect(await counted("admin-step-up")).toEqual({
      "group.create/machine-credential": 1,
      "role.create/no-approval": 1,
      "grant.create/no-approval": 2,
      "grant.revoke/no-approval": 1,
      "grant.replace/no-approval": 1,
      "group.create/no-approval": 1,
    });
    const byActor = (await counters()).filter((r) => r.reason === "machine-credential");
    expect(byActor.map((r) => r.actor_identity_id)).toEqual([bot.id]);
  });

  it("counts only what an operation changed: repeated additions, reactivating a live identity and identical replacements change nothing", async () => {
    const svc = await ok("POST", `${ORG}/identities`, admin, { name: "svc", kind: "service" });
    const group = await ok("POST", `${ORG}/groups`, admin, { name: "ops" });
    const team = await ok("POST", `${ORG}/teams`, admin, { name: "platform" });
    const grant = await ok("POST", `${ORG}/grants`, admin, { subjectIdentityId: svc.id, scope: { kind: "organization" }, actions: ["project.read"] });
    await setMode("admin-step-up", "report");
    for (let i = 0; i < 2; i++) {
      // The same HTTP answer both times, as before.
      expect((await call("POST", `${ORG}/groups/${group.id}/members`, admin, { identityId: svc.id })).status).toBe(204);
      expect((await call("POST", `${ORG}/teams/${team.id}/members`, admin, { identityId: svc.id })).status).toBe(204);
      expect((await call("POST", `${ORG}/teams/${team.id}/projects`, admin, { projectId })).status).toBe(204);
    }
    // Still enabled: reactivating changes nothing.
    await ok("POST", `${ORG}/identities/${svc.id}/reactivate`, admin, {});
    // Replaced with the same declaration: a new Grant, the same access.
    const same = await ok("POST", `${ORG}/grants/${grant.id}/replace`, admin, {
      subjectIdentityId: svc.id, scope: { kind: "organization" }, actions: ["project.read"],
    });
    await ok("POST", `${ORG}/grants/${same.grant.id}/replace`, admin, {
      subjectIdentityId: svc.id, scope: { kind: "organization" }, actions: ["environment.read"],
    });
    expect(await counted("admin-step-up")).toEqual({
      "group.member_add/no-approval": 1,
      "team.member_add/no-approval": 1,
      "team.project_add/no-approval": 1,
      "grant.replace/no-approval": 1,
    });
  });

  it("counts under the control's version at decision time", async () => {
    await setMode("admin-step-up", "report");
    await ok("POST", `${ORG}/groups`, admin, { name: "one" });
    // Off and on again: version 3.
    await setMode("admin-step-up", "off");
    await ok("POST", `${ORG}/groups`, admin, { name: "uncounted" });
    await setMode("admin-step-up", "report");
    await ok("POST", `${ORG}/groups`, admin, { name: "two" });
    await ok("POST", `${ORG}/groups`, admin, { name: "three" });
    expect((await counters()).map((r) => [r.operation, r.config_version, r.count])).toEqual([
      ["group.create", 1, 1],
      ["group.create", 3, 2],
    ]);
  });
});

describe("requirement-protection in report mode", () => {
  it("counts edits and revocations without an approval, not creation, failures or edits that change nothing", async () => {
    await setMode("requirement-protection", "report");
    const requirement = await ok("POST", `${ORG}/requirements`, admin, {
      kind: "tailnet", target: { kind: "tier", tier: "staging" }, selector: { tailnet: "example.ts.net", tags: ["tag:ci"] },
    });
    const edit = (expectedVersion: number, tags: string[]) =>
      call("PATCH", `${ORG}/requirements/${requirement.id}`, admin, { expectedVersion, selector: { tailnet: "example.ts.net", tags } });
    expect((await edit(1, ["tag:prod"])).status).toBe(200);
    // An edit that changes nothing.
    expect((await call("PATCH", `${ORG}/requirements/${requirement.id}`, admin, { expectedVersion: 2 })).body.version).toBe(2);
    expect((await edit(1, ["tag:dev"])).status).toBe(409);
    expect((await call("DELETE", `${ORG}/requirements/${requirement.id}`, admin)).status).toBe(204);
    expect((await call("DELETE", `${ORG}/requirements/${requirement.id}`, admin)).status).toBe(404);
    expect(await counted("requirement-protection")).toEqual({ "requirement.update/no-approval": 1, "requirement.revoke/no-approval": 1 });
    // Only its own control: admin-step-up is off.
    expect(await counted("admin-step-up")).toEqual({});
  });
});

describe("credential-lifetime in report mode", () => {
  it("counts would-default and would-refuse separately, and issues exactly as before", async () => {
    await setMode("credential-lifetime", "report", { defaultTtlSeconds: 3600, maxTtlSeconds: 86_400 });
    const none = await ok("POST", `${ORG}/identities`, admin, { name: "none", kind: "service" });
    expect(none.credentialExpiresAt).toBeNull();
    const long = await ok("POST", `${ORG}/identities`, admin, { name: "long", kind: "workload", credentialTtlSeconds: 172_800 });
    expect(Date.parse(long.credentialExpiresAt) - Date.now()).toBeGreaterThan(172_000_000);
    await ok("POST", `${ORG}/identities`, admin, { name: "short", kind: "broker", credentialTtlSeconds: 3600 });
    // No credential, nothing to count.
    await ok("POST", `${ORG}/identities`, admin, { name: "ci", kind: "ci" });
    const issued = await ok("POST", `${ORG}/identities/${none.id}/credentials`, admin, { name: "again" });
    expect(issued.expiresAt).toBeNull();
    const issuedLong = await ok("POST", `${ORG}/identities/${none.id}/credentials`, admin, { name: "long", ttlSeconds: 90_000 });
    expect(issuedLong.expiresAt).not.toBeNull();
    await ok("POST", `${ORG}/identities/${none.id}/credentials`, admin, { name: "ok", ttlSeconds: 86_400 });
    expect(await counted("credential-lifetime")).toEqual({
      "identity.create/would-default": 1,
      "identity.create/would-refuse": 1,
      "credential.issue/would-default": 1,
      "credential.issue/would-refuse": 1,
    });
    // Tightening the lifetimes is a new version; counts follow it.
    await setMode("credential-lifetime", "report", { defaultTtlSeconds: 3600, maxTtlSeconds: 7200 });
    await ok("POST", `${ORG}/identities/${none.id}/credentials`, admin, { name: "now too long", ttlSeconds: 86_400 });
    expect((await counters()).filter((r) => r.config_version === 2).map((r) => [r.operation, r.reason, r.count])).toEqual([
      ["credential.issue", "would-refuse", 1],
    ]);
    expect(await counted("admin-step-up")).toEqual({});
  });

  it("leaves agent-run issuance by a broker alone", async () => {
    await setMode("credential-lifetime", "report", { defaultTtlSeconds: 60, maxTtlSeconds: 60 });
    const broker = await ok("POST", `${ORG}/identities`, admin, { name: "broker", kind: "broker", credentialTtlSeconds: 60 });
    const agent = await ok("POST", `${ORG}/identities`, admin, { name: "agent", kind: "agent" });
    await ok("POST", `${ORG}/identities/${agent.id}/credentials`, broker.credential, { ttlSeconds: 600 });
    expect(await counted("credential-lifetime")).toEqual({});
  });
});

describe("passkey-verification in report mode", () => {
  it("counts a person's successful accesses without trusted, user-verified evidence, as the action they were authorized for", async () => {
    await setMode("passkey-verification", "report");
    const verified = await browser(adminId, { userVerified: true, trust: "trusted" });
    const unverified = await browser(adminId, { userVerified: false, trust: "trusted" });
    const untrusted = await browser(adminId, { userVerified: true, trust: "unconfirmed" });
    const before = await browser(adminId, null);
    for (const token of [verified, unverified, untrusted, before, admin]) await ok("GET", ORG, token);
    // The CLI from device sign-in carries the approval's evidence itself.
    const key = await registerSoftPasskey(ctx.db, adminId, { ...RP, trust: "trusted" });
    const device = await issueCredential(ctx.db, { identityId: adminId, kind: "cli", evidence: { userVerified: true, passkeyId: key.passkeyId } });
    await ok("GET", ORG, device.token);
    expect(await counted("passkey-verification")).toEqual({
      "organization.read/not-user-verified": 1,
      "organization.read/untrusted-passkey": 1,
      // The pre-upgrade session and the CLI credential without evidence.
      "organization.read/no-evidence": 2,
    });
  });

  it("covers retrieval, validation and writes, never counts refusals, outsiders or machines, and only its Organization", async () => {
    const bob = await person("Bob", "member");
    const bot = await machine("bot", ["organization.read", "config.metadata.read"]);
    const beta = (await ok("POST", "/v1/organizations", admin, { name: "Beta", slug: "beta" })).id as string;
    const outsider = await person("Olga", "member", beta);
    await setMode("passkey-verification", "report");
    // A retrieval: decided in its snapshot, counted after it.
    expect((await call("POST", `${E}/retrievals`, admin, { mode: "strict" })).status).toBe(200);
    expect((await call("POST", `${E}/validate`, admin, {})).status).toBe(200);
    // A write.
    await ok("PATCH", P, admin, { name: "API gateway" });
    // Refused: a member asking for more than they hold; an outsider.
    expect((await call("PATCH", ORG, bob.cli, { name: "Bob's" })).status).toBe(403);
    expect((await call("GET", ORG, outsider.cli)).status).toBe(404);
    // A machine, whatever its evidence: exempt by kind.
    await ok("GET", ORG, bot.token);
    // Another Organization, its control off.
    await ok("GET", "/v1/organizations/beta", admin);
    // Not an Organization access.
    await ok("GET", "/v1/me", admin);
    expect(await counted("passkey-verification")).toEqual({
      "config.metadata.read/no-evidence": 1,
      "environment.read/no-evidence": 1,
      "project.manage/no-evidence": 1,
    });
    expect((await counters()).every((r) => r.actor_identity_id === adminId)).toBe(true);
    // Counting wrote no audit event.
    expect(await wouldBlockEvents()).toEqual([]);
  });

  it("evaluates each Organization of the Convex token, and exempts machines", async () => {
    const beta = (await ok("POST", "/v1/organizations", admin, { name: "Beta", slug: "beta" })).id as string;
    const gamma = (await ok("POST", "/v1/organizations", admin, { name: "Gamma", slug: "gamma" })).id as string;
    const bot = await machine("bot", ["organization.read"]);
    await setMode("passkey-verification", "report");
    await ok("PATCH", "/v1/organizations/gamma/security/controls/passkey-verification", admin, { mode: "report", expectedVersion: 0 });
    // Setting gamma's control was an access to gamma, decided while it was off.
    expect(await counters()).toEqual([]);
    await ok("POST", "/v1/tokens/convex", admin);
    await ok("POST", "/v1/tokens/convex", bot.token);
    await ok("POST", "/v1/tokens/convex", await browser(adminId, { userVerified: true, trust: "trusted" }));
    const rowsOf = await rows("SELECT organization_id, operation, reason, count::int AS count FROM security_control_counters ORDER BY organization_id");
    expect(rowsOf).toEqual(
      [orgId, gamma].sort().map((organization_id) => ({ organization_id, operation: "convex.token", reason: "no-evidence", count: 1 })),
    );
    expect(rowsOf.map((r) => r.organization_id)).not.toContain(beta);
  });
});

describe("GET /security/control-report", () => {
  it("returns per-control totals, the current hour and entries, to organization.manage only", async () => {
    const bob = await person("Bob", "member");
    await setMode("admin-step-up", "report");
    await setMode("credential-lifetime", "report", { defaultTtlSeconds: 3600, maxTtlSeconds: 86_400 });
    await ok("POST", `${ORG}/identities`, admin, { name: "svc", kind: "service" });
    await ok("POST", `${ORG}/groups`, admin, { name: "a" });
    await ok("POST", `${ORG}/groups`, admin, { name: "b" });
    const report = await ok("GET", `${ORG}/security/control-report`, admin);
    expect(report).toMatchObject({ organizationId: orgId, days: 30, summaryDelayMinutes: 10 });
    expect(report.controls.map((c: { control: string }) => c.control)).toEqual([
      "requirement-protection", "admin-step-up", "passkey-verification", "credential-lifetime",
    ]);
    const step = report.controls[1];
    expect(step).toMatchObject({ mode: "report", version: 1, total: 3, currentHour: 3, pending: 3 });
    expect(step.entries[0]).toMatchObject({
      configVersion: 1, operation: "group.create", reason: "no-approval", count: 2, actor: { id: adminId, name: "Admin", kind: "human" },
    });
    expect(report.controls[3]).toMatchObject({ total: 1, entries: [{ operation: "identity.create", reason: "would-default", count: 1 }] });
    expect(report.controls[0]).toMatchObject({ mode: "off", version: 0, total: 0, entries: [] });
    expect((await call("GET", `${ORG}/security/control-report`, bob.cli)).status).toBe(403);
    expect((await ok("GET", `${ORG}/security/control-report?days=1`, admin)).days).toBe(1);
    for (const days of ["0", "31", "x", "1.5"]) {
      expect((await call("GET", `${ORG}/security/control-report?days=${days}`, admin)).status).toBe(422);
    }
    expect((await call("GET", "/v1/organizations/nope/security/control-report", admin)).status).toBe(404);
    expect((await ok("GET", "/v1/meta", admin)).capabilities).toContain("security.report");
  });
});

describe("closing buckets", () => {
  const twoHoursAgo = () => new Date(Date.now() - 2 * 3600_000);
  const attempt = (operation: "grant.create" | "role.create" = "grant.create") => ({
    control: "admin-step-up" as const, configVersion: 1, operation, actorIdentityId: adminId, reason: "no-approval" as const,
  });

  it("summarizes each closed hour once, keeps the current one open, and sends a late increment to the current hour", async () => {
    await withTx(ctx.db, (db) => countWouldBlock(db, orgId, [attempt(), attempt(), attempt("role.create")], { at: twoHoursAgo() }));
    await withTx(ctx.db, (db) => countWouldBlock(db, orgId, [attempt()]));
    expect(await emitDueSummaries(ctx)).toBe(2);
    expect(await emitDueSummaries(ctx)).toBe(0);
    const events = await wouldBlockEvents();
    expect(events.map((e) => [e.actor, e.org, e.metadata.operation, e.metadata.count, e.metadata.reason, e.metadata.configVersion])).toEqual([
      [adminId, orgId, "grant.create", 2, "no-approval", 1],
      [adminId, orgId, "role.create", 1, "no-approval", 1],
    ]);
    expect(Object.keys(events[0]!.metadata).sort()).toEqual(
      ["bucketHour", "configVersion", "control", "count", "firstSeen", "lastSeen", "operation", "reason"],
    );
    // A long transaction that started back then: its bucket is closed.
    await withTx(ctx.db, (db) => countWouldBlock(db, orgId, [attempt()], { at: twoHoursAgo() }));
    expect((await counters()).map((r) => [r.operation, r.count, r.current_hour, r.emitted])).toEqual([
      ["grant.create", 2, false, true],
      ["grant.create", 2, true, false],
      ["role.create", 1, false, true],
    ]);
    // The summary never changes.
    expect((await wouldBlockEvents())[0]!.metadata.count).toBe(2);
  });

  it("leaves no count from a transaction that rolls back", async () => {
    await expect(withTx(ctx.db, async (db) => {
      await countWouldBlock(db, orgId, [attempt()]);
      throw new Error("the operation failed");
    })).rejects.toThrow("the operation failed");
    expect(await counters()).toEqual([]);
  });

  it("deletes counter rows 35 days after their summary", async () => {
    await withTx(ctx.db, (db) => countWouldBlock(db, orgId, [attempt(), attempt("role.create")], { at: twoHoursAgo() }));
    expect(await emitDueSummaries(ctx)).toBe(2);
    await ctx.db.query("UPDATE security_control_counters SET emitted_at = clock_timestamp() - interval '36 days' WHERE operation = 'grant.create'");
    await ctx.db.query("UPDATE security_control_counters SET emitted_at = clock_timestamp() - interval '34 days' WHERE operation = 'role.create'");
    expect(await deleteExpiredCounters(ctx)).toBe(1);
    expect((await counters()).map((r) => r.operation)).toEqual(["role.create"]);
    // The summaries stay in the audit log.
    expect(await wouldBlockEvents()).toHaveLength(2);
  });

  it("never summarizes a deleted Organization's counters, and deletes them", async () => {
    const beta = (await ok("POST", "/v1/organizations", admin, { name: "Beta", slug: "beta" })).id as string;
    await withTx(ctx.db, (db) => countWouldBlock(db, beta, [attempt()], { at: twoHoursAgo() }));
    await withTx(ctx.db, (db) => countWouldBlock(db, orgId, [attempt()], { at: twoHoursAgo() }));
    // A row that survived its Organization's deletion (deletion removes them).
    await ctx.db.query("UPDATE organizations SET deleted_at = now(), wrapped_org_kek = NULL, org_kek_destroyed_at = now() WHERE id = $1", [beta]);
    expect(await emitDueSummaries(ctx)).toBe(1);
    expect((await wouldBlockEvents()).map((e) => e.org)).toEqual([orgId]);
    expect(await deleteExpiredCounters(ctx)).toBe(1);
    expect((await rows("SELECT DISTINCT organization_id FROM security_control_counters")).map((r) => r.organization_id)).toEqual([orgId]);
  });

  it("goes with its Organization when the Organization is deleted", async () => {
    await withTx(ctx.db, (db) => countWouldBlock(db, orgId, [attempt()]));
    const { finalizeDeletion } = await import("../src/domain/orgdeletion.js");
    const scheduled = await ok("POST", `${ORG}/deletion`, admin, { afterDays: 1 });
    await ctx.db.query("UPDATE organization_deletions SET scheduled_at = now() - interval '2 days', run_after = now() - interval '1 minute'");
    expect(await finalizeDeletion(ctx, scheduled.id, orgId)).not.toBeNull();
    expect(await counters()).toEqual([]);
  });
});
