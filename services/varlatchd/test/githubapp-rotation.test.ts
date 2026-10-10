// SPDX-License-Identifier: AGPL-3.0-or-later
import { generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey, type Envelope } from "../src/crypto/aead.js";
import { decryptGitHubAppKey } from "../src/crypto/hierarchy.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
} from "../src/domain/bootstrap.js";
import { getOrganization, orgKekOf } from "../src/domain/orgs.js";
import { runSyncOnce } from "../src/domain/syncdelivery.js";
import { buildApp, type BuildAppOptions } from "../src/http/app.js";
import { fakeGitHubApps } from "./helpers/fake-github-app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * App-wide key rotation and App removal (ADR-0047 Decision 5). Rotation is
 * a new disclosure grant for every non-revoked Target of every non-revoked
 * Connection on the App (paused and auto-disabled ones included), verified
 * against GitHub before any lock, atomic, and version-guarded. Removal
 * revokes every Connection on the App and deletes its key; their Targets
 * are disabled and keep their destination claims.
 */

const APP = {
  id: 5254113,
  slug: "varlatch-acme",
  clientId: "Iv23liCheck1009",
  owner: { login: "acme-gh", id: 1009, type: "Organization" as const },
  permissions: { secrets: "write", environments: "write", metadata: "read" },
};
const ENV_PATH = "/v1/organizations/acme/projects/api/environments/development";

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let github: ReturnType<typeof fakeGitHubApps>;
let pem: string;
let connA: string;
let connB: string;
let tokenConn: string;
let targets: { active: string; paused: string; autoDisabled: string; revoked: string; onToken: string };

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  adminToken = (await issueCredential(ctx.db, { identityId: consumed.identityId, kind: "cli" })).token;
  github = fakeGitHubApps();
  rebuild();
  await post("/v1/organizations", { name: "Acme", slug: "acme" });
  await post("/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "git" });
  await post("/v1/organizations/acme/projects/api/environments", { name: "development", tier: "development" });
  await put(`${ENV_PATH}/values/PORT`, { value: "8080" });
  pem = github.addApp(APP);
  expect((await post("/v1/organizations/acme/github-app/import", { appId: APP.id, privateKey: pem })).status).toBe(201);
  const repos = [{ name: "api", private: true }, { name: "web", private: true }, { name: "jobs", private: true }, { name: "old", private: true }];
  const instA = github.install(APP.id, { login: "acme-gh", id: 1009, type: "Organization" }, "selected", null, repos);
  const instB = github.install(APP.id, { login: "acme-labs", id: 2000, type: "Organization" }, "selected", null, [{ name: "lab", private: true }]);
  connA = (await (await post("/v1/organizations/acme/platform-connections", { credentialKind: "github-app", installationId: instA, name: "A" })).json()).id;
  connB = (await (await post("/v1/organizations/acme/platform-connections", { credentialKind: "github-app", installationId: instB, name: "B" })).json()).id;
  tokenConn = (await (await post("/v1/organizations/acme/platform-connections", { platform: "github-actions", baseIdentity: "acme-tok", name: "Token", credential: "ghp_x" })).json()).id;
  targets = {
    active: await createTarget(connA, { repo: "api" }),
    paused: await createTarget(connA, { repo: "web" }),
    autoDisabled: await createTarget(connB, { repo: "lab" }),
    revoked: await createTarget(connA, { repo: "old" }),
    onToken: await createTarget(tokenConn, { repo: "api" }),
  };
  expect((await post(`${ENV_PATH}/sync-targets/${targets.paused}/pause`, {})).status).toBe(200);
  await ctx.db.query("UPDATE sync_targets SET state = 'disabled', disabled_reason = 'failure-budget-exhausted' WHERE id = $1", [targets.autoDisabled]);
  await ctx.db.query("UPDATE sync_targets SET revoked_at = now() WHERE id = $1", [targets.revoked]);
  await ctx.db.query("UPDATE sync_targets SET needs_sync = false");
  github.calls.length = 0;
});
afterEach(async () => {
  await ctx.close();
});

function rebuild(options: BuildAppOptions = {}) {
  app = buildApp(ctx, { syncFetch: github.fetchImpl, ...options });
}
function auth(token = adminToken): HeadersInit {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}
async function post(path: string, body: unknown, token = adminToken) {
  return app.request(path, { method: "POST", headers: auth(token), body: JSON.stringify(body) });
}
async function put(path: string, body: unknown, token = adminToken) {
  return app.request(path, { method: "PUT", headers: auth(token), body: JSON.stringify(body) });
}
async function del(path: string, token = adminToken) {
  return app.request(path, { method: "DELETE", headers: auth(token) });
}
/** Remove the App the caller sees, as the dashboard confirms it: by its id. */
async function removeApp(token = adminToken, appId?: string) {
  const id = appId ?? ((await (await app.request("/v1/organizations/acme/github-app", { headers: auth(token) })).json()) as { id: string }).id;
  return del(`/v1/organizations/acme/github-app?appId=${encodeURIComponent(id)}`, token);
}
async function createTarget(connectionId: string, destination: Record<string, string>) {
  const res = await post(`${ENV_PATH}/sync-targets`, { connectionId, destination, mapping: { kind: "wildcard" } });
  expect(res.status).toBe(201);
  return ((await res.json()) as { id: string }).id;
}
async function rotate(privateKey: string, expectedVersion = 1, token = adminToken) {
  const res = await post("/v1/organizations/acme/github-app/key", { privateKey, expectedVersion }, token);
  return { res, body: (await res.json()) as Record<string, any> };
}
const storedKey = async () => {
  const row = (await ctx.db.query("SELECT id, key_envelope, version FROM github_apps WHERE removed_at IS NULL")).rows[0] as
    | { id: string; key_envelope: Envelope | string; version: number }
    | undefined;
  if (!row) return null;
  const org = await getOrganization(ctx, "acme");
  const envelope = typeof row.key_envelope === "string" ? (JSON.parse(row.key_envelope) as Envelope) : row.key_envelope;
  return { version: row.version, pem: decryptGitHubAppKey(orgKekOf(ctx, org), org.id, row.id, envelope) };
};
const queued = async () =>
  ((await ctx.db.query("SELECT id FROM sync_targets WHERE needs_sync ORDER BY id")).rows as { id: string }[]).map((r) => r.id);
const events = async (type: string) =>
  ((await ctx.db.query("SELECT metadata FROM audit_events WHERE event_type = $1 ORDER BY event_order", [type])).rows as { metadata: Record<string, unknown> }[]).map(
    (r) => r.metadata,
  );
const sortedIds = (...ids: string[]) => [...ids].sort().join(",");

describe("rotating the App's key", () => {
  it("verifies the new key first, replaces it, moves the version, and queues every live Target on the App, paused and auto-disabled ones included", async () => {
    const next = github.addKey(APP.id);
    const { res, body } = await rotate(next);
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(body).toMatchObject({ outcome: "rotated", app: { version: 2, slug: "varlatch-acme" } });
    expect(github.calls).toEqual([{ method: "GET", path: "/app", issuer: APP.clientId }]);
    expect(await storedKey()).toEqual({ version: 2, pem: next });
    expect(await queued()).toEqual([targets.active, targets.paused, targets.autoDisabled].sort());
    expect(await events("sync.github_app_key_rotated")).toEqual([
      {
        appId: APP.id,
        slug: "varlatch-acme",
        version: 2,
        connections: sortedIds(connA, connB),
        reauthorizedTargets: sortedIds(targets.active, targets.paused, targets.autoDisabled),
      },
    ]);
  });

  it("keeps pushing after the old key is deleted on GitHub, which it could not do without the rotation", async () => {
    const next = github.addKey(APP.id);
    github.deleteKey(APP.id, pem);
    await ctx.db.query("UPDATE sync_targets SET needs_sync = true WHERE id = $1", [targets.active]);
    await runSyncOnce(ctx, { fetchImpl: github.fetchImpl });
    expect(github.secret("acme-gh", "api", undefined, "PORT")).toBeUndefined();
    expect((await rotate(next)).body.outcome).toBe("rotated");
    await ctx.db.query("UPDATE sync_targets SET next_attempt_at = NULL WHERE id = $1", [targets.active]);
    await runSyncOnce(ctx, { fetchImpl: github.fetchImpl });
    expect(github.secret("acme-gh", "api", undefined, "PORT")).toBe("8080");
  });

  it("refuses a key GitHub does not accept for this App, before any lock, changing nothing", async () => {
    const stranger = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs1", format: "pem" }) as string;
    const { res, body } = await rotate(stranger);
    expect(res.status).toBe(200);
    expect(body).toMatchObject({ outcome: "failed", status: "credential-rejected", where: "connection", httpStatus: 401 });
    expect(body.message).toContain("deleted on GitHub, or belongs to another App");
    github.state.clockOffsetMs = 15 * 60_000;
    expect((await rotate(github.addKey(APP.id))).body.message).toContain("about 15 minutes behind GitHub's");
    github.state.clockOffsetMs = 0;
    rebuild({ syncFetch: (async () => { throw new TypeError("fetch failed"); }) as typeof fetch });
    expect((await rotate(pem)).body).toMatchObject({ outcome: "failed", status: "unreachable" });
    rebuild({ syncFetch: (async () => Response.json({ id: 777, slug: "other" })) as typeof fetch });
    expect((await rotate(pem)).body).toMatchObject({ outcome: "failed", status: "failed", message: expect.stringContaining("not GitHub's") });
    rebuild();
    expect((await rotate("not a key")).res.status).toBe(422);
    expect(await storedKey()).toEqual({ version: 1, pem });
    expect(await queued()).toEqual([]);
    expect(await events("sync.github_app_key_rotated")).toEqual([]);
  });

  it("records each integration's disclosure decisions in the rotation event, as the gate made them", async () => {
    // A second environment, and a runner allowed to disclose each environment through its own Grant.
    expect((await post("/v1/organizations/acme/projects/api/environments", { name: "staging", tier: "staging" })).status).toBe(201);
    await put("/v1/organizations/acme/projects/api/environments/staging/values/PORT", { value: "9090" });
    const staged = await post("/v1/organizations/acme/projects/api/environments/staging/sync-targets", { connectionId: connA, destination: { repo: "jobs" }, mapping: { kind: "wildcard" } });
    expect(staged.status).toBe(201);
    const stagingTarget = ((await staged.json()) as { id: string }).id;
    const envIds = Object.fromEntries(
      ((await ctx.db.query("SELECT id, name, project_id FROM environments")).rows as { id: string; name: string; project_id: string }[]).map((e) => [e.name, e]),
    );
    const projectId = envIds.development!.project_id;
    const svc = await (await post("/v1/organizations/acme/identities", { name: "runner", kind: "service" })).json();
    await post("/v1/organizations/acme/grants", { subjectIdentityId: svc.id, scope: { kind: "organization" }, actions: ["config.sync.manage", "organization.read"] });
    const grant = async (env: string) => {
      const res = await post("/v1/organizations/acme/grants", {
        subjectIdentityId: svc.id,
        scope: { kind: "environments", projectId, selector: { kind: "environments", environmentIds: [envIds[env]!.id] } },
        actions: ["secret.reveal", "config.value.read"],
      });
      const body = await res.json();
      expect(res.status, JSON.stringify(body)).toBe(201);
      return (body as { id: string }).id;
    };
    const devGrant = await grant("development");
    const stagingGrant = await grant("staging");

    const { res, body } = await rotate(github.addKey(APP.id), 1, svc.credential);
    expect(res.status, JSON.stringify(body)).toBe(200);
    const event = (await ctx.db.query("SELECT authz FROM audit_events WHERE event_type = 'sync.github_app_key_rotated'")).rows[0] as {
      authz: { reauthorizedTargets: Record<string, Record<string, { grantIds: string[]; requirements: unknown }>> };
    };
    const decided = event.authz.reauthorizedTargets;
    expect(Object.keys(decided).sort()).toEqual([targets.active, targets.paused, targets.autoDisabled, stagingTarget].sort());
    for (const id of [targets.active, targets.paused, targets.autoDisabled]) {
      expect(decided[id]!["secret.reveal"]!.grantIds, id).toEqual([devGrant]);
    }
    expect(decided[stagingTarget]!["secret.reveal"]!.grantIds).toEqual([stagingGrant]);
    expect(decided[stagingTarget]).toHaveProperty(["secret.reveal", "requirements"]);
    // A service identity holds no Organization role: its authority is the Grants alone.
    for (const id of Object.keys(decided)) expect(decided[id]!["secret.reveal"], id).not.toHaveProperty("role");
  });

  it("records the admin's role for each Target when the built-in role allowed the rotation", async () => {
    expect((await rotate(github.addKey(APP.id))).body.outcome).toBe("rotated");
    const event = (await ctx.db.query("SELECT authz FROM audit_events WHERE event_type = 'sync.github_app_key_rotated'")).rows[0] as {
      authz: { reauthorizedTargets: Record<string, unknown> };
    };
    const admin = { role: "admin", grantIds: [], requirements: [] };
    expect(event.authz.reauthorizedTargets).toEqual(
      Object.fromEntries([targets.active, targets.paused, targets.autoDisabled].map((id) => [id, { "secret.reveal": admin, "config.value.read": admin }])),
    );
  });

  it("refuses a stale version", async () => {
    expect((await rotate(github.addKey(APP.id))).body.outcome).toBe("rotated");
    const stale = await rotate(pem, 1);
    expect(stale.res.status).toBe(409);
    expect(stale.body.error.code).toBe("VERSION_CONFLICT");
    expect((await storedKey())!.version).toBe(2);
  });

  it("is refused wholesale when the actor lacks disclosure authority for any Target on the App", async () => {
    const svc = await (await post("/v1/organizations/acme/identities", { name: "runner", kind: "service" })).json();
    await post("/v1/organizations/acme/grants", {
      subjectIdentityId: svc.id,
      scope: { kind: "organization" },
      actions: ["config.sync.manage", "organization.read"],
    });
    const { res, body } = await rotate(github.addKey(APP.id), 1, svc.credential);
    expect(res.status).toBe(403);
    expect(body.error.message).toContain("Rotating the GitHub App's key re-authorizes every Sync Target");
    expect(await storedKey()).toEqual({ version: 1, pem });
    expect(await queued()).toEqual([]);
    expect(await events("sync.github_app_key_rotated")).toEqual([]);
  });

  it("is not found without an App, or for a caller without config.sync.manage; needs outbound sync", async () => {
    await ctx.db.query("INSERT INTO identities(id,kind,name) VALUES ('idn_stranger','human','Stranger')");
    const stranger = (await issueCredential(ctx.db, { identityId: "idn_stranger", kind: "cli" })).token;
    expect((await rotate(pem, 1, stranger)).res.status).toBe(404);
    rebuild({ sync: null });
    expect((await rotate(pem)).res.status).toBe(403);
    rebuild();
    expect((await removeApp()).status).toBe(204);
    expect((await rotate(pem)).res.status).toBe(404);
  });
});

describe("removing the App", () => {
  it("revokes every Connection on it, disables their Targets (claims kept), deletes the key, and audits it", async () => {
    const res = await removeApp();
    expect(res.status).toBe(204);
    expect((await ctx.db.query("SELECT id, revoked_at IS NOT NULL AS revoked FROM platform_connections ORDER BY id")).rows).toEqual(
      [
        { id: connA, revoked: true },
        { id: connB, revoked: true },
        { id: tokenConn, revoked: false },
      ].sort((a, b) => a.id.localeCompare(b.id)),
    );
    const states = Object.fromEntries(
      ((await ctx.db.query("SELECT id, state, disabled_reason, revoked_at IS NOT NULL AS revoked FROM sync_targets")).rows as Record<string, unknown>[]).map((r) => [r.id, r]),
    );
    for (const id of [targets.active, targets.paused, targets.autoDisabled]) {
      expect(states[id]).toMatchObject({ state: "disabled", disabled_reason: "connection-revoked", revoked: false });
    }
    expect(states[targets.revoked]).toMatchObject({ revoked: true });
    expect(states[targets.onToken]).toMatchObject({ state: "active", revoked: false });
    expect((await ctx.db.query("SELECT removed_at IS NOT NULL AS removed, key_envelope, version FROM github_apps")).rows).toEqual([
      { removed: true, key_envelope: null, version: 2 },
    ]);
    expect(await events("sync.github_app_removed")).toEqual([
      {
        appId: APP.id,
        slug: "varlatch-acme",
        revokedConnections: sortedIds(connA, connB),
        disabledTargets: sortedIds(targets.active, targets.paused, targets.autoDisabled),
      },
    ]);
    // The disabled Targets keep their destination claims: another Connection on the same account cannot take one over.
    const sameAccount = (await (await post("/v1/organizations/acme/platform-connections", { platform: "github-actions", baseIdentity: "acme-gh", name: "PAT", credential: "ghp_y" })).json()).id;
    const takeover = await post(`${ENV_PATH}/sync-targets`, { connectionId: sameAccount, destination: { repo: "web" }, mapping: { kind: "wildcard" } });
    expect(takeover.status).toBe(409);
    expect(JSON.stringify(await takeover.json())).toContain("already claims this destination");
  });

  it("pushes nothing for the removed App's Targets, and lets the Organization take an App again", async () => {
    expect((await removeApp()).status).toBe(204);
    await ctx.db.query("UPDATE sync_targets SET needs_sync = true, next_attempt_at = NULL");
    await runSyncOnce(ctx, { fetchImpl: github.fetchImpl });
    expect(github.mints).toEqual([]);
    expect((await app.request("/v1/organizations/acme/github-app", { headers: auth() })).status).toBe(404);
    expect((await removeApp(adminToken, "gha_whatever")).status).toBe(404);
    expect((await post("/v1/organizations/acme/github-app/import", { appId: APP.id, privateKey: pem })).status).toBe(201);
  });

  it("removes only the App the caller confirmed: one that replaced it meanwhile stays, with its connections", async () => {
    const confirmed = ((await (await app.request("/v1/organizations/acme/github-app", { headers: auth() })).json()) as { id: string }).id;
    expect((await removeApp(adminToken, confirmed)).status).toBe(204);
    const other = { ...APP, id: 777, slug: "varlatch-other", clientId: "Iv23other" };
    const otherPem = github.addApp(other);
    expect((await post("/v1/organizations/acme/github-app/import", { appId: other.id, privateKey: otherPem })).status).toBe(201);
    const inst = github.install(other.id, { login: "acme-new", id: 3000, type: "Organization" });
    const conn = (await (await post("/v1/organizations/acme/platform-connections", { credentialKind: "github-app", installationId: inst, name: "New" })).json()).id;

    const stale = await removeApp(adminToken, confirmed);
    expect(stale.status).toBe(409);
    expect(JSON.stringify(await stale.json())).toContain("changed since you confirmed");
    expect((await ctx.db.query("SELECT slug, removed_at IS NULL AS live, key_envelope IS NOT NULL AS keyed FROM github_apps WHERE removed_at IS NULL")).rows).toEqual([
      { slug: "varlatch-other", live: true, keyed: true },
    ]);
    expect((await ctx.db.query("SELECT revoked_at FROM platform_connections WHERE id = $1", [conn])).rows).toEqual([{ revoked_at: null }]);
    expect(await events("sync.github_app_removed")).toHaveLength(1);
    expect((await del("/v1/organizations/acme/github-app")).status).toBe(422);
  });

  it("needs only config.sync.manage, since it narrows disclosure", async () => {
    const svc = await (await post("/v1/organizations/acme/identities", { name: "runner", kind: "service" })).json();
    await post("/v1/organizations/acme/grants", {
      subjectIdentityId: svc.id,
      scope: { kind: "organization" },
      actions: ["config.sync.manage", "organization.read"],
    });
    expect((await removeApp(svc.credential)).status).toBe(204);
  });
});
