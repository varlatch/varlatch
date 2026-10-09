// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
} from "../src/domain/bootstrap.js";
import { runSyncOnce } from "../src/domain/syncdelivery.js";
import { buildApp, type BuildAppOptions } from "../src/http/app.js";
import { fakeGitHubApps } from "./helpers/fake-github-app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * App Connections (ADR-0047 Decisions 2-4): a Connection on an installation
 * of the Organization's GitHub App stores no token. Every push, access
 * check, and listing mints a one-hour installation token narrowed to the
 * use; the unchanged adapter pushes and checks destinations with it; the
 * Connection alone is checked, and listed, through the installation; and
 * no expiry is ever recorded or returned. GitHub is a fetch stub that
 * verifies the App's JWT and enforces each token's narrowing.
 */

const APP = {
  id: 5254113,
  slug: "varlatch-acme",
  clientId: "Iv23liCheck1009",
  owner: { login: "Acme-GH", id: 1009, type: "Organization" as const },
  permissions: { secrets: "write", environments: "write", metadata: "read" },
};
const ACCOUNT = { login: "Acme-GH", id: 1009, type: "Organization" as const };
const ENV_PATH = "/v1/organizations/acme/projects/api/environments/development";

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let github: ReturnType<typeof fakeGitHubApps>;
let pem: string;
let installationId: number;

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
  await put(`${ENV_PATH}/values/DATABASE_URL`, { value: "postgres://dev-db/main" });
  await put(`${ENV_PATH}/values/PORT`, { value: "8080" });
  pem = github.addApp(APP);
  expect((await post("/v1/organizations/acme/github-app/import", { appId: APP.id, privateKey: pem })).status).toBe(201);
  installationId = github.install(APP.id, ACCOUNT, "selected", null, [
    { name: "api", private: true, environments: ["production"] },
    { name: "web", private: false },
    { name: "old", private: true, archived: true },
  ]);
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
async function appConnection(id = installationId, token = adminToken) {
  const res = await post("/v1/organizations/acme/platform-connections", { credentialKind: "github-app", installationId: id, name: "GitHub (App)" }, token);
  return { res, body: (await res.json()) as Record<string, any> };
}
async function check(body: Record<string, unknown>) {
  const res = await post("/v1/organizations/acme/platform-connections/check", body);
  return { res, body: (await res.json()) as Record<string, any> };
}
async function createTarget(connectionId: string, destination: Record<string, string>) {
  const res = await post(`${ENV_PATH}/sync-targets`, { connectionId, destination, mapping: { kind: "wildcard" } });
  expect(res.status).toBe(201);
  return (await res.json()) as { id: string };
}
const audit = async (type: string) =>
  (await ctx.db.query("SELECT resource, metadata FROM audit_events WHERE event_type = $1 ORDER BY event_order", [type])).rows as {
    resource: Record<string, unknown>;
    metadata: Record<string, unknown>;
  }[];
const target = async (id: string) =>
  (await ctx.db.query("SELECT last_result, failure_count, state FROM sync_targets WHERE id = $1", [id])).rows[0] as Record<string, unknown>;

describe("creating an App Connection", () => {
  it("reads the installation as the App, takes its account as the base identity, stores no token, and audits the kind", async () => {
    const { res, body } = await appConnection();
    expect(res.status).toBe(201);
    expect(body).toMatchObject({
      platform: "github-actions",
      baseIdentity: "acme-gh",
      name: "GitHub (App)",
      credentialKind: "github-app",
      githubAppId: expect.stringMatching(/^gha_/),
      installationId,
      credentialExpiresAt: null,
    });
    expect(github.calls).toEqual([{ method: "GET", path: `/app/installations/${installationId}`, issuer: APP.clientId }]);
    const [row] = (await ctx.db.query("SELECT credential_envelope, credential_kind FROM platform_connections")).rows as Record<string, unknown>[];
    expect(row).toEqual({ credential_envelope: null, credential_kind: "github-app" });
    expect((await audit("sync.connection_created"))[0]!.metadata).toMatchObject({
      platform: "github-actions",
      baseIdentity: "acme-gh",
      credentialKind: "github-app",
      installationId,
    });
  });

  it("refuses an installation of another App, an unknown or suspended one, and an Organization without an App", async () => {
    const other = { ...APP, id: 777, slug: "other", clientId: "Iv23other" };
    github.addApp(other);
    const foreign = github.install(other.id, ACCOUNT);
    const wrong = await appConnection(foreign);
    expect(wrong.res.status).toBe(422);
    expect(wrong.body.error.message).toContain("not an installation of this GitHub App");
    expect((await appConnection(424242)).res.status).toBe(422);
    const suspended = github.install(APP.id, { login: "acme-labs", id: 2000, type: "Organization" }, "all", "2026-10-01T00:00:00Z");
    const refused = await appConnection(suspended);
    expect(refused.res.status).toBe(422);
    expect(refused.body.error.message).toContain("is suspended");
    expect((await ctx.db.query("SELECT id FROM platform_connections")).rows).toEqual([]);

    await post("/v1/organizations", { name: "Beta", slug: "beta" });
    const none = await post("/v1/organizations/beta/platform-connections", { credentialKind: "github-app", installationId, name: "x" });
    expect(none.status).toBe(404);
  });

  it("refuses an installation answer that is not this App's, or not about this installation", async () => {
    for (const change of [{ app_id: 777 }, { app_id: undefined }, { id: 1 }, { account: { login: "acme gh", id: 1009, type: "Organization" } }]) {
      rebuild({
        syncFetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
          const res = await github.fetchImpl(input, init);
          if (!String(input).endsWith(`/app/installations/${installationId}`)) return res;
          return Response.json({ ...(await res.json()), ...change }, { headers: { date: new Date().toUTCString() } });
        }) as typeof fetch,
      });
      const { res, body } = await appConnection();
      expect(res.status, JSON.stringify(change)).toBe(422);
      expect(body.error.message).toContain("not GitHub's");
    }
    expect((await ctx.db.query("SELECT id FROM platform_connections")).rows).toEqual([]);
  });

  it("needs the GitHub adapter, outbound sync, and config.sync.manage", async () => {
    rebuild({ sync: { adapters: ["coolify"] } });
    expect((await appConnection()).res.status).toBe(422);
    rebuild({ sync: null });
    expect((await appConnection()).res.status).toBe(403);
    rebuild();
    await ctx.db.query("INSERT INTO identities(id,kind,name) VALUES ('idn_stranger','human','Stranger')");
    const stranger = (await issueCredential(ctx.db, { identityId: "idn_stranger", kind: "cli" })).token;
    expect((await appConnection(installationId, stranger)).res.status).toBe(404);
  });

  it("has no credential to replace, check as a replacement, or supply", async () => {
    const { body: connection } = await appConnection();
    const replaced = await post(`/v1/organizations/acme/platform-connections/${connection.id}/credential`, { credential: "ghp_x", expectedVersion: 1 });
    expect(replaced.status).toBe(422);
    expect(JSON.stringify(await replaced.json())).toContain("Rotate the App's key instead");
    expect((await check({ connectionId: connection.id, credential: "ghp_x" })).res.status).toBe(422);
  });
});

describe("checking and listing through the App", () => {
  it("checks the Connection alone through the installation, with an installation-wide metadata token, and records no expiry", async () => {
    const { body: connection } = await appConnection();
    const { res, body } = await check({ connectionId: connection.id });
    expect(res.status).toBe(200);
    expect(body).toEqual({ status: "ok", where: "connection", message: "The GitHub App is installed on acme-gh, with access to 3 repositories." });
    expect(github.mints).toEqual([{ installationId, repositories: null, permissions: { metadata: "read" } }]);
    // GitHub sent an expiry header with the minted token's answers: never the Connection's.
    expect((await ctx.db.query("SELECT credential_expires_at, credential_expiry_seen_at FROM platform_connections")).rows).toEqual([
      { credential_expires_at: null, credential_expiry_seen_at: null },
    ]);
    expect((await audit("sync.connection_checked"))[0]!.metadata).toMatchObject({ credential: "stored", credentialKind: "github-app", status: "ok" });
  });

  it("checks a destination with a token narrowed to it: secrets read, or environments read", async () => {
    const { body: connection } = await appConnection();
    expect((await check({ connectionId: connection.id, destination: { repo: "api" } })).body).toMatchObject({ status: "ok", where: "destination" });
    expect((await check({ connectionId: connection.id, destination: { repo: "api", environment: "production" } })).body).toMatchObject({ status: "ok" });
    expect(github.mints).toEqual([
      { installationId, repositories: ["api"], permissions: { secrets: "read", metadata: "read" } },
      { installationId, repositories: ["api"], permissions: { environments: "read", metadata: "read" } },
    ]);
  });

  it("explains a refused token: a repository outside the installation (private or public), or a permission the App lacks", async () => {
    const { body: connection } = await appConnection();
    github.createRepository("acme-gh", { name: "vault", private: true });
    github.createRepository("acme-gh", { name: "docs", private: false });
    expect((await check({ connectionId: connection.id, destination: { repo: "vault" } })).body).toMatchObject({
      status: "not-found",
      where: "destination",
      message: expect.stringContaining("cannot see acme-gh/vault"),
    });
    expect((await check({ connectionId: connection.id, destination: { repo: "docs" } })).body).toMatchObject({
      status: "not-found",
      where: "destination",
      message: expect.stringContaining("acme-gh/docs is not among the App installation's repositories"),
    });
    github.app(APP.id)!.permissions = { secrets: "write", metadata: "read" };
    expect((await check({ connectionId: connection.id, destination: { repo: "api", environment: "production" } })).body).toMatchObject({
      status: "failed",
      where: "connection",
      message: expect.stringContaining("though the App's installation includes it"),
    });
  });

  it("reads a key deleted on GitHub as the key, and an uninstalled App as a credential problem", async () => {
    const { body: connection } = await appConnection();
    github.addKey(APP.id);
    github.deleteKey(APP.id, pem);
    expect((await check({ connectionId: connection.id })).body).toMatchObject({
      status: "credential-rejected",
      where: "connection",
      message: expect.stringContaining("deleted on GitHub, or belongs to another App"),
    });
  });

  it("lists exactly the installation's repositories, archived ones left out, with no date", async () => {
    const { body: connection } = await appConnection();
    const res = await post("/v1/organizations/acme/platform-connections/destinations", { connectionId: connection.id });
    expect(res.status).toBe(200);
    const listing = await res.json();
    expect(listing.items.map((i: { label: string }) => i.label)).toEqual(["api", "web"]);
    expect(listing.check).not.toHaveProperty("credentialExpiresAt");
    expect(github.mints).toEqual([{ installationId, repositories: null, permissions: { metadata: "read" } }]);
    expect((await audit("sync.destinations_listed"))[0]!.metadata).toMatchObject({ credentialKind: "github-app", count: 2 });
  });
});

describe("pushing through the App", () => {
  it("pushes with a token minted for the destination alone, with write on its secrets, and records no expiry", async () => {
    const { body: connection } = await appConnection();
    const created = await createTarget(connection.id, { repo: "api" });
    await runSyncOnce(ctx, { fetchImpl: github.fetchImpl });
    expect(github.secret("acme-gh", "api", undefined, "DATABASE_URL")).toBe("postgres://dev-db/main");
    expect(github.secret("acme-gh", "api", undefined, "PORT")).toBe("8080");
    expect(github.mints).toEqual([{ installationId, repositories: ["api"], permissions: { secrets: "write", metadata: "read" } }]);
    expect(await target(created.id)).toMatchObject({ failure_count: 0, state: "active" });
    expect((await ctx.db.query("SELECT credential_expires_at FROM platform_connections")).rows).toEqual([{ credential_expires_at: null }]);
  });

  it("pushes to an environment with environments write", async () => {
    const { body: connection } = await appConnection();
    await createTarget(connection.id, { repo: "api", environment: "production" });
    await runSyncOnce(ctx, { fetchImpl: github.fetchImpl });
    expect(github.secret("acme-gh", "api", "production", "PORT")).toBe("8080");
    expect(github.mints).toEqual([{ installationId, repositories: ["api"], permissions: { environments: "write", metadata: "read" } }]);
  });

  it("fails the run with Varlatch's reading when no token can be minted, before any intent is recorded", async () => {
    const { body: connection } = await appConnection();
    const keyGone = await createTarget(connection.id, { repo: "api" });
    github.addKey(APP.id);
    github.deleteKey(APP.id, pem);
    await runSyncOnce(ctx, { fetchImpl: github.fetchImpl });
    expect(await target(keyGone.id)).toMatchObject({ failure_count: 1, last_result: expect.stringContaining("GitHub App: GitHub refused the App's key") });
    expect((await ctx.db.query("SELECT * FROM sync_ledger")).rows).toEqual([]);
    expect(github.secret("acme-gh", "api", undefined, "PORT")).toBeUndefined();
  });

  it("fails the run for a destination outside the installation, saying so", async () => {
    const { body: connection } = await appConnection();
    github.createRepository("acme-gh", { name: "vault", private: true });
    const outside = await createTarget(connection.id, { repo: "vault" });
    await runSyncOnce(ctx, { fetchImpl: github.fetchImpl });
    expect(await target(outside.id)).toMatchObject({ failure_count: 1, last_result: expect.stringContaining("cannot see acme-gh/vault") });
  });

  it("never attaches a Target, or pushes, once the App is gone", async () => {
    const { body: connection } = await appConnection();
    const created = await createTarget(connection.id, { repo: "api" });
    await ctx.db.query("UPDATE github_apps SET removed_at = now(), key_envelope = NULL");
    const attach = await post(`${ENV_PATH}/sync-targets`, { connectionId: connection.id, destination: { repo: "web" }, mapping: { kind: "wildcard" } });
    expect(attach.status).toBe(422);
    expect(JSON.stringify(await attach.json())).toContain("GitHub App was removed");
    await runSyncOnce(ctx, { fetchImpl: github.fetchImpl });
    expect(await target(created.id)).toMatchObject({ failure_count: 1, last_result: expect.stringContaining("GitHub App was removed from Varlatch") });
    expect(github.mints).toEqual([]);
  });

  it("revokes an App Connection like any other, leaving the App and its key", async () => {
    const { body: connection } = await appConnection();
    const created = await createTarget(connection.id, { repo: "api" });
    expect((await del(`/v1/organizations/acme/platform-connections/${connection.id}`)).status).toBe(204);
    expect(await target(created.id)).toMatchObject({ state: "disabled" });
    expect((await ctx.db.query("SELECT removed_at IS NULL AS live, key_envelope IS NOT NULL AS keyed FROM github_apps")).rows).toEqual([{ live: true, keyed: true }]);
  });
});
