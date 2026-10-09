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
import { buildApp, type BuildAppOptions } from "../src/http/app.js";
import { fakeGitHubApps } from "./helpers/fake-github-app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * The App's own calls (ADR-0047): importing an App by id and key, verified
 * with GET /app, and listing its installations. Both sign a JWT with the
 * stored key, and read a refused JWT as finding A does. GitHub is a fetch
 * stub that verifies the JWT as GitHub does.
 */

const APP = {
  id: 5254113,
  slug: "varlatch-acme",
  clientId: "Iv23liCheck1009",
  owner: { login: "acme-gh", id: 1009, type: "Organization" as const },
  permissions: { secrets: "write", environments: "write", metadata: "read" },
};

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let adminId: string;
let github: ReturnType<typeof fakeGitHubApps>;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  adminId = consumed.identityId;
  adminToken = (await issueCredential(ctx.db, { identityId: adminId, kind: "cli" })).token;
  github = fakeGitHubApps();
  app = buildApp(ctx, { syncFetch: github.fetchImpl });
  await post("/v1/organizations", { name: "Acme", slug: "acme" });
});
afterEach(async () => {
  await ctx.close();
});

function auth(token = adminToken): HeadersInit {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}
async function post(path: string, body: unknown, token = adminToken) {
  return app.request(path, { method: "POST", headers: auth(token), body: JSON.stringify(body) });
}
async function get(path: string, token = adminToken) {
  return app.request(path, { headers: auth(token) });
}
function rebuild(options: BuildAppOptions = {}) {
  app = buildApp(ctx, { syncFetch: github.fetchImpl, ...options });
}
async function importApp(appId: number, privateKey: string, org = "acme", token = adminToken) {
  const res = await post(`/v1/organizations/${org}/github-app/import`, { appId, privateKey }, token);
  return { res, body: (await res.json()) as Record<string, any> };
}
async function installations(token = adminToken) {
  const res = await get("/v1/organizations/acme/github-app/installations", token);
  return { res, body: (await res.json()) as Record<string, any> };
}
const apps = async () => (await ctx.db.query("SELECT * FROM github_apps")).rows as Record<string, unknown>[];
const audit = async (type: string) =>
  (await ctx.db.query("SELECT decision, actor_identity_id, resource, metadata FROM audit_events WHERE event_type = $1 ORDER BY event_order", [type]))
    .rows as { decision: string; actor_identity_id: string; resource: Record<string, unknown>; metadata: Record<string, unknown> }[];
async function stranger() {
  await ctx.db.query("INSERT INTO identities(id,kind,name) VALUES ('idn_stranger','human','Stranger')");
  return (await issueCredential(ctx.db, { identityId: "idn_stranger", kind: "cli" })).token;
}

describe("importing an App", () => {
  it("verifies the id and key with GET /app, keeps GitHub's slug, client id, and owner, wraps the key, and audits it", async () => {
    const pem = github.addApp(APP);
    const { res, body } = await importApp(APP.id, pem);
    expect(res.status).toBe(201);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(body).toEqual({
      outcome: "registered",
      app: expect.objectContaining({
        githubAppId: APP.id,
        slug: "varlatch-acme",
        clientId: "Iv23liCheck1009",
        owner: { login: "acme-gh", id: 1009, type: "organization" },
        version: 1,
      }),
    });
    expect(JSON.stringify(body)).not.toContain("PRIVATE KEY");
    // Signed as the App id: the only identifier given.
    expect(github.calls).toEqual([{ method: "GET", path: "/app", issuer: String(APP.id) }]);

    const [row] = await apps();
    const org = await getOrganization(ctx, "acme");
    const envelope = (typeof row!.key_envelope === "string" ? JSON.parse(row!.key_envelope) : row!.key_envelope) as Envelope;
    expect(decryptGitHubAppKey(orgKekOf(ctx, org), org.id, String(row!.id), envelope)).toBe(pem);
    expect(await audit("sync.github_app_registered")).toEqual([
      {
        decision: "info",
        actor_identity_id: adminId,
        resource: { githubAppId: row!.id },
        metadata: { via: "import", appId: APP.id, slug: "varlatch-acme", owner: "acme-gh", ownerType: "organization" },
      },
    ]);
    expect((await (await get("/v1/organizations/acme/github-app")).json()).slug).toBe("varlatch-acme");
  });

  it("imports an App with more permissions than Varlatch needs, and names them in the audit event", async () => {
    const pem = github.addApp({ ...APP, permissions: { ...APP.permissions, contents: "write", actions: "read" } });
    expect((await importApp(APP.id, pem)).res.status).toBe(201);
    expect((await audit("sync.github_app_registered"))[0]!.metadata.extraPermissions).toBe("actions:read,contents:write");
  });

  it("refuses an App that lacks a permission Varlatch pushes with, and names it", async () => {
    const pem = github.addApp({ ...APP, permissions: { secrets: "read", metadata: "read" } });
    const { res, body } = await importApp(APP.id, pem);
    expect(res.status).toBe(200);
    expect(body).toMatchObject({ outcome: "failed", status: "permission-missing", where: "connection", httpStatus: 200 });
    expect(body.message).toContain("lacks secrets: write, environments: write");
    expect(await apps()).toEqual([]);
  });

  it("reads a refused key as the key when the request was valid at GitHub's time", async () => {
    github.addApp(APP);
    const otherKey = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs1", format: "pem" }) as string;
    const { res, body } = await importApp(APP.id, otherKey);
    expect(res.status).toBe(200);
    expect(body).toMatchObject({ outcome: "failed", status: "credential-rejected", where: "connection", httpStatus: 401 });
    expect(body.message).toContain("deleted on GitHub, or belongs to another App");
    expect(await apps()).toEqual([]);
  });

  it("names this server's clock, with its direction, when it is far off; tolerates 45 seconds", async () => {
    const pem = github.addApp(APP);
    github.state.clockOffsetMs = -15 * 60_000;
    const ahead = await importApp(APP.id, pem);
    expect(ahead.body).toMatchObject({ outcome: "failed", status: "failed", httpStatus: 401 });
    expect(ahead.body.message).toContain("about 15 minutes ahead of GitHub's");
    github.state.clockOffsetMs = 15 * 60_000;
    expect((await importApp(APP.id, pem)).body.message).toContain("about 15 minutes behind GitHub's");
    github.state.clockOffsetMs = -45_000;
    expect((await importApp(APP.id, pem)).res.status).toBe(201);
  });

  it("names both causes when GitHub sends no Date header", async () => {
    github.addApp(APP);
    github.state.sendDate = false;
    const otherKey = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs1", format: "pem" }) as string;
    const { body } = await importApp(APP.id, otherKey);
    expect(body).toMatchObject({ outcome: "failed", status: "failed" });
    expect(body.message).toContain("Varlatch cannot tell which");
  });

  it("refuses a key that is not an RSA private key before calling GitHub", async () => {
    github.addApp(APP);
    const ed25519 = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    for (const key of ["not a key", "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n", ed25519]) {
      expect((await importApp(APP.id, key)).res.status).toBe(422);
    }
    expect(github.calls).toEqual([]);
  });

  it("keeps nothing when GitHub cannot be reached, refuses otherwise, or answers as GitHub would not", async () => {
    const pem = github.addApp(APP);
    rebuild({ syncFetch: (async () => { throw new TypeError("fetch failed"); }) as typeof fetch });
    expect((await importApp(APP.id, pem)).body).toMatchObject({ outcome: "failed", status: "unreachable" });
    rebuild({ syncFetch: (async () => Response.json({ message: "Server Error" }, { status: 500 })) as typeof fetch });
    expect((await importApp(APP.id, pem)).body).toMatchObject({ outcome: "failed", status: "failed", httpStatus: 500 });
    const foreign: (() => Response)[] = [
      () => new Response("<html>Sign in</html>", { status: 200 }),
      () => Response.json({ id: APP.id, slug: APP.slug, client_id: APP.clientId, permissions: APP.permissions }),
      () => Response.json({ id: 999, slug: APP.slug, client_id: APP.clientId, owner: APP.owner, permissions: APP.permissions }),
      () => Response.json({ id: APP.id, slug: APP.slug, client_id: APP.clientId, owner: APP.owner }),
    ];
    for (const answer of foreign) {
      rebuild({ syncFetch: (async () => answer()) as typeof fetch });
      const { body } = await importApp(APP.id, pem);
      expect(body).toMatchObject({ outcome: "failed", status: "failed" });
      expect(body.message).toContain("not GitHub's");
    }
    expect(await apps()).toEqual([]);
  });

  it("refuses when the Organization has an App, or another Organization has this one", async () => {
    const pem = github.addApp(APP);
    expect((await importApp(APP.id, pem)).res.status).toBe(201);
    const calls = github.calls.length;
    expect((await importApp(APP.id, pem)).res.status).toBe(409);
    expect(github.calls).toHaveLength(calls);

    await post("/v1/organizations", { name: "Beta", slug: "beta" });
    const taken = await importApp(APP.id, pem, "beta");
    expect(taken.res.status).toBe(409);
    expect(JSON.stringify(taken.body)).toContain("Another Organization on this Varlatch already uses the App varlatch-acme");
  });

  it("needs config.sync.manage, outbound sync, and the GitHub adapter", async () => {
    const pem = github.addApp(APP);
    expect((await importApp(APP.id, pem, "acme", await stranger())).res.status).toBe(404);
    rebuild({ sync: null });
    expect((await importApp(APP.id, pem)).res.status).toBe(403);
    rebuild({ sync: { adapters: ["coolify"] } });
    expect((await importApp(APP.id, pem)).res.status).toBe(422);
    expect(github.calls).toEqual([]);
  });
});

describe("listing the App's installations", () => {
  async function imported() {
    const pem = github.addApp(APP);
    expect((await importApp(APP.id, pem)).res.status).toBe(201);
    github.calls.length = 0;
    return pem;
  }

  it("lists where the App is installed, signed as the client id, and audits the listing", async () => {
    await imported();
    const id = github.install(APP.id, { login: "acme-gh", id: 1009, type: "Organization" });
    github.install(APP.id, { login: "acme-gh-labs", id: 2000, type: "Organization" }, "all", "2026-10-01T00:00:00Z");
    const { res, body } = await installations();
    expect(res.status).toBe(200);
    expect(body).toEqual({
      check: { status: "ok", where: "connection", message: "listed" },
      items: [
        { installationId: id, account: { login: "acme-gh", id: 1009, type: "organization" }, repositorySelection: "selected", suspended: false },
        { installationId: id + 1, account: { login: "acme-gh-labs", id: 2000, type: "organization" }, repositorySelection: "all", suspended: true },
      ],
      truncated: false,
    });
    expect(github.calls).toEqual([{ method: "GET", path: "/app/installations?per_page=100&page=1", issuer: APP.clientId }]);
    const [event] = await audit("sync.github_app_installations_listed");
    expect(event).toMatchObject({ decision: "info", actor_identity_id: adminId, metadata: { status: "ok", httpStatus: null, count: 2, truncated: false } });
    expect(event!.resource.githubAppId).toMatch(/^gha_/);
  });

  it("reads every page, and says when it stopped at the limit", async () => {
    await imported();
    for (let i = 0; i < 150; i++) github.install(APP.id, { login: `acct${i}`, id: 3000 + i, type: "User" });
    let listed = await installations();
    expect(listed.body.items).toHaveLength(150);
    expect(listed.body.truncated).toBe(false);
    for (let i = 150; i < 3001; i++) github.install(APP.id, { login: `acct${i}`, id: 3000 + i, type: "User" });
    listed = await installations();
    expect(listed.body.items).toHaveLength(3000);
    expect(listed.body.truncated).toBe(true);
  });

  it("reads a key deleted on GitHub as the key", async () => {
    const pem = await imported();
    github.addKey(APP.id);
    github.deleteKey(APP.id, pem);
    const { body } = await installations();
    expect(body).toMatchObject({ check: { status: "credential-rejected", where: "connection", httpStatus: 401 }, items: [], truncated: false });
    expect((await audit("sync.github_app_installations_listed"))[0]!.metadata).toMatchObject({ status: "credential-rejected", httpStatus: 401, count: 0 });
  });

  it("names this server's clock when it is far off", async () => {
    await imported();
    github.state.clockOffsetMs = 15 * 60_000;
    const { body } = await installations();
    expect(body.check).toMatchObject({ status: "failed", httpStatus: 401 });
    expect(body.check.message).toContain("about 15 minutes behind GitHub's");
  });

  it("fails the listing, rather than skipping, on an answer that is not GitHub's", async () => {
    await imported();
    const answers: (() => Response)[] = [
      () => Response.json({ installations: [] }),
      () => Response.json([{ id: 1, account: { login: "acme-gh", id: 1009, type: "Organization" } }]),
      () => Response.json([{ id: 1, account: { login: "acme gh", id: 1009, type: "Organization" }, repository_selection: "all" }]),
      () => new Response("<html>Sign in</html>"),
    ];
    for (const answer of answers) {
      rebuild({ syncFetch: (async () => answer()) as typeof fetch });
      const { body } = await installations();
      expect(body).toMatchObject({ check: { status: "failed", where: "connection" }, items: [], truncated: false });
      expect(body.check.message).toContain("not GitHub's");
    }
    rebuild({ syncFetch: (async () => { throw new TypeError("fetch failed"); }) as typeof fetch });
    expect((await installations()).body.check.status).toBe("unreachable");
  });

  it("fails the whole listing on an installation of another App, or without an App id, on any page", async () => {
    await imported();
    const entry = (n: number, appId?: unknown) => ({
      id: 9000 + n,
      ...(appId === undefined ? {} : { app_id: appId }),
      account: { login: `acct${n}`, id: 4000 + n, type: "User" },
      repository_selection: "selected",
      suspended_at: null,
    });
    const pages = (second: unknown[]) => (async (input: RequestInfo | URL) => {
      const page = Number(new URL(String(input)).searchParams.get("page"));
      return Response.json(page === 1 ? Array.from({ length: 100 }, (_, i) => entry(i, APP.id)) : second, { headers: { date: new Date().toUTCString() } });
    }) as typeof fetch;
    rebuild({ syncFetch: pages([entry(100, APP.id)]) });
    expect((await installations()).body).toMatchObject({ check: { status: "ok" }, truncated: false });
    expect((await installations()).body.items).toHaveLength(101);
    for (const appId of [5254114, null, "5254113", 0]) {
      rebuild({ syncFetch: pages([entry(100, APP.id), entry(101, appId)]) });
      const { body } = await installations();
      expect(body, String(appId)).toMatchObject({ check: { status: "failed", where: "connection" }, items: [], truncated: false });
      expect(body.check.message).toContain("not GitHub's");
    }
    rebuild({ syncFetch: pages([entry(100)]) });
    expect((await installations()).body).toMatchObject({ check: { status: "failed" }, items: [] });
  });

  it("is not found without an App, and hidden from a caller without config.sync.manage", async () => {
    expect((await installations()).res.status).toBe(404);
    await imported();
    expect((await installations(await stranger())).res.status).toBe(404);
  });
});
