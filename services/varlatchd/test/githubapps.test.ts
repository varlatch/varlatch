// SPDX-License-Identifier: AGPL-3.0-or-later
import { generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { hashToken, issueCredential } from "../src/auth/credentials.js";
import { generateKey, type Envelope } from "../src/crypto/aead.js";
import { decryptGitHubAppKey, decryptPlatformCredential } from "../src/crypto/hierarchy.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
} from "../src/domain/bootstrap.js";
import { completeRegistration } from "../src/domain/githubapps.js";
import { getOrganization, orgKekOf } from "../src/domain/orgs.js";
import { buildApp, type BuildAppOptions } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * GitHub App registration (ADR-0047 Decision 1 and its 2026-10-09
 * amendment): the manifest flow's start and completion, the single-use
 * state, the owner check, and the wrapped key. GitHub is a fetch stub.
 */

const PUBLIC_URL = "https://varlatch.test";
const PEM = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs1", format: "pem" }) as string;

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let adminId: string;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  adminId = consumed.identityId;
  adminToken = (await issueCredential(ctx.db, { identityId: adminId, kind: "cli" })).token;
  app = buildApp(ctx, { publicUrl: PUBLIC_URL });
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

/** GitHub's conversion endpoint: one answer per call, every call recorded. */
function fakeGitHub(answer: (code: string) => Response | Promise<Response>) {
  const calls: { method: string; url: string }[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ method: init?.method ?? "GET", url });
    const m = url.match(/^https:\/\/api\.github\.com\/app-manifests\/([^/]+)\/conversions$/);
    if (!m || init?.method !== "POST") return Response.json({ message: "Not Found" }, { status: 404 });
    return answer(decodeURIComponent(m[1]!));
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const conversion = (overrides: Record<string, unknown> = {}) => ({
  id: 5254113,
  slug: "varlatch-acme",
  node_id: "A_kwDOB",
  client_id: "Iv23liCheck1009",
  client_secret: "client-secret-not-to-keep",
  webhook_secret: null,
  pem: PEM,
  name: "Varlatch acme",
  owner: { login: "acme-gh", id: 1009, type: "Organization" },
  permissions: { secrets: "write", environments: "write", metadata: "read" },
  events: [],
  ...overrides,
});
const created = (overrides: Record<string, unknown> = {}) => () => Response.json(conversion(overrides), { status: 201 });

function withGitHub(answer: (code: string) => Response | Promise<Response>, options: BuildAppOptions = {}) {
  const github = fakeGitHub(answer);
  app = buildApp(ctx, { publicUrl: PUBLIC_URL, syncFetch: github.fetchImpl, ...options });
  return github;
}

async function start(account = { login: "acme-gh", type: "organization" }, org = "acme", token = adminToken) {
  const res = await post(`/v1/organizations/${org}/github-app/registrations`, { account }, token);
  return { res, body: (await res.json()) as { state: string; action: string; manifest: Record<string, unknown>; expiresAt: string } };
}
async function complete(state: string, code = "code-1", org = "acme", token = adminToken) {
  const res = await post(`/v1/organizations/${org}/github-app/registrations/complete`, { state, code }, token);
  return { res, body: (await res.json()) as Record<string, any> };
}
const audit = async (prefix = "sync.github_app") =>
  (await ctx.db.query(
    "SELECT event_type, decision, actor_identity_id, organization_id, resource, metadata FROM audit_events WHERE event_type LIKE $1 ORDER BY event_order",
    [`${prefix}%`],
  )).rows as { event_type: string; decision: string; actor_identity_id: string; organization_id: string; resource: unknown; metadata: Record<string, unknown> }[];
const apps = async () => (await ctx.db.query("SELECT * FROM github_apps ORDER BY created_at")).rows as Record<string, unknown>[];

describe("starting a registration", () => {
  it("returns the manifest and where to post it, and stores only the state's hash, bound to the actor, Organization, and account", async () => {
    const { res, body } = await start();
    expect(res.status).toBe(201);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(body.manifest).toEqual({
      name: "Varlatch acme",
      url: PUBLIC_URL,
      description: "Varlatch writes GitHub Actions secrets for the Acme Organization.",
      redirect_url: `${PUBLIC_URL}/o/acme/connections/github-app`,
      public: false,
      default_permissions: { secrets: "write", environments: "write", metadata: "read" },
      default_events: [],
    });
    expect(body.manifest).not.toHaveProperty("hook_attributes");
    expect(body.action).toBe(`https://github.com/organizations/acme-gh/settings/apps/new?state=${body.state}`);
    expect(body.state).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const expiresIn = Date.parse(body.expiresAt) - Date.now();
    expect(expiresIn).toBeGreaterThan(3500_000);
    expect(expiresIn).toBeLessThanOrEqual(3600_000);

    const rows = (await ctx.db.query("SELECT * FROM github_app_registrations")).rows as Record<string, unknown>[];
    expect(rows).toHaveLength(1);
    expect(JSON.stringify(rows)).not.toContain(body.state);
    expect(rows[0]).toMatchObject({
      state_hash: hashToken(body.state),
      actor_identity_id: adminId,
      account_login: "acme-gh",
      account_type: "organization",
      consumed_at: null,
    });
  });

  it("posts to the user's own settings for a personal account", async () => {
    const { res, body } = await start({ login: "jeremy", type: "user" });
    expect(res.status).toBe(201);
    expect(body.action).toBe(`https://github.com/settings/apps/new?state=${body.state}`);
  });

  it("needs a public URL over HTTPS (or loopback), outbound sync, and the GitHub adapter", async () => {
    app = buildApp(ctx);
    expect((await start()).res.status).toBe(422);
    app = buildApp(ctx, { publicUrl: "http://varlatch.example.com" });
    expect((await start()).res.status).toBe(422);
    app = buildApp(ctx, { publicUrl: "http://localhost:8686" });
    expect((await start()).res.status).toBe(201);
    app = buildApp(ctx, { publicUrl: PUBLIC_URL, sync: null });
    expect((await start()).res.status).toBe(403);
    app = buildApp(ctx, { publicUrl: PUBLIC_URL, sync: { adapters: ["coolify"] } });
    expect((await start()).res.status).toBe(422);
  });

  it("refuses a name GitHub would not have, a caller without config.sync.manage, and an Organization that has an App", async () => {
    expect((await start({ login: "-acme", type: "organization" })).res.status).toBe(422);
    expect((await start({ login: "acme", type: "team" } as never)).res.status).toBe(422);

    await ctx.db.query("INSERT INTO identities(id,kind,name) VALUES ('idn_stranger','human','Stranger')");
    const stranger = (await issueCredential(ctx.db, { identityId: "idn_stranger", kind: "cli" })).token;
    expect((await start(undefined, "acme", stranger)).res.status).toBe(404);

    withGitHub(created());
    expect((await complete((await start()).body.state)).res.status).toBe(201);
    const again = await start();
    expect(again.res.status).toBe(409);
    expect(JSON.stringify(again.body)).toContain("already has a GitHub App");
  });

  it("deletes registrations a day after they expired", async () => {
    await ctx.db.query(
      `INSERT INTO github_app_registrations(state_hash,organization_id,actor_identity_id,account_login,account_type,created_at,expires_at)
       SELECT 'old', id, $1, 'acme-gh', 'organization', now() - interval '3 days', now() - interval '2 days' FROM organizations`,
      [adminId],
    );
    await start();
    expect((await ctx.db.query("SELECT state_hash FROM github_app_registrations WHERE state_hash = 'old'")).rows).toEqual([]);
  });
});

describe("completing a registration", () => {
  it("stores the App with its key wrapped under the Organization KEK, keeps no client secret, and audits it", async () => {
    const github = withGitHub(created());
    const { body: started } = await start();
    const { res, body } = await complete(started.state, "code-from-github");
    expect(res.status).toBe(201);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(github.calls).toEqual([{ method: "POST", url: "https://api.github.com/app-manifests/code-from-github/conversions" }]);
    expect(body).toEqual({
      outcome: "registered",
      app: {
        id: expect.stringMatching(/^gha_/),
        organizationId: expect.stringMatching(/^org_/),
        githubAppId: 5254113,
        slug: "varlatch-acme",
        clientId: "Iv23liCheck1009",
        owner: { login: "acme-gh", id: 1009, type: "organization" },
        htmlUrl: "https://github.com/apps/varlatch-acme",
        version: 1,
        createdAt: expect.any(String),
        updatedAt: null,
      },
    });
    const text = JSON.stringify(body);
    expect(text).not.toContain("PRIVATE KEY");
    expect(text).not.toContain("client-secret-not-to-keep");

    const [row] = await apps();
    expect(JSON.stringify(row)).not.toContain("PRIVATE KEY");
    expect(JSON.stringify(row)).not.toContain("client-secret-not-to-keep");
    const org = await getOrganization(ctx, "acme");
    const envelope = (typeof row!.key_envelope === "string" ? JSON.parse(row!.key_envelope) : row!.key_envelope) as Envelope;
    expect(decryptGitHubAppKey(orgKekOf(ctx, org), org.id, String(row!.id), envelope)).toBe(PEM);
    // Bound to its row and purpose: not readable as another App's key, or as a Platform Credential.
    expect(() => decryptGitHubAppKey(orgKekOf(ctx, org), org.id, "gha_other", envelope)).toThrow();
    expect(() => decryptPlatformCredential(orgKekOf(ctx, org), org.id, String(row!.id), envelope)).toThrow();

    expect(await audit()).toEqual([
      {
        event_type: "sync.github_app_registered",
        decision: "info",
        actor_identity_id: adminId,
        organization_id: org.id,
        resource: { githubAppId: row!.id },
        metadata: { via: "manifest", appId: 5254113, slug: "varlatch-acme", owner: "acme-gh", ownerType: "organization" },
      },
    ]);
    const read = await get("/v1/organizations/acme/github-app");
    expect(read.status).toBe(200);
    expect(await read.json()).toEqual(body.app);
  });

  it("matches the account's login whatever its case", async () => {
    withGitHub(created());
    const { body: started } = await start({ login: "ACME-GH", type: "organization" });
    expect((await complete(started.state)).body.outcome).toBe("registered");
  });

  it("refuses an App GitHub created on the person's own account, stores nothing, says where to delete it, and audits the refusal", async () => {
    withGitHub(created({ owner: { login: "jeremydeceuster", id: 60345314, type: "User" } }));
    const { body: started } = await start();
    const { res, body } = await complete(started.state);
    expect(res.status).toBe(200);
    expect(body).toMatchObject({
      outcome: "refused",
      reason: "owner-mismatch",
      app: { githubAppId: 5254113, slug: "varlatch-acme", owner: { login: "jeremydeceuster", type: "user" } },
      account: { login: "acme-gh", type: "organization" },
      deleteUrl: "https://github.com/settings/apps/varlatch-acme/advanced",
    });
    expect(body.message).toContain("on jeremydeceuster's own account, not on acme-gh");
    expect(JSON.stringify(body)).not.toContain("PRIVATE KEY");
    expect(await apps()).toEqual([]);
    expect(await audit()).toEqual([
      expect.objectContaining({
        event_type: "sync.github_app_registration_refused",
        decision: "deny",
        actor_identity_id: adminId,
        metadata: {
          reason: "owner-mismatch",
          appId: 5254113,
          slug: "varlatch-acme",
          owner: "jeremydeceuster",
          ownerType: "user",
          account: "acme-gh",
          accountType: "organization",
        },
      }),
    ]);
    expect((await get("/v1/organizations/acme/github-app")).status).toBe(404);
  });

  it("compares the account's type too: the same login as a user is not the organization", async () => {
    withGitHub(created({ owner: { login: "acme-gh", id: 1009, type: "User" } }));
    const { body: started } = await start({ login: "acme-gh", type: "organization" });
    expect((await complete(started.state)).body).toMatchObject({ outcome: "refused", reason: "owner-mismatch" });
    expect(await apps()).toEqual([]);
  });

  it("is single-use: a second completion is refused and never reaches GitHub", async () => {
    const github = withGitHub(created());
    const { body: started } = await start();
    expect((await complete(started.state)).res.status).toBe(201);
    const second = await complete(started.state);
    expect(second.res.status).toBe(410);
    expect(second.body.error.code).toBe("CONSUMED");
    expect(github.calls).toHaveLength(1);
  });

  it("lets one of two simultaneous completions through", async () => {
    const github = withGitHub(created());
    const { body: started } = await start();
    const results = await Promise.all([complete(started.state), complete(started.state)]);
    expect(results.map(r => r.res.status).sort()).toEqual([201, 410]);
    expect(github.calls).toHaveLength(1);
    expect(await apps()).toHaveLength(1);
  });

  it("refuses an expired, unknown, or foreign state, and one from another Organization or another person", async () => {
    const github = withGitHub(created());
    const { body: started } = await start();
    await ctx.db.query("UPDATE github_app_registrations SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 second'");
    const expired = await complete(started.state);
    expect(expired.res.status).toBe(410);
    expect(expired.body.error.code).toBe("EXPIRED");

    expect((await complete("forged-state")).res.status).toBe(404);

    await post("/v1/organizations", { name: "Beta", slug: "beta" });
    const { body: fresh } = await start();
    expect((await complete(fresh.state, "code-1", "beta")).res.status).toBe(404);

    await ctx.db.query("INSERT INTO identities(id,kind,name) VALUES ('idn_other','human','Other')");
    const org = await getOrganization(ctx, "acme");
    await expect(completeRegistration(ctx, org, { state: fresh.state, code: "code-1" }, "idn_other", github.fetchImpl)).rejects.toMatchObject({
      code: "RESOURCE_NOT_FOUND",
    });
    expect(github.calls).toEqual([]);
    // Still the starter's to complete.
    expect((await complete(fresh.state)).res.status).toBe(201);
  });

  it("releases the state when GitHub cannot be reached, so the same code can be tried again", async () => {
    let reachable = false;
    withGitHub(() => {
      if (!reachable) throw new TypeError("fetch failed");
      return Response.json(conversion(), { status: 201 });
    });
    const { body: started } = await start();
    const failed = await complete(started.state);
    expect(failed.res.status).toBe(200);
    expect(failed.body).toMatchObject({ outcome: "failed", retryable: true });
    expect(failed.body.message).toContain("could not reach api.github.com");
    expect(await apps()).toEqual([]);
    reachable = true;
    expect((await complete(started.state)).body.outcome).toBe("registered");
  });

  it("consumes the state when GitHub refuses the code", async () => {
    withGitHub(() => Response.json({ message: "Not Found" }, { status: 404 }));
    const { body: started } = await start();
    const failed = await complete(started.state);
    expect(failed.body).toMatchObject({ outcome: "failed", retryable: false, httpStatus: 404 });
    expect((await complete(started.state)).res.status).toBe(410);
    expect(await apps()).toEqual([]);
  });

  it("keeps nothing from an answer that is not GitHub's", async () => {
    const answers: (() => Response)[] = [
      () => new Response("<html>Sign in</html>", { status: 201, headers: { "content-type": "text/html" } }),
      () => Response.json([conversion()], { status: 201 }),
      created({ pem: undefined }),
      created({ pem: "-----BEGIN RSA PRIVATE KEY-----\nnot a key\n-----END RSA PRIVATE KEY-----\n" }),
      created({ pem: generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }) }),
      created({ owner: undefined }),
      created({ owner: { login: "acme-gh", id: 1009, type: "Bot" } }),
      created({ id: "5254113" }),
      created({ slug: "Varlatch Acme" }),
      created({ client_id: "" }),
    ];
    for (const answer of answers) {
      withGitHub(answer);
      const { body: started } = await start();
      const { res, body } = await complete(started.state);
      expect(res.status).toBe(200);
      expect(body).toMatchObject({ outcome: "failed", retryable: false });
      expect(body.message).toContain("not GitHub's");
    }
    expect(await apps()).toEqual([]);
    expect(await audit()).toEqual([]);
  });

  it("refuses the App when the Organization got another one meanwhile, and names where to delete it", async () => {
    withGitHub(created());
    const { body: first } = await start();
    const { body: second } = await start();
    expect((await complete(first.state)).body.outcome).toBe("registered");
    withGitHub(created({ id: 5254114, slug: "varlatch-acme-2" }));
    const { body } = await complete(second.state);
    expect(body).toMatchObject({
      outcome: "refused",
      reason: "organization-has-app",
      deleteUrl: "https://github.com/organizations/acme-gh/settings/apps/varlatch-acme-2/advanced",
    });
    expect((await apps()).map(a => a.slug)).toEqual(["varlatch-acme"]);
    expect((await audit("sync.github_app_registration_refused")).map(e => e.metadata.reason)).toEqual(["organization-has-app"]);
  });

  it("refuses an App another Organization already has", async () => {
    await post("/v1/organizations", { name: "Beta", slug: "beta" });
    withGitHub(created());
    expect((await complete((await start(undefined, "beta")).body.state, "code-1", "beta")).body.outcome).toBe("registered");
    const { body } = await complete((await start()).body.state);
    expect(body).toMatchObject({ outcome: "refused", reason: "app-in-use" });
    expect((await apps()).map(a => a.slug)).toEqual(["varlatch-acme"]);
  });
});

describe("reading the App", () => {
  it("is not found before registration, and hidden from a caller without config.sync.manage", async () => {
    expect((await get("/v1/organizations/acme/github-app")).status).toBe(404);
    await ctx.db.query("INSERT INTO identities(id,kind,name) VALUES ('idn_stranger','human','Stranger')");
    const stranger = (await issueCredential(ctx.db, { identityId: "idn_stranger", kind: "cli" })).token;
    withGitHub(created());
    await complete((await start()).body.state);
    expect((await get("/v1/organizations/acme/github-app")).status).toBe(200);
    expect((await get("/v1/organizations/acme/github-app", stranger)).status).toBe(404);
  });
});
