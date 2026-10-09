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
import { buildApp } from "../src/http/app.js";
import type { WhoisResult } from "../src/tailnet/whois.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * GET /v1/me (capability identity.whoami): any authenticated caller, human
 * or machine, learns the identity it authenticated as, that identity's
 * organization, the credential it presented, and the listener it came in
 * on. No Grant is needed, nothing names another identity or credential, a
 * successful call records no audit event, and a refused credential is the
 * bearer middleware's authentication.failed.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let adminId: string;
let runnerId: string;
/** The credential issued with the identity. */
let runnerToken: string;

const IDS = (id: string, org = "acme") => `/v1/organizations/${org}/identities/${id}`;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  adminId = consumed.identityId;
  adminToken = (await issueCredential(ctx.db, { identityId: adminId, kind: "cli" })).token;
  app = buildApp(ctx);

  expect((await post("/v1/organizations", { name: "Acme", slug: "acme" })).status).toBe(201);
  const runner = (await (await post("/v1/organizations/acme/identities", { name: "runner-macmini", kind: "service" })).json()) as {
    id: string;
    credential: string;
  };
  runnerId = runner.id;
  runnerToken = runner.credential;
});
afterEach(async () => {
  await ctx.close();
});

function auth(token = adminToken): HeadersInit {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}
async function post(path: string, body?: unknown, token = adminToken) {
  return app.request(path, {
    method: "POST",
    headers: auth(token),
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}
async function whoami(token: string, on = app, headers: Record<string, string> = {}) {
  return on.request("/v1/me", { headers: { ...auth(token), ...headers } });
}
/** Another named credential of an identity, as `varlatch credential issue` makes one. */
async function issue(name: string, extra: Record<string, unknown> = {}, id = runnerId) {
  const res = await post(`${IDS(id)}/credentials`, { name, ...extra });
  expect(res.status).toBe(201);
  return (await res.json()) as { id: string; token: string; expiresAt: string | null };
}
async function auditCount(): Promise<number> {
  return ((await ctx.db.query("SELECT count(*)::int AS n FROM audit_events")).rows[0] as { n: number }).n;
}
async function lastAuthFailure(): Promise<{ reason: string } | undefined> {
  const res = await ctx.db.query(
    "SELECT metadata FROM audit_events WHERE event_type = 'authentication.failed' ORDER BY event_order DESC LIMIT 1",
  );
  const row = res.rows[0] as { metadata: unknown } | undefined;
  if (!row) return undefined;
  return (typeof row.metadata === "string" ? JSON.parse(row.metadata) : row.metadata) as { reason: string };
}

describe("capability", () => {
  it("meta advertises identity.whoami", async () => {
    const meta = await (await app.request("/v1/meta")).json();
    expect(meta.capabilities).toContain("identity.whoami");
  });
});

describe("a human caller", () => {
  it("gets its identity and credential, no organization, and the ordinary listener", async () => {
    const res = await whoami(adminToken);
    expect(res.status).toBe(200);
    const body = await res.json();
    const credentialId = (
      (await ctx.db.query("SELECT id FROM credentials WHERE identity_id = $1 AND kind = 'cli'", [adminId])).rows[0] as { id: string }
    ).id;
    expect(body).toEqual({
      identity: { id: adminId, name: "Jeremy", kind: "human", email: null },
      // Humans belong to the Installation and join organizations as members.
      organization: null,
      credential: { id: credentialId, name: null, kind: "cli", expiresAt: null },
      listener: "ordinary",
    });
  });

  it("gets the email its profile shows, never the profile image", async () => {
    await ctx.db.query(
      `INSERT INTO "user" (id, name, email, "image") VALUES ('ba_user_1', 'Jeremy', 'jeremy@example.com', 'data:image/png;base64,aGk=')`,
    );
    await ctx.db.query("INSERT INTO auth_user_links (better_auth_user_id, identity_id) VALUES ('ba_user_1', $1)", [adminId]);
    const body = await (await whoami(adminToken)).json();
    expect(body.identity).toEqual({ id: adminId, name: "Jeremy", kind: "human", email: "jeremy@example.com" });
    expect(JSON.stringify(body)).not.toContain("data:image");
  });

  it("names the credential it presented, with its expiry", async () => {
    const expiresAt = new Date(Date.now() + 3_600_000).toISOString();
    const named = await issueCredential(ctx.db, { identityId: adminId, kind: "cli", name: "laptop login", expiresAt });
    const body = await (await whoami(named.token)).json();
    expect(body.credential).toEqual({ id: named.credentialId, name: "laptop login", kind: "cli", expiresAt });
  });
});

describe("a machine credential", () => {
  it("gets its identity and its organization, with no Grant at all", async () => {
    const desktopRunner = await issue("desktop-runner");
    const res = await whoami(desktopRunner.token);
    expect(res.status).toBe(200);
    const body = await res.json();
    const org = await (await app.request("/v1/organizations/acme", { headers: auth() })).json();
    expect(body).toEqual({
      identity: { id: runnerId, name: "runner-macmini", kind: "service", email: null },
      organization: { id: org.id, slug: "acme", name: "Acme", createdAt: org.createdAt },
      credential: { id: desktopRunner.id, name: "desktop-runner", kind: "service", expiresAt: null },
      listener: "ordinary",
    });
    // The same identity's /v1/organizations lists no membership: a machine
    // learns its organization here.
    expect((await (await app.request("/v1/organizations", { headers: auth(desktopRunner.token) })).json()).items).toEqual([]);
  });

  it("tells the programs that share an identity apart by their credentials", async () => {
    const programs = ["desktop-runner", "session-handler", "lock-authority"];
    const issued = await Promise.all(programs.map((name) => issue(name, { ttlSeconds: 3600 })));
    for (const [i, cred] of issued.entries()) {
      const body = await (await whoami(cred.token)).json();
      expect(body.identity.id).toBe(runnerId);
      expect(body.credential).toEqual({ id: cred.id, name: programs[i], kind: "service", expiresAt: cred.expiresAt });
    }
    // The credential issued with the identity carries the default name.
    expect((await (await whoami(runnerToken)).json()).credential).toMatchObject({ name: "runner-macmini credential", kind: "service" });
  });

  it("works for every machine kind that holds a credential", async () => {
    for (const kind of ["workload", "broker"]) {
      const created = (await (await post("/v1/organizations/acme/identities", { name: `a-${kind}`, kind })).json()) as {
        id: string;
        credential: string;
      };
      const body = await (await whoami(created.credential)).json();
      expect(body.identity).toEqual({ id: created.id, name: `a-${kind}`, kind, email: null });
      expect(body.organization.slug).toBe("acme");
    }
  });

  it("follows a rename on the next call", async () => {
    const res = await app.request(IDS(runnerId), { method: "PATCH", headers: auth(), body: JSON.stringify({ name: "runner-mini" }) });
    expect(res.status).toBe(200);
    expect((await (await whoami(runnerToken)).json()).identity.name).toBe("runner-mini");
  });
});

describe("refused credentials", () => {
  it("a retired identity's credentials get 401, audited as authentication.failed, and stay refused after reactivation", async () => {
    const desktopRunner = await issue("desktop-runner");
    expect((await post(`${IDS(runnerId)}/retire`)).status).toBe(200);
    for (const token of [runnerToken, desktopRunner.token]) {
      const res = await whoami(token);
      expect(res.status).toBe(401);
      expect((await res.json()).error.code).toBe("INVALID_CREDENTIAL");
    }
    // Retiring revokes every credential (ADR-0034 §3).
    expect(await lastAuthFailure()).toMatchObject({ reason: "revoked" });
    expect((await post(`${IDS(runnerId)}/reactivate`)).status).toBe(200);
    expect((await whoami(desktopRunner.token)).status).toBe(401);
  });

  it("a disabled identity is refused even with a credential that was never revoked", async () => {
    await ctx.db.query("UPDATE identities SET disabled = true WHERE id = $1", [runnerId]);
    const res = await whoami(runnerToken);
    expect(res.status).toBe(401);
    expect(await lastAuthFailure()).toMatchObject({ reason: "identity-disabled" });
  });

  it("a revoked credential gets 401, while the identity's other credentials still answer", async () => {
    const sessionHandler = await issue("session-handler");
    const lockAuthority = await issue("lock-authority");
    const res = await app.request(`${IDS(runnerId)}/credentials/${sessionHandler.id}`, { method: "DELETE", headers: auth() });
    expect(res.status).toBe(204);
    const refused = await whoami(sessionHandler.token);
    expect(refused.status).toBe(401);
    expect((await refused.json()).error.code).toBe("INVALID_CREDENTIAL");
    expect(await lastAuthFailure()).toMatchObject({ reason: "revoked" });
    expect((await (await whoami(lockAuthority.token)).json()).credential.name).toBe("lock-authority");
  });

  it("an expired credential, an unknown token, and no bearer at all are refused", async () => {
    const expired = await issueCredential(ctx.db, {
      identityId: runnerId,
      kind: "service",
      name: "old",
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    });
    expect((await whoami(expired.token)).status).toBe(401);
    expect(await lastAuthFailure()).toMatchObject({ reason: "expired" });
    expect((await whoami("vlt_svc_not-a-credential")).status).toBe(401);
    expect(await lastAuthFailure()).toMatchObject({ reason: "invalid" });
    const none = await app.request("/v1/me");
    expect(none.status).toBe(401);
    expect((await none.json()).error.code).toBe("AUTHENTICATION_REQUIRED");
  });

  it("spends a use of a credential with a use budget, like every authenticated request", async () => {
    const budgeted = await issue("one-shot", { maxUses: 2 });
    expect((await whoami(budgeted.token)).status).toBe(200);
    expect((await whoami(budgeted.token)).status).toBe(200);
    expect((await whoami(budgeted.token)).status).toBe(401);
    expect(await lastAuthFailure()).toMatchObject({ reason: "exhausted" });
  });
});

describe("audit", () => {
  it("records no event for a successful call, as for the other /v1/me reads", async () => {
    const before = await auditCount();
    expect((await whoami(adminToken)).status).toBe(200);
    expect((await whoami(runnerToken)).status).toBe(200);
    expect((await app.request("/v1/me/credentials", { headers: auth(runnerToken) })).status).toBe(200);
    expect(await auditCount()).toBe(before);
  });
});

describe("nothing about anyone else", () => {
  it("names only the caller: no other identity, organization, or credential, and no token", async () => {
    // Neighbors: a sibling credential, another machine in the same
    // organization, a member, and another organization with its own machine.
    const sibling = await issue("lock-authority");
    const neighbor = (await (await post("/v1/organizations/acme/identities", { name: "runner-imac", kind: "service" })).json()) as {
      id: string;
      credential: string;
    };
    const invite = await post("/v1/organizations/acme/invitations", { name: "Sam", role: "member" });
    const { identityId: memberId } = await consumeSetupGrant(ctx, (await invite.json()).token, {});
    expect((await post("/v1/organizations", { name: "Globex", slug: "globex" })).status).toBe(201);
    const foreign = (await (await post("/v1/organizations/globex/identities", { name: "globex-runner", kind: "service" })).json()) as {
      id: string;
      credential: string;
    };
    const globex = await (await app.request("/v1/organizations/globex", { headers: auth() })).json();
    const others = [adminId, "Jeremy", sibling.id, "lock-authority", neighbor.id, "runner-imac", memberId, "Sam", foreign.id, "globex-runner", globex.id, "globex"];

    const res = await whoami(runnerToken);
    const body = await res.json();
    expect(Object.keys(body).sort()).toEqual(["credential", "identity", "listener", "organization"]);
    expect(Object.keys(body.identity).sort()).toEqual(["email", "id", "kind", "name"]);
    expect(Object.keys(body.credential).sort()).toEqual(["expiresAt", "id", "kind", "name"]);
    const text = JSON.stringify(body);
    for (const other of others) expect(text, other).not.toContain(other);
    // No token material, the caller's own included.
    expect(text).not.toMatch(/vlt_|token/i);
    expect(text).not.toContain(runnerToken);

    // The other organization's machine sees its own organization only.
    const theirs = await (await whoami(foreign.credential)).json();
    expect(theirs.organization.slug).toBe("globex");
    expect(JSON.stringify(theirs)).not.toMatch(new RegExp(`${runnerId}|runner-macmini|"acme"`));
  });

  it("takes nothing from the request that could name another identity", async () => {
    const neighbor = (await (await post("/v1/organizations/acme/identities", { name: "runner-imac", kind: "service" })).json()) as {
      id: string;
    };
    const res = await app.request(`/v1/me?identity=${neighbor.id}&id=${neighbor.id}`, {
      headers: { ...auth(runnerToken), "X-Varlatch-Identity": neighbor.id },
    });
    expect((await res.json()).identity.id).toBe(runnerId);
    // /v1/me/<anything else> is not a lookup by ID.
    expect((await app.request(`/v1/me/${neighbor.id}`, { headers: auth(runnerToken) })).status).toBe(404);
  });
});

describe("listeners", () => {
  const device = {
    tailnet: "example.ts.net",
    nodeId: "nRunner",
    nodeName: "macmini",
    tags: ["tag:desktop-runner", "tag:runner-macmini"],
  };

  it("on the tailnet listener, reports the device the connection resolved to, its machine name included", async () => {
    const tailnetApp = buildApp(ctx, { resolveTailnetContext: async () => device });
    const body = await (await whoami(runnerToken, tailnetApp)).json();
    expect(body.listener).toBe("tailnet");
    expect(body.tailnet).toEqual({ recognized: true, ...device });
    expect(body.identity.name).toBe("runner-macmini");
    // An untagged device's user, and a device without a machine name.
    const userApp = buildApp(ctx, {
      resolveTailnetContext: async () => ({ tailnet: "example.ts.net", nodeId: "nLaptop", tags: [], userLogin: "jeremy@example.com" }),
    });
    expect((await (await whoami(adminToken, userApp)).json()).tailnet).toEqual({
      recognized: true,
      tailnet: "example.ts.net",
      nodeId: "nLaptop",
      tags: [],
      userLogin: "jeremy@example.com",
    });
  });

  it("on the browser endpoint, reports the same device as GET /v1/tailnet/context, and is no cross-origin route", async () => {
    const host = "varlatch.example.ts.net";
    const browserApp = buildApp(ctx, {
      resolveTailnetContext: async () => device,
      tailnetBrowser: { host, port: 8688, origins: ["https://varlatch.example.com"] },
      browserEndpoint: `https://${host}:8688`,
    });
    const headers = { ...auth(runnerToken), Host: `${host}:8688` } as Record<string, string>;
    const me = await (await browserApp.request("/v1/me", { headers })).json();
    const context = await (await browserApp.request("/v1/tailnet/context", { headers })).json();
    expect(me.tailnet).toEqual({ recognized: true, ...device });
    expect(me.tailnet).toEqual(context);
    // ADR-0046 Decision 4: pages may call only the protected reads and the device check.
    const page = await browserApp.request("/v1/me", { headers: { ...headers, Origin: "https://varlatch.example.com" } });
    expect(page.status).toBe(403);
    expect(page.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });

  it.each(["resolver-unavailable", "unrecognized", "other-tailnet", "shared", "self"] as const)(
    "on the tailnet listener, says why a connection has no device (%s), and still answers",
    async (reason) => {
      const refusing = buildApp(ctx, { resolveTailnetContext: async (): Promise<WhoisResult> => ({ ok: false, reason }) });
      const res = await whoami(runnerToken, refusing);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.listener).toBe("tailnet");
      expect(body.tailnet).toEqual({ recognized: false, reason });
    },
  );

  it("on the ordinary listener, headers never make a device", async () => {
    const body = await (
      await whoami(runnerToken, app, {
        "X-Forwarded-For": "100.64.0.7",
        "Tailscale-User-Login": "jeremy@example.com",
        "Tailscale-User-Name": "Jeremy",
      })
    ).json();
    expect(body.listener).toBe("ordinary");
    expect(body).not.toHaveProperty("tailnet");
  });
});
