// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { VarlatchClient } from "@varlatch/sdk";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
} from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * Issuing another service credential for an existing machine identity
 * (capability identity.credentials.issue): identity.manage at organization
 * scope, service/workload/broker identities that are not retired, every
 * other target existence-hidden. The Broker path of the same route
 * (ADR-0023) is unchanged.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let adminId: string;
let svcId: string;
let svcToken: string;

const IDS = (id: string, org = "acme") => `/v1/organizations/${org}/identities/${id}`;
const CREDS = (id: string, org = "acme") => `${IDS(id, org)}/credentials`;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  adminId = consumed.identityId;
  adminToken = (await issueCredential(ctx.db, { identityId: adminId, kind: "cli" })).token;
  app = buildApp(ctx);

  await post("/v1/organizations", { name: "Acme", slug: "acme" });
  const svc = await (await post("/v1/organizations/acme/identities", { name: "host-01", kind: "service" })).json();
  svcId = svc.id;
  svcToken = svc.credential;
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
async function get(path: string, token = adminToken) {
  return app.request(path, { headers: auth(token) });
}
async function del(path: string, token = adminToken) {
  return app.request(path, { method: "DELETE", headers: auth(token) });
}

async function issue(body: Record<string, unknown> = { name: "backup job" }, id = svcId, token = adminToken) {
  return post(CREDS(id), body, token);
}
async function listCreds(id = svcId) {
  const res = await get(CREDS(id));
  expect(res.status).toBe(200);
  return (await res.json()).items as {
    id: string;
    kind: string;
    name: string | null;
    expiresAt: string | null;
    revokedAt: string | null;
  }[];
}
async function create(name: string, kind: string, org = "acme") {
  const res = await post(`/v1/organizations/${org}/identities`, { name, kind });
  expect(res.status).toBe(201);
  return (await res.json()) as { id: string; credential: string | null };
}
async function memberToken(): Promise<string> {
  const invite = await post("/v1/organizations/acme/invitations", { name: "Sam", role: "member" });
  const { identityId } = await consumeSetupGrant(ctx, (await invite.json()).token, {});
  return (await issueCredential(ctx.db, { identityId, kind: "cli" })).token;
}
const parse = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v);

describe("capability", () => {
  it("meta advertises identity.credentials.issue", async () => {
    const meta = await (await app.request("/v1/meta")).json();
    expect(meta.capabilities).toContain("identity.credentials.issue");
  });
});

describe("issuance", () => {
  it("issues a named service credential, returned once and never cached", async () => {
    const res = await issue();
    expect(res.status).toBe(201);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = await res.json();
    expect(Object.keys(body).sort()).toEqual(["expiresAt", "id", "kind", "maxUses", "name", "token"]);
    expect(body).toMatchObject({ kind: "service", name: "backup job", expiresAt: null, maxUses: null });
    expect(body.id).toMatch(/^crd_/);
    expect(body.token).toMatch(/^vlt_svc_/);
    expect(body.token).not.toBe(svcToken);
  });

  it("authenticates as the identity and appears in the listing under its name", async () => {
    const issued = await (await issue()).json();
    const mine = await get("/v1/me/credentials", issued.token);
    expect(mine.status).toBe(200);
    const current = (await mine.json()).items.find((c: { current: boolean }) => c.current);
    expect(current).toMatchObject({ id: issued.id, kind: "service", name: "backup job" });

    const items = await listCreds();
    expect(items).toHaveLength(2);
    expect(items.find((c) => c.id === issued.id)).toMatchObject({ kind: "service", name: "backup job", revokedAt: null });
    expect(JSON.stringify(items)).not.toContain(issued.token);
  });

  it("one identity, one credential per program: each revocable on its own", async () => {
    const backup = await (await issue({ name: "backup job" })).json();
    const metrics = await (await issue({ name: "metrics agent" })).json();
    expect((await del(`${CREDS(svcId)}/${backup.id}`)).status).toBe(204);
    expect((await get("/v1/organizations", backup.token)).status).toBe(401);
    expect((await get("/v1/organizations", metrics.token)).status).toBe(200);
    expect((await get("/v1/organizations", svcToken)).status).toBe(200);
    const revoked = (await listCreds()).find((c) => c.id === backup.id);
    expect(revoked?.revokedAt).not.toBeNull();
  });

  it("honours the TTL: expiresAt within the window, and no authentication past it", async () => {
    const before = Date.now();
    const issued = await (await issue({ name: "short", ttlSeconds: 600 })).json();
    const exp = new Date(issued.expiresAt).getTime();
    expect(exp).toBeGreaterThanOrEqual(before + 600_000);
    expect(exp).toBeLessThanOrEqual(Date.now() + 600_000);
    expect((await listCreds()).find((c) => c.id === issued.id)?.expiresAt).toBe(issued.expiresAt);
    expect((await get("/v1/organizations", issued.token)).status).toBe(200);
    await ctx.db.query("UPDATE credentials SET expires_at = now() - interval '1 second' WHERE id = $1", [issued.id]);
    expect((await get("/v1/organizations", issued.token)).status).toBe(401);
  });

  it("honours the use budget", async () => {
    const issued = await (await issue({ name: "one-shot", maxUses: 2 })).json();
    expect(issued.maxUses).toBe(2);
    expect((await get("/v1/organizations", issued.token)).status).toBe(200);
    expect((await get("/v1/organizations", issued.token)).status).toBe(200);
    expect((await get("/v1/organizations", issued.token)).status).toBe(401);
  });

  it("validates the body with the limits identity creation takes", async () => {
    for (const body of [
      {},
      { name: "" },
      { name: "x".repeat(201) },
      { name: "n", ttlSeconds: 0 },
      { name: "n", ttlSeconds: 315_360_001 },
      { name: "n", ttlSeconds: 1.5 },
      { name: "n", maxUses: 0 },
      { name: "n", maxUses: 1_000_001 },
    ]) {
      expect((await issue(body)).status, JSON.stringify(body)).toBe(422);
    }
    expect((await issue({ name: "x".repeat(200), ttlSeconds: 315_360_000, maxUses: 1_000_000 })).status).toBe(201);
    expect(await listCreds()).toHaveLength(2);
  });

  it("issues for workload and broker identities too", async () => {
    for (const kind of ["workload", "broker"]) {
      const identity = await create(`a ${kind}`, kind);
      const res = await issue({ name: "second" }, identity.id);
      expect(res.status, kind).toBe(201);
      expect((await res.json()).token).toMatch(/^vlt_svc_/);
    }
  });
});

describe("audit", () => {
  it("records credential.issued with the actor, the owning identity, and identifiers only", async () => {
    const issued = await (await issue({ name: "backup job", ttlSeconds: 600, maxUses: 5 })).json();
    const res = await ctx.db.query(
      "SELECT actor_identity_id, credential_id, organization_id, resource, metadata FROM audit_events WHERE event_type = 'credential.issued' AND credential_id = $1",
      [issued.id],
    );
    expect(res.rows).toHaveLength(1);
    const row = res.rows[0] as Record<string, unknown>;
    const org = (await (await get("/v1/organizations/acme")).json()) as { id: string };
    expect(row.actor_identity_id).toBe(adminId);
    expect(row.organization_id).toBe(org.id);
    expect(parse(row.resource)).toEqual({ identityId: svcId });
    expect(parse(row.metadata)).toEqual({ kind: "service", name: "backup job", expiresAt: issued.expiresAt, maxUses: 5 });
    expect(JSON.stringify(await ctx.db.query("SELECT * FROM audit_events"))).not.toContain(issued.token);

    // The organization's audit listing shows it.
    const listing = await (await get("/v1/organizations/acme/audit-events?eventType=credential.issued")).json();
    expect(listing.items.map((e: { credentialId: string }) => e.credentialId)).toContain(issued.id);
  });

  it("shows the credential issued at identity creation in the organization's audit listing", async () => {
    const listing = await (await get("/v1/organizations/acme/audit-events?eventType=credential.issued")).json();
    const issued = listing.items.filter((e: { resource: { identityId?: string } }) => e.resource.identityId === svcId);
    expect(issued).toHaveLength(1);
    expect(issued[0].actorIdentityId).toBe(adminId);
  });

  it("records no expiry and no budget as null", async () => {
    const issued = await (await issue()).json();
    const res = await ctx.db.query("SELECT metadata FROM audit_events WHERE credential_id = $1 AND event_type = 'credential.issued'", [issued.id]);
    expect(parse((res.rows[0] as { metadata: unknown }).metadata)).toEqual({ kind: "service", name: "backup job", expiresAt: null, maxUses: null });
  });
});

describe("authorization and existence hiding", () => {
  it("denies callers without identity.manage, identically for existing and unknown ids", async () => {
    expect((await issue({ name: "x" }, svcId, svcToken)).status).toBe(403);
    expect((await issue({ name: "x" }, "idn_nope", svcToken)).status).toBe(403);
    const member = await memberToken();
    expect((await issue({ name: "x" }, svcId, member)).status).toBe(403);
    expect((await issue({ name: "x" }, "idn_nope", member)).status).toBe(403);
    expect(await listCreds()).toHaveLength(1);
  });

  it("identity.manage granted to a machine identity is enough", async () => {
    const grant = await post("/v1/organizations/acme/grants", {
      subjectIdentityId: svcId,
      scope: { kind: "organization" },
      actions: ["identity.manage"],
    });
    expect(grant.status).toBe(201);
    const res = await issue({ name: "rotated" }, svcId, svcToken);
    expect(res.status).toBe(201);
    const rows = await ctx.db.query("SELECT actor_identity_id FROM audit_events WHERE credential_id = $1 AND event_type = 'credential.issued'", [(await res.json()).id]);
    expect((rows.rows[0] as { actor_identity_id: string }).actor_identity_id).toBe(svcId);
  });

  it("refuses retired identities; reactivation restores nothing until one is issued", async () => {
    expect((await post(`${IDS(svcId)}/retire`)).status).toBe(200);
    expect((await issue()).status).toBe(404);
    expect((await post(`${IDS(svcId)}/reactivate`)).status).toBe(200);
    expect((await get("/v1/organizations", svcToken)).status).toBe(401);
    const issued = await (await issue({ name: "after reactivation" })).json();
    expect((await get("/v1/organizations", issued.token)).status).toBe(200);
  });

  it("hides humans, ci and agent identities, and unknown ids", async () => {
    expect((await issue({ name: "x" }, adminId)).status).toBe(404);
    expect((await issue({ name: "x" }, (await create("pipeline", "ci")).id)).status).toBe(404);
    expect((await issue({ name: "x" }, (await create("coding agent", "agent")).id)).status).toBe(404);
    expect((await issue({ name: "x" }, "idn_nope")).status).toBe(404);
  });

  it("hides other organizations' identities", async () => {
    await post("/v1/organizations", { name: "Beta", slug: "beta" });
    const foreign = await create("beta-host", "service", "beta");
    // Through the wrong organization's path: not this organization's identity.
    expect((await post(CREDS(foreign.id, "acme"), { name: "x" })).status).toBe(404);
    // A machine identity acts only inside its own organization, whatever its Grants.
    await post("/v1/organizations/acme/grants", {
      subjectIdentityId: svcId,
      scope: { kind: "organization" },
      actions: ["identity.manage"],
    });
    expect((await post(CREDS(foreign.id, "beta"), { name: "x" }, svcToken)).status).toBe(404);
    const held = await ctx.db.query("SELECT count(*)::int AS n FROM credentials WHERE identity_id = $1", [foreign.id]);
    expect((held.rows[0] as { n: number }).n).toBe(1);
  });
});

describe("the Broker path is unchanged", () => {
  let brokerToken: string;
  let agentId: string;
  beforeEach(async () => {
    brokerToken = (await create("local broker", "broker")).credential!;
    agentId = (await create("coding agent", "agent")).id;
  });

  it("a Broker still mints agent-run credentials for an Agent Identity", async () => {
    const res = await post(CREDS(agentId), { ttlSeconds: 600, runId: "run_1" }, brokerToken);
    expect(res.status).toBe(201);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = await res.json();
    expect(Object.keys(body).sort()).toEqual(["expiresAt", "id", "token"]);
    expect(body.token).toMatch(/^vlt_agr_/);
  });

  it("a Broker cannot reach the service path, even with identity.manage", async () => {
    const brokerId = (await (await get("/v1/organizations/acme/identities")).json()).items.find(
      (i: { name: string }) => i.name === "local broker",
    ).id;
    await post("/v1/organizations/acme/grants", {
      subjectIdentityId: brokerId,
      scope: { kind: "organization" },
      actions: ["identity.manage"],
    });
    expect((await post(CREDS(svcId), { name: "x" }, brokerToken)).status).toBe(404);
    expect((await post(CREDS(svcId), { name: "x", ttlSeconds: 600 }, brokerToken)).status).toBe(404);
    // A service-path body for an agent: still an agent-run credential, the name ignored as before.
    const res = await post(CREDS(agentId), { name: "x", ttlSeconds: 600 }, brokerToken);
    expect(res.status).toBe(201);
    expect((await res.json()).token).toMatch(/^vlt_agr_/);
    expect((await post(CREDS(agentId), { name: "x" }, brokerToken)).status).toBe(422);
    expect(await listCreds()).toHaveLength(1);
  });

  it("identity.manage cannot mint agent-run credentials", async () => {
    expect((await post(CREDS(agentId), { ttlSeconds: 600 })).status).toBe(404);
    expect((await post(CREDS(agentId), { name: "x", ttlSeconds: 600 })).status).toBe(404);
  });
});

describe("SDK", () => {
  it("issueMachineCredential drives the route", async () => {
    const fetchImpl: typeof fetch = (input, init) =>
      app.request(input instanceof Request ? input : String(input).replace("http://varlatch", ""), init);
    const client = new VarlatchClient({ server: "http://varlatch", token: adminToken, fetch: fetchImpl });
    const issued = await client.issueMachineCredential("acme", svcId, { name: "sdk", ttlSeconds: 60, maxUses: 3 });
    expect(issued).toMatchObject({ kind: "service", name: "sdk", maxUses: 3 });
    expect(issued.expiresAt).not.toBeNull();
    const items = await client.listIdentityCredentials("acme", svcId);
    expect(items.items.map((c) => c.name)).toContain("sdk");
  });
});
