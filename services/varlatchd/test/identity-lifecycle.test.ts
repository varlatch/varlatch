// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { runMigrations } from "../src/db/migrate.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
} from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { testDb } from "./helpers/pglite.js";

/**
 * Machine identity lifecycle (ADR-0034): credential enumeration/revocation
 * under identity.manage, retire/reactivate, rename, and throttled last-used
 * tracking. All routes are existence-hiding, consistent with the identity
 * routes they extend.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let adminId: string;
let svcId: string;
let svcToken: string;

const IDS = (id: string) => `/v1/organizations/acme/identities/${id}`;

beforeEach(async () => {
  const db = await testDb();
  await runMigrations(db);
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  adminId = consumed.identityId;
  const cred = await issueCredential(ctx.db, { identityId: adminId, kind: "cli" });
  adminToken = cred.token;
  app = buildApp(ctx);

  await post("/v1/organizations", { name: "Acme", slug: "acme" });
  const svc = await (
    await post("/v1/organizations/acme/identities", { name: "runner-01", kind: "service" })
  ).json();
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
async function patch(path: string, body: unknown, token = adminToken) {
  return app.request(path, { method: "PATCH", headers: auth(token), body: JSON.stringify(body) });
}
async function get(path: string, token = adminToken) {
  return app.request(path, { headers: auth(token) });
}
async function del(path: string, token = adminToken) {
  return app.request(path, { method: "DELETE", headers: auth(token) });
}

async function listCreds(id = svcId, token = adminToken) {
  const res = await get(`${IDS(id)}/credentials`, token);
  expect(res.status).toBe(200);
  return (await res.json()).items as {
    id: string;
    kind: string;
    name: string | null;
    createdAt: string;
    expiresAt: string | null;
    revokedAt: string | null;
    lastUsedAt: string | null;
  }[];
}

describe("capability", () => {
  it("meta advertises identity.lifecycle", async () => {
    const meta = await (await app.request("/v1/meta")).json();
    expect(meta.capabilities).toContain("identity.lifecycle");
  });
});

describe("credential listing", () => {
  it("returns metadata only, never token material", async () => {
    const items = await listCreds();
    expect(items).toHaveLength(1);
    expect(items[0]!.kind).toBe("service");
    expect(items[0]!.revokedAt).toBeNull();
    expect(JSON.stringify(items)).not.toContain("vlt_");
    expect(Object.keys(items[0]!).sort()).toEqual(
      ["createdAt", "expiresAt", "id", "kind", "lastUsedAt", "name", "revokedAt"],
    );
  });

  it("hides human identities and unknown ids", async () => {
    expect((await get(`${IDS(adminId)}/credentials`)).status).toBe(404);
    expect((await get(`${IDS("idn_nope")}/credentials`)).status).toBe(404);
  });

  it("requires identity.manage; authorization precedes identity lookup", async () => {
    // The deny is identical for existing and unknown ids: nothing leaks.
    expect((await get(`${IDS(svcId)}/credentials`, svcToken)).status).toBe(403);
    expect((await get(`${IDS("idn_nope")}/credentials`, svcToken)).status).toBe(403);
  });
});

describe("service credential revocation", () => {
  it("identity.manage revokes a service credential; it stops authenticating", async () => {
    const [cred] = await listCreds();
    expect((await get("/v1/organizations/acme/identities", svcToken)).status).not.toBe(401);
    const res = await del(`${IDS(svcId)}/credentials/${cred!.id}`);
    expect(res.status).toBe(204);
    expect((await listCreds())[0]!.revokedAt).not.toBeNull();
    expect((await get("/v1/organizations/acme/identities", svcToken)).status).toBe(401);
  });

  it("cli/browser credentials are not reachable through this route", async () => {
    // The admin is a human identity: machine loading hides it entirely.
    const res = await del(`${IDS(adminId)}/credentials/whatever`);
    expect(res.status).toBe(404);
  });

  it("a principal may burn the credential it is authenticated with", async () => {
    const grant = await post("/v1/organizations/acme/grants", {
      subjectIdentityId: svcId,
      scope: { kind: "organization" },
      actions: ["identity.manage", "identity.read"],
    });
    expect(grant.status).toBe(201);
    const [cred] = await listCreds();
    const res = await del(`${IDS(svcId)}/credentials/${cred!.id}`, svcToken);
    expect(res.status).toBe(204);
    // Every subsequent request fails.
    expect((await listCreds(svcId, svcToken).catch(() => null))).toBeNull();
  });

  it("records kind and owning identity on the audit event", async () => {
    const [cred] = await listCreds();
    await del(`${IDS(svcId)}/credentials/${cred!.id}`);
    const res = await ctx.db.query(
      "SELECT resource, metadata FROM audit_events WHERE event_type = 'credential.revoked' ORDER BY occurred_at DESC LIMIT 1",
    );
    const row = res.rows[0] as { resource: unknown; metadata: unknown };
    const resource = typeof row.resource === "string" ? JSON.parse(row.resource) : row.resource;
    const metadata = typeof row.metadata === "string" ? JSON.parse(row.metadata) : row.metadata;
    expect(resource.identityId).toBe(svcId);
    expect(metadata.kind).toBe("service");
  });
});

describe("retire and reactivate", () => {
  it("retire disables the identity and revokes every credential transactionally", async () => {
    const res = await post(`${IDS(svcId)}/retire`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ id: svcId, disabled: true });
    expect((await listCreds()).every((c) => c.revokedAt !== null)).toBe(true);
    expect((await get("/v1/organizations/acme/identities", svcToken)).status).toBe(401);
    const listing = await (await get("/v1/organizations/acme/identities")).json();
    const svc = listing.items.find((i: { id: string }) => i.id === svcId);
    expect(svc.disabled).toBe(true);
  });

  it("reactivate clears the flag only; credentials stay dead", async () => {
    await post(`${IDS(svcId)}/retire`);
    const res = await post(`${IDS(svcId)}/reactivate`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ id: svcId, disabled: false });
    // Zero working credentials until an admin deliberately issues one.
    expect((await get("/v1/organizations/acme/identities", svcToken)).status).toBe(401);
    expect((await listCreds()).every((c) => c.revokedAt !== null)).toBe(true);
  });

  it("machine kinds only; humans and unknowns collapse to 404", async () => {
    expect((await post(`${IDS(adminId)}/retire`)).status).toBe(404);
    expect((await post(`${IDS("idn_nope")}/retire`)).status).toBe(404);
    expect((await post(`${IDS(adminId)}/reactivate`)).status).toBe(404);
  });

  it("emits identity.retired with the revoked credential count", async () => {
    await post(`${IDS(svcId)}/retire`);
    const res = await ctx.db.query(
      "SELECT metadata FROM audit_events WHERE event_type = 'identity.retired'",
    );
    const row = res.rows[0] as { metadata: unknown };
    const metadata = typeof row.metadata === "string" ? JSON.parse(row.metadata) : row.metadata;
    expect(metadata.revokedCredentials).toBe(1);
    const reactivated = await post(`${IDS(svcId)}/reactivate`);
    expect(reactivated.status).toBe(200);
    const evt = await ctx.db.query(
      "SELECT id FROM audit_events WHERE event_type = 'identity.reactivated'",
    );
    expect(evt.rows).toHaveLength(1);
  });
});

describe("rename", () => {
  it("renames a machine identity and audits both names", async () => {
    const res = await patch(IDS(svcId), { name: "fleet-runner-01" });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ id: svcId, name: "fleet-runner-01" });
    const listing = await (await get("/v1/organizations/acme/identities")).json();
    const svc = listing.items.find((i: { id: string }) => i.id === svcId);
    expect(svc.name).toBe("fleet-runner-01");
    const evt = await ctx.db.query(
      "SELECT metadata FROM audit_events WHERE event_type = 'identity.renamed'",
    );
    const row = evt.rows[0] as { metadata: unknown };
    const metadata = typeof row.metadata === "string" ? JSON.parse(row.metadata) : row.metadata;
    expect(metadata.previousName).toBe("runner-01");
    expect(metadata.name).toBe("fleet-runner-01");
  });

  it("validates the name like creation and hides humans", async () => {
    expect((await patch(IDS(svcId), { name: "" })).status).toBe(422);
    expect((await patch(IDS(svcId), { name: "x".repeat(201) })).status).toBe(422);
    expect((await patch(IDS(adminId), { name: "nope" })).status).toBe(404);
  });
});

describe("last used", () => {
  it("successful verification records lastUsedAt and identity lastSeenAt", async () => {
    expect((await listCreds())[0]!.lastUsedAt).toBeNull();
    await get("/v1/organizations/acme/identities", svcToken);
    const [cred] = await listCreds();
    expect(cred!.lastUsedAt).not.toBeNull();
    const listing = await (await get("/v1/organizations/acme/identities")).json();
    const svc = listing.items.find((i: { id: string }) => i.id === svcId);
    expect(svc.lastSeenAt).not.toBeNull();
    // Throttled: a second request inside the 60s window keeps the timestamp.
    await get("/v1/organizations/acme/identities", svcToken);
    expect((await listCreds())[0]!.lastUsedAt).toBe(cred!.lastUsedAt);
  });
});
