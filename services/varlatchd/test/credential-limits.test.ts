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
 * Optional credential lifetime limits: a service credential may carry a
 * wall-clock TTL and/or a use budget. Both are optional; absent means
 * today's behavior (revocation only). A spent or expired credential
 * collapses to INVALID_CREDENTIAL like every other auth failure.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;

beforeEach(async () => {
  const db = await testDb();
  await runMigrations(db);
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  const cred = await issueCredential(ctx.db, { identityId: consumed.identityId, kind: "cli" });
  adminToken = cred.token;
  app = buildApp(ctx);
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

async function createService(extra: Record<string, unknown> = {}) {
  const res = await post("/v1/organizations/acme/identities", {
    name: "ci deployer",
    kind: "service",
    ...extra,
  });
  expect(res.status).toBe(201);
  return res.json();
}

describe("credential TTL", () => {
  it("defaults to no expiry", async () => {
    const created = await createService();
    expect(created.credentialExpiresAt).toBeNull();
  });

  it("issues with an expiry and stops authenticating past it", async () => {
    const created = await createService({ credentialTtlSeconds: 600 });
    const exp = new Date(created.credentialExpiresAt).getTime();
    expect(exp).toBeGreaterThan(Date.now());
    expect(exp).toBeLessThanOrEqual(Date.now() + 601_000);

    expect((await get("/v1/organizations", created.credential)).status).toBe(200);
    await ctx.db.query(
      "UPDATE credentials SET expires_at = now() - interval '1 second' WHERE token_hash IS NOT NULL AND kind = 'service'",
    );
    const res = await get("/v1/organizations", created.credential);
    expect(res.status).toBe(401);
    expect((await res.json()).error.code).toBe("INVALID_CREDENTIAL");
  });

  it("rejects invalid TTLs", async () => {
    const res = await post("/v1/organizations/acme/identities", {
      name: "svc",
      kind: "service",
      credentialTtlSeconds: 0,
    });
    expect(res.status).toBe(422);
  });
});

describe("credential use budget", () => {
  it("a one-shot token authenticates exactly once", async () => {
    const created = await createService({ credentialMaxUses: 1 });
    expect((await get("/v1/organizations", created.credential)).status).toBe(200);
    const second = await get("/v1/organizations", created.credential);
    expect(second.status).toBe(401);
    expect((await second.json()).error.code).toBe("INVALID_CREDENTIAL");
  });

  it("a budget of N allows exactly N requests", async () => {
    const created = await createService({ credentialMaxUses: 3 });
    for (let i = 0; i < 3; i++) {
      expect((await get("/v1/organizations", created.credential)).status).toBe(200);
    }
    expect((await get("/v1/organizations", created.credential)).status).toBe(401);
  });

  it("audits exhaustion as an authentication failure", async () => {
    const created = await createService({ credentialMaxUses: 1 });
    await get("/v1/organizations", created.credential);
    await get("/v1/organizations", created.credential);
    const res = await ctx.db.query(
      "SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'authentication.failed' AND metadata::jsonb->>'reason' = 'exhausted'",
    );
    expect((res.rows[0] as { n: number }).n).toBe(1);
  });

  it("unbudgeted credentials never advance a use counter", async () => {
    const created = await createService();
    await get("/v1/organizations", created.credential);
    await get("/v1/organizations", created.credential);
    const res = await ctx.db.query(
      "SELECT use_count, max_uses FROM credentials WHERE kind = 'service'",
    );
    expect(res.rows[0]).toMatchObject({ use_count: 0, max_uses: null });
  });

  it("self-listing shows the budget and consumption", async () => {
    const created = await createService({ credentialMaxUses: 5 });
    await get("/v1/organizations", created.credential);
    const mine = await (await get("/v1/me/credentials", created.credential)).json();
    const row = mine.items.find((i: { kind: string }) => i.kind === "service");
    // Two uses so far: the request above and the self-listing itself.
    expect(row.maxUses).toBe(5);
    expect(row.useCount).toBe(2);
  });
});
