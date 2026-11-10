// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CREDENTIAL_EXPIRES_HEADER, credentialExpiresNotice, issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * ADR-0054 Decision 8: every /v1 response to a request authenticated by a
 * credential that expires within 7 days carries Varlatch-Credential-Expires,
 * refusals and handler-built responses included. Credentials without an
 * expiry or expiring later get none, and neither does an unauthenticated
 * or refused request.
 */

const DAY = 24 * 60 * 60 * 1000;
let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let runnerId: string;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  adminToken = (await issueCredential(ctx.db, { identityId: consumed.identityId, kind: "cli" })).token;
  app = buildApp(ctx);
  expect((await call("POST", "/v1/organizations", adminToken, { name: "Acme", slug: "acme" })).status).toBe(201);
  const runner = await call("POST", "/v1/organizations/acme/identities", adminToken, { name: "runner", kind: "service" });
  expect(runner.status).toBe(201);
  runnerId = ((await runner.json()) as { id: string }).id;
});
afterEach(async () => {
  await ctx.close();
});

async function call(method: string, path: string, token?: string, body?: unknown): Promise<Response> {
  return app.request(path, {
    method,
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

async function credential(expiresInMs: number | null, kind: "service" | "agent-run" = "service"): Promise<{ token: string; expiresAt: string | undefined }> {
  const expiresAt = expiresInMs === null ? undefined : new Date(Date.now() + expiresInMs).toISOString();
  const { token } = await issueCredential(ctx.db, { identityId: runnerId, kind, ...(expiresAt ? { expiresAt } : {}) });
  return { token, expiresAt };
}

describe("Varlatch-Credential-Expires", () => {
  it("names the expiry of a credential that expires within 7 days, as an ISO 8601 UTC timestamp", async () => {
    const soon = await credential(3 * DAY);
    const res = await call("GET", "/v1/me", soon.token);
    expect(res.status).toBe(200);
    expect(res.headers.get(CREDENTIAL_EXPIRES_HEADER)).toBe(soon.expiresAt);
    expect(res.headers.get(CREDENTIAL_EXPIRES_HEADER)).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    // The same instant the credential reports about itself.
    const me = (await res.json()) as { credential: { expiresAt: string } };
    expect(me.credential.expiresAt).toBe(soon.expiresAt);
  });

  it("is absent for a credential without expiry or one that expires later", async () => {
    const never = await credential(null);
    const later = await credential(30 * DAY);
    for (const { token } of [never, later]) {
      const res = await call("GET", "/v1/me", token);
      expect(res.status).toBe(200);
      expect(res.headers.has(CREDENTIAL_EXPIRES_HEADER)).toBe(false);
    }
  });

  it("is absent from unauthenticated and refused requests", async () => {
    const meta = await call("GET", "/v1/meta");
    expect(meta.status).toBe(200);
    expect(meta.headers.has(CREDENTIAL_EXPIRES_HEADER)).toBe(false);
    const anonymous = await call("GET", "/v1/organizations");
    expect(anonymous.status).toBe(401);
    expect(anonymous.headers.has(CREDENTIAL_EXPIRES_HEADER)).toBe(false);
    const invalid = await call("GET", "/v1/organizations", "vlt_svc_not-a-real-credential");
    expect(invalid.status).toBe(401);
    expect(invalid.headers.has(CREDENTIAL_EXPIRES_HEADER)).toBe(false);
  });

  it("is on error responses to an authenticated credential", async () => {
    const soon = await credential(2 * DAY);
    // Refused by a handler: the runner has no Grant on this organization's projects.
    const missing = await call("GET", "/v1/organizations/acme/projects/nope/environments", soon.token);
    expect(missing.status).toBeGreaterThanOrEqual(400);
    expect(missing.headers.get(CREDENTIAL_EXPIRES_HEADER)).toBe(soon.expiresAt);
    // Refused by the bearer middleware itself, after authentication: an
    // agent-run credential cannot write.
    const agentRun = await credential(60 * 60 * 1000, "agent-run");
    const write = await call("POST", "/v1/organizations", agentRun.token, { name: "Other", slug: "other" });
    expect(write.status).toBe(403);
    expect(write.headers.get(CREDENTIAL_EXPIRES_HEADER)).toBe(agentRun.expiresAt);
  });

  it("is on responses a handler builds itself, such as the NDJSON audit export", async () => {
    const { token } = await issueCredential(ctx.db, {
      identityId: (await (await call("GET", "/v1/me", adminToken)).json() as { identity: { id: string } }).identity.id,
      kind: "cli",
      expiresAt: new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString(),
    });
    const res = await call("GET", "/v1/organizations/acme/audit-events/export", token);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("application/x-ndjson");
    expect(res.headers.has(CREDENTIAL_EXPIRES_HEADER)).toBe(true);
    await res.text();
  });

  it("uses an inclusive 7-day window", () => {
    const now = Date.parse("2026-11-10T12:00:00Z");
    expect(credentialExpiresNotice(null, now)).toBeNull();
    expect(credentialExpiresNotice("garbage", now)).toBeNull();
    expect(credentialExpiresNotice(new Date(now + 7 * DAY), now)).toBe("2026-11-17T12:00:00.000Z");
    expect(credentialExpiresNotice(new Date(now + 7 * DAY + 1), now)).toBeNull();
    expect(credentialExpiresNotice("2026-11-11T13:00:00+01:00", now)).toBe("2026-11-11T12:00:00.000Z");
    // Already past (expiry checked after authentication): still named.
    expect(credentialExpiresNotice(new Date(now - 1000), now)).toBe("2026-11-10T11:59:59.000Z");
  });
});
