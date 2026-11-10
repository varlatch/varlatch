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
 * machine credential (kind service) that expires within 7 days carries
 * Varlatch-Credential-Expires, refusals and handler-built responses
 * included, whatever the credential's total lifetime. Credentials without an
 * expiry or expiring later get none, nor do human (cli, browser),
 * OIDC-exchanged and agent-run credentials, renewed by design, nor an
 * unauthenticated or refused request.
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

type Kind = "service" | "agent-run" | "cli" | "browser" | "oidc";

/**
 * A credential of the runner (or `identityId`) that expires in `leftMs`,
 * issued `lifetimeMs` before its expiry; no expiry when `leftMs` is null.
 */
async function credential(
  leftMs: number | null,
  lifetimeMs = 30 * DAY,
  kind: Kind = "service",
  identityId = runnerId,
): Promise<{ token: string; expiresAt: string | undefined }> {
  const expiresAt = leftMs === null ? undefined : new Date(Date.now() + leftMs).toISOString();
  const { token, credentialId } = await issueCredential(ctx.db, { identityId, kind, ...(expiresAt ? { expiresAt } : {}) });
  if (expiresAt) {
    await ctx.db.query("UPDATE credentials SET created_at = $2 WHERE id = $1", [
      credentialId,
      new Date(Date.parse(expiresAt) - lifetimeMs).toISOString(),
    ]);
  }
  return { token, expiresAt };
}

async function header(token: string): Promise<string | null> {
  const res = await call("GET", "/v1/me", token);
  expect(res.status).toBe(200);
  return res.headers.get(CREDENTIAL_EXPIRES_HEADER);
}

async function adminId(): Promise<string> {
  return ((await (await call("GET", "/v1/me", adminToken)).json()) as { identity: { id: string } }).identity.id;
}

describe("Varlatch-Credential-Expires", () => {
  it("names the expiry of a 30-day machine credential with 3 days left, as an ISO 8601 UTC timestamp", async () => {
    const soon = await credential(3 * DAY, 30 * DAY);
    const res = await call("GET", "/v1/me", soon.token);
    expect(res.status).toBe(200);
    expect(res.headers.get(CREDENTIAL_EXPIRES_HEADER)).toBe(soon.expiresAt);
    expect(res.headers.get(CREDENTIAL_EXPIRES_HEADER)).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    // The same instant the credential reports about itself.
    const me = (await res.json()) as { credential: { expiresAt: string } };
    expect(me.credential.expiresAt).toBe(soon.expiresAt);
  });

  it("names it for a short-lived machine credential too: nothing renews it but a person", async () => {
    const fiveDays = await credential(2 * DAY, 5 * DAY);
    expect(await header(fiveDays.token)).toBe(fiveDays.expiresAt);
    const oneDay = await credential(60 * 60 * 1000, DAY);
    expect(await header(oneDay.token)).toBe(oneDay.expiresAt);
  });

  it("is absent for a machine credential without expiry or one that expires later", async () => {
    expect(await header((await credential(null)).token)).toBeNull();
    expect(await header((await credential(30 * DAY, 365 * DAY)).token)).toBeNull();
    expect(await header((await credential(8 * DAY, 30 * DAY)).token)).toBeNull();
  });

  it("is absent for human, OIDC-exchanged and agent-run credentials, however close their expiry", async () => {
    const admin = await adminId();
    // A person's CLI sign-in and dashboard session.
    expect(await header((await credential(2 * 60 * 60 * 1000, DAY, "cli", admin)).token)).toBeNull();
    expect(await header((await credential(10 * 60 * 1000, 15 * 60 * 1000, "browser", admin)).token)).toBeNull();
    // A machine's OIDC exchange and an agent run, even issued for longer.
    expect(await header((await credential(10 * 60 * 1000, 60 * 60 * 1000, "oidc")).token)).toBeNull();
    expect(await header((await credential(2 * DAY, 30 * DAY, "agent-run")).token)).toBeNull();
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

  it("is on error responses to an authenticated machine credential", async () => {
    const soon = await credential(2 * DAY);
    // Refused by a handler: the runner has no Grant on this organization's projects.
    const missing = await call("GET", "/v1/organizations/acme/projects/nope/environments", soon.token);
    expect(missing.status).toBeGreaterThanOrEqual(400);
    expect(missing.headers.get(CREDENTIAL_EXPIRES_HEADER)).toBe(soon.expiresAt);
    // Refused by the bearer middleware after authentication (an agent-run
    // credential cannot write): no header, as for any agent-run credential.
    const agentRun = await credential(60 * 60 * 1000, 2 * 60 * 60 * 1000, "agent-run");
    const write = await call("POST", "/v1/organizations", agentRun.token, { name: "Other", slug: "other" });
    expect(write.status).toBe(403);
    expect(write.headers.has(CREDENTIAL_EXPIRES_HEADER)).toBe(false);
  });

  it("is on responses a handler builds itself, such as the NDJSON audit export", async () => {
    const grant = await call("POST", "/v1/organizations/acme/grants", adminToken, {
      subjectIdentityId: runnerId,
      scope: { kind: "organization" },
      actions: ["audit.read"],
    });
    expect(grant.status).toBe(201);
    const { token, expiresAt } = await credential(3 * DAY);
    const res = await call("GET", "/v1/organizations/acme/audit-events/export", token);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("application/x-ndjson");
    expect(res.headers.get(CREDENTIAL_EXPIRES_HEADER)).toBe(expiresAt);
    await res.text();
  });

  it("applies to kind service of a non-human identity, within an inclusive 7-day window", () => {
    const now = Date.parse("2026-11-10T12:00:00Z");
    const svc = (expires_at: string | Date | null) => ({ kind: "service" as const, expires_at });
    expect(credentialExpiresNotice(svc(null), "service", now)).toBeNull();
    expect(credentialExpiresNotice(svc("garbage"), "service", now)).toBeNull();
    expect(credentialExpiresNotice(svc(new Date(now + 7 * DAY)), "workload", now)).toBe("2026-11-17T12:00:00.000Z");
    expect(credentialExpiresNotice(svc(new Date(now + 7 * DAY + 1)), "service", now)).toBeNull();
    expect(credentialExpiresNotice(svc("2026-11-11T13:00:00+01:00"), "broker", now)).toBe("2026-11-11T12:00:00.000Z");
    // Already past (expiry checked at authentication, a race): still named.
    expect(credentialExpiresNotice(svc(new Date(now - 1000)), "service", now)).toBe("2026-11-10T11:59:59.000Z");
    // Never for a human identity, nor for kinds renewed by design.
    expect(credentialExpiresNotice(svc(new Date(now + DAY)), "human", now)).toBeNull();
    for (const kind of ["cli", "browser", "oidc", "agent-run"] as const) {
      expect(credentialExpiresNotice({ kind, expires_at: new Date(now + DAY) }, "service", now)).toBeNull();
    }
  });
});
