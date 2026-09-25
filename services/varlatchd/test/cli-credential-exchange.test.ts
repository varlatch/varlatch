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
 * CLI credential exchange (ADR-0024): the browser-handoff bearer is the
 * dashboard's 15-minute session token; the CLI trades it for a longer-lived
 * `cli` credential and the bearer is revoked in the same exchange.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminId: string;

beforeEach(async () => {
  const db = await testDb();
  await runMigrations(db);
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  adminId = (await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" })).identityId;
  app = buildApp(ctx);
});
afterEach(async () => {
  await ctx.close();
});

async function browserBearer(): Promise<string> {
  const { token } = await issueCredential(ctx.db, {
    identityId: adminId,
    kind: "browser",
    name: "dashboard session bearer",
    expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
  });
  return token;
}

function exchange(token: string, body: unknown = {}) {
  return app.request("/v1/me/credentials/cli", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("browser bearer -> CLI credential exchange", () => {
  it("mints a cli credential and revokes the presenting bearer", async () => {
    const bearer = await browserBearer();
    const res = await exchange(bearer);
    expect(res.status).toBe(201);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const issued = await res.json();
    expect(issued.token).toMatch(/^vlt_cli_/);
    // Default TTL is 12 hours.
    const exp = new Date(issued.expiresAt).getTime();
    expect(exp).toBeGreaterThan(Date.now() + 11 * 3600 * 1000);
    expect(exp).toBeLessThanOrEqual(Date.now() + 12 * 3600 * 1000);

    // The new credential authenticates; the handoff bearer is dead.
    const ok = await app.request("/v1/organizations", {
      headers: { Authorization: `Bearer ${issued.token}` },
    });
    expect(ok.status).toBe(200);
    const revoked = await exchange(bearer);
    expect(revoked.status).toBe(401);
  });

  it("honors an explicit ttlSeconds within the 24h cap", async () => {
    const res = await exchange(await browserBearer(), { ttlSeconds: 3600 });
    const issued = await res.json();
    expect(new Date(issued.expiresAt).getTime()).toBeLessThanOrEqual(Date.now() + 3601_000);

    const tooLong = await exchange(await browserBearer(), { ttlSeconds: 100_000 });
    expect(tooLong.status).toBe(422);
  });

  it("refuses non-browser credentials", async () => {
    const { token } = await issueCredential(ctx.db, { identityId: adminId, kind: "cli" });
    const res = await exchange(token);
    expect(res.status).toBe(403);
    expect((await res.json()).error.code).toBe("PERMISSION_DENIED");
  });

  it("audits issuance with the source credential", async () => {
    await exchange(await browserBearer());
    const res = await ctx.db.query(
      `SELECT count(*)::int AS n FROM audit_events
       WHERE event_type = 'credential.issued'
         AND metadata::jsonb->>'exchangedFromCredentialId' IS NOT NULL`,
    );
    expect((res.rows[0] as { n: number }).n).toBe(1);
  });
});
