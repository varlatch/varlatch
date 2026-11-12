// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Context } from "hono";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import { getOrganization } from "../src/domain/orgs.js";
import { inSnapshot } from "../src/domain/retrieval.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { buildApp } from "../src/http/app.js";
import { organizationEntryChecks } from "../src/http/organization.js";
import { entryBlockDenial, type Principal } from "../src/http/support.js";
import { RP } from "./helpers/device-sign-in.js";
import { registerSoftPasskey } from "./helpers/soft-authenticator.js";

/**
 * passkey-verification at the retrieval's snapshot boundary, on real
 * PostgreSQL (ADR-0054 Decisions 2 and 7): the entry check reads the mode
 * in the request's snapshot, so a retrieval whose snapshot began before
 * the control was enforced finishes under the old mode, and the next one
 * is refused. And requests racing the change each get one of the two
 * answers, never anything else; once the change committed, every one is
 * refused.
 */
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("passkey-verification on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let app: ReturnType<typeof buildApp>;
  let adminId: string;
  let cli: string;
  let verified: string;
  const database = `varlatch_passkeyverification_test_${process.pid}`;
  const E = "/v1/organizations/acme/projects/api/environments/production";

  const call = async (method: string, path: string, token: string, body?: unknown) => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null };
  };

  beforeEach(async () => {
    admin = createPgQuerier(url!);
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${database}`);
    const target = new URL(url!);
    target.pathname = `/${database}`;
    db = createPgQuerier(target.toString());
    const connection = await db.connect();
    try { await runMigrations(connection); } finally { connection.release(); }
    ctx = { db, rootKek: Buffer.alloc(32, 47) };
    await ensureInstallation(ctx);
    adminId = (await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" })).identityId;
    cli = (await issueCredential(db, { identityId: adminId, kind: "cli" })).token;
    // A dashboard sign-in with a trusted passkey that verified the admin.
    const key = await registerSoftPasskey(db, adminId, { ...RP, trust: "trusted" });
    await db.query(
      `INSERT INTO "session" (id, "expiresAt", token, "userId")
       SELECT 'ses_verified', now() + interval '1 day', 'ses_verified', better_auth_user_id FROM auth_user_links WHERE identity_id = $1`,
      [adminId],
    );
    await db.query("INSERT INTO auth_session_evidence (session_id, ceremony, user_verified, passkey_id) VALUES ('ses_verified', 'sign-in', true, $1)", [key.passkeyId]);
    verified = (await issueCredential(db, { identityId: adminId, kind: "browser", expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(), authSessionId: "ses_verified" })).token;
    app = buildApp(ctx);
    for (const [path, body] of [
      ["/v1/organizations", { name: "Acme", slug: "acme" }],
      ["/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "git" }],
      ["/v1/organizations/acme/projects/api/environments", { name: "production", tier: "production" }],
    ] as const) expect((await call("POST", path, cli, body)).status).toBe(201);
    expect((await call("PUT", `${E}/values/DB_PASS`, cli, { value: "hunter2-hunter2" })).status).toBe(200);
  });

  afterEach(async () => {
    await accessCountsSettled();
    await db.end();
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.end();
  });

  const enforce = async () => {
    const res = await call("PATCH", "/v1/organizations/acme/security/controls/passkey-verification", verified, { mode: "enforce", expectedVersion: 0 });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
  };

  /** The admin's CLI principal, as the bearer middleware would set it. */
  const principal = async (): Promise<Principal> => {
    const identity = (await db.query("SELECT * FROM identities WHERE id = $1", [adminId])).rows[0] as Principal["identity"];
    const credentialId = ((await db.query("SELECT id FROM credentials WHERE identity_id = $1 AND kind = 'cli'", [adminId])).rows[0] as { id: string }).id;
    return { identity, credentialId, credentialKind: "cli" };
  };

  /** A request context as far as the entry check uses it. */
  const requestContext = () => {
    const vars = new Map<string, unknown>([["requestId", "req_test"]]);
    return { get: (k: string) => vars.get(k), set: (k: string, v: unknown) => void vars.set(k, v), req: { param: () => "acme" } } as unknown as Context;
  };

  it("a retrieval's snapshot that began before the control was enforced finishes under the old mode; the next is refused", async () => {
    const p = await principal();
    const decided = await inSnapshot(ctx, async (sctx) => {
      // The snapshot is taken by its first read.
      const org = await getOrganization(sctx, "acme");
      // The control is enforced and committed while the snapshot is open.
      await enforce();
      const c = requestContext();
      await organizationEntryChecks(sctx, c, p, org);
      return entryBlockDenial(c, p, { organizationId: org.id }, "config.metadata.read");
    });
    expect(decided).toBeNull();
    // A snapshot that begins after the change sees it.
    const after = await inSnapshot(ctx, async (sctx) => {
      const org = await getOrganization(sctx, "acme");
      const c = requestContext();
      await organizationEntryChecks(sctx, c, p, org);
      return entryBlockDenial(c, p, { organizationId: org.id }, "config.metadata.read");
    });
    expect(after?.error.code).toBe("PASSKEY_VERIFICATION_REQUIRED");
    const refused = await call("POST", `${E}/retrievals`, cli, { mode: "strict" });
    expect(refused.status).toBe(403);
    expect(refused.body.error.code).toBe("PASSKEY_VERIFICATION_REQUIRED");
    expect(JSON.stringify(refused.body)).not.toContain("hunter2");
    expect((await call("POST", `${E}/retrievals`, verified, { mode: "strict" })).status).toBe(200);
  }, 30_000);

  it("requests racing the change get the old answer or the refusal, and every request after it is refused", async () => {
    const racing = Array.from({ length: 12 }, (_, i) =>
      i % 2 === 0 ? call("POST", `${E}/retrievals`, cli, { mode: "strict" }) : call("GET", "/v1/organizations/acme/projects", cli),
    );
    const [changed, ...answers] = await Promise.all([enforce(), ...racing]);
    void changed;
    for (const a of answers) {
      expect(a.status === 200 || (a.status === 403 && a.body.error.code === "PASSKEY_VERIFICATION_REQUIRED"), JSON.stringify(a.body)).toBe(true);
    }
    const later = await Promise.all(Array.from({ length: 6 }, () => call("POST", `${E}/retrievals`, cli, { mode: "strict" })));
    expect(later.map((a) => a.body.error?.code)).toEqual(Array(6).fill("PASSKEY_VERIFICATION_REQUIRED"));
    // No count while enforcing.
    await accessCountsSettled();
    expect(((await db.query("SELECT count(*)::int AS n FROM security_control_counters")).rows[0] as { n: number }).n).toBe(0);
  }, 30_000);
});
