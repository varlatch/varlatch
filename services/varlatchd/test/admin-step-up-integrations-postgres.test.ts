// SPDX-License-Identifier: AGPL-3.0-or-later
import { generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { withApproval, type Requester } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import { attachRegistration, discardRegistration, sweepExpiredRegistrations } from "../src/domain/githubapps.js";
import { getOrganization } from "../src/domain/orgs.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * GitHub App registration's attachment on real PostgreSQL (ADR-0054
 * amendment D): attachment, discard and the expiry sweep each lock the
 * registration row FOR UPDATE and check under it that it is still
 * pending; whichever commits first wins, and the other changes nothing.
 * Attachment consumes a real approval; when it loses, its consumption
 * rolls back with it and the approval stays unconsumed.
 *
 * A trigger with pg_sleep holds the first transaction at the point where
 * it holds the registration row, so the second one meets it there.
 */
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("GitHub App registration races on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let app: ReturnType<typeof buildApp>;
  let orgId: string;
  let owner: Person;
  const database = `varlatch_stepup_integrations_test_${process.pid}`;
  const PEM = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs1", format: "pem" }) as string;
  let nextAppId = 5_254_113;

  interface Person {
    id: string;
    cli: string;
    cliId: string;
    web: string;
    key: SoftAuthenticator;
  }

  const call = async (method: string, path: string, token: string, body?: unknown, headers: Record<string, string> = {}) => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null };
  };

  async function person(identityId: string): Promise<Person> {
    const cli = await issueCredential(db, { identityId, kind: "cli", name: "test cli" });
    const key = await registerSoftPasskey(db, identityId, { ...RP, trust: "trusted" });
    const sessionId = `session-${identityId}`;
    await db.query(
      `INSERT INTO "session" (id, "expiresAt", token, "userId")
       SELECT $1, now() + interval '1 day', $1, better_auth_user_id FROM auth_user_links WHERE identity_id = $2`,
      [sessionId, identityId],
    );
    const web = await issueCredential(db, { identityId, kind: "browser", expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(), authSessionId: sessionId });
    return { id: identityId, cli: cli.token, cliId: cli.credentialId, web: web.token, key };
  }
  const requester = (p: Person): Requester => ({ identityId: p.id, identityKind: "human", credentialId: p.cliId, credentialKind: "cli" });

  /** A converted registration waiting for its approval, approved: its id and the approval's. */
  async function pendingApproved(): Promise<{ registrationId: string; approvalId: string }> {
    const started = await call("POST", "/v1/organizations/acme/github-app/registrations", owner.cli, { account: { login: "acme-gh", type: "organization" } });
    expect(started.status, JSON.stringify(started.body)).toBe(201);
    const asked = await call("POST", "/v1/organizations/acme/github-app/registrations/complete", owner.cli, { state: started.body.state, code: `code-${started.body.id}` });
    expect(asked.body.error.code, JSON.stringify(asked.body)).toBe("STEP_UP_REQUIRED");
    const approvalId = asked.body.error.details.approval.id as string;
    const options = await call("POST", `/v1/me/approvals/${approvalId}/options`, owner.web);
    const done = await call("POST", `/v1/me/approvals/${approvalId}/approve`, owner.web, {
      assertion: owner.key.assert(options.body.publicKey.challenge, { userVerified: true }),
    });
    expect(done.status, JSON.stringify(done.body)).toBe(200);
    return { registrationId: started.body.id as string, approvalId };
  }
  const attach = async (registrationId: string, approvalId: string) =>
    withApproval(ctx, { requester: requester(owner), approvalId, publicUrl: PUBLIC_URL }, async (gate) =>
      attachRegistration(ctx, gate, await getOrganization(ctx, "acme"), registrationId));
  const state = async (registrationId: string) =>
    (await db.query("SELECT end_reason, pending_key_envelope IS NOT NULL AS has_key FROM github_app_registrations WHERE id = $1", [registrationId])).rows[0];
  const consumedAt = async (id: string) => (await db.query("SELECT consumed_at FROM approval_intents WHERE id = $1", [id])).rows[0].consumed_at;
  const eventCount = async (type: string) => (await db.query("SELECT count(*)::int AS n FROM audit_events WHERE event_type = $1", [type])).rows[0].n as number;
  const appCount = async () => (await db.query("SELECT count(*)::int AS n FROM github_apps")).rows[0].n as number;
  /** Pending material is never updated by Varlatch: a test moves its expiry with the guard off. */
  async function expireAt(registrationId: string, sql: string) {
    await db.query("ALTER TABLE github_app_registrations DISABLE TRIGGER github_app_registrations_pending_once");
    await db.query(`UPDATE github_app_registrations SET pending_expires_at = ${sql} WHERE id = $1`, [registrationId]);
    await db.query("ALTER TABLE github_app_registrations ENABLE TRIGGER github_app_registrations_pending_once");
  }
  /** Hold the transaction that fires it for `seconds`, at that point. */
  async function slowTrigger(name: string, table: string, timing: string, seconds: number, when = "true") {
    await db.query(`CREATE FUNCTION ${name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF ${when} THEN PERFORM pg_sleep(${seconds}); END IF; RETURN NEW; END $$`);
    await db.query(`CREATE TRIGGER ${name} ${timing} ON ${table} FOR EACH ROW EXECUTE FUNCTION ${name}()`);
  }
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  beforeEach(async () => {
    admin = createPgQuerier(url!);
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${database}`);
    const target = new URL(url!);
    target.pathname = `/${database}`;
    db = createPgQuerier(target.toString());
    const connection = await db.connect();
    try { await runMigrations(connection); } finally { connection.release(); }
    ctx = { db, rootKek: Buffer.alloc(32, 48) };
    await ensureInstallation(ctx);
    owner = await person((await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" })).identityId);
    // GitHub's manifest conversion: each code hands over a new App.
    const syncFetch = (async (input: RequestInfo | URL) => {
      const id = nextAppId++;
      void input;
      return Response.json({ id, slug: `varlatch-acme-${id}`, client_id: `Iv23li${id}`, pem: PEM, owner: { login: "acme-gh", id: 1009, type: "Organization" } }, { status: 201 });
    }) as typeof fetch;
    app = buildApp(ctx, { publicUrl: PUBLIC_URL, clientAddress: () => "203.0.113.7", syncFetch });
    orgId = (await call("POST", "/v1/organizations", owner.cli, { name: "Acme", slug: "acme" })).body.id;
    await db.query(
      `INSERT INTO security_controls (organization_id, control, mode, config, version, changed_by, changed_at)
       VALUES ($1, 'admin-step-up', 'enforce', NULL, 1, $2, now())`,
      [orgId, owner.id],
    );
  });
  afterEach(async () => {
    await db?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
      await admin.end();
    }
  });

  it("attachment holding the row, then discard: the attachment wins, the discard changes nothing", async () => {
    const { registrationId, approvalId } = await pendingApproved();
    await slowTrigger("slow_app_insert", "github_apps", "BEFORE INSERT", 1.5);
    const attaching = attach(registrationId, approvalId);
    await sleep(500);
    const discarding = discardRegistration(ctx, await getOrganization(ctx, "acme"), registrationId, owner.id);
    expect(await attaching).toMatchObject({ outcome: "registered" });
    expect(await discarding).toMatchObject({ discarded: false });
    expect(await state(registrationId)).toEqual({ end_reason: "attached", has_key: false });
    expect(await consumedAt(approvalId)).not.toBeNull();
    expect(await appCount()).toBe(1);
    expect(await eventCount("sync.github_app_registration_abandoned")).toBe(0);
  });

  it("discard holding the row, then the attachment: the discard wins, the attachment is refused and its approval stays unconsumed", async () => {
    const { registrationId, approvalId } = await pendingApproved();
    await slowTrigger("slow_discard", "github_app_registrations", "BEFORE UPDATE", 1.5, "NEW.end_reason = 'discarded'");
    const discarding = discardRegistration(ctx, await getOrganization(ctx, "acme"), registrationId, owner.id);
    await sleep(500);
    const attaching = attach(registrationId, approvalId);
    expect(await discarding).toMatchObject({ discarded: true });
    expect(await attaching).toMatchObject({ outcome: "refused", reason: "registration-ended" });
    expect(await state(registrationId)).toEqual({ end_reason: "discarded", has_key: false });
    expect(await consumedAt(approvalId)).toBeNull();
    expect(await appCount()).toBe(0);
    expect(await eventCount("sync.github_app_registration_abandoned")).toBe(1);
  });

  it("an attachment that holds the row before the expiry attaches; the sweep skips it and finds nothing after", async () => {
    const { registrationId, approvalId } = await pendingApproved();
    await expireAt(registrationId, "clock_timestamp() + interval '1 second'");
    await slowTrigger("slow_app_insert", "github_apps", "BEFORE INSERT", 2.5);
    const attaching = attach(registrationId, approvalId);
    await sleep(1_600);
    // Expired by the clock now, but locked: the sweep skips it without waiting.
    const started = Date.now();
    expect(await sweepExpiredRegistrations(ctx)).toBe(0);
    expect(Date.now() - started).toBeLessThan(1_000);
    expect(await attaching).toMatchObject({ outcome: "registered" });
    expect(await sweepExpiredRegistrations(ctx)).toBe(0);
    expect(await state(registrationId)).toEqual({ end_reason: "attached", has_key: false });
    expect(await eventCount("sync.github_app_registration_abandoned")).toBe(0);
  });

  it("the sweep holding an expired row, then the attachment: the sweep wins, the attachment is refused as expired and its approval stays unconsumed", async () => {
    const { registrationId, approvalId } = await pendingApproved();
    await expireAt(registrationId, "converted_at + interval '1 millisecond'");
    await slowTrigger("slow_sweep", "github_app_registrations", "BEFORE UPDATE", 1.5, "NEW.end_reason = 'expired'");
    const sweeping = sweepExpiredRegistrations(ctx);
    await sleep(500);
    const attaching = attach(registrationId, approvalId);
    expect(await sweeping).toBe(1);
    // Refused before consuming anything; its cleanup waits for the sweep's row and finds it ended.
    expect(await attaching).toMatchObject({ outcome: "refused", reason: "expired" });
    expect(await state(registrationId)).toEqual({ end_reason: "expired", has_key: false });
    expect(await consumedAt(approvalId)).toBeNull();
    expect(await appCount()).toBe(0);
    expect(await eventCount("sync.github_app_registration_abandoned")).toBe(1);
  });
});
