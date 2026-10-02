// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { PUBLIC_URL, approvingHuman, deviceClient } from "./helpers/device-sign-in.js";

/**
 * Device sign-in races on real PostgreSQL (PGlite runs one connection, so
 * transactions never interleave there). Each race fires many requests at
 * once through the pool; the expectations count outcomes and rows.
 */
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("device sign-in on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let app: ReturnType<typeof buildApp>;
  let adminId: string;
  let peer = "203.0.113.7";
  const client = deviceClient(() => app);
  const database = `varlatch_dsi_test_${process.pid}`;
  const rows = async (sql: string, params: unknown[] = []) => (await db.query(sql, params)).rows as any[];
  const deviceCredentials = () => rows("SELECT id FROM credentials WHERE kind = 'cli'");

  beforeEach(async () => {
    admin = createPgQuerier(url!);
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${database}`);
    const target = new URL(url!);
    target.pathname = `/${database}`;
    db = createPgQuerier(target.toString());
    const connection = await db.connect();
    try { await runMigrations(connection); } finally { connection.release(); }
    ctx = { db, rootKek: Buffer.alloc(32, 23) };
    await ensureInstallation(ctx);
    adminId = (await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, {})).identityId;
    peer = "203.0.113.7";
    app = buildApp(ctx, { publicUrl: PUBLIC_URL, clientAddress: () => peer });
  });
  afterEach(async () => {
    await db?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
      await admin.end();
    }
  });

  it("two (and eight) concurrent collectors get exactly one credential between them", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const started = (await client.start()).body;
    expect((await client.approve(human.token, started.userCode, human.passkey)).status).toBe(200);
    const results = await Promise.all(Array.from({ length: 8 }, () => client.poll(started.deviceCode)));
    const issued = results.filter((r) => r.status === 201);
    expect(issued).toHaveLength(1);
    const consumed = results.filter((r) => r.status === 410);
    expect(consumed).toHaveLength(7);
    for (const r of consumed) expect(r.body.error).toMatchObject({ code: "CONSUMED", details: { credentialId: issued[0]!.body.id } });
    expect(await deviceCredentials()).toEqual([{ id: issued[0]!.body.id }]);
    expect(await rows("SELECT id FROM audit_events WHERE event_type = 'authentication.device_collected'")).toHaveLength(1);
  });

  it("a lost collection response: the retry gets CONSUMED with the credential id, and no second credential", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const started = (await client.start()).body;
    await client.approve(human.token, started.userCode, human.passkey);
    const lost = await client.poll(started.deviceCode); // the response never reaches the CLI
    const retry = await client.poll(started.deviceCode);
    expect(retry.status).toBe(410);
    expect(retry.body.error).toMatchObject({ code: "CONSUMED", details: { credentialId: lost.body.id } });
    expect(JSON.stringify(retry.body)).not.toContain(lost.body.token);
    expect(await deviceCredentials()).toHaveLength(1);
  });

  it("concurrent approvals and denials leave exactly one decision", async () => {
    for (let round = 0; round < 5; round++) {
      const human = await approvingHuman(ctx, `Decider ${round}`);
      const started = (await client.start()).body;
      // Each approval needs its own challenge: look up first, from separate sessions.
      const approvers = await Promise.all(Array.from({ length: 3 }, async (_, i) => {
        const token = await human.session(`s-${round}-${i}`);
        const { challenge } = (await client.lookup(token, started.userCode)).body.approval.publicKey;
        return { token, assertion: human.passkey.assert(challenge) };
      }));
      const results = await Promise.all([
        ...approvers.map((a) => client.decide(a.token, started.userCode, "approve", a.assertion)),
        ...Array.from({ length: 3 }, () => client.decide(human.token, started.userCode, "deny")),
      ]);
      const decided = results.filter((r) => r.status === 200);
      expect(decided).toHaveLength(1);
      // The losers find the sign-in decided: it is no longer pending (409), or its code no longer matches (404).
      for (const r of results.filter((r) => r.status !== 200)) expect([404, 409]).toContain(r.status);
      const [row] = await rows("SELECT status FROM device_sign_ins WHERE user_code = $1", [started.userCode.replace("-", "")]);
      expect(row.status).toBe(decided[0]!.body.decision);
      const events = await rows(
        `SELECT event_type FROM audit_events WHERE event_type IN ('authentication.device_approved', 'authentication.device_denied')
         AND resource->>'deviceSignInId' = (SELECT id FROM device_sign_ins WHERE user_code = $1)`,
        [started.userCode.replace("-", "")],
      );
      expect(events).toHaveLength(1);
    }
  });

  it("an approval assertion replayed concurrently approves once; replayed later it is refused", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const started = (await client.start()).body;
    const { challenge } = (await client.lookup(human.token, started.userCode)).body.approval.publicKey;
    const assertion = human.passkey.assert(challenge);
    const results = await Promise.all(Array.from({ length: 8 }, () => client.decide(human.token, started.userCode, "approve", assertion)));
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    for (const r of results.filter((r) => r.status !== 200)) expect([403, 404, 409]).toContain(r.status);
    // Replayed against a new sign-in of the same human: the challenge belongs to the old one.
    const next = (await client.start()).body;
    await client.lookup(human.token, next.userCode);
    expect((await client.decide(human.token, next.userCode, "approve", assertion)).status).toBe(403);
    expect((await rows("SELECT status FROM device_sign_ins ORDER BY created_at")).map((r) => r.status)).toEqual(["approved", "pending"]);
  });

  it("refuses an assertion bound to another sign-in, identity, or session", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const other = await approvingHuman(ctx, "Other");
    const first = (await client.start()).body;
    const second = (await client.start()).body;
    const forFirst = (await client.lookup(human.token, first.userCode)).body.approval.publicKey.challenge;
    await client.lookup(human.token, second.userCode);
    expect((await client.decide(human.token, second.userCode, "approve", human.passkey.assert(forFirst))).status).toBe(403);
    const forOther = (await client.lookup(other.token, second.userCode)).body.approval.publicKey.challenge;
    expect((await client.decide(human.token, second.userCode, "approve", human.passkey.assert(forOther))).status).toBe(403);
    const forSession = (await client.lookup(human.token, second.userCode)).body.approval.publicKey.challenge;
    expect((await client.decide(await human.session("elsewhere"), second.userCode, "approve", human.passkey.assert(forSession))).status).toBe(403);
    expect((await rows("SELECT status FROM device_sign_ins")).map((r) => r.status)).toEqual(["pending", "pending"]);
    expect(await deviceCredentials()).toHaveLength(0);
  });

  it("issues nothing when the sign-in expires between approval and collection", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const started = (await client.start()).body;
    await client.approve(human.token, started.userCode, human.passkey);
    await db.query("UPDATE device_sign_ins SET expires_at = now() - interval '1 second'");
    const results = await Promise.all(Array.from({ length: 4 }, () => client.poll(started.deviceCode)));
    for (const r of results) expect(r.body.error.code).toBe("EXPIRED");
    expect(await deviceCredentials()).toHaveLength(0);
  });

  it("concurrent wrong codes from several sessions of one identity cannot exceed five; another identity is not locked (control)", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const started = (await client.start()).body;
    const sessions = await Promise.all(Array.from({ length: 3 }, (_, i) => human.session(`parallel-${i}`)));
    const results = await Promise.all(Array.from({ length: 15 }, (_, i) => client.lookup(sessions[i % 3]!, "BBBB-BBBB")));
    expect(results.filter((r) => r.status === 404)).toHaveLength(5);
    expect(results.filter((r) => r.status === 429)).toHaveLength(10);
    expect(await rows("SELECT failures FROM device_code_attempt_windows WHERE scope = 'identity'")).toEqual([{ failures: 5 }]);
    expect((await client.lookup(sessions[0]!, started.userCode)).status).toBe(429);
    const other = await approvingHuman(ctx, "Other");
    expect((await client.lookup(other.token, started.userCode)).status).toBe(200);
  });

  it("concurrent requests from one peer cannot exceed ten pending sign-ins", async () => {
    const results = await Promise.all(Array.from({ length: 16 }, () => client.start()));
    expect(results.filter((r) => r.status === 201)).toHaveLength(10);
    expect(results.filter((r) => r.status === 429)).toHaveLength(6);
    expect(await rows("SELECT id FROM device_sign_ins")).toHaveLength(10);
  });
});
