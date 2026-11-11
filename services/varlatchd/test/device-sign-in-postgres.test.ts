// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { PUBLIC_URL, RP, approvingHuman, deviceClient } from "./helpers/device-sign-in.js";
import { registerSoftPasskey } from "./helpers/soft-authenticator.js";

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

  it("a poll that read no approver, then finds the sign-in approved under its lock, retries with the approver locked first", async () => {
    // ADR-0054 amendment E: the approver (step 2) before the sign-in row.
    const started = (await client.start()).body;
    const id = (await rows("SELECT id FROM device_sign_ins WHERE user_code = $1", [started.userCode.replace("-", "")]))[0].id as string;
    // Another transaction holds the row and approves it; the poll reads
    // no approver yet, then waits for the row.
    const other = await db.connect();
    const statements: string[] = [];
    const logged = <Q extends { query: (t: string, p?: unknown[]) => Promise<{ rows: unknown[] }> }>(q: Q): Q =>
      ({ ...q, query: async (t: string, p?: unknown[]) => { statements.push(t); return q.query(t, p); } });
    const ldb = { ...logged(db), connect: async () => logged(await db.connect()) } as typeof db;
    const lapp = buildApp({ ...ctx, db: ldb }, { publicUrl: PUBLIC_URL, clientAddress: () => peer });
    try {
      await other.query("BEGIN");
      await other.query("SELECT id FROM device_sign_ins WHERE id = $1 FOR UPDATE", [id]);
      await other.query(
        "UPDATE device_sign_ins SET status = 'approved', approved_by_identity_id = $2, decided_at = clock_timestamp() WHERE id = $1",
        [id, adminId],
      );
      const polled = deviceClient(() => lapp).poll(started.deviceCode);
      for (let i = 0; i < 250; i++) {
        const waiting = await admin.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'", [database]);
        if ((waiting.rows[0] as { n: number }).n > 0) break;
        await new Promise((r) => setTimeout(r, 20));
      }
      await other.query("COMMIT");
      const answer = await polled;
      expect(answer.status).toBe(201);
      expect(await deviceCredentials()).toHaveLength(1);
    } finally {
      await other.query("ROLLBACK").catch(() => undefined);
      other.release();
    }
    // The first attempt rolled back before writing; the second locked the
    // approver before the sign-in row.
    const signInLocks = statements.flatMap((t, i) => (/FROM device_sign_ins WHERE device_code_hash = \$1 FOR UPDATE/.test(t) ? [i] : []));
    expect(signInLocks).toHaveLength(2);
    const between = statements.slice(signInLocks[0]! + 1, signInLocks[1]!);
    expect(between.some((t) => /^ROLLBACK/.test(t))).toBe(true);
    expect(between.some((t) => /FROM identities WHERE id = ANY\(\$1\) ORDER BY id FOR KEY SHARE/.test(t))).toBe(true);
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
      // A lost race is not a failed passkey confirmation.
      expect(await rows("SELECT id FROM audit_events WHERE event_type = 'authentication.failed'")).toEqual([]);
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
    // Losers that arrive after the approval find no pending sign-in for the
    // code, which counts as a wrong code: after five, this identity is locked
    // out (429) for the rest of the window.
    for (const r of results.filter((r) => r.status !== 200)) expect([403, 404, 409, 429]).toContain(r.status);
    await db.query("DELETE FROM device_code_attempt_windows");
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

  describe("a wait for a lock that crosses an expiry", () => {
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
    /** Hold `sql`'s row locks in another connection until released. */
    async function hold(sql: string, params: unknown[]) {
      const client = await db.connect();
      await client.query("BEGIN");
      await client.query(sql, params);
      return async () => {
        await client.query("COMMIT");
        client.release();
      };
    }
    /** Resolve once a request in this database waits for a lock. */
    async function untilWaiting() {
      for (let i = 0; i < 250; i++) {
        const [r] = await rows("SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'");
        if (r.n > 0) return;
        await sleep(20);
      }
      throw new Error("no request waited for the lock");
    }
    /** Resolve once the database's live clock is past `sql`'s timestamp. */
    async function untilPast(sql: string, params: unknown[]) {
      for (let i = 0; i < 250; i++) {
        const [r] = await rows(`SELECT (${sql}) <= clock_timestamp() AS past`, params);
        if (r.past) return;
        await sleep(20);
      }
      throw new Error("the expiry never passed");
    }
    const signInId = async (userCode: string) =>
      (await rows("SELECT id FROM device_sign_ins WHERE user_code = $1", [userCode.replace("-", "")]))[0].id as string;
    const expireSoon = (id: string) => db.query("UPDATE device_sign_ins SET expires_at = clock_timestamp() + interval '1500 milliseconds' WHERE id = $1", [id]);
    const lockSignIn = "SELECT id FROM device_sign_ins WHERE id = $1 FOR UPDATE";
    const signInExpiry = "SELECT expires_at FROM device_sign_ins WHERE id = $1";

    for (const crossesExpiry of [true, false]) {
      const label = crossesExpiry ? "past the expiry: no credential" : "before the expiry (control): issued";
      it(`collection waiting for the sign-in's lock, released ${label}`, async () => {
        const human = await approvingHuman(ctx, "Admin", adminId);
        const started = (await client.start()).body;
        expect((await client.approve(human.token, started.userCode, human.passkey)).status).toBe(200);
        const id = await signInId(started.userCode);
        await expireSoon(id);
        const release = await hold(lockSignIn, [id]);
        const polled = client.poll(started.deviceCode);
        await untilWaiting();
        if (crossesExpiry) await untilPast(signInExpiry, [id]);
        await release();
        const answer = await polled;
        if (crossesExpiry) {
          expect(answer.status).toBe(410);
          expect(answer.body.error.code).toBe("EXPIRED");
          expect(await deviceCredentials()).toHaveLength(0);
          expect((await rows("SELECT status FROM device_sign_ins WHERE id = $1", [id]))[0].status).toBe("expired");
        } else {
          expect(answer.status).toBe(201);
          expect(await deviceCredentials()).toHaveLength(1);
        }
      });

      for (const decision of ["approve", "deny"] as const) {
        it(`${decision} waiting for the sign-in's lock, released ${crossesExpiry ? "past the expiry: no decision" : "before the expiry (control): decided"}`, async () => {
          const human = await approvingHuman(ctx, "Admin", adminId);
          const started = (await client.start()).body;
          const { challenge } = (await client.lookup(human.token, started.userCode)).body.approval.publicKey;
          const id = await signInId(started.userCode);
          await expireSoon(id);
          const release = await hold(lockSignIn, [id]);
          const decided = client.decide(human.token, started.userCode, decision, decision === "approve" ? human.passkey.assert(challenge) : undefined);
          await untilWaiting();
          if (crossesExpiry) await untilPast(signInExpiry, [id]);
          await release();
          const answer = await decided;
          const [row] = await rows("SELECT status FROM device_sign_ins WHERE id = $1", [id]);
          if (crossesExpiry) {
            expect(answer.status).toBe(409);
            expect(answer.body.error.code).toBe("STATE_CHANGED");
            expect(row.status).toBe("pending");
            expect(await rows("SELECT id FROM audit_events WHERE event_type IN ('authentication.device_approved', 'authentication.device_denied')")).toEqual([]);
          } else {
            expect(answer.status).toBe(200);
            expect(row.status).toBe(decision === "approve" ? "approved" : "denied");
          }
        });
      }

      it(`approval waiting for the lock while its challenge expires, released ${crossesExpiry ? "past the challenge's expiry: refused" : "before it (control): approved"}`, async () => {
        const human = await approvingHuman(ctx, "Admin", adminId);
        const started = (await client.start()).body;
        const { challenge } = (await client.lookup(human.token, started.userCode)).body.approval.publicKey;
        const id = await signInId(started.userCode);
        await db.query("UPDATE device_sign_in_challenges SET expires_at = clock_timestamp() + interval '1500 milliseconds' WHERE challenge = $1", [challenge]);
        const release = await hold(lockSignIn, [id]);
        const decided = client.decide(human.token, started.userCode, "approve", human.passkey.assert(challenge));
        await untilWaiting();
        if (crossesExpiry) await untilPast("SELECT expires_at FROM device_sign_in_challenges WHERE challenge = $1", [challenge]);
        await release();
        const answer = await decided;
        const [row] = await rows("SELECT status FROM device_sign_ins WHERE id = $1", [id]);
        if (crossesExpiry) {
          expect(answer.status).toBe(403);
          expect(row.status).toBe("pending");
        } else {
          expect(answer.status).toBe(200);
          expect(row.status).toBe("approved");
        }
      });

      it(`code lookup waiting for the attempt counters, released ${crossesExpiry ? "past the sign-in's expiry: not found" : "before it (control): found"}`, async () => {
        const human = await approvingHuman(ctx, "Admin", adminId);
        const started = (await client.start()).body;
        const id = await signInId(started.userCode);
        await db.query("INSERT INTO device_code_attempt_windows (scope, key, window_started_at) VALUES ('global', 'all', clock_timestamp()) ON CONFLICT DO NOTHING");
        await expireSoon(id);
        const release = await hold("SELECT 1 FROM device_code_attempt_windows WHERE scope = 'global' FOR UPDATE", []);
        const found = client.lookup(human.token, started.userCode);
        await untilWaiting();
        if (crossesExpiry) await untilPast(signInExpiry, [id]);
        await release();
        expect((await found).status).toBe(crossesExpiry ? 404 : 200);
      });
    }
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

  it("an approval and a passkey confirmation start of one person, on the same passkey, both complete without a deadlock", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    // human.passkey is unconfirmed: it approves the sign-in and is the passkey being confirmed.
    await registerSoftPasskey(db, human.identityId, { ...RP, trust: "trusted" });
    const confirmationOptions = () =>
      app.request(`/v1/me/passkeys/${human.passkey.passkeyId}/confirmation/options`, {
        method: "POST",
        headers: { Authorization: `Bearer ${human.token}` },
      });
    // An earlier, unused confirmation challenge, which the next start supersedes.
    expect((await confirmationOptions()).status).toBe(200);
    const started = (await client.start()).body;
    const { challenge } = (await client.lookup(human.token, started.userCode)).body.approval.publicKey;
    const assertion = human.passkey.assert(challenge);
    const lockWaiters = async () =>
      (await rows("SELECT query FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'", [database])).map((r) => r.query as string);
    const until = async (done: (waiting: string[]) => boolean) => {
      for (let i = 0; i < 400; i++) {
        if (done(await lockWaiters())) return;
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      throw new Error(`Lock waits never matched: ${JSON.stringify(await lockWaiters())}`);
    };
    // Hold the earlier challenge, so the confirmation start stops at superseding it while it holds the person.
    const gate = await db.connect();
    let confirming: Promise<Response> | undefined;
    let approving: ReturnType<typeof client.decide> | undefined;
    try {
      await gate.query("BEGIN");
      await gate.query("SELECT id FROM passkey_confirmation_challenges WHERE target_passkey_id = $1 FOR UPDATE", [human.passkey.passkeyId]);
      confirming = confirmationOptions();
      await until((waiting) => waiting.some((q) => /UPDATE passkey_confirmation_challenges/i.test(q)));
      // The approval runs as far as it can while the confirmation holds the person.
      approving = client.decide(human.token, started.userCode, "approve", assertion);
      await until((waiting) => waiting.length === 2);
      // Released, the confirmation start goes on to reference the passkey.
      await gate.query("COMMIT");
    } finally {
      gate.release();
    }
    const [confirmed, approved] = await Promise.all([confirming, approving]);
    expect(confirmed.status).toBe(200);
    expect(approved.status).toBe(200);
    expect((await rows("SELECT status FROM device_sign_ins")).map((r) => r.status)).toEqual(["approved"]);
    expect((await rows("SELECT counter FROM passkey WHERE id = $1", [human.passkey.passkeyId]))[0].counter).toBe(1);
  });
});
