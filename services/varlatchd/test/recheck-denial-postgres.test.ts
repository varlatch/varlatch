// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { lockedQuery } from "../src/db/locks.js";
import { runMigrations } from "../src/db/migrate.js";
import { createPgQuerier } from "../src/db/pg.js";
import { withTx, type PoolQuerier } from "../src/db/tx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { lockLiveScope } from "../src/domain/liveness.js";
import { resetControls } from "../src/domain/securitycontrols.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * ADR-0054 follow-up (f) on real PostgreSQL: freezing, lifting a freeze and
 * changing a security control, racing a real demotion of their requester.
 * The demotion holds the Organization row (and the membership) when the
 * request arrives: the route's own check reads Carol an admin, the
 * operation waits for the Organization row FOR UPDATE, the demotion
 * commits, and the recheck in the operation's transaction denies.
 *
 * - With a control at report: one authorization.denied, equal to the
 *   route's ordinary denial of the same request, recorded after the
 *   rollback.
 * - With every control off: the same answer and no audit event, as on
 *   main.
 *
 * - While the operator's reset holds the Organization row (uncommitted,
 *   turning the only control off), a freeze waits for it: its recheck
 *   decides on the state the reset left. A committed reset leaves every
 *   control off, so the denial takes main's path; a reset that rolled back
 *   leaves the control on, so the denial is audited once.
 *
 * The same races on PGlite, and report to off: recheck-denial.test.ts.
 */
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("a recheck denial racing a demotion, on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let app: ReturnType<typeof buildApp>;
  let orgId: string;
  let owner: Person;
  let carol: Person;
  const database = `varlatch_recheck_denial_test_${process.pid}`;

  interface Person {
    id: string;
    cli: string;
    web: string;
    key: SoftAuthenticator;
  }
  type Answer = { status: number; body: any };

  const call = async (method: string, path: string, token: string, body?: unknown, headers: Record<string, string> = {}): Promise<Answer> => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null };
  };
  const rows = async (sql: string, params: unknown[] = []) => (await db.query(sql, params)).rows as any[];
  const parse = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v) as Record<string, any>;
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const deferred = () => {
    let resolve!: () => void;
    const promise = new Promise<void>((r) => { resolve = r; });
    return { promise, resolve };
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
    const web = await issueCredential(db, {
      identityId,
      kind: "browser",
      expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      authSessionId: sessionId,
    });
    return { id: identityId, cli: cli.token, web: web.token, key };
  }

  /** The approval a request asks for (STEP_UP_REQUIRED), approved by `p` in the dashboard. */
  async function approved(p: Person, ask: () => Promise<Answer>): Promise<string> {
    const asked = await ask();
    expect(asked.status, JSON.stringify(asked.body)).toBe(403);
    expect(asked.body.error.code).toBe("STEP_UP_REQUIRED");
    const id = asked.body.error.details.approval.id as string;
    const started = await call("POST", `/v1/me/approvals/${id}/options`, p.web);
    expect(started.status, JSON.stringify(started.body)).toBe(200);
    const done = await call("POST", `/v1/me/approvals/${id}/approve`, p.web, {
      assertion: p.key.assert(started.body.publicKey.challenge, { userVerified: true }),
    });
    expect(done.status, JSON.stringify(done.body)).toBe(200);
    return id;
  }

  const FREEZE = "/v1/organizations/acme/incident-freeze";
  const freeze = (token: string) => call("POST", FREEZE, token, { reason: "A CI token leaked" });
  const lift = (token: string, freezeId: string, approval?: string) =>
    call("POST", `${FREEZE}/${freezeId}/lift`, token, undefined, approval ? { "Varlatch-Approval": approval } : {});
  const change = (token: string, control: string, mode: string, expectedVersion: number) =>
    call("PATCH", `/v1/organizations/acme/security/controls/${control}`, token, { mode, expectedVersion });

  /** A control at report, written directly in the database. */
  const report = (control: string) =>
    db.query(
      `INSERT INTO security_controls (organization_id, control, mode, config, version, changed_by, changed_at)
       VALUES ($1, $2, 'report', NULL, 1, $3, now())`,
      [orgId, control, owner.id],
    );
  const setRole = (role: string) =>
    db.query("UPDATE org_memberships SET role = $3 WHERE organization_id = $1 AND identity_id = $2", [orgId, carol.id, role]);

  const denials = async () =>
    (await rows(
      `SELECT event_type, decision, actor_identity_id, credential_id, organization_id, action, resource, authz, metadata
       FROM audit_events WHERE event_type = 'authorization.denied' AND actor_identity_id = $1 ORDER BY event_order`,
      [carol.id],
    )).map((r) => ({ ...r, resource: parse(r.resource), authz: parse(r.authz), metadata: parse(r.metadata) }));
  const auditCount = async () => Number((await rows("SELECT count(*)::int AS n FROM audit_events"))[0].n);
  const withoutRequestId = (a: Answer) => ({ status: a.status, error: { ...a.body.error, requestId: undefined } });

  /**
   * `send` racing Carol's demotion: the demotion holds the Organization
   * row and her membership, uncommitted, until the request is seen waiting
   * on a lock; then it commits. Carol is an admin again afterwards.
   */
  async function demotedWhileWaiting(send: () => Promise<Answer>): Promise<Answer> {
    const locked = deferred();
    const release = deferred();
    const demoting = withTx(db, async (tx) => {
      // Demoting an admin is recovery during an incident freeze (ADR-0055).
      await lockLiveScope(tx, { organizationId: orgId, people: [carol.id], duringIncidentFreeze: "recovery" });
      await lockedQuery(
        tx,
        { table: "org_memberships", mode: "no key update", key: "lock_key" },
        `SELECT concat_ws('|', organization_id::text, identity_id::text) AS lock_key FROM org_memberships
         WHERE organization_id = $1 AND identity_id = $2 FOR NO KEY UPDATE`,
        [orgId, carol.id],
      );
      await tx.query("UPDATE org_memberships SET role = 'member', version = version + 1 WHERE organization_id = $1 AND identity_id = $2", [orgId, carol.id]);
      locked.resolve();
      await release.promise;
    });
    await Promise.race([locked.promise, demoting]);
    let finished = false;
    const sending = send().finally(() => { finished = true; });
    try {
      // The request waits for the Organization row the demotion holds.
      let waiting = 0;
      for (let i = 0; i < 100 && waiting === 0 && !finished; i++) {
        await sleep(50);
        waiting = Number(((await admin.query(
          "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'",
          [database],
        )).rows[0] as { n: number }).n);
      }
      expect(finished, "the request waited for the demotion").toBe(false);
      expect(waiting).toBeGreaterThan(0);
    } finally {
      release.resolve();
      await demoting;
    }
    const res = await sending;
    await setRole("admin");
    return res;
  }

  /**
   * The race: refused with PERMISSION_DENIED. With `audited`, exactly one
   * authorization.denied for Carol, equal to the route's ordinary denial of
   * the same request; without, no audit event of any kind.
   */
  async function race(send: () => Promise<Answer>, audited: boolean): Promise<Answer> {
    const before = await denials();
    const total = await auditCount();
    const res = await demotedWhileWaiting(send);
    expect(res.status, JSON.stringify(res.body)).toBe(403);
    expect(res.body.error.code).toBe("PERMISSION_DENIED");
    const after = await denials();
    if (!audited) {
      expect(after).toEqual(before);
      expect(await auditCount()).toBe(total);
      return res;
    }
    expect(after).toHaveLength(before.length + 1);
    expect(await auditCount()).toBe(total + 1);
    const deferredDenial = after.at(-1)!;
    expect(deferredDenial).toMatchObject({ decision: "deny", organization_id: orgId, action: "organization.manage" });
    // The route's own denial of the same request, Carol demoted beforehand.
    await setRole("member");
    const ordinary = await send();
    await setRole("admin");
    expect(ordinary.body.error.code).toBe("PERMISSION_DENIED");
    expect(deferredDenial).toEqual((await denials()).at(-1));
    expect(withoutRequestId(res)).toEqual(withoutRequestId(ordinary));
    return res;
  }

  beforeEach(async () => {
    admin = createPgQuerier(url!);
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${database}`);
    const target = new URL(url!);
    target.pathname = `/${database}`;
    db = createPgQuerier(target.toString());
    const connection = await db.connect();
    try { await runMigrations(connection); } finally { connection.release(); }
    ctx = { db, rootKek: Buffer.alloc(32, 53) };
    await ensureInstallation(ctx);
    owner = await person((await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" })).identityId);
    app = buildApp(ctx, { publicUrl: PUBLIC_URL, clientAddress: () => "203.0.113.7" });
    orgId = (await call("POST", "/v1/organizations", owner.cli, { name: "Acme", slug: "acme" })).body.id;
    const grant = await issueInviteGrant(ctx, { organizationId: orgId, role: "admin", name: "Carol" }, owner.id);
    carol = await person((await consumeSetupGrant(ctx, grant.token, {})).identityId);
  });
  afterEach(async () => {
    await db?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
      await admin.end();
    }
  });

  it("freezing: with every control off no event and main's answer; with a control on, the same answer and one denial", async () => {
    const off = await race(() => freeze(carol.cli), false);
    await report("admin-step-up");
    const on = await race(() => freeze(carol.cli), true);
    expect(withoutRequestId(on)).toEqual(withoutRequestId(off));
    expect(await rows("SELECT id FROM organization_freezes")).toEqual([]);
  });

  it("lifting with an approval: with every control off no event; with a control on, one denial; the approval stays unused", async () => {
    const created = await freeze(owner.cli);
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const id = created.body.id as string;
    const approval = await approved(carol, () => lift(carol.cli, id));
    const off = await race(() => lift(carol.cli, id, approval), false);
    await report("requirement-protection");
    const on = await race(() => lift(carol.cli, id, approval), true);
    expect(withoutRequestId(on)).toEqual(withoutRequestId(off));
    expect((await rows("SELECT lifted_at FROM organization_freezes WHERE id = $1", [id]))[0].lifted_at).toBeNull();
    expect((await rows("SELECT consumed_at FROM approval_intents WHERE id = $1", [approval]))[0].consumed_at).toBeNull();
  });

  /**
   * The operator's reset of every control, held at its COMMIT: it has taken
   * the Organization row FOR UPDATE and written its changes. `outcome`
   * commits it or makes the COMMIT fail, which rolls it back.
   */
  function heldReset() {
    const held = deferred();
    const release = deferred();
    let outcome: "commit" | "fail" = "commit";
    const resetDb: PoolQuerier = {
      query: (text, params) => db.query(text, params),
      connect: async () => {
        const client = await db.connect();
        return {
          query: async (text: string, params?: unknown[]) => {
            if (text.trim() === "COMMIT") {
              held.resolve();
              await release.promise;
              if (outcome === "fail") throw new Error("the reset's COMMIT failed (injected)");
            }
            return client.query(text, params);
          },
          release: (destroy?: boolean) => client.release(destroy),
        };
      },
    };
    const resetting = resetControls({ ...ctx, db: resetDb }, { organization: "acme", controls: "all" });
    resetting.catch(() => undefined);
    return {
      holding: Promise.race([held.promise, resetting.then(() => { throw new Error("the reset finished without waiting"); })]),
      finish: async (how: "commit" | "fail") => {
        outcome = how;
        release.resolve();
        return resetting.then(() => "committed" as const, () => "rolled back" as const);
      },
    };
  }

  /**
   * Carol freezes while the reset holds the Organization row: the route's
   * own check reads her an admin, the freeze's transaction waits for the
   * row, she is demoted meanwhile (her membership only, not the
   * Organization row), and the reset ends as `how` says before the freeze
   * gets the row.
   */
  async function freezeWhileResetHolds(how: "commit" | "fail"): Promise<{ res: Answer; reset: string }> {
    const reset = heldReset();
    await reset.holding;
    let finished = false;
    const sending = freeze(carol.cli).finally(() => { finished = true; });
    let reached: string;
    try {
      let waiting = 0;
      for (let i = 0; i < 100 && waiting === 0 && !finished; i++) {
        await sleep(50);
        waiting = Number(((await admin.query(
          "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'",
          [database],
        )).rows[0] as { n: number }).n);
      }
      expect(finished, "the freeze waited for the reset").toBe(false);
      expect(waiting).toBeGreaterThan(0);
      await setRole("member");
    } finally {
      reached = await reset.finish(how);
    }
    const res = await sending;
    await setRole("admin");
    return { res, reset: reached };
  }

  const otherEvents = async () =>
    Number((await rows("SELECT count(*)::int AS n FROM audit_events WHERE event_type <> 'security_control.reset'"))[0].n);
  const resets = async () => Number((await rows("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'security_control.reset'"))[0].n);

  it("freezing while the operator's reset holds the Organization: decided on the state the reset leaves", async () => {
    // Main's answer for the same race with every control off.
    const off = await race(() => freeze(carol.cli), false);

    // The reset commits: every control off when the freeze gets the row, so main's path, no denial recorded.
    await report("admin-step-up");
    let others = await otherEvents();
    let denied = (await denials()).length;
    const committed = await freezeWhileResetHolds("commit");
    expect(committed.reset).toBe("committed");
    expect(committed.res.status, JSON.stringify(committed.res.body)).toBe(403);
    expect(withoutRequestId(committed.res)).toEqual(withoutRequestId(off));
    expect((await denials()).length).toBe(denied);
    expect(await otherEvents()).toBe(others);
    expect(await resets()).toBe(4);
    expect(await rows("SELECT control, mode FROM security_controls")).toEqual([{ control: "admin-step-up", mode: "off" }]);

    // The reset rolls back: the control is still at report when the freeze gets the row, so one denial.
    await db.query("UPDATE security_controls SET mode = 'report', version = version + 1 WHERE organization_id = $1", [orgId]);
    others = await otherEvents();
    denied = (await denials()).length;
    const rolledBack = await freezeWhileResetHolds("fail");
    expect(rolledBack.reset).toBe("rolled back");
    expect(withoutRequestId(rolledBack.res)).toEqual(withoutRequestId(off));
    const after = await denials();
    expect(after).toHaveLength(denied + 1);
    expect(after.at(-1)).toMatchObject({ decision: "deny", organization_id: orgId, action: "organization.manage" });
    expect(await otherEvents()).toBe(others + 1);
    expect(await resets()).toBe(4);
    expect(await rows("SELECT control, mode FROM security_controls")).toEqual([{ control: "admin-step-up", mode: "report" }]);
    expect(await rows("SELECT id FROM organization_freezes")).toEqual([]);
  });

  it("changing a control: off to report from all off records nothing; with another control on, one denial", async () => {
    const off = await race(() => change(carol.cli, "admin-step-up", "report", 0), false);
    await report("requirement-protection");
    const on = await race(() => change(carol.cli, "admin-step-up", "report", 0), true);
    expect(withoutRequestId(on)).toEqual(withoutRequestId(off));
    expect(await rows("SELECT control, mode FROM security_controls ORDER BY control")).toEqual([{ control: "requirement-protection", mode: "report" }]);
  });
});
