// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { getOrganization } from "../src/domain/orgs.js";
import { requireOrganizationAccess, withRequester } from "../src/domain/requestaccess.js";
import { inSnapshot } from "../src/domain/retrieval.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { buildApp } from "../src/http/app.js";
import { RP } from "./helpers/device-sign-in.js";
import { registerSoftPasskey } from "./helpers/soft-authenticator.js";

/**
 * Where passkey-verification decides, on real PostgreSQL (ADR-0054
 * Decisions 2 and 7, src/domain/requestaccess.ts):
 *
 * - a write decides under its Organization lock: a request that entered
 *   the Organization while the control was off, and locks it after
 *   enforce committed, is refused and changes nothing; a writer that
 *   locked first commits under the old mode, and the change waits for it;
 * - a SERIALIZABLE writer whose snapshot predates the change cannot commit
 *   under it: the change bumps the Organization's security epoch, so the
 *   writer fails to lock the row and runs again on a new snapshot;
 * - a retrieval decides in its snapshot;
 * - report mode counts the decision the write took under its lock, once;
 * - an Idempotency-Key replay is checked against the current mode;
 * - a protected external effect runs in a transaction holding the
 *   Organization row from its checkpoint until the effect is done: a
 *   control change waits for it, and once enforce committed the request is
 *   refused before any outbound call;
 * - a missing nested target keeps its not-found.
 *
 * The races are made deterministic by holding a row lock in a connection
 * of the test's own and waiting until the request blocks on it.
 */
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("passkey-verification on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let app: ReturnType<typeof buildApp>;
  let adminId: string;
  let orgId: string;
  /** The admin's CLI credential: no sign-in evidence. */
  let cli: string;
  /** The admin's dashboard bearer for a sign-in with a trusted passkey that verified them. */
  let verified: string;
  let bobId: string;
  const database = `varlatch_passkeyverification_test_${process.pid}`;
  const ORG = "/v1/organizations/acme";
  const P = `${ORG}/projects/api`;
  const E = `${P}/environments/production`;
  const CONTROL = `${ORG}/security/controls/passkey-verification`;

  /** A platform the access check calls, held at its first request until `release` (the external effect). */
  const platform = {
    calls: 0,
    hold: null as Promise<void> | null,
    release: () => undefined as void,
    fetch: (async () => {
      platform.calls++;
      if (platform.hold) await platform.hold;
      return new Response("4.0.0", { status: 200 });
    }) as unknown as typeof fetch,
    holdNext() {
      platform.hold = new Promise<void>((r) => { platform.release = () => { platform.hold = null; r(); }; });
    },
  };
  const CHECK = "/v1/organizations/acme/platform-connections/check";
  const checkBody = { platform: "coolify", baseIdentity: "https://coolify.example.com", credential: "tok" };

  const call = async (method: string, path: string, token: string, body?: unknown, headers: Record<string, string> = {}) => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null };
  };
  const one = async <T>(sql: string, params: unknown[] = []) => (await db.query(sql, params)).rows[0] as T;
  const n = async (sql: string, params: unknown[] = []) => (await one<{ n: number }>(sql, params)).n;

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
    const key = await registerSoftPasskey(db, adminId, { ...RP, trust: "trusted" });
    await db.query(
      `INSERT INTO "session" (id, "expiresAt", token, "userId")
       SELECT 'ses_verified', now() + interval '1 day', 'ses_verified', better_auth_user_id FROM auth_user_links WHERE identity_id = $1`,
      [adminId],
    );
    await db.query("INSERT INTO auth_session_evidence (session_id, ceremony, user_verified, passkey_id) VALUES ('ses_verified', 'sign-in', true, $1)", [key.passkeyId]);
    verified = (await issueCredential(db, { identityId: adminId, kind: "browser", expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(), authSessionId: "ses_verified" })).token;
    platform.calls = 0;
    platform.hold = null;
    app = buildApp(ctx, { syncFetch: platform.fetch });
    for (const [path, body] of [
      ["/v1/organizations", { name: "Acme", slug: "acme" }],
      [`${ORG}/projects`, { name: "API", slug: "api", contractAuthority: "git" }],
      [`${P}/environments`, { name: "production", tier: "production" }],
    ] as const) expect((await call("POST", path, cli, body)).status).toBe(201);
    expect((await call("PUT", `${E}/values/DB_PASS`, cli, { value: "hunter2-hunter2" })).status).toBe(200);
    orgId = (await one<{ id: string }>("SELECT id FROM organizations WHERE slug = 'acme'")).id;
    bobId = (await consumeSetupGrant(ctx, (await issueInviteGrant(ctx, { organizationId: orgId, role: "member", name: "Bob" }, adminId)).token, {})).identityId;
    // A new database, every migration and the fixtures: over the default
    // hook timeout when the machine is busy.
  }, 30_000);

  afterEach(async () => {
    await accessCountsSettled();
    await db.end();
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.end();
  }, 30_000);

  const enforce = async () => {
    const res = await call("PATCH", CONTROL, verified, { mode: "enforce", expectedVersion: 0 });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
  };

  /** Resolves once `count` backends of the test database wait for a lock. */
  const waiters = async (count: number) => {
    for (let i = 0; i < 400; i++) {
      const waiting = await admin.query(
        "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'",
        [database],
      );
      if ((waiting.rows[0] as { n: number }).n >= count) return;
      await new Promise((r) => setTimeout(r, 25));
    }
    throw new Error(`fewer than ${count} backends ever waited for a lock`);
  };

  /**
   * A control change in flight, as changeControl makes it: the
   * Organization row FOR UPDATE, the control written, the security epoch
   * bumped; committed when `commit` is called. `epoch: false` leaves the
   * epoch alone (what the change did before this fix).
   */
  const changeInFlight = async (mode: "off" | "report" | "enforce", opts: { epoch?: boolean } = {}) => {
    const x = await db.connect();
    await x.query("BEGIN");
    await x.query("SELECT id FROM organizations WHERE id = $1 FOR UPDATE", [orgId]);
    await x.query(
      `INSERT INTO security_controls (organization_id, control, mode, version, changed_at)
       VALUES ($1, 'passkey-verification', $2, 1, clock_timestamp())
       ON CONFLICT (organization_id, control) DO UPDATE SET mode = EXCLUDED.mode, version = security_controls.version + 1`,
      [orgId, mode],
    );
    if (opts.epoch !== false) await x.query("UPDATE organizations SET security_epoch = security_epoch + 1 WHERE id = $1", [orgId]);
    return {
      commit: async () => {
        await x.query("COMMIT");
        x.release();
      },
    };
  };

  const passkeyDenials = () => n("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'authorization.denied' AND metadata::jsonb->>'reason' = 'passkey_verification_required'");
  const projectName = async () => (await one<{ name: string }>("SELECT name FROM projects WHERE slug = 'api'")).name;
  const bobIsMember = async () => (await n("SELECT count(*)::int AS n FROM org_memberships WHERE identity_id = $1 AND removed_at IS NULL", [bobId])) === 1;

  it("a control change bumps the Organization's security epoch", async () => {
    const before = (await one<{ e: string }>("SELECT security_epoch::text AS e FROM organizations WHERE id = $1", [orgId])).e;
    await call("PATCH", CONTROL, verified, { mode: "report", expectedVersion: 0 });
    const after = (await one<{ e: string }>("SELECT security_epoch::text AS e FROM organizations WHERE id = $1", [orgId])).e;
    expect(Number(after)).toBe(Number(before) + 1);
  });

  it("a writer that entered while the control was off and locks after enforce committed is refused, and changes nothing", async () => {
    const change = await changeInFlight("enforce");
    // The rename enters the Organization and authorizes with the control
    // off (the change is not committed), then waits for the row lock.
    const rename = call("PATCH", P, cli, { name: "Renamed" });
    await waiters(1);
    await change.commit();
    const res = await rename;
    expect(res.status, JSON.stringify(res.body)).toBe(403);
    expect(res.body.error.code).toBe("PASSKEY_VERIFICATION_REQUIRED");
    expect(await projectName()).toBe("API");
    expect(await passkeyDenials()).toBe(1);
  }, 30_000);

  it("a writer that locked first commits under the old mode; the control change waits for it, and the next write is refused", async () => {
    // Hold the Project row: the rename takes the Organization FOR KEY
    // SHARE, captures the mode (off), then waits here.
    const x = await db.connect();
    await x.query("BEGIN");
    await x.query("SELECT id FROM projects WHERE slug = 'api' FOR UPDATE");
    const rename = call("PATCH", P, cli, { name: "Renamed" });
    await waiters(1);
    // The change needs the Organization FOR UPDATE: it waits for the rename.
    const change = call("PATCH", CONTROL, verified, { mode: "enforce", expectedVersion: 0 });
    await waiters(2);
    await x.query("ROLLBACK");
    x.release();
    const renamed = await rename;
    expect(renamed.status, JSON.stringify(renamed.body)).toBe(200);
    expect((await change).status).toBe(200);
    expect(await projectName()).toBe("Renamed");
    const next = await call("PATCH", P, cli, { name: "Again" });
    expect(next.body.error.code).toBe("PASSKEY_VERIFICATION_REQUIRED");
    expect(await projectName()).toBe("Renamed");
  }, 30_000);

  it("an external effect holds the Organization row from its checkpoint until it is done: a control change waits for it", async () => {
    platform.holdNext();
    const checking = call("POST", CHECK, cli, checkBody);
    // The check passed its checkpoint (off) and is at the platform.
    for (let i = 0; i < 400 && platform.calls === 0; i++) await new Promise((r) => setTimeout(r, 25));
    expect(platform.calls).toBeGreaterThan(0);
    const change = call("PATCH", CONTROL, verified, { mode: "enforce", expectedVersion: 0 });
    await waiters(1);
    // While the effect is in progress, the change has not committed.
    expect((await one<{ n: number }>("SELECT count(*)::int AS n FROM security_controls WHERE mode = 'enforce'")).n).toBe(0);
    platform.release();
    const checked = await checking;
    expect(checked.status, JSON.stringify(checked.body)).toBe(200);
    expect((await change).status).toBe(200);
    // The next one is refused before the platform is called.
    const calls = platform.calls;
    const refused = await call("POST", CHECK, cli, checkBody);
    expect(refused.body.error.code).toBe("PASSKEY_VERIFICATION_REQUIRED");
    expect(platform.calls).toBe(calls);
  }, 30_000);

  it("an external operation that locks after enforce committed is refused before any outbound call, and records nothing", async () => {
    const change = await changeInFlight("enforce");
    const checking = call("POST", CHECK, cli, checkBody);
    await waiters(1);
    await change.commit();
    const refused = await checking;
    expect(refused.status, JSON.stringify(refused.body)).toBe(403);
    expect(refused.body.error.code).toBe("PASSKEY_VERIFICATION_REQUIRED");
    expect(platform.calls).toBe(0);
    expect(await n("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'sync.connection_checked'")).toBe(0);
    expect(await passkeyDenials()).toBe(1);
  }, 30_000);

  it("a SERIALIZABLE writer whose snapshot predates the change runs again and is refused; without the epoch it would commit under the old mode", async () => {
    // With the epoch: the removal's first statement (the Organization
    // lock) takes its snapshot, waits for the change, then fails to lock
    // the row the change updated (40001); its retry reads enforce.
    const change = await changeInFlight("enforce");
    const removal = call("DELETE", `${ORG}/members/${bobId}`, cli);
    await waiters(1);
    await change.commit();
    const refused = await removal;
    expect(refused.status, JSON.stringify(refused.body)).toBe(403);
    expect(refused.body.error.code).toBe("PASSKEY_VERIFICATION_REQUIRED");
    expect(await bobIsMember()).toBe(true);

    // The counterfactual, showing what the epoch is for: back to off, then a
    // change that leaves the epoch alone. The removal locks the unchanged
    // row and decides from its older snapshot: the stale mode.
    await db.query("UPDATE security_controls SET mode = 'off' WHERE organization_id = $1", [orgId]);
    const stale = await changeInFlight("enforce", { epoch: false });
    const staleRemoval = call("DELETE", `${ORG}/members/${bobId}`, cli);
    await waiters(1);
    await stale.commit();
    expect((await staleRemoval).status).toBe(200);
    expect(await bobIsMember()).toBe(false);
  }, 30_000);

  it("report mode counts the mode the write read under its lock, once; off counts nothing", async () => {
    // off -> report committed while the writer waits: counted.
    let change = await changeInFlight("report");
    let rename = call("PATCH", P, cli, { name: "First" });
    await waiters(1);
    await change.commit();
    expect((await rename).status).toBe(200);
    await accessCountsSettled();
    const counted = await db.query("SELECT operation, reason, count::int AS count FROM security_control_counters WHERE control = 'passkey-verification'");
    expect(counted.rows).toEqual([{ operation: "project.manage", reason: "no-evidence", count: 1 }]);

    // report -> off committed while the writer waits: not counted.
    change = await changeInFlight("off");
    rename = call("PATCH", P, cli, { name: "Second" });
    await waiters(1);
    await change.commit();
    expect((await rename).status).toBe(200);
    await accessCountsSettled();
    expect(await n("SELECT coalesce(sum(count), 0)::int AS n FROM security_control_counters WHERE control = 'passkey-verification'")).toBe(1);

    // A SERIALIZABLE writer retried by the change counts once.
    change = await changeInFlight("report");
    const promote = call("PATCH", `${ORG}/members/${bobId}`, cli, { role: "admin" });
    await waiters(1);
    await change.commit();
    expect((await promote).status).toBe(200);
    await accessCountsSettled();
    expect(await n("SELECT coalesce(sum(count), 0)::int AS n FROM security_control_counters WHERE control = 'passkey-verification'")).toBe(2);
  }, 30_000);

  it("an Idempotency-Key replay is checked against the current mode: refused under enforce, answered again once it is off", async () => {
    const key = { "Idempotency-Key": "pv-replay-1" };
    const first = await call("PUT", `${E}/values/DB_PASS`, cli, { value: "changed-changed" }, key);
    expect(first.status).toBe(200);
    await enforce();
    const replay = await call("PUT", `${E}/values/DB_PASS`, cli, { value: "changed-changed" }, key);
    expect(replay.status).toBe(403);
    expect(replay.body.error.code).toBe("PASSKEY_VERIFICATION_REQUIRED");
    expect(JSON.stringify(replay.body)).not.toContain(first.body.versionId);
    await db.query("UPDATE security_controls SET mode = 'off', version = version + 1 WHERE organization_id = $1", [orgId]);
    const again = await call("PUT", `${E}/values/DB_PASS`, cli, { value: "changed-changed" }, key);
    expect(again).toEqual(first);
    // One version from the first request; the replays wrote none.
    expect(await n("SELECT count(*)::int AS n FROM value_versions")).toBe(2);
  }, 30_000);

  it("a missing nested target keeps its not-found under enforce", async () => {
    await enforce();
    for (const [method, path] of [
      ["GET", `${P}/contract/revisions/crev_missing`],
      ["DELETE", `${E}/values/NOPE`],
      ["DELETE", `${ORG}/grants/grant_missing`],
      ["PATCH", `${ORG}/members/idt_missing`],
    ] as const) {
      const res = await call(method, path, cli, method === "PATCH" ? { role: "admin" } : undefined);
      expect(res.body.error?.code, `${method} ${path}`).toBe("RESOURCE_NOT_FOUND");
    }
    expect(await passkeyDenials()).toBe(0);
  }, 30_000);

  it("a retrieval's snapshot that began before the control was enforced decides under the old mode; the next is refused", async () => {
    const requester = { identityId: adminId, identityKind: "human", credentialId: (await one<{ id: string }>("SELECT id FROM credentials WHERE identity_id = $1 AND kind = 'cli'", [adminId])).id, credentialKind: "cli" };
    const decided = await withRequester(requester, () =>
      inSnapshot(ctx, async (sctx) => {
        // The snapshot is taken by its first read.
        const org = await getOrganization(sctx, "acme");
        // The control is enforced and committed while the snapshot is open.
        await enforce();
        await requireOrganizationAccess(sctx.db, org.id);
        return "allowed";
      }),
    );
    expect(decided).toBe("allowed");
    const after = withRequester(requester, () =>
      inSnapshot(ctx, async (sctx) => {
        const org = await getOrganization(sctx, "acme");
        await requireOrganizationAccess(sctx.db, org.id);
      }),
    );
    await expect(after).rejects.toMatchObject({ code: "PASSKEY_VERIFICATION_REQUIRED" });
    const refused = await call("POST", `${E}/retrievals`, cli, { mode: "strict" });
    expect(refused.status).toBe(403);
    expect(refused.body.error.code).toBe("PASSKEY_VERIFICATION_REQUIRED");
    expect(JSON.stringify(refused.body)).not.toContain("hunter2");
    expect((await call("POST", `${E}/retrievals`, verified, { mode: "strict" })).status).toBe(200);
  }, 30_000);

  it("requests racing the change get the old answer or the refusal, and every request after it is refused", async () => {
    const racing = Array.from({ length: 12 }, (_, i) =>
      i % 2 === 0 ? call("POST", `${E}/retrievals`, cli, { mode: "strict" }) : call("GET", `${ORG}/projects`, cli),
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
    expect(await n("SELECT count(*)::int AS n FROM security_control_counters")).toBe(0);
  }, 30_000);
});
