// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import { lockedQuery } from "../src/db/locks.js";
import { withTx } from "../src/db/tx.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { withApproval, type ProtectedGate, type Requester } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { lockLiveScope } from "../src/domain/liveness.js";
import { changeMemberRole, removeMember } from "../src/domain/members.js";
import { noApprovalGate } from "../src/domain/protected.js";
import { changeControl } from "../src/domain/securitycontrols.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * admin-step-up for people on real PostgreSQL (ADR-0054 step 4.7). Role
 * changes and removals run in SERIALIZABLE transactions
 * (withSerializableTx) and consume real approvals:
 *
 * - two admins, each with an approval, demote each other at once: the
 *   last-admin rule holds, one wins, and the other's attempt rolls back
 *   with its consumption, so its approval stays unconsumed;
 * - a removal that bound the membership's version races a demotion of the
 *   same person: its retry consumes the approval again in the new attempt,
 *   finds it stale, and removes nobody;
 * - a role change that starts while a control change holds the
 *   Organization waits for it and runs under the new mode (Decision 2).
 *   Its SERIALIZABLE snapshot began before the wait, but both write an
 *   audit event, so the role change fails to serialize and its retry reads
 *   the new mode.
 */
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("admin-step-up for people on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let app: ReturnType<typeof buildApp>;
  let orgId: string;
  const database = `varlatch_stepup_people_test_${process.pid}`;

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
  const deferred = () => {
    let resolve!: () => void;
    const promise = new Promise<void>((r) => { resolve = r; });
    return { promise, resolve };
  };
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

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
    return { id: identityId, cli: cli.token, cliId: cli.credentialId, web: web.token, key };
  }
  const requester = (p: Person): Requester => ({ identityId: p.id, identityKind: "human", credentialId: p.cliId, credentialKind: "cli" });

  /** Ask through the route, approve in the dashboard with the person's passkey; the approval id. */
  async function approval(p: Person, method: string, path: string, body?: unknown): Promise<string> {
    const asked = await call(method, path, p.cli, body);
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
  const consumedAt = async (id: string) =>
    ((await db.query("SELECT consumed_at FROM approval_intents WHERE id = $1", [id])).rows[0] as { consumed_at: Date | null }).consumed_at;
  const membership = async (identityId: string) => {
    const row = (await db.query("SELECT role, version, removed_at IS NOT NULL AS removed FROM org_memberships WHERE organization_id = $1 AND identity_id = $2", [orgId, identityId]))
      .rows[0] as { role: string; version: number | string; removed: boolean };
    return { ...row, version: Number(row.version) };
  };

  let owner: Person;
  async function invite(name: string, role: "admin" | "member"): Promise<Person> {
    const grant = await issueInviteGrant(ctx, { organizationId: orgId, role, name }, owner.id);
    return person((await consumeSetupGrant(ctx, grant.token, {})).identityId);
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
    ctx = { db, rootKek: Buffer.alloc(32, 47) };
    await ensureInstallation(ctx);
    owner = await person((await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" })).identityId);
    app = buildApp(ctx, { publicUrl: PUBLIC_URL, clientAddress: () => "203.0.113.7" });
    orgId = (await call("POST", "/v1/organizations", owner.cli, { name: "Acme", slug: "acme" })).body.id;
  });
  afterEach(async () => {
    await db?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
      await admin.end();
    }
  });

  /** admin-step-up at enforce, written directly: the API refuses it until step 4.9. */
  const enforce = () =>
    db.query(
      `INSERT INTO security_controls (organization_id, control, mode, config, version, changed_by, changed_at)
       VALUES ($1, 'admin-step-up', 'enforce', NULL, 1, $2, now())`,
      [orgId, owner.id],
    );

  it("two admins demoting each other at once, each with an approval: one wins, the last admin stays, the other's approval stays unconsumed", async () => {
    const carol = await invite("Carol", "admin");
    await enforce();
    const ownerApproval = await approval(owner, "PATCH", `/v1/organizations/acme/members/${carol.id}`, { role: "member" });
    const carolApproval = await approval(carol, "PATCH", `/v1/organizations/acme/members/${owner.id}`, { role: "member" });

    // Both attempts consume their approval and then wait for each other, so
    // they overlap; SERIALIZABLE lets only one of them commit.
    let arrived = 0;
    const both = deferred();
    const meet = (gate: ProtectedGate): ProtectedGate => ({
      ...gate,
      require: async (tx, binding) => {
        const used = await gate.require(tx, binding);
        if (++arrived === 2) both.resolve();
        await Promise.race([both.promise, sleep(2_000)]);
        return used;
      },
    });
    const demote = (by: Person, approvalId: string, target: Person) =>
      withApproval(ctx, { requester: requester(by), approvalId, publicUrl: PUBLIC_URL }, (gate) =>
        changeMemberRole(ctx, meet(gate), orgId, target.id, "member"));
    const outcomes = await Promise.allSettled([demote(owner, ownerApproval, carol), demote(carol, carolApproval, owner)]);

    // Both consumed in overlapping attempts before either could commit.
    expect(arrived).toBeGreaterThanOrEqual(2);
    expect(outcomes.filter((o) => o.status === "fulfilled")).toHaveLength(1);
    const [lost] = outcomes.filter((o): o is PromiseRejectedResult => o.status === "rejected");
    // The loser's retry finds its requester demoted (or the rule refusing).
    expect(["PERMISSION_DENIED", "VALIDATION_FAILED"]).toContain(lost!.reason.code);
    const admins = (await db.query(
      "SELECT identity_id FROM org_memberships WHERE organization_id = $1 AND role = 'admin' AND removed_at IS NULL",
      [orgId],
    )).rows as { identity_id: string }[];
    expect(admins).toHaveLength(1);
    const winner = admins[0]!.identity_id;
    // The winner's approval was consumed; the loser's rolled back with its attempt.
    expect(await consumedAt(winner === owner.id ? ownerApproval : carolApproval)).not.toBeNull();
    expect(await consumedAt(winner === owner.id ? carolApproval : ownerApproval)).toBeNull();
    expect((await db.query("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'membership.role_changed'")).rows[0]).toEqual({ n: 1 });
  });

  it("a removal that bound the membership's version, racing a demotion: its retry consumes the approval again, finds it stale and removes nobody", async () => {
    const carol = await invite("Carol", "admin");
    await enforce();
    const before = await membership(carol.id);
    const removal = await approval(owner, "DELETE", `/v1/organizations/acme/members/${carol.id}`);
    expect(Number((await db.query("SELECT expected_version FROM approval_intents WHERE id = $1", [removal])).rows[0].expected_version)).toBe(before.version);

    // A demotion holding Carol's membership row, not yet committed. (It
    // holds no lock on the remover, so the removal gets as far as the row.)
    const locked = deferred();
    const release = deferred();
    const demoting = withTx(db, async (tx) => {
      await lockLiveScope(tx, { organizationId: orgId, people: [carol.id] });
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
    await locked.promise;

    // The removal reads the old version (the demotion has not committed),
    // consumes its approval, then waits for the membership's row.
    let attempts = 0;
    let finished = false;
    const removing = withApproval(ctx, { requester: requester(owner), approvalId: removal, publicUrl: PUBLIC_URL }, (gate) =>
      removeMember(ctx, { ...gate, require: async (tx, binding) => { attempts++; return gate.require(tx, binding); } }, orgId, carol.id),
    ).finally(() => { finished = true; });
    removing.catch(() => undefined);
    await sleep(300);
    expect(finished).toBe(false);
    expect(attempts).toBe(1);

    release.resolve();
    await demoting;
    // The first attempt failed to serialize and rolled back with its
    // consumption; the retry consumed again, with the version it now reads.
    await expect(removing).rejects.toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "stale" } });
    expect(attempts).toBe(2);
    expect(await consumedAt(removal)).toBeNull();
    expect(await membership(carol.id)).toEqual({ role: "member", version: before.version + 1, removed: false });
    expect((await db.query("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'membership.removed'")).rows[0]).toEqual({ n: 0 });
  });
  it("a role change that starts during a control change waits for it and runs under the new mode, though its snapshot began first", async () => {
    const dave = await invite("Dave", "member");
    const locked = deferred();
    const release = deferred();
    const change = changeControl(ctx, { require: async () => { throw new Error("no approval expected"); } }, {
      organizationId: orgId,
      control: "admin-step-up",
      mode: "report",
      expectedVersion: 0,
      actorIdentityId: owner.id,
      requestId: "req_test",
      // Runs after the change holds the Organization FOR UPDATE.
      authorizeIn: async () => {
        locked.resolve();
        await release.promise;
      },
    });
    await locked.promise;

    let finished = false;
    const promoting = changeMemberRole(ctx, noApprovalGate(requester(owner)), orgId, dave.id, "admin").finally(() => { finished = true; });
    promoting.catch(() => undefined);
    await sleep(300);
    expect(finished).toBe(false);

    release.resolve();
    expect((await change).control.mode).toBe("report");
    expect(await promoting).toEqual({ identityId: dave.id, role: "admin", previousRole: "member" });
    // Counted under report: it saw the mode the control change committed.
    expect((await db.query(
      "SELECT operation, reason, count::int AS count FROM security_control_counters WHERE organization_id = $1 AND control = 'admin-step-up'",
      [orgId],
    )).rows).toEqual([{ operation: "member.promote", reason: "no-approval", count: 1 }]);
  });
});
