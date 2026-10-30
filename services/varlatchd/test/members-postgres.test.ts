// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { recordAuditEvent } from "../src/audit/events.js";
import { runMigrations } from "../src/db/migrate.js";
import { createPgQuerier } from "../src/db/pg.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { removeMember } from "../src/domain/members.js";
import { buildApp } from "../src/http/app.js";

/**
 * Member removal under real concurrency (ADR-0052 Decision 2): removal,
 * leaving and role changes are SERIALIZABLE, and the writes they must not
 * miss pin the person's membership, so every race ends as some serial order.
 */

// Always run in CI against a disposable database; never use an installation DB.
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("member removal on real PostgreSQL", () => {
  let server: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let app: ReturnType<typeof buildApp>;
  let admin: { id: string; token: string };
  let orgId: string;
  const database = `varlatch_members_${process.pid}`;
  const ORG = "/v1/organizations/test";

  const call = async (method: string, path: string, body?: unknown, token = admin.token) => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    return { status: res.status, body: await res.json().catch(() => null) };
  };
  const addHuman = async (name: string, role: "admin" | "member") => {
    const invite = await issueInviteGrant(ctx, { organizationId: orgId, role, name }, admin.id);
    const { identityId } = await consumeSetupGrant(ctx, invite.token, {});
    return { id: identityId, token: (await issueCredential(db, { identityId, kind: "cli" })).token };
  };
  const liveAdmins = async () =>
    Number(
      (
        (
          await db.query(
            "SELECT count(*) AS n FROM org_memberships WHERE organization_id = $1 AND role = 'admin' AND removed_at IS NULL",
            [orgId],
          )
        ).rows[0] as { n: string }
      ).n,
    );

  /**
   * Pauses the first transaction statement matching `pattern` until
   * released, so a competing write can run and commit in the gap: after the
   * paused transaction's snapshot, before its own write. Only the first
   * match waits; a retry runs through.
   */
  let gate: { pattern: RegExp; reached: () => void; wait: Promise<void> } | null = null;
  const pauseAt = (pattern: RegExp) => {
    let release!: () => void;
    let reached!: () => void;
    const wait = new Promise<void>((r) => (release = r));
    const arrived = new Promise<void>((r) => (reached = r));
    gate = { pattern, reached, wait };
    return { arrived, release };
  };
  const gated = (pool: ReturnType<typeof createPgQuerier>): ReturnType<typeof createPgQuerier> => ({
    query: (text, params) => pool.query(text, params),
    end: () => pool.end(),
    connect: async () => {
      const client = await pool.connect();
      return {
        release: (destroy?: boolean) => client.release(destroy),
        query: async (text: string, params?: unknown[]) => {
          const g = gate;
          if (g && g.pattern.test(text)) {
            gate = null;
            g.reached();
            await g.wait;
          }
          return client.query(text, params);
        },
      };
    },
  });

  beforeEach(async () => {
    server = createPgQuerier(url!);
    await server.query(`CREATE DATABASE ${database}`);
    const target = new URL(url!);
    target.pathname = `/${database}`;
    db = createPgQuerier(target.toString());
    const connection = await db.connect();
    try {
      await runMigrations(connection);
    } finally {
      connection.release();
    }
    gate = null;
    ctx = { db: gated(db), rootKek: Buffer.alloc(32, 7) };
    await ensureInstallation(ctx);
    const setup = await issueBootstrapGrant(ctx);
    const identityId = (await consumeSetupGrant(ctx, setup.token, {})).identityId;
    admin = { id: identityId, token: (await issueCredential(db, { identityId, kind: "cli" })).token };
    app = buildApp(ctx);
    orgId = (await call("POST", "/v1/organizations", { slug: "test", name: "Test" })).body.id;
  });
  afterEach(async () => {
    await db?.end();
    if (server) {
      await server.query(`DROP DATABASE IF EXISTS ${database}`);
      await server.end();
    }
  });

  it("two admins removing or demoting each other never leave the Organization without an admin", async () => {
    for (let round = 0; round < 6; round++) {
      // A fresh Organization whose only admins are a and b.
      const slug = `pair${round}`;
      orgId = (await call("POST", "/v1/organizations", { slug, name: slug })).body.id;
      const a = await addHuman(`A${round}`, "admin");
      const b = await addHuman(`B${round}`, "admin");
      expect((await call("DELETE", `/v1/organizations/${slug}/members/me`)).status).toBe(200);
      const demote = round % 2 === 1;
      const results = await Promise.all(
        [
          [a, b],
          [b, a],
        ].map(([actor, subject]) =>
          demote
            ? call("PATCH", `/v1/organizations/${slug}/members/${subject!.id}`, { role: "member" }, actor!.token)
            : call("DELETE", `/v1/organizations/${slug}/members/${subject!.id}`, undefined, actor!.token),
        ),
      );
      expect(results.filter((r) => r.status === 200), JSON.stringify(results)).toHaveLength(1);
      expect(await liveAdmins()).toBe(1);
    }
  });

  it("a Grant created after a removal's snapshot, before its write, makes the removal retry and revoke it", async () => {
    await call("POST", `${ORG}/projects`, { name: "API", slug: "api", contractAuthority: "managed" });
    await call("POST", `${ORG}/projects/api/environments`, { name: "production", tier: "production" });
    const bob = await addHuman("Bob", "member");
    const paused = pauseAt(/^UPDATE org_memberships SET removed_at/);
    const removal = call("DELETE", `${ORG}/members/${bob.id}`);
    await paused.arrived;
    const created = await call("POST", `${ORG}/grants`, { subjectIdentityId: bob.id, scope: { kind: "organization" }, actions: ["secret.reveal"] });
    expect(created.status).toBe(201);
    paused.release();
    const removed = await removal;
    expect(removed.status, JSON.stringify(removed.body)).toBe(200);
    // The retry saw the Grant: revoked, and in the snapshot.
    expect(removed.body.grantsRevoked).toBe(1);
    expect((await db.query("SELECT id FROM grants WHERE subject_identity_id = $1 AND revoked_at IS NULL", [bob.id])).rows).toEqual([]);
    expect(
      (await db.query("SELECT 1 FROM removal_authority WHERE grant_id = $1", [created.body.id])).rows.length,
    ).toBeGreaterThan(0);
  });

  it("a Grant created after a removal's write is refused", async () => {
    const bob = await addHuman("Bob", "member");
    const paused = pauseAt(/^INSERT INTO audit_events/);
    const removal = call("DELETE", `${ORG}/members/${bob.id}`);
    await paused.arrived;
    // The removal holds the membership row: the Grant waits for it, then finds no live membership.
    const creating = call("POST", `${ORG}/grants`, { subjectIdentityId: bob.id, scope: { kind: "organization" }, actions: ["audit.read"] });
    await new Promise((r) => setTimeout(r, 100));
    paused.release();
    expect((await removal).status).toBe(200);
    expect((await creating).status).toBe(404);
  });

  it("replacing a Grant locks the membership before the Grant, as removal does: no deadlock", async () => {
    const bob = await addHuman("Bob", "member");
    const original = (await call("POST", `${ORG}/grants`, { subjectIdentityId: bob.id, scope: { kind: "organization" }, actions: ["audit.read"] })).body.id as string;
    const paused = pauseAt(/^SELECT kind, organization_id FROM identities/);
    const replacing = call("POST", `${ORG}/grants/${original}/replace`, {
      subjectIdentityId: bob.id,
      scope: { kind: "organization" },
      actions: ["policy.read"],
    });
    await paused.arrived;
    // Paused before pinning the membership, the replacement holds no lock on the Grant yet.
    const probe = await db.connect();
    try {
      await probe.query("BEGIN");
      await probe.query("SELECT id FROM grants WHERE id = $1 FOR UPDATE NOWAIT", [original]);
      await probe.query("ROLLBACK");
    } finally {
      probe.release();
    }
    // So a removal runs through, revoking the original.
    const removed = await call("DELETE", `${ORG}/members/${bob.id}`);
    expect(removed.status).toBe(200);
    expect(removed.body.grantsRevoked).toBe(1);
    paused.release();
    // Then the replacement finds no live membership.
    expect((await replacing).status).toBe(404);
    expect((await db.query("SELECT id FROM grants WHERE subject_identity_id = $1 AND revoked_at IS NULL", [bob.id])).rows).toEqual([]);
  });

  it("a Grant replaced between a removal's snapshot and its write is revoked by the retry", async () => {
    const bob = await addHuman("Bob", "member");
    const original = (await call("POST", `${ORG}/grants`, { subjectIdentityId: bob.id, scope: { kind: "organization" }, actions: ["audit.read"] })).body.id as string;
    const paused = pauseAt(/^UPDATE org_memberships SET removed_at/);
    const removal = call("DELETE", `${ORG}/members/${bob.id}`);
    await paused.arrived;
    const replaced = await call("POST", `${ORG}/grants/${original}/replace`, {
      subjectIdentityId: bob.id,
      scope: { kind: "organization" },
      actions: ["policy.read"],
    });
    expect([200, 201]).toContain(replaced.status);
    paused.release();
    const removed = await removal;
    expect(removed.status).toBe(200);
    expect(removed.body.grantsRevoked).toBe(1);
    expect((await db.query("SELECT id FROM grants WHERE subject_identity_id = $1 AND revoked_at IS NULL", [bob.id])).rows).toEqual([]);
  });

  it("a group link added after a removal's snapshot makes the removal retry and remove it", async () => {
    const bob = await addHuman("Bob", "member");
    const group = (await call("POST", `${ORG}/groups`, { name: "ops" })).body.id as string;
    const paused = pauseAt(/^UPDATE org_memberships SET removed_at/);
    const removal = call("DELETE", `${ORG}/members/${bob.id}`);
    await paused.arrived;
    expect((await call("POST", `${ORG}/groups/${group}/members`, { identityId: bob.id })).status).toBe(204);
    paused.release();
    const removed = await removal;
    expect(removed.status).toBe(200);
    expect(removed.body.groupsLeft).toBe(1);
    expect((await db.query("SELECT 1 FROM group_members WHERE identity_id = $1", [bob.id])).rows).toEqual([]);
  });

  it("an invitation the removed person issued is either accepted first or revoked, without deadlock", async () => {
    for (let round = 0; round < 10; round++) {
      const bob = await addHuman(`Bob${round}`, "admin");
      const invite = await issueInviteGrant(ctx, { organizationId: orgId, role: "member", name: `Guest${round}` }, bob.id);
      const [accepted, removed] = await Promise.allSettled([
        consumeSetupGrant(ctx, invite.token, {}),
        removeMember(ctx, orgId, bob.id, { id: admin.id, kind: "human" }),
      ]);
      expect(removed.status).toBe("fulfilled");
      const row = (await db.query("SELECT consumed_at, revoked_at FROM setup_grants WHERE id = $1", [invite.id])).rows[0] as {
        consumed_at: string | null;
        revoked_at: string | null;
      };
      if (accepted.status === "fulfilled") {
        expect(row).toMatchObject({ revoked_at: null });
        expect(row.consumed_at).not.toBeNull();
        expect((removed as PromiseFulfilledResult<{ invitationsRevoked: number }>).value.invitationsRevoked).toBe(0);
      } else {
        expect(row.revoked_at).not.toBeNull();
        expect(row.consumed_at).toBeNull();
      }
    }
  });

  it("an invitation issued after a removal's snapshot makes the removal retry and revoke it", async () => {
    const bob = await addHuman("Bob", "admin");
    const paused = pauseAt(/^UPDATE org_memberships SET removed_at/);
    const removal = call("DELETE", `${ORG}/members/${bob.id}`);
    await paused.arrived;
    const issued = await call("POST", `${ORG}/invitations`, { name: "Guest", role: "admin" }, bob.token);
    expect(issued.status).toBe(201);
    paused.release();
    const removed = await removal;
    expect(removed.status).toBe(200);
    expect(removed.body.invitationsRevoked).toBe(1);
    const row = (await db.query("SELECT revoked_at FROM setup_grants WHERE id = $1", [issued.body.id])).rows[0] as { revoked_at: string | null };
    expect(row.revoked_at).not.toBeNull();
  });

  it("completes under unrelated audit traffic, retrying a bounded number of times", async () => {
    const bob = await addHuman("Bob", "member");
    let stop = false;
    const traffic = (async () => {
      let n = 0;
      while (!stop) {
        await recordAuditEvent(db, { eventType: "test.noise", decision: "info", metadata: { n: n++ } });
      }
    })();
    try {
      const removed = await call("DELETE", `${ORG}/members/${bob.id}`);
      // Either it got through, or it gave up with the retryable error and changed nothing.
      if (removed.status === 409) {
        expect(removed.body.error).toMatchObject({ code: "STATE_CHANGED", details: { retryable: true } });
        expect(
          (await db.query("SELECT removed_at FROM org_memberships WHERE identity_id = $1", [bob.id])).rows[0],
        ).toEqual({ removed_at: null });
      } else {
        expect(removed.status).toBe(200);
      }
    } finally {
      stop = true;
      await traffic;
    }
  });
});
