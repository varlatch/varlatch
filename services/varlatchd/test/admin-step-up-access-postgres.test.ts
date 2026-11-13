// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import { lockedQuery } from "../src/db/locks.js";
import { withTx } from "../src/db/tx.js";
import type { AppCtx } from "../src/domain/ctx.js";
import type { ProtectedGate } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import { lockLiveScope } from "../src/domain/liveness.js";
import { addGroupMember, deleteRole } from "../src/domain/policy.js";
import { noApprovalGate } from "../src/domain/protected.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL } from "./helpers/device-sign-in.js";

/**
 * admin-step-up for the access structure on real PostgreSQL (ADR-0054
 * step 4.6). Each operation decides what it binds from an unlocked read,
 * then takes its rows:
 *
 * - a role deletion binds the version it read; an edit that commits in
 *   between makes the approval stale under the row lock (STATE_CHANGED),
 *   and the consumption rolls back with the attempt;
 * - adding a current member needs no approval; a removal that commits in
 *   between must not let it add the member without the approval it then
 *   needs: it is refused with STATE_CHANGED, and nothing changes.
 */
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("admin-step-up for the access structure on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let app: ReturnType<typeof buildApp>;
  let orgId: string;
  let adminId: string;
  let cli: { token: string; credentialId: string };
  const database = `varlatch_stepup_access_test_${process.pid}`;

  const call = async (method: string, path: string, token: string, body?: unknown) => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
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
  const requester = () => ({ identityId: adminId, identityKind: "human", credentialId: cli.credentialId, credentialKind: "cli" });

  /**
   * A gate that holds an approval: it stands in for consumeApproval (whose
   * own checks the PGlite suites cover), recording what it was asked to
   * consume, so the race after consumption runs without a passkey.
   */
  const approvingGate = (consumed: unknown[]): ProtectedGate => ({
    requester: requester(),
    approvalId: "apr_test",
    require: async (_db, binding) => {
      consumed.push(binding);
      return { id: "apr_test", passkeyId: "pk_test", userVerified: true };
    },
  });

  beforeEach(async () => {
    admin = createPgQuerier(url!);
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${database}`);
    const target = new URL(url!);
    target.pathname = `/${database}`;
    db = createPgQuerier(target.toString());
    const connection = await db.connect();
    try { await runMigrations(connection); } finally { connection.release(); }
    ctx = { db, rootKek: Buffer.alloc(32, 46) };
    await ensureInstallation(ctx);
    adminId = (await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" })).identityId;
    cli = await issueCredential(db, { identityId: adminId, kind: "cli" });
    app = buildApp(ctx, { publicUrl: PUBLIC_URL });
    orgId = (await call("POST", "/v1/organizations", cli.token, { name: "Acme", slug: "acme" })).body.id;
  });
  afterEach(async () => {
    await db?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
      await admin.end();
    }
  });

  /** admin-step-up at enforce, written directly in the database (the API accepts it since step 4.9). */
  const enforce = () =>
    db.query(
      `INSERT INTO security_controls (organization_id, control, mode, config, version, changed_by, changed_at)
       VALUES ($1, 'admin-step-up', 'enforce', NULL, 1, $2, now())`,
      [orgId, adminId],
    );

  it("a role deletion that bound the version it read waits for a racing edit, then refuses with STATE_CHANGED", async () => {
    const role = await call("POST", "/v1/organizations/acme/roles", cli.token, { name: "reader", actions: ["project.read"] });
    expect(role.status).toBe(201);
    const roleId = role.body.id as string;
    await enforce();

    // An edit holding the role's row, not yet committed.
    const locked = deferred();
    const release = deferred();
    const editing = withTx(db, async (tx) => {
      await lockLiveScope(tx, { organizationId: orgId, people: [adminId] });
      await lockedQuery(tx, { table: "roles", mode: "update" }, "SELECT id FROM roles WHERE id = $1 FOR UPDATE", [roleId]);
      await tx.query("UPDATE roles SET actions = $1, version = version + 1 WHERE id = $2", [["project.read", "config.value.write"], roleId]);
      locked.resolve();
      await release.promise;
    });
    await locked.promise;

    // The deletion reads version 1 (the edit has not committed) and binds
    // it, then waits (for the requester, whom the edit holds, and the row).
    const consumed: { expectedVersion: number | null }[] = [];
    let finished = false;
    const deleting = deleteRole(ctx, approvingGate(consumed), orgId, roleId).finally(() => { finished = true; });
    deleting.catch(() => undefined);
    await sleep(300);
    expect(finished).toBe(false);

    release.resolve();
    await editing;
    // It consumed its approval for version 1, then found version 2 under the
    // row lock: the attempt rolls back, consumption included.
    await expect(deleting).rejects.toMatchObject({ code: "STATE_CHANGED" });
    expect(consumed).toEqual([expect.objectContaining({ operation: "role.delete", expectedVersion: 1 })]);
    expect((await db.query("SELECT version, revoked_at FROM roles WHERE id = $1", [roleId])).rows[0]).toEqual({ version: 2, revoked_at: null });
    expect((await db.query("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'role.deleted'")).rows[0]).toEqual({ n: 0 });
  });

  it("adding a member who was one when it read waits for a racing removal, then refuses with STATE_CHANGED", async () => {
    const svc = await call("POST", "/v1/organizations/acme/identities", cli.token, { name: "api", kind: "service" });
    const group = await call("POST", "/v1/organizations/acme/groups", cli.token, { name: "oncall" });
    expect((await call("POST", `/v1/organizations/acme/groups/${group.body.id}/members`, cli.token, { identityId: svc.body.id })).status).toBe(204);
    const [groupId, identityId] = [group.body.id as string, svc.body.id as string];
    await enforce();

    // A removal holding the membership's row, not yet committed.
    const locked = deferred();
    const release = deferred();
    const removing = withTx(db, async (tx) => {
      await lockLiveScope(tx, { organizationId: orgId, people: [adminId] });
      await tx.query("DELETE FROM group_members WHERE group_id = $1 AND identity_id = $2", [groupId, identityId]);
      locked.resolve();
      await release.promise;
    });
    await locked.promise;

    // The addition reads the membership (the removal has not committed), so
    // it asks for no approval, then waits for the row.
    const gate = noApprovalGate(requester());
    let finished = false;
    const adding = addGroupMember(ctx, gate, orgId, groupId, identityId).finally(() => { finished = true; });
    adding.catch(() => undefined);
    await sleep(300);
    expect(finished).toBe(false);

    release.resolve();
    await removing;
    await expect(adding).rejects.toMatchObject({ code: "STATE_CHANGED" });
    expect((await db.query("SELECT count(*)::int AS n FROM group_members WHERE group_id = $1", [groupId])).rows[0]).toEqual({ n: 0 });

    // Asked again, it now needs the approval a new membership needs.
    await expect(addGroupMember(ctx, gate, orgId, groupId, identityId)).rejects.toMatchObject({ name: "ApprovalNeeded" });
  });
});
