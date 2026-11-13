// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import { withTx } from "../src/db/tx.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { withApproval, type Requester } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import { reactivateIdentity } from "../src/domain/identities.js";
import { lockLiveScope } from "../src/domain/liveness.js";
import { noApprovalGate } from "../src/domain/protected.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { registerSoftPasskey } from "./helpers/soft-authenticator.js";

/**
 * admin-step-up for machine identities on real PostgreSQL (ADR-0054 step
 * 4.5): a reactivation decides whether it needs an approval from an
 * unlocked read, then takes the identity's row. A retirement that commits
 * in between must not let it reactivate without the approval the identity
 * then needs: it is refused with STATE_CHANGED, and nothing changes. A
 * reactivation by someone else that commits in between leaves nothing to
 * do: the approval is used and the request succeeds, changing nothing.
 */
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("admin-step-up on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let app: ReturnType<typeof buildApp>;
  let orgId: string;
  let adminId: string;
  let cli: { token: string; credentialId: string };
  const database = `varlatch_stepup_test_${process.pid}`;

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

  beforeEach(async () => {
    admin = createPgQuerier(url!);
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${database}`);
    const target = new URL(url!);
    target.pathname = `/${database}`;
    db = createPgQuerier(target.toString());
    const connection = await db.connect();
    try { await runMigrations(connection); } finally { connection.release(); }
    ctx = { db, rootKek: Buffer.alloc(32, 45) };
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
  const enforceAdminStepUp = () =>
    db.query(
      `INSERT INTO security_controls (organization_id, control, mode, config, version, changed_by, changed_at)
       VALUES ($1, 'admin-step-up', 'enforce', NULL, 1, $2, now())`,
      [orgId, adminId],
    );

  /** A transaction holding the identity's row with `disabled` set to `disabled`, until released. */
  const holdIdentity = async (identityId: string, disabled: boolean) => {
    const locked = deferred();
    const release = deferred();
    const done = withTx(db, async (tx) => {
      await lockLiveScope(tx, { organizationId: orgId, people: [adminId, { id: identityId, mode: "update" }] });
      await tx.query("UPDATE identities SET disabled = $2 WHERE id = $1", [identityId, disabled]);
      locked.resolve();
      await release.promise;
    });
    await locked.promise;
    return { release: release.resolve, done };
  };

  it("a reactivation that read the identity enabled waits for a racing retirement, then refuses with STATE_CHANGED", async () => {
    const created = await call("POST", "/v1/organizations/acme/identities", cli.token, { name: "worker", kind: "workload" });
    expect(created.status).toBe(201);
    const identityId = created.body.id as string;
    // admin-step-up at enforce, written directly in the database (the API accepts it since step 4.9).
    await db.query(
      `INSERT INTO security_controls (organization_id, control, mode, config, version, changed_by, changed_at)
       VALUES ($1, 'admin-step-up', 'enforce', NULL, 1, $2, now())`,
      [orgId, adminId],
    );

    // A retirement holding the identity's row, not yet committed.
    const locked = deferred();
    const release = deferred();
    const retiring = withTx(db, async (tx) => {
      await lockLiveScope(tx, { organizationId: orgId, people: [adminId, { id: identityId, mode: "update" }] });
      await tx.query("UPDATE identities SET disabled = true WHERE id = $1", [identityId]);
      locked.resolve();
      await release.promise;
    });
    await locked.promise;

    // The reactivation reads it enabled (the retirement has not committed),
    // so it asks for no approval, then waits for the row.
    const gate = noApprovalGate({ identityId: adminId, identityKind: "human", credentialId: cli.credentialId, credentialKind: "cli" });
    let finished = false;
    const reactivating = reactivateIdentity(ctx, gate, orgId, identityId).finally(() => { finished = true; });
    reactivating.catch(() => undefined);
    await sleep(300);
    expect(finished).toBe(false);

    release.resolve();
    await retiring;
    await expect(reactivating).rejects.toMatchObject({ code: "STATE_CHANGED" });
    expect((await db.query("SELECT disabled FROM identities WHERE id = $1", [identityId])).rows[0]).toEqual({ disabled: true });
    expect((await db.query("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'identity.reactivated'")).rows[0]).toEqual({ n: 0 });

    // Asked again, it now needs the approval a disabled identity needs.
    await expect(reactivateIdentity(ctx, gate, orgId, identityId)).rejects.toMatchObject({ name: "ApprovalNeeded" });
  });

  it("a reactivation that read the identity disabled, racing another reactivation, uses its approval and changes nothing", async () => {
    const created = await call("POST", "/v1/organizations/acme/identities", cli.token, { name: "worker", kind: "workload" });
    const identityId = created.body.id as string;
    expect((await call("POST", `/v1/organizations/acme/identities/${identityId}/retire`, cli.token)).status).toBe(200);
    await enforceAdminStepUp();

    // Asked through the API, then approved directly (the ceremony is covered on PGlite).
    const asked = await call("POST", `/v1/organizations/acme/identities/${identityId}/reactivate`, cli.token);
    expect(asked.body?.error?.code, JSON.stringify(asked.body)).toBe("STEP_UP_REQUIRED");
    const approvalId = asked.body.error.details.approval.id as string;
    const key = await registerSoftPasskey(db, adminId, { ...RP, trust: "trusted" });
    await db.query(
      "UPDATE approval_intents SET approved_at = clock_timestamp(), approved_with_passkey_id = $2, approval_user_verified = true WHERE id = $1",
      [approvalId, key.passkeyId],
    );

    // Someone else's reactivation holds the row, not yet committed: the
    // request reads the identity disabled, so it needs its approval, then waits.
    const other = await holdIdentity(identityId, false);
    const requester: Requester = { identityId: adminId, identityKind: "human", credentialId: cli.credentialId, credentialKind: "cli" };
    let finished = false;
    const reactivating = withApproval(ctx, { requester, approvalId, publicUrl: PUBLIC_URL }, (gate) => reactivateIdentity(ctx, gate, orgId, identityId))
      .finally(() => { finished = true; });
    reactivating.catch(() => undefined);
    await sleep(300);
    expect(finished).toBe(false);

    other.release();
    await other.done;
    await reactivating;
    expect((await db.query("SELECT disabled FROM identities WHERE id = $1", [identityId])).rows[0]).toEqual({ disabled: false });
    expect((await db.query("SELECT consumed_at IS NOT NULL AS used FROM approval_intents WHERE id = $1", [approvalId])).rows[0]).toEqual({ used: true });
    const audited = (await db.query("SELECT metadata FROM audit_events WHERE event_type = 'identity.reactivated'")).rows as { metadata: Record<string, unknown> }[];
    expect(audited).toHaveLength(1);
    expect(audited[0]!.metadata).toMatchObject({ approvalId });
  });
});
