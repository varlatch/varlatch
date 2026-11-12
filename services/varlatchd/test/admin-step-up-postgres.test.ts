// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import { withTx } from "../src/db/tx.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import { reactivateIdentity } from "../src/domain/identities.js";
import { lockLiveScope } from "../src/domain/liveness.js";
import { noApprovalGate } from "../src/domain/protected.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL } from "./helpers/device-sign-in.js";

/**
 * admin-step-up for machine identities on real PostgreSQL (ADR-0054 step
 * 4.5): a reactivation decides whether it needs an approval from an
 * unlocked read, then takes the identity's row. A retirement that commits
 * in between must not let it reactivate without the approval the identity
 * then needs: it is refused with STATE_CHANGED, and nothing changes.
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

  it("a reactivation that read the identity enabled waits for a racing retirement, then refuses with STATE_CHANGED", async () => {
    const created = await call("POST", "/v1/organizations/acme/identities", cli.token, { name: "worker", kind: "workload" });
    expect(created.status).toBe(201);
    const identityId = created.body.id as string;
    // admin-step-up at enforce, written directly: the API refuses it until step 4.9.
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
});
