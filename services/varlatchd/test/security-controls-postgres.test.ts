// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import { withTx } from "../src/db/tx.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import { APPROVALS, consumeApproval, type ApprovalGate, type ApprovalBinding, type Requester } from "../src/domain/approvals.js";
import { lockLiveScope } from "../src/domain/liveness.js";
import { changeControl, controlMode } from "../src/domain/securitycontrols.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { registerSoftPasskey } from "./helpers/soft-authenticator.js";

/**
 * Security Controls under concurrency, on real PostgreSQL (ADR-0054
 * Decisions 2 and 3): a control change locks the Organization row FOR
 * UPDATE, a protected write takes it FOR KEY SHARE and reads the mode
 * after that lock, so the write either commits first or sees the new mode;
 * one approval is consumed once however many requests race for it; the
 * per-credential cap holds when requests arrive together.
 */
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("Security Controls on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let app: ReturnType<typeof buildApp>;
  let orgId: string;
  let adminId: string;
  let cli: { token: string; credentialId: string };
  const database = `varlatch_secctl_test_${process.pid}`;

  const call = async (method: string, path: string, token: string, body?: unknown, headers: Record<string, string> = {}) => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null };
  };

  beforeEach(async () => {
    admin = createPgQuerier(url!);
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${database}`);
    const target = new URL(url!);
    target.pathname = `/${database}`;
    db = createPgQuerier(target.toString());
    const connection = await db.connect();
    try { await runMigrations(connection); } finally { connection.release(); }
    ctx = { db, rootKek: Buffer.alloc(32, 41) };
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

  const noApproval: ApprovalGate = { require: async () => { throw new Error("no approval expected"); } };
  const deferred = () => {
    let resolve!: () => void;
    const promise = new Promise<void>((r) => { resolve = r; });
    return { promise, resolve };
  };
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  /** A protected write: the Organization FOR KEY SHARE, then the mode, read after the lock. */
  const protectedWrite = (onLocked?: () => Promise<void>) =>
    withTx(db, async (tx) => {
      await lockLiveScope(tx, { organizationId: orgId });
      await onLocked?.();
      return controlMode(tx, orgId, "admin-step-up");
    });

  it("a protected write that starts during a control change waits for it and sees the new mode", async () => {
    const locked = deferred();
    const release = deferred();
    const change = changeControl(ctx, noApproval, {
      organizationId: orgId,
      control: "admin-step-up",
      mode: "report",
      expectedVersion: 0,
      actorIdentityId: adminId,
      requestId: "req_test",
      // Runs after the change holds the Organization FOR UPDATE.
      authorizeIn: async () => {
        locked.resolve();
        await release.promise;
      },
    });
    await locked.promise;
    let finished = false;
    const write = protectedWrite().then((mode) => { finished = true; return mode; });
    await sleep(300);
    expect(finished).toBe(false);
    release.resolve();
    expect((await change).control.mode).toBe("report");
    expect(await write).toBe("report");
  });

  it("a control change that starts during a protected write waits for the write to commit", async () => {
    const locked = deferred();
    const release = deferred();
    const write = protectedWrite(async () => {
      locked.resolve();
      await release.promise;
    });
    await locked.promise;
    let changed = false;
    const change = changeControl(ctx, noApproval, {
      organizationId: orgId,
      control: "admin-step-up",
      mode: "report",
      expectedVersion: 0,
      actorIdentityId: adminId,
      requestId: "req_test",
      authorizeIn: async () => undefined,
    }).then((r) => { changed = true; return r; });
    await sleep(300);
    expect(changed).toBe(false);
    release.resolve();
    // The write committed under the old mode; the change came after it.
    expect(await write).toBe("off");
    expect((await change).control).toMatchObject({ mode: "report", version: 1 });
  });

  it("consumes one approval once, however many requests race for it", async () => {
    expect((await call("PATCH", "/v1/organizations/acme/security/controls/admin-step-up", cli.token, { mode: "report", expectedVersion: 0 })).status).toBe(200);
    const asked = await call("PATCH", "/v1/organizations/acme/security/controls/admin-step-up", cli.token, { mode: "off", expectedVersion: 1 });
    expect(asked.body.error.code).toBe("STEP_UP_REQUIRED");
    const approvalId = asked.body.error.details.approval.id as string;
    // Approved directly: the WebAuthn ceremony is covered on PGlite.
    const key = await registerSoftPasskey(db, adminId, { ...RP, trust: "trusted" });
    await db.query(
      "UPDATE approval_intents SET approved_at = clock_timestamp(), approved_with_passkey_id = $2, approval_user_verified = true WHERE id = $1",
      [approvalId, key.passkeyId],
    );
    const requester: Requester = { identityId: adminId, identityKind: "human", credentialId: cli.credentialId, credentialKind: "cli" };
    const binding: ApprovalBinding = {
      operation: "security_control.change", organizationId: orgId, target: { control: "admin-step-up" },
      body: { mode: "off", config: null, expectedVersion: 1 }, query: {}, expectedVersion: 1, summary: { title: "", changes: [] },
    };
    const attempts = await Promise.allSettled(
      Array.from({ length: 6 }, () => withTx(db, async (tx) => {
        const used = await consumeApproval(tx, ctx.rootKek, requester, approvalId, binding);
        await sleep(50);
        return used;
      })),
    );
    expect(attempts.filter((a) => a.status === "fulfilled")).toHaveLength(1);
    for (const a of attempts.filter((a) => a.status === "rejected")) {
      expect((a as PromiseRejectedResult).reason).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "consumed" } });
    }
  });

  it("holds the open-approvals cap per credential when requests arrive together", async () => {
    expect((await call("PATCH", "/v1/organizations/acme/security/controls/admin-step-up", cli.token, { mode: "report", expectedVersion: 0 })).status).toBe(200);
    const answers = await Promise.all(
      Array.from({ length: 9 }, () =>
        call("PATCH", "/v1/organizations/acme/security/controls/admin-step-up", cli.token, { mode: "off", expectedVersion: 1 })),
    );
    expect(answers.filter((a) => a.body.error?.code === "STEP_UP_REQUIRED")).toHaveLength(APPROVALS.openPerCredential);
    expect(answers.filter((a) => a.body.error?.code === "RATE_LIMITED")).toHaveLength(9 - APPROVALS.openPerCredential);
    expect((await db.query("SELECT count(*)::int AS n FROM approval_intents")).rows).toEqual([{ n: APPROVALS.openPerCredential }]);
  });
});
