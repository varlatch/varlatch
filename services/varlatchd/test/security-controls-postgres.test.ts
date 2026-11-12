// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import { withTx } from "../src/db/tx.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { completePublicUrlChange, consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant, issueReenrollmentGrants } from "../src/domain/bootstrap.js";
import { approveDeviceSignIn, findSignInByCode, issueApprovalChallenge, requestDeviceSignIn } from "../src/domain/device-sign-in.js";
import { lockPeople, lockPerson } from "../src/domain/personlocks.js";
import { finalizeDeletion } from "../src/domain/orgdeletion.js";
import { APPROVALS, consumeApproval, createApproval, startApproval, type ApprovalGate, type ApprovalBinding, type Requester } from "../src/domain/approvals.js";
import { lockLiveScope } from "../src/domain/liveness.js";
import { changeControl, controlMode, resetControls } from "../src/domain/securitycontrols.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { registerSoftPasskey } from "./helpers/soft-authenticator.js";

/**
 * Security Controls under concurrency, on real PostgreSQL (ADR-0054
 * Decisions 2 and 3): a control change locks the Organization row FOR
 * UPDATE, a protected write takes it FOR KEY SHARE and reads the mode
 * after that lock, so the write either commits first or sees the new mode;
 * one approval is consumed once however many requests race for it; the
 * per-credential cap holds when requests arrive together; starting and
 * approving take the person's row before the approval's, so they never
 * deadlock, and the per-person challenge cap holds across approvals.
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

  /** A gate that consumes `approvalId` for the requester, like withApproval with the header. */
  const withApprovalGate = <T,>(requester: Requester, approvalId: string, run: (gate: ApprovalGate) => Promise<T>) =>
    run({ require: (tx, binding) => consumeApproval(tx, ctx.rootKek, requester, approvalId, binding) });
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

  describe("requirement-protection enforced (ADR-0054 step 4.2)", () => {
    const REQS = "/v1/organizations/acme/requirements";
    /** Ask for an approval with `request`, then approve it directly (the ceremony is covered on PGlite). */
    const approved = async (request: () => Promise<{ status: number; body: any }>) => {
      const asked = await request();
      expect(asked.body?.error?.code, JSON.stringify(asked.body)).toBe("STEP_UP_REQUIRED");
      const id = asked.body.error.details.approval.id as string;
      const key = await registerSoftPasskey(db, adminId, { ...RP, trust: "trusted" });
      await db.query(
        "UPDATE approval_intents SET approved_at = clock_timestamp(), approved_with_passkey_id = $2, approval_user_verified = true WHERE id = $1",
        [id, key.passkeyId],
      );
      return id;
    };
    const setup = async () => {
      expect((await call("PATCH", "/v1/organizations/acme/security/controls/requirement-protection", cli.token, { mode: "enforce", expectedVersion: 0 })).status).toBe(200);
      const created = await call("POST", REQS, cli.token, { kind: "tailnet", target: { kind: "tier", tier: "production" }, selector: { tailnet: "example.ts.net", tags: ["tag:prod"] } });
      expect(created.status).toBe(201);
      return created.body.id as string;
    };

    it("revocations racing with one approval: one revokes, the others are refused, none deadlocks", async () => {
      const id = await setup();
      const approval = await approved(() => call("DELETE", `${REQS}/${id}`, cli.token));
      const answers = await Promise.all(
        Array.from({ length: 6 }, () => call("DELETE", `${REQS}/${id}`, cli.token, undefined, { "Varlatch-Approval": approval })),
      );
      expect(answers.filter((a) => a.status === 204)).toHaveLength(1);
      for (const a of answers.filter((a) => a.status !== 204)) {
        // Refused before or at consumption: already revoked, or already used.
        expect(["RESOURCE_NOT_FOUND", "APPROVAL_INVALID"]).toContain(a.body.error.code);
      }
      expect((await db.query("SELECT count(*)::int AS n FROM approval_intents WHERE consumed_at IS NOT NULL")).rows[0]).toEqual({ n: 1 });
    });

    it("an approved edit and an approved revocation of one Requirement race without a deadlock; the loser's approval stays unused", async () => {
      const id = await setup();
      const body = { expectedVersion: 1, selector: { tailnet: "example.ts.net", tags: ["tag:prod", "tag:ops"] } };
      const editApproval = await approved(() => call("PATCH", `${REQS}/${id}`, cli.token, body));
      const revokeApproval = await approved(() => call("DELETE", `${REQS}/${id}`, cli.token));
      const [edit, revoke] = await Promise.all([
        call("PATCH", `${REQS}/${id}`, cli.token, body, { "Varlatch-Approval": editApproval }),
        call("DELETE", `${REQS}/${id}`, cli.token, undefined, { "Varlatch-Approval": revokeApproval }),
      ]);
      expect([edit.status, revoke.status].filter((s) => s >= 500)).toEqual([]);
      const consumed = (await db.query("SELECT id FROM approval_intents WHERE consumed_at IS NOT NULL")).rows as { id: string }[];
      // Exactly one commits: the other finds the version it bound changed
      // (stale, or STATE_CHANGED under the row lock) or the Requirement gone.
      expect([edit.status === 200, revoke.status === 204].filter(Boolean)).toHaveLength(1);
      expect(consumed.map((r) => r.id)).toEqual([edit.status === 200 ? editApproval : revokeApproval]);
    });
  });

  describe("credential-lifetime enforced (ADR-0054 step 4.3)", () => {
    const IDENTITIES = "/v1/organizations/acme/identities";
    const LIFETIMES = { defaultTtlSeconds: 3600, maxTtlSeconds: 86_400 };

    it("an issuance that starts during the change to enforce waits for it, then gets the default", async () => {
      const machine = await call("POST", IDENTITIES, cli.token, { name: "m", kind: "service" });
      expect(machine.body.credentialExpiresAt).toBeNull();
      const locked = deferred();
      const release = deferred();
      const change = changeControl(ctx, noApproval, {
        organizationId: orgId,
        control: "credential-lifetime",
        mode: "enforce",
        config: LIFETIMES,
        expectedVersion: 0,
        actorIdentityId: adminId,
        requestId: "req_test",
        authorizeIn: async () => {
          locked.resolve();
          await release.promise;
        },
      });
      await locked.promise;
      let finished = false;
      const issued = call("POST", `${IDENTITIES}/${machine.body.id}/credentials`, cli.token, { name: "during" })
        .then((r) => { finished = true; return r; });
      const refused = call("POST", `${IDENTITIES}/${machine.body.id}/credentials`, cli.token, { name: "long", ttlSeconds: LIFETIMES.maxTtlSeconds + 1 });
      await sleep(300);
      expect(finished).toBe(false);
      release.resolve();
      expect((await change).control.mode).toBe("enforce");
      const answer = await issued;
      expect(answer.status, JSON.stringify(answer.body)).toBe(201);
      const left = (Date.parse(answer.body.expiresAt) - Date.now()) / 1000;
      expect(left).toBeGreaterThan(LIFETIMES.defaultTtlSeconds - 60);
      expect(left).toBeLessThanOrEqual(LIFETIMES.defaultTtlSeconds);
      expect((await refused).body.error.code).toBe("CREDENTIAL_LIFETIME_EXCEEDED");
    });

    it("issuances racing with lifetime changes never deadlock, and each follows the state it committed under", async () => {
      expect((await call("PATCH", "/v1/organizations/acme/security/controls/credential-lifetime", cli.token, { mode: "enforce", config: LIFETIMES, expectedVersion: 0 })).status).toBe(200);
      const machine = await call("POST", IDENTITIES, cli.token, { name: "m", kind: "service" });
      const shorter = { defaultTtlSeconds: 600, maxTtlSeconds: 7200 };
      const [tightened, ...answers] = await Promise.all([
        call("PATCH", "/v1/organizations/acme/security/controls/credential-lifetime", cli.token, { config: shorter, expectedVersion: 1 }),
        ...Array.from({ length: 6 }, (_, i) =>
          i % 2 === 0
            ? call("POST", `${IDENTITIES}/${machine.body.id}/credentials`, cli.token, { name: `c${i}` })
            : call("POST", IDENTITIES, cli.token, { name: `m${i}`, kind: "service", credentialTtlSeconds: 43_200 })),
      ]);
      expect(tightened.status).toBe(200);
      const near = (left: number, ttl: number) => left > ttl - 60 && left <= ttl;
      answers.forEach((a, i) => {
        const defaulted = i % 2 === 0;
        // Committed before the change (the old default, or 12 hours under the
        // old maximum), or after it (the new default, or refused above the new one).
        if (a.status === 422) {
          expect(defaulted, "only the 12-hour requests can exceed a maximum").toBe(false);
          expect(a.body.error.code).toBe("CREDENTIAL_LIFETIME_EXCEEDED");
          return;
        }
        expect(a.status, JSON.stringify(a.body)).toBe(201);
        const left = (Date.parse(a.body.expiresAt ?? a.body.credentialExpiresAt) - Date.now()) / 1000;
        const allowed = defaulted ? [LIFETIMES.defaultTtlSeconds, shorter.defaultTtlSeconds] : [43_200];
        expect(allowed.some((ttl) => near(left, ttl)), `${left}s left, expected one of ${allowed.join(", ")}`).toBe(true);
      });
      // After the change, the new maximum holds: 12 hours is refused, the default is the new one.
      const late = await call("POST", IDENTITIES, cli.token, { name: "late", kind: "service", credentialTtlSeconds: 43_200 });
      expect(late.body.error.code).toBe("CREDENTIAL_LIFETIME_EXCEEDED");
      const lateDefault = await call("POST", `${IDENTITIES}/${machine.body.id}/credentials`, cli.token, { name: "late-default" });
      expect(near((Date.parse(lateDefault.body.expiresAt) - Date.now()) / 1000, shorter.defaultTtlSeconds)).toBe(true);
    });
  });

  /** A browser bearer of the admin for one Better Auth session. */
  const browser = async (sessionId: string) =>
    (await issueCredential(db, {
      identityId: adminId, kind: "browser", authSessionId: sessionId,
      expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
    })).token;
  /** A pending approval for turning admin-step-up off, asked for by a CLI credential of its own. */
  const pendingApproval = async () => {
    const token = (await issueCredential(db, { identityId: adminId, kind: "cli" })).token;
    const asked = await call("PATCH", "/v1/organizations/acme/security/controls/admin-step-up", token, { mode: "off", expectedVersion: 1 });
    expect(asked.body.error.code, JSON.stringify(asked.body)).toBe("STEP_UP_REQUIRED");
    return asked.body.error.details.approval.id as string;
  };

  it("starting and approving one approval at once never deadlock: both take the person, then the approval", async () => {
    expect((await call("PATCH", "/v1/organizations/acme/security/controls/admin-step-up", cli.token, { mode: "report", expectedVersion: 0 })).status).toBe(200);
    const key = await registerSoftPasskey(db, adminId, { ...RP, trust: "trusted" });
    const sessionA = await browser("session-a");
    const sessionB = await browser("session-b");
    for (let round = 0; round < 8; round++) {
      const approvalId = await pendingApproval();
      const started = await call("POST", `/v1/me/approvals/${approvalId}/options`, sessionA);
      expect(started.status).toBe(200);
      const assertion = key.assert(started.body.publicKey.challenge);
      // Session B starts while session A approves with its challenge.
      const [restart, approved] = await Promise.all([
        call("POST", `/v1/me/approvals/${approvalId}/options`, sessionB),
        call("POST", `/v1/me/approvals/${approvalId}/approve`, sessionA, { assertion }),
      ]);
      expect(approved.status, JSON.stringify(approved.body)).toBe(200);
      // Before the approval: a challenge; after it: no longer pending. Never a deadlock (a 500).
      expect([200, 409], JSON.stringify(restart.body)).toContain(restart.status);
      if (restart.status === 409) expect(restart.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "approved" } });
      await db.query("UPDATE approval_intents SET closed_at = clock_timestamp(), close_reason = 'cancelled' WHERE id = $1", [approvalId]);
    }
  });

  it("consuming an approval and starting it at once never deadlock: consumption takes the person before the approval", async () => {
    // Another admin changed the control last, so the loosening change writes a new changed_by (a foreign key to the person).
    const other = (await consumeSetupGrant(ctx, (await issueInviteGrant(ctx, { organizationId: orgId, role: "admin", name: "Other" }, adminId)).token, {})).identityId;
    const otherCli = (await issueCredential(db, { identityId: other, kind: "cli" })).token;
    expect((await call("PATCH", "/v1/organizations/acme/security/controls/admin-step-up", otherCli, { mode: "report", expectedVersion: 0 })).status).toBe(200);
    const asked = await call("PATCH", "/v1/organizations/acme/security/controls/admin-step-up", cli.token, { mode: "off", expectedVersion: 1 });
    const approvalId = asked.body.error.details.approval.id as string;
    const key = await registerSoftPasskey(db, adminId, { ...RP, trust: "trusted" });
    await db.query(
      "UPDATE approval_intents SET approved_at = clock_timestamp(), approved_with_passkey_id = $2, approval_user_verified = true WHERE id = $1",
      [approvalId, key.passkeyId],
    );
    const requester: Requester = { identityId: adminId, identityKind: "human", credentialId: cli.credentialId, credentialKind: "cli" };
    // The change pauses right after consuming, holding the approval, before it writes changed_by.
    const consumed = deferred();
    const release = deferred();
    const pausing: ApprovalGate = {
      require: async (tx, binding) => {
        const used = await consumeApproval(tx, ctx.rootKek, requester, approvalId, binding);
        consumed.resolve();
        await release.promise;
        return used;
      },
    };
    const change = changeControl(ctx, pausing, {
      organizationId: orgId,
      control: "admin-step-up",
      mode: "off",
      expectedVersion: 1,
      actorIdentityId: adminId,
      requestId: "req_test",
      authorizeIn: async () => undefined,
    }).then((r) => r, (e) => e);
    await consumed.promise;
    // A start of the same approval, from the person's dashboard session, while the change holds it.
    const start = startApproval(ctx, RP, { approvalId, identityId: adminId, authSessionId: "session-a" }).then((r) => r, (e) => e);
    await sleep(300);
    release.resolve();
    expect(await change).toMatchObject({ changed: true, loosened: true, control: { mode: "off", changedBy: { id: adminId } } });
    // The start waited for the change and found the approval used; never a deadlock (40P01).
    expect(await start).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "consumed" } });
  });

  it("asking for an approval while a control change consumes one never deadlocks: both take the Organization before the person", async () => {
    const other = (await consumeSetupGrant(ctx, (await issueInviteGrant(ctx, { organizationId: orgId, role: "admin", name: "Other" }, adminId)).token, {})).identityId;
    const otherCli = (await issueCredential(db, { identityId: other, kind: "cli" })).token;
    expect((await call("PATCH", "/v1/organizations/acme/security/controls/admin-step-up", otherCli, { mode: "report", expectedVersion: 0 })).status).toBe(200);
    const asked = await call("PATCH", "/v1/organizations/acme/security/controls/admin-step-up", cli.token, { mode: "off", expectedVersion: 1 });
    const approvalId = asked.body.error.details.approval.id as string;
    const key = await registerSoftPasskey(db, adminId, { ...RP, trust: "trusted" });
    await db.query(
      "UPDATE approval_intents SET approved_at = clock_timestamp(), approved_with_passkey_id = $2, approval_user_verified = true WHERE id = $1",
      [approvalId, key.passkeyId],
    );
    const requester: Requester = { identityId: adminId, identityKind: "human", credentialId: cli.credentialId, credentialKind: "cli" };
    // The change holds the Organization FOR UPDATE and pauses before it consumes.
    const locked = deferred();
    const release = deferred();
    const change = withApprovalGate(requester, approvalId, async (gate) => changeControl(ctx, gate, {
      organizationId: orgId,
      control: "admin-step-up",
      mode: "off",
      expectedVersion: 1,
      actorIdentityId: adminId,
      requestId: "req_test",
      authorizeIn: async () => {
        locked.resolve();
        await release.promise;
      },
    })).then((r) => r, (e) => e);
    await locked.promise;
    // Meanwhile the same person asks for another approval in that Organization.
    const second = await issueCredential(db, { identityId: adminId, kind: "cli" });
    const asking = createApproval(ctx, { ...requester, credentialId: second.credentialId }, {
      operation: "security_control.change",
      organizationId: orgId,
      target: { control: "credential-lifetime" },
      body: { mode: "off", config: null, expectedVersion: 0 },
      query: {},
      expectedVersion: 0,
      summary: { title: "t", changes: [] },
    }, PUBLIC_URL).then((r) => r, (e) => e);
    await sleep(300);
    release.resolve();
    expect(await change).toMatchObject({ changed: true, loosened: true, control: { mode: "off" } });
    expect(await asking).toMatchObject({ state: "pending", operation: "security_control.change" });
  });

  it("stays free of deadlocks and consistent under a random mix of approval and control work", async () => {
    const other = (await consumeSetupGrant(ctx, (await issueInviteGrant(ctx, { organizationId: orgId, role: "admin", name: "Other" }, adminId)).token, {})).identityId;
    const otherCli = (await issueCredential(db, { identityId: other, kind: "cli" })).token;
    const key = await registerSoftPasskey(db, adminId, { ...RP, trust: "trusted" });
    const session = await browser("session-stress");
    const clis = await Promise.all(Array.from({ length: 4 }, () => issueCredential(db, { identityId: adminId, kind: "cli" })));
    const tokenOf = new Map(clis.map((c) => [c.credentialId, c.token]));
    const PATH = "/v1/organizations/acme/security/controls/admin-step-up";
    const failures: string[] = [];
    const pick = <T,>(items: readonly T[]): T | undefined => items[Math.floor(Math.random() * items.length)];
    const version = async () =>
      ((await db.query("SELECT version FROM security_controls WHERE organization_id = $1 AND control = 'admin-step-up'", [orgId])).rows[0] as
        | { version: number } | undefined)?.version ?? 0;
    const intents = async (where: string) =>
      (await db.query(`SELECT id, credential_id, expected_version FROM approval_intents WHERE ${where}`)).rows as
        { id: string; credential_id: string; expected_version: number }[];
    const check = (what: string, res: { status: number; body: any }) => {
      if (res.status >= 500) failures.push(`${what}: ${res.status} ${JSON.stringify(res.body)}`);
    };
    const domain = async (what: string, run: () => Promise<unknown>) => {
      try { await run(); } catch (err) {
        if (!(err instanceof Error) || (err as { code?: unknown }).code === "40P01" || !("code" in err) || /deadlock/.test(err.message)) {
          failures.push(`${what}: ${String(err)}`);
        }
      }
    };
    const ops: Record<string, (v: number) => Promise<void>> = {
      ask: async (v) => {
        const c = pick(clis)!;
        check("ask", await call("PATCH", PATH, c.token, { mode: "off", expectedVersion: v }));
      },
      tighten: async (v) => check("tighten", await call("PATCH", PATH, otherCli, { mode: "report", expectedVersion: v })),
      start: async () => {
        const i = pick(await intents("operation = 'security_control.change'"));
        if (i) check("start", await call("POST", `/v1/me/approvals/${i.id}/options`, session));
      },
      approve: async () => {
        const i = pick(await intents("approved_at IS NULL AND closed_at IS NULL AND expires_at > clock_timestamp()"));
        if (!i) return;
        const started = await call("POST", `/v1/me/approvals/${i.id}/options`, session);
        check("approve options", started);
        if (started.status !== 200) return;
        check("approve", await call("POST", `/v1/me/approvals/${i.id}/approve`, session, { assertion: key.assert(started.body.publicKey.challenge) }));
      },
      consume: async () => {
        const i = pick(await intents("approved_at IS NOT NULL AND consumed_at IS NULL AND closed_at IS NULL"));
        if (!i) return;
        check("consume", await call("PATCH", PATH, tokenOf.get(i.credential_id)!, { mode: "off", expectedVersion: i.expected_version },
          { "Varlatch-Approval": i.id }));
      },
      cancel: async () => {
        const i = pick(await intents("consumed_at IS NULL AND closed_at IS NULL"));
        if (i) check("cancel", await call("POST", `/v1/me/approvals/${i.id}/cancel`, tokenOf.get(i.credential_id)!));
      },
      poll: async () => {
        const i = pick(await intents("true"));
        if (i) check("poll", await call("GET", `/v1/me/approvals/${i.id}`, tokenOf.get(i.credential_id)!));
      },
      reset: async () => domain("reset", () => resetControls(ctx, { organization: "acme", controls: ["admin-step-up"] })),
    };
    const names = Object.keys(ops);
    let ran = 0;
    for (let round = 0; round < 50; round++) {
      // Keep the per-person windows and the per-credential cap from stopping the work.
      await db.query("UPDATE approval_intents SET created_at = created_at - interval '11 minutes'");
      await db.query("UPDATE approval_intent_challenges SET created_at = created_at - interval '11 minutes'");
      await db.query(
        "UPDATE approval_intents SET expires_at = clock_timestamp() - interval '1 second' WHERE created_at < clock_timestamp() - interval '40 minutes' AND expires_at > clock_timestamp()",
      );
      const v = await version();
      const batch = Array.from({ length: 6 }, () => pick(names)!);
      ran += batch.length;
      await Promise.all(batch.map((name) => ops[name]!(v)));
    }
    expect(ran).toBe(300);
    expect(failures).toEqual([]);
    expect((await intents("true")).length).toBeGreaterThan(0);
    // Consistent: the version counts every recorded change and every reset that changed the mode; each used
    // approval was used by exactly one recorded change.
    const events = (await db.query(
      `SELECT event_type, metadata FROM audit_events WHERE event_type IN ('security_control.changed', 'security_control.reset')
         AND resource ->> 'control' = 'admin-step-up'`,
    )).rows as { event_type: string; metadata: any }[];
    const meta = (m: unknown) => (typeof m === "string" ? JSON.parse(m) : m) as Record<string, any>;
    const bumps = events.filter((e) => e.event_type === "security_control.changed" || meta(e.metadata).toVersion !== meta(e.metadata).fromVersion).length;
    expect(await version()).toBe(bumps);
    const used = (await intents("consumed_at IS NOT NULL")).map((i) => i.id).sort();
    const recorded = events.map((e) => meta(e.metadata).approvalId).filter((id) => typeof id === "string").sort();
    expect(recorded).toEqual(used);
  }, 120_000);

  it("the public-URL change takes people, then passkeys in id order, against an approval or a confirmation holding one", async () => {
    // A person with two passkeys, the one with the higher id stored first, so a bulk DELETE scanning the
    // table meets it first.
    await db.query(`INSERT INTO "user" (id, name, email, "emailVerified", "updatedAt") VALUES ('bau_pu', 'P', 'p@varlatch.placeholder.invalid', false, now())`);
    await db.query("INSERT INTO auth_user_links (better_auth_user_id, identity_id) VALUES ('bau_pu', $1)", [adminId]);
    for (const id of ["pk_b_order", "pk_a_order"]) {
      await db.query(
        `INSERT INTO passkey (id, "publicKey", "userId", "credentialID", counter, "deviceType", "backedUp", "createdAt")
         VALUES ($1, 'k', 'bau_pu', $1, 0, 'singleDevice', false, now())`,
        [id],
      );
    }
    // A transaction in the documented order, as approveApproval and confirmPasskey take it: the person, then
    // the passkeys in id order. It holds the first passkey when the public-URL change starts.
    const held = await db.connect();
    let change: Promise<unknown> = Promise.resolve();
    try {
      await held.query("BEGIN");
      await lockPerson(held, adminId, "update");
      await held.query("SELECT id FROM passkey WHERE id = 'pk_a_order' FOR UPDATE");
      change = completePublicUrlChange(ctx, { from: "https://old.varlatch.test", to: PUBLIC_URL }).then((r) => r, (e) => e);
      await sleep(300);
      const second = await held.query("SELECT id FROM passkey WHERE id = 'pk_b_order' FOR UPDATE").then(() => "locked", (e) => e);
      expect(second).toBe("locked");
      await held.query("COMMIT");
    } finally {
      await held.query("ROLLBACK").catch(() => undefined);
      held.release();
    }
    // The change waited for the person, then removed both passkeys; never a deadlock (40P01).
    expect(await change).toMatchObject({ passkeysRemoved: 2 });
    expect((await db.query("SELECT count(*)::int AS n FROM passkey")).rows).toEqual([{ n: 0 }]);
  });

  /** Run `during` while another connection holds what `hold` locked, then let `finish` take more and commit. */
  async function whileHeld(hold: (q: typeof db) => Promise<void>, during: () => Promise<unknown>, finish: (q: typeof db) => Promise<void>) {
    const held = await db.connect();
    let outcome: Promise<unknown> = Promise.resolve();
    try {
      await held.query("BEGIN");
      await hold(held as unknown as typeof db);
      outcome = during().then((r) => r, (e) => e);
      await sleep(300);
      const second = await finish(held as unknown as typeof db).then(() => "locked", (e) => e);
      expect(second).toBe("locked");
      await held.query("COMMIT");
    } finally {
      await held.query("ROLLBACK").catch(() => undefined);
      held.release();
    }
    return outcome;
  }

  it("device sign-in approval takes the person and their passkeys before it advances a counter", async () => {
    const key = await registerSoftPasskey(db, adminId, { ...RP, trust: "trusted" });
    const started = await requestDeviceSignIn(ctx, { peer: "203.0.113.9", userAgent: null, requestId: "req_test" });
    const found = await findSignInByCode(ctx, { identityId: adminId, peer: "203.0.113.9", userCode: started.userCode, requestId: "req_test" });
    if (found.kind !== "found") throw new Error("no sign-in");
    const options = await issueApprovalChallenge(ctx, RP, { signInId: found.signIn.id, identityId: adminId, authSessionId: "session-d" });
    const assertion = key.assert(options!.challenge);
    // An approval, a confirmation or the public-URL change: the person FOR UPDATE, then the passkey.
    const outcome = await whileHeld(
      (q) => lockPerson(q, adminId, "update"),
      () => approveDeviceSignIn(ctx, RP, { signInId: found.signIn.id, identityId: adminId, authSessionId: "session-d", assertion, requestId: "req_test" }),
      async (q) => { await q.query("SELECT id FROM passkey WHERE id = $1 FOR UPDATE", [key.passkeyId]); },
    );
    // The approval waited for the person, then went through; never a deadlock (40P01).
    expect(outcome).toBeUndefined();
    expect((await db.query("SELECT status FROM device_sign_ins WHERE id = $1", [found.signIn.id])).rows).toEqual([{ status: "approved" }]);
  });

  it("re-enrollment takes several people in id order, as every transaction locking people does", async () => {
    // The lowest id is a member; a higher id is an Installation Admin, listed (and once locked) first.
    await db.query("INSERT INTO identities (id, kind, name, installation_admin) VALUES ('idn_0reenroll', 'human', 'Low', false)");
    await db.query("INSERT INTO identities (id, kind, name, installation_admin) VALUES ('idn_zreenroll', 'human', 'High', true)");
    const outcome = await whileHeld(
      (q) => lockPerson(q, "idn_0reenroll", "update"),
      () => issueReenrollmentGrants(ctx, { identityIds: "all" }),
      (q) => lockPeople(q, ["idn_0reenroll", "idn_zreenroll"], "update"),
    );
    // Issued for everyone, still listed admins first; never a deadlock (40P01).
    const grants = outcome as { identityId: string; installationAdmin: boolean }[];
    expect(Array.isArray(grants), String(outcome)).toBe(true);
    expect(grants.map((g) => g.identityId).sort()).toEqual([adminId, "idn_0reenroll", "idn_zreenroll"].sort());
    expect(grants.at(-1)).toMatchObject({ identityId: "idn_0reenroll", installationAdmin: false });
    expect(grants.slice(0, 2).every((g) => g.installationAdmin)).toBe(true);
  });

  it("Organization deletion takes every person it references in id order before writing", async () => {
    // A member with an id below the admin's: the admin is an audit reader, inserted first; the member's
    // removal comes after.
    await db.query("INSERT INTO identities (id, kind, name) VALUES ('idn_0member', 'human', 'Member')");
    await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, 'idn_0member', 'member')", [orgId]);
    expect("idn_0member" < adminId).toBe(true);
    const scheduled = await call("POST", "/v1/organizations/acme/deletion", cli.token, { afterDays: 1 });
    expect(scheduled.status, JSON.stringify(scheduled.body)).toBe(201);
    await db.query("UPDATE organization_deletions SET scheduled_at = now() - interval '2 days', run_after = now() - interval '1 minute' WHERE organization_id = $1", [orgId]);
    // A transaction that locks people in id order, as re-enrollment and the round-4 public-URL change did.
    const outcome = await whileHeld(
      (q) => lockPerson(q, "idn_0member", "update"),
      () => finalizeDeletion(ctx, scheduled.body.id, orgId),
      (q) => lockPerson(q, adminId, "update"),
    );
    // The deletion waited for the member, then ran; never a deadlock (40P01).
    expect(outcome).toMatchObject({ organizationId: orgId, members: 2 });
  });

  it("the public-URL change waits for nobody who only references people", async () => {
    await db.query(`INSERT INTO "user" (id, name, email, "emailVerified", "updatedAt") VALUES ('bau_ks', 'P', 'ks@varlatch.placeholder.invalid', false, now())`);
    await db.query("INSERT INTO auth_user_links (better_auth_user_id, identity_id) VALUES ('bau_ks', $1)", [adminId]);
    // A writer holding the person FOR KEY SHARE (a foreign key it inserted) and still open.
    const held = await db.connect();
    try {
      await held.query("BEGIN");
      await lockPerson(held, adminId, "key share");
      const done = await Promise.race([
        completePublicUrlChange(ctx, { from: "https://old.varlatch.test", to: PUBLIC_URL }).then(() => "done"),
        sleep(2000).then(() => "waiting"),
      ]);
      expect(done).toBe("done");
      await held.query("COMMIT");
    } finally {
      await held.query("ROLLBACK").catch(() => undefined);
      held.release();
    }
  });

  it("holds the per-person challenge cap when starts for different approvals arrive together", async () => {
    expect((await call("PATCH", "/v1/organizations/acme/security/controls/admin-step-up", cli.token, { mode: "report", expectedVersion: 0 })).status).toBe(200);
    await registerSoftPasskey(db, adminId, { ...RP, trust: "trusted" });
    const approvals = [await pendingApproval(), await pendingApproval(), await pendingApproval()];
    // One below the cap: 19 challenges already issued in the window.
    for (let i = 0; i < APPROVALS.challengesPerPerson - 1; i++) {
      await db.query(
        `INSERT INTO approval_intent_challenges (id, intent_id, identity_id, auth_session_id, challenge, created_at, expires_at)
         VALUES ($1, $2, $3, 'session-x', $4, clock_timestamp(), clock_timestamp() + interval '1 minute')`,
        [`apc_fill${i}`, approvals[0], adminId, `fill-${i}`],
      );
    }
    const sessions = await Promise.all(["s1", "s2", "s3"].map((s) => browser(s)));
    const answers = await Promise.all(
      approvals.map((id, i) => call("POST", `/v1/me/approvals/${id}/options`, sessions[i]!)),
    );
    expect(answers.filter((a) => a.status === 200)).toHaveLength(1);
    expect(answers.filter((a) => a.body.error?.code === "RATE_LIMITED")).toHaveLength(2);
    expect((await db.query("SELECT count(*)::int AS n FROM approval_intent_challenges")).rows).toEqual([{ n: APPROVALS.challengesPerPerson }]);
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
