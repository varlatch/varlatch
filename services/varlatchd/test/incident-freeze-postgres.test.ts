// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildHumanAuth, type HumanAuth } from "../src/auth/humanauth.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations, type Querier } from "../src/db/migrate.js";
import { withSnapshot, type PoolQuerier } from "../src/db/tx.js";
import { ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import { activateRevision, pushRevision } from "../src/domain/contracts.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { getEnvironment, type EnvironmentRow } from "../src/domain/environments.js";
import { freezeOrganization, operatorUnfreeze } from "../src/domain/freeze.js";
import { scheduleDeletion } from "../src/domain/orgdeletion.js";
import { getOrganization, type OrgRow } from "../src/domain/orgs.js";
import { getProject, type ProjectRow } from "../src/domain/projects.js";
import { captureState } from "../src/domain/retrieval.js";
import { changeControl } from "../src/domain/securitycontrols.js";
import { setValue } from "../src/domain/values.js";
import { buildApp } from "../src/http/app.js";
import { deviceClient, PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { softAuthenticator, type UnregisteredAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * The incident freeze (ADR-0055) on real PostgreSQL: what PGlite's one
 * connection cannot show.
 *
 * - End to end, from signed out to a lift, through Better Auth itself (it
 *   keeps its own connection pool): a passkey sign-in, the dashboard's
 *   bearer minted and renewed through POST /auth/varlatch-token while
 *   frozen, the lift's STEP_UP_REQUIRED, the intent read, the challenge,
 *   the approval with a trusted passkey and the repeated lift; the same
 *   from the CLI through device sign-in.
 * - A snapshot that began before the freeze finishes and returns.
 * - Writes racing the freeze commit first or refuse, and the freeze does
 *   not deadlock with a Contract activation, a Security Control change or
 *   deletion scheduling: one side pauses holding the Organization row, the
 *   other is seen waiting on a lock, and both finish.
 */
const url = process.env.VARLATCH_TEST_DATABASE_URL;

/** A pool whose transactions can pause once, right after one matching statement ran. */
function pausing(db: PoolQuerier) {
  let armed: { match: RegExp; reached: () => void; release: Promise<void> } | null = null;
  const wrap = <Q extends Querier>(q: Q): Q => ({
    ...q,
    query: async (text: string, params?: unknown[]) => {
      const res = await q.query(text, params);
      if (armed && armed.match.test(text)) {
        const pause = armed;
        armed = null;
        pause.reached();
        await pause.release;
      }
      return res;
    },
  });
  const pool: PoolQuerier = { ...wrap(db), connect: async () => wrap(await db.connect()) };
  return {
    pool,
    pauseAfter(match: RegExp) {
      let reached!: () => void;
      let release!: () => void;
      const reachedP = new Promise<void>((r) => (reached = r));
      const releaseP = new Promise<void>((r) => (release = r));
      armed = { match, reached, release: releaseP };
      return { reached: reachedP, release };
    },
  };
}

/** lockLiveScope's Organization lock, in a mode. */
const ORG_LOCK = (mode: string) => new RegExp(`SELECT deleted_at FROM organizations WHERE id = \\$1 ${mode}`);

const outcome = (r: PromiseSettledResult<unknown>) =>
  r.status === "fulfilled" ? "ok" : ((r.reason as { code?: string }).code ?? String((r.reason as Error).message));

describe.skipIf(!url)("the incident freeze on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let humanAuth: HumanAuth;
  let app: ReturnType<typeof buildApp>;
  const database = `varlatch_freeze_test_${process.pid}`;

  beforeEach(async () => {
    admin = createPgQuerier(url!);
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${database}`);
    const target = new URL(url!);
    target.pathname = `/${database}`;
    db = createPgQuerier(target.toString());
    const connection = await db.connect();
    try { await runMigrations(connection); } finally { connection.release(); }
    ctx = { db, rootKek: Buffer.alloc(32, 31) };
    await ensureInstallation(ctx);
    humanAuth = buildHumanAuth({ ctx, databaseUrl: target.toString(), publicUrl: PUBLIC_URL });
    app = buildApp(ctx, { publicUrl: PUBLIC_URL, humanAuth, clientAddress: () => "203.0.113.7" });
  });
  afterEach(async () => {
    await humanAuth?.close();
    await db?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
      await admin.end();
    }
  });

  /** One browser: its cookies, kept between requests as a browser would. */
  class Browser {
    cookies = new Map<string, string>();
    async request(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
      const res = await app.request(`${PUBLIC_URL}${path}`, {
        method,
        headers: {
          Origin: RP.origin,
          ...(this.cookies.size ? { Cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ") } : {}),
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
          ...headers,
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      for (const cookie of res.headers.getSetCookie()) {
        const [pair] = cookie.split(";");
        const eq = pair!.indexOf("=");
        const name = pair!.slice(0, eq);
        const value = pair!.slice(eq + 1);
        if (value === "" || /max-age=0/i.test(cookie)) this.cookies.delete(name);
        else this.cookies.set(name, value);
      }
      const text = await res.text();
      let parsed: any = null;
      try { parsed = text ? JSON.parse(text) : null; } catch { parsed = text; }
      return { status: res.status, body: parsed, headers: res.headers };
    }
    async signIn(authenticator: UnregisteredAuthenticator) {
      const options = await this.request("GET", "/auth/passkey/generate-authenticate-options");
      expect(options.status).toBe(200);
      const res = await this.request("POST", "/auth/passkey/verify-authentication", { response: authenticator.assert(options.body.challenge, { userVerified: true }) });
      expect(res.status, JSON.stringify(res.body)).toBe(200);
    }
    async bearer() {
      const res = await this.request("POST", "/auth/varlatch-token");
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      return res.body.token as string;
    }
  }

  async function call(method: string, path: string, token: string, body?: unknown, headers: Record<string, string> = {}) {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null };
  }

  /** The first admin, enrolled through the bootstrap grant: a trusted passkey. */
  async function bootstrapAdmin() {
    const grant = await issueBootstrapGrant(ctx);
    const enrolling = new Browser();
    const key = softAuthenticator(RP);
    const options = await enrolling.request("GET", `/auth/passkey/generate-register-options?context=${encodeURIComponent(grant.token)}`);
    const enrolled = await enrolling.request("POST", "/auth/passkey/verify-registration", {
      response: key.attest(options.body.challenge, {}),
      name: "test key",
      createSession: true,
    });
    expect(enrolled.status, JSON.stringify(enrolled.body)).toBe(200);
    const identityId = ((await db.query("SELECT identity_id FROM auth_user_links")).rows[0] as { identity_id: string }).identity_id;
    const token = await enrolling.bearer();
    expect((await call("POST", "/v1/organizations", token, { name: "Acme", slug: "acme" })).status).toBe(201);
    expect((await call("POST", "/v1/organizations/acme/projects", token, { name: "API", slug: "api", contractAuthority: "managed" })).status).toBe(201);
    expect((await call("POST", "/v1/organizations/acme/projects/api/environments", token, { name: "dev", tier: "development" })).status).toBe(201);
    return { key, identityId, token };
  }

  /** The person approves in the dashboard: the intent, its challenge, the assertion. */
  async function approveIn(bearer: string, key: UnregisteredAuthenticator, approvalId: string) {
    const read = await call("GET", `/v1/me/approvals/${approvalId}`, bearer);
    expect(read.status).toBe(200);
    expect(read.body).toMatchObject({ operation: "organization.unfreeze", state: "pending" });
    const started = await call("POST", `/v1/me/approvals/${approvalId}/options`, bearer);
    expect(started.status, JSON.stringify(started.body)).toBe(200);
    const approved = await call("POST", `/v1/me/approvals/${approvalId}/approve`, bearer, {
      assertion: key.assert(started.body.publicKey.challenge, { userVerified: true }),
    });
    expect(approved.status, JSON.stringify(approved.body)).toBe(200);
  }

  it("from signed out to a lift, in the dashboard: sign in, mint and renew the bearer, approve, lift", async () => {
    const { key, identityId } = await bootstrapAdmin();
    const org = await getOrganization(ctx, "acme");
    const frozen = await freezeOrganization(ctx, {
      organizationId: org.id, actor: { id: identityId, kind: "human" }, credentialKind: "browser", reason: "Stolen session", requestId: "req_test", authorizeIn: async () => undefined,
    });

    // Signed out: a new browser with no session and no bearer.
    const browser = new Browser();
    expect((await browser.request("POST", "/auth/varlatch-token")).status).toBe(401);
    await browser.signIn(key);
    let bearer = await browser.bearer();
    expect((await call("GET", "/v1/organizations/acme/projects/api/environments/dev/effective-configuration", bearer)).body.error.code).toBe("ORGANIZATION_FROZEN");
    // The bearer runs out; the dashboard renews it from the session, while frozen.
    await db.query("UPDATE credentials SET expires_at = now() - interval '1 second' WHERE kind = 'browser' AND identity_id = $1", [identityId]);
    expect((await call("GET", "/v1/organizations/acme/incident-freeze", bearer)).status).toBe(401);
    bearer = await browser.bearer();
    expect((await call("GET", "/v1/organizations/acme/incident-freeze", bearer)).body.freeze.id).toBe(frozen.id);

    const lift = (approval?: string) => call("POST", `/v1/organizations/acme/incident-freeze/${frozen.id}/lift`, bearer, undefined, approval ? { "Varlatch-Approval": approval } : {});
    const asked = await lift();
    expect(asked.status).toBe(403);
    expect(asked.body.error.code).toBe("STEP_UP_REQUIRED");
    const approvalId = asked.body.error.details.approval.id as string;
    await approveIn(bearer, key, approvalId);
    const done = await lift(approvalId);
    expect(done.status, JSON.stringify(done.body)).toBe(200);
    expect(done.body.freeze).toMatchObject({ id: frozen.id, liftMethod: "approval", liftedBy: { id: identityId } });
    expect((await call("GET", "/v1/organizations/acme/projects", bearer)).status).toBe(200);
  });

  it("from signed out to a lift, from the CLI through device sign-in", async () => {
    const { key, identityId } = await bootstrapAdmin();
    const org = await getOrganization(ctx, "acme");
    const frozen = await freezeOrganization(ctx, {
      organizationId: org.id, actor: { id: identityId, kind: "human" }, credentialKind: "cli", reason: "Leaked CI token", requestId: "req_test", authorizeIn: async () => undefined,
    });
    const device = deviceClient(() => app);
    const started = await device.start();
    expect(started.status, JSON.stringify(started.body)).toBe(201);
    // The person signs in in a browser and approves the device there.
    const browser = new Browser();
    await browser.signIn(key);
    const bearer = await browser.bearer();
    const approved = await device.approve(bearer, started.body.userCode, key as never);
    expect(approved.status, JSON.stringify(approved.body)).toBe(200);
    const polled = await device.poll(started.body.deviceCode);
    expect(polled.status, JSON.stringify(polled.body)).toBe(201);
    const cli = polled.body.token as string;

    const lift = (approval?: string) => call("POST", `/v1/organizations/acme/incident-freeze/${frozen.id}/lift`, cli, undefined, approval ? { "Varlatch-Approval": approval } : {});
    const asked = await lift();
    expect(asked.body.error.code).toBe("STEP_UP_REQUIRED");
    const approvalId = asked.body.error.details.approval.id as string;
    // The CLI polls its approval while the person approves in the dashboard.
    expect((await call("GET", `/v1/me/approvals/${approvalId}`, cli)).body.state).toBe("pending");
    await approveIn(bearer, key, approvalId);
    const done = await lift(approvalId);
    expect(done.status, JSON.stringify(done.body)).toBe(200);
    expect(done.body.freeze.liftMethod).toBe("approval");
  });

  describe("concurrency", () => {
    let paused: ReturnType<typeof pausing>;
    let pctx: AppCtx;
    let identityId: string;
    let org: OrgRow;
    let project: ProjectRow;
    let env: EnvironmentRow;

    beforeEach(async () => {
      ({ identityId } = await bootstrapAdmin());
      paused = pausing(db);
      pctx = { db: paused.pool, rootKek: ctx.rootKek };
      org = await getOrganization(ctx, "acme");
      project = await getProject(ctx, org.id, "api");
      env = await getEnvironment(ctx, project.id, "dev");
      await setValue(ctx, org, project, env, "API_KEY", { value: "first" }, identityId);
    });

    const freezeIt = (c: AppCtx = ctx) =>
      freezeOrganization(c, {
        organizationId: org.id, actor: { id: identityId, kind: "human" }, credentialKind: "cli", reason: "race", requestId: "req_test", authorizeIn: async () => undefined,
      });

    const waitingOnLock = async () => {
      for (let i = 0; i < 250; i++) {
        const res = await admin.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'", [database]);
        if ((res.rows[0] as { n: number }).n >= 1) return;
        await new Promise((r) => setTimeout(r, 20));
      }
      throw new Error("the second transaction never waited on a lock");
    };

    /** `first` pauses right after `pausedAt`; `second` starts and waits on a lock; `first` goes on. */
    const race = async (pausedAt: RegExp, first: () => Promise<unknown>, second: () => Promise<unknown>) => {
      const pause = paused.pauseAfter(pausedAt);
      const running = first();
      await pause.reached;
      const other = second();
      await waitingOnLock();
      pause.release();
      return (await Promise.allSettled([running, other])).map(outcome);
    };

    it("a snapshot that began before the freeze finishes and returns its values", async () => {
      const captured = await withSnapshot(db, async (sdb, now) => {
        // The snapshot is taken by its first read; the freeze commits after it.
        await sdb.query("SELECT 1 FROM organizations WHERE id = $1", [org.id]);
        await freezeIt();
        return captureState({ ...ctx, db: sdb }, { org, project, env }, now, () => true);
      });
      expect(captured).toBeTruthy();
      // A snapshot that begins after it is refused.
      const after = await withSnapshot(db, async (sdb, now) => captureState({ ...ctx, db: sdb }, { org, project, env }, now, () => true)).catch((e: { code?: string }) => e.code);
      expect(after).toBe("ORGANIZATION_FROZEN");
    });

    it("a write in progress commits first; a write that waits for the freeze is refused", async () => {
      expect(await race(ORG_LOCK("FOR KEY SHARE"), () => setValue(pctx, org, project, env, "API_KEY", { value: "second" }, identityId), () => freezeIt()))
        .toEqual(["ok", "ok"]);
      await operatorUnfreeze(ctx, { organization: "acme", confirm: "acme" });
      expect(await race(ORG_LOCK("FOR UPDATE"), () => freezeIt(pctx), () => setValue(ctx, org, project, env, "API_KEY", { value: "third" }, identityId)))
        .toEqual(["ok", "ORGANIZATION_FROZEN"]);
    });

    it("does not deadlock with a Contract activation", async () => {
      const contract = { schemaVersion: 1, items: [{ name: "API_KEY", required: { kind: "always" }, sensitive: true, type: "string" }] };
      const rev = await pushRevision(ctx, org.id, project.id, contract, undefined, identityId);
      expect(await race(ORG_LOCK("FOR KEY SHARE"), () => activateRevision(pctx, org.id, project, rev.id, identityId), () => freezeIt()))
        .toEqual(["ok", "ok"]);
      await operatorUnfreeze(ctx, { organization: "acme", confirm: "acme" });
      const next = await pushRevision(ctx, org.id, project.id, { ...contract, items: [...contract.items, { name: "PORT", required: { kind: "never" }, sensitive: false, type: "number" }] }, undefined, identityId);
      expect(await race(ORG_LOCK("FOR UPDATE"), () => freezeIt(pctx), async () => activateRevision(ctx, org.id, await getProject(ctx, org.id, project.id), next.id, identityId)))
        .toEqual(["ok", "ORGANIZATION_FROZEN"]);
    });

    it("does not deadlock with a Security Control change, which passes as recovery", async () => {
      const change = (c: AppCtx, expectedVersion: number, mode: "report" | "off") =>
        changeControl(c, { require: async () => { throw new Error("no approval expected"); } }, {
          organizationId: org.id, control: "credential-lifetime", mode, config: mode === "off" ? undefined : { defaultTtlSeconds: 60, maxTtlSeconds: 600 },
          expectedVersion, actorIdentityId: identityId, requestId: "req_test", authorizeIn: async () => undefined,
        });
      expect(await race(ORG_LOCK("FOR UPDATE"), () => change(pctx, 0, "report"), () => freezeIt())).toEqual(["ok", "ok"]);
      await operatorUnfreeze(ctx, { organization: "acme", confirm: "acme" });
      // Tightening while the freeze holds the row: it waits, then passes.
      await db.query("UPDATE security_controls SET mode = 'off' WHERE organization_id = $1", [org.id]);
      expect(await race(ORG_LOCK("FOR UPDATE"), () => freezeIt(pctx), () => change(ctx, 1, "report"))).toEqual(["ok", "ok"]);
    });

    it("does not deadlock with deletion scheduling: a pending deletion can be frozen, a frozen Organization cannot be scheduled", async () => {
      const schedule = (c: AppCtx) => scheduleDeletion(c, org.id, { id: identityId, kind: "human" }, {});
      expect(await race(ORG_LOCK("FOR UPDATE"), () => schedule(pctx), () => freezeIt())).toEqual(["ok", "ok"]);
      await operatorUnfreeze(ctx, { organization: "acme", confirm: "acme" });
      await db.query("UPDATE organization_deletions SET cancelled_at = now(), cancelled_by = $1", [identityId]);
      expect(await race(ORG_LOCK("FOR UPDATE"), () => freezeIt(pctx), () => schedule(ctx))).toEqual(["ok", "ORGANIZATION_FROZEN"]);
    });
  });
});
