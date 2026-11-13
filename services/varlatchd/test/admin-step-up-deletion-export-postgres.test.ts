// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations, type Querier } from "../src/db/migrate.js";
import type { PoolQuerier } from "../src/db/tx.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { createEnvironment, getEnvironment, type EnvironmentRow } from "../src/domain/environments.js";
import { getOrganization, type OrgRow } from "../src/domain/orgs.js";
import { getProject, type ProjectRow } from "../src/domain/projects.js";
import { applyChangeSet, beginRotation, setValue } from "../src/domain/values.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * admin-step-up for deletion and export on real PostgreSQL (ADR-0054 step
 * 4.9, amendments C and E), where transactions can wait for each other.
 *
 * An export's phase 2 consumes its approval (the requester FOR UPDATE at
 * step 2), then takes the Project and the environment FOR SHARE (steps 8
 * and 9). A value write takes its person at step 2 too, then the
 * environment FOR NO KEY UPDATE. So a value write racing phase 2 either
 * committed first, and the export finds its capture stale (STATE_CHANGED,
 * the approval unused), or it waits until the export has committed; never
 * a deadlock:
 *
 * - the writer holds the environment, the same person exports: the export
 *   waits at step 2, then refuses as stale; repeated, it discloses the new
 *   value (setValue, beginRotation, applyChangeSet);
 * - another person writes: the export waits at step 9, then refuses as
 *   stale;
 * - the export holds the environment: the same person's write waits at
 *   step 2 until the export committed the old value.
 *
 * And a protected Project deletion with a real approval against
 * createEnvironment in that Project by the same person: one waits, both
 * finish.
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

/** lockLiveScope's environment lock, in a mode. */
const ENV_LOCK = (mode: string) => new RegExp(`FROM environments WHERE id = ANY\\(\\$1\\) AND project_id = \\$2 ORDER BY id ${mode}`);
/** The export's phase-2 environment lock (exportstepup.ts). */
const EXPORT_ENV_LOCK = /SELECT id FROM environments WHERE id = ANY\(\$1\) ORDER BY id FOR SHARE/;

describe.skipIf(!url)("admin-step-up for deletion and export on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let paused: ReturnType<typeof pausing>;
  let pctx: AppCtx;
  let app: ReturnType<typeof buildApp>;
  let org: OrgRow;
  let project: ProjectRow;
  let env: EnvironmentRow;
  let owner: Person;
  const database = `varlatch_stepup_deletion_export_${process.pid}`;
  const E = "/v1/organizations/acme/projects/api/environments/prod";

  interface Person {
    id: string;
    cli: string;
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

  /** Ask through the route, approve in the dashboard with the person's passkey; the approval id. */
  async function approval(p: Person, method: string, path: string, body?: unknown): Promise<string> {
    const asked = await call(method, path, p.web, body);
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
  const consumed = async (id: string) =>
    ((await db.query("SELECT consumed_at IS NOT NULL AS c FROM approval_intents WHERE id = $1", [id])).rows[0] as { c: boolean }).c;

  const waitingOnLock = async () => {
    for (let i = 0; i < 250; i++) {
      const res = await admin.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'", [database]);
      if ((res.rows[0] as { n: number }).n >= 1) return;
      await new Promise((r) => setTimeout(r, 20));
    }
    throw new Error("the second transaction never waited on a lock");
  };

  /** The first side pauses right after `pausedAt`; the second starts and waits on a lock; then the first goes on. */
  const race = async <A, B>(pausedAt: RegExp, first: () => Promise<A>, second: () => Promise<B>) => {
    const pause = paused.pauseAfter(pausedAt);
    const firstRun = first();
    await pause.reached;
    const secondRun = second();
    await waitingOnLock();
    pause.release();
    return Promise.all([firstRun, secondRun]);
  };

  const exportDbPass = (approvalId: string) =>
    call("POST", `${E}/disclosures`, owner.web, { items: ["DB_PASS"], purpose: "export" }, { "Varlatch-Approval": approvalId });

  beforeEach(async () => {
    admin = createPgQuerier(url!);
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${database}`);
    const target = new URL(url!);
    target.pathname = `/${database}`;
    db = createPgQuerier(target.toString());
    const connection = await db.connect();
    try { await runMigrations(connection); } finally { connection.release(); }
    ctx = { db, rootKek: Buffer.alloc(32, 49) };
    paused = pausing(db);
    pctx = { db: paused.pool, rootKek: ctx.rootKek };
    await ensureInstallation(ctx);
    owner = await person((await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" })).identityId);
    // Every request goes through the pausing pool.
    app = buildApp(pctx, { publicUrl: PUBLIC_URL, clientAddress: () => "203.0.113.7" });
    expect((await call("POST", "/v1/organizations", owner.cli, { name: "Acme", slug: "acme" })).status).toBe(201);
    const projectId = (await call("POST", "/v1/organizations/acme/projects", owner.cli, { name: "API", slug: "api", contractAuthority: "managed" })).body.id;
    await call("POST", "/v1/organizations/acme/projects/api/environments", owner.cli, { name: "prod", tier: "production" });
    const item = (name: string) => ({ name, required: { kind: "never" }, sensitive: true, type: "string" });
    const revision = (await call("POST", "/v1/organizations/acme/projects/api/contract/revisions", owner.cli, { contract: { schemaVersion: 1, items: [item("DB_PASS"), item("OTHER")] } })).body;
    await call("POST", `/v1/organizations/acme/projects/api/contract/revisions/${revision.id}/activate`, owner.cli, {});
    org = await getOrganization(ctx, "acme");
    project = await getProject(ctx, org.id, projectId);
    env = await getEnvironment(ctx, project.id, "prod");
    await setValue(ctx, org, project, env, "DB_PASS", { value: "first" }, owner.id);
    await db.query(
      `INSERT INTO security_controls (organization_id, control, mode, config, version, changed_by, changed_at)
       VALUES ($1, 'admin-step-up', 'enforce', NULL, 1, $2, now())`,
      [org.id, owner.id],
    );
  });
  afterEach(async () => {
    await db?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
      await admin.end();
    }
  });

  describe("a value write by the same person, holding the environment, then the export: it waits at step 2 and finds its capture stale", () => {
    const writers: [string, () => Promise<unknown>, string][] = [
      ["setValue", () => setValue(pctx, org, project, env, "DB_PASS", { value: "second" }, owner.id), "second"],
      ["beginRotation", () => beginRotation(pctx, org, project, env, "DB_PASS", { value: "rotated" }, owner.id), "rotated"],
      ["applyChangeSet", () => applyChangeSet(pctx, org, project, env, [{ op: "set", item: "DB_PASS", value: "batch" }, { op: "set", item: "OTHER", value: "new" }], owner.id), "batch"],
    ];
    for (const [name, writer, value] of writers) {
      it(name, async () => {
        const asked = await approval(owner, "POST", `${E}/disclosures`, { items: ["DB_PASS"], purpose: "export" });
        const [, stale] = await race(ENV_LOCK("FOR NO KEY UPDATE"), writer, () => exportDbPass(asked));
        expect(stale.status, JSON.stringify(stale.body)).toBe(409);
        expect(stale.body.error).toMatchObject({ code: "STATE_CHANGED", details: { reason: "stale-capture" } });
        expect(await consumed(asked)).toBe(false);
        const fresh = await exportDbPass(asked);
        expect(fresh.status, JSON.stringify(fresh.body)).toBe(200);
        expect(fresh.body.items[0].value).toBe(value);
        expect(await consumed(asked)).toBe(true);
      });
    }
  });

  it("a value write by another person, holding the environment: the export waits at step 9 and finds its capture stale", async () => {
    // Inviting a member needs no approval; Bob is made an admin directly.
    const invite = await issueInviteGrant(ctx, { organizationId: org.id, role: "member", name: "Bob" }, owner.id);
    const bob = (await consumeSetupGrant(ctx, invite.token, {})).identityId;
    await db.query("UPDATE org_memberships SET role = 'admin' WHERE organization_id = $1 AND identity_id = $2", [org.id, bob]);
    const asked = await approval(owner, "POST", `${E}/disclosures`, { items: ["DB_PASS"], purpose: "export" });
    const [, stale] = await race(
      ENV_LOCK("FOR NO KEY UPDATE"),
      () => setValue(pctx, org, project, env, "DB_PASS", { value: "bobs" }, bob),
      () => exportDbPass(asked),
    );
    expect(stale.status, JSON.stringify(stale.body)).toBe(409);
    expect(stale.body.error.details.reason).toBe("stale-capture");
    expect(await consumed(asked)).toBe(false);
    expect((await exportDbPass(asked)).body.items[0].value).toBe("bobs");
  });

  it("the export holding the environment, then a value write by the same person: the write waits until the export committed the old value", async () => {
    const asked = await approval(owner, "POST", `${E}/disclosures`, { items: ["DB_PASS"], purpose: "export" });
    const [exported] = await race(EXPORT_ENV_LOCK, () => exportDbPass(asked), () => setValue(pctx, org, project, env, "DB_PASS", { value: "second" }, owner.id));
    expect(exported.status, JSON.stringify(exported.body)).toBe(200);
    expect(exported.body.items[0].value).toBe("first");
    expect(await consumed(asked)).toBe(true);
    const now = await call("POST", `${E}/disclosures`, owner.cli, { items: ["DB_PASS"] });
    expect(now.body.items[0].value).toBe("second");
  });

  it("a protected Project deletion, with its approval, against createEnvironment in that Project by the same person: both finish", async () => {
    const asked = await approval(owner, "DELETE", "/v1/organizations/acme/projects/api");
    const [created, deleted] = await race(
      ENV_LOCK("FOR KEY SHARE"),
      () => createEnvironment(pctx, org.id, project.id, { name: "prod/pr-1", kind: "preview", parentEnvironmentId: env.id }, owner.id),
      () => call("DELETE", "/v1/organizations/acme/projects/api", owner.web, undefined, { "Varlatch-Approval": asked }),
    );
    expect(created).toMatchObject({ name: "prod/pr-1" });
    expect(deleted.status, JSON.stringify(deleted.body)).toBe(200);
    expect(deleted.body).toMatchObject({ environments: 2 });
    expect(await consumed(asked)).toBe(true);
  });

  describe("a Project deletion while another transaction holds the same Project's deletion uncommitted: it waits, then answers not-found before passkey-verification", () => {
    const P = "/v1/organizations/acme/projects/api";
    const intents = async () => ((await db.query("SELECT count(*)::int AS n FROM approval_intents")).rows[0] as { n: number }).n;
    const setControl = (control: string, mode: string) =>
      db.query(
        `INSERT INTO security_controls (organization_id, control, mode, config, version, changed_by, changed_at)
         VALUES ($1, $2, $3, NULL, 1, $4, now())
         ON CONFLICT (organization_id, control) DO UPDATE SET mode = $3, version = security_controls.version + 1`,
        [org.id, control, mode, owner.id],
      );
    /**
     * Transaction A deletes the Project (its row FOR UPDATE, tombstoned)
     * and holds it uncommitted while `send` runs; once `send` waits on a
     * lock, A commits.
     */
    const whileDeleting = async <T>(send: () => Promise<T>): Promise<T> => {
      const a = await db.connect();
      await a.query("BEGIN");
      await a.query("SELECT id FROM organizations WHERE id = $1 FOR KEY SHARE", [org.id]);
      await a.query("SELECT id FROM identities WHERE id = $1 FOR KEY SHARE", [owner.id]);
      await a.query("SELECT id FROM projects WHERE id = $1 FOR UPDATE", [project.id]);
      await a.query("UPDATE projects SET deleted_at = now() WHERE id = $1", [project.id]);
      const sent = send();
      try {
        await waitingOnLock();
      } finally {
        await a.query("COMMIT");
        a.release();
      }
      return sent;
    };
    const notFound = (res: { status: number; body: any }) => {
      expect(res.status, JSON.stringify(res.body)).toBe(404);
      expect(res.body.error.code).toBe("RESOURCE_NOT_FOUND");
    };

    it("admin-step-up off, passkey-verification at enforce, a requester without passkey evidence: 404, not 403", async () => {
      await setControl("admin-step-up", "off");
      await setControl("passkey-verification", "enforce");
      notFound(await whileDeleting(() => call("DELETE", P, owner.cli)));
    });

    it("admin-step-up at enforce, asking without an approval: 404, and no intent created", async () => {
      await setControl("passkey-verification", "enforce");
      const before = await intents();
      notFound(await whileDeleting(() => call("DELETE", P, owner.cli)));
      expect(await intents()).toBe(before);
    });

    it("admin-step-up at enforce, carrying an approval, by a requester passkey-verification refuses: 404, the approval unused", async () => {
      const asked = await approval(owner, "DELETE", P);
      await setControl("passkey-verification", "enforce");
      notFound(await whileDeleting(() => call("DELETE", P, owner.web, undefined, { "Varlatch-Approval": asked })));
      expect(await consumed(asked)).toBe(false);
    });

    it("admin-step-up at enforce, carrying an approval, passkey-verification off: found missing under the Project lock after the consumption, which rolls back", async () => {
      const asked = await approval(owner, "DELETE", P);
      notFound(await whileDeleting(() => call("DELETE", P, owner.web, undefined, { "Varlatch-Approval": asked })));
      expect(await consumed(asked)).toBe(false);
    });
  });
});
