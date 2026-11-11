// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations, type Querier } from "../src/db/migrate.js";
import type { PoolQuerier } from "../src/db/tx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { createEnvironment, getEnvironment, type EnvironmentRow } from "../src/domain/environments.js";
import { getOrganization, type OrgRow } from "../src/domain/orgs.js";
import { deleteProject, getProject, type ProjectRow } from "../src/domain/projects.js";
import { createConnection, createTarget, revokeConnection } from "../src/domain/sync.js";
import { applyChangeSet, beginRotation, setValue } from "../src/domain/values.js";
import { buildApp } from "../src/http/app.js";

/**
 * The one lock order (ADR-0054 amendment E) against the interleavings that
 * deadlock under the old order, on real PostgreSQL (PGlite has one
 * connection: nothing there can wait or deadlock).
 *
 * Under the old order a writer took its Project and environment, and only
 * later its person, implicitly, through a foreign key (created_by,
 * owner_identity_id). A transaction that consumes the same person's
 * approval takes the person FOR UPDATE first, then the Project or
 * environment or Connection: each waited for the other, and PostgreSQL
 * aborted one (40P01). Under the one order every writer takes its people
 * at step 2, before any Project, environment or domain row, so one of the
 * two waits there, holding nothing the other needs, and both finish.
 *
 * The protected side is emulated with plain SQL where its code does not
 * exist yet: an export's phase 2 (amendment C), and the approval
 * consumption of a protected deletion (its person FOR UPDATE, after the
 * Organization) in front of the real deletion. Each case is made
 * deterministic: the writer pauses right after it took the row the other
 * side needs, the other side starts and is seen waiting on a lock, and only
 * then does the writer go on.
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

/** The environment lock of the writer protocol, in any mode (old and new statement text alike). */
const ENV_LOCK = (mode: string) => new RegExp(`FROM environments WHERE id = ANY\\(\\$1\\) AND project_id = \\$2 ORDER BY id ${mode}`);
/** lockConnectionsAndApps' Connection lock. */
const CONNECTION_LOCK = /FROM platform_connections\s+WHERE id = ANY\(\$1::text\[\]\) AND organization_id = \$2\s+ORDER BY id FOR UPDATE/;

/** "ok", or the SQLSTATE (40P01: deadlock) or message a side failed with. */
const outcome = (r: PromiseSettledResult<unknown>) =>
  r.status === "fulfilled" ? "ok" : ((r.reason as { code?: string }).code ?? String((r.reason as Error).message));

describe.skipIf(!url)("one lock order (ADR-0054 amendment E) on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let paused: ReturnType<typeof pausing>;
  let pctx: AppCtx;
  let identityId: string;
  let org: OrgRow;
  let project: ProjectRow;
  let env: EnvironmentRow;
  let connectionId: string;
  const database = `varlatch_lockorder_e_${process.pid}`;

  const waitingOnLock = async () => {
    for (let i = 0; i < 250; i++) {
      const res = await admin.query(
        "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'",
        [database],
      );
      if ((res.rows[0] as { n: number }).n >= 1) return;
      await new Promise((r) => setTimeout(r, 20));
    }
    throw new Error("the second transaction never waited on a lock");
  };

  /**
   * One transaction on its own connection: `body` runs inside it, then it
   * commits; any failure rolls it back and is rethrown.
   */
  const inTransaction = async (body: (q: Querier) => Promise<void>) => {
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      await body(client);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  };

  /**
   * The consumption of the person's approval (amendment E: steps 1 and 2):
   * the Organization FOR KEY SHARE, then the person FOR UPDATE.
   */
  const consume = async (q: Querier) => {
    await q.query("SELECT id FROM organizations WHERE id = $1 FOR KEY SHARE", [org.id]);
    await q.query("SELECT id FROM identities WHERE id = $1 FOR UPDATE", [identityId]);
  };

  /**
   * An export's phase 2 (amendment C, emulated: the code does not exist
   * yet): the Organization, the consumption (the person FOR UPDATE), the
   * Project FOR SHARE, the environment and its parent FOR SHARE in id
   * order; then the audit event and the commit.
   */
  const exportPhase2 = () =>
    inTransaction(async (q) => {
      await consume(q);
      await q.query("SELECT id FROM projects WHERE id = $1 FOR SHARE", [project.id]);
      await q.query("SELECT id FROM environments WHERE id = ANY($1) ORDER BY id FOR SHARE", [[env.id]]);
    });

  /** A protected deletion: the consumption, then the real deletion, in one transaction. */
  const protectedly = (run: (c: AppCtx) => Promise<unknown>) =>
    inTransaction(async (q) => {
      await consume(q);
      // The deletion's own withTx issues a BEGIN (a warning only, inside
      // this transaction) and the COMMIT that ends both.
      await run({ ...ctx, db: q });
    });

  beforeEach(async () => {
    admin = createPgQuerier(url!);
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${database}`);
    const dbUrl = new URL(url!);
    dbUrl.pathname = `/${database}`;
    db = createPgQuerier(dbUrl.toString());
    const connection = await db.connect();
    try {
      await runMigrations(connection);
    } finally {
      connection.release();
    }
    ctx = { db, rootKek: Buffer.alloc(32, 23) };
    paused = pausing(db);
    pctx = { db: paused.pool, rootKek: ctx.rootKek };
    await ensureInstallation(ctx);
    identityId = (await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, {})).identityId;
    const token = (await issueCredential(db, { identityId, kind: "cli" })).token;
    const app = buildApp(ctx);
    const post = async (path: string, body: unknown) => {
      const res = await app.request(path, { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
      expect(res.status, path).toBe(201);
      return (await res.json()) as { id: string };
    };
    await post("/v1/organizations", { slug: "test", name: "Test" });
    const projectId = (await post("/v1/organizations/test/projects", { slug: "api", name: "API", contractAuthority: "managed" })).id;
    await post("/v1/organizations/test/projects/api/environments", { name: "dev", tier: "development" });
    org = await getOrganization(ctx, "test");
    project = await getProject(ctx, org.id, projectId);
    env = await getEnvironment(ctx, project.id, "dev");
    await setValue(ctx, org, project, env, "API_KEY", { value: "first" }, identityId);
    connectionId = (await createConnection(ctx, org, { platform: "github-actions", baseIdentity: "acme", name: "GitHub", credential: "ghp_first" }, identityId)).id;
  });

  afterEach(async () => {
    await db?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
      await admin.end();
    }
  });

  /**
   * The writer pauses holding `pausedAt`; the other side starts and waits
   * for a lock; the writer goes on. Both must finish.
   */
  const race = async (pausedAt: RegExp, writer: () => Promise<unknown>, other: () => Promise<unknown>) => {
    const pause = paused.pauseAfter(pausedAt);
    const writing = writer();
    await pause.reached;
    const otherRun = other();
    await waitingOnLock();
    pause.release();
    return (await Promise.allSettled([writing, otherRun])).map(outcome);
  };

  describe("export phase 2 against a value write by the same person, holding the environment", () => {
    it("setValue", async () => {
      expect(await race(ENV_LOCK("FOR NO KEY UPDATE"), () => setValue(pctx, org, project, env, "API_KEY", { value: "second" }, identityId), exportPhase2))
        .toEqual(["ok", "ok"]);
    });

    it("beginRotation", async () => {
      expect(await race(ENV_LOCK("FOR NO KEY UPDATE"), () => beginRotation(pctx, org, project, env, "API_KEY", { value: "rotated" }, identityId), exportPhase2))
        .toEqual(["ok", "ok"]);
    });

    it("applyChangeSet", async () => {
      expect(await race(
        ENV_LOCK("FOR NO KEY UPDATE"),
        () => applyChangeSet(pctx, org, project, env, [{ op: "set", item: "API_KEY", value: "batch" }, { op: "set", item: "OTHER", value: "new" }], identityId),
        exportPhase2,
      )).toEqual(["ok", "ok"]);
    });
  });

  it("a protected Connection deletion against createTarget on that Connection by the same person", async () => {
    expect(await race(
      CONNECTION_LOCK,
      () => createTarget(pctx, org, project.id, env.id, { connectionId, destination: { repo: "api" }, mapping: { kind: "wildcard" }, removeOrphans: false, redeploy: false }, {}, identityId),
      () => protectedly((c) => revokeConnection(c, org, connectionId, identityId)),
    )).toEqual(["ok", "ok"]);
  });

  describe("a protected Project deletion against a writer in that Project by the same person", () => {
    it("createEnvironment (a personal environment the person owns)", async () => {
      expect(await race(
        ENV_LOCK("FOR KEY SHARE"),
        () => createEnvironment(pctx, org.id, project.id, { name: "dev/alice", kind: "personal", parentEnvironmentId: env.id }, identityId),
        () => protectedly((c) => deleteProject(c, org.id, project.id, identityId)),
      )).toEqual(["ok", "ok"]);
    });

    it("createTarget", async () => {
      expect(await race(
        CONNECTION_LOCK,
        () => createTarget(pctx, org, project.id, env.id, { connectionId, destination: { repo: "api" }, mapping: { kind: "wildcard" }, removeOrphans: false, redeploy: false }, {}, identityId),
        () => protectedly((c) => deleteProject(c, org.id, project.id, identityId)),
      )).toEqual(["ok", "ok"]);
    });
  });
});
