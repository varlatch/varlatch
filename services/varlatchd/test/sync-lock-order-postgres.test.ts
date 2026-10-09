// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations, type Querier } from "../src/db/migrate.js";
import type { PoolQuerier } from "../src/db/tx.js";
import { issueCredential } from "../src/auth/credentials.js";
import { ensureInstallation, issueBootstrapGrant, consumeSetupGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { getOrganization } from "../src/domain/orgs.js";
import {
  createConnection,
  createTarget,
  replaceConnectionCredential,
  revokeConnection,
  updateTarget,
  type SyncTargetRow,
} from "../src/domain/sync.js";
import { buildApp } from "../src/http/app.js";

/**
 * Lock order of Target edits against Connection credential replacement and
 * revocation, on real PostgreSQL (PGlite has one connection and cannot show
 * a lock wait). Replacement and revocation lock the Connection, then its
 * Targets; a Target edit must take the Connection before the Target too, or
 * the two deadlock and PostgreSQL aborts one (40P01).
 *
 * Each case is made deterministic: one side pauses right after its first
 * lock, the other starts and is seen waiting on a lock in pg_stat_activity,
 * and only then does the first side go on.
 */

const url = process.env.VARLATCH_TEST_DATABASE_URL;

/** A pool whose queries can pause once, right after one matching statement ran. */
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

describe.skipIf(!url)("Target edits and Connection replacement or revocation on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let paused: ReturnType<typeof pausing>;
  let pctx: AppCtx;
  let identityId: string;
  let connectionId: string;
  let target: SyncTargetRow;
  const database = `varlatch_lockorder_${process.pid}`;

  const waitingOnLock = async (expected = 1) => {
    for (let i = 0; i < 100; i++) {
      const res = await admin.query(
        "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'",
        [database],
      );
      if ((res.rows[0] as { n: number }).n >= expected) return;
      await new Promise((r) => setTimeout(r, 20));
    }
    throw new Error("the second operation never waited on a lock");
  };
  const org = () => getOrganization(ctx, "test");
  const edit = async () =>
    updateTarget(pctx, await org(), target, { expectedVersion: target.version, mapping: { kind: "wildcard", exclude: ["PORT"] } }, null, identityId);

  beforeEach(async () => {
    admin = createPgQuerier(url!);
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
    ctx = { db, rootKek: Buffer.alloc(32, 17) };
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
    const environmentId = (await post("/v1/organizations/test/projects/api/environments", { name: "dev", tier: "development" })).id;
    const o = await org();
    connectionId = (await createConnection(ctx, o, { platform: "github-actions", baseIdentity: "acme", name: "GitHub", credential: "ghp_first" }, identityId)).id;
    target = await createTarget(
      ctx,
      o,
      projectId,
      environmentId,
      { connectionId, destination: { repo: "api" }, mapping: { kind: "wildcard" }, removeOrphans: false, redeploy: false },
      {},
      identityId,
    );
  });
  afterEach(async () => {
    await db?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
      await admin.end();
    }
  });

  it("a Target edit that arrives while a credential replacement holds the Connection waits, and both complete", async () => {
    const pause = paused.pauseAfter(/FROM platform_connections\s+WHERE id = \$1 AND organization_id = \$2 AND revoked_at IS NULL FOR UPDATE/);
    const replacing = replaceConnectionCredential(pctx, await org(), connectionId, { credential: "ghp_second", expectedVersion: 1 }, async () => {}, identityId);
    await pause.reached;
    const editing = edit();
    await waitingOnLock();
    pause.release();
    const [replaced, edited] = await Promise.allSettled([replacing, editing]);
    expect(replaced.status, String((replaced as PromiseRejectedResult).reason)).toBe("fulfilled");
    expect(edited.status, String((edited as PromiseRejectedResult).reason)).toBe("fulfilled");
  });

  it("a credential replacement that arrives during a Target edit waits, and both complete", async () => {
    const pause = paused.pauseAfter(/FROM sync_targets WHERE id = \$1 AND revoked_at IS NULL FOR UPDATE/);
    const editing = edit();
    await pause.reached;
    const replacing = replaceConnectionCredential(pctx, await org(), connectionId, { credential: "ghp_second", expectedVersion: 1 }, async () => {}, identityId);
    await waitingOnLock();
    pause.release();
    const [edited, replaced] = await Promise.allSettled([editing, replacing]);
    expect(edited.status, String((edited as PromiseRejectedResult).reason)).toBe("fulfilled");
    expect(replaced.status, String((replaced as PromiseRejectedResult).reason)).toBe("fulfilled");
  });

  it("a Target edit that arrives while the Connection is being revoked waits, then is refused as stale, never as a deadlock", async () => {
    const pause = paused.pauseAfter(/UPDATE platform_connections SET revoked_at/);
    const revoking = revokeConnection(pctx, await org(), connectionId, identityId);
    await pause.reached;
    const editing = edit();
    await waitingOnLock();
    pause.release();
    const [revoked, edited] = await Promise.allSettled([revoking, editing]);
    expect(revoked.status, String((revoked as PromiseRejectedResult).reason)).toBe("fulfilled");
    expect(edited.status).toBe("rejected");
    expect((edited as PromiseRejectedResult).reason).toMatchObject({ code: "VERSION_CONFLICT" });
    const row = (await db.query("SELECT state, disabled_reason FROM sync_targets WHERE id = $1", [target.id])).rows[0];
    expect(row).toEqual({ state: "disabled", disabled_reason: "connection-revoked" });
  });

  it("a revocation that arrives during a Target edit waits, and disables the edited Target", async () => {
    const pause = paused.pauseAfter(/FROM sync_targets WHERE id = \$1 AND revoked_at IS NULL FOR UPDATE/);
    const editing = edit();
    await pause.reached;
    const revoking = revokeConnection(pctx, await org(), connectionId, identityId);
    await waitingOnLock();
    pause.release();
    const [edited, revoked] = await Promise.allSettled([editing, revoking]);
    expect(edited.status, String((edited as PromiseRejectedResult).reason)).toBe("fulfilled");
    expect(revoked.status, String((revoked as PromiseRejectedResult).reason)).toBe("fulfilled");
    const row = (await db.query("SELECT state, disabled_reason, mapping FROM sync_targets WHERE id = $1", [target.id])).rows[0];
    expect(row).toMatchObject({ state: "disabled", disabled_reason: "connection-revoked", mapping: { kind: "wildcard", exclude: ["PORT"] } });
  });
});
