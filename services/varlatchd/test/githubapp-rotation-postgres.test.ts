// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { encryptGitHubAppKey } from "../src/crypto/hierarchy.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations, type Querier } from "../src/db/migrate.js";
import type { PoolQuerier } from "../src/db/tx.js";
import { ensureInstallation, issueBootstrapGrant, consumeSetupGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { getOrganization, orgKekOf } from "../src/domain/orgs.js";
import {
  createAppConnection,
  createTarget,
  removeGitHubApp,
  rotateGitHubAppKey,
  updateTarget,
  type SyncTargetRow,
} from "../src/domain/sync.js";
import { buildApp } from "../src/http/app.js";
import { fakeGitHubApps } from "./helpers/fake-github-app.js";

/**
 * Key rotation and App removal against attachment, on real PostgreSQL
 * (ADR-0047 Decision 5; the spike's E6.6-E6.10 and E7.11-E7.13, now on the
 * implementation). Each interleaving is deterministic: one side pauses
 * right after a known lock, the other starts and is seen waiting on a lock,
 * and only then does the first go on. A mixed concurrent run shows no
 * deadlock.
 */

const url = process.env.VARLATCH_TEST_DATABASE_URL;
const ROTATION_TARGETS = /FROM sync_targets\s+WHERE connection_id = ANY\(\$1::text\[\]\) AND revoked_at IS NULL ORDER BY id FOR UPDATE/;
const ATTACH_APP_LOCK = /SELECT id, removed_at FROM github_apps WHERE id = ANY/;

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

describe.skipIf(!url)("GitHub App rotation and removal against attachment on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let pctx: AppCtx;
  let paused: ReturnType<typeof pausing>;
  let identityId: string;
  let projectId: string;
  let environmentId: string;
  let connA: string;
  let connB: string;
  let instA: number;
  let pem: string;
  let github: ReturnType<typeof fakeGitHubApps>;
  const database = `varlatch_approt_${process.pid}`;
  const org = () => getOrganization(ctx, "test");
  let repoCounter = 0;

  const waitingOnLock = async () => {
    for (let i = 0; i < 150; i++) {
      const res = await admin.query(
        "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'",
        [database],
      );
      if ((res.rows[0] as { n: number }).n >= 1) return;
      await new Promise((r) => setTimeout(r, 20));
    }
    throw new Error("the second operation never waited on a lock");
  };
  const attach = async (c: AppCtx, connectionId: string) =>
    createTarget(c, await org(), projectId, environmentId, { connectionId, destination: { repo: `r${++repoCounter}` }, mapping: { kind: "wildcard" }, removeOrphans: false, redeploy: false }, {}, identityId);
  const appVersion = async () => ((await db.query("SELECT version FROM github_apps WHERE removed_at IS NULL")).rows[0] as { version: number }).version;
  const rotate = async (c: AppCtx, gate: (t: SyncTargetRow) => Promise<void> = async () => {}) =>
    rotateGitHubAppKey(c, await org(), { privateKey: pem, expectedVersion: await appVersion() }, gate, identityId, github.fetchImpl);
  const lastRotation = async () =>
    ((await db.query("SELECT metadata FROM audit_events WHERE event_type = 'sync.github_app_key_rotated' ORDER BY event_order DESC LIMIT 1")).rows[0] as {
      metadata: { reauthorizedTargets: string | null };
    }).metadata.reauthorizedTargets?.split(",") ?? [];

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
    const http = buildApp(ctx);
    const post = async (path: string, body: unknown) => {
      const res = await http.request(path, { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
      expect(res.status, path).toBe(201);
      return (await res.json()) as { id: string };
    };
    await post("/v1/organizations", { slug: "test", name: "Test" });
    projectId = (await post("/v1/organizations/test/projects", { slug: "api", name: "API", contractAuthority: "managed" })).id;
    environmentId = (await post("/v1/organizations/test/projects/api/environments", { name: "dev", tier: "development" })).id;
    const o = await org();
    github = fakeGitHubApps();
    pem = github.addApp({ id: 5254113, slug: "varlatch-test", clientId: "Iv23rot", owner: { login: "acme", id: 1, type: "Organization" }, permissions: { secrets: "write", environments: "write", metadata: "read" } });
    instA = github.install(5254113, { login: "acme", id: 1, type: "Organization" });
    const instB = github.install(5254113, { login: "acme-labs", id: 2, type: "Organization" });
    await db.query(
      `INSERT INTO github_apps (id, organization_id, github_app_id, slug, client_id, owner_login, owner_id, owner_type, key_envelope, created_by)
       VALUES ('gha_rot', $1, 5254113, 'varlatch-test', 'Iv23rot', 'acme', 1, 'organization', $2, $3)`,
      [o.id, JSON.stringify(encryptGitHubAppKey(orgKekOf(ctx, o), o.id, "gha_rot", pem)), identityId],
    );
    connA = (await createAppConnection(ctx, o, { installationId: instA, name: "A" }, identityId, null, github.fetchImpl)).id;
    connB = (await createAppConnection(ctx, o, { installationId: instB, name: "B" }, identityId, null, github.fetchImpl)).id;
    await attach(ctx, connA);
  });
  afterEach(async () => {
    await db?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
      await admin.end();
    }
  });

  it("an attachment that arrives while a rotation holds its locks waits, then lands outside that rotation's set", async () => {
    const pause = paused.pauseAfter(ROTATION_TARGETS);
    const rotating = rotate(pctx);
    await pause.reached;
    const attaching = attach(ctx, connA);
    await waitingOnLock();
    pause.release();
    const [rotated, attached] = await Promise.all([rotating, attaching]);
    expect(rotated.outcome).toBe("rotated");
    expect(await lastRotation()).not.toContain(attached.id);
  });

  it("a rotation that arrives while an attachment holds the App waits, then re-authorizes the new Target too", async () => {
    const pause = paused.pauseAfter(ATTACH_APP_LOCK);
    const attaching = attach(pctx, connB);
    await pause.reached;
    const gated: string[] = [];
    const rotating = rotate(ctx, async (t) => {
      gated.push(t.id);
    });
    await waitingOnLock();
    pause.release();
    const [attached, rotated] = await Promise.all([attaching, rotating]);
    expect(rotated.outcome).toBe("rotated");
    expect(gated).toContain(attached.id);
    expect(await lastRotation()).toContain(attached.id);
  });

  it("an attachment that arrives while removal holds its locks waits, then is refused", async () => {
    const pause = paused.pauseAfter(ROTATION_TARGETS);
    const removing = removeGitHubApp(pctx, await org(), "gha_rot", identityId);
    await pause.reached;
    const attaching = attach(ctx, connA);
    await waitingOnLock();
    pause.release();
    const [removed, attached] = await Promise.allSettled([removing, attaching]);
    expect(removed.status).toBe("fulfilled");
    expect(attached.status).toBe("rejected");
    expect((attached as PromiseRejectedResult).reason).toMatchObject({ code: "RESOURCE_NOT_FOUND" });
    expect((await db.query("SELECT count(*)::int AS n FROM sync_targets")).rows).toEqual([{ n: 1 }]);
  });

  it("a removal that arrives while an attachment holds the App waits, then disables the new Target too", async () => {
    const pause = paused.pauseAfter(ATTACH_APP_LOCK);
    const attaching = attach(pctx, connA);
    await pause.reached;
    const removing = removeGitHubApp(ctx, await org(), "gha_rot", identityId);
    await waitingOnLock();
    pause.release();
    const [attached] = await Promise.all([attaching, removing]);
    expect((await db.query("SELECT state, disabled_reason FROM sync_targets WHERE id = $1", [attached.id])).rows).toEqual([
      { state: "disabled", disabled_reason: "connection-revoked" },
    ]);
  });

  it("rotations, attachments, re-points, and App Connection creations run concurrently without a deadlock", async () => {
    const errors: string[] = [];
    let rotated = 0;
    let stale = 0;
    const worker = async (n: number) => {
      for (let i = 0; i < 15; i++) {
        const op = (n + i) % 4;
        try {
          if (op === 0) {
            const result = await rotate(ctx);
            if (result.outcome === "rotated") rotated++;
          } else if (op === 1) {
            await attach(ctx, i % 2 === 0 ? connA : connB);
          } else if (op === 2) {
            const rows = (await db.query("SELECT * FROM sync_targets WHERE revoked_at IS NULL ORDER BY random() LIMIT 1")).rows as SyncTargetRow[];
            if (rows[0]) {
              const t = rows[0];
              await updateTarget(ctx, await org(), t, { expectedVersion: t.version, connectionId: t.connection_id === connA ? connB : connA }, null, identityId);
            }
          } else {
            await createAppConnection(ctx, await org(), { installationId: instA, name: `extra-${n}-${i}` }, identityId, null, github.fetchImpl);
          }
        } catch (err) {
          const code = (err as { code?: string }).code;
          if (code === "VERSION_CONFLICT") stale++;
          else errors.push(`${code ?? ""} ${(err as Error).message}`);
        }
      }
    };
    await Promise.all(Array.from({ length: 6 }, (_, n) => worker(n)));
    expect(errors).toEqual([]);
    expect(rotated).toBeGreaterThan(0);
    expect(rotated + stale).toBeGreaterThan(0);
  });
});
