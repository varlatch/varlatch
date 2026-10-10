// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { encryptGitHubAppKey } from "../src/crypto/hierarchy.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import { ensureInstallation, issueBootstrapGrant, consumeSetupGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { getOrganization, orgKekOf } from "../src/domain/orgs.js";
import {
  createAppConnection,
  createConnection,
  createTarget,
  revokeConnection,
  updateTarget,
} from "../src/domain/sync.js";
import { buildApp } from "../src/http/app.js";
import { fakeGitHubApps } from "./helpers/fake-github-app.js";

/**
 * ADR-0047 Decision 5's lock order on real PostgreSQL: every path that
 * touches an App Connection takes the App's row first, then Connections,
 * then Targets, as key rotation will. An outside transaction holds the App
 * row (as a rotation would); each path must be seen waiting on it, and,
 * while it waits, must not yet hold the Connection or Target: a probe
 * locks those with NOWAIT and succeeds.
 */

const url = process.env.VARLATCH_TEST_DATABASE_URL;

describe.skipIf(!url)("GitHub App lock order on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let identityId: string;
  let projectId: string;
  let environmentId: string;
  let appRowId: string;
  let appConnectionId: string;
  let tokenConnectionId: string;
  let github: ReturnType<typeof fakeGitHubApps>;
  let installationId: number;
  const database = `varlatch_applock_${process.pid}`;
  const org = () => getOrganization(ctx, "test");

  const waitingOnLock = async () => {
    for (let i = 0; i < 100; i++) {
      const res = await admin.query(
        "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'",
        [database],
      );
      if ((res.rows[0] as { n: number }).n >= 1) return;
      await new Promise((r) => setTimeout(r, 20));
    }
    throw new Error("the operation never waited on the App's lock");
  };

  /** Holds the App row, as a key rotation would, until released. */
  const holdApp = async () => {
    const holder = await db.connect();
    await holder.query("BEGIN");
    await holder.query("SELECT id FROM github_apps WHERE id = $1 FOR UPDATE", [appRowId]);
    return async () => {
      await holder.query("COMMIT");
      holder.release();
    };
  };

  /** Locks rows with NOWAIT and lets them go: throws if the waiting path already holds one. */
  const probe = async (table: "platform_connections" | "sync_targets", ids: string[]) => {
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      await client.query(`SELECT id FROM ${table} WHERE id = ANY($1::text[]) FOR UPDATE NOWAIT`, [ids]);
      await client.query("ROLLBACK");
    } finally {
      client.release();
    }
  };

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
    const pem = github.addApp({ id: 5254113, slug: "varlatch-test", clientId: "Iv23lock", owner: { login: "acme", id: 1, type: "Organization" }, permissions: { secrets: "write", environments: "write", metadata: "read" } });
    installationId = github.install(5254113, { login: "acme", id: 1, type: "Organization" }, "selected", null, [{ name: "api", private: true }]);
    appRowId = "gha_locktest";
    await db.query(
      `INSERT INTO github_apps (id, organization_id, github_app_id, slug, client_id, owner_login, owner_id, owner_type, key_envelope, created_by)
       VALUES ($1, $2, 5254113, 'varlatch-test', 'Iv23lock', 'acme', 1, 'organization', $3, $4)`,
      [appRowId, o.id, JSON.stringify(encryptGitHubAppKey(orgKekOf(ctx, o), o.id, appRowId, pem)), identityId],
    );
    appConnectionId = (await createAppConnection(ctx, o, { installationId, name: "App" }, identityId, null, github.fetchImpl)).id;
    tokenConnectionId = (await createConnection(ctx, o, { platform: "github-actions", baseIdentity: "acme", name: "Token", credential: "ghp_x" }, identityId)).id;
  });
  afterEach(async () => {
    await db?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
      await admin.end();
    }
  });

  const targetInput = (connectionId: string) => ({ connectionId, destination: { repo: "api" }, mapping: { kind: "wildcard" as const }, removeOrphans: false, redeploy: false });

  it("attaching a Target to an App Connection waits on the App before it locks the Connection", async () => {
    const release = await holdApp();
    const attaching = createTarget(ctx, await org(), projectId, environmentId, targetInput(appConnectionId), {}, identityId);
    await waitingOnLock();
    await probe("platform_connections", [appConnectionId]);
    await release();
    await expect(attaching).resolves.toMatchObject({ connection_id: appConnectionId });
  });

  it("re-pointing a Target onto an App Connection waits on the App before it locks either Connection or the Target", async () => {
    const t = await createTarget(ctx, await org(), projectId, environmentId, targetInput(tokenConnectionId), {}, identityId);
    const release = await holdApp();
    const repointing = updateTarget(ctx, await org(), t, { expectedVersion: t.version, connectionId: appConnectionId }, null, identityId);
    await waitingOnLock();
    await probe("platform_connections", [appConnectionId, tokenConnectionId]);
    await probe("sync_targets", [t.id]);
    await release();
    await expect(repointing).resolves.toMatchObject({ connection_id: appConnectionId });
  });

  it("revoking an App Connection waits on the App before it locks the Connection or its Targets", async () => {
    const t = await createTarget(ctx, await org(), projectId, environmentId, targetInput(appConnectionId), {}, identityId);
    const release = await holdApp();
    const revoking = revokeConnection(ctx, await org(), appConnectionId, identityId);
    await waitingOnLock();
    await probe("platform_connections", [appConnectionId]);
    await probe("sync_targets", [t.id]);
    await release();
    await expect(revoking).resolves.toBeUndefined();
    expect((await db.query("SELECT state FROM sync_targets WHERE id = $1", [t.id])).rows).toEqual([{ state: "disabled" }]);
  });

  it("creating an App Connection waits on the App", async () => {
    const release = await holdApp();
    const creating = createAppConnection(ctx, await org(), { installationId, name: "Second" }, identityId, null, github.fetchImpl);
    await waitingOnLock();
    await release();
    await expect(creating).resolves.toMatchObject({ credential_kind: "github-app" });
  });
});
