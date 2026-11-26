// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import { withTx, type PoolQuerier } from "../src/db/tx.js";
import { CapabilityRepair } from "../src/domain/capabilityrepair.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { retireIdentity } from "../src/domain/identities.js";
import { getOrganization } from "../src/domain/orgs.js";
import { buildApp } from "../src/http/app.js";

/**
 * Retirement against an issuance in flight, on real PostgreSQL: the
 * issuance passed authentication and its advisory reads while the
 * retirement was not yet committed, then waits for the identity's lock.
 * Once the retirement commits, the issuance must see it and refuse;
 * otherwise it would insert a Capability after retirement's revocation
 * sweep, which nothing revokes.
 */

const url = process.env.VARLATCH_TEST_DATABASE_URL;

describe.skipIf(!url)("Capability issuance racing an identity's retirement on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let http: ReturnType<typeof buildApp>;
  let adminId: string;
  let adminToken: string;
  let brokerId: string;
  let brokerToken: string;
  let agentId: string;
  const database = `varlatch_capretire_${process.pid}`;
  const ENV_PATH = "/v1/organizations/acme/projects/api/environments/development";

  const request = (path: string, method: string, body: unknown, token: string) =>
    http.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });

  const waitingOnLock = async () => {
    for (let i = 0; i < 200; i++) {
      const res = await admin.query(
        "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'",
        [database],
      );
      if ((res.rows[0] as { n: number }).n >= 1) return;
      await new Promise((r) => setTimeout(r, 20));
    }
    throw new Error("the issuance never waited on the identity's lock");
  };

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
    await ensureInstallation(ctx);
    adminId = (await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, {})).identityId;
    adminToken = (await issueCredential(db, { identityId: adminId, kind: "cli" })).token;
    http = buildApp(ctx);
    const post = async (path: string, body: unknown) => {
      const res = await request(path, "POST", body, adminToken);
      expect(res.status, path).toBe(201);
      return (await res.json()) as { id: string; credential: string | null };
    };
    await post("/v1/organizations", { slug: "acme", name: "Acme" });
    await post("/v1/organizations/acme/projects", { slug: "api", name: "API", contractAuthority: "git" });
    await post("/v1/organizations/acme/projects/api/environments", { name: "development", tier: "development" });
    const broker = await post("/v1/organizations/acme/identities", { name: "broker", kind: "broker" });
    brokerId = broker.id;
    brokerToken = broker.credential!;
    agentId = (await post("/v1/organizations/acme/identities", { name: "agent", kind: "agent" })).id;
    // The broker's credential is used once, so the race's request does not
    // also write its last use.
    expect((await request(`${ENV_PATH}/capabilities`, "GET", undefined, brokerToken)).status).toBe(200);
  });
  afterEach(async () => {
    await db?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
      await admin.end();
    }
  });

  const issue = () =>
    request(
      `${ENV_PATH}/capabilities`,
      "POST",
      {
        agentIdentityId: agentId,
        items: ["STRIPE_KEY"],
        destinations: ["api.stripe.com"],
        targets: { STRIPE_KEY: ["header:authorization"] },
        ttlSeconds: 600,
      },
      brokerToken,
    );

  /**
   * Retires `identityId` in a transaction that stays open until an
   * issuance started meanwhile waits on the identity's lock, then commits.
   * Returns the issuance's response.
   */
  const issueWhileRetiring = async (identityId: string) => {
    const orgId = (await getOrganization(ctx, "acme")).id;
    const holder = await db.connect();
    let retired!: () => void;
    const retiredUncommitted = new Promise<void>((r) => (retired = r));
    let commit!: () => void;
    const mayCommit = new Promise<void>((r) => (commit = r));
    const retiring = withTx(holder, async (tx) => {
      await retireIdentity({ ...ctx, db: tx }, orgId, identityId, adminId);
      retired();
      await mayCommit;
    }).finally(() => holder.release());
    await retiredUncommitted;
    const issuing = issue();
    await waitingOnLock();
    commit();
    await retiring;
    return issuing;
  };

  const liveCapabilitiesOf = async (identityId: string) =>
    (
      (
        await db.query(
          `SELECT count(*)::int AS n FROM capabilities
           WHERE (agent_identity_id = $1 OR broker_identity_id = $1) AND revoked_at IS NULL`,
          [identityId],
        )
      ).rows[0] as { n: number }
    ).n;

  it("an issuance for an Agent retired while it waited is refused", async () => {
    const res = await issueWhileRetiring(agentId);
    expect(res.status, await res.clone().text()).toBe(422);
    expect((await res.json()).error.message).toBe("Agent identity is disabled");
    expect(await liveCapabilitiesOf(agentId)).toBe(0);
  });

  it("an issuance by a Broker retired while it waited is refused", async () => {
    const res = await issueWhileRetiring(brokerId);
    expect(res.status, await res.clone().text()).toBe(401);
    expect((await res.json()).error.code).toBe("INVALID_CREDENTIAL");
    expect(await liveCapabilitiesOf(brokerId)).toBe(0);
  });

  it("an exercise whose snapshot opened before the repair completed is refused", async () => {
    // A Capability an earlier release's retirement of its Agent left live;
    // the Agent was reactivated since, which made it work again.
    expect((await request(`${ENV_PATH}/values/STRIPE_KEY`, "PUT", { value: "sk_live_1" }, adminToken)).status).toBe(200);
    const projectId = ((await (await request("/v1/organizations/acme/projects/api", "GET", undefined, adminToken)).json()) as { id: string }).id;
    expect(
      (
        await request(
          "/v1/organizations/acme/grants",
          "POST",
          { subjectIdentityId: agentId, scope: { kind: "project", projectId }, actions: ["secret.use"] },
          adminToken,
        )
      ).status,
    ).toBe(201);
    const issued = await issue();
    expect(issued.status, await issued.clone().text()).toBe(201);
    const cap = (await issued.json()) as { id: string; secret: string };
    expect((await request(`/v1/organizations/acme/identities/${agentId}/retire`, "POST", {}, adminToken)).status).toBe(200);
    await db.query("UPDATE capabilities SET revoked_at = NULL WHERE id = $1", [cap.id]);
    expect((await request(`/v1/organizations/acme/identities/${agentId}/reactivate`, "POST", {}, adminToken)).status).toBe(200);

    // The repair has not run; it completes right after the exercise's
    // snapshot opened, before anything else the exercise reads.
    const repair = new CapabilityRepair(undefined, { log: () => {}, error: () => {} });
    let armed = true;
    let repairedDuringSnapshot = false;
    const racing: PoolQuerier = {
      query: (text, params) => db.query(text, params),
      connect: async () => {
        const client = await db.connect();
        return {
          release: (destroy?: boolean) => client.release(destroy),
          query: async (text: string, params?: unknown[]) => {
            const res = await client.query(text, params);
            if (armed && text === "SELECT now() AS now") {
              armed = false;
              repairedDuringSnapshot = await repair.attempt(ctx);
            }
            return res;
          },
        };
      },
    };
    const racingApp = buildApp({ ...ctx, db: racing, capabilityRepair: repair });
    const res = await racingApp.request(`${ENV_PATH}/capabilities/${cap.id}/exercises`, {
      method: "POST",
      headers: { Authorization: `Bearer ${brokerToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        capabilitySecret: cap.secret,
        destination: { host: "api.stripe.com", port: 443 },
        placements: [{ item: "STRIPE_KEY", target: "header:authorization" }],
      }),
    });
    const text = await res.text();
    expect([403, 503], text).toContain(res.status);
    expect(text).not.toContain("sk_live_1");
    if (repairedDuringSnapshot) expect(repair.ready).toBe(true);
    expect(
      (
        (
          await db.query(
            "SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'capability.exercised' AND resource->>'capabilityId' = $1",
            [cap.id],
          )
        ).rows[0] as { n: number }
      ).n,
    ).toBe(0);
    // Repaired, the Capability is revoked.
    expect(await repair.attempt(ctx)).toBe(true);
    expect(((await db.query("SELECT revoked_at FROM capabilities WHERE id = $1", [cap.id])).rows[0] as { revoked_at: unknown }).revoked_at).not.toBeNull();
  });
});
