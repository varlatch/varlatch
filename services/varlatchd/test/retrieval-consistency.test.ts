// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { ensureInstallation, issueBootstrapGrant, consumeSetupGrant } from "../src/domain/bootstrap.js";
import type { Querier } from "../src/db/migrate.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { buildApp } from "../src/http/app.js";

/**
 * A retrieval reads one snapshot (ADR-0038 Decision 6). A change that
 * commits while a request is between two of its reads is invisible to that
 * request, never half-applied; the next request sees it. Authorization is
 * effective at the snapshot boundary: a revocation that commits after the
 * snapshot began does not affect the request in flight.
 *
 * Needs real PostgreSQL for concurrency; CI provides a disposable database.
 */
const url = process.env.VARLATCH_TEST_DATABASE_URL;

describe.skipIf(!url)("retrieval reads one snapshot (real PostgreSQL)", () => {
  const database = `varlatch_retrieval_${process.pid}`;
  const P = "/v1/organizations/acme/projects/api";
  const DEV = `${P}/environments/dev`;
  const CHILD = `${P}/environments/${encodeURIComponent("dev/child")}`;
  let admin: ReturnType<typeof createPgQuerier>;
  let pool: ReturnType<typeof createPgQuerier>;
  let app: ReturnType<typeof buildApp>;
  let token: string;
  let projectId: string;
  /** Runs once, on the snapshot's connection, just before a matching read. */
  let trap: { when: RegExp; nth: number; run: () => Promise<void> } | null = null;

  const call = async (method: string, path: string, body?: unknown, bearer = token) => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${bearer}`, "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    return { status: res.status, body: (await res.json().catch(() => null)) as Record<string, unknown> };
  };
  const values = (body: Record<string, unknown>) =>
    Object.fromEntries(
      (body.items as { name: string; value: string | null; sensitive: boolean }[]).map((i) => [i.name, i.value]),
    );

  beforeEach(async () => {
    admin = createPgQuerier(url!);
    await admin.query(`CREATE DATABASE ${database}`);
    const target = new URL(url!);
    target.pathname = `/${database}`;
    pool = createPgQuerier(target.toString());
    // Every checked-out connection that starts a retrieval snapshot springs
    // the trap before its nth matching read; the write runs on another
    // connection and commits while the snapshot is open.
    const db = {
      ...pool,
      connect: async () => {
        const client = await pool.connect();
        let inSnapshot = false;
        let seen = 0;
        const querier: Querier & { release: (destroy?: boolean) => void } = {
          query: async (text, params) => {
            if (/^BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY/.test(text)) inSnapshot = true;
            else if (inSnapshot && trap && trap.when.test(text) && ++seen === trap.nth) {
              const { run } = trap;
              trap = null;
              await run();
            }
            return client.query(text, params);
          },
          release: client.release,
        };
        return querier;
      },
    };
    const connection = await pool.connect();
    try {
      await runMigrations(connection);
    } finally {
      connection.release();
    }
    const ctx: AppCtx = { db, rootKek: Buffer.alloc(32, 7) };
    await ensureInstallation(ctx);
    const setup = await issueBootstrapGrant(ctx);
    const identityId = (await consumeSetupGrant(ctx, setup.token, {})).identityId;
    token = (await issueCredential(pool, { identityId, kind: "cli" })).token;
    app = buildApp(ctx);
    await call("POST", "/v1/organizations", { slug: "acme", name: "Acme" });
    projectId = (await call("POST", "/v1/organizations/acme/projects", { slug: "api", name: "API", contractAuthority: "managed" })).body.id as string;
    const dev = await call("POST", `${P}/environments`, { name: "dev", tier: "development" });
    await call("POST", `${P}/environments`, { name: "dev/child", parentEnvironmentId: dev.body.id });
    const contract = (sensitiveFlag: boolean) => ({
      schemaVersion: 1,
      items: [
        { name: "A", required: { kind: "never" }, sensitive: false, type: "string" },
        { name: "B", required: { kind: "never" }, sensitive: false, type: "string" },
        { name: "FLAG", required: { kind: "never" }, sensitive: sensitiveFlag, type: "string" },
        { name: "TOKEN", required: { kind: "never" }, sensitive: true, type: "string" },
      ],
    });
    const first = await call("POST", `${P}/contract/revisions`, { contract: contract(false) });
    await call("POST", `${P}/contract/revisions/${first.body.id}/activate`, {});
    await call("POST", `${P}/contract/revisions`, { contract: contract(true) });
    for (const [path, name, value] of [
      [DEV, "A", "a1"],
      [DEV, "B", "b1"],
      [DEV, "FLAG", "on"],
      [DEV, "TOKEN", "t1"],
      [CHILD, "A", "child-a1"],
    ] as const) {
      expect((await call("PUT", `${path}/values/${name}`, { value })).status).toBe(200);
    }
  });
  afterEach(async () => {
    trap = null;
    await pool?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS ${database}`);
      await admin.end();
    }
  });

  it("a parent write between the Environment's two value reads is invisible, not half-applied", async () => {
    // resolveItems reads the child's values, then the parent's.
    trap = {
      when: /FROM env_values/,
      nth: 2,
      run: async () => {
        expect((await call("PUT", `${CHILD}/values/A`, { value: "child-a2" })).status).toBe(200);
        expect((await call("PUT", `${DEV}/values/B`, { value: "b2" })).status).toBe(200);
      },
    };
    const during = await call("GET", `${CHILD}/effective-configuration?include=values`);
    expect(trap).toBeNull();
    expect(values(during.body)).toMatchObject({ A: "child-a1", B: "b1" });
    const after = await call("GET", `${CHILD}/effective-configuration?include=values`);
    expect(values(after.body)).toMatchObject({ A: "child-a2", B: "b2" });
  });

  it("a Contract activation between reads is invisible: sensitivity and values come from one revision", async () => {
    const revisions = await pool.query("SELECT id FROM contract_revisions ORDER BY created_at DESC LIMIT 1");
    const second = (revisions.rows[0] as { id: string }).id;
    trap = {
      when: /FROM env_values/,
      nth: 1,
      run: async () => {
        expect((await call("POST", `${P}/contract/revisions/${second}/activate`, {})).status).toBe(200);
      },
    };
    const during = await call("GET", `${DEV}/effective-configuration?include=values`);
    expect(trap).toBeNull();
    // FLAG was non-sensitive in the snapshot's revision, so it is returned.
    expect(values(during.body).FLAG).toBe("on");
    const after = await call("GET", `${DEV}/effective-configuration?include=values`);
    expect(values(after.body).FLAG).toBeNull();
  });

  it("a rotation that begins mid-request is invisible to it", async () => {
    trap = {
      when: /FROM env_values/,
      nth: 1,
      run: async () => {
        expect((await call("POST", `${DEV}/values/TOKEN/rotations`, { value: "t2" })).status).toBe(201);
      },
    };
    const during = await call("POST", `${DEV}/disclosures`, { items: ["TOKEN"] });
    expect(trap).toBeNull();
    expect(during.body.items).toEqual([expect.objectContaining({ name: "TOKEN", value: "t1" })]);
    expect((during.body.items as { retiring?: unknown }[])[0]?.retiring).toBeUndefined();
    const after = await call("POST", `${DEV}/disclosures`, { items: ["TOKEN"] });
    expect((after.body.items as { value: string; retiring?: { value: string } }[])[0]).toMatchObject({
      value: "t2",
      retiring: { value: "t1" },
    });
  });

  it("a Grant revocation that commits after the snapshot began does not affect that request; the next is denied", async () => {
    const svc = await call("POST", "/v1/organizations/acme/identities", { name: "reader", kind: "service" });
    const grant = await call("POST", "/v1/organizations/acme/grants", {
      subjectIdentityId: svc.body.id,
      scope: { kind: "project", projectId },
      actions: ["config.metadata.read", "config.value.read"],
    });
    expect(grant.status).toBe(201);
    const reader = svc.body.credential as string;
    trap = {
      when: /FROM env_values/,
      nth: 1,
      run: async () => {
        expect((await call("DELETE", `/v1/organizations/acme/grants/${grant.body.id}`)).status).toBe(204);
      },
    };
    const during = await call("GET", `${DEV}/effective-configuration?include=values`, undefined, reader);
    expect(trap).toBeNull();
    expect(during.status).toBe(200);
    expect(values(during.body)).toMatchObject({ A: "a1", B: "b1" });
    const after = await call("GET", `${DEV}/effective-configuration?include=values`, undefined, reader);
    // A machine identity is aware of its own organization: denied, not hidden.
    expect(after.status).toBe(403);
  });

  it("concurrent audit writes never abort a retrieval", async () => {
    const requests = Array.from({ length: 24 }, (_, i) =>
      i % 3 === 0
        ? call("POST", `${DEV}/disclosures`, { scope: "all-authorized-secrets" })
        : i % 3 === 1
          ? call("GET", `${DEV}/effective-configuration?include=values`)
          : call("POST", `${DEV}/validate`, {}),
    );
    const statuses = (await Promise.all(requests)).map((r) => r.status);
    expect(statuses).toEqual(Array(24).fill(200));
  });
});
