// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { runMigrations } from "../src/db/migrate.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
} from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * Capabilities over HTTP (ADR-0022): issuance narrows and never grants;
 * exercise is the authoritative boundary — Agent secret.use, destination,
 * expiry, revocation, and Requirements all evaluated against current state,
 * audited before decryption.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let brokerToken: string;
let brokerId: string;
let agentId: string;

const ENV_PATH = "/v1/organizations/acme/projects/api/environments/development";

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  const cred = await issueCredential(ctx.db, { identityId: consumed.identityId, kind: "cli" });
  adminToken = cred.token;
  app = buildApp(ctx);

  await post("/v1/organizations", { name: "Acme", slug: "acme" });
  await post("/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "git" });
  await post("/v1/organizations/acme/projects/api/environments", { name: "development", tier: "development" });

  const broker = await (await post("/v1/organizations/acme/identities", { name: "local broker", kind: "broker" })).json();
  brokerId = broker.id;
  brokerToken = broker.credential;
  const agent = await (await post("/v1/organizations/acme/identities", { name: "coding agent", kind: "agent" })).json();
  agentId = agent.id;
  expect(agent.credential).toBeNull(); // ADR-0022 §8: no reusable credential by default.

  // Uncontracted items are sensitive: STRIPE_KEY is a Secret.
  await put(`${ENV_PATH}/values/STRIPE_KEY`, { value: "sk_live_1" });
});
afterEach(async () => {
  await ctx.close();
});

function auth(token = adminToken): HeadersInit {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}
async function post(path: string, body: unknown, token = adminToken) {
  return app.request(path, { method: "POST", headers: auth(token), body: JSON.stringify(body) });
}
async function put(path: string, body: unknown) {
  return app.request(path, { method: "PUT", headers: auth(), body: JSON.stringify(body) });
}

async function grantUse(subject = agentId) {
  const res = await post("/v1/organizations/acme/grants", {
    subjectIdentityId: subject,
    scope: { kind: "project", projectId: (await projectId()) },
    actions: ["secret.use"],
  });
  expect(res.status).toBe(201);
  return (await res.json()).id as string;
}

async function projectId(): Promise<string> {
  const res = await app.request("/v1/organizations/acme/projects/api", { headers: auth() });
  return (await res.json()).id;
}

/** The items of the last issuance: exercise places each at its header target by default. */
let lastItems: string[] = ["STRIPE_KEY"];

async function issue(overrides: Record<string, unknown> = {}, token = brokerToken) {
  const items = (overrides.items as string[] | undefined) ?? ["STRIPE_KEY"];
  lastItems = items;
  return post(
    `${ENV_PATH}/capabilities`,
    {
      agentIdentityId: agentId,
      items,
      destinations: ["api.stripe.com"],
      targets: Object.fromEntries(items.map((item) => [item, ["header:authorization"]])),
      ttlSeconds: 600,
      runId: "run_test",
      ...overrides,
    },
    token,
  );
}

const placed = (...items: string[]) => items.map((item) => ({ item, target: "header:authorization" }));

async function exercise(
  capabilityId: string,
  secret: string,
  destination = { host: "api.stripe.com", port: 443 },
  token = brokerToken,
  placements: { item: string; target: string }[] = placed(...lastItems),
) {
  return post(`${ENV_PATH}/capabilities/${capabilityId}/exercises`, { capabilitySecret: secret, destination, placements }, token);
}

async function auditCount(eventType: string, reason?: string): Promise<number> {
  const params: unknown[] = [eventType];
  let where = "event_type = $1";
  if (reason) {
    where += " AND metadata::jsonb->>'reason' = $2";
    params.push(reason);
  }
  const res = await ctx.db.query(`SELECT count(*)::int AS n FROM audit_events WHERE ${where}`, params);
  return (res.rows[0] as { n: number }).n;
}

describe("issuance", () => {
  it("meta advertises the capability", async () => {
    const meta = await (await app.request("/v1/meta")).json();
    expect(meta.capabilities).toContain("capabilities.broker");
  });

  it("only broker identities may issue; others learn nothing", async () => {
    expect((await issue({}, adminToken)).status).toBe(404);
    const svc = await (await post("/v1/organizations/acme/identities", { name: "svc", kind: "service" })).json();
    expect((await issue({}, svc.credential)).status).toBe(404);
  });

  it("validates agent identity, items, destinations, ttl", async () => {
    const svc = await (await post("/v1/organizations/acme/identities", { name: "svc2", kind: "service" })).json();
    expect((await issue({ agentIdentityId: svc.id })).status).toBe(422);
    expect((await issue({ agentIdentityId: "idn_nope" })).status).toBe(422);
    expect((await issue({ destinations: ["http://x/y"] })).status).toBe(422);
    expect((await issue({ destinations: ["*.1.2.3.4"] })).status).toBe(422);
    expect((await issue({ items: ["bad name!"] })).status).toBe(422);
    expect((await issue({ ttlSeconds: 999999999 })).status).toBe(422);
  });

  it("returns a one-time secret, canonical selectors, and an advisory preflight", async () => {
    const res = await issue({ destinations: ["*.Stripe.com", "api.stripe.com:8443"] });
    expect(res.status).toBe(201);
    const cap = await res.json();
    expect(cap.secret).toMatch(/^vlt_cap_/);
    expect(cap.destinations).toEqual(["*.stripe.com:443", "api.stripe.com:8443"]);
    expect(cap.preflight).toBe("agent-lacks-secret-use"); // no Grant yet — advisory only
    const stored = await ctx.db.query("SELECT secret_hash FROM capabilities WHERE id = $1", [cap.id]);
    expect((stored.rows[0] as { secret_hash: string }).secret_hash).not.toContain(cap.secret);
    expect(await auditCount("capability.issued")).toBe(1);
  });
});

describe("exercise", () => {
  it("issuance does not grant: a valid-looking Capability without secret.use is denied", async () => {
    const cap = await (await issue()).json();
    const res = await exercise(cap.id, cap.secret);
    expect(res.status).toBe(403);
    expect((await res.json()).error.details.reason).toBe("authz-denied");
    expect(await auditCount("capability.denied", "authz-denied")).toBe(1);
  });

  it("with secret.use granted, exercise resolves current versions and audits before disclosure", async () => {
    await grantUse();
    const cap = await (await issue()).json();
    const res = await exercise(cap.id, cap.secret);
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = await res.json();
    expect(body.items).toHaveLength(1);
    expect(body.items[0]).toMatchObject({ name: "STRIPE_KEY", value: "sk_live_1" });
    const audit = await ctx.db.query(
      "SELECT metadata::jsonb AS m FROM audit_events WHERE event_type = 'capability.exercised'",
    );
    const meta = (audit.rows[0] as { m: Record<string, unknown> }).m;
    expect(meta.items).toBe(`STRIPE_KEY@${body.items[0].versionId}`);
    expect(meta.destination).toBe("api.stripe.com:443");
    expect(meta.runId).toBe("run_test");
  });

  it("secret rotation takes effect on the next exercise (Model B)", async () => {
    await grantUse();
    const cap = await (await issue()).json();
    const first = await (await exercise(cap.id, cap.secret)).json();
    await put(`${ENV_PATH}/values/STRIPE_KEY`, { value: "sk_live_2" });
    const second = await (await exercise(cap.id, cap.secret)).json();
    expect(second.items[0].value).toBe("sk_live_2");
    expect(second.items[0].versionId).not.toBe(first.items[0].versionId);
  });

  it("revoking the Agent's Grant denies the very next exercise", async () => {
    const grantId = await grantUse();
    const cap = await (await issue()).json();
    expect((await exercise(cap.id, cap.secret)).status).toBe(200);
    await app.request(`/v1/organizations/acme/grants/${grantId}`, { method: "DELETE", headers: auth() });
    expect((await exercise(cap.id, cap.secret)).status).toBe(403);
  });

  it("wrong secret and wrong broker are indistinguishable from not-found", async () => {
    await grantUse();
    const cap = await (await issue()).json();
    expect((await exercise(cap.id, "vlt_cap_wrong")).status).toBe(404);
    const other = await (await post("/v1/organizations/acme/identities", { name: "other broker", kind: "broker" })).json();
    expect((await exercise(cap.id, cap.secret, undefined, other.credential)).status).toBe(404);
    expect((await exercise("cap_missing", cap.secret)).status).toBe(404);
    expect(await auditCount("capability.denied", "bad-secret")).toBe(1);
    expect(await auditCount("capability.denied", "wrong-broker")).toBe(1);
  });

  it("destination is checked per exercise: wrong host, wrong port, wildcard apex", async () => {
    await grantUse();
    const cap = await (await issue({ destinations: ["*.stripe.com"] })).json();
    expect((await exercise(cap.id, cap.secret, { host: "api.stripe.com", port: 443 })).status).toBe(200);
    for (const destination of [
      { host: "evil.example", port: 443 },
      { host: "api.stripe.com", port: 8443 },
      { host: "stripe.com", port: 443 }, // apex is never matched by the wildcard
      { host: "notstripe.com", port: 443 },
    ]) {
      const res = await exercise(cap.id, cap.secret, destination);
      expect(res.status).toBe(403);
      expect((await res.json()).error.details.reason).toBe("destination-mismatch");
    }
  });

  it("expiry and revocation fail closed", async () => {
    await grantUse();
    const cap = await (await issue()).json();
    await ctx.db.query("UPDATE capabilities SET expires_at = now() - interval '1 second' WHERE id = $1", [cap.id]);
    const expired = await exercise(cap.id, cap.secret);
    expect(expired.status).toBe(403);
    expect((await expired.json()).error.details.reason).toBe("expired");

    const cap2 = await (await issue()).json();
    const del = await app.request(`${ENV_PATH}/capabilities/${cap2.id}`, {
      method: "DELETE",
      headers: auth(brokerToken),
    });
    expect(del.status).toBe(204);
    const revoked = await exercise(cap2.id, cap2.secret);
    expect(revoked.status).toBe(403);
    expect((await revoked.json()).error.details.reason).toBe("revoked");
  });

  it("retiring the Agent revokes its Capabilities at once, and reactivation does not bring them back", async () => {
    await grantUse();
    const cap = await (await issue()).json();
    expect((await exercise(cap.id, cap.secret)).status).toBe(200);
    const retire = await post(`/v1/organizations/acme/identities/${agentId}/retire`, {});
    expect(retire.status).toBe(200);
    const after = await exercise(cap.id, cap.secret);
    expect(after.status).toBe(403);
    expect((await after.json()).error.details.reason).toBe("revoked");
    expect(await auditCount("capability.revoked", "identity-retired")).toBe(1);

    expect((await post(`/v1/organizations/acme/identities/${agentId}/reactivate`, {})).status).toBe(200);
    const reactivated = await exercise(cap.id, cap.secret);
    expect(reactivated.status).toBe(403);
    expect((await reactivated.json()).error.details.reason).toBe("revoked");
  });

  it("retiring the Broker revokes the Capabilities it issued", async () => {
    await grantUse();
    const cap = await (await issue()).json();
    expect((await post(`/v1/organizations/acme/identities/${brokerId}/retire`, {})).status).toBe(200);
    const row = await ctx.db.query("SELECT revoked_at FROM capabilities WHERE id = $1", [cap.id]);
    expect((row.rows[0] as { revoked_at: unknown }).revoked_at).not.toBeNull();
  });

  it("non-broker principals cannot exercise, even the Agent itself", async () => {
    await grantUse();
    const cap = await (await issue()).json();
    // Administratively issue the agent a credential; the endpoint still refuses.
    const agentCred = await issueCredential(ctx.db, { identityId: agentId, kind: "service" });
    expect((await exercise(cap.id, cap.secret, undefined, agentCred.token)).status).toBe(404);
  });
});

describe("tailnet Requirements at exercise (ADR-0022 §18)", () => {
  it("apply to the broker->varlatchd request and fail closed off-tailnet", async () => {
    await grantUse();
    await post("/v1/organizations/acme/requirements", {
      kind: "tailnet",
      target: { kind: "tier", tier: "development" },
      selector: { tailnet: "example.ts.net", tags: ["tag:broker"] },
    });
    const cap = await (await issue()).json();
    const denied = await exercise(cap.id, cap.secret);
    expect(denied.status).toBe(403);
    expect((await denied.json()).error.code).toBe("TAILNET_CONTEXT_REQUIRED");

    const tailnetApp = buildApp(ctx, {
      resolveTailnetContext: async () => ({ tailnet: "example.ts.net", nodeId: "n1", tags: ["tag:broker"] }),
    });
    const ok = await tailnetApp.request(`${ENV_PATH}/capabilities/${cap.id}/exercises`, {
      method: "POST",
      headers: auth(brokerToken),
      body: JSON.stringify({
        capabilitySecret: cap.secret,
        destination: { host: "api.stripe.com", port: 443 },
        placements: placed("STRIPE_KEY"),
      }),
    });
    expect(ok.status).toBe(200);
  });
});

describe("substitution targets (ADR-0039)", () => {
  const errorOf = async (res: Response) => ((await res.json()) as { error: { code: string; message: string } }).error;

  it("meta advertises capabilities.targets", async () => {
    const meta = await (await app.request("/v1/meta")).json();
    expect(meta.capabilities).toContain("capabilities.targets");
  });

  it("issuance validates targets: required, known kinds, never transport-owned, at most four, only for items (test 5)", async () => {
    const missing = await issue({ targets: undefined });
    expect(missing.status).toBe(422);
    expect((await errorOf(missing)).message).toContain("0.11.0");
    const cases: [Record<string, unknown>, string][] = [
      [{ targets: { STRIPE_KEY: ["path:/x"] } }, "not a target kind"],
      [{ targets: { STRIPE_KEY: [] } }, "STRIPE_KEY has no substitution target"],
      [{ targets: {} }, "STRIPE_KEY has no substitution target"],
      [{ targets: { STRIPE_KEY: ["header:a", "header:b", "header:c", "header:d", "header:e"] } }, "at most 4"],
      [{ targets: { STRIPE_KEY: ["header:a", "header:A"] } }, "repeats a target"],
      [{ targets: { STRIPE_KEY: ["header:authorization"], OTHER: ["header:x"] } }, "not an item of this Capability"],
      [{ targets: { STRIPE_KEY: ["json:no-slash"] } }, "JSON Pointer"],
      [{ targets: { STRIPE_KEY: ["header:bad name"] } }, "not a valid header name"],
    ];
    const transportOwned = [
      "Host", "Content-Length", "Transfer-Encoding", "Expect", "Connection", "Keep-Alive", "Upgrade", "TE", "Trailer",
      "Proxy-Authorization", "Proxy-Authenticate", "Proxy-Connection", "Via", "Forwarded", "X-Forwarded-For",
      "X-Forwarded-Host", "Content-Type", "Content-Encoding", "Accept-Encoding", "Range", "If-Range",
    ];
    for (const header of transportOwned) cases.push([{ targets: { STRIPE_KEY: [`header:${header}`] } }, "transport-owned"]);
    for (const [overrides, fragment] of cases) {
      const res = await issue(overrides);
      expect(res.status, JSON.stringify(overrides)).toBe(422);
      expect((await errorOf(res)).message).toContain(fragment);
    }
    expect(await auditCount("capability.issued")).toBe(0);
  });

  it("records canonical targets immutably, returns them, and audits names and locations only (tests 5 and 15)", async () => {
    const res = await issue({ targets: { STRIPE_KEY: ["query:key", "header:X-Api-Key"] } });
    expect(res.status).toBe(201);
    const cap = await res.json();
    expect(cap.targets).toEqual({ STRIPE_KEY: ["header:x-api-key", "query:key"] });
    const audit = await ctx.db.query(
      "SELECT metadata::jsonb->>'targets' AS targets FROM audit_events WHERE event_type = 'capability.issued'",
    );
    expect(audit.rows).toEqual([{ targets: "STRIPE_KEY=header:x-api-key;STRIPE_KEY=query:key" }]);
    // There is no route that changes a Capability's targets.
    for (const method of ["PATCH", "PUT"]) {
      const change = await app.request(`${ENV_PATH}/capabilities/${cap.id}`, {
        method,
        headers: auth(brokerToken),
        body: JSON.stringify({ targets: { STRIPE_KEY: ["header:x"] } }),
      });
      expect(change.status).toBe(404);
    }
    await grantUse();
    const ex = await exercise(cap.id, cap.secret, undefined, undefined, [{ item: "STRIPE_KEY", target: "query:key" }]);
    expect(ex.status).toBe(200);
    expect((await ex.json()).targets).toEqual({ STRIPE_KEY: ["header:x-api-key", "query:key"] });
  });

  it("exercise names placements, returns only placed items, and refuses one not on the Capability (test 19)", async () => {
    await put(`${ENV_PATH}/values/DB_PASSWORD`, { value: "hunter2" });
    await grantUse();
    const cap = await (await issue({ items: ["STRIPE_KEY", "DB_PASSWORD"] })).json();

    const one = await exercise(cap.id, cap.secret, undefined, undefined, placed("DB_PASSWORD"));
    expect(one.status).toBe(200);
    const body = await one.json();
    expect(body.items.map((i: { name: string }) => i.name)).toEqual(["DB_PASSWORD"]);
    expect(JSON.stringify(body)).not.toContain("sk_live_1");
    const exercised = await ctx.db.query(
      "SELECT metadata::jsonb AS m FROM audit_events WHERE event_type = 'capability.exercised'",
    );
    const meta = (exercised.rows[0] as { m: Record<string, string> }).m;
    expect(meta.placements).toBe("DB_PASSWORD=header:authorization");
    expect(meta.items).toMatch(/^DB_PASSWORD@ver_/);

    for (const placements of [
      [{ item: "DB_PASSWORD", target: "header:x-api-key" }],
      [{ item: "UNBOUND", target: "header:authorization" }],
      [],
    ]) {
      const denied = await exercise(cap.id, cap.secret, undefined, undefined, placements);
      expect(denied.status).toBe(403);
      expect((await denied.json()).error.details.reason).toBe("placement-not-targeted");
    }
    expect(await auditCount("capability.denied", "placement-not-targeted")).toBe(3);
    expect(await auditCount("capability.exercised")).toBe(1);
  });

  it("a Capability issued before the migration is refused at exercise; revocation and expiry still work (test 7)", async () => {
    await grantUse();
    const legacy = await (await issue()).json();
    const expiring = await (await issue()).json();
    const revocable = await (await issue()).json();
    // Upgrade in place: these rows existed before migration 22 ran.
    await ctx.db.query("ALTER TABLE capabilities DROP COLUMN targets");
    await ctx.db.query("DELETE FROM varlatch_migrations WHERE id = 22");
    expect((await runMigrations(ctx.db)).applied.map((m) => m.id)).toEqual([22]);
    const rows = await ctx.db.query("SELECT targets FROM capabilities");
    expect(rows.rows.every((r) => (r as { targets: unknown }).targets === null)).toBe(true);

    const res = await exercise(legacy.id, legacy.secret);
    expect(res.status).toBe(403);
    const error = (await res.json()).error;
    expect(error.details.reason).toBe("capability-without-targets");
    expect(error.message).toBe(
      "This Capability was issued before substitution targets were required. Restart the agent-safe run with Varlatch CLI 0.11.0 or later.",
    );
    expect(await auditCount("capability.denied", "capability-without-targets")).toBe(1);
    expect(await auditCount("capability.exercised")).toBe(0);

    const del = await app.request(`${ENV_PATH}/capabilities/${revocable.id}`, { method: "DELETE", headers: auth(brokerToken) });
    expect(del.status).toBe(204);
    expect((await (await exercise(revocable.id, revocable.secret)).json()).error.details.reason).toBe("revoked");
    await ctx.db.query("UPDATE capabilities SET expires_at = now() - interval '1 second' WHERE id = $1", [expiring.id]);
    expect((await (await exercise(expiring.id, expiring.secret)).json()).error.details.reason).toBe("expired");
  });
});

describe("listing and revocation authority", () => {
  it("brokers list their own; policy.read lists all; other machines are denied", async () => {
    await grantUse();
    const cap = await (await issue()).json();
    const other = await (await post("/v1/organizations/acme/identities", { name: "b2", kind: "broker" })).json();

    const mine = await app.request(`${ENV_PATH}/capabilities`, { headers: auth(brokerToken) });
    expect((await mine.json()).items.map((i: { id: string }) => i.id)).toEqual([cap.id]);
    const theirs = await app.request(`${ENV_PATH}/capabilities`, { headers: auth(other.credential) });
    expect((await theirs.json()).items).toEqual([]);
    const admin = await app.request(`${ENV_PATH}/capabilities`, { headers: auth() });
    expect((await admin.json()).items).toHaveLength(1);

    const svc = await (await post("/v1/organizations/acme/identities", { name: "svc3", kind: "service" })).json();
    const deniedList = await app.request(`${ENV_PATH}/capabilities`, { headers: auth(svc.credential) });
    expect(deniedList.status).toBe(403);

    // A foreign broker cannot revoke; an admin (policy.manage) can.
    const foreignRevoke = await app.request(`${ENV_PATH}/capabilities/${cap.id}`, {
      method: "DELETE",
      headers: auth(other.credential),
    });
    expect(foreignRevoke.status).toBe(404);
    const adminRevoke = await app.request(`${ENV_PATH}/capabilities/${cap.id}`, {
      method: "DELETE",
      headers: auth(),
    });
    expect(adminRevoke.status).toBe(204);
  });
});

describe("reference expansion at exercise (ADR-0026)", () => {
  // Contract marks DB_HOST non-sensitive; COMPOSED/ESC/BROKEN are Secrets
  // composed from references. Strict rule: every reference in exercised
  // material resolves or the exercise denies — never a literal ${NAME}
  // injected upstream.
  async function seedComposed() {
    const item = (name: string, sensitive: boolean) => ({
      name,
      type: "string",
      sensitive,
      required: { kind: "never" },
    });
    const push = await post("/v1/organizations/acme/projects/api/contract/revisions", {
      contract: {
        schemaVersion: 1,
        items: [
          item("STRIPE_KEY", true),
          item("DB_PASSWORD", true),
          item("COMPOSED", true),
          item("ESC", true),
          item("BROKEN", true),
          item("DB_HOST", false),
        ],
      },
    });
    expect(push.status).toBe(201);
    const revision = await push.json();
    expect(
      (
        await post(
          `/v1/organizations/acme/projects/api/contract/revisions/${revision.id}/activate`,
          {},
        )
      ).status,
    ).toBe(200);
    await put(`${ENV_PATH}/values/DB_HOST`, { value: "db.internal" });
    await put(`${ENV_PATH}/values/DB_PASSWORD`, { value: "hunter2" });
    await put(`${ENV_PATH}/values/COMPOSED`, {
      value: "postgres://app:${DB_PASSWORD}@${DB_HOST}/app",
    });
  }
  async function grantPlainRead() {
    const res = await post("/v1/organizations/acme/grants", {
      subjectIdentityId: agentId,
      scope: { kind: "project", projectId: await projectId() },
      actions: ["config.value.read"],
    });
    expect(res.status).toBe(201);
  }

  it("expands bound-secret and authorized plain references; plain pull-ins audited", async () => {
    await seedComposed();
    await grantUse();
    await grantPlainRead();
    const cap = await (await issue({ items: ["COMPOSED", "DB_PASSWORD"] })).json();
    const res = await exercise(cap.id, cap.secret);
    expect(res.status).toBe(200);
    const body = await res.json();
    const composed = body.items.find((i: { name: string }) => i.name === "COMPOSED");
    expect(composed.value).toBe("postgres://app:hunter2@db.internal/app");
    const audit = await ctx.db.query(
      "SELECT metadata::jsonb AS m FROM audit_events WHERE event_type = 'value.disclosed' AND metadata::jsonb->>'mode' = 'reference-expansion'",
    );
    expect(audit.rows).toHaveLength(1);
    const meta = (audit.rows[0] as { m: Record<string, unknown> }).m;
    expect(String(meta.items)).toContain("DB_HOST@");
    expect(meta.runId).toBe("run_test");
  });

  it("a reference to a Secret the Capability does not name denies the exercise", async () => {
    await seedComposed();
    await grantUse();
    await grantPlainRead();
    const cap = await (await issue({ items: ["COMPOSED"] })).json();
    const res = await exercise(cap.id, cap.secret);
    expect(res.status).toBe(403);
    const err = (await res.json()).error;
    expect(err.details).toMatchObject({
      reason: "unresolved-reference",
      reference: "DB_PASSWORD",
      referencedBy: "COMPOSED",
      cause: "secret-not-bound",
    });
    expect(err.message).toContain("DB_PASSWORD");
    expect(JSON.stringify(err)).not.toContain("hunter2");
    expect(await auditCount("capability.denied", "unresolved-reference")).toBe(1);
  });

  it("a plain reference without config.value.read denies the exercise", async () => {
    await seedComposed();
    await grantUse(); // secret.use only
    const cap = await (await issue({ items: ["COMPOSED", "DB_PASSWORD"] })).json();
    const res = await exercise(cap.id, cap.secret);
    expect(res.status).toBe(403);
    expect((await res.json()).error.details).toMatchObject({
      reason: "unresolved-reference",
      reference: "DB_HOST",
      cause: "plain-read-denied",
    });
  });

  it("an unknown reference denies with the escape hint; $${NAME} stays literal", async () => {
    await seedComposed();
    await grantUse();
    await put(`${ENV_PATH}/values/BROKEN`, { value: "x=${NOPE}" });
    await put(`${ENV_PATH}/values/ESC`, { value: "tpl=$${DB_HOST}" });
    const broken = await (await issue({ items: ["BROKEN"] })).json();
    const denied = await exercise(broken.id, broken.secret);
    expect(denied.status).toBe(403);
    const err = (await denied.json()).error;
    expect(err.details).toMatchObject({
      reason: "unresolved-reference",
      reference: "NOPE",
      cause: "unknown-item",
    });
    expect(err.message).toContain("$${NAME}");
    // Escaped references need no plain-read authority and expand to literal text.
    const esc = await (await issue({ items: ["ESC"] })).json();
    const ok = await exercise(esc.id, esc.secret);
    expect(ok.status).toBe(200);
    expect((await ok.json()).items[0].value).toBe("tpl=${DB_HOST}");
  });
});

describe("the repair of earlier retirements", () => {
  const live = async (id: string) =>
    ((await ctx.db.query("SELECT revoked_at FROM capabilities WHERE id = $1", [id])).rows[0] as { revoked_at: unknown })
      .revoked_at === null;
  const newAgent = async (name: string) => {
    const id = (await (await post("/v1/organizations/acme/identities", { name, kind: "agent" })).json()).id as string;
    await grantUse(id);
    return id;
  };
  /** Retires the identity as a release before the fix did: its Capabilities stay live. */
  const retireAsBefore = async (identityId: string, ...capabilityIds: string[]) => {
    expect((await post(`/v1/organizations/acme/identities/${identityId}/retire`, {})).status).toBe(200);
    await ctx.db.query("UPDATE capabilities SET revoked_at = NULL WHERE id = ANY($1::text[])", [capabilityIds]);
  };
  const reactivate = async (identityId: string) =>
    expect((await post(`/v1/organizations/acme/identities/${identityId}/reactivate`, {})).status).toBe(200);
  /** An Organization's deletion, cancelled: what an identity it suspended names. */
  const deletion = async () => {
    const admin = (await ctx.db.query("SELECT id FROM identities WHERE installation_admin LIMIT 1")).rows[0] as { id: string };
    await ctx.db.query(
      `INSERT INTO organization_deletions (id, organization_id, requested_by, run_after, approval_required, cancelled_by, cancelled_at)
       SELECT 'odl_test', id, $1, now() + interval '1 day', false, $1, now() FROM organizations WHERE slug = 'acme'`,
      [admin.id],
    );
    return "odl_test";
  };
  /** A Capability row with no capability.issued: an imported one. */
  const imported = async (from: string, id: string) =>
    ctx.db.query(
      `INSERT INTO capabilities
       SELECT (jsonb_populate_record(NULL::capabilities, to_jsonb(c) || jsonb_build_object(
         'id', $2::text, 'secret_hash', c.secret_hash || 'x', 'revoked_at', NULL,
         'expires_at', now() + interval '3 days', 'created_at', now()))).*
       FROM capabilities c WHERE id = $1`,
      [from, id],
    );

  it("revokes what an earlier retirement left live, and keeps what came after a reactivation or a suspension", async () => {
    const { revokeCapabilitiesOfRetiredIdentities } = await import("../src/domain/capabilityrepair.js");
    await grantUse();
    // Issued before the Agent's retirement, which left it live; the Agent
    // was reactivated since, which made it work again.
    const before = await (await issue()).json();
    const expired = await (await issue()).json();
    await ctx.db.query("UPDATE capabilities SET expires_at = now() - interval '1 second' WHERE id = $1", [expired.id]);
    await retireAsBefore(agentId, before.id, expired.id);
    await reactivate(agentId);
    expect((await exercise(before.id, before.secret)).status).toBe(200);
    // Issued after the reactivation.
    const after = await (await issue()).json();
    // Issued while its Agent was retired: an issuance that raced the
    // retirement.
    const raced = await newAgent("raced agent");
    const racedCap = await (await issue({ agentIdentityId: raced })).json();
    await retireAsBefore(raced, racedCap.id);
    await ctx.db.query("UPDATE capabilities SET created_at = now() WHERE id = $1", [racedCap.id]);
    // An Organization's deletion suspends an identity without retiring it.
    const suspended = await newAgent("suspended agent");
    const suspendedCap = await (await issue({ agentIdentityId: suspended })).json();
    await ctx.db.query("UPDATE identities SET disabled = true, suspended_by_deletion = $2 WHERE id = $1", [
      suspended,
      await deletion(),
    ]);
    const revokedBefore = await auditCount("capability.revoked", "identity-retired");

    expect(await revokeCapabilitiesOfRetiredIdentities(ctx)).toBe(2);
    expect(await live(before.id)).toBe(false);
    expect(await live(racedCap.id)).toBe(false);
    expect(await live(after.id)).toBe(true);
    expect(await live(suspendedCap.id)).toBe(true);
    expect(await live(expired.id)).toBe(true);
    const denied = await exercise(before.id, before.secret);
    expect(denied.status).toBe(403);
    expect((await denied.json()).error.details.reason).toBe("revoked");
    expect((await exercise(after.id, after.secret)).status).toBe(200);
    // Each audited, with no actor.
    expect(await auditCount("capability.revoked", "identity-retired")).toBe(revokedBefore + 2);
    const events = (
      await ctx.db.query(
        `SELECT actor_identity_id, resource->>'capabilityId' AS capability, metadata->>'identityId' AS identity
         FROM audit_events WHERE event_type = 'capability.revoked' AND actor_identity_id IS NULL ORDER BY capability`,
      )
    ).rows;
    expect(events).toEqual(
      [
        { actor_identity_id: null, capability: before.id, identity: agentId },
        { actor_identity_id: null, capability: racedCap.id, identity: raced },
      ].sort((a, b) => (a.capability < b.capability ? -1 : 1)),
    );
    // Once repaired, it finds nothing.
    expect(await revokeCapabilitiesOfRetiredIdentities(ctx)).toBe(0);
  });

  it("orders an issuance by the audit log, not by its row's timestamp", async () => {
    const { revokeCapabilitiesOfRetiredIdentities } = await import("../src/domain/capabilityrepair.js");
    await grantUse();
    expect((await post(`/v1/organizations/acme/identities/${agentId}/retire`, {})).status).toBe(200);
    await reactivate(agentId);
    const after = await (await issue()).json();
    // Its created_at precedes the reactivation's occurred_at (a clock, or a
    // transaction begun before the reactivation committed); its
    // capability.issued comes after it.
    await ctx.db.query("UPDATE capabilities SET created_at = created_at - interval '1 hour' WHERE id = $1", [after.id]);
    expect(await revokeCapabilitiesOfRetiredIdentities(ctx)).toBe(0);
    expect(await live(after.id)).toBe(true);
  });

  it("finds an issuance however far its row's created_at is from it", async () => {
    const { revokeCapabilitiesOfRetiredIdentities } = await import("../src/domain/capabilityrepair.js");
    await grantUse();
    expect((await post(`/v1/organizations/acme/identities/${agentId}/retire`, {})).status).toBe(200);
    await reactivate(agentId);
    const after = await (await issue()).json();
    // An imported Capability's created_at, days from its capability.issued.
    await ctx.db.query(
      "UPDATE capabilities SET created_at = created_at - interval '3 days', expires_at = now() + interval '1 day' WHERE id = $1",
      [after.id],
    );
    expect(await revokeCapabilitiesOfRetiredIdentities(ctx)).toBe(0);
    expect(await live(after.id)).toBe(true);
  });

  it("works in bounded batches, each its own transaction", async () => {
    const { revokeCapabilitiesOfRetiredIdentities } = await import("../src/domain/capabilityrepair.js");
    await grantUse();
    const ended: string[] = [];
    for (let i = 0; i < 5; i++) ended.push((await (await issue()).json()).id);
    await retireAsBefore(agentId, ...ended);
    await reactivate(agentId);
    const kept: string[] = [];
    for (let i = 0; i < 3; i++) kept.push((await (await issue()).json()).id);
    const statements: string[] = [];
    const db = ctx.db;
    const recording = {
      query: (text: string, params?: unknown[]) => {
        statements.push(text);
        return db.query(text, params);
      },
    };
    expect(await revokeCapabilitiesOfRetiredIdentities({ ...ctx, db: recording }, { batchSize: 2 })).toBe(5);
    for (const id of ended) expect(await live(id)).toBe(false);
    for (const id of kept) expect(await live(id)).toBe(true);
    // Eight live Capabilities, two at a time: five transactions (the last
    // one finds none), each locking at most two.
    expect(statements.filter((t) => t === "BEGIN")).toHaveLength(5);
    expect(statements.filter((t) => /FROM capabilities[\s\S]*LIMIT \$3 FOR NO KEY UPDATE/.test(t))).toHaveLength(5);
  });

  it("reads a retirement however old, for a Capability that outlives a day", async () => {
    const { revokeCapabilitiesOfRetiredIdentities } = await import("../src/domain/capabilityrepair.js");
    await grantUse();
    const cap = await (await issue()).json();
    await retireAsBefore(agentId, cap.id);
    // An imported Capability, three days long, of an Agent retired three
    // days ago and still retired.
    await ctx.db.query(
      "UPDATE capabilities SET created_at = now() - interval '4 days', expires_at = now() + interval '3 days' WHERE id = $1",
      [cap.id],
    );
    await ctx.db.query(
      `UPDATE audit_events SET occurred_at = now() - interval '3 days'
       WHERE event_type = 'identity.retired' AND resource->>'identityId' = $1`,
      [agentId],
    );
    expect(await revokeCapabilitiesOfRetiredIdentities(ctx)).toBe(1);
    expect(await live(cap.id)).toBe(false);
  });

  it("revokes a Capability whose issuance its history does not show, once its identity was retired", async () => {
    const { revokeCapabilitiesOfRetiredIdentities } = await import("../src/domain/capabilityrepair.js");
    await grantUse();
    const cap = await (await issue()).json();
    const untouched = await newAgent("never retired");
    const kept = await (await issue({ agentIdentityId: untouched })).json();
    expect((await post(`/v1/organizations/acme/identities/${agentId}/retire`, {})).status).toBe(200);
    await reactivate(agentId);
    await imported(cap.id, "cap_imported_retired");
    await imported(kept.id, "cap_imported_kept");
    expect(await revokeCapabilitiesOfRetiredIdentities(ctx)).toBe(1);
    expect(await live("cap_imported_retired")).toBe(false);
    expect(await live("cap_imported_kept")).toBe(true);
  });

  it("revokes the Capabilities of an identity retired now, whatever its audit history", async () => {
    const { revokeCapabilitiesOfRetiredIdentities } = await import("../src/domain/capabilityrepair.js");
    await grantUse();
    const cap = await (await issue()).json();
    await imported(cap.id, "cap_imported");
    await ctx.db.query("UPDATE identities SET disabled = true WHERE id = $1", [agentId]);
    expect(await revokeCapabilitiesOfRetiredIdentities(ctx)).toBe(2);
    expect(await live(cap.id)).toBe(false);
    expect(await live("cap_imported")).toBe(false);
  });
});

describe("Capabilities wait for the repair", () => {
  const refusedUntilRepaired = async (res: Response) => {
    expect(res.status).toBe(503);
    expect((await res.json()).error.code).toBe("MAINTENANCE");
  };

  it("refuses issuance and exercise until the repair has run, and after it failed", async () => {
    const { CapabilityRepair } = await import("../src/domain/capabilityrepair.js");
    await grantUse();
    const cap = await (await issue()).json();
    let fail = true;
    const errors: unknown[] = [];
    const repair = new CapabilityRepair(
      async () => {
        if (fail) throw new Error("connection lost");
        return 0;
      },
      { log: () => {}, error: (...args: unknown[]) => errors.push(args) },
    );
    ctx.capabilityRepair = repair;
    await refusedUntilRepaired(await issue());
    await refusedUntilRepaired(await exercise(cap.id, cap.secret));
    expect(await repair.attempt(ctx)).toBe(false);
    expect(errors).toHaveLength(1);
    await refusedUntilRepaired(await issue());
    await refusedUntilRepaired(await exercise(cap.id, cap.secret));
    fail = false;
    expect(await repair.attempt(ctx)).toBe(true);
    expect((await issue()).status).toBe(201);
    expect((await exercise(cap.id, cap.secret)).status).toBe(200);
    // A restore brings back what was never repaired.
    repair.invalidate();
    await refusedUntilRepaired(await issue());
  });

  it("runs behind no maintenance gate, and once a restore's gate is gone", async () => {
    const { mkdtempSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { Maintenance, prepareRestore } = await import("@varlatch/backup");
    const { CapabilityRepair } = await import("../src/domain/capabilityrepair.js");
    const dir = mkdtempSync(join(tmpdir(), "vl-caprepair-"));
    try {
      const maintenance = new Maintenance(dir);
      const gate = prepareRestore(dir, "arc_test");
      let runs = 0;
      const repair = new CapabilityRepair(async () => {
        runs++;
        return 0;
      });
      const gated = { ...ctx, maintenance, capabilityRepair: repair };
      expect(await repair.attempt(gated)).toBe(false);
      expect(runs).toBe(0);
      const stop = repair.start(gated, 10);
      try {
        await new Promise((r) => setTimeout(r, 50));
        expect(runs).toBe(0);
        expect(repair.ready).toBe(false);
        maintenance.phase(gate.id, "reconciling");
        maintenance.completeRestore(gate.id);
        for (let i = 0; i < 100 && !repair.ready; i++) await new Promise((r) => setTimeout(r, 10));
        expect(repair.ready).toBe(true);
        expect(runs).toBe(1);
        // A restore's gate seen again: not ready until it is gone and the repair ran again.
        prepareRestore(dir, "arc_second");
        for (let i = 0; i < 100 && repair.ready; i++) await new Promise((r) => setTimeout(r, 10));
        expect(repair.ready).toBe(false);
      } finally {
        stop();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("starts at once, not after its first interval", async () => {
    const { CapabilityRepair } = await import("../src/domain/capabilityrepair.js");
    const repair = new CapabilityRepair(async () => 0);
    const stop = repair.start({ ...ctx, capabilityRepair: repair }, 60_000);
    try {
      for (let i = 0; i < 100 && !repair.ready; i++) await new Promise((r) => setTimeout(r, 10));
      expect(repair.ready).toBe(true);
    } finally {
      stop();
    }
  });

  it("survives an unreadable maintenance file: not ready, and tried again once it reads", async () => {
    const { mkdtempSync, rmSync, writeFileSync, unlinkSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { Maintenance } = await import("@varlatch/backup");
    const { CapabilityRepair } = await import("../src/domain/capabilityrepair.js");
    const dir = mkdtempSync(join(tmpdir(), "vl-caprepair-"));
    try {
      const maintenance = new Maintenance(dir);
      const errors: unknown[] = [];
      let runs = 0;
      const repair = new CapabilityRepair(
        async () => {
          runs++;
          return 0;
        },
        { log: () => {}, error: (...args: unknown[]) => errors.push(args) },
      );
      const gated = { ...ctx, maintenance, capabilityRepair: repair };
      expect(await repair.attempt(gated)).toBe(true);
      // The file becomes unreadable: an attempt refuses (never throws), and
      // the timer makes Capabilities wait.
      writeFileSync(join(dir, "maintenance.json"), "{not json");
      repair.invalidate();
      expect(() => void repair.attempt(gated)).not.toThrow();
      await expect(repair.attempt(gated)).resolves.toBe(false);
      expect(repair.ready).toBe(false);
      const stop = repair.start(gated, 10);
      try {
        await new Promise((r) => setTimeout(r, 60));
        expect(repair.ready).toBe(false);
        expect(errors.length).toBeGreaterThan(0);
        const before = runs;
        unlinkSync(join(dir, "maintenance.json"));
        for (let i = 0; i < 100 && !repair.ready; i++) await new Promise((r) => setTimeout(r, 10));
        expect(repair.ready).toBe(true);
        expect(runs).toBe(before + 1);
      } finally {
        stop();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
