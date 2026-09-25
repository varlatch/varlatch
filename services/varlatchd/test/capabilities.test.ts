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
import { testDb } from "./helpers/pglite.js";

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
  const db = await testDb();
  await runMigrations(db);
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

async function issue(overrides: Record<string, unknown> = {}, token = brokerToken) {
  return post(
    `${ENV_PATH}/capabilities`,
    {
      agentIdentityId: agentId,
      items: ["STRIPE_KEY"],
      destinations: ["api.stripe.com"],
      ttlSeconds: 600,
      runId: "run_test",
      ...overrides,
    },
    token,
  );
}

async function exercise(
  capabilityId: string,
  secret: string,
  destination = { host: "api.stripe.com", port: 443 },
  token = brokerToken,
) {
  return post(`${ENV_PATH}/capabilities/${capabilityId}/exercises`, { capabilitySecret: secret, destination }, token);
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
      body: JSON.stringify({ capabilitySecret: cap.secret, destination: { host: "api.stripe.com", port: 443 } }),
    });
    expect(ok.status).toBe(200);
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
