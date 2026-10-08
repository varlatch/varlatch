// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
} from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * Agent metadata credentials (ADR-0023, foreseen by ADR-0022 §8): a Broker
 * mints a short-lived agent-run credential for an Agent Identity. The
 * credential establishes identity only (authority stays with the Agent's
 * Grants) and is read-only at the HTTP layer.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let brokerToken: string;
let brokerId: string;
let agentId: string;

const ENV_PATH = "/v1/organizations/acme/projects/api/environments/development";
const AGENT_CREDS = () => `/v1/organizations/acme/identities/${agentId}/credentials`;

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
async function put(path: string, body: unknown, token = adminToken) {
  return app.request(path, { method: "PUT", headers: auth(token), body: JSON.stringify(body) });
}
async function get(path: string, token = adminToken) {
  return app.request(path, { headers: auth(token) });
}
async function del(path: string, token = adminToken) {
  return app.request(path, { method: "DELETE", headers: auth(token) });
}

async function mint(body: Record<string, unknown> = {}, token = brokerToken) {
  return post(AGENT_CREDS(), { ttlSeconds: 600, runId: "run_meta", ...body }, token);
}

async function grantMetadataRead() {
  const project = await (await get("/v1/organizations/acme/projects/api")).json();
  const res = await post("/v1/organizations/acme/grants", {
    subjectIdentityId: agentId,
    scope: { kind: "project", projectId: project.id },
    actions: ["config.metadata.read"],
  });
  expect(res.status).toBe(201);
}

describe("issuance", () => {
  it("meta advertises the capability", async () => {
    const meta = await (await app.request("/v1/meta")).json();
    expect(meta.capabilities).toContain("credentials.agent");
  });

  it("broker mints a short-lived agent-run credential, returned once", async () => {
    const res = await mint();
    expect(res.status).toBe(201);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = await res.json();
    expect(body.token).toMatch(/^vlt_agr_/);
    expect(new Date(body.expiresAt).getTime()).toBeGreaterThan(Date.now());
    expect(new Date(body.expiresAt).getTime()).toBeLessThanOrEqual(Date.now() + 601_000);
  });

  it("only in-org brokers may mint; others learn nothing", async () => {
    // Other callers take the identity.manage path (identity.credentials.issue),
    // which issues service credentials only and hides Agent Identities.
    expect((await mint({}, adminToken)).status).toBe(404);
    const svc = await (await post("/v1/organizations/acme/identities", { name: "svc", kind: "service" })).json();
    // Without identity.manage the denial comes first, the same for any id.
    expect((await mint({}, svc.credential)).status).toBe(403);
    const unknown = await post("/v1/organizations/acme/identities/idn_nope/credentials", { ttlSeconds: 600 }, svc.credential);
    expect(unknown.status).toBe(403);
    const minted = await ctx.db.query("SELECT count(*)::int AS n FROM credentials WHERE kind = 'agent-run'");
    expect((minted.rows[0] as { n: number }).n).toBe(0);
  });

  it("only agent identities are mintable-for; wrong kind and unknown ids collapse to 404", async () => {
    const forBroker = await post(`/v1/organizations/acme/identities/${brokerId}/credentials`, { ttlSeconds: 600 }, brokerToken);
    expect(forBroker.status).toBe(404);
    const unknown = await post("/v1/organizations/acme/identities/idn_nope/credentials", { ttlSeconds: 600 }, brokerToken);
    expect(unknown.status).toBe(404);
  });

  it("caps TTL at one hour", async () => {
    expect((await mint({ ttlSeconds: 3601 })).status).toBe(422);
    expect((await mint({ ttlSeconds: 0 })).status).toBe(422);
  });

  it("audits issuance with the run id", async () => {
    await mint();
    const res = await ctx.db.query(
      "SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'credential.issued' AND metadata::jsonb->>'runId' = 'run_meta'",
    );
    expect((res.rows[0] as { n: number }).n).toBe(1);
  });
});

describe("using the credential", () => {
  it("reads metadata under the agent's Grants; never sensitive plaintext", async () => {
    await grantMetadataRead();
    const { token } = await (await mint()).json();
    const res = await get(`${ENV_PATH}/effective-configuration`, token);
    expect(res.status).toBe(200);
    const body = await res.json();
    const names = (body.items ?? []).map((i: { name: string }) => i.name);
    expect(names).toContain("STRIPE_KEY");
    expect(JSON.stringify(body)).not.toContain("sk_live_1");
  });

  it("is identity, not authority: without a Grant, reads are denied", async () => {
    const { token } = await (await mint()).json();
    const res = await get(`${ENV_PATH}/effective-configuration`, token);
    expect([403, 404]).toContain(res.status);
  });

  it("is read-only at the HTTP layer regardless of Grants", async () => {
    await grantMetadataRead();
    const { token } = await (await mint()).json();
    const write = await put(`${ENV_PATH}/values/STRIPE_KEY`, { value: "sk_live_2" }, token);
    expect(write.status).toBe(403);
    expect((await write.json()).error.code).toBe("PERMISSION_DENIED");
    const disclose = await post(`${ENV_PATH}/disclosures`, { scope: "all-authorized-secrets" }, token);
    expect(disclose.status).toBe(403);
  });

  it("expires", async () => {
    await grantMetadataRead();
    const minted = await (await mint()).json();
    await ctx.db.query("UPDATE credentials SET expires_at = now() - interval '1 second' WHERE id = $1", [minted.id]);
    const res = await get(`${ENV_PATH}/effective-configuration`, minted.token);
    expect(res.status).toBe(401);
    expect((await res.json()).error.code).toBe("INVALID_CREDENTIAL");
  });
});

describe("revocation", () => {
  it("broker revokes; the credential stops working immediately", async () => {
    await grantMetadataRead();
    const minted = await (await mint()).json();
    const res = await del(`${AGENT_CREDS()}/${minted.id}`, brokerToken);
    expect(res.status).toBe(204);
    expect((await get(`${ENV_PATH}/effective-configuration`, minted.token)).status).toBe(401);
  });

  it("only agent-run credentials are revocable through this endpoint", async () => {
    // An admin CLI credential id is not reachable here even if guessed.
    const mine = await (await get("/v1/me/credentials")).json();
    const cliCredId = mine.items[0].id as string;
    const res = await del(`${AGENT_CREDS()}/${cliCredId}`, brokerToken);
    expect(res.status).toBe(404);
  });

  it("non-brokers learn nothing", async () => {
    const minted = await (await mint()).json();
    expect((await del(`${AGENT_CREDS()}/${minted.id}`, adminToken)).status).toBe(404);
  });
});
