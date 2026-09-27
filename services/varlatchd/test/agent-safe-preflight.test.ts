// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
import { checkAuditBeforeDecryption, traceLog, traced, type TraceLog } from "./helpers/trace.js";

/**
 * The agent-safe strict preflight (ADR-0038 Decision 7): the operator's
 * preflight retrieval returns non-sensitive values and a verdict per Secret,
 * never a Secret value; the Broker's issuance compares the retrieval's state
 * without decrypting and reports presence and the Agent's authorization.
 * A matching digest shows the same configuration state, not the same
 * permissions: exercise still resolves every reference or denies.
 */

const hooks = vi.hoisted(() => ({ log: null as TraceLog | null }));
vi.mock("../src/crypto/hierarchy.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/crypto/hierarchy.js")>();
  return {
    ...actual,
    decryptValue: (...args: Parameters<typeof actual.decryptValue>) => {
      hooks.log?.decrypt(args[3]);
      return actual.decryptValue(...args);
    },
  };
});

const P = "/v1/organizations/acme/projects/api";
const E = `${P}/environments/production`;

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let log: TraceLog;
let adminToken: string;
let brokerToken: string;
let agentId: string;
let projectId: string;

async function call(method: string, path: string, body?: unknown, token = adminToken) {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, text, body: (text ? JSON.parse(text) : null) as Record<string, any> };
}
const preflight = (token = adminToken) => call("POST", `${E}/retrievals`, { mode: "preflight" }, token);

function item(name: string, sensitive: boolean, fields: Record<string, unknown> = {}) {
  return { name, required: { kind: "always" }, sensitive, type: "string", ...fields };
}

async function grant(subject: string, actions: string[], scope: unknown = { kind: "project", projectId }) {
  const res = await call("POST", "/v1/organizations/acme/grants", { subjectIdentityId: subject, scope, actions });
  expect(res.status).toBe(201);
}

async function issue(retrieval: Record<string, any>, overrides: Record<string, unknown> = {}) {
  const items = (overrides.items as string[] | undefined) ?? ["DB_PASS", "STRIPE_KEY", "DATABASE_URL"];
  return call(
    "POST",
    `${E}/capabilities`,
    {
      agentIdentityId: agentId,
      items,
      destinations: ["api.example.com"],
      targets: Object.fromEntries(items.map((item) => [item, [`json:/${item.toLowerCase()}`]])),
      ttlSeconds: 600,
      precondition: {
        projectId: retrieval.manifest.projectId,
        environmentId: retrieval.manifest.environment.id,
        stateDigest: retrieval.stateDigest,
        stateDigests: retrieval.stateDigests,
      },
      ...overrides,
    },
    brokerToken,
  );
}

beforeEach(async () => {
  log = traceLog();
  hooks.log = log;
  const db = traced(await migratedTestDb(), log);
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const setup = await issueBootstrapGrant(ctx);
  const { identityId } = await consumeSetupGrant(ctx, setup.token, { adminName: "Admin" });
  adminToken = (await issueCredential(ctx.db, { identityId, kind: "cli" })).token;
  app = buildApp(ctx);
  await call("POST", "/v1/organizations", { name: "Acme", slug: "acme" });
  projectId = (await call("POST", "/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "managed" })).body.id;
  await call("POST", `${P}/environments`, { name: "production", tier: "production" });
  const revision = await call("POST", `${P}/contract/revisions`, {
    contract: {
      schemaVersion: 1,
      semanticsVersion: 2,
      items: [
        item("DB_HOST", false),
        item("DB_PASS", true),
        item("DATABASE_URL", true, { type: "url" }),
        item("STRIPE_KEY", true, { type: "enum", enumValues: ["sk-live-1234", "sk-test-0000"] }),
      ],
    },
  });
  await call("POST", `${P}/contract/revisions/${revision.body.id}/activate`, {});
  for (const [name, value] of [
    ["DB_HOST", "db.internal"],
    ["DB_PASS", "hunter2-hunter2"],
    ["DATABASE_URL", "postgres://app:${DB_PASS}@${DB_HOST}/app"],
    ["STRIPE_KEY", "sk-live-1234"],
  ]) {
    expect((await call("PUT", `${E}/values/${name}`, { value })).status).toBe(200);
  }
  const broker = (await call("POST", "/v1/organizations/acme/identities", { name: "broker", kind: "broker" })).body;
  brokerToken = broker.credential;
  agentId = (await call("POST", "/v1/organizations/acme/identities", { name: "agent", kind: "agent" })).body.id;
});
afterEach(async () => {
  hooks.log = null;
  await ctx.close();
});

describe("the operator's preflight retrieval", () => {
  it("returns non-sensitive values and a verdict per Secret, never a Secret value", async () => {
    await call("PUT", `${E}/values/STRIPE_KEY`, { value: "sk-bogus-9999" });
    log.reset();
    const res = await preflight();
    expect(res.status).toBe(200);
    expect(res.body.mode).toBe("preflight");
    // The stored Secret values never appear. (The Contract's enum values are
    // Contract metadata, and do appear in the verdict's reason.)
    for (const secret of ["hunter2-hunter2", "sk-bogus-9999", "postgres://app"]) expect(res.text).not.toContain(secret);
    const byName = Object.fromEntries(res.body.items.map((i: { name: string }) => [i.name, i]));
    expect(byName.DB_HOST.value).toBe("db.internal");
    expect(byName.DB_PASS.value).toBeNull();
    expect(res.body.callerView.withheld).toEqual([]);
    // Verdicts on the expanded Secret values, in-process only.
    expect(res.body.validation).toMatchObject({
      complete: true,
      invalid: [{ name: "STRIPE_KEY", reason: "must be one of: sk-live-1234, sk-test-0000" }],
      unresolved: [],
      notEvaluated: [],
    });
    expect(res.body.stateDigests).toEqual({
      environment: expect.stringMatching(/^sha256:/),
      contract: expect.stringMatching(/^sha256:/),
      items: expect.stringMatching(/^sha256:/),
      rotation: expect.stringMatching(/^sha256:/),
    });
  });

  it("audits each Secret decryption as preflight validation, before it happens, with no verdict", async () => {
    log.reset();
    expect((await preflight()).status).toBe(200);
    const { decrypted, audited } = checkAuditBeforeDecryption(log);
    expect(audited).toEqual(decrypted);
    const events = await ctx.db.query(
      "SELECT metadata FROM audit_events WHERE event_type = 'secret.validated' ORDER BY event_order DESC LIMIT 1",
    );
    const metadata = (events.rows[0] as { metadata: unknown }).metadata;
    const parsed = typeof metadata === "string" ? JSON.parse(metadata) : metadata;
    expect(Object.keys(parsed).sort()).toEqual(["items", "purpose"]);
    expect(parsed.purpose).toBe("preflight-validation");
  });

  it("without secret.reveal, Secrets are not evaluated and nothing sensitive is decrypted", async () => {
    const svc = (await call("POST", "/v1/organizations/acme/identities", { name: "operator", kind: "service" })).body;
    await grant(svc.id, ["config.metadata.read", "config.value.read", "secret.use", "contract.read"]);
    log.reset();
    const res = await preflight(svc.credential);
    expect(res.status).toBe(200);
    expect(res.body.validation.notEvaluated).toEqual([
      { name: "DATABASE_URL", reason: "permission", requires: "secret.reveal" },
      { name: "DB_PASS", reason: "permission", requires: "secret.reveal" },
      { name: "STRIPE_KEY", reason: "permission", requires: "secret.reveal" },
    ]);
    expect(res.body.validation.complete).toBe(false);
    const decrypted = log.entries.filter((e) => e.kind === "decrypt").length;
    expect(decrypted).toBe(1); // DB_HOST only
  });
});

describe("the Broker's issuance with a precondition", () => {
  it("on a match, reports presence and the Agent's authorization, and decrypts nothing", async () => {
    await grant(agentId, ["secret.use"]);
    const retrieval = (await preflight()).body;
    log.reset();
    const res = await issue(retrieval, { items: ["DB_PASS", "STRIPE_KEY", "NOT_STORED"] });
    expect(res.status).toBe(201);
    expect(res.body.preflightItems).toEqual([
      { name: "DB_PASS", present: true, authorized: true },
      { name: "STRIPE_KEY", present: true, authorized: true },
      { name: "NOT_STORED", present: false, authorized: true },
    ]);
    expect(log.entries.filter((e) => e.kind === "decrypt")).toHaveLength(0);
    expect(res.text).not.toContain("validation");
  });

  it("reports an Agent without secret.use as unauthorized, with a reason class", async () => {
    const retrieval = (await preflight()).body;
    const res = await issue(retrieval, { items: ["DB_PASS"] });
    expect(res.body.preflightItems).toEqual([{ name: "DB_PASS", present: true, authorized: false, reason: "permission" }]);
  });

  it("refuses a changed state with the categories that changed, never identifiers, and issues nothing", async () => {
    await grant(agentId, ["secret.use"]);
    const cases: [() => Promise<unknown>, string[]][] = [
      [() => call("PUT", `${E}/values/DB_HOST`, { value: "db2.internal" }), ["items"]],
      [() => call("POST", `${E}/values/DB_PASS/rotations`, { value: "hunter3-hunter3" }), ["items", "rotation"]],
      [
        async () => {
          const next = await call("POST", `${P}/contract/revisions`, {
            contract: { schemaVersion: 1, semanticsVersion: 2, items: [item("DB_HOST", false)] },
          });
          await call("POST", `${P}/contract/revisions/${next.body.id}/activate`, {});
        },
        ["contract"],
      ],
    ];
    for (const [change, categories] of cases) {
      const retrieval = (await preflight()).body;
      await change();
      const before = await ctx.db.query("SELECT count(*)::int AS n FROM capabilities");
      const res = await issue(retrieval);
      expect(res.status).toBe(409);
      expect(res.body.error.code).toBe("STATE_CHANGED");
      expect(res.body.error.details).toEqual({ categories });
      expect(res.text).not.toMatch(/(val|ver|rev|env|prj)_[a-z0-9]{6,}/);
      const after = await ctx.db.query("SELECT count(*)::int AS n FROM capabilities");
      expect((after.rows[0] as { n: number }).n).toBe((before.rows[0] as { n: number }).n);
    }
  });

  it("rejects a precondition for another Environment", async () => {
    const retrieval = (await preflight()).body;
    const res = await issue(retrieval, {
      precondition: { ...retrieval.manifest, projectId, environmentId: "env_other", stateDigest: retrieval.stateDigest, stateDigests: retrieval.stateDigests },
    });
    expect(res.status).toBe(422);
  });

  it("a matching digest is not a claim about the Agent's references: exercise still resolves or denies", async () => {
    // The operator expands DATABASE_URL (it reads DB_HOST); the Agent holds
    // secret.use but not config.value.read, so it cannot.
    await grant(agentId, ["secret.use"]);
    const retrieval = (await preflight()).body;
    expect(retrieval.validation.unresolved).toEqual([]);
    const issued = await issue(retrieval, { items: ["DATABASE_URL", "DB_PASS"] });
    expect(issued.status).toBe(201);
    expect(issued.body.preflightItems.every((i: { authorized: boolean }) => i.authorized)).toBe(true);
    const exercise = await call(
      "POST",
      `${E}/capabilities/${issued.body.id}/exercises`,
      {
        capabilitySecret: issued.body.secret,
        destination: { host: "api.example.com", port: 443 },
        placements: [{ item: "DATABASE_URL", target: "json:/database_url" }],
      },
      brokerToken,
    );
    expect(exercise.status).toBe(403);
    expect(exercise.body.error.details).toMatchObject({ reason: "unresolved-reference", cause: "plain-read-denied" });
  });
});
