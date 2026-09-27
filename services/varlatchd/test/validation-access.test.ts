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
 * Validation verdicts are value-derived: an enum verdict says whether a value
 * is in a list, and a principal who can also change the Contract can turn
 * that into a guessing oracle. `POST …/validate` used to need only
 * environment.read and to decrypt every value without an audit event. Now each
 * verdict needs the right to read what it describes (secret.reveal, with its
 * Requirements, for Secrets), decryption is audited before it happens, and
 * everything else is reported as not evaluated.
 */

const VALIDATE = "/v1/organizations/acme/projects/api/environments/production/validate";
const STORED = { PORT: "not-a-number", LOG_LEVEL: "info", API_TOKEN: "tok-abc-123", REGION: "eu-west-9" };

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let projectId: string;

function auth(token = adminToken): HeadersInit {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}
async function post(path: string, body: unknown, token = adminToken, on = app) {
  return on.request(path, { method: "POST", headers: auth(token), body: JSON.stringify(body) });
}
async function put(path: string, body: unknown) {
  return app.request(path, { method: "PUT", headers: auth(), body: JSON.stringify(body) });
}

function contract(regionEnum: string[]) {
  return {
    schemaVersion: 1,
    items: [
      { name: "API_TOKEN", required: { kind: "always" }, sensitive: true, type: "string" },
      { name: "DATABASE_URL", required: { kind: "always" }, sensitive: true, type: "url" },
      { name: "LOG_LEVEL", required: { kind: "never" }, sensitive: false, type: "enum", enumValues: ["debug", "info"] },
      { name: "PORT", required: { kind: "always" }, sensitive: false, type: "number" },
      { name: "REGION", required: { kind: "never" }, sensitive: true, type: "enum", enumValues: regionEnum },
    ],
  };
}

async function activate(regionEnum: string[], token = adminToken) {
  const push = await post("/v1/organizations/acme/projects/api/contract/revisions", { contract: contract(regionEnum) }, token);
  expect(push.status).toBe(201);
  const revision = await push.json();
  const act = await post(`/v1/organizations/acme/projects/api/contract/revisions/${revision.id}/activate`, {}, token);
  expect(act.status).toBe(200);
}

/** A service identity with the given actions on production (and project-level actions, if any). */
async function identity(name: string, envActions: string[], projectActions: string[] = []) {
  const svc = await (await post("/v1/organizations/acme/identities", { name, kind: "service" })).json();
  const envGrant = await post("/v1/organizations/acme/grants", {
    subjectIdentityId: svc.id,
    scope: { kind: "environments", projectId, selector: { kind: "tier", tier: "production" } },
    actions: envActions,
  });
  expect(envGrant.status).toBe(201);
  if (projectActions.length > 0) {
    const prjGrant = await post("/v1/organizations/acme/grants", {
      subjectIdentityId: svc.id,
      scope: { kind: "project", projectId },
      actions: projectActions,
    });
    expect(prjGrant.status).toBe(201);
  }
  return { id: svc.id as string, token: svc.credential as string };
}

async function validationEvents(actorId?: string) {
  const res = await ctx.db.query(
    `SELECT event_type, actor_identity_id, action, metadata FROM audit_events
      WHERE event_type IN ('secret.validated', 'value.validated') ORDER BY occurred_at, id`,
  );
  return (res.rows as { event_type: string; actor_identity_id: string; action: string; metadata: unknown }[])
    .filter((r) => actorId === undefined || r.actor_identity_id === actorId)
    .map((r) => ({
      eventType: r.event_type,
      action: r.action,
      metadata: (typeof r.metadata === "string" ? JSON.parse(r.metadata) : r.metadata) as Record<string, unknown>,
    }));
}

function expectNoStoredValues(text: string) {
  for (const value of Object.values(STORED)) expect(text).not.toContain(value);
}

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Admin" });
  adminToken = (await issueCredential(ctx.db, { identityId: consumed.identityId, kind: "cli" })).token;
  app = buildApp(ctx);

  await post("/v1/organizations", { name: "Acme", slug: "acme" });
  const prj = await (await post("/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "git" })).json();
  projectId = prj.id;
  await post("/v1/organizations/acme/projects/api/environments", { name: "production", tier: "production" });
  await activate(["eu-west-9", "us-east-9"]);
  for (const [name, value] of Object.entries(STORED)) {
    const res = await put(`/v1/organizations/acme/projects/api/environments/production/values/${name}`, { value });
    expect(res.status).toBe(200);
  }
});
afterEach(async () => {
  await ctx.close();
});

describe("validation requires the right to read what each verdict describes", () => {
  it("environment.read and metadata only: presence is reported, no value-derived verdict, nothing decrypted", async () => {
    const reader = await identity("reader", ["environment.read", "config.metadata.read"]);
    const res = await post(VALIDATE, {}, reader.token);
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const text = await res.text();
    expectNoStoredValues(text);
    const report = JSON.parse(text);
    expect(report).toMatchObject({ valid: false, complete: false, missing: ["DATABASE_URL"], invalid: [] });
    expect(report.notEvaluated).toEqual([
      { name: "API_TOKEN", reason: "permission", requires: "secret.reveal" },
      { name: "LOG_LEVEL", reason: "permission", requires: "config.value.read" },
      { name: "PORT", reason: "permission", requires: "config.value.read" },
      { name: "REGION", reason: "permission", requires: "secret.reveal" },
    ]);
    expect(await validationEvents(reader.id)).toEqual([]);
  });

  it("environment.read alone: even presence is not evaluated", async () => {
    const bare = await identity("bare", ["environment.read"]);
    const report = await (await post(VALIDATE, {}, bare.token)).json();
    expect(report).toMatchObject({ valid: false, complete: false, missing: [], invalid: [] });
    expect(report.notEvaluated.map((i: { name: string; requires: string }) => `${i.name}:${i.requires}`)).toEqual([
      "API_TOKEN:config.metadata.read",
      "DATABASE_URL:config.metadata.read",
      "LOG_LEVEL:config.metadata.read",
      "PORT:config.metadata.read",
      "REGION:config.metadata.read",
    ]);
  });

  it("config.value.read without secret.reveal: non-sensitive verdicts only, and their decryption is audited", async () => {
    const plain = await identity("plain", ["environment.read", "config.metadata.read", "config.value.read"]);
    const text = await (await post(VALIDATE, {}, plain.token)).text();
    expectNoStoredValues(text);
    const report = JSON.parse(text);
    expect(report).toMatchObject({
      valid: false,
      complete: false,
      missing: ["DATABASE_URL"],
      invalid: [{ name: "PORT", reason: "must be a number" }],
    });
    expect(report.notEvaluated.map((i: { name: string }) => i.name)).toEqual(["API_TOKEN", "REGION"]);
    const events = await validationEvents(plain.id);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ eventType: "value.validated", action: "config.value.read" });
    expect(events[0]!.metadata).toMatchObject({ purpose: "validation" });
    expect(String(events[0]!.metadata.items)).toMatch(/^LOG_LEVEL@\S+,PORT@\S+$/);
  });

  it("secret.reveal: full evaluation; decryption audited with item versions, verdicts never recorded", async () => {
    const revealer = await identity("revealer", [
      "environment.read",
      "config.metadata.read",
      "config.value.read",
      "secret.reveal",
    ]);
    const text = await (await post(VALIDATE, {}, revealer.token)).text();
    expectNoStoredValues(text);
    const report = JSON.parse(text);
    expect(report).toMatchObject({
      valid: false,
      complete: true,
      missing: ["DATABASE_URL"],
      invalid: [{ name: "PORT", reason: "must be a number" }],
      notEvaluated: [],
    });
    const events = await validationEvents(revealer.id);
    expect(events.map((e) => e.eventType).sort()).toEqual(["secret.validated", "value.validated"]);
    const secretEvent = events.find((e) => e.eventType === "secret.validated")!;
    expect(secretEvent).toMatchObject({ action: "secret.reveal" });
    expect(String(secretEvent.metadata.items)).toMatch(/^API_TOKEN@\S+,REGION@\S+$/);
    for (const event of events) {
      expect(Object.keys(event.metadata).sort()).toEqual(["contractRevisionId", "items", "purpose"]);
      expectNoStoredValues(JSON.stringify(event.metadata));
    }
  });

  it("an unmet Tailnet Requirement leaves Secrets (and values) not evaluated; the tailnet listener evaluates them", async () => {
    const revealer = await identity("revealer", [
      "environment.read",
      "config.metadata.read",
      "config.value.read",
      "secret.reveal",
    ]);
    const created = await post("/v1/organizations/acme/requirements", {
      kind: "tailnet",
      target: { kind: "tier", tier: "production" },
      selector: { tailnet: "example.ts.net", tags: ["tag:prod"] },
    });
    expect(created.status).toBe(201);

    const ordinary = await (await post(VALIDATE, {}, revealer.token)).json();
    expect(ordinary).toMatchObject({ valid: false, complete: false, missing: ["DATABASE_URL"], invalid: [] });
    expect(ordinary.notEvaluated).toEqual([
      { name: "API_TOKEN", reason: "requirement", requires: "secret.reveal" },
      { name: "LOG_LEVEL", reason: "requirement", requires: "config.value.read" },
      { name: "PORT", reason: "requirement", requires: "config.value.read" },
      { name: "REGION", reason: "requirement", requires: "secret.reveal" },
    ]);
    expect(await validationEvents(revealer.id)).toEqual([]);

    const tailnetApp = buildApp(ctx, {
      resolveTailnetContext: async () => ({ tailnet: "example.ts.net", nodeId: "nT", tags: ["tag:prod"] }),
    });
    const onTailnet = await (await post(VALIDATE, {}, revealer.token, tailnetApp)).json();
    expect(onTailnet).toMatchObject({ complete: true, notEvaluated: [], invalid: [{ name: "PORT", reason: "must be a number" }] });
  });

  it("audit is committed before decryption: if the audit write fails, no verdict is produced", async () => {
    const revealer = await identity("revealer", [
      "environment.read",
      "config.metadata.read",
      "config.value.read",
      "secret.reveal",
    ]);
    await ctx.db.query(`
      CREATE FUNCTION refuse_secret_validated() RETURNS trigger AS $$
      BEGIN
        IF NEW.event_type = 'secret.validated' THEN RAISE EXCEPTION 'audit unavailable'; END IF;
        RETURN NEW;
      END $$ LANGUAGE plpgsql`);
    await ctx.db.query(`
      CREATE TRIGGER refuse_secret_validated BEFORE INSERT ON audit_events
        FOR EACH ROW EXECUTE FUNCTION refuse_secret_validated()`);
    const res = await post(VALIDATE, {}, revealer.token);
    expect(res.status).toBe(500);
    const text = await res.text();
    expectNoStoredValues(text);
    expect(text).not.toContain("must be a number");
    expect(text).not.toContain("must be one of");
  });

  it("repeated enum probes without secret.reveal learn nothing, even with control of the Contract", async () => {
    const prober = await identity(
      "prober",
      ["environment.read", "config.metadata.read"],
      ["contract.read", "contract.submit", "contract.activate"],
    );
    const reports: unknown[] = [];
    for (const guess of ["ap-south-9", "eu-west-9", "us-east-9"]) {
      await activate([guess], prober.token);
      const text = await (await post(VALIDATE, {}, prober.token)).text();
      expectNoStoredValues(text);
      const { contractRevisionId: _rev, ...rest } = JSON.parse(text);
      reports.push(rest);
    }
    // Identical whatever the guess: the correct one is indistinguishable.
    expect(reports[1]).toEqual(reports[0]);
    expect(reports[2]).toEqual(reports[0]);
    expect(reports[0]).toMatchObject({
      notEvaluated: expect.arrayContaining([{ name: "REGION", reason: "permission", requires: "secret.reveal" }]),
    });
    expect(await validationEvents(prober.id)).toEqual([]);
  });

  it("with secret.reveal the same probes do produce verdicts, and every one is audited", async () => {
    const insider = await identity(
      "insider",
      ["environment.read", "config.metadata.read", "config.value.read", "secret.reveal"],
      ["contract.read", "contract.submit", "contract.activate"],
    );
    const regionInvalid: boolean[] = [];
    for (const guess of ["ap-south-9", "eu-west-9", "us-east-9"]) {
      await activate([guess], insider.token);
      const report = await (await post(VALIDATE, {}, insider.token)).json();
      regionInvalid.push(report.invalid.some((i: { name: string }) => i.name === "REGION"));
    }
    // secret.reveal already allows reading the value; the verdicts add nothing,
    // but each probe leaves an audit record naming the version it examined.
    expect(regionInvalid).toEqual([true, false, true]);
    const secretEvents = (await validationEvents(insider.id)).filter((e) => e.eventType === "secret.validated");
    expect(secretEvents).toHaveLength(3);
  });
});
