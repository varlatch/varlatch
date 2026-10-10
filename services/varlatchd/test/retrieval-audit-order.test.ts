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
 * Two-phase retrieval (ADR-0038 Decision 6): every read comes from one
 * read-only snapshot, and each decryption is preceded by the audit commit
 * that names its version, level by level for reference-expansion inputs.
 * A failed audit commit stops the request before that decryption; a failed
 * decryption leaves the audit event as the record of the attempt.
 */

const hooks = vi.hoisted(() => ({ log: null as TraceLog | null, failDecrypt: false }));
vi.mock("../src/crypto/hierarchy.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/crypto/hierarchy.js")>();
  return {
    ...actual,
    decryptValue: (...args: Parameters<typeof actual.decryptValue>) => {
      hooks.log?.decrypt(args[3]);
      if (hooks.failDecrypt) throw new Error("injected decryption failure");
      return actual.decryptValue(...args);
    },
  };
});

const P = "/v1/organizations/acme/projects/api";
const E = `${P}/environments/production`;
const PLAINTEXT = ["db.internal", "hunter2-hunter2", "tok-new-new", "tok-old-old"];

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let log: TraceLog;
let adminToken: string;
let brokerToken: string;
let agentId: string;

async function call(method: string, path: string, body?: unknown, token = adminToken) {
  return app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

function item(name: string, sensitive: boolean) {
  return { name, required: { kind: "never" }, sensitive, type: "string" };
}

async function versionOf(name: string): Promise<string> {
  const res = await ctx.db.query("SELECT current_version_id FROM env_values WHERE item_name = $1", [name]);
  return (res.rows[0] as { current_version_id: string }).current_version_id;
}

async function auditRows(eventType: string) {
  const res = await ctx.db.query("SELECT metadata FROM audit_events WHERE event_type = $1", [eventType]);
  return res.rows.length;
}

/** Run one request with a fresh trace. */
async function traceRequest(run: () => Promise<Response>) {
  log.reset();
  const res = await run();
  const text = await res.text();
  return { status: res.status, text };
}

beforeEach(async () => {
  log = traceLog();
  hooks.log = log;
  hooks.failDecrypt = false;
  const db = traced(await migratedTestDb(), log);
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId } = await consumeSetupGrant(ctx, grant.token, { adminName: "Admin" });
  adminToken = (await issueCredential(ctx.db, { identityId, kind: "cli" })).token;
  app = buildApp(ctx);
  await call("POST", "/v1/organizations", { name: "Acme", slug: "acme" });
  const project = await (await call("POST", "/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "managed" })).json();
  await call("POST", `${P}/environments`, { name: "production", tier: "production" });
  const revision = await (
    await call("POST", `${P}/contract/revisions`, {
      contract: {
        schemaVersion: 1,
        items: [
          item("DB_HOST", false),
          item("DB_ADDR", false),
          item("DB_PASS", true),
          item("DATABASE_URL", true),
          item("TOKEN", true),
        ],
      },
    })
  ).json();
  await call("POST", `${P}/contract/revisions/${revision.id}/activate`, {});
  for (const [name, value] of [
    ["DB_HOST", "db.internal"],
    ["DB_ADDR", "${DB_HOST}:5432"],
    ["DB_PASS", "hunter2-hunter2"],
    ["DATABASE_URL", "postgres://app:${DB_PASS}@${DB_ADDR}/app"],
    ["TOKEN", "tok-old-old"],
  ]) {
    expect((await call("PUT", `${E}/values/${name}`, { value })).status).toBe(200);
  }
  // A rotation in progress: disclosure decrypts the retiring version too.
  expect((await call("POST", `${E}/values/TOKEN/rotations`, { value: "tok-new-new" })).status).toBe(201);

  const broker = await (await call("POST", "/v1/organizations/acme/identities", { name: "broker", kind: "broker" })).json();
  brokerToken = broker.credential;
  const agent = await (await call("POST", "/v1/organizations/acme/identities", { name: "agent", kind: "agent" })).json();
  agentId = agent.id;
  expect(
    (
      await call("POST", "/v1/organizations/acme/grants", {
        subjectIdentityId: agentId,
        scope: { kind: "project", projectId: project.id },
        actions: ["secret.use", "config.value.read"],
      })
    ).status,
  ).toBe(201);
});
afterEach(async () => {
  hooks.log = null;
  await ctx.close();
});

async function issueCapability() {
  const res = await call(
    "POST",
    `${E}/capabilities`,
    {
      agentIdentityId: agentId,
      items: ["DATABASE_URL", "DB_PASS"],
      destinations: ["db.example.com"],
      targets: { DATABASE_URL: ["json:/dsn"], DB_PASS: ["json:/password"] },
      ttlSeconds: 600,
    },
    brokerToken,
  );
  expect(res.status).toBe(201);
  return (await res.json()) as { id: string; secret: string };
}

const exercise = (cap: { id: string; secret: string }) =>
  call(
    "POST",
    `${E}/capabilities/${cap.id}/exercises`,
    // Only DATABASE_URL is placed: DB_PASS is a bound dependency, decrypted to
    // expand it and never returned (ADR-0039 Decision 7).
    {
      capabilitySecret: cap.secret,
      destination: { host: "db.example.com", port: 443 },
      placements: [{ item: "DATABASE_URL", target: "json:/dsn" }],
    },
    brokerToken,
  );

describe("every decryption follows the audit commit that names it, and nothing is read after the snapshot", () => {
  it("effective configuration with values", async () => {
    const res = await traceRequest(() => call("GET", `${E}/effective-configuration?include=values`));
    expect(res.status).toBe(200);
    const { decrypted, audited } = checkAuditBeforeDecryption(log);
    expect(decrypted).toEqual([await versionOf("DB_ADDR"), await versionOf("DB_HOST")].sort());
    expect(audited).toEqual(decrypted);
  });

  it("disclosure, including the retiring version and two reference levels", async () => {
    const res = await traceRequest(() => call("POST", `${E}/disclosures`, { scope: "all-authorized-secrets" }));
    expect(res.status).toBe(200);
    expect(res.text).toContain("postgres://app:hunter2-hunter2@db.internal:5432/app");
    const { decrypted, audited } = checkAuditBeforeDecryption(log);
    const retiring = (
      (await ctx.db.query("SELECT retiring_version_id FROM env_values WHERE item_name = 'TOKEN'")).rows[0] as {
        retiring_version_id: string;
      }
    ).retiring_version_id;
    expect(decrypted).toEqual(
      [
        await versionOf("DATABASE_URL"),
        await versionOf("DB_PASS"),
        await versionOf("TOKEN"),
        retiring,
        await versionOf("DB_ADDR"),
        await versionOf("DB_HOST"),
      ].sort(),
    );
    expect(audited).toEqual(decrypted);
  });

  it("validation", async () => {
    const res = await traceRequest(() => call("POST", `${E}/validate`, {}));
    expect(res.status).toBe(200);
    const { decrypted, audited } = checkAuditBeforeDecryption(log);
    expect(decrypted).toHaveLength(5);
    expect(audited).toEqual(decrypted);
  });

  it("capability exercise, with a bound dependency and reference expansion (ADR-0039 test 20)", async () => {
    const cap = await issueCapability();
    const dbPass = await versionOf("DB_PASS");
    const res = await traceRequest(() => exercise(cap));
    expect(res.status).toBe(200);
    const body = JSON.parse(res.text) as { items: { name: string; value: string }[] };
    expect(body.items.map((i) => i.name)).toEqual(["DATABASE_URL"]);
    expect(body.items[0]!.value).toBe("postgres://app:hunter2-hunter2@db.internal:5432/app");
    const { decrypted, audited } = checkAuditBeforeDecryption(log);
    const dependency = (
      await ctx.db.query(
        "SELECT metadata::jsonb->>'items' AS items FROM audit_events WHERE event_type = 'secret.disclosed' AND metadata::jsonb->>'mode' = 'reference-expansion'",
      )
    ).rows as { items: string }[];
    expect(dependency).toEqual([{ items: `DB_PASS@${dbPass}` }]);
    // Expansion levels record what they were allowed by, as the exercise does (issue #22).
    const expansions = (
      await ctx.db.query(
        "SELECT event_type, action, authz FROM audit_events WHERE metadata::jsonb->>'mode' = 'reference-expansion' AND metadata::jsonb ? 'runId'",
      )
    ).rows as { event_type: string; action: string; authz: unknown }[];
    expect(new Set(expansions.map((e) => `${e.event_type}:${e.action}`))).toEqual(new Set(["secret.disclosed:secret.use", "value.disclosed:config.value.read"]));
    for (const e of expansions) {
      expect(typeof e.authz === "string" ? JSON.parse(e.authz) : e.authz).toMatchObject({ grantIds: expect.any(Array), requirements: [] });
    }
    expect(decrypted).toEqual(
      [
        await versionOf("DATABASE_URL"),
        await versionOf("DB_PASS"),
        await versionOf("DB_ADDR"),
        await versionOf("DB_HOST"),
      ].sort(),
    );
    expect(audited).toEqual(decrypted);
  });
});

describe("a failed audit commit stops the request before the decryption it covers", () => {
  const decryptions = () => log.entries.filter((e) => e.kind === "decrypt").length;
  const noPlaintext = (text: string) => {
    for (const value of PLAINTEXT) expect(text).not.toContain(value);
  };

  it("effective configuration", async () => {
    log.reset();
    log.failAudit = (type) => type === "value.disclosed";
    const res = await app.request(`${E}/effective-configuration?include=values`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    expect(res.status).toBe(500);
    noPlaintext(await res.text());
    expect(decryptions()).toBe(0);
  });

  it("disclosure: the requested Secrets", async () => {
    log.reset();
    log.failAudit = (type) => type === "secret.disclosed";
    const res = await call("POST", `${E}/disclosures`, { scope: "all-authorized-secrets" });
    expect(res.status).toBe(500);
    noPlaintext(await res.text());
    expect(decryptions()).toBe(0);
  });

  it("disclosure: a reference-expansion level", async () => {
    log.reset();
    log.failAudit = (type, metadata) => type === "value.disclosed" && metadata.includes("reference-expansion");
    const res = await call("POST", `${E}/disclosures`, { scope: "all-authorized-secrets" });
    expect(res.status).toBe(500);
    noPlaintext(await res.text());
    const decrypted = log.entries.flatMap((e) => (e.kind === "decrypt" ? [e.versionId] : []));
    expect(decrypted).not.toContain(await versionOf("DB_ADDR"));
    expect(decrypted).not.toContain(await versionOf("DB_HOST"));
  });

  it("validation", async () => {
    log.reset();
    log.failAudit = (type) => type === "secret.validated";
    const res = await call("POST", `${E}/validate`, {});
    expect(res.status).toBe(500);
    expect(decryptions()).toBe(0);
  });

  it("capability exercise", async () => {
    const cap = await issueCapability();
    log.reset();
    log.failAudit = (type) => type === "capability.exercised";
    const res = await exercise(cap);
    expect(res.status).toBe(500);
    noPlaintext(await res.text());
    expect(decryptions()).toBe(0);
  });

  it("capability exercise: a bound dependency's reference-expansion level", async () => {
    const cap = await issueCapability();
    log.reset();
    log.failAudit = (type, metadata) => type === "secret.disclosed" && metadata.includes("reference-expansion");
    const res = await exercise(cap);
    expect(res.status).toBe(500);
    noPlaintext(await res.text());
    const decrypted = log.entries.flatMap((e) => (e.kind === "decrypt" ? [e.versionId] : []));
    expect(decrypted).toEqual([await versionOf("DATABASE_URL")]);
  });
});

describe("a failed decryption leaves the audit event as the record of the attempt", () => {
  it("disclosure", async () => {
    const before = await auditRows("secret.disclosed");
    hooks.failDecrypt = true;
    const res = await call("POST", `${E}/disclosures`, { items: ["DB_PASS"] });
    hooks.failDecrypt = false;
    expect(res.status).toBe(500);
    expect(await auditRows("secret.disclosed")).toBe(before + 1);
  });
});
