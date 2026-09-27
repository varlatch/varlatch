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
 * Strict retrieval and the state manifest (ADR-0038 Decision 6): one
 * request returns the values this caller may receive, the caller-independent
 * manifest and its digest, the caller view, the Contract, and the
 * validation of exactly those values, all from one snapshot, or fails with
 * no values at all.
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
const DEV = `${P}/environments/dev`;
const CHILD = `${P}/environments/${encodeURIComponent("dev/child")}`;
const PLAINTEXT = ["db.internal", "hunter2-hunter2", "tok-1-tok-1"];

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let log: TraceLog;
let adminToken: string;
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
const strict = (path: string, token = adminToken) => call("POST", `${path}/retrievals`, { mode: "strict" }, token);

function item(name: string, sensitive: boolean, type = "string", required: unknown = { kind: "never" }) {
  return { name, required, sensitive, type };
}

async function identity(name: string, actions: string[], projectActions: string[] = []) {
  const svc = (await call("POST", "/v1/organizations/acme/identities", { name, kind: "service" })).body;
  const grant = await call("POST", "/v1/organizations/acme/grants", {
    subjectIdentityId: svc.id,
    scope: { kind: "environments", projectId, selector: { kind: "tier", tier: "development" } },
    actions,
  });
  expect(grant.status).toBe(201);
  if (projectActions.length > 0) {
    await call("POST", "/v1/organizations/acme/grants", {
      subjectIdentityId: svc.id,
      scope: { kind: "project", projectId },
      actions: projectActions,
    });
  }
  return svc.credential as string;
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
  projectId = (await call("POST", "/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "managed" })).body.id;
  const dev = await call("POST", `${P}/environments`, { name: "dev", tier: "development" });
  await call("POST", `${P}/environments`, { name: "dev/child", parentEnvironmentId: dev.body.id });
  const revision = await call("POST", `${P}/contract/revisions`, {
    contract: {
      schemaVersion: 1,
      semanticsVersion: 2,
      items: [
        item("DB_HOST", false, "string", { kind: "always" }),
        item("PORT", false, "number"),
        item("LEAK", false),
        item("DB_PASS", true),
        item("DATABASE_URL", true, "url"),
        item("TOKEN", true),
        item("MISSING", false, "string", { kind: "always" }),
      ],
    },
  });
  await call("POST", `${P}/contract/revisions/${revision.body.id}/activate`, {});
  for (const [name, value] of [
    ["DB_HOST", "db.internal"],
    ["PORT", "not-a-port"],
    ["LEAK", "${DB_PASS}"],
    ["DB_PASS", "hunter2-hunter2"],
    ["DATABASE_URL", "postgres://app:${DB_PASS}@${DB_HOST}:5432/app"],
    ["TOKEN", "tok-1-tok-1"],
  ]) {
    expect((await call("PUT", `${DEV}/values/${name}`, { value })).status).toBe(200);
  }
});
afterEach(async () => {
  hooks.log = null;
  await ctx.close();
});

describe("strict retrieval", () => {
  it("returns every authorized value, the manifest, the Contract, and verdicts on exactly those values", async () => {
    const res = await strict(DEV);
    expect(res.status).toBe(200);
    const byName = Object.fromEntries(res.body.items.map((i: { name: string }) => [i.name, i]));
    expect(byName.DATABASE_URL.value).toBe("postgres://app:hunter2-hunter2@db.internal:5432/app");
    expect(byName.DATABASE_URL.rawValue).toBe("postgres://app:${DB_PASS}@${DB_HOST}:5432/app");
    // A non-sensitive value never expands a Secret: literal, and reported.
    expect(byName.LEAK.value).toBe("${DB_PASS}");
    expect(res.body.callerView).toEqual({
      withheld: [],
      unexpanded: [{ name: "LEAK", references: ["DB_PASS"] }],
      contractWithheld: false,
    });
    expect(res.body.contract.items.map((i: { name: string }) => i.name)).toContain("MISSING");
    expect(res.body.validation).toMatchObject({
      valid: false,
      complete: true,
      missing: ["MISSING"],
      invalid: [{ name: "PORT", reason: "must be a number" }],
      unresolved: [{ name: "LEAK", reason: "reference" }],
      notEvaluated: [],
    });
    expect(res.body.manifest.contract).toMatchObject({ semanticsVersion: 2 });
    expect(res.body.stateDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("audits before every decryption and reads nothing after the snapshot", async () => {
    log.reset();
    expect((await strict(DEV)).status).toBe(200);
    const { decrypted, audited } = checkAuditBeforeDecryption(log);
    expect(decrypted).toHaveLength(6);
    expect(audited).toEqual(decrypted);
  });

  it("a caller without secret.reveal gets the non-sensitive values in the same response, Secrets withheld", async () => {
    const reader = await identity("reader", ["config.metadata.read", "config.value.read"]);
    const res = await strict(DEV, reader);
    expect(res.status).toBe(200);
    for (const secret of ["hunter2-hunter2", "tok-1-tok-1"]) expect(res.text).not.toContain(secret);
    const byName = Object.fromEntries(res.body.items.map((i: { name: string }) => [i.name, i]));
    expect(byName.DB_HOST.value).toBe("db.internal");
    expect(byName.TOKEN.value).toBeNull();
    expect(res.body.callerView.withheld).toEqual([
      { name: "DATABASE_URL", reason: "permission", requires: "secret.reveal" },
      { name: "DB_PASS", reason: "permission", requires: "secret.reveal" },
      { name: "TOKEN", reason: "permission", requires: "secret.reveal" },
    ]);
    // Withheld items get no verdict; the Contract needs contract.read.
    expect(res.body.validation.notEvaluated.map((i: { name: string }) => i.name)).toEqual(["DATABASE_URL", "DB_PASS", "TOKEN"]);
    expect(res.body.validation.complete).toBe(false);
    expect(res.body.contract).toBeNull();
    expect(res.body.callerView.contractWithheld).toBe(true);
  });

  it("requires config.metadata.read, and names the request mode", async () => {
    const nobody = await identity("nobody", ["environment.read"]);
    expect((await strict(DEV, nobody)).status).toBe(403);
    expect((await call("POST", `${DEV}/retrievals`, { mode: "lenient" })).status).toBe(422);
  });

  it("a failed audit commit returns an error and no values", async () => {
    log.reset();
    log.failAudit = (type) => type === "secret.disclosed";
    const res = await strict(DEV);
    expect(res.status).toBe(500);
    for (const value of PLAINTEXT) expect(res.text).not.toContain(value);
    expect(log.entries.filter((e) => e.kind === "decrypt")).toHaveLength(0);
  });

  it("a failed decryption or expansion returns an error and no values", async () => {
    hooks.failDecrypt = true;
    const failed = await strict(DEV);
    hooks.failDecrypt = false;
    expect(failed.status).toBe(500);
    for (const value of PLAINTEXT) expect(failed.text).not.toContain(value);

    // An expansion over the size limit fails the whole retrieval.
    const big = "x".repeat(600 * 1024);
    await call("PUT", `${DEV}/values/DB_HOST`, { value: big });
    await call("PUT", `${DEV}/values/LEAK`, { value: "${DB_HOST}${DB_HOST}" });
    const over = await strict(DEV);
    expect(over.status).toBe(422);
    for (const value of PLAINTEXT) expect(over.text).not.toContain(value);
  });

  it("/v1/meta advertises it", async () => {
    const meta = await (await app.request("/v1/meta")).json();
    expect(meta.capabilities).toEqual(expect.arrayContaining(["retrieval.strict", "retrieval.manifest"]));
  });
});

describe("the state manifest and stateDigest", () => {
  it("contain identifiers only, never plaintext", async () => {
    const res = await strict(DEV);
    const manifest = JSON.stringify({ manifest: res.body.manifest, stateDigest: res.body.stateDigest });
    for (const value of [...PLAINTEXT, "not-a-port", "${DB_PASS}"]) expect(manifest).not.toContain(value);
    expect(Object.keys(res.body.manifest).sort()).toEqual(["contract", "environment", "items", "manifestVersion", "projectId"]);
  });

  it("are the same for callers with different Grants, and across the endpoints that carry them", async () => {
    const reader = await identity("reader", ["config.metadata.read", "config.value.read"]);
    const metadataOnly = await identity("meta", ["config.metadata.read"]);
    const digests = [
      (await strict(DEV)).body.stateDigest,
      (await strict(DEV, reader)).body.stateDigest,
      (await strict(DEV, metadataOnly)).body.stateDigest,
      (await call("GET", `${DEV}/effective-configuration`, undefined, metadataOnly)).body.stateDigest,
      (await call("GET", `${DEV}/effective-configuration?include=values`)).body.stateDigest,
      (await call("POST", `${DEV}/disclosures`, { scope: "all-authorized-secrets" })).body.stateDigest,
    ];
    expect(new Set(digests).size).toBe(1);
  });

  it("change with the parent's values, a source switch, a rotation window, and a reference input's version", async () => {
    const digest = async () => (await strict(CHILD)).body.stateDigest as string;
    const seen = [await digest()];
    // A parent write changes what the child resolves.
    await call("PUT", `${DEV}/values/TOKEN`, { value: "tok-2-tok-2" });
    seen.push(await digest());
    // The child overrides a name: its source switches from parent to self.
    await call("PUT", `${CHILD}/values/DB_HOST`, { value: "child.internal" });
    seen.push(await digest());
    // A rotation opens a window, and its deadline passing closes it without a write to the value.
    await call("POST", `${DEV}/values/DB_PASS/rotations`, { value: "hunter3-hunter3" });
    seen.push(await digest());
    await ctx.db.query("UPDATE env_values SET rotation_deadline = now() - interval '1 second' WHERE item_name = 'DB_PASS'");
    seen.push(await digest());
    // DATABASE_URL's own version is unchanged, but an input it references moved.
    await call("PUT", `${CHILD}/values/DB_HOST`, { value: "child2.internal" });
    seen.push(await digest());
    expect(new Set(seen).size).toBe(seen.length);
  });

  it("carry the caller view on the two-request path", async () => {
    const effective = await call("GET", `${DEV}/effective-configuration?include=values`);
    expect(effective.body.callerView).toEqual({ withheld: [], unexpanded: [{ name: "LEAK", references: ["DB_PASS"] }] });
    const reader = await identity("meta", ["config.metadata.read"]);
    const withheld = await call("GET", `${DEV}/effective-configuration?include=values`, undefined, reader);
    expect(withheld.body.callerView.withheld.map((w: { name: string }) => w.name)).toEqual(["DB_HOST", "LEAK", "PORT"]);
    const disclosure = await call("POST", `${DEV}/disclosures`, { scope: "all-authorized-secrets" });
    expect(disclosure.body.callerView).toEqual({ withheld: [], unexpanded: [] });
  });
});
