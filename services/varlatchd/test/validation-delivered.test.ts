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
 * Validation evaluates the delivered form of a value: references expanded
 * exactly as `varlatch run` receives them. A non-sensitive value expands
 * from non-sensitive values only; a Secret from Secrets and, when the caller
 * may read them, non-sensitive values. A value that would keep a reference
 * literal gets no type verdict: it is reported as unresolved. Values read
 * only to expand references are audited before they are decrypted.
 */

const P = "/v1/organizations/acme/projects/api";
const E = `${P}/environments/production`;

const STORED: Record<string, string> = {
  DB_HOST: "db.internal",
  DB_PASS: "hunter2-hunter2",
  DATABASE_URL: "postgres://app:${DB_PASS}@${DB_HOST}:5432/app",
  PORT_BASE: "808",
  PORT: "${PORT_BASE}0",
  LEAK: "${DB_PASS}",
  GHOST: "${NOPE}",
  CYCLE_A: "${CYCLE_B}",
  CYCLE_B: "${CYCLE_A}",
  ESCAPED: "$${NOT_A_REFERENCE}",
  // Stored but not in the Contract, so sensitive: read only for expansion.
  EXTRA: "extra-extra-1",
  TOKEN: "Bearer ${EXTRA}",
};

function item(name: string, sensitive: boolean, type = "string") {
  return { name, required: { kind: "never" }, sensitive, type };
}

const CONTRACT = {
  schemaVersion: 1,
  items: [
    item("DB_HOST", false),
    item("DB_PASS", true),
    item("DATABASE_URL", true, "url"),
    item("PORT_BASE", false),
    item("PORT", false, "number"),
    item("LEAK", false),
    item("GHOST", false),
    item("CYCLE_A", false),
    item("CYCLE_B", false),
    item("ESCAPED", false),
    item("TOKEN", true),
  ],
};

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let adminId: string;
let projectId: string;

async function call(method: string, path: string, body?: unknown, token = adminToken) {
  return app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

async function identity(name: string, actions: string[]) {
  const svc = await (await call("POST", "/v1/organizations/acme/identities", { name, kind: "service" })).json();
  const grant = await call("POST", "/v1/organizations/acme/grants", {
    subjectIdentityId: svc.id,
    scope: { kind: "environments", projectId, selector: { kind: "tier", tier: "production" } },
    actions,
  });
  expect(grant.status).toBe(201);
  return { id: svc.id as string, token: svc.credential as string };
}

async function events(actorId: string) {
  const res = await ctx.db.query(
    `SELECT event_type, metadata FROM audit_events
      WHERE event_type IN ('secret.validated', 'value.validated') AND actor_identity_id = $1
      ORDER BY event_order`,
    [actorId],
  );
  return (res.rows as { event_type: string; metadata: unknown }[]).map((r) => ({
    eventType: r.event_type,
    metadata: (typeof r.metadata === "string" ? JSON.parse(r.metadata) : r.metadata) as Record<string, string>,
  }));
}

async function versionOf(name: string): Promise<string> {
  const res = await ctx.db.query(
    `SELECT v.current_version_id FROM env_values v JOIN environments e ON e.id = v.environment_id
      WHERE e.name = 'production' AND v.item_name = $1`,
    [name],
  );
  return (res.rows[0] as { current_version_id: string }).current_version_id;
}

beforeEach(async () => {
  const db = await testDb();
  await runMigrations(db);
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const consumed = await consumeSetupGrant(ctx, grant.token, { adminName: "Admin" });
  adminId = consumed.identityId;
  adminToken = (await issueCredential(ctx.db, { identityId: adminId, kind: "cli" })).token;
  app = buildApp(ctx);
  await call("POST", "/v1/organizations", { name: "Acme", slug: "acme" });
  projectId = (await (await call("POST", "/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "managed" })).json()).id;
  expect((await call("POST", `${P}/environments`, { name: "production", tier: "production" })).status).toBe(201);
  const revision = await (await call("POST", `${P}/contract/revisions`, { contract: CONTRACT })).json();
  expect((await call("POST", `${P}/contract/revisions/${revision.id}/activate`, {})).status).toBe(200);
  for (const [name, value] of Object.entries(STORED)) {
    expect((await call("PUT", `${E}/values/${name}`, { value })).status).toBe(200);
  }
});
afterEach(async () => {
  await ctx.close();
});

describe("validation evaluates the delivered form", () => {
  it("expands references as delivery does, and reports what would stay literal", async () => {
    const res = await call("POST", `${E}/validate`, {});
    expect(res.status).toBe(200);
    const text = await res.text();
    for (const value of ["db.internal", "hunter2-hunter2", "extra-extra-1", "8080"]) {
      expect(text).not.toContain(value);
    }
    const report = JSON.parse(text);
    // PORT is `${PORT_BASE}0`: invalid as stored text, a valid number as delivered.
    // DATABASE_URL expands to a URL; TOKEN expands from an item outside the Contract.
    // ESCAPED is delivered as a literal `${NOT_A_REFERENCE}`, by design.
    expect(report.invalid).toEqual([]);
    expect(report.unresolved).toEqual([
      { name: "CYCLE_A", reason: "reference" },
      { name: "CYCLE_B", reason: "reference" },
      // A reference to an item with no value.
      { name: "GHOST", reason: "reference" },
      // A non-sensitive value never expands a Secret, for anyone.
      { name: "LEAK", reason: "reference" },
    ]);
    expect(report).toMatchObject({ valid: false, complete: true, missing: [], notEvaluated: [] });
  });

  it("audits a value read only for expansion before decrypting it, and never a value it does not need", async () => {
    await call("POST", `${E}/validate`, {});
    const audit = await events(adminId);
    const expansion = audit.filter((e) => e.metadata.mode === "reference-expansion");
    // EXTRA is outside the Contract: decrypted only to expand TOKEN, and audited as a Secret read.
    expect(expansion).toEqual([
      {
        eventType: "secret.validated",
        metadata: expect.objectContaining({
          purpose: "validation",
          mode: "reference-expansion",
          items: `EXTRA@${await versionOf("EXTRA")}`,
        }),
      },
    ]);
    // The evaluated items were audited first, in their own events.
    expect(audit[0]?.metadata.mode).toBeUndefined();
    expect(audit.at(-1)?.metadata.mode).toBe("reference-expansion");
    const named = audit.flatMap((e) => e.metadata.items?.split(",") ?? []).map((i) => i.split("@")[0]);
    expect(named).not.toContain("NOPE");
  });

  it("a Secret that references values this caller may not read is unresolved for authority, and nothing plain is decrypted", async () => {
    const revealer = await identity("revealer", ["environment.read", "config.metadata.read", "secret.reveal"]);
    const report = await (await call("POST", `${E}/validate`, {}, revealer.token)).json();
    expect(report.unresolved).toEqual([{ name: "DATABASE_URL", reason: "authority" }]);
    // DB_PASS and TOKEN (with EXTRA) need no non-sensitive value.
    expect(report.invalid).toEqual([]);
    expect(report.notEvaluated.map((i: { name: string }) => i.name)).toEqual([
      "CYCLE_A",
      "CYCLE_B",
      "DB_HOST",
      "ESCAPED",
      "GHOST",
      "LEAK",
      "PORT",
      "PORT_BASE",
    ]);
    expect(report).toMatchObject({ valid: false, complete: false });
    const audit = await events(revealer.id);
    expect(audit.map((e) => e.eventType)).not.toContain("value.validated");
    const named = audit.flatMap((e) => e.metadata.items?.split(",") ?? []).map((i) => i.split("@")[0]);
    expect(named).not.toContain("DB_HOST");
  });

  it("a caller who may read non-sensitive values but not Secrets never has a Secret decrypted", async () => {
    const reader = await identity("reader", ["environment.read", "config.metadata.read", "config.value.read"]);
    const report = await (await call("POST", `${E}/validate`, {}, reader.token)).json();
    expect(report.unresolved).toEqual([
      { name: "CYCLE_A", reason: "reference" },
      { name: "CYCLE_B", reason: "reference" },
      { name: "GHOST", reason: "reference" },
      { name: "LEAK", reason: "reference" },
    ]);
    const audit = await events(reader.id);
    expect(audit.map((e) => e.eventType)).not.toContain("secret.validated");
  });
});
