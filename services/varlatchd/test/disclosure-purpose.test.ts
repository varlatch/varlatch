// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { VarlatchApiError, VarlatchClient } from "@varlatch/sdk";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * The disclosure `purpose` (ADR-0038 Decision 14): an optional, allowlisted
 * declaration recorded in the disclosure's audit events. It changes nothing
 * else: not what is returned, and not who may ask.
 */

const P = "/v1/organizations/acme/projects/api";
const E = `${P}/environments/production`;

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminToken: string;
let client: VarlatchClient;
let projectId: string;

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

async function versionOf(name: string, column = "current_version_id"): Promise<string> {
  const res = await ctx.db.query(`SELECT ${column} AS id FROM env_values WHERE item_name = $1`, [name]);
  return (res.rows[0] as { id: string }).id;
}

async function events(eventType: string): Promise<Record<string, unknown>[]> {
  const res = await ctx.db.query(
    "SELECT metadata FROM audit_events WHERE event_type = $1 ORDER BY occurred_at, id",
    [eventType],
  );
  return res.rows.map((r) => {
    const m = (r as { metadata: unknown }).metadata;
    return (typeof m === "string" ? JSON.parse(m) : m) as Record<string, unknown>;
  });
}

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId } = await consumeSetupGrant(ctx, grant.token, { adminName: "Admin" });
  adminToken = (await issueCredential(ctx.db, { identityId, kind: "cli" })).token;
  app = buildApp(ctx);
  const fetchImpl: typeof fetch = (input, init) =>
    app.request(input instanceof Request ? input : String(input).replace("http://varlatch", ""), init);
  client = new VarlatchClient({ server: "http://varlatch", token: adminToken, fetch: fetchImpl });

  await call("POST", "/v1/organizations", { name: "Acme", slug: "acme" });
  projectId = (await (await call("POST", "/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "managed" })).json()).id;
  await call("POST", `${P}/environments`, { name: "production", tier: "production" });
  const revision = await (
    await call("POST", `${P}/contract/revisions`, {
      contract: {
        schemaVersion: 1,
        items: [item("DB_HOST", false), item("DB_PASS", true), item("DATABASE_URL", true), item("TOKEN", true)],
      },
    })
  ).json();
  await call("POST", `${P}/contract/revisions/${revision.id}/activate`, {});
  for (const [name, value] of [
    ["DB_HOST", "db.internal"],
    ["DB_PASS", "hunter2-hunter2"],
    ["DATABASE_URL", "postgres://app:${DB_PASS}@${DB_HOST}/app"],
    ["TOKEN", "tok-old-old-old"],
  ]) {
    expect((await call("PUT", `${E}/values/${name}`, { value })).status).toBe(200);
  }
  // A rotation in progress: the scan needs the retiring value too.
  expect((await call("POST", `${E}/values/TOKEN/rotations`, { value: "tok-new-new-new" })).status).toBe(201);
});
afterEach(async () => {
  await ctx.close();
});

describe("the disclosure purpose", () => {
  it("is advertised in /v1/meta", async () => {
    expect((await client.meta()).capabilities).toContain("secrets.disclosure-purpose");
  });

  it("scan: one disclosure, audited before decryption with purpose scan, current and retiring versions", async () => {
    const disclosed = await client.discloseSecrets("acme", "api", "production", {
      scope: "all-authorized-secrets",
      purpose: "scan",
    });
    const token = disclosed.items.find((i) => i.name === "TOKEN");
    expect(token).toMatchObject({ value: "tok-new-new-new", retiring: { value: "tok-old-old-old" } });
    expect(disclosed.items.find((i) => i.name === "DATABASE_URL")?.value).toBe(
      "postgres://app:hunter2-hunter2@db.internal/app",
    );

    const disclosedEvents = await events("secret.disclosed");
    expect(disclosedEvents).toHaveLength(1);
    const [event] = disclosedEvents;
    expect(event).toMatchObject({ mode: "all-authorized-secrets", purpose: "scan", withheld: 0 });
    const items = String(event!.items).split(",").sort();
    expect(items).toEqual(
      [
        `DATABASE_URL@${await versionOf("DATABASE_URL")}`,
        `DB_PASS@${await versionOf("DB_PASS")}`,
        `TOKEN@${await versionOf("TOKEN")}+${await versionOf("TOKEN", "retiring_version_id")}`,
      ].sort(),
    );
    // The non-sensitive value read to expand DATABASE_URL carries the purpose too.
    const expansion = await events("value.disclosed");
    expect(expansion).toEqual([
      { mode: "reference-expansion", items: `DB_HOST@${await versionOf("DB_HOST")}`, purpose: "scan" },
    ]);
    // The public audit shape carries it, and never a value.
    const page = await client.listAuditEvents("acme", { limit: 50 });
    const exported = page.items.find((e) => e.eventType === "secret.disclosed");
    expect(exported?.metadata).toMatchObject({ purpose: "scan" });
    const serialized = JSON.stringify(page.items);
    for (const secret of ["hunter2-hunter2", "tok-new-new-new", "tok-old-old-old", "db.internal"]) {
      expect(serialized).not.toContain(secret);
    }
  });

  it("without a purpose, the response and the audit event are unchanged", async () => {
    const plain = await client.discloseSecrets("acme", "api", "production", { scope: "all-authorized-secrets" });
    const scan = await client.discloseSecrets("acme", "api", "production", {
      scope: "all-authorized-secrets",
      purpose: "scan",
    });
    expect(scan).toEqual(plain);
    const [first, second] = await events("secret.disclosed");
    expect(first).not.toHaveProperty("purpose");
    expect(Object.keys(first!).sort()).toEqual(["items", "mode", "withheld"]);
    expect(second).toEqual({ ...first, purpose: "scan" });
    const expansion = await events("value.disclosed");
    expect(expansion[0]).not.toHaveProperty("purpose");
    expect(expansion[1]).toMatchObject({ purpose: "scan" });
  });

  it("works with requested items too", async () => {
    const res = await call("POST", `${E}/disclosures`, { items: ["TOKEN", "NOPE"], purpose: "scan" });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.withheld).toEqual(["NOPE"]);
    expect(await events("secret.disclosed")).toEqual([
      {
        mode: "requested",
        items: `TOKEN@${await versionOf("TOKEN")}+${await versionOf("TOKEN", "retiring_version_id")}`,
        withheld: 1,
        purpose: "scan",
      },
    ]);
  });

  it("is an allowlist: anything else is refused before anything is audited or decrypted", async () => {
    for (const purpose of ["backup", "", "SCAN", 1, null]) {
      for (const request of [{ scope: "all-authorized-secrets" }, { items: ["TOKEN"] }]) {
        const res = await call("POST", `${E}/disclosures`, { ...request, purpose });
        expect(res.status, JSON.stringify(purpose)).toBe(422);
        expect((await res.json()).error.code).toBe("VALIDATION_FAILED");
      }
    }
    await expect(
      client.discloseSecrets("acme", "api", "production", {
        scope: "all-authorized-secrets",
        purpose: "exfiltrate" as "scan",
      }),
    ).rejects.toBeInstanceOf(VarlatchApiError);
    expect(await events("secret.disclosed")).toEqual([]);
    expect(await events("value.disclosed")).toEqual([]);
  });

  it("confers no authority: an identity with secret.use but not secret.reveal cannot scan", async () => {
    const svc = await (await call("POST", "/v1/organizations/acme/identities", { name: "ci", kind: "service" })).json();
    expect(
      (
        await call("POST", "/v1/organizations/acme/grants", {
          subjectIdentityId: svc.id,
          scope: { kind: "project", projectId },
          actions: ["secret.use", "config.metadata.read", "config.value.read"],
        })
      ).status,
    ).toBe(201);
    const res = await call("POST", `${E}/disclosures`, { scope: "all-authorized-secrets", purpose: "scan" }, svc.credential);
    expect([403, 404]).toContain(res.status);
    const text = await res.text();
    expect(text).not.toContain("hunter2-hunter2");
    expect(await events("secret.disclosed")).toEqual([]);
  });
});
