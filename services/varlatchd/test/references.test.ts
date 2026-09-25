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
import { expandReferences, referencedNames } from "../src/domain/references.js";
import { buildApp } from "../src/http/app.js";
import { testDb } from "./helpers/pglite.js";

/**
 * Value references (${NAME}): expanded server-side, only from values the
 * caller is authorized to read through the same operation. Expansion never
 * expands authority; unauthorized or unknown references stay literal.
 */

describe("expandReferences (pure)", () => {
  const table = new Map([
    ["HOST", "db.internal"],
    ["PORT", "5432"],
    ["ADDR", "${HOST}:${PORT}"],
  ]);
  const lookup = (n: string) => table.get(n);

  it("expands simple and chained references", () => {
    expect(expandReferences("postgres://${HOST}:${PORT}/app", lookup)).toBe(
      "postgres://db.internal:5432/app",
    );
    expect(expandReferences("url=${ADDR}", lookup)).toBe("url=db.internal:5432");
  });

  it("leaves unknown references literal", () => {
    expect(expandReferences("x=${NOPE}", lookup)).toBe("x=${NOPE}");
  });

  it("escapes $${NAME} to a literal ${NAME}", () => {
    expect(expandReferences("tpl=$${HOST}", lookup)).toBe("tpl=${HOST}");
  });

  it("terminates on cycles, leaving the cycle literal", () => {
    const cyclic = new Map([
      ["A", "${B}"],
      ["B", "${A}"],
    ]);
    const out = expandReferences("${A}", (n) => cyclic.get(n));
    expect(out).toMatch(/^\$\{[AB]\}$/);
  });

  it("rejects transitive missing references and cycles for delivery", () => {
    expect(() => expandReferences("${A}", n => new Map([["A", "${B}"], ["B", "${MISSING}"]]).get(n), true)).toThrow(/MISSING/);
    expect(() => expandReferences("${A}", () => "${A}", true)).toThrow(/cyclic/);
    expect(expandReferences("${A}", () => "$${MISSING}", true)).toBe("${MISSING}");
  });

  it("bounds amplification before allocating an oversized result", () => {
    const lookup = (name: string): string | undefined => name === "A" ? "${B}".repeat(1000) : "x".repeat(2000);
    expect(() => expandReferences("${A}", lookup, true)).toThrow(/1 MiB/);
  });

  it("collects referenced names, ignoring escapes", () => {
    expect(referencedNames("${A} $${B} ${C_1}")).toEqual(["A", "C_1"]);
  });
});

describe("reference expansion over the API", () => {
  let ctx: AppCtx & { close: () => Promise<void> };
  let app: ReturnType<typeof buildApp>;
  let adminToken: string;

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
    await post("/v1/organizations/acme/projects", {
      name: "API",
      slug: "api",
      contractAuthority: "managed",
    });
    await post("/v1/organizations/acme/projects/api/environments", {
      name: "development",
      tier: "development",
    });
    // Managed contract marking DB_PASSWORD and DATABASE_URL sensitive.
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
          item("DB_HOST", false),
          item("DB_PORT", false),
          item("DB_ADDR", false),
          item("DB_PASSWORD", true),
          item("DATABASE_URL", true),
        ],
      },
    });
    expect(push.status).toBe(201);
    const revision = await push.json();
    const activate = await post(
      `/v1/organizations/acme/projects/api/contract/revisions/${revision.id}/activate`,
      {},
    );
    expect(activate.status).toBe(200);

    await put(`${ENV_PATH}/values/DB_HOST`, { value: "db.internal" });
    await put(`${ENV_PATH}/values/DB_PORT`, { value: "5432" });
    await put(`${ENV_PATH}/values/DB_ADDR`, { value: "${DB_HOST}:${DB_PORT}" });
    await put(`${ENV_PATH}/values/DB_PASSWORD`, { value: "hunter2" });
    await put(`${ENV_PATH}/values/DATABASE_URL`, {
      value: "postgres://app:${DB_PASSWORD}@${DB_ADDR}/app",
    });
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

  it("meta advertises the capability", async () => {
    const meta = await (await app.request("/v1/meta")).json();
    expect(meta.capabilities).toContain("values.references");
  });

  it("effective-configuration expands plain-to-plain chains", async () => {
    const res = await get(`${ENV_PATH}/effective-configuration?include=values`);
    const body = await res.json();
    const byName = Object.fromEntries(
      body.items.map((i: { name: string; value: string | null }) => [i.name, i.value]),
    );
    expect(byName.DB_ADDR).toBe("db.internal:5432");
    // Secrets never leave this endpoint, expanded or not.
    expect(byName.DATABASE_URL).toBeNull();
  });

  it("returns the literal stored text as rawValue when expansion changed the value", async () => {
    const res = await get(`${ENV_PATH}/effective-configuration?include=values`);
    const body = await res.json();
    const byName = Object.fromEntries(
      body.items.map((i: { name: string }) => [i.name, i]),
    ) as Record<string, { value: string | null; rawValue?: string }>;
    expect(byName.DB_ADDR!.rawValue).toBe("${DB_HOST}:${DB_PORT}");
    // Items that needed no expansion carry no rawValue at all.
    expect(byName.DB_HOST!.rawValue).toBeUndefined();
  });

  it("a plain item referencing a Secret stays literal on the metadata path", async () => {
    await put(`${ENV_PATH}/values/DB_ADDR`, { value: "${DB_PASSWORD}@${DB_HOST}" });
    const res = await get(`${ENV_PATH}/effective-configuration?include=values`);
    const body = await res.json();
    const addr = body.items.find((i: { name: string }) => i.name === "DB_ADDR");
    expect(addr.value).toBe("${DB_PASSWORD}@db.internal");
    expect(JSON.stringify(body)).not.toContain("hunter2");
  });

  it("disclosure expands secret-to-secret and secret-to-plain closures", async () => {
    const res = await post(`${ENV_PATH}/disclosures`, { scope: "all-authorized-secrets" });
    expect(res.status).toBe(200);
    const body = await res.json();
    const url = body.items.find((i: { name: string }) => i.name === "DATABASE_URL");
    expect(url.value).toBe("postgres://app:hunter2@db.internal:5432/app");
  });

  it("audits the plain values pulled in by expansion, one reference level at a time", async () => {
    await post(`${ENV_PATH}/disclosures`, { scope: "all-authorized-secrets" });
    const res = await ctx.db.query(
      "SELECT metadata FROM audit_events WHERE event_type = 'value.disclosed' AND metadata::jsonb->>'mode' = 'reference-expansion' ORDER BY event_order",
    );
    // Each level is known only once the previous one is decrypted, so each
    // is audited, and the audit committed, before it is decrypted.
    const levels = (res.rows as { metadata: string | Record<string, unknown> }[]).map((r) =>
      String((typeof r.metadata === "string" ? JSON.parse(r.metadata) : r.metadata).items)
        .split(",")
        .map((i) => i.split("@")[0])
        .sort(),
    );
    expect(levels).toEqual([["DB_ADDR"], ["DB_HOST", "DB_PORT"]]);
  });

  it("requested-items disclosure does not expand references to unrequested Secrets", async () => {
    await put(`${ENV_PATH}/values/DATABASE_URL`, { value: "pw=${DB_PASSWORD}" });
    const res = await post(`${ENV_PATH}/disclosures`, { items: ["DATABASE_URL"] });
    const body = await res.json();
    expect(body.items[0].value).toBe("pw=${DB_PASSWORD}");
  });
});
