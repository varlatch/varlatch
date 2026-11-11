// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, describe, expect, it } from "vitest";
import type { Querier } from "../src/db/migrate.js";
import { MIGRATIONS } from "../src/db/migrations/index.js";
import { checkOutbound } from "../src/doctor.js";
import { outboundCheck, outboundCheckLines } from "../src/net/outbound-check.js";
import { OutboundPolicy, type Resolver } from "../src/net/outbound.js";
import { migratedTestDb, testDb } from "./helpers/pglite.js";

/**
 * `varlatchd admin outbound check` and doctor's outbound check (ADR-0057
 * Decisions 8 and 10): the verdict on every configured destination, the
 * suggested allow list, the exit code, and a database at an older schema.
 */

const ANSWERS: Record<string, string[]> = {
  "sink.example": ["93.184.215.14"],
  "private.lan": ["10.0.0.4"],
  "hooks.lan": ["127.0.0.1"],
  "coolify.private": ["10.0.0.5"],
  "convex.lan": ["10.0.0.6"],
  "ci.example": ["93.184.215.14"],
  "issuer.ts": ["100.101.102.103"],
};
const resolve: Resolver = async (name) => {
  const list = ANSWERS[name];
  if (!list) throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${name}`), { code: "ENOTFOUND" });
  return list.map((address) => ({ address, family: 4 as const }));
};
const policy = (spec: string) => new OutboundPolicy(spec, { resolve, log: () => {} });

let close: (() => Promise<void>) | null = null;
afterEach(async () => {
  await close?.();
  close = null;
});

/** The rows, with only the columns migrations 0001, 0002, 0010, 0011 and 0016 created. */
async function seed(db: Querier): Promise<void> {
  await db.query("INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_a', 'acme', 'Acme', '{}'), ('org_b', 'beta', 'Beta', '{}')");
  await db.query("INSERT INTO identities (id, kind, name, organization_id) VALUES ('idn_ci', 'ci', 'ci', 'org_a')");
  const hook = (id: string, org: string, url: string, revoked = false) =>
    db.query(
      `INSERT INTO webhooks (id, organization_id, url, secret_envelope, cursor_occurred_at, revoked_at) VALUES ($1, $2, $3, '{}', now(), ${revoked ? "now()" : "NULL"})`,
      [id, org, url],
    );
  await hook("wh_public", "org_a", "https://sink.example/hook?token=secret");
  await hook("wh_private", "org_a", "https://private.lan/hook");
  await hook("wh_loopback", "org_a", "https://hooks.lan/hook");
  await hook("wh_http", "org_b", "http://sink.example/hook");
  await hook("wh_literal", "org_b", "https://10.0.0.9/hook");
  await hook("wh_gone", "org_b", "https://gone.example/hook");
  await hook("wh_revoked", "org_b", "https://private.lan/old", true);
  const connection = (id: string, platform: string, base: string) =>
    db.query("INSERT INTO platform_connections (id, organization_id, platform, base_identity, name, credential_envelope) VALUES ($1, 'org_a', $2, $3, $4, '{}')", [id, platform, base, `${platform} ${id}`]);
  await connection("pc_coolify", "coolify", "https://coolify.private:8443");
  await connection("pc_convex", "convex", "https://convex.lan:3210");
  await connection("pc_github", "github-actions", "acme");
  await db.query("INSERT INTO oidc_bindings (id, identity_id, organization_id, issuer, audience, subject) VALUES ('ob_1', 'idn_ci', 'org_a', 'https://ci.example', 'a', 's'), ('ob_2', 'idn_ci', 'org_a', 'https://issuer.ts', 'a', 's')");
}

describe("admin outbound check", () => {
  it("gives each destination a verdict, suggests the allow list, and exits 1 when something is refused", async () => {
    const db = await migratedTestDb();
    close = db.close;
    await seed(db);
    const report = await outboundCheck(db, policy(""));
    const verdicts = Object.fromEntries(report.destinations.map((d) => [d.id, d.verdict === "refused" ? d.reason : d.verdict]));
    expect(verdicts).toEqual({
      wh_public: "public",
      wh_private: "private_address",
      wh_loopback: "host_only_address",
      wh_http: "scheme",
      wh_literal: "private_address",
      wh_gone: "unresolved",
      pc_coolify: "private_address",
      pc_convex: "private_address",
      ob_1: "public",
      ob_2: "private_address",
    });
    expect(report.destinations.find((d) => d.id === "pc_coolify")).toMatchObject({ organization: "acme", kind: "coolify", name: "coolify pc_coolify", host: "coolify.private", port: 8443, addresses: ["10.0.0.5"] });
    // Names as hostname entries, with the port when it is not the default; literal and host-only cases apart.
    expect(report.suggested).toBe("private.lan,sink.example,coolify.private:8443,convex.lan:3210,issuer.ts");
    expect(report.apart.map((a) => [a.host, a.port])).toEqual([["hooks.lan", 443], ["10.0.0.9", 443]]);
    expect(report.apart[1]?.why).toMatch(/10\.0\.0\.9\/32/);
    expect(report.exitCode).toBe(1);
    // A webhook URL is reduced to its host and port.
    expect(JSON.stringify(report)).not.toMatch(/token|secret|\/hook/);
    const lines = outboundCheckLines(report).join("\n");
    expect(lines).toContain("VARLATCH_OUTBOUND_ALLOW=private.lan,sink.example,coolify.private:8443,convex.lan:3210,issuer.ts");
    expect(lines).toContain("REFUSED (private_address)");
    expect(lines).toContain("Not suggested");
  });

  it("tests a candidate value: --allow changes the verdicts and the exit code", async () => {
    const db = await migratedTestDb();
    close = db.close;
    await seed(db);
    const suggested = (await outboundCheck(db, policy(""))).suggested as string;
    const withSuggested = await outboundCheck(db, policy(suggested));
    expect(withSuggested.destinations.filter((d) => d.verdict === "refused").map((d) => d.id)).toEqual(["wh_loopback", "wh_literal"]);
    expect(withSuggested.destinations.find((d) => d.id === "pc_convex")).toMatchObject({ verdict: "allowed", entries: ["convex.lan:3210"] });
    const everything = await outboundCheck(db, policy(`${suggested},127.0.0.1/32,10.0.0.9/32`));
    expect(everything.destinations.filter((d) => d.verdict === "refused")).toEqual([]);
    expect(everything.suggested).toBeNull();
    expect(everything.exitCode).toBe(2); // gone.example did not resolve
    const one = await outboundCheck(db, policy(""), { org: "beta" });
    expect(new Set(one.destinations.map((d) => d.organization))).toEqual(new Set(["beta"]));
  });

  it("runs against a database at an older schema: only the tables of migrations 0010, 0011 and 0016", async () => {
    const db = await testDb();
    close = db.close;
    for (const migration of MIGRATIONS.filter((m) => m.id <= 16)) {
      if (db.exec) await db.exec(migration.sql);
      else await db.query(migration.sql);
    }
    await seed(db);
    const report = await outboundCheck(db, policy(""));
    expect(report.destinations).toHaveLength(10);
    expect(report.exitCode).toBe(1);
  });
});

describe("doctor's outbound check", () => {
  it("reports refused destinations and the remedy, and warns about the allow list", async () => {
    const db = await migratedTestDb();
    close = db.close;
    await seed(db);
    const failing = await checkOutbound({ ctx: null, db, stateDir: "/nonexistent", publicUrl: undefined, convexUrl: undefined, outboundPolicy: policy("0.0.0.0/0,127.0.0.1/32:*") });
    expect(failing).toMatchObject({ id: "outbound.policy", class: "advisory", status: "fail" });
    expect(failing.detail).toMatch(/VARLATCH_OUTBOUND_ALLOW: 0\.0\.0\.0\/0,127\.0\.0\.1\/32:\*/);
    expect(failing.detail).toMatch(/configured destinations are refused/);
    expect(failing.detail).toMatch(/adds only the private ranges/);
    expect(failing.detail).toMatch(/opens a host-only range/);
    expect(failing.remedy).toMatch(/Set VARLATCH_OUTBOUND_ALLOW=/);
    await db.query("UPDATE webhooks SET revoked_at = now() WHERE id <> 'wh_public'");
    await db.query("UPDATE platform_connections SET revoked_at = now()");
    await db.query("UPDATE oidc_bindings SET revoked_at = now()");
    const passing = await checkOutbound({ ctx: null, db, stateDir: "/nonexistent", publicUrl: undefined, convexUrl: undefined, outboundPolicy: policy("") });
    expect(passing).toMatchObject({ status: "pass" });
    expect(passing.detail).toMatch(/not set; 1 configured destinations allowed/);
  });

  it("is unknown when the destinations cannot be read", async () => {
    const check = await checkOutbound({ ctx: null, db: { query: async () => { throw new Error("down"); } }, stateDir: "/x", publicUrl: undefined, convexUrl: undefined });
    expect(check.status).toBe("unknown");
  });
});
