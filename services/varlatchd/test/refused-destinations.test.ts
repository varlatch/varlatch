// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { LOOKUP_SLOTS, SCAN_TTL_MS, sharedOutboundCheck } from "../src/net/outbound-check.js";
import { OutboundPolicy, OutboundRefusedError, type Resolver } from "../src/net/outbound.js";
import { PUBLIC_URL } from "./helpers/device-sign-in.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * Refused outbound destinations in the API (ADR-0057 Decision 8):
 *
 * - GET /v1/organizations/{org}/security/refused-destinations: the
 *   Organization's own refused destinations with since when, for its
 *   admins only (organization.manage), hidden from outsiders, an
 *   Installation Admin included;
 * - GET /v1/installation/outbound: the allow list as parsed with doctor's
 *   warnings, every refused destination by Organization and the suggested
 *   line, for Installation Admins only.
 *
 * Neither ever holds a resolved address, a URL path or query, or a
 * credential.
 */

const ANSWERS: Record<string, string[]> = {
  "sink.example": ["93.184.215.14"],
  "hooks.lan": ["10.0.0.4"],
  "coolify.private": ["10.0.0.5"],
  "metadata.lan": ["169.254.169.254"],
  "other.lan": ["10.9.9.9"],
};
/** Every lookup made, and a gate tests can hold shut to make requests overlap. */
let lookups: string[] = [];
let gate: Promise<void> | null = null;
let running = 0;
let peak = 0;
const resolve: Resolver = async (name) => {
  lookups.push(name);
  peak = Math.max(peak, ++running);
  try {
    if (gate) await gate;
  } finally {
    running--;
  }
  const list = ANSWERS[name];
  if (!list) throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${name}`), { code: "ENOTFOUND" });
  return list.map((address) => ({ address, family: 4 as const }));
};

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let acme: string;
let admin: { id: string; cli: string };

type Answer = { status: number; body: any; text: string; headers: Headers };

async function call(path: string, token: string): Promise<Answer> {
  const res = await app.request(path, { headers: { Authorization: `Bearer ${token}` } });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null, text, headers: res.headers };
}

async function invite(name: string, role: "admin" | "member") {
  const grant = await issueInviteGrant(ctx, { organizationId: acme, role, name }, admin.id);
  const { identityId } = await consumeSetupGrant(ctx, grant.token, {});
  return { id: identityId, cli: (await issueCredential(ctx.db, { identityId, kind: "cli" })).token };
}

async function webhook(id: string, organizationId: string, url: string, revoked = false) {
  await ctx.db.query(
    `INSERT INTO webhooks (id, organization_id, url, secret_envelope, cursor_occurred_at, revoked_at)
     VALUES ($1, $2, $3, '{}', now(), ${revoked ? "now()" : "NULL"})`,
    [id, organizationId, url],
  );
}

async function connection(id: string, organizationId: string, platform: string, base: string, name: string) {
  await ctx.db.query(
    "INSERT INTO platform_connections (id, organization_id, platform, base_identity, name, credential_envelope) VALUES ($1, $2, $3, $4, $5, '{}')",
    [id, organizationId, platform, base, name],
  );
}

/** A refusal as delivery records it: the real audit path, within its rate bound. */
async function refused(
  organizationId: string,
  resource: Record<string, string>,
  host: string,
  port: number,
  addresses: string[],
  reason: "private_address" | "mixed_answers" = "private_address",
) {
  await ctx.outbound!.recordRefusal(ctx.db, {
    organizationId,
    purpose: resource.webhookId ? "webhook" : "sync_delivery",
    phase: "connection",
    refusal: new OutboundRefusedError(reason, { scheme: "https:", host, port }, addresses),
    resource,
  });
}

function boot(allow: string) {
  ctx.outbound = new OutboundPolicy(allow, { resolve, log: () => {} });
  app = buildApp(ctx, { publicUrl: PUBLIC_URL, clientAddress: () => "203.0.113.7" });
}

beforeEach(async () => {
  lookups = [];
  gate = null;
  peak = 0;
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const { identityId } = await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" });
  boot("");
  admin = { id: identityId, cli: (await issueCredential(ctx.db, { identityId, kind: "cli" })).token };
  acme = (await (await app.request("/v1/organizations", {
    method: "POST",
    headers: { Authorization: `Bearer ${admin.cli}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Acme", slug: "acme" }),
  })).json() as { id: string }).id;
  // An Organization the installation's admin is not a member of.
  await ctx.db.query("INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_beta', 'beta', 'Beta', '{}')");

  await webhook("wh_public", acme, "https://sink.example/hook");
  await webhook("wh_private", acme, "https://hooks.lan/deliver/here?token=s3cret");
  await webhook("wh_revoked", acme, "https://hooks.lan/old", true);
  await webhook("wh_http", acme, "http://sink.example/plain");
  await connection("pc_coolify", acme, "coolify", "https://coolify.private:8443", "Production Coolify");
  await connection("pc_github", acme, "github-actions", "acme", "GitHub");
  await webhook("wh_beta", "org_beta", "https://other.lan/beta-path");
  await webhook("wh_meta", "org_beta", "https://metadata.lan/latest");
  await connection("pc_beta", "org_beta", "convex", "https://other.lan:3210", "Beta Convex");
});
afterEach(async () => {
  await ctx.outbound?.close();
  await ctx.close();
});

describe("an Organization's refused destinations", () => {
  const PATH = "/v1/organizations/acme/security/refused-destinations";

  it("is advertised as a capability, with the installation's", async () => {
    const caps = (await call("/v1/meta", admin.cli)).body.capabilities as string[];
    expect(caps).toContain("security.refused-destinations");
    expect(caps).toContain("installation.outbound");
  });

  it("lists the admin's own refused destinations with kind, name, host, reason and since when", async () => {
    await refused(acme, { webhookId: "wh_private" }, "hooks.lan", 443, ["10.0.0.4"]);
    // A refusal for another host (the URL before an edit) does not date this one.
    await refused(acme, { webhookId: "wh_private" }, "earlier.lan", 443, ["10.0.0.8"], "mixed_answers");
    const first = (
      await ctx.db.query("SELECT min(occurred_at) AS at FROM audit_events WHERE event_type = 'outbound.refused' AND metadata->>'host' = 'hooks.lan'")
    ).rows[0] as { at: Date | string };
    const res = await call(PATH, admin.cli);
    expect(res.status, res.text).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.body.sinceDays).toBe(30);
    expect(res.body).toMatchObject({ checked: 4, unresolved: 0 });
    expect(res.body.items).toEqual([
      {
        kind: "webhook",
        id: "wh_private",
        name: null,
        scheme: "https",
        host: "hooks.lan",
        port: 443,
        reason: "private_address",
        since: new Date(first.at).toISOString(),
      },
      { kind: "webhook", id: "wh_http", name: null, scheme: "http", host: "sink.example", port: 80, reason: "scheme", since: null },
      {
        kind: "coolify",
        id: "pc_coolify",
        name: "Production Coolify",
        scheme: "https",
        host: "coolify.private",
        port: 8443,
        reason: "private_address",
        since: null,
      },
    ]);
  });

  it("follows the host's allow list", async () => {
    boot("hooks.lan,coolify.private:8443");
    const res = await call(PATH, admin.cli);
    expect(res.body.items.map((d: { id: string }) => d.id)).toEqual(["wh_http"]);
  });

  it("never holds a resolved address, a path, a query, a credential or the allow list", async () => {
    boot("sink.example:9999");
    await refused(acme, { webhookId: "wh_private" }, "hooks.lan", 443, ["10.0.0.4"]);
    const res = await call(PATH, admin.cli);
    expect(res.status).toBe(200);
    for (const leak of ["10.0.0.4", "10.0.0.5", "/deliver", "token", "s3cret", "/plain", "9999", "allow"]) expect(res.text).not.toContain(leak);
  });

  it("needs organization.manage: a member is refused, an admin of the Organization reads it", async () => {
    const bob = await invite("Bob", "member");
    const zoe = await invite("Zoe", "admin");
    const member = await call(PATH, bob.cli);
    expect([403, 404]).toContain(member.status);
    expect(member.text).not.toContain("hooks.lan");
    const other = await call(PATH, zoe.cli);
    expect(other.status).toBe(200);
    expect(other.body.items).toHaveLength(3);
  });

  it("never shows another Organization's destinations, to its admins or to an Installation Admin", async () => {
    const zoe = await invite("Zoe", "admin");
    for (const token of [zoe.cli, admin.cli]) {
      const res = await call("/v1/organizations/beta/security/refused-destinations", token);
      expect(res.status).toBe(404);
      expect(res.text).not.toContain("other.lan");
    }
    // Acme's own list holds nothing of Beta's.
    const own = await call(PATH, admin.cli);
    expect(own.text).not.toMatch(/other\.lan|metadata\.lan|wh_beta|pc_beta/);
  });
});

describe("the installation's outbound policy", () => {
  const PATH = "/v1/installation/outbound";

  it("shows the allow list as parsed, its warnings, every refused destination by Organization and the suggested line", async () => {
    boot("sink.example:9999, 127.0.0.1/32");
    const res = await call(PATH, admin.cli);
    expect(res.status, res.text).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.body.allow).toEqual(["sink.example:9999", "127.0.0.1/32"]);
    expect(res.body.warnings).toEqual([expect.stringContaining("127.0.0.1/32 opens a host-only range")]);
    const rows = res.body.refused.map((d: any) => [d.organization.slug, d.organization.name, d.kind, d.id, d.name, d.host, d.port, d.reason, d.notSuggested]);
    expect(rows).toEqual([
      ["acme", "Acme", "webhook", "wh_private", null, "hooks.lan", 443, "private_address", null],
      ["acme", "Acme", "webhook", "wh_http", null, "sink.example", 80, "port", null],
      ["acme", "Acme", "coolify", "pc_coolify", "Production Coolify", "coolify.private", 8443, "private_address", null],
      ["beta", "Beta", "webhook", "wh_beta", null, "other.lan", 443, "private_address", null],
      ["beta", "Beta", "webhook", "wh_meta", null, "metadata.lan", 443, "host_only_address", expect.stringContaining("hostname entry never opens")],
      ["beta", "Beta", "convex", "pc_beta", "Beta Convex", "other.lan", 3210, "private_address", null],
    ]);
    expect(res.body.suggested).toBe("sink.example:9999,127.0.0.1/32,hooks.lan,sink.example,other.lan,coolify.private:8443,other.lan:3210");
    expect(res.body.unresolved).toBe(0);
  });

  it("never holds a resolved address, a path, a query or a credential", async () => {
    const res = await call(PATH, admin.cli);
    expect(res.status).toBe(200);
    for (const leak of ["10.0.0.4", "10.0.0.5", "10.9.9.9", "169.254", "/deliver", "token", "s3cret", "/plain", "/beta-path", "/latest"]) {
      expect(res.text).not.toContain(leak);
    }
  });

  it("is for Installation Admins only: an Organization's admin is refused", async () => {
    const zoe = await invite("Zoe", "admin");
    const res = await call(PATH, zoe.cli);
    expect(res.status).toBe(403);
    expect(res.text).not.toContain("hooks.lan");
  });
});

describe("destinations that could not be checked", () => {
  it("are counted, so no refusal is not read as every destination allowed", async () => {
    await ctx.db.query("UPDATE webhooks SET url = 'https://gone.example/hook' WHERE organization_id = $1", [acme]);
    await ctx.db.query("UPDATE platform_connections SET base_identity = 'https://gone.example' WHERE id = 'pc_coolify'");
    const res = await call("/v1/organizations/acme/security/refused-destinations", admin.cli);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ items: [], checked: 4, unresolved: 4 });
    const inst = await call("/v1/installation/outbound", admin.cli);
    expect(inst.body).toMatchObject({ checked: 7, unresolved: 4 });
  });

  it("counts none when the Organization configured nothing", async () => {
    await ctx.db.query("UPDATE webhooks SET revoked_at = now() WHERE organization_id = $1", [acme]);
    await ctx.db.query("UPDATE platform_connections SET revoked_at = now() WHERE organization_id = $1", [acme]);
    const res = await call("/v1/organizations/acme/security/refused-destinations", admin.cli);
    expect(res.body).toMatchObject({ items: [], checked: 0, unresolved: 0 });
  });
});

describe("the DNS work behind the pages", () => {
  const settle = () => new Promise((r) => setTimeout(r, 100));

  it("resolves each name once per scan, however many destinations use it", async () => {
    const res = await call("/v1/installation/outbound", admin.cli);
    expect(res.status).toBe(200);
    // sink.example (two webhooks) and other.lan (a webhook and a Connection) once each.
    expect([...lookups].sort()).toEqual(["coolify.private", "hooks.lan", "metadata.lan", "other.lan", "sink.example"]);
  });

  it("shares one scan between overlapping requests, and its lookups with an overlapping scan of an Organization", async () => {
    let open!: () => void;
    gate = new Promise<void>((r) => (open = r));
    const pending = [
      call("/v1/installation/outbound", admin.cli),
      call("/v1/installation/outbound", admin.cli),
      call("/v1/organizations/acme/security/refused-destinations", admin.cli),
      call("/v1/organizations/acme/security/refused-destinations", admin.cli),
    ];
    await settle();
    open();
    const answers = await Promise.all(pending);
    for (const a of answers) expect(a.status).toBe(200);
    expect(answers[0]!.body).toEqual(answers[1]!.body);
    expect(answers[2]!.body.items).toEqual(answers[3]!.body.items);
    expect([...lookups].sort()).toEqual(["coolify.private", "hooks.lan", "metadata.lan", "other.lan", "sink.example"]);
  });

  it("reuses a finished scan for a short while; a restart's new policy checks again", async () => {
    await call("/v1/installation/outbound", admin.cli);
    const first = lookups.length;
    const again = await call("/v1/installation/outbound", admin.cli);
    expect(again.status).toBe(200);
    expect(lookups).toHaveLength(first);
    boot("");
    await call("/v1/installation/outbound", admin.cli);
    expect(lookups).toHaveLength(2 * first);
  });

  it("checks again once the reuse window is over, and keeps no failed scan", async () => {
    let clock = 1_000_000;
    const policy = ctx.outbound!;
    await sharedOutboundCheck(ctx.db, policy, {}, () => clock);
    clock += SCAN_TTL_MS - 1;
    await sharedOutboundCheck(ctx.db, policy, {}, () => clock);
    expect(lookups).toHaveLength(5);
    clock += 2;
    await sharedOutboundCheck(ctx.db, policy, {}, () => clock);
    expect(lookups).toHaveLength(10);
    const broken = { query: async () => Promise.reject(new Error("database gone")) };
    const other = new OutboundPolicy("", { resolve, log: () => {} });
    await expect(sharedOutboundCheck(broken, other, {}, () => clock)).rejects.toThrow("database gone");
    await expect(sharedOutboundCheck(ctx.db, other, {}, () => clock)).resolves.toMatchObject({ checkedAt: expect.any(String) });
  });

  it("never runs more than a fixed number of lookups at once in the process", async () => {
    for (let i = 0; i < 20; i++) {
      ANSWERS[`host${i}.example`] = ["93.184.215.14"];
      await webhook(`wh_many_${i}`, "org_beta", `https://host${i}.example/x`);
    }
    let open!: () => void;
    gate = new Promise<void>((r) => (open = r));
    const pending = Promise.all([
      call("/v1/installation/outbound", admin.cli),
      call("/v1/organizations/acme/security/refused-destinations", admin.cli),
    ]);
    await settle();
    expect(lookups).toHaveLength(LOOKUP_SLOTS);
    open();
    const [inst] = await pending;
    expect(inst!.body.checked).toBe(27);
    expect(new Set(lookups).size).toBe(25);
    // Never more at once, also after the gate opened and the queue drained.
    expect(peak).toBe(LOOKUP_SLOTS);
  });
});
