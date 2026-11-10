// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * Credential review (ADR-0054 Decision 8): per Organization, the machine
 * credentials never used, unused for 30 days, or without expiry. Reporting
 * only. Revoked, expired and used-up credentials are not a risk and are left
 * out, as are people's credentials and the short-lived OIDC and agent-run
 * kinds.
 */

const REVIEW = (org = "acme") => `/v1/organizations/${org}/security/credential-review`;

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let admin: { id: string; token: string };
let acmeId: string;

async function call(method: string, path: string, body?: unknown, token = admin.token) {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null, headers: res.headers };
}

/** A machine identity with its first credential; ttl gives the credential an expiry. */
async function machine(name: string, opts: { org?: string; kind?: string; ttlSeconds?: number; maxUses?: number } = {}) {
  const res = await call("POST", `/v1/organizations/${opts.org ?? "acme"}/identities`, {
    name,
    kind: opts.kind ?? "service",
    ...(opts.ttlSeconds ? { credentialTtlSeconds: opts.ttlSeconds } : {}),
    ...(opts.maxUses ? { credentialMaxUses: opts.maxUses } : {}),
  });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  // ci and agent identities get no credential at creation.
  const first = (await ctx.db.query("SELECT id FROM credentials WHERE identity_id = $1", [res.body.id])).rows[0] as
    | { id: string }
    | undefined;
  return { id: res.body.id as string, token: res.body.credential as string, credentialId: first?.id ?? "" };
}

async function lastUsedDaysAgo(credentialId: string, days: number) {
  await ctx.db.query("UPDATE credentials SET last_used_at = now() - $2::int * interval '1 day' WHERE id = $1", [credentialId, days]);
}

type Item = {
  id: string;
  name: string | null;
  identity: { id: string; name: string; kind: string; state: string; disabledReason: string | null };
  reasons: string[];
  lastUsedAt: string | null;
  expiresAt: string | null;
  issuedBy: { id: string; name: string } | null;
};

async function review(org = "acme", token = admin.token) {
  const res = await call("GET", REVIEW(org), undefined, token);
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  return res.body as { generatedAt: string; idleDays: number; summary: Record<string, number>; items: Item[] };
}

const reasonsOf = (items: Item[], credentialId: string) => items.find((i) => i.id === credentialId)?.reasons ?? null;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const setup = await issueBootstrapGrant(ctx);
  const { identityId } = await consumeSetupGrant(ctx, setup.token, { adminName: "Admin" });
  admin = { id: identityId, token: (await issueCredential(ctx.db, { identityId, kind: "cli" })).token };
  app = buildApp(ctx);
  acmeId = (await call("POST", "/v1/organizations", { name: "Acme", slug: "acme" })).body.id;
  expect((await call("POST", "/v1/organizations", { name: "Other", slug: "other" })).status).toBe(201);
});
afterEach(async () => {
  await ctx.close();
});

describe("credential review", () => {
  it("is advertised as a capability", async () => {
    expect((await call("GET", "/v1/meta")).body.capabilities).toContain("security.credential-review");
  });

  it("lists machine credentials never used, idle for 30 days, or without expiry, with their reasons", async () => {
    const never = await machine("never-used"); // no expiry, never used
    const idle = await machine("idle", { ttlSeconds: 365 * 86400 });
    await lastUsedDaysAgo(idle.credentialId, 40);
    const recent = await machine("recent", { ttlSeconds: 365 * 86400 });
    await lastUsedDaysAgo(recent.credentialId, 1);
    const forever = await machine("forever");
    await lastUsedDaysAgo(forever.credentialId, 1);
    const idleForever = await machine("idle-forever");
    await lastUsedDaysAgo(idleForever.credentialId, 40);
    const fresh = await machine("fresh", { ttlSeconds: 86400 }); // with expiry, never used

    const r = await review();
    expect(r.idleDays).toBe(30);
    expect(reasonsOf(r.items, never.credentialId)).toEqual(["never-used", "no-expiry"]);
    expect(reasonsOf(r.items, idle.credentialId)).toEqual(["idle"]);
    expect(reasonsOf(r.items, recent.credentialId)).toBeNull();
    expect(reasonsOf(r.items, forever.credentialId)).toEqual(["no-expiry"]);
    expect(reasonsOf(r.items, idleForever.credentialId)).toEqual(["idle", "no-expiry"]);
    expect(reasonsOf(r.items, fresh.credentialId)).toEqual(["never-used"]);
    expect(r.summary).toEqual({ reviewed: 6, listed: 5, neverUsed: 2, idle: 2, noExpiry: 3 });

    // Ordered by identity name; identity, issuer and use are named.
    expect(r.items.map((i) => i.identity.name)).toEqual(["forever", "fresh", "idle", "idle-forever", "never-used"]);
    const first = r.items.find((i) => i.id === idle.credentialId)!;
    expect(first.identity).toEqual({ id: idle.id, name: "idle", kind: "service", state: "live", disabledReason: null });
    expect(first.issuedBy).toEqual({ id: admin.id, name: "Admin" });
    expect(first.expiresAt).not.toBeNull();
    expect(Date.now() - Date.parse(first.lastUsedAt!)).toBeGreaterThan(39 * 86400_000);
    expect(r.items.find((i) => i.id === never.credentialId)!.lastUsedAt).toBeNull();

    // Metadata only: never a token or a hash.
    const raw = JSON.stringify(r);
    expect(raw).not.toContain(never.token);
    expect(raw).not.toContain("vlt_");
    expect(raw).not.toMatch(/hash/i);
    expect(Object.keys(first).sort()).toEqual(
      ["createdAt", "expiresAt", "id", "identity", "issuedBy", "kind", "lastUsedAt", "name", "reasons"],
    );
  });

  it("counts a credential as used once it authenticates", async () => {
    const svc = await machine("worker", { ttlSeconds: 365 * 86400 });
    expect(reasonsOf((await review()).items, svc.credentialId)).toEqual(["never-used"]);
    await call("GET", "/v1/organizations/acme/identities", undefined, svc.token);
    expect(reasonsOf((await review()).items, svc.credentialId)).toBeNull();
  });

  it("leaves out revoked, expired and used-up credentials", async () => {
    const revoked = await machine("revoked");
    expect((await call("DELETE", `/v1/organizations/acme/identities/${revoked.id}/credentials/${revoked.credentialId}`)).status).toBe(204);
    const expired = await machine("expired", { ttlSeconds: 3600 });
    await ctx.db.query("UPDATE credentials SET expires_at = now() - interval '1 day' WHERE id = $1", [expired.credentialId]);
    const usedUp = await machine("used-up", { maxUses: 1 });
    await call("GET", "/v1/organizations/acme/identities", undefined, usedUp.token);
    expect((await ctx.db.query("SELECT use_count FROM credentials WHERE id = $1", [usedUp.credentialId])).rows[0]).toEqual({ use_count: 1 });
    // A budget not yet spent still counts.
    const budget = await machine("budget", { maxUses: 5 });

    const r = await review();
    expect(r.items.map((i) => i.id)).toEqual([budget.credentialId]);
    expect(r.summary.reviewed).toBe(1);
  });

  it("leaves out people's credentials and the short-lived OIDC and agent-run kinds", async () => {
    // A person's unused CLI credential without expiry.
    await issueCredential(ctx.db, { identityId: admin.id, kind: "cli", name: "spare" });
    const agent = await machine("agent", { kind: "agent" });
    const inAnHour = new Date(Date.now() + 3600_000).toISOString();
    await issueCredential(ctx.db, { identityId: agent.id, kind: "agent-run", name: "run", expiresAt: inAnHour });
    const ci = await machine("ci", { kind: "ci" });
    await issueCredential(ctx.db, { identityId: ci.id, kind: "oidc", name: "exchange", expiresAt: inAnHour });

    // Both would otherwise be listed as never used.
    const service = await machine("service");

    const r = await review();
    expect(r.items.map((i) => i.identity.name)).toEqual(["service"]);
    expect(r.items.map((i) => i.id)).toEqual([service.credentialId]);
    expect(r.summary.reviewed).toBe(1);
  });

  it("shows only the Organization's own machines", async () => {
    const mine = await machine("mine");
    const theirs = await machine("theirs", { org: "other" });
    expect((await review("acme")).items.map((i) => i.id)).toEqual([mine.credentialId]);
    expect((await review("other")).items.map((i) => i.id)).toEqual([theirs.credentialId]);
  });

  it("names the identity's state: a retired machine's credentials are revoked, a suspended one's are listed", async () => {
    const retired = await machine("retired");
    expect((await call("POST", `/v1/organizations/acme/identities/${retired.id}/retire`)).status).toBe(200);
    // Disabled outside retirement with a credential left unrevoked: it would work again on reactivation.
    const legacy = await machine("legacy");
    await ctx.db.query("UPDATE identities SET disabled = true WHERE id = $1", [legacy.id]);
    let r = await review();
    expect(r.items.map((i) => i.id)).toEqual([legacy.credentialId]);
    expect(r.items[0]!.identity).toMatchObject({ state: "retired", disabledReason: null });

    // A deletion request suspends machines and keeps their credentials.
    const doomed = await machine("doomed", { org: "other" });
    expect((await call("POST", "/v1/organizations/other/deletion", {})).status).toBe(201);
    r = await review("other");
    expect(r.items.map((i) => i.id)).toEqual([doomed.credentialId]);
    expect(r.items[0]!.identity).toMatchObject({ state: "disabled", disabledReason: "organization-deletion" });
  });

  it("is empty with nothing to review", async () => {
    const r = await review();
    expect(r.items).toEqual([]);
    expect(r.summary).toEqual({ reviewed: 0, listed: 0, neverUsed: 0, idle: 0, noExpiry: 0 });
  });

  it("needs identity.manage, like listing an identity's credentials; existence-hiding outside the Organization", async () => {
    const svc = await machine("reader");
    // A machine without the action, then with identity.read only: refused.
    expect((await call("GET", REVIEW(), undefined, svc.token)).status).toBe(403);
    const grant = async (actions: string[]) =>
      expect(
        (await call("POST", "/v1/organizations/acme/grants", { subjectIdentityId: svc.id, scope: { kind: "organization" }, actions })).status,
      ).toBe(201);
    await grant(["identity.read"]);
    expect((await call("GET", REVIEW(), undefined, svc.token)).status).toBe(403);
    await grant(["identity.manage"]);
    expect((await call("GET", REVIEW(), undefined, svc.token)).status).toBe(200);
    // Another Organization's review does not exist for it.
    expect((await call("GET", REVIEW("other"), undefined, svc.token)).status).toBe(404);

    // A member (fixed bundle: no identity actions) is refused.
    const invite = await issueInviteGrant(ctx, { organizationId: acmeId, role: "member", name: "Bob" }, admin.id);
    const { identityId } = await consumeSetupGrant(ctx, invite.token, {});
    const bob = (await issueCredential(ctx.db, { identityId, kind: "cli" })).token;
    expect((await call("GET", REVIEW(), undefined, bob)).status).toBe(403);
  });

  it("is not cached", async () => {
    expect((await call("GET", REVIEW())).headers.get("cache-control")).toBe("no-store");
  });
});
