// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * The approval keys of an Organization's admins (ADR-0054 Decisions 4 and
 * 11): per live admin, trusted and unconfirmed passkeys by name, never key
 * material. It needs organization.manage, like the control report, and hides
 * the Organization from outsiders.
 */

const ORG = "/v1/organizations/acme";
const KEYS = `${ORG}/security/approval-keys`;

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let orgId: string;
let admin: { id: string; cli: string };

type Answer = { status: number; body: any; headers: Headers };

async function call(method: string, path: string, token: string, body?: unknown): Promise<Answer> {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null, headers: res.headers };
}

async function invite(name: string, role: "admin" | "member", organizationId = orgId) {
  const grant = await issueInviteGrant(ctx, { organizationId, role, name }, admin.id);
  const { identityId } = await consumeSetupGrant(ctx, grant.token, {});
  return { id: identityId, cli: (await issueCredential(ctx.db, { identityId, kind: "cli" })).token };
}

const key = (identityId: string, trust?: "trusted" | "unconfirmed") => registerSoftPasskey(ctx.db, identityId, { ...RP, ...(trust ? { trust } : {}) });

async function rename(k: SoftAuthenticator, name: string) {
  await ctx.db.query("UPDATE passkey SET name = $2 WHERE id = $1", [k.passkeyId, name]);
}

async function keys(token = admin.cli) {
  const res = await call("GET", KEYS, token);
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  return res.body as {
    generatedAt: string;
    summary: { admins: number; withTrustedKey: number; withoutTrustedKey: number };
    items: {
      identity: { id: string; name: string };
      trusted: number;
      unconfirmed: number;
      lastConfirmedAt: string | null;
      passkeys: { name: string | null; trust: string; trustedVia: string | null; createdAt: string | null; trustedAt: string | null }[];
    }[];
  };
}

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const { identityId } = await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" });
  app = buildApp(ctx, { publicUrl: PUBLIC_URL, clientAddress: () => "203.0.113.7" });
  admin = { id: identityId, cli: (await issueCredential(ctx.db, { identityId, kind: "cli" })).token };
  orgId = (await call("POST", "/v1/organizations", admin.cli, { name: "Acme", slug: "acme" })).body.id;
  expect((await call("POST", "/v1/organizations", admin.cli, { name: "Other", slug: "other" })).status).toBe(201);
});
afterEach(async () => {
  await ctx.close();
});

describe("approval keys", () => {
  it("is advertised as a capability", async () => {
    expect((await call("GET", "/v1/meta", admin.cli)).body.capabilities).toContain("security.approval-keys");
  });

  it("counts each admin's trusted and unconfirmed passkeys, trusted first, by name only", async () => {
    const laptop = await key(admin.id, "trusted");
    await rename(laptop, "Laptop");
    const phone = await key(admin.id, "unconfirmed");
    await rename(phone, "Phone");
    // A passkey without a provenance row counts as unconfirmed.
    const legacy = await key(admin.id);
    await rename(legacy, "Old key");
    // Confirmed with the trusted one.
    const tablet = await key(admin.id, "unconfirmed");
    await rename(tablet, "Tablet");
    await ctx.db.query(
      `UPDATE passkey_provenance SET trust = 'trusted', trusted_via = 'confirmed', trusted_at = now() - interval '1 hour',
              confirmed_by_passkey_id = $2 WHERE passkey_id = $1`,
      [tablet.passkeyId, laptop.passkeyId],
    );
    const zoe = await invite("Zoe", "admin");
    await rename(await key(zoe.id, "unconfirmed"), "Zoe's key");
    // Members are not listed.
    const bob = await invite("Bob", "member");
    await key(bob.id, "trusted");

    const r = await keys();
    expect(r.summary).toEqual({ admins: 2, withTrustedKey: 1, withoutTrustedKey: 1 });
    expect(r.items.map((a) => a.identity.name)).toEqual(["Admin", "Zoe"]);
    const [mine, theirs] = r.items;
    expect(mine).toMatchObject({ identity: { id: admin.id, name: "Admin" }, trusted: 2, unconfirmed: 2 });
    expect(mine!.passkeys.map((p) => [p.name, p.trust, p.trustedVia])).toEqual([
      ["Laptop", "trusted", "setup-grant"],
      ["Tablet", "trusted", "confirmed"],
      ["Phone", "unconfirmed", null],
      ["Old key", "unconfirmed", null],
    ]);
    expect(mine!.lastConfirmedAt).not.toBeNull();
    expect(Date.now() - Date.parse(mine!.lastConfirmedAt!)).toBeGreaterThan(3500_000);
    expect(mine!.passkeys[2]!.trustedAt).toBeNull();
    expect(theirs).toMatchObject({ identity: { id: zoe.id, name: "Zoe" }, trusted: 0, unconfirmed: 1, lastConfirmedAt: null });

    // Never key material, credential ids or passkey ids.
    const raw = JSON.stringify(r);
    for (const k of [laptop, phone, legacy, tablet]) {
      expect(raw).not.toContain(k.credentialId);
      expect(raw).not.toContain(k.passkeyId);
    }
    expect(raw).not.toMatch(/publicKey|counter|credentialID/i);
    expect(Object.keys(mine!.passkeys[0]!).sort()).toEqual(["createdAt", "name", "trust", "trustedAt", "trustedVia"]);
  });

  it("lists an admin without passkeys with none, and leaves out removed and demoted admins", async () => {
    const gone = await invite("Gone", "admin");
    await key(gone.id, "trusted");
    expect((await call("DELETE", `${ORG}/members/${gone.id}`, admin.cli)).status).toBe(200);
    const demoted = await invite("Demoted", "admin");
    expect((await call("PATCH", `${ORG}/members/${demoted.id}`, admin.cli, { role: "member" })).status).toBe(200);

    const r = await keys();
    expect(r.items).toEqual([{ identity: { id: admin.id, name: "Admin" }, trusted: 0, unconfirmed: 0, lastConfirmedAt: null, passkeys: [] }]);
    expect(r.summary).toEqual({ admins: 1, withTrustedKey: 0, withoutTrustedKey: 1 });
  });

  it("shows only this Organization's admins", async () => {
    const elsewhere = await invite("Elsewhere", "admin", (await call("GET", "/v1/organizations/other", admin.cli)).body.id);
    await key(elsewhere.id, "trusted");
    expect((await keys()).items.map((a) => a.identity.name)).toEqual(["Admin"]);
  });

  it("needs organization.manage: a member and a machine are refused, an outsider and an unknown organization see nothing", async () => {
    const bob = await invite("Bob", "member");
    expect((await call("GET", KEYS, bob.cli)).status).toBe(403);
    const svc = await call("POST", `${ORG}/identities`, admin.cli, { name: "svc", kind: "service" });
    expect(svc.status).toBe(201);
    expect((await call("GET", KEYS, svc.body.credential)).status).toBe(403);
    const outsider = await invite("Outsider", "member", (await call("GET", "/v1/organizations/other", admin.cli)).body.id);
    expect((await call("GET", KEYS, outsider.cli)).status).toBe(404);
    expect((await call("GET", "/v1/organizations/nope/security/approval-keys", admin.cli)).status).toBe(404);
  });

  it("is not cached", async () => {
    expect((await call("GET", KEYS, admin.cli)).headers.get("cache-control")).toBe("no-store");
  });
});
