// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
  peekSetupGrant,
} from "../src/domain/bootstrap.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * Invitation management (capability invitations.manage): list (pending by
 * default, status=all for every state) and revoke a pending invitation,
 * authorized like creation (identity.manage), existence-hiding, audited,
 * never exposing a token.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminId: string;
let adminToken: string;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  adminId = (await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" })).identityId;
  adminToken = (await issueCredential(ctx.db, { identityId: adminId, kind: "cli" })).token;
  app = buildApp(ctx);
  expect((await call("POST", "/v1/organizations", { name: "Acme", slug: "acme" })).status).toBe(201);
});
afterEach(async () => {
  await ctx.close();
});

async function call(method: string, path: string, body?: unknown, token = adminToken) {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, text, body: text ? JSON.parse(text) : undefined };
}

async function invite(name: string, role: "admin" | "member" = "member") {
  const res = await call("POST", "/v1/organizations/acme/invitations", { name, role });
  expect(res.status).toBe(201);
  return res.body as { id: string; token: string; expiresAt: string };
}

const list = (query = "") => call("GET", `/v1/organizations/acme/invitations${query}`);

describe("listing invitations", () => {
  it("lists pending invitations newest first, every state with status=all, and never a token", async () => {
    const consumed = await invite("Consumed", "admin");
    const expired = await invite("Expired");
    const revoked = await invite("Revoked");
    const pending = await invite("Pending");
    await consumeSetupGrant(ctx, consumed.token, {});
    await ctx.db.query("UPDATE setup_grants SET expires_at = now() - interval '1 minute' WHERE id = $1", [expired.id]);
    expect((await call("DELETE", `/v1/organizations/acme/invitations/${revoked.id}`)).status).toBe(204);

    const pendingOnly = await list();
    expect(pendingOnly.status).toBe(200);
    expect(pendingOnly.body).toEqual({
      items: [
        {
          id: pending.id,
          name: "Pending",
          orgRole: "member",
          status: "pending",
          createdAt: expect.any(String),
          expiresAt: pending.expiresAt,
          createdByIdentityId: adminId,
          consumedAt: null,
          revokedAt: null,
        },
      ],
      nextCursor: null,
    });

    const all = await list("?status=all");
    expect(all.status).toBe(200);
    expect(all.body.items.map((i: { id: string; status: string }) => [i.id, i.status])).toEqual([
      [pending.id, "pending"],
      [revoked.id, "revoked"],
      [expired.id, "expired"],
      [consumed.id, "consumed"],
    ]);
    const byId = new Map(all.body.items.map((i: { id: string }) => [i.id, i]));
    expect(byId.get(consumed.id)).toMatchObject({ orgRole: "admin", consumedAt: expect.any(String), revokedAt: null });
    expect(byId.get(revoked.id)).toMatchObject({ consumedAt: null, revokedAt: expect.any(String) });

    // No token, and nothing derived from one, in any listing.
    const hashes = (await ctx.db.query("SELECT token_hash FROM setup_grants")).rows as { token_hash: string }[];
    for (const text of [pendingOnly.text, all.text]) {
      expect(text).not.toMatch(/vlt_invite_|token/i);
      for (const { token_hash } of hashes) expect(text).not.toContain(token_hash);
    }
  });

  it("paginates deterministically with an opaque cursor", async () => {
    const created = [];
    for (let i = 0; i < 5; i++) created.push((await invite(`Person ${i}`)).id);
    const seen: string[] = [];
    let cursor: string | null = null;
    let pages = 0;
    do {
      const page = await list(`?limit=2${cursor ? `&cursor=${cursor}` : ""}`);
      expect(page.status).toBe(200);
      expect(page.body.items.length).toBeLessThanOrEqual(2);
      seen.push(...page.body.items.map((i: { id: string }) => i.id));
      cursor = page.body.nextCursor;
      pages++;
    } while (cursor && pages < 10);
    expect(pages).toBe(3);
    expect(seen).toEqual([...created].reverse());
  });

  it("validates status, limit, and cursor", async () => {
    expect((await list("?status=consumed")).status).toBe(422);
    expect((await list("?limit=0")).status).toBe(422);
    expect((await list("?limit=501")).status).toBe(422);
    expect((await list("?limit=two")).status).toBe(422);
    expect((await list("?cursor=not-a-cursor")).status).toBe(422);
    expect((await list("?limit=500")).status).toBe(200);
  });

  it("is authorized like creation and hides the organization from outsiders", async () => {
    await invite("Sam");
    // An Organization Member holds organization.read, not identity.manage.
    const memberInvite = await invite("Member");
    const member = await consumeSetupGrant(ctx, memberInvite.token, {});
    const memberToken = (await issueCredential(ctx.db, { identityId: member.identityId, kind: "cli" })).token;
    expect((await call("GET", "/v1/organizations/acme/invitations", undefined, memberToken)).status).toBe(403);
    // A machine identity of the org without identity.manage is refused, not hidden.
    const svc = await call("POST", "/v1/organizations/acme/identities", { name: "runner", kind: "service" });
    expect((await call("GET", "/v1/organizations/acme/invitations", undefined, svc.body.credential)).status).toBe(403);
    // A human outside the organization learns nothing.
    const outsiderInvite = await call("POST", "/v1/organizations", { name: "Other", slug: "other" });
    expect(outsiderInvite.status).toBe(201);
    const other = await call("POST", "/v1/organizations/other/invitations", { name: "Outsider", role: "admin" });
    const outsider = await consumeSetupGrant(ctx, other.body.token, {});
    const outsiderToken = (await issueCredential(ctx.db, { identityId: outsider.identityId, kind: "cli" })).token;
    expect((await call("GET", "/v1/organizations/acme/invitations", undefined, outsiderToken)).status).toBe(404);
    // Each organization lists only its own invitations.
    const acme = await list("?status=all");
    expect(acme.body.items.map((i: { name: string }) => i.name)).not.toContain("Outsider");
  });
});

describe("revoking an invitation", () => {
  it("revokes a pending invitation, kills its token at once, and audits it", async () => {
    const inv = await invite("Sam", "admin");
    // An enrollment ceremony may already have started with the link.
    await expect(peekSetupGrant(ctx, inv.token)).resolves.toMatchObject({ kind: "invite" });
    const res = await call("DELETE", `/v1/organizations/acme/invitations/${inv.id}`);
    expect(res.status).toBe(204);

    await expect(peekSetupGrant(ctx, inv.token)).rejects.toMatchObject({ code: "INVALID_CREDENTIAL" });
    await expect(consumeSetupGrant(ctx, inv.token, {})).rejects.toMatchObject({ code: "INVALID_CREDENTIAL" });
    const humans = await ctx.db.query("SELECT count(*)::int AS n FROM identities WHERE name = 'Sam'");
    expect((humans.rows[0] as { n: number }).n).toBe(0);

    const org = (await call("GET", "/v1/organizations/acme")).body as { id: string };
    const events = await ctx.db.query(
      "SELECT event_type, actor_identity_id, organization_id, action, resource, metadata FROM audit_events WHERE event_type LIKE 'invitation.%' ORDER BY event_order",
    );
    const parse = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v);
    const rows = (events.rows as Record<string, unknown>[]).map((r) => ({
      ...r,
      resource: parse(r.resource),
      metadata: parse(r.metadata),
    }));
    expect(rows.map((r) => r.event_type)).toEqual(["invitation.issued", "invitation.revoked"]);
    expect(rows[0]!.resource).toEqual({ invitationId: inv.id });
    expect(rows[1]).toEqual({
      event_type: "invitation.revoked",
      actor_identity_id: adminId,
      organization_id: org.id,
      action: "identity.manage",
      resource: { invitationId: inv.id },
      metadata: { role: "admin", inviteeName: "Sam" },
    });
    expect(JSON.stringify(rows)).not.toContain(inv.token);
  });

  it("refuses an invitation that is no longer pending with its status", async () => {
    const consumed = await invite("Consumed");
    await consumeSetupGrant(ctx, consumed.token, {});
    const expired = await invite("Expired");
    await ctx.db.query("UPDATE setup_grants SET expires_at = now() - interval '1 minute' WHERE id = $1", [expired.id]);
    const revoked = await invite("Revoked");
    expect((await call("DELETE", `/v1/organizations/acme/invitations/${revoked.id}`)).status).toBe(204);

    for (const [inv, status] of [[consumed, "consumed"], [expired, "expired"], [revoked, "revoked"]] as const) {
      const res = await call("DELETE", `/v1/organizations/acme/invitations/${inv.id}`);
      expect(res.status, status).toBe(409);
      expect(res.body.error).toMatchObject({ code: "VERSION_CONFLICT", details: { status } });
    }
    const revocations = await ctx.db.query("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'invitation.revoked'");
    expect((revocations.rows[0] as { n: number }).n).toBe(1);
    // The consumed invitation's acceptance stays intact.
    const row = await ctx.db.query("SELECT consumed_at, revoked_at FROM setup_grants WHERE id = $1", [consumed.id]);
    expect(row.rows[0]).toMatchObject({ consumed_at: expect.anything(), revoked_at: null });
  });

  it("hides unknown invitations and other organizations' invitations, and needs identity.manage", async () => {
    expect((await call("DELETE", "/v1/organizations/acme/invitations/sgr_unknown")).status).toBe(404);
    await call("POST", "/v1/organizations", { name: "Other", slug: "other" });
    const foreign = (await call("POST", "/v1/organizations/other/invitations", { name: "X", role: "member" })).body;
    expect((await call("DELETE", `/v1/organizations/acme/invitations/${foreign.id}`)).status).toBe(404);
    // Bootstrap and recovery grants are not invitations.
    const bootstrapGrant = (await ctx.db.query("SELECT id FROM setup_grants WHERE kind = 'bootstrap'")).rows[0] as { id: string };
    expect((await call("DELETE", `/v1/organizations/acme/invitations/${bootstrapGrant.id}`)).status).toBe(404);

    const inv = await invite("Sam");
    const svc = await call("POST", "/v1/organizations/acme/identities", { name: "runner", kind: "service" });
    expect((await call("DELETE", `/v1/organizations/acme/invitations/${inv.id}`, undefined, svc.body.credential)).status).toBe(403);
    expect((await list()).body.items.map((i: { id: string }) => i.id)).toContain(inv.id);
  });

  it("advertises invitations.manage", async () => {
    const meta = await app.request("/v1/meta").then((r) => r.json() as Promise<{ capabilities: string[] }>);
    expect(meta.capabilities).toContain("invitations.manage");
  });
});
