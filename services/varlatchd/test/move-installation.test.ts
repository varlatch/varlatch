// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { authenticateBearer, issueCredential } from "../src/auth/credentials.js";
import { completeEnrollment, enrollmentUser } from "../src/auth/humanauth.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  bootstrapStatus,
  completePublicUrlChange,
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
  issueInviteGrant,
  issueReenrollmentGrants,
  moveFacts,
  peekSetupGrant,
} from "../src/domain/bootstrap.js";
import { createMachineIdentity } from "../src/domain/identities.js";
import { createOrganization } from "../src/domain/orgs.js";
import { migratedTestDb } from "./helpers/pglite.js";

/** Moving an installation to another public URL (issue #103). */

let ctx: AppCtx & { close: () => Promise<void> };
beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
});
afterEach(async () => {
  await ctx.close();
});

const count = async (sql: string, params: unknown[] = []) =>
  ((await ctx.db.query(sql, params)).rows[0] as { n: number }).n;

/** An Installation Admin and a member, both enrolled with a passkey, plus a machine. */
async function installation() {
  await ensureInstallation(ctx);
  const boot = await issueBootstrapGrant(ctx);
  const admin = await completeEnrollment(ctx, (await enrollmentUser(ctx, boot.token)).id, boot.token);
  const adminId = admin!.userId.replace(/^bau_/, "");
  const org = await createOrganization(ctx, { slug: "acme", name: "Acme" }, adminId);
  const invite = await issueInviteGrant(ctx, { organizationId: org.id, role: "member", name: "Sam" }, adminId);
  const member = await completeEnrollment(ctx, (await enrollmentUser(ctx, invite.token)).id, invite.token);
  const memberId = member!.userId.replace(/^bau_/, "");
  const machine = await createMachineIdentity(ctx, org.id, { name: "prod-api", kind: "service" }, adminId);
  for (const [userId, n] of [[admin!.userId, 1], [member!.userId, 2]] as const) {
    await ctx.db.query(
      `INSERT INTO "passkey" (id, "publicKey", "userId", "credentialID", counter, "deviceType", "backedUp")
       VALUES ($1, 'pk', $2, $3, 0, 'singleDevice', false)`,
      [`pk_${n}`, userId, `cred_${n}`],
    );
    await ctx.db.query(
      `INSERT INTO "session" (id, "expiresAt", token, "userId") VALUES ($1, now() + interval '1 day', $2, $3)`,
      [`ses_${n}`, `tok_${n}`, userId],
    );
  }
  return { adminId, memberId, machineId: machine.identity.id, org };
}

describe("re-enrollment links (issue #103)", () => {
  it("issue one link per enabled person, Installation Admins first, never for machines", async () => {
    const { adminId, memberId } = await installation();
    const grants = await issueReenrollmentGrants(ctx, { identityIds: "all" });
    expect(grants.map((g) => [g.identityId, g.installationAdmin])).toEqual([[adminId, true], [memberId, false]]);
    for (const g of grants) expect(g.token).toMatch(/^vlt_reenroll_/);
    expect(new Date(grants[0]!.expiresAt).getTime() - Date.now()).toBeGreaterThan(23 * 3600_000);
    expect(await count("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'reenrollment.grant_issued'")).toBe(2);
  });

  it("add a passkey to the existing identity: nothing is created, and each link works once", async () => {
    const { memberId } = await installation();
    const identities = await count("SELECT count(*)::int AS n FROM identities");
    const [grant] = await issueReenrollmentGrants(ctx, { identityIds: [memberId] });
    expect(await peekSetupGrant(ctx, grant!.token)).toMatchObject({ kind: "reenroll", displayName: "Sam" });
    const user = await enrollmentUser(ctx, grant!.token);
    const done = await completeEnrollment(ctx, user.id, grant!.token);
    expect(done?.userId).toBe(`bau_${memberId}`);
    expect(await count("SELECT count(*)::int AS n FROM identities")).toBe(identities);
    expect(await count("SELECT count(*)::int AS n FROM auth_user_links WHERE identity_id = $1", [memberId])).toBe(1);
    expect(await count("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'reenrollment.completed'")).toBe(1);
    await expect(consumeSetupGrant(ctx, grant!.token, {})).rejects.toMatchObject({ code: "INVALID_CREDENTIAL" });
  });

  it("a new link for a person revokes the unused one before it", async () => {
    const { memberId } = await installation();
    const [first] = await issueReenrollmentGrants(ctx, { identityIds: [memberId] });
    const [second] = await issueReenrollmentGrants(ctx, { identityIds: [memberId] });
    await expect(peekSetupGrant(ctx, first!.token)).rejects.toMatchObject({ code: "INVALID_CREDENTIAL" });
    expect((await consumeSetupGrant(ctx, second!.token, {})).identityId).toBe(memberId);
  });

  it("refuse machines, unknown and disabled people, and a person disabled after issue", async () => {
    const { memberId, machineId } = await installation();
    await expect(issueReenrollmentGrants(ctx, { identityIds: [machineId] })).rejects.toMatchObject({ code: "RESOURCE_NOT_FOUND" });
    await expect(issueReenrollmentGrants(ctx, { identityIds: ["idn_unknown"] })).rejects.toMatchObject({ code: "RESOURCE_NOT_FOUND" });
    const [grant] = await issueReenrollmentGrants(ctx, { identityIds: [memberId] });
    await ctx.db.query("UPDATE identities SET disabled = true WHERE id = $1", [memberId]);
    // Refused when the ceremony starts, before an authenticator makes a credential, and at consumption.
    await expect(peekSetupGrant(ctx, grant!.token)).rejects.toMatchObject({ code: "INVALID_CREDENTIAL" });
    await expect(consumeSetupGrant(ctx, grant!.token, {})).rejects.toMatchObject({ code: "INVALID_CREDENTIAL" });
    await expect(issueReenrollmentGrants(ctx, { identityIds: [memberId] })).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
    expect((await issueReenrollmentGrants(ctx, { identityIds: "all" })).map((g) => g.identityId)).not.toContain(memberId);
  });

  it("keep link lifetimes between one second and a week, and need a bootstrapped installation", async () => {
    await expect(issueReenrollmentGrants(ctx, { identityIds: "all" })).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
    await installation();
    for (const ttlHours of [0, -1, 169, Number.NaN]) {
      await expect(issueReenrollmentGrants(ctx, { identityIds: "all", ttlHours })).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
    }
    const [grant] = await issueReenrollmentGrants(ctx, { identityIds: "all", ttlHours: 168 });
    expect(new Date(grant!.expiresAt).getTime() - Date.now()).toBeGreaterThan(167 * 3600_000);
  });

  it("the schema refuses a re-enrollment grant without a person", async () => {
    await expect(
      ctx.db.query("INSERT INTO setup_grants (id, kind, token_hash, expires_at) VALUES ('sgr_x','reenroll','h', now())"),
    ).rejects.toThrow();
  });
});

describe("completing a public URL change (issue #103)", () => {
  it("removes every passkey, ends every session, revokes browser tokens, keeps other credentials", async () => {
    const { adminId, memberId } = await installation();
    const browser = await issueCredential(ctx.db, { identityId: memberId, kind: "browser", authSessionId: "ses_2" });
    const cli = await issueCredential(ctx.db, { identityId: memberId, kind: "cli" });
    expect((await bootstrapStatus(ctx.db)).admins).toEqual([{ id: adminId, enabled: true, hasPasskey: true }]);

    const result = await completePublicUrlChange(ctx, { from: "https://vault.example.com/", to: "https://vault.example.org" });
    expect(result).toEqual({
      from: "https://vault.example.com", to: "https://vault.example.org",
      passkeysRemoved: 2, sessionsEnded: 2, browserCredentialsRevoked: 1,
    });
    expect(await count(`SELECT count(*)::int AS n FROM "passkey"`)).toBe(0);
    expect(await count(`SELECT count(*)::int AS n FROM "session"`)).toBe(0);
    expect((await authenticateBearer(ctx.db, browser.token)).ok).toBe(false);
    expect((await authenticateBearer(ctx.db, cli.token)).ok).toBe(true);
    // Setup's bootstrap phase now sees the admin without a working passkey.
    expect((await bootstrapStatus(ctx.db)).admins).toEqual([{ id: adminId, enabled: true, hasPasskey: false }]);
    const audit = await ctx.db.query("SELECT metadata FROM audit_events WHERE event_type = 'installation.public_url_changed'");
    expect(audit.rows).toHaveLength(1);
    expect((audit.rows[0] as { metadata: unknown }).metadata).toMatchObject({ from: result.from, to: result.to, passkeysRemoved: 2 });
  });

  it("removes passkeys once per move: a rerun or a wrong --from after people re-enrolled removes nothing", async () => {
    const { memberId } = await installation();
    await completePublicUrlChange(ctx, { from: "https://a.example.com", to: "https://b.example.com" });
    const [grant] = await issueReenrollmentGrants(ctx, { identityIds: [memberId] });
    await completeEnrollment(ctx, (await enrollmentUser(ctx, grant!.token)).id, grant!.token);
    await ctx.db.query(
      `INSERT INTO "passkey" (id, "publicKey", "userId", "credentialID", counter, "deviceType", "backedUp")
       VALUES ('pk_new', 'pk', $1, 'cred_new', 0, 'singleDevice', false)`,
      [`bau_${memberId}`],
    );
    await expect(completePublicUrlChange(ctx, { from: "https://a.example.com", to: "https://b.example.com" })).rejects.toThrow(/already removed/);
    await expect(completePublicUrlChange(ctx, { from: "https://typo.example.com", to: "https://c.example.com" })).rejects.toThrow(/last moved to https:\/\/b\.example\.com/);
    expect(await count(`SELECT count(*)::int AS n FROM "passkey"`)).toBe(1);
    // The next real move starts from the recorded address.
    expect((await completePublicUrlChange(ctx, { from: "https://b.example.com", to: "https://c.example.com" })).passkeysRemoved).toBe(1);
  });

  it("writes one credential.revoked line per browser token, as every revocation does", async () => {
    const { memberId, adminId } = await installation();
    const a = await issueCredential(ctx.db, { identityId: memberId, kind: "browser", authSessionId: "ses_2" });
    const b = await issueCredential(ctx.db, { identityId: adminId, kind: "browser", authSessionId: "ses_1" });
    await completePublicUrlChange(ctx, { from: "https://vault.example.com", to: "https://vault.example.org" });
    const lines = await ctx.db.query(
      "SELECT credential_id FROM audit_events WHERE event_type = 'credential.revoked' ORDER BY credential_id",
    );
    expect((lines.rows as { credential_id: string }[]).map((r) => r.credential_id)).toEqual([a.credentialId, b.credentialId].sort());
  });

  it("refuses the same address, and changes nothing", async () => {
    await installation();
    await expect(
      completePublicUrlChange(ctx, { from: "https://vault.example.com", to: "https://vault.example.com/" }),
    ).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
    expect(await count(`SELECT count(*)::int AS n FROM "passkey"`)).toBe(2);
  });

  it("move facts count what a move affects", async () => {
    await installation();
    await ctx.db.query(
      `INSERT INTO requirements (id, organization_id, kind, target, config)
       SELECT 'req_1', id, 'tailnet', '{}', '{}' FROM organizations LIMIT 1`,
    );
    expect(await moveFacts(ctx.db)).toEqual({
      people: 2, installationAdmins: 1, passkeys: 2, sessions: 2, tailnetConstraints: 1, pendingInvitations: 0,
    });
  });
});
