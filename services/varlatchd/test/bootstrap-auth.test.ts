// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { authenticateBearer, issueCredential, revokeCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { runMigrations } from "../src/db/migrate.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  adminsWithoutPasskey,
  bootstrapStatus,
  consumeSetupGrant,
  ensureInstallation,
  issueBootstrapGrant,
  issueRecoveryGrant,
  peekSetupGrant,
  verifyLoadedKek,
} from "../src/domain/bootstrap.js";
import { completeEnrollment, enrollmentUser } from "../src/auth/humanauth.js";
import { createOrganization } from "../src/domain/orgs.js";
import { createMachineIdentity } from "../src/domain/identities.js";
import { testDb } from "./helpers/pglite.js";

let ctx: AppCtx & { close: () => Promise<void> };
beforeEach(async () => {
  const db = await testDb();
  await runMigrations(db);
  ctx = { db, rootKek: generateKey(), close: db.close };
});
afterEach(async () => {
  await ctx.close();
});

async function bootstrap(): Promise<string> {
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId } = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
  return identityId;
}

describe("installation lifecycle", () => {
  it("initializes idempotently and verifies the loaded KEK against the canary", async () => {
    const a = await ensureInstallation(ctx);
    const b = await ensureInstallation(ctx);
    expect(b.id).toBe(a.id);
    expect(await verifyLoadedKek(ctx)).toBe(true);
    expect(await verifyLoadedKek(ctx, generateKey())).toBe(false);
  });

  it("bootstrap grant is single-use and creates an installation admin", async () => {
    await ensureInstallation(ctx);
    const grant = await issueBootstrapGrant(ctx);
    expect(grant.token).toMatch(/^vlt_setup_/);
    const { identityId, kind } = await consumeSetupGrant(ctx, grant.token, { adminName: "Jeremy" });
    expect(kind).toBe("bootstrap");
    const row = await ctx.db.query("SELECT installation_admin FROM identities WHERE id = $1", [identityId]);
    expect((row.rows[0] as { installation_admin: boolean }).installation_admin).toBe(true);
    // Single-use.
    await expect(consumeSetupGrant(ctx, grant.token, {})).rejects.toMatchObject({
      code: "INVALID_CREDENTIAL",
    });
    // Bootstrap no longer possible.
    await expect(issueBootstrapGrant(ctx)).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
  });
});

describe("break-glass recovery (ADR-0020 §1)", () => {
  it("targets a named enabled installation admin", async () => {
    const adminId = await bootstrap();
    const grant = await issueRecoveryGrant(ctx, { mode: "identity", identityId: adminId });
    const { identityId, kind } = await consumeSetupGrant(ctx, grant.token, {});
    expect(kind).toBe("recover");
    expect(identityId).toBe(adminId);
  });

  it("refuses disabled admins without explicit --enable", async () => {
    const adminId = await bootstrap();
    await ctx.db.query("UPDATE identities SET disabled = true WHERE id = $1", [adminId]);
    await expect(
      issueRecoveryGrant(ctx, { mode: "identity", identityId: adminId }),
    ).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
    const grant = await issueRecoveryGrant(ctx, { mode: "identity", identityId: adminId, enable: true });
    await consumeSetupGrant(ctx, grant.token, {});
    const row = await ctx.db.query("SELECT disabled FROM identities WHERE id = $1", [adminId]);
    expect((row.rows[0] as { disabled: boolean }).disabled).toBe(false);
  });

  it("allows --new-admin only when zero enabled admins exist", async () => {
    const adminId = await bootstrap();
    await expect(issueRecoveryGrant(ctx, { mode: "new-admin" })).rejects.toMatchObject({
      code: "VALIDATION_FAILED",
    });
    await ctx.db.query("UPDATE identities SET disabled = true WHERE id = $1", [adminId]);
    const grant = await issueRecoveryGrant(ctx, { mode: "new-admin" });
    const { identityId } = await consumeSetupGrant(ctx, grant.token, { adminName: "Replacement" });
    expect(identityId).not.toBe(adminId);
  });

  it("recovery requires a bootstrapped installation", async () => {
    await ensureInstallation(ctx);
    await expect(issueRecoveryGrant(ctx, { mode: "new-admin" })).rejects.toMatchObject({
      code: "VALIDATION_FAILED",
    });
  });
});

describe("credentials", () => {
  it("issues, authenticates, and revokes opaque bearer credentials", async () => {
    const adminId = await bootstrap();
    const { credentialId, token } = await issueCredential(ctx.db, {
      identityId: adminId,
      kind: "cli",
      name: "laptop",
    });
    const ok = await authenticateBearer(ctx.db, token);
    expect(ok.ok).toBe(true);
    if (ok.ok) {
      expect(ok.identity.id).toBe(adminId);
      expect(ok.credential.id).toBe(credentialId);
    }
    expect((await authenticateBearer(ctx.db, "vlt_cli_nonsense")).ok).toBe(false);

    await revokeCredential(ctx.db, credentialId, adminId);
    const revoked = await authenticateBearer(ctx.db, token);
    expect(revoked).toMatchObject({ ok: false, reason: "revoked" });
  });

  it("rejects expired credentials and disabled identities", async () => {
    const adminId = await bootstrap();
    const { token } = await issueCredential(ctx.db, {
      identityId: adminId,
      kind: "cli",
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    });
    expect(await authenticateBearer(ctx.db, token)).toMatchObject({ ok: false, reason: "expired" });

    const { token: live } = await issueCredential(ctx.db, { identityId: adminId, kind: "cli" });
    await ctx.db.query("UPDATE identities SET disabled = true WHERE id = $1", [adminId]);
    expect(await authenticateBearer(ctx.db, live)).toMatchObject({
      ok: false,
      reason: "identity-disabled",
    });
  });
});

describe("machine identities", () => {
  it("service identities are org-scoped and get a one-time credential", async () => {
    const adminId = await bootstrap();
    const org = await createOrganization(ctx, { slug: "acme", name: "Acme" }, adminId);
    const { identity, credential } = await createMachineIdentity(
      ctx,
      org.id,
      { name: "prod-api", kind: "service" },
      adminId,
    );
    expect(identity.organization_id).toBe(org.id);
    expect(credential).toMatch(/^vlt_svc_/);
    const auth = await authenticateBearer(ctx.db, credential as string);
    expect(auth.ok).toBe(true);
  });

  it("ci identities get no static credential by default", async () => {
    const adminId = await bootstrap();
    const org = await createOrganization(ctx, { slug: "acme", name: "Acme" }, adminId);
    const { credential } = await createMachineIdentity(
      ctx,
      org.id,
      { name: "gha", kind: "ci" },
      adminId,
    );
    expect(credential).toBeNull();
  });

  it("schema forbids humans with org scope and machines without", async () => {
    await expect(
      ctx.db.query("INSERT INTO identities (id, kind, name) VALUES ('idn_x','service','no-org')"),
    ).rejects.toThrow();
  });
});

describe("invitations (ADR-0006/0010)", () => {
  it("invite consumption creates a non-admin human with the org membership", async () => {
    const adminId = await bootstrap();
    const org = await createOrganization(ctx, { slug: "acme", name: "Acme" }, adminId);
    const { issueInviteGrant } = await import("../src/domain/bootstrap.js");
    const invite = await issueInviteGrant(
      ctx,
      { organizationId: org.id, role: "member", name: "Sam" },
      adminId,
    );
    expect(invite.token).toMatch(/^vlt_invite_/);
    const { identityId, kind } = await consumeSetupGrant(ctx, invite.token, {});
    expect(kind).toBe("invite");
    const row = await ctx.db.query(
      "SELECT installation_admin, name FROM identities WHERE id = $1",
      [identityId],
    );
    expect(row.rows[0]).toMatchObject({ installation_admin: false, name: "Sam" });
    const membership = await ctx.db.query(
      "SELECT role FROM org_memberships WHERE organization_id = $1 AND identity_id = $2",
      [org.id, identityId],
    );
    expect((membership.rows[0] as { role: string }).role).toBe("member");
    // Single-use.
    await expect(consumeSetupGrant(ctx, invite.token, {})).rejects.toMatchObject({
      code: "INVALID_CREDENTIAL",
    });
    const audit = await ctx.db.query(
      "SELECT count(*)::int AS n FROM audit_events WHERE event_type IN ('invitation.issued','invitation.accepted')",
    );
    expect((audit.rows[0] as { n: number }).n).toBe(2);
  });
});

describe("enrollment grant lifecycle (issue #23)", () => {
  async function setupGrant(): Promise<string> {
    await ensureInstallation(ctx);
    return (await issueBootstrapGrant(ctx)).token;
  }
  const count = async (sql: string, params: unknown[] = []) =>
    ((await ctx.db.query(sql, params)).rows[0] as { n: number }).n;

  it("starting a ceremony checks the grant without consuming it", async () => {
    const token = await setupGrant();
    const peeked = await peekSetupGrant(ctx, token);
    expect(peeked).toMatchObject({ kind: "bootstrap", displayName: "Installation Admin" });
    const user = await enrollmentUser(ctx, token);
    expect(user.id).toBe(`setup:${peeked.grantId}`);
    // Abandoned ceremony: nothing consumed, created, or bootstrapped.
    expect(await count("SELECT count(*)::int AS n FROM setup_grants WHERE consumed_at IS NOT NULL")).toBe(0);
    expect(await count("SELECT count(*)::int AS n FROM identities")).toBe(0);
    const inst = await ctx.db.query("SELECT bootstrapped_at FROM installation");
    expect((inst.rows[0] as { bootstrapped_at: string | null }).bootstrapped_at).toBeNull();
    // The same link still enrolls afterwards.
    const done = await completeEnrollment(ctx, user.id, token);
    expect(done?.userId).toMatch(/^bau_idn_/);
  });

  it("completion consumes the grant, bootstraps, and links the user atomically", async () => {
    const token = await setupGrant();
    const { id } = await enrollmentUser(ctx, token);
    const done = await completeEnrollment(ctx, id, token);
    const identityId = done!.userId.replace(/^bau_/, "");
    const admin = await ctx.db.query("SELECT installation_admin FROM identities WHERE id = $1", [identityId]);
    expect((admin.rows[0] as { installation_admin: boolean }).installation_admin).toBe(true);
    expect(await count(`SELECT count(*)::int AS n FROM "user" WHERE id = $1`, [done!.userId])).toBe(1);
    expect(await count("SELECT count(*)::int AS n FROM auth_user_links WHERE identity_id = $1", [identityId])).toBe(1);
    expect(await count("SELECT count(*)::int AS n FROM installation WHERE bootstrapped_at IS NOT NULL")).toBe(1);
    // Single use: a second completion and a second ceremony start both fail.
    await expect(completeEnrollment(ctx, id, token)).rejects.toMatchObject({ statusCode: 400 });
    await expect(enrollmentUser(ctx, token)).rejects.toMatchObject({ statusCode: 400 });
  });

  it("rolls consumption back when the grant does not match the ceremony", async () => {
    const token = await setupGrant();
    await expect(completeEnrollment(ctx, "setup:sgr_other", token)).rejects.toMatchObject({ statusCode: 400 });
    expect(await count("SELECT count(*)::int AS n FROM setup_grants WHERE consumed_at IS NOT NULL")).toBe(0);
    expect(await count("SELECT count(*)::int AS n FROM identities")).toBe(0);
  });

  it("leaves signed-in passkey additions alone and ignores the token", async () => {
    const token = await setupGrant();
    expect(await completeEnrollment(ctx, "bau_idn_existing", token)).toBeUndefined();
    expect(await count("SELECT count(*)::int AS n FROM setup_grants WHERE consumed_at IS NOT NULL")).toBe(0);
  });

  it("rejects unknown, expired, and missing tokens at ceremony start, with audit", async () => {
    const token = await setupGrant();
    await ctx.db.query("UPDATE setup_grants SET expires_at = now() - interval '1 minute'");
    await expect(enrollmentUser(ctx, token)).rejects.toMatchObject({ statusCode: 400 });
    await expect(enrollmentUser(ctx, "vlt_setup_unknown")).rejects.toMatchObject({ statusCode: 400 });
    await expect(enrollmentUser(ctx, null)).rejects.toMatchObject({ statusCode: 400 });
    expect(await count("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'setup.grant_rejected'")).toBe(2);
  });

  it("recovery re-enrollment reuses the identity's existing Better Auth user", async () => {
    const token = await setupGrant();
    const first = await completeEnrollment(ctx, (await enrollmentUser(ctx, token)).id, token);
    const identityId = first!.userId.replace(/^bau_/, "");
    const recovery = await issueRecoveryGrant(ctx, { mode: "identity", identityId });
    const user = await enrollmentUser(ctx, recovery.token);
    const again = await completeEnrollment(ctx, user.id, recovery.token);
    expect(again?.userId).toBe(first!.userId);
    expect(await count("SELECT count(*)::int AS n FROM auth_user_links")).toBe(1);
  });

  it("names admins without a passkey when bootstrap is refused", async () => {
    const identityId = await bootstrap();
    expect(await adminsWithoutPasskey(ctx.db)).toEqual([identityId]);
    await expect(issueBootstrapGrant(ctx)).rejects.toThrow(`admin recover --identity ${identityId}`);
  });
});

describe("bootstrap-status (ADR-0035 D7)", () => {
  it("reports not-initialized, then bootstrapped-without-passkey, per admin", async () => {
    expect(await bootstrapStatus(ctx.db)).toEqual({ initialized: false, bootstrapped: false, admins: [] });
    await ensureInstallation(ctx);
    expect(await bootstrapStatus(ctx.db)).toEqual({ initialized: true, bootstrapped: false, admins: [] });
    const identityId = await bootstrap();
    expect(await bootstrapStatus(ctx.db)).toEqual({ initialized: true, bootstrapped: true, admins: [{ id: identityId, enabled: true, hasPasskey: false }] });
  });
});
