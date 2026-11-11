// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { authenticateBearer, issueCredential } from "../src/auth/credentials.js";
import type { HumanAuth } from "../src/auth/humanauth.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { completePublicUrlChange, consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import { createMachineIdentity } from "../src/domain/identities.js";
import { createOrganization } from "../src/domain/orgs.js";
import { buildApp } from "../src/http/app.js";
import { migratedTestDb } from "./helpers/pglite.js";

/**
 * A browser credential ends with the Better Auth session it was minted from
 * (migration 43): any DELETE of session rows revokes their live `browser`
 * credentials and records each revocation. The real Better Auth endpoints
 * and the lock order are covered on PostgreSQL in
 * session-end-revocation-postgres.test.ts.
 */
let ctx: AppCtx & { close: () => Promise<void> };
let personId: string;
beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  personId = (await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Jeremy" })).identityId;
  await db.query(`INSERT INTO "user" (id, name, email) VALUES ('bau_p', 'Jeremy', 'p@varlatch.placeholder.invalid')`);
  await db.query("INSERT INTO auth_user_links (better_auth_user_id, identity_id) VALUES ('bau_p', $1)", [personId]);
  for (const id of ["ses_a", "ses_b"]) await session(id);
});
afterEach(async () => {
  await ctx.close();
});

async function session(id: string, expires = "now() + interval '7 days'") {
  await ctx.db.query(`INSERT INTO "session" (id, "expiresAt", token, "userId") VALUES ($1, ${expires}, $2, 'bau_p')`, [id, `tok_${id}`]);
}
const browser = (authSessionId: string, minutes = 15) =>
  issueCredential(ctx.db, {
    identityId: personId, kind: "browser", authSessionId,
    expiresAt: new Date(Date.now() + minutes * 60_000).toISOString(),
  });
const works = async (token: string) => (await authenticateBearer(ctx.db, token)).ok;
const revocations = async () =>
  (await ctx.db.query(
    `SELECT credential_id, actor_identity_id, organization_id, decision, resource, metadata, id
     FROM audit_events WHERE event_type = 'credential.revoked' ORDER BY event_order`,
  )).rows as { credential_id: string; actor_identity_id: string | null; organization_id: string | null; decision: string; resource: unknown; metadata: unknown; id: string }[];

describe("ending a session revokes its browser credentials (migration 43)", () => {
  it("revokes the session's live browser credentials, records each, and leaves everything else", async () => {
    const a1 = await browser("ses_a");
    const a2 = await browser("ses_a");
    const b = await browser("ses_b");
    // A CLI credential from the browser handoff carries the session too; it outlives it (ADR-0024).
    const handoff = await issueCredential(ctx.db, { identityId: personId, kind: "cli", authSessionId: "ses_a" });
    const cli = await issueCredential(ctx.db, { identityId: personId, kind: "cli" });
    const org = await createOrganization(ctx, { slug: "acme", name: "Acme" }, personId);
    const machine = await createMachineIdentity(ctx, org.id, { name: "prod-api", kind: "service" }, personId);
    const service = await issueCredential(ctx.db, { identityId: machine.identity.id, kind: "service" });
    const before = (await revocations()).length;

    await ctx.db.query(`DELETE FROM "session" WHERE id = 'ses_a'`);

    expect(await works(a1.token)).toBe(false);
    expect(await works(a2.token)).toBe(false);
    expect(await authenticateBearer(ctx.db, a1.token)).toEqual({ ok: false, reason: "revoked" });
    for (const token of [b.token, handoff.token, cli.token, service.token]) expect(await works(token)).toBe(true);
    const lines = (await revocations()).slice(before);
    expect(lines.map((l) => l.credential_id)).toEqual([a1.credentialId, a2.credentialId].sort());
    for (const line of lines) {
      expect(line).toMatchObject({
        actor_identity_id: null, organization_id: null, decision: "info",
        resource: { identityId: personId }, metadata: { kind: "browser", reason: "session-ended" },
      });
      // The shape of db/ids.ts: evt_ and 128 random bits in lowercase base32.
      expect(line.id).toMatch(/^evt_[a-z2-7]{26}$/);
    }
    expect(new Set(lines.map((l) => l.id)).size).toBe(lines.length);
  });

  it("leaves credentials that already ended alone, and records nothing for them", async () => {
    const expired = await browser("ses_a", -1);
    const revoked = await browser("ses_a");
    await ctx.db.query("UPDATE credentials SET revoked_at = now() - interval '1 minute' WHERE id = $1", [revoked.credentialId]);
    const before = await ctx.db.query("SELECT id, revoked_at FROM credentials WHERE id = ANY($1) ORDER BY id", [[expired.credentialId, revoked.credentialId]]);
    const lines = (await revocations()).length;
    await ctx.db.query(`DELETE FROM "session" WHERE id = 'ses_a'`);
    expect((await ctx.db.query("SELECT id, revoked_at FROM credentials WHERE id = ANY($1) ORDER BY id", [[expired.credentialId, revoked.credentialId]])).rows).toEqual(before.rows);
    expect((await revocations()).length).toBe(lines);
  });

  it("a session without credentials ends without an audit line", async () => {
    const events = async () => ((await ctx.db.query("SELECT count(*)::int AS n FROM audit_events")).rows[0] as { n: number }).n;
    const before = await events();
    await ctx.db.query(`DELETE FROM "session" WHERE id = 'ses_b'`);
    expect(await events()).toBe(before);
  });

  it("covers bulk deletes and the cascade from a deleted Better Auth user, one line per credential", async () => {
    const tokens = [await browser("ses_a"), await browser("ses_b"), await browser("ses_b")];
    // All of a person's sessions in one statement, as Better Auth's revoke-sessions does.
    await ctx.db.query(`DELETE FROM "session" WHERE "userId" = 'bau_p'`);
    for (const t of tokens) expect(await works(t.token)).toBe(false);
    expect((await revocations()).map((l) => l.credential_id)).toEqual(tokens.map((t) => t.credentialId).sort());

    await session("ses_c");
    const c = await browser("ses_c");
    await ctx.db.query(`DELETE FROM "user" WHERE id = 'bau_p'`);
    expect(await works(c.token)).toBe(false);
    expect((await revocations()).at(-1)).toMatchObject({ credential_id: c.credentialId, metadata: { reason: "session-ended" } });
  });

  it("the public-URL change still records each browser credential once, with its own reason", async () => {
    const a = await browser("ses_a");
    const b = await browser("ses_b");
    await completePublicUrlChange(ctx, { from: "https://vault.example.com", to: "https://vault.example.org" });
    expect(await works(a.token)).toBe(false);
    expect(await works(b.token)).toBe(false);
    const lines = await revocations();
    expect(lines.map((l) => l.credential_id).sort()).toEqual([a.credentialId, b.credentialId].sort());
    for (const line of lines) expect(line.metadata).toEqual({ reason: "public-url-changed" });
  });
});

describe("the session exchange (/auth/varlatch-token)", () => {
  let current: { identityId: string; sessionId: string } | null;
  let app: ReturnType<typeof buildApp>;
  beforeEach(() => {
    current = { identityId: personId, sessionId: "ses_a" };
    const humanAuth: HumanAuth = {
      handler: async () => new Response(null, { status: 404 }),
      sessionFor: async () => current,
      close: async () => undefined,
    };
    app = buildApp(ctx, { humanAuth });
  });
  const exchange = () => app.request("/auth/varlatch-token", { method: "POST" });

  it("mints a 15-minute bearer from a live session", async () => {
    const res = await exchange();
    expect(res.status).toBe(200);
    const body = (await res.json()) as { token: string; expiresAt: string };
    expect(Date.parse(body.expiresAt) - Date.now()).toBeGreaterThan(14 * 60_000);
    expect(await works(body.token)).toBe(true);
    await ctx.db.query(`DELETE FROM "session" WHERE id = 'ses_a'`);
    expect(await works(body.token)).toBe(false);
  });

  it("refuses a session that ended after it was read, and another person's session", async () => {
    // Better Auth answered for the session, then a sign-out deleted it before the bearer was issued.
    await ctx.db.query(`DELETE FROM "session" WHERE id = 'ses_a'`);
    expect((await exchange()).status).toBe(401);
    current = { identityId: personId, sessionId: "ses_unknown" };
    expect((await exchange()).status).toBe(401);
    // A session row of another Better Auth user never mints for this person.
    await ctx.db.query(`INSERT INTO "user" (id, name, email) VALUES ('bau_q', 'Sam', 'q@varlatch.placeholder.invalid')`);
    await ctx.db.query(`INSERT INTO "session" (id, "expiresAt", token, "userId") VALUES ('ses_q', now() + interval '1 day', 'tok_q', 'bau_q')`);
    current = { identityId: personId, sessionId: "ses_q" };
    expect((await exchange()).status).toBe(401);
    expect(((await ctx.db.query("SELECT count(*)::int AS n FROM credentials WHERE kind = 'browser'")).rows[0] as { n: number }).n).toBe(0);
  });

  it("never outlives the session's own expiry", async () => {
    await session("ses_short", "now() + interval '2 minutes'");
    current = { identityId: personId, sessionId: "ses_short" };
    const res = await exchange();
    expect(res.status).toBe(200);
    const { expiresAt } = (await res.json()) as { expiresAt: string };
    const sessionExpiry = ((await ctx.db.query(`SELECT "expiresAt" AS e FROM "session" WHERE id = 'ses_short'`)).rows[0] as { e: Date }).e;
    expect(Date.parse(expiresAt)).toBe(new Date(sessionExpiry).getTime());
    await session("ses_expired", "now() - interval '1 second'");
    current = { identityId: personId, sessionId: "ses_expired" };
    expect((await exchange()).status).toBe(401);
  });
});
