// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { MIGRATIONS } from "../src/db/migrations/index.js";
import { runMigrations } from "../src/db/migrate.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import { PASSKEY_CONFIRMATION, credentialEvidence, quarantineReport, quarantinedPasskeys, recordSessionEvidence } from "../src/domain/passkeys.js";
import { buildApp } from "../src/http/app.js";
import { newId } from "../src/db/ids.js";
import { PUBLIC_URL, RP, deviceClient } from "./helpers/device-sign-in.js";
import { migratedTestDb, testDb } from "./helpers/pglite.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * Passkey provenance and sign-in evidence (ADR-0054 Decisions 4 and 6),
 * without Better Auth: the /v1 routes, the confirmation ceremony, device
 * sign-in evidence and the CLI handoff's session link. The Better Auth
 * ceremonies themselves (enrollment, sign-in, the disabled native removal)
 * run against real PostgreSQL in passkey-evidence-postgres.test.ts.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let adminId: string;

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  adminId = (await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" })).identityId;
  app = buildApp(ctx, { publicUrl: PUBLIC_URL, clientAddress: () => "203.0.113.7" });
});
afterEach(async () => {
  await ctx.close();
});

const rows = async (sql: string, params: unknown[] = []) => (await ctx.db.query(sql, params)).rows as any[];

async function call(method: string, path: string, token: string, body?: unknown) {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, body: res.status === 204 ? null : ((await res.json().catch(() => null)) as any), headers: res.headers };
}

/** A person with a dashboard bearer for one Better Auth session. */
async function person(name: string, identityId?: string) {
  const id = identityId ?? newId("identity");
  if (!identityId) await ctx.db.query("INSERT INTO identities (id, kind, name) VALUES ($1, 'human', $2)", [id, name]);
  const session = async (sessionId = `session-${id}`) =>
    (await issueCredential(ctx.db, {
      identityId: id,
      kind: "browser",
      expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      authSessionId: sessionId,
    })).token;
  return {
    id,
    session,
    token: await session(),
    key: (trust?: "trusted" | "unconfirmed") => registerSoftPasskey(ctx.db, id, { ...RP, ...(trust ? { trust } : {}) }),
  };
}

const startConfirmation = (token: string, passkeyId: string) => call("POST", `/v1/me/passkeys/${passkeyId}/confirmation/options`, token);
const finishConfirmation = (token: string, passkeyId: string, assertion: unknown) =>
  call("POST", `/v1/me/passkeys/${passkeyId}/confirmation`, token, { assertion });
async function confirmWith(token: string, target: string, by: SoftAuthenticator, assertOptions: { userVerified?: boolean } = {}) {
  const started = await startConfirmation(token, target);
  expect(started.status).toBe(200);
  return finishConfirmation(token, target, by.assert(started.body.publicKey.challenge, assertOptions));
}
const trustOf = async (passkeyId: string) =>
  (await rows("SELECT trust, trusted_via, confirmed_by_passkey_id FROM passkey_provenance WHERE passkey_id = $1", [passkeyId]))[0] ?? null;

describe("migration 39", () => {
  it("trusts every passkey that exists at the upgrade, and records no evidence for what came before", async () => {
    const db = await testDb();
    try {
      await db.exec!("CREATE TABLE varlatch_migrations (id integer PRIMARY KEY, name text NOT NULL)");
      for (const migration of MIGRATIONS.filter((m) => m.id <= 38)) {
        await db.exec!(migration.sql);
        await db.query("INSERT INTO varlatch_migrations VALUES ($1,$2)", [migration.id, migration.name]);
      }
      await db.query("INSERT INTO identities(id,kind,name) VALUES ('idn_a','human','A')");
      await db.query(`INSERT INTO "user"(id,name,email) VALUES ('bau_a','A','a@varlatch.placeholder.invalid')`);
      await db.query("INSERT INTO auth_user_links(better_auth_user_id, identity_id) VALUES ('bau_a','idn_a')");
      await db.query(`INSERT INTO passkey(id,"publicKey","userId","credentialID",counter,"deviceType","backedUp")
        VALUES ('pk_1','k','bau_a','c1',0,'singleDevice',false), ('pk_2','k','bau_a','c2',0,'multiDevice',true)`);
      // Two later rows with an existing credential id, as nothing refused them before this migration.
      await db.query(`INSERT INTO passkey(id,name,"publicKey","userId","credentialID",counter,"deviceType","backedUp",transports,"createdAt",aaguid)
        VALUES ('pk_0dup','copy','k0','bau_a','c1',3,'singleDevice',false,'usb','2026-11-01T10:00:00Z','aa-0'),
               ('pk_9dup',NULL,'k9','bau_a','c1',7,'multiDevice',true,NULL,'2026-11-02T10:00:00Z',NULL)`);
      await db.query(`INSERT INTO "session"(id,"expiresAt",token,"userId") VALUES ('ses_old', now() + interval '1 day', 't', 'bau_a')`);
      await db.query("INSERT INTO credentials(id,identity_id,kind,token_hash,auth_session_id) VALUES ('crd_web','idn_a','browser','h1','ses_old')");
      await db.query("INSERT INTO credentials(id,identity_id,kind,token_hash) VALUES ('crd_cli','idn_a','cli','h2')");

      expect((await runMigrations(db)).applied.map((m) => m.id)).toEqual([39, 40, 41, 42, 43, 44, 45, 46, 47, 49]);
      // The oldest row of a credential id stays (pk_1 has no date, so it sorts first) and is trusted, like every remaining passkey.
      expect((await db.query("SELECT passkey_id, trust, trusted_via, trusted_at IS NOT NULL AS dated FROM passkey_provenance ORDER BY passkey_id")).rows).toEqual([
        { passkey_id: "pk_1", trust: "trusted", trusted_via: "existing-at-upgrade", dated: true },
        { passkey_id: "pk_2", trust: "trusted", trusted_via: "existing-at-upgrade", dated: true },
      ]);
      // The later duplicates moved to the quarantine with every column, when, why, and which row was kept.
      expect((await db.query(`SELECT id FROM passkey WHERE "credentialID" = 'c1'`)).rows).toEqual([{ id: "pk_1" }]);
      expect((await db.query(
        `SELECT id, name, "publicKey", "userId", "credentialID", counter, "deviceType", "backedUp", transports, "createdAt", aaguid,
                reason, kept_passkey_id, quarantined_at IS NOT NULL AS dated
         FROM passkey_quarantine ORDER BY id`,
      )).rows).toEqual([
        { id: "pk_0dup", name: "copy", publicKey: "k0", userId: "bau_a", credentialID: "c1", counter: 3, deviceType: "singleDevice", backedUp: false,
          transports: "usb", createdAt: new Date("2026-11-01T10:00:00Z"), aaguid: "aa-0", reason: "duplicate-credential-id", kept_passkey_id: "pk_1", dated: true },
        { id: "pk_9dup", name: null, publicKey: "k9", userId: "bau_a", credentialID: "c1", counter: 7, deviceType: "multiDevice", backedUp: true,
          transports: null, createdAt: new Date("2026-11-02T10:00:00Z"), aaguid: null, reason: "duplicate-credential-id", kept_passkey_id: "pk_1", dated: true },
      ]);
      // The migrate command's report: same-person copies, with the kept passkey named.
      const quarantined = await quarantinedPasskeys(db);
      expect(quarantined.map((q) => [q.passkeyId, q.identityId, q.keptPasskeyId, q.samePerson, q.samePublicKey])).toEqual([
        ["pk_0dup", "idn_a", "pk_1", true, false],
        ["pk_9dup", "idn_a", "pk_1", true, false],
      ]);
      const report = quarantineReport(quarantined);
      expect(report[0]).toContain("Migration 39 moved 2 passkey(s) to passkey_quarantine");
      expect(report[1]).toContain("A [idn_a]: passkey pk_0dup; their passkey pk_1 with the same credential id was kept.");
      expect(report.at(-1)).toContain("varlatch admin reenroll --identity");
      expect(quarantineReport([])).toEqual([]);
      // A plain unique index: every passkey's credential id is unique.
      expect((await db.query("SELECT indexdef FROM pg_indexes WHERE indexname = 'passkey_credential_id_unique'")).rows).toEqual([
        { indexdef: 'CREATE UNIQUE INDEX passkey_credential_id_unique ON public.passkey USING btree ("credentialID")' },
      ]);
      const newPasskey = (id: string, credentialId: string) =>
        db.query(`INSERT INTO passkey(id,"publicKey","userId","credentialID",counter,"deviceType","backedUp") VALUES ($1,'k','bau_a',$2,0,'singleDevice',false)`, [id, credentialId]);
      await expect(newPasskey("pk_new1", "c1")).rejects.toThrow(/duplicate key/);
      await expect(newPasskey("pk_new2", "c2")).rejects.toThrow(/duplicate key/);
      await newPasskey("pk_new3", "c3");
      await expect(newPasskey("pk_new4", "c3")).rejects.toThrow(/duplicate key/);
      // No guessed evidence: old sessions and credentials stay unverified.
      expect((await db.query("SELECT * FROM auth_session_evidence")).rows).toEqual([]);
      expect((await db.query("SELECT id, evidence_user_verified, evidence_passkey_id FROM credentials ORDER BY id")).rows).toEqual([
        { id: "crd_cli", evidence_user_verified: null, evidence_passkey_id: null },
        { id: "crd_web", evidence_user_verified: null, evidence_passkey_id: null },
      ]);

      // A CLI credential may now link a session; evidence comes in pairs, on CLI credentials only, never with a session link.
      await db.query("UPDATE credentials SET auth_session_id = 'ses_old' WHERE id = 'crd_cli'");
      await expect(db.query("INSERT INTO credentials(id,identity_id,kind,token_hash,auth_session_id) VALUES ('crd_svc','idn_a','service','h3','s')")).rejects.toThrow(/check constraint/);
      await expect(db.query("UPDATE credentials SET evidence_user_verified = true WHERE id = 'crd_web'")).rejects.toThrow(/check constraint/);
      await expect(db.query("UPDATE credentials SET evidence_user_verified = true, evidence_passkey_id = 'pk_1' WHERE id = 'crd_web'")).rejects.toThrow(/check constraint/);
      await expect(db.query("UPDATE credentials SET evidence_user_verified = true, evidence_passkey_id = 'pk_1' WHERE id = 'crd_cli'")).rejects.toThrow(/check constraint/);
      await db.query("UPDATE credentials SET auth_session_id = NULL, evidence_user_verified = true, evidence_passkey_id = 'pk_1' WHERE id = 'crd_cli'");
      // Provenance is consistent: trusted says how, confirmed says by which key, unconfirmed says neither.
      await expect(db.query("UPDATE passkey_provenance SET trust = 'unconfirmed' WHERE passkey_id = 'pk_1'")).rejects.toThrow(/check constraint/);
      await expect(db.query("UPDATE passkey_provenance SET trusted_via = 'confirmed' WHERE passkey_id = 'pk_1'")).rejects.toThrow(/check constraint/);
      await expect(db.query("UPDATE passkey_provenance SET trusted_via = 'confirmed', confirmed_by_passkey_id = 'pk_1' WHERE passkey_id = 'pk_1'")).rejects.toThrow(/check constraint/);
      await db.query("UPDATE passkey_provenance SET trusted_via = 'confirmed', confirmed_by_passkey_id = 'pk_2' WHERE passkey_id = 'pk_1'");
      // Removing a passkey removes its provenance.
      await db.query("DELETE FROM passkey WHERE id = 'pk_2'");
      expect((await db.query("SELECT passkey_id FROM passkey_provenance WHERE passkey_id IN ('pk_1', 'pk_2')")).rows).toEqual([{ passkey_id: "pk_1" }]);
      expect((await runMigrations(db)).applied).toEqual([]);
    } finally {
      await db.close();
    }
  });
});

describe("migration 39 on an installation without duplicate credential ids", () => {
  it("makes the credential id unique for every passkey", async () => {
    const ada = await person("Ada");
    const key = await ada.key("trusted");
    await expect(
      ctx.db.query(`INSERT INTO passkey(id,"publicKey","userId","credentialID",counter,"deviceType","backedUp") VALUES ('pk_copy','k',$1,$2,0,'singleDevice',false)`, [
        `bau_${ada.id}`,
        key.credentialId,
      ]),
    ).rejects.toThrow(/duplicate key/);
  });
});

describe("migration 40: a passkey's signature counter only moves forward", () => {
  it("refuses any write that does not increase a counter above zero, and allows 0 over 0", async () => {
    const ada = await person("Ada");
    const key = await ada.key("trusted");
    const set = (counter: number) => ctx.db.query("UPDATE passkey SET counter = $2 WHERE id = $1", [key.passkeyId, counter]);
    const counter = async () => (await rows("SELECT counter FROM passkey WHERE id = $1", [key.passkeyId]))[0].counter as number;
    // An authenticator without a counter reports 0 every time.
    await set(0);
    await set(0);
    await set(1);
    await set(5);
    for (const lower of [5, 4, 1, 0]) await expect(set(lower)).rejects.toThrow(/signature counter/);
    expect(await counter()).toBe(5);
    // Writes that leave the counter out are not checked: renaming a passkey.
    await ctx.db.query("UPDATE passkey SET name = 'renamed' WHERE id = $1", [key.passkeyId]);
    await set(6);
    expect(await counter()).toBe(6);
  });
});

describe("GET /v1/me/passkeys", () => {
  it("lists the caller's own passkeys with their provenance; a passkey without a record is unconfirmed", async () => {
    const ada = await person("Ada");
    const trusted = await ada.key("trusted");
    const added = await ada.key("unconfirmed");
    const unrecorded = await ada.key();
    await (await person("Bob")).key("trusted");
    const res = await call("GET", "/v1/me/passkeys", ada.token);
    expect(res.status).toBe(200);
    expect(res.body.nextCursor).toBeNull();
    const byId = Object.fromEntries(res.body.items.map((p: any) => [p.id, p]));
    expect(Object.keys(byId).sort()).toEqual([trusted.passkeyId, added.passkeyId, unrecorded.passkeyId].sort());
    expect(byId[trusted.passkeyId]).toMatchObject({ trust: "trusted", trustedVia: "setup-grant", setupGrantKind: "invite", confirmedByPasskeyId: null });
    expect(byId[added.passkeyId]).toMatchObject({ trust: "unconfirmed", trustedVia: null, trustedAt: null });
    expect(byId[unrecorded.passkeyId]).toMatchObject({ trust: "unconfirmed", trustedVia: null });
    // Never key material: no public key, no credential id.
    expect(Object.keys(byId[trusted.passkeyId]).sort()).toEqual(
      ["backedUp", "confirmedByPasskeyId", "createdAt", "deviceType", "id", "name", "setupGrantKind", "trust", "trustedAt", "trustedVia"],
    );
  });

  it("is empty for a machine, and the capability is advertised", async () => {
    await ctx.db.query("INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_a', 'acme', 'Acme', '{}')");
    await ctx.db.query("INSERT INTO identities (id, kind, name, organization_id) VALUES ('idn_svc', 'service', 'deployer', 'org_a')");
    const { token } = await issueCredential(ctx.db, { identityId: "idn_svc", kind: "service" });
    expect((await call("GET", "/v1/me/passkeys", token)).body).toEqual({ items: [], nextCursor: null });
    const meta = await app.request("/v1/meta");
    expect(((await meta.json()) as { capabilities: string[] }).capabilities).toContain("account.passkeys");
  });
});

describe("confirming a passkey with a trusted one", () => {
  it("asks for one of the person's trusted passkeys, with user verification, and then trusts the new one", async () => {
    const ada = await person("Ada");
    const trusted = await ada.key("trusted");
    const otherTrusted = await ada.key("trusted");
    const added = await ada.key("unconfirmed");
    const alsoAdded = await ada.key("unconfirmed");

    const started = await startConfirmation(ada.token, added.passkeyId);
    expect(started.status).toBe(200);
    expect(started.headers.get("Cache-Control")).toBe("no-store");
    expect(started.body.publicKey.userVerification).toBe("required");
    expect(started.body.publicKey.allowCredentials.map((c: { id: string }) => c.id).sort()).toEqual(
      [trusted.credentialId, otherTrusted.credentialId].sort(),
    );

    const done = await finishConfirmation(ada.token, added.passkeyId, trusted.assert(started.body.publicKey.challenge));
    expect(done.status).toBe(200);
    expect(done.body).toMatchObject({ id: added.passkeyId, trust: "trusted", trustedVia: "confirmed", confirmedByPasskeyId: trusted.passkeyId });
    expect(await trustOf(added.passkeyId)).toEqual({ trust: "trusted", trusted_via: "confirmed", confirmed_by_passkey_id: trusted.passkeyId });
    const events = await rows("SELECT actor_identity_id, decision, resource, metadata FROM audit_events WHERE event_type = 'authentication.passkey_confirmed'");
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ actor_identity_id: ada.id, decision: "info", resource: { passkeyId: added.passkeyId } });
    expect(events[0].metadata).toMatchObject({ confirmedByPasskeyId: trusted.passkeyId, userVerified: true });

    // A confirmed passkey is a trusted one: it can confirm the next.
    expect((await confirmWith(ada.token, alsoAdded.passkeyId, added)).body).toMatchObject({ trust: "trusted", confirmedByPasskeyId: added.passkeyId });
    // Nothing to confirm on a trusted key.
    expect((await startConfirmation(ada.token, trusted.passkeyId)).body.error.code).toBe("STATE_CHANGED");
  });

  it("refuses an assertion without user verification, and the challenge is used up", async () => {
    const ada = await person("Ada");
    const trusted = await ada.key("trusted");
    const added = await ada.key("unconfirmed");
    const started = await startConfirmation(ada.token, added.passkeyId);
    const refused = await finishConfirmation(ada.token, added.passkeyId, trusted.assert(started.body.publicKey.challenge, { userVerified: false }));
    expect(refused.status).toBe(403);
    expect(refused.body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "user-verification-required" } });
    expect(await trustOf(added.passkeyId)).toMatchObject({ trust: "unconfirmed" });
    const again = await finishConfirmation(ada.token, added.passkeyId, trusted.assert(started.body.publicKey.challenge));
    expect(again.body.error.details).toEqual({ reason: "challenge" });
    const failures = await rows("SELECT metadata FROM audit_events WHERE event_type = 'authentication.failed' ORDER BY event_order");
    expect(failures.map((f) => f.metadata)).toEqual([
      { method: "passkey-confirmation", reason: "user-verification-required" },
      { method: "passkey-confirmation", reason: "challenge" },
    ]);
  });

  it("accepts only a trusted passkey of the same person: not the key itself, not another unconfirmed one, not someone else's", async () => {
    const ada = await person("Ada");
    await ada.key("trusted");
    const added = await ada.key("unconfirmed");
    const otherAdded = await ada.key("unconfirmed");
    const bob = await person("Bob");
    const bobs = await bob.key("trusted");
    for (const by of [added, otherAdded, bobs]) {
      const res = await confirmWith(ada.token, added.passkeyId, by);
      expect(res.status).toBe(403);
      expect(res.body.error.details).toEqual({ reason: "unknown-passkey" });
    }
    expect(await trustOf(added.passkeyId)).toMatchObject({ trust: "unconfirmed" });
    // A tampered signature by a trusted key is no better.
    const trusted = (await ada.key("trusted"));
    const started = await startConfirmation(ada.token, added.passkeyId);
    const tampered = await finishConfirmation(ada.token, added.passkeyId, trusted.assert(started.body.publicKey.challenge, { tamper: true }));
    expect(tampered.body.error.details).toEqual({ reason: "invalid-assertion" });
  });

  it("binds the challenge to the passkey being confirmed and to the session, once, until it expires", async () => {
    const ada = await person("Ada");
    const trusted = await ada.key("trusted");
    const first = await ada.key("unconfirmed");
    const second = await ada.key("unconfirmed");
    const forFirst = await startConfirmation(ada.token, first.passkeyId);
    // Used for another passkey: refused, and the second stays unconfirmed.
    const crossed = await finishConfirmation(ada.token, second.passkeyId, trusted.assert(forFirst.body.publicKey.challenge));
    expect(crossed.body.error.details).toEqual({ reason: "challenge" });
    expect(await trustOf(second.passkeyId)).toMatchObject({ trust: "unconfirmed" });
    // From another session of the same person: refused.
    const otherSession = await ada.session("another-session");
    const elsewhere = await finishConfirmation(otherSession, first.passkeyId, trusted.assert(forFirst.body.publicKey.challenge));
    expect(elsewhere.body.error.details).toEqual({ reason: "challenge" });
    // The right passkey and session: accepted, once.
    const ok = await finishConfirmation(ada.token, first.passkeyId, trusted.assert(forFirst.body.publicKey.challenge));
    expect(ok.status).toBe(200);
    // Expired on the live clock: refused.
    const forSecond = await startConfirmation(ada.token, second.passkeyId);
    await ctx.db.query("UPDATE passkey_confirmation_challenges SET expires_at = clock_timestamp() - interval '1 second' WHERE challenge = $1", [
      forSecond.body.publicKey.challenge,
    ]);
    const late = await finishConfirmation(ada.token, second.passkeyId, trusted.assert(forSecond.body.publicKey.challenge));
    expect(late.body.error.details).toEqual({ reason: "challenge" });
    // A newer challenge replaces an unused older one for the same passkey and session.
    const older = await startConfirmation(ada.token, second.passkeyId);
    const newer = await startConfirmation(ada.token, second.passkeyId);
    expect((await finishConfirmation(ada.token, second.passkeyId, trusted.assert(older.body.publicKey.challenge))).body.error.details).toEqual({ reason: "challenge" });
    expect((await finishConfirmation(ada.token, second.passkeyId, trusted.assert(newer.body.publicKey.challenge))).status).toBe(200);
  });

  it("is the person's own, from the dashboard, with a trusted key to confirm with, and rate-limited", async () => {
    const ada = await person("Ada");
    const added = await ada.key("unconfirmed");
    const bob = await person("Bob");
    const bobsAdded = await bob.key("unconfirmed");
    await bob.key("trusted");
    // Someone else's passkey is not found.
    expect((await startConfirmation(ada.token, bobsAdded.passkeyId)).body.error.code).toBe("RESOURCE_NOT_FOUND");
    // No trusted passkey: the way back is the host operator.
    const none = await startConfirmation(ada.token, added.passkeyId);
    expect(none.status).toBe(403);
    expect(none.body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "no-trusted-passkey" } });
    expect(none.body.error.message).toContain("admin reenroll");
    // A CLI credential cannot run the ceremony.
    const { token: cli } = await issueCredential(ctx.db, { identityId: ada.id, kind: "cli" });
    expect((await startConfirmation(cli, added.passkeyId)).body.error.code).toBe("PERMISSION_DENIED");
    // At most challengesPerWindow starts per person per window, across sessions.
    await ada.key("trusted");
    for (let i = 0; i < PASSKEY_CONFIRMATION.challengesPerWindow; i++) {
      const token = i % 2 ? ada.token : await ada.session(`s-${i}`);
      expect((await startConfirmation(token, added.passkeyId)).status).toBe(200);
    }
    const limited = await startConfirmation(ada.token, added.passkeyId);
    expect(limited.status).toBe(429);
    expect(limited.body.error).toMatchObject({ code: "RATE_LIMITED" });
    expect(typeof limited.body.error.details.retryAt).toBe("string");
  });
});

describe("removing a passkey through Varlatch", () => {
  it("removes the caller's own passkey, provenance included, and never someone else's", async () => {
    const ada = await person("Ada");
    const first = await ada.key("trusted");
    const second = await ada.key("unconfirmed");
    const bob = await person("Bob");
    const bobs = await bob.key("trusted");

    expect((await call("DELETE", `/v1/me/passkeys/${bobs.passkeyId}`, ada.token)).body.error.code).toBe("RESOURCE_NOT_FOUND");
    expect((await call("DELETE", "/v1/me/passkeys/pk_nothing", ada.token)).body.error.code).toBe("RESOURCE_NOT_FOUND");
    expect(await rows("SELECT id FROM passkey WHERE id = $1", [bobs.passkeyId])).toHaveLength(1);

    // As Better Auth's own removal, with no restriction: trusted or not, and with no audit event of its own.
    const auditBefore = (await rows("SELECT count(*)::int AS n FROM audit_events"))[0].n;
    expect((await call("DELETE", `/v1/me/passkeys/${second.passkeyId}`, ada.token)).status).toBe(204);
    expect((await call("DELETE", `/v1/me/passkeys/${first.passkeyId}`, ada.token)).status).toBe(204);
    expect(await rows("SELECT id FROM passkey WHERE id IN ($1, $2)", [first.passkeyId, second.passkeyId])).toEqual([]);
    expect(await rows("SELECT passkey_id FROM passkey_provenance WHERE passkey_id IN ($1, $2)", [first.passkeyId, second.passkeyId])).toEqual([]);
    expect((await rows("SELECT count(*)::int AS n FROM audit_events"))[0].n).toBe(auditBefore);
  });

  it("takes the dashboard's session bearer, as the native removal took the session cookie", async () => {
    const ada = await person("Ada");
    const key = await ada.key("trusted");
    const { token: cli } = await issueCredential(ctx.db, { identityId: ada.id, kind: "cli" });
    expect((await call("DELETE", `/v1/me/passkeys/${key.passkeyId}`, cli)).body.error.code).toBe("PERMISSION_DENIED");
    expect(await rows("SELECT id FROM passkey WHERE id = $1", [key.passkeyId])).toHaveLength(1);
  });
});

describe("sweeping session evidence", () => {
  it("keeps the evidence a live credential links, however old the sign-in; sweeps what nothing can use", async () => {
    const ada = await person("Ada");
    const key = await ada.key("trusted");
    const userId = `bau_${ada.id}`;
    const evidence = (sessionId: string, age: string) =>
      ctx.db.query(
        `INSERT INTO auth_session_evidence (session_id, ceremony, user_verified, passkey_id, recorded_at)
         VALUES ($1, 'sign-in', true, $2, now() - $3::interval)`,
        [sessionId, key.passkeyId, age],
      );
    const cliFor = (sessionId: string, extra: { expiresAt?: string } = {}) =>
      issueCredential(ctx.db, { identityId: ada.id, kind: "cli", authSessionId: sessionId, expiresAt: extra.expiresAt ?? new Date(Date.now() + 3_600_000).toISOString() });
    // A 3-day-old sign-in handed to a fresh CLI credential, then signed out: its session row is gone.
    await evidence("ses_handed_off", "3 days");
    const live = await cliFor("ses_handed_off");
    // Ended sessions nothing live links: no credential, a revoked one, an expired one.
    await evidence("ses_unlinked", "3 days");
    await evidence("ses_revoked", "3 days");
    await ctx.db.query("UPDATE credentials SET revoked_at = now() WHERE id = $1", [(await cliFor("ses_revoked")).credentialId]);
    await evidence("ses_expired", "3 days");
    await cliFor("ses_expired", { expiresAt: new Date(Date.now() - 60_000).toISOString() });
    // A session that has not ended, with no credential at all.
    const openSession = (id: string) =>
      ctx.db.query(`INSERT INTO "session" (id, "expiresAt", token, "userId") VALUES ($1, now() + interval '1 day', $1, $2)`, [id, userId]);
    await openSession("ses_open");
    await evidence("ses_open", "3 days");

    // Another sign-in runs the sweep.
    await openSession("ses_next");
    expect(await recordSessionEvidence(ctx.db, { sessionId: "ses_next", betterAuthUserId: userId, credentialId: key.credentialId, userVerified: true, ceremony: "sign-in" })).toBe(true);
    expect((await rows("SELECT session_id FROM auth_session_evidence ORDER BY session_id")).map((r) => r.session_id)).toEqual(["ses_handed_off", "ses_next", "ses_open"]);
    expect(await credentialEvidence(ctx.db, live.credentialId)).toMatchObject({ source: "session", userVerified: true, passkeyId: key.passkeyId });

    // Once the CLI credential is revoked, the next sweep removes it.
    await ctx.db.query("UPDATE credentials SET revoked_at = now() WHERE id = $1", [live.credentialId]);
    await openSession("ses_after");
    await recordSessionEvidence(ctx.db, { sessionId: "ses_after", betterAuthUserId: userId, credentialId: key.credentialId, userVerified: true, ceremony: "sign-in" });
    expect((await rows("SELECT session_id FROM auth_session_evidence ORDER BY session_id")).map((r) => r.session_id)).toEqual(["ses_after", "ses_next", "ses_open"]);
  });
});

describe("sign-in evidence on credentials", () => {
  it("device sign-in carries the approval's evidence onto the CLI credential, user verification recorded, not required", async () => {
    const client = deviceClient(() => app);
    const ada = await person("Ada", adminId);
    for (const userVerified of [false, true]) {
      const key = await ada.key(userVerified ? "trusted" : "unconfirmed");
      const started = (await client.start()).body;
      const found = await client.lookup(ada.token, started.userCode);
      expect(found.body.approval.publicKey.userVerification).toBe("preferred");
      const approved = await client.decide(ada.token, started.userCode, "approve", key.assert(found.body.approval.publicKey.challenge, { userVerified }));
      expect(approved.status).toBe(200);
      expect((await rows("SELECT approval_user_verified, approval_passkey_id FROM device_sign_ins WHERE user_code = $1", [started.userCode.replace("-", "")]))[0])
        .toEqual({ approval_user_verified: userVerified, approval_passkey_id: key.passkeyId });
      const issued = await client.poll(started.deviceCode);
      expect(issued.status).toBe(201);
      expect((await rows("SELECT auth_session_id, evidence_user_verified, evidence_passkey_id FROM credentials WHERE id = $1", [issued.body.id]))[0])
        .toEqual({ auth_session_id: null, evidence_user_verified: userVerified, evidence_passkey_id: key.passkeyId });
      expect(await credentialEvidence(ctx.db, issued.body.id)).toEqual({
        source: "credential", userVerified, passkeyId: key.passkeyId, passkeyTrusted: userVerified,
      });
    }
  });

  it("a device sign-in approved before the upgrade yields a CLI credential without evidence", async () => {
    const client = deviceClient(() => app);
    const ada = await person("Ada", adminId);
    const key = await ada.key("trusted");
    const started = (await client.start()).body;
    await client.approve(ada.token, started.userCode, key);
    await ctx.db.query("UPDATE device_sign_ins SET approval_user_verified = NULL, approval_passkey_id = NULL");
    const issued = await client.poll(started.deviceCode);
    expect(await credentialEvidence(ctx.db, issued.body.id)).toBeNull();
  });

  it("the CLI handoff credential links the browser session, and so carries its evidence", async () => {
    const ada = await person("Ada", adminId);
    const key = await ada.key("unconfirmed");
    const browser = await ada.session("ses_browser");
    const res = await call("POST", "/v1/me/credentials/cli", browser, { ttlSeconds: 3600 });
    expect(res.status).toBe(201);
    expect((await rows("SELECT kind, auth_session_id, evidence_passkey_id FROM credentials WHERE id = $1", [res.body.id]))[0])
      .toEqual({ kind: "cli", auth_session_id: "ses_browser", evidence_passkey_id: null });
    // The session has no evidence: unverified.
    expect(await credentialEvidence(ctx.db, res.body.id)).toBeNull();
    await ctx.db.query(
      "INSERT INTO auth_session_evidence (session_id, ceremony, user_verified, passkey_id) VALUES ('ses_browser', 'sign-in', true, $1)",
      [key.passkeyId],
    );
    expect(await credentialEvidence(ctx.db, res.body.id)).toEqual({ source: "session", userVerified: true, passkeyId: key.passkeyId, passkeyTrusted: false });
    // Provenance is read when the evidence is used: confirming the key later counts.
    await ctx.db.query("UPDATE passkey_provenance SET trust = 'trusted', trusted_via = 'confirmed', trusted_at = now(), confirmed_by_passkey_id = 'pk_other' WHERE passkey_id = $1", [key.passkeyId]);
    expect(await credentialEvidence(ctx.db, res.body.id)).toMatchObject({ passkeyTrusted: true });
    // And a removed key no longer counts.
    await ctx.db.query("DELETE FROM passkey WHERE id = $1", [key.passkeyId]);
    expect(await credentialEvidence(ctx.db, res.body.id)).toMatchObject({ passkeyTrusted: false });
    // The CLI credential is still no approver for device sign-in: only the dashboard's bearer is.
    const client = deviceClient(() => app);
    const started = (await client.start()).body;
    expect((await client.lookup(res.body.token, started.userCode)).body.error.code).toBe("PERMISSION_DENIED");
  });
});
