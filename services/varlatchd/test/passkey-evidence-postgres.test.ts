// SPDX-License-Identifier: AGPL-3.0-or-later
import pg from "pg";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import { MIGRATIONS } from "../src/db/migrations/index.js";
import { buildHumanAuth, type HumanAuth } from "../src/auth/humanauth.js";
import { verifyAssertion } from "../src/auth/approval-assertion.js";
import { withTx } from "../src/db/tx.js";
import { ensureInstallation, issueBootstrapGrant, issueReenrollmentGrants } from "../src/domain/bootstrap.js";
import { credentialEvidence, quarantineReport, quarantinedPasskeys } from "../src/domain/passkeys.js";
import { buildApp } from "../src/http/app.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { softAuthenticator, type UnregisteredAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * Passkey provenance and sign-in evidence through Better Auth itself
 * (ADR-0054 Decisions 4 and 6), on real PostgreSQL: Better Auth keeps its
 * own connection pool, which PGlite cannot serve. Enrollment through a
 * setup grant, a passkey added by a signed-in session, sign-in evidence
 * written to the ceremony's own session only (concurrent sign-ins of one
 * person included), the signature counter under concurrent assertions of
 * one passkey, the CLI handoff's session link, and the native passkey
 * removal turned off.
 */
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("passkey evidence through Better Auth on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let humanAuth: HumanAuth;
  let app: ReturnType<typeof buildApp>;
  const database = `varlatch_pkev_test_${process.pid}`;
  const rows = async (sql: string, params: unknown[] = []) => (await db.query(sql, params)).rows as any[];

  beforeEach(async () => {
    admin = createPgQuerier(url!);
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${database}`);
    const target = new URL(url!);
    target.pathname = `/${database}`;
    db = createPgQuerier(target.toString());
    const connection = await db.connect();
    try { await runMigrations(connection); } finally { connection.release(); }
    ctx = { db, rootKek: Buffer.alloc(32, 29) };
    await ensureInstallation(ctx);
    humanAuth = buildHumanAuth({ ctx, databaseUrl: target.toString(), publicUrl: PUBLIC_URL });
    app = buildApp(ctx, { publicUrl: PUBLIC_URL, humanAuth, clientAddress: () => "203.0.113.7" });
  });
  afterEach(async () => {
    await humanAuth?.close();
    await db?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
      await admin.end();
    }
  });

  /** One browser: its cookies, kept between requests as a browser would. */
  class Browser {
    cookies = new Map<string, string>();
    async request(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
      const res = await app.request(`${PUBLIC_URL}${path}`, {
        method,
        headers: {
          Origin: RP.origin,
          ...(this.cookies.size ? { Cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ") } : {}),
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
          ...headers,
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      for (const cookie of res.headers.getSetCookie()) {
        const [pair] = cookie.split(";");
        const eq = pair!.indexOf("=");
        const name = pair!.slice(0, eq);
        const value = pair!.slice(eq + 1);
        if (value === "" || /max-age=0/i.test(cookie)) this.cookies.delete(name);
        else this.cookies.set(name, value);
      }
      const text = await res.text();
      let parsed: any = null;
      try { parsed = text ? JSON.parse(text) : null; } catch { parsed = text; }
      return { status: res.status, body: parsed };
    }

    /** Better Auth's passkey enrollment, with a setup token as `context` or within this browser's session. */
    async enroll(authenticator: UnregisteredAuthenticator, input: { context?: string; createSession?: boolean; userVerified?: boolean; credentialId?: string } = {}) {
      const query = input.context ? `?context=${encodeURIComponent(input.context)}` : "";
      const options = await this.request("GET", `/auth/passkey/generate-register-options${query}`);
      expect(options.status).toBe(200);
      return this.request("POST", "/auth/passkey/verify-registration", {
        response: authenticator.attest(options.body.challenge, {
          ...(input.userVerified === undefined ? {} : { userVerified: input.userVerified }),
          ...(input.credentialId ? { credentialId: input.credentialId } : {}),
        }),
        name: "test key",
        ...(input.createSession ? { createSession: true } : {}),
      });
    }

    /** Better Auth's passkey sign-in; the options come first, so concurrent sign-ins can interleave after them. */
    async signInOptions() {
      const options = await this.request("GET", "/auth/passkey/generate-authenticate-options");
      expect(options.status).toBe(200);
      return options.body.challenge as string;
    }
    async signIn(authenticator: UnregisteredAuthenticator, challenge: string, userVerified = true) {
      const res = await this.request("POST", "/auth/passkey/verify-authentication", {
        response: authenticator.assert(challenge, { userVerified }),
      });
      expect(res.status).toBe(200);
      return res.body.session.id as string;
    }

    /** The dashboard's /v1 bearer from this browser's session. */
    async bearer() {
      const res = await this.request("POST", "/auth/varlatch-token");
      expect(res.status).toBe(200);
      return res.body.token as string;
    }
  }

  async function bearerCall(method: string, path: string, token: string, body?: unknown) {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    return { status: res.status, body: res.status === 204 ? null : ((await res.json().catch(() => null)) as any) };
  }

  const provenance = async (credentialId: string) =>
    (await rows(
      `SELECT pp.trust, pp.trusted_via, pp.setup_grant_kind FROM passkey p LEFT JOIN passkey_provenance pp ON pp.passkey_id = p.id
       WHERE p."credentialID" = $1`,
      [credentialId],
    ))[0];
  const passkeyIdOf = async (credentialId: string) => (await rows(`SELECT id FROM passkey WHERE "credentialID" = $1`, [credentialId]))[0]?.id as string;
  const evidenceOf = async (sessionId: string) =>
    (await rows("SELECT ceremony, user_verified, passkey_id FROM auth_session_evidence WHERE session_id = $1", [sessionId]))[0] ?? null;

  /** Bootstrap through the enrollment page's ceremony: the first admin, their first passkey, and their browser. */
  async function bootstrapAdmin() {
    const grant = await issueBootstrapGrant(ctx);
    const browser = new Browser();
    const key = softAuthenticator(RP);
    const enrolled = await browser.enroll(key, { context: grant.token, createSession: true });
    expect(enrolled.status).toBe(200);
    const identityId = (await rows("SELECT identity_id FROM auth_user_links"))[0].identity_id as string;
    return { browser, key, identityId, sessionId: enrolled.body.session.id as string };
  }

  it("a setup grant enrolls a trusted passkey, and the session it creates carries that ceremony's evidence", async () => {
    const { key, sessionId } = await bootstrapAdmin();
    expect(await provenance(key.credentialId)).toEqual({ trust: "trusted", trusted_via: "setup-grant", setup_grant_kind: "bootstrap" });
    expect(await evidenceOf(sessionId)).toEqual({ ceremony: "enrollment", user_verified: true, passkey_id: await passkeyIdOf(key.credentialId) });
  });

  it("a reenroll grant, opened without a session, enrolls a trusted passkey too", async () => {
    const { identityId } = await bootstrapAdmin();
    const [link] = await issueReenrollmentGrants(ctx, { identityIds: [identityId] });
    const key = softAuthenticator(RP);
    const res = await new Browser().enroll(key, { context: link!.token, createSession: true });
    expect(res.status).toBe(200);
    expect(await provenance(key.credentialId)).toEqual({ trust: "trusted", trusted_via: "setup-grant", setup_grant_kind: "reenroll" });
  });

  it("a passkey added by a signed-in session is unconfirmed, even with a setup token, which it leaves unused", async () => {
    const { browser, identityId } = await bootstrapAdmin();
    const added = softAuthenticator(RP);
    expect((await browser.enroll(added)).status).toBe(200);
    expect(await provenance(added.credentialId)).toEqual({ trust: "unconfirmed", trusted_via: null, setup_grant_kind: null });

    const [link] = await issueReenrollmentGrants(ctx, { identityIds: [identityId] });
    const withToken = softAuthenticator(RP);
    expect((await browser.enroll(withToken, { context: link!.token })).status).toBe(200);
    expect(await provenance(withToken.credentialId)).toMatchObject({ trust: "unconfirmed" });
    expect((await rows("SELECT consumed_at FROM setup_grants WHERE kind = 'reenroll'"))[0].consumed_at).toBeNull();
  });

  it("refuses to register a credential id that is already registered", async () => {
    const { browser, key } = await bootstrapAdmin();
    const copy = softAuthenticator(RP);
    const res = await browser.enroll(copy, { credentialId: key.credentialId });
    expect(res.status).toBe(400);
    expect(await rows(`SELECT id FROM passkey WHERE "credentialID" = $1`, [key.credentialId])).toHaveLength(1);
  });

  /**
   * Browsers signed in as the bootstrap admin, each ready to post a
   * registration of `credentialId` (options already fetched). They sign in
   * one after another: concurrent assertions of one key race on its
   * signature counter, and only the registrations race here.
   */
  async function racingRegistrations(key: UnregisteredAuthenticator, count: number, credentialId: string) {
    const posts: Array<() => ReturnType<Browser["request"]>> = [];
    for (let i = 0; i < count; i++) {
      const browser = new Browser();
      await browser.signIn(key, await browser.signInOptions());
      const options = await browser.request("GET", "/auth/passkey/generate-register-options");
      expect(options.status).toBe(200);
      const response = softAuthenticator(RP).attest(options.body.challenge, { credentialId });
      posts.push(() => browser.request("POST", "/auth/passkey/verify-registration", { response, name: "racing key" }));
    }
    return posts;
  }

  it("concurrent registrations of one credential id store exactly one passkey; the others are a 400", async () => {
    const { key } = await bootstrapAdmin();
    for (let round = 0; round < 3; round++) {
      const credentialId = softAuthenticator(RP).credentialId;
      const posts = await racingRegistrations(key, 6, credentialId);
      const results = await Promise.all(posts.map((post) => post()));
      expect(results.map((r) => r.status).sort()).toEqual([200, 400, 400, 400, 400, 400]);
      for (const r of results.filter((r) => r.status === 400)) expect(r.body.message).toBe("This passkey is already registered");
      expect(await rows(`SELECT id FROM passkey WHERE "credentialID" = $1`, [credentialId])).toHaveLength(1);
      expect(await provenance(credentialId)).toMatchObject({ trust: "unconfirmed" });
    }
  });

  it("a registration that passes the early check but loses at the insert is a 400, not a server error", async () => {
    const { key, identityId } = await bootstrapAdmin();
    const credentialId = softAuthenticator(RP).credentialId;
    const [post] = await racingRegistrations(key, 1, credentialId);
    const userId = (await rows("SELECT better_auth_user_id FROM auth_user_links WHERE identity_id = $1", [identityId]))[0].better_auth_user_id;
    // Another registration of the same credential id, inserted but not committed: the early check cannot see it.
    const other = await db.connect();
    try {
      await other.query("BEGIN");
      await other.query(
        `INSERT INTO passkey (id, "publicKey", "userId", "credentialID", counter, "deviceType", "backedUp") VALUES ('pk_racer', 'k', $1, $2, 0, 'singleDevice', false)`,
        [userId, credentialId],
      );
      const pending = post!();
      // Better Auth's insert waits on the unique index for that transaction.
      let waited = false;
      for (let i = 0; i < 200 && !waited; i++) {
        waited = (await rows(
          "SELECT 1 FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock' AND query ILIKE '%insert into%passkey%'",
          [database],
        )).length > 0;
        if (!waited) await new Promise((resolve) => setTimeout(resolve, 25));
      }
      expect(waited).toBe(true);
      await other.query("COMMIT");
      const res = await pending;
      expect(res.status).toBe(400);
      expect(res.body.message).toBe("This passkey is already registered");
    } finally {
      other.release();
    }
    expect(await rows(`SELECT id FROM passkey WHERE "credentialID" = $1`, [credentialId])).toEqual([{ id: "pk_racer" }]);
  });

  it("a failure after the passkey row is written stays a 500, not a duplicate", async () => {
    const original = pg.Client.prototype.query;
    // The insert commits, then its acknowledgement is lost: a matching row exists, yet this request did not lose a race.
    const spy = vi.spyOn(pg.Client.prototype, "query").mockImplementation(function (this: pg.Client, ...args: unknown[]) {
      const [text, values] = args;
      const run = (original as (...a: unknown[]) => unknown).apply(this, args);
      if (typeof text === "string" && /insert into "passkey"/i.test(text) && Array.isArray(values) && values.includes("lost-ack")) {
        return (run as Promise<unknown>).then(() => { throw new Error("Connection terminated unexpectedly"); });
      }
      return run as never;
    });
    try {
      // Pooled clients pick the spy up when they connect, so it is in place before the first Better Auth query.
      const { browser: fresh } = await bootstrapAdmin();
      const added = softAuthenticator(RP);
      const options = await fresh.request("GET", "/auth/passkey/generate-register-options");
      const res = await fresh.request("POST", "/auth/passkey/verify-registration", { response: added.attest(options.body.challenge), name: "lost-ack" });
      expect(res.status).toBe(500);
      expect(JSON.stringify(res.body)).not.toContain("already registered");
      expect(await rows(`SELECT id FROM passkey WHERE "credentialID" = $1`, [added.credentialId])).toHaveLength(1);
      // Its provenance was never written: it counts as unconfirmed.
      expect(await provenance(added.credentialId)).toEqual({ trust: null, trusted_via: null, setup_grant_kind: null });
    } finally {
      spy.mockRestore();
    }
  });

  /**
   * A database at migration 38, seeded by `seed`, then migrated to the latest and
   * served by its own Better Auth while `body` runs (Browser talks to it).
   */
  async function withUpgradedDatabase(
    seed: (connection: { query: (sql: string, params?: unknown[]) => Promise<unknown> }) => Promise<void>,
    body: (legacy: ReturnType<typeof createPgQuerier>) => Promise<void>,
  ) {
    const legacyName = `${database}_legacy`;
    await admin.query(`DROP DATABASE IF EXISTS ${legacyName} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${legacyName}`);
    const target = new URL(url!);
    target.pathname = `/${legacyName}`;
    const legacy = createPgQuerier(target.toString());
    let legacyAuth: HumanAuth | undefined;
    const mainApp = app;
    try {
      const connection = await legacy.connect();
      try {
        await connection.query("CREATE TABLE varlatch_migrations (id integer PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())");
        for (const migration of MIGRATIONS.filter((m) => m.id <= 38)) {
          await connection.query(migration.sql);
          await connection.query("INSERT INTO varlatch_migrations (id, name) VALUES ($1, $2)", [migration.id, migration.name]);
        }
        await seed(connection);
        expect((await runMigrations(connection)).applied.map((m) => m.id)).toEqual([39, 40, 41, 42, 43, 44, 45]);
      } finally {
        connection.release();
      }
      const legacyCtx: AppCtx = { db: legacy, rootKek: Buffer.alloc(32, 31) };
      legacyAuth = buildHumanAuth({ ctx: legacyCtx, databaseUrl: target.toString(), publicUrl: PUBLIC_URL });
      app = buildApp(legacyCtx, { publicUrl: PUBLIC_URL, humanAuth: legacyAuth, clientAddress: () => "203.0.113.7" });
      await body(legacy);
    } finally {
      app = mainApp;
      await legacyAuth?.close();
      await legacy.end();
      await admin.query(`DROP DATABASE IF EXISTS ${legacyName} WITH (FORCE)`);
    }
  }

  const seedPerson = async (connection: { query: (sql: string, params?: unknown[]) => Promise<unknown> }, letter: string) => {
    await connection.query("INSERT INTO identities (id, kind, name) VALUES ($1, 'human', $2)", [`idn_${letter}`, letter.toUpperCase()]);
    await connection.query(`INSERT INTO "user" (id, name, email) VALUES ($1, $2, $3)`, [`bau_${letter}`, letter, `${letter}@varlatch.placeholder.invalid`]);
    await connection.query("INSERT INTO auth_user_links (better_auth_user_id, identity_id) VALUES ($1, $2)", [`bau_${letter}`, `idn_${letter}`]);
  };
  const seedPasskey = (connection: { query: (sql: string, params?: unknown[]) => Promise<unknown> }, id: string, userId: string, publicKey: Buffer, credentialId: string, createdAt: string) =>
    connection.query(
      `INSERT INTO passkey (id, name, "publicKey", "userId", "credentialID", counter, "deviceType", "backedUp", transports, "createdAt")
       VALUES ($1, $1, $2, $3, $4, 0, 'singleDevice', false, 'internal', $5)`,
      [id, publicKey.toString("base64"), userId, credentialId, createdAt],
    );

  it("after the upgrade, the authenticator of a quarantined same-person duplicate signs in with the passkey that was kept", async () => {
    const key = softAuthenticator(RP);
    const impostor = softAuthenticator(RP);
    await withUpgradedDatabase(async (connection) => {
      await seedPerson(connection, "a");
      // The authenticator's own row, and a later row with its credential id but another key, as nothing refused before.
      await seedPasskey(connection, "pk_kept", "bau_a", key.coseKey, key.credentialId, "2026-11-01T10:00:00Z");
      await seedPasskey(connection, "pk_copy", "bau_a", impostor.coseKey, key.credentialId, "2026-11-02T10:00:00Z");
    }, async (legacy) => {
      expect((await legacy.query(`SELECT id FROM passkey WHERE "credentialID" = $1`, [key.credentialId])).rows).toEqual([{ id: "pk_kept" }]);
      expect((await legacy.query("SELECT id, kept_passkey_id FROM passkey_quarantine")).rows).toEqual([{ id: "pk_copy", kept_passkey_id: "pk_kept" }]);
      const browser = new Browser();
      const sessionId = await browser.signIn(key, await browser.signInOptions());
      expect((await legacy.query("SELECT ceremony, user_verified, passkey_id FROM auth_session_evidence WHERE session_id = $1", [sessionId])).rows)
        .toEqual([{ ceremony: "sign-in", user_verified: true, passkey_id: "pk_kept" }]);
      // The quarantined row's key no longer signs in: its credential id now names the kept passkey only.
      const refused = new Browser();
      const challenge = await refused.signInOptions();
      const response = { ...impostor.assert(challenge), id: key.credentialId, rawId: key.credentialId };
      expect((await refused.request("POST", "/auth/passkey/verify-authentication", { response })).status).not.toBe(200);
      expect((await legacy.query("SELECT count(*)::int AS n FROM auth_session_evidence")).rows).toEqual([{ n: 1 }]);
    });
  }, 30_000);

  it("across people: B's only passkey, sharing A's older credential id, is quarantined; that key signs in as A, and the report names B", async () => {
    const key = softAuthenticator(RP);
    await withUpgradedDatabase(async (connection) => {
      await seedPerson(connection, "a");
      await seedPerson(connection, "b");
      // Even with the identical public key.
      await seedPasskey(connection, "pk_a", "bau_a", key.coseKey, key.credentialId, "2026-11-01T10:00:00Z");
      await seedPasskey(connection, "pk_b", "bau_b", key.coseKey, key.credentialId, "2026-11-02T10:00:00Z");
    }, async (legacy) => {
      expect((await legacy.query(`SELECT id FROM passkey WHERE "userId" = 'bau_b'`)).rows).toEqual([]);
      expect((await legacy.query(`SELECT id, "userId", kept_passkey_id FROM passkey_quarantine`)).rows).toEqual([
        { id: "pk_b", userId: "bau_b", kept_passkey_id: "pk_a" },
      ]);
      // B has no passkey left; that authenticator now signs in as A.
      const browser = new Browser();
      const signedIn = await browser.request("POST", "/auth/passkey/verify-authentication", {
        response: key.assert(await browser.signInOptions()),
      });
      expect(signedIn.status).toBe(200);
      expect(signedIn.body.user.id).toBe("bau_a");
      expect((await legacy.query("SELECT passkey_id FROM auth_session_evidence WHERE session_id = $1", [signedIn.body.session.id])).rows)
        .toEqual([{ passkey_id: "pk_a" }]);
      const quarantined = await quarantinedPasskeys(legacy);
      expect(quarantined).toEqual([expect.objectContaining({
        passkeyId: "pk_b", identityId: "idn_b", identityName: "B", keptPasskeyId: "pk_a", keptIdentityId: "idn_a", samePerson: false, samePublicKey: true,
      })]);
      const report = quarantineReport(quarantined).join("\n");
      expect(report).toContain("B [idn_b]");
      expect(report).toContain("another person's [idn_a]");
      expect(report).toContain("now signs in as that person");
      expect(report).toContain("varlatch admin reenroll --identity");
      // The operator's way back for B: a reenroll link enrolls a new, trusted passkey that signs in as B.
      const legacyCtx: AppCtx = { db: legacy, rootKek: Buffer.alloc(32, 31) };
      await ensureInstallation(legacyCtx);
      await legacy.query("UPDATE installation SET bootstrapped_at = now()");
      const [link] = await issueReenrollmentGrants(legacyCtx, { identityIds: ["idn_b"] });
      const fresh = softAuthenticator(RP);
      expect((await new Browser().enroll(fresh, { context: link!.token, createSession: true })).status).toBe(200);
      const restored = await legacy.query(
        `SELECT p."userId", pp.trust, pp.setup_grant_kind FROM passkey p JOIN passkey_provenance pp ON pp.passkey_id = p.id WHERE p."credentialID" = $1`,
        [fresh.credentialId],
      );
      expect(restored.rows).toEqual([{ userId: "bau_b", trust: "trusted", setup_grant_kind: "reenroll" }]);
      const asB = new Browser();
      const signedInAsB = await asB.request("POST", "/auth/passkey/verify-authentication", { response: fresh.assert(await asB.signInOptions()) });
      expect(signedInAsB.body.user.id).toBe("bau_b");
    });
  }, 30_000);

  it("sign-in writes the evidence onto its own session only, user verification as the authenticator said", async () => {
    const { key, sessionId: enrollmentSession } = await bootstrapAdmin();
    const before = await evidenceOf(enrollmentSession);
    const browser = new Browser();
    const sessionId = await browser.signIn(key, await browser.signInOptions(), false);
    expect(await evidenceOf(sessionId)).toEqual({ ceremony: "sign-in", user_verified: false, passkey_id: await passkeyIdOf(key.credentialId) });
    // The person's other session keeps its own evidence.
    expect(await evidenceOf(enrollmentSession)).toEqual(before);
    expect(await rows("SELECT session_id FROM auth_session_evidence ORDER BY session_id")).toHaveLength(2);
  });

  it("concurrent sign-ins of one person each get their own evidence", async () => {
    const admin = await bootstrapAdmin();
    // One key per concurrent sign-in: concurrent assertions of one key race
    // on its signature counter, and the one that arrives out of order is
    // refused (see the counter tests below). Every other key is unconfirmed
    // and signs in without user verification.
    const keys = [{ key: admin.key, userVerified: true, passkeyId: await passkeyIdOf(admin.key.credentialId) }];
    for (let i = 1; i < 8; i++) {
      const added = softAuthenticator(RP);
      expect((await admin.browser.enroll(added)).status).toBe(200);
      keys.push({ key: added, userVerified: i % 2 === 0, passkeyId: await passkeyIdOf(added.credentialId) });
    }
    for (let round = 0; round < 4; round++) {
      const attempts = keys.map((k) => ({ ...k, browser: new Browser() }));
      const challenges = await Promise.all(attempts.map((a) => a.browser.signInOptions()));
      const sessions = await Promise.all(attempts.map((a, i) => a.browser.signIn(a.key, challenges[i]!, a.userVerified)));
      expect(new Set(sessions).size).toBe(attempts.length);
      for (const [i, sessionId] of sessions.entries()) {
        expect(await evidenceOf(sessionId)).toEqual({ ceremony: "sign-in", user_verified: attempts[i]!.userVerified, passkey_id: attempts[i]!.passkeyId });
      }
    }
  });

  const counterOf = async (passkeyId: string) => (await rows("SELECT counter FROM passkey WHERE id = $1", [passkeyId]))[0].counter as number;
  const sessionCount = async () => (await rows(`SELECT count(*)::int AS n FROM "session"`))[0].n as number;
  const hasSessionCookie = (browser: Browser) => [...browser.cookies.keys()].some((name) => name.includes("session_token"));
  const postAssertion = (browser: Browser, response: unknown) => browser.request("POST", "/auth/passkey/verify-authentication", { response });

  /**
   * Holds Better Auth's first write of signature counter `counter` (its
   * UPDATE of the passkey row) until `release`; `held` resolves once that
   * write waits. Install it before the test's first Better Auth query:
   * pooled clients pick it up when they connect.
   */
  function holdCounterWrite(counter: number) {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let markHeld!: () => void;
    const held = new Promise<void>((resolve) => { markHeld = resolve; });
    let holding = true;
    const original = pg.Client.prototype.query as (...a: unknown[]) => unknown;
    const spy = vi.spyOn(pg.Client.prototype, "query").mockImplementation(function (this: pg.Client, ...args: unknown[]) {
      const [text, values] = args;
      if (holding && typeof text === "string" && /^update "passkey" set "counter"/i.test(text) && Array.isArray(values) && values[0] === counter) {
        holding = false;
        markHeld();
        return gate.then(() => original.apply(this, args)) as never;
      }
      return original.apply(this, args) as never;
    });
    return { held, release, restore: () => spy.mockRestore() };
  }

  it("a sign-in whose counter write lands after a later counter's is refused, creates no session, and the counter never goes back", async () => {
    const hold = holdCounterWrite(1);
    try {
      const { key } = await bootstrapAdmin();
      const passkeyId = await passkeyIdOf(key.credentialId);
      const sessionsBefore = await sessionCount();
      const first = new Browser();
      const second = new Browser();
      const [c1, c2] = await Promise.all([first.signInOptions(), second.signInOptions()]);
      // The authenticator signs counter 1, then counter 2.
      const a1 = key.assert(c1);
      const a2 = key.assert(c2);
      // Counter 1 is verified against the stored 0; its write is held.
      const late = postAssertion(first, a1);
      await hold.held;
      // Counter 2, verified against the same stored 0, commits first.
      const won = await postAssertion(second, a2);
      expect(won.status).toBe(200);
      expect(await counterOf(passkeyId)).toBe(2);
      hold.release();
      const lost = await late;
      expect(lost.status).toBe(400);
      expect(await counterOf(passkeyId)).toBe(2);
      expect(await sessionCount()).toBe(sessionsBefore + 1);
      expect(hasSessionCookie(first)).toBe(false);
      // The same answer as an assertion whose counter is plainly stale.
      const replay = new Browser();
      const stale = await postAssertion(replay, key.assert(await replay.signInOptions(), { signCount: 2 }));
      expect(stale.status).toBe(400);
      expect(lost.body).toEqual(stale.body);
      expect(await counterOf(passkeyId)).toBe(2);
    } finally {
      hold.release();
      hold.restore();
    }
  });

  it("an authenticator without a counter (always 0) signs in concurrently, every time", async () => {
    const hold = holdCounterWrite(0);
    try {
      const { key } = await bootstrapAdmin();
      const passkeyId = await passkeyIdOf(key.credentialId);
      const first = new Browser();
      const second = new Browser();
      const [c1, c2] = await Promise.all([first.signInOptions(), second.signInOptions()]);
      const late = postAssertion(first, key.assert(c1, { signCount: 0 }));
      await hold.held;
      expect((await postAssertion(second, key.assert(c2, { signCount: 0 }))).status).toBe(200);
      hold.release();
      expect((await late).status).toBe(200);
      const browsers = Array.from({ length: 6 }, () => new Browser());
      const challenges = await Promise.all(browsers.map((b) => b.signInOptions()));
      const results = await Promise.all(browsers.map((b, i) => postAssertion(b, key.assert(challenges[i]!, { signCount: 0 }))));
      expect(results.map((r) => r.status)).toEqual([200, 200, 200, 200, 200, 200]);
      expect(await counterOf(passkeyId)).toBe(0);
    } finally {
      hold.release();
      hold.restore();
    }
  });

  /**
   * Varlatch's own assertion (device sign-in approval, passkey
   * confirmation): `first` verified in a transaction left open, then
   * `late` verified in another while it is, then the first commits.
   * Returns both outcomes.
   */
  async function raceOwnAssertions(identityId: string, first: { assertion: unknown; challenge: string }, late: { assertion: unknown; challenge: string }) {
    const holder = await db.connect();
    try {
      await holder.query("BEGIN");
      const firstResult = await verifyAssertion(holder, RP, identityId, first.assertion, first.challenge, { requireUserVerification: false });
      const pending = withTx(db, (tx) => verifyAssertion(tx, RP, identityId, late.assertion, late.challenge, { requireUserVerification: false }));
      // The late verification waits on the passkey row the first one holds.
      let waited = false;
      for (let i = 0; i < 200 && !waited; i++) {
        waited = (await rows("SELECT 1 FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'", [database])).length > 0;
        if (!waited) await new Promise((resolve) => setTimeout(resolve, 25));
      }
      expect(waited).toBe(true);
      await holder.query("COMMIT");
      return { first: firstResult, late: await pending };
    } finally {
      holder.release();
    }
  }

  it("Varlatch's own assertions verify the counter under the passkey's lock: the late, lower counter is an invalid assertion", async () => {
    const { key, identityId } = await bootstrapAdmin();
    const passkeyId = await passkeyIdOf(key.credentialId);
    const one = { challenge: "Y291bnRlci1vbmU", assertion: undefined as unknown };
    const two = { challenge: "Y291bnRlci10d28", assertion: undefined as unknown };
    one.assertion = key.assert(one.challenge);
    two.assertion = key.assert(two.challenge);
    const { first, late } = await raceOwnAssertions(identityId, two, one);
    expect(first).toEqual({ ok: true, passkeyId, userVerified: true });
    expect(late).toEqual({ ok: false, reason: "invalid-assertion" });
    expect(await counterOf(passkeyId)).toBe(2);
  });

  it("Varlatch's own assertions from an authenticator without a counter both pass", async () => {
    const { key, identityId } = await bootstrapAdmin();
    const passkeyId = await passkeyIdOf(key.credentialId);
    const one = { challenge: "emVyby1vbmU", assertion: key.assert("emVyby1vbmU", { signCount: 0 }) };
    const two = { challenge: "emVyby10d28", assertion: key.assert("emVyby10d28", { signCount: 0 }) };
    const { first, late } = await raceOwnAssertions(identityId, one, two);
    expect(first).toEqual({ ok: true, passkeyId, userVerified: true });
    expect(late).toEqual({ ok: true, passkeyId, userVerified: true });
    expect(await counterOf(passkeyId)).toBe(0);
  });

  it("the CLI handoff credential links the browser session and carries its evidence", async () => {
    const { key } = await bootstrapAdmin();
    const browser = new Browser();
    const sessionId = await browser.signIn(key, await browser.signInOptions());
    const bearer = await browser.bearer();
    const cli = await bearerCall("POST", "/v1/me/credentials/cli", bearer, { ttlSeconds: 3600 });
    expect(cli.status).toBe(201);
    expect((await rows("SELECT kind, auth_session_id FROM credentials WHERE id = $1", [cli.body.id]))[0]).toEqual({ kind: "cli", auth_session_id: sessionId });
    expect(await credentialEvidence(db, cli.body.id)).toEqual({
      source: "session", userVerified: true, passkeyId: await passkeyIdOf(key.credentialId), passkeyTrusted: true,
    });
    // Signing the browser out ends the session; the CLI credential keeps the evidence of the ceremony it came from.
    expect((await browser.request("POST", "/auth/sign-out", {})).status).toBe(200);
    expect(await rows(`SELECT id FROM "session" WHERE id = $1`, [sessionId])).toEqual([]);
    expect(await credentialEvidence(db, cli.body.id)).toMatchObject({ source: "session", userVerified: true });
    // However old that sign-in was: the next sign-in's sweep leaves evidence a live credential links.
    await db.query("UPDATE auth_session_evidence SET recorded_at = now() - interval '3 days' WHERE session_id = $1", [sessionId]);
    const later = new Browser();
    await later.signIn(key, await later.signInOptions());
    expect(await credentialEvidence(db, cli.body.id)).toMatchObject({ source: "session", userVerified: true });
    // Revoked, it is swept by the next sign-in.
    await db.query("UPDATE credentials SET revoked_at = now() WHERE id = $1", [cli.body.id]);
    await later.signIn(key, await later.signInOptions());
    expect(await evidenceOf(sessionId)).toBeNull();
  });

  it("confirms a session-added passkey with a trusted one, from the dashboard", async () => {
    const { browser, key } = await bootstrapAdmin();
    const added = softAuthenticator(RP);
    await browser.enroll(added);
    const addedId = await passkeyIdOf(added.credentialId);
    const bearer = await browser.bearer();
    const listed = await bearerCall("GET", "/v1/me/passkeys", bearer);
    expect(listed.body.items.map((p: any) => [p.id, p.trust]).sort()).toEqual(
      [[await passkeyIdOf(key.credentialId), "trusted"], [addedId, "unconfirmed"]].sort(),
    );
    const started = await bearerCall("POST", `/v1/me/passkeys/${addedId}/confirmation/options`, bearer);
    expect(started.status).toBe(200);
    const done = await bearerCall("POST", `/v1/me/passkeys/${addedId}/confirmation`, bearer, {
      assertion: key.assert(started.body.publicKey.challenge),
    });
    expect(done.status).toBe(200);
    expect(await provenance(added.credentialId)).toMatchObject({ trust: "trusted", trusted_via: "confirmed" });
  });

  it("turns off Better Auth's native passkey removal; Varlatch's route removes the caller's own passkey", async () => {
    const { browser } = await bootstrapAdmin();
    const added = softAuthenticator(RP);
    await browser.enroll(added);
    const addedId = await passkeyIdOf(added.credentialId);
    for (const path of ["/auth/passkey/delete-passkey", "/auth/passkey/delete-passkey/", "/auth//passkey/delete-passkey"]) {
      const res = await browser.request("POST", path, { id: addedId });
      expect(res.status, path).toBe(404);
    }
    expect(await passkeyIdOf(added.credentialId)).toBe(addedId);
    // The other passkey endpoints are still there.
    const listed = await browser.request("GET", "/auth/passkey/list-user-passkeys");
    expect(listed.status).toBe(200);
    expect(listed.body).toHaveLength(2);

    const bearer = await browser.bearer();
    expect((await bearerCall("DELETE", `/v1/me/passkeys/${addedId}`, bearer)).status).toBe(204);
    expect(await passkeyIdOf(added.credentialId)).toBeUndefined();
  });
});
