// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import { buildHumanAuth, type HumanAuth } from "../src/auth/humanauth.js";
import { ensureInstallation, issueBootstrapGrant, issueReenrollmentGrants } from "../src/domain/bootstrap.js";
import { credentialEvidence } from "../src/domain/passkeys.js";
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
 * person included), the CLI handoff's session link, and the native passkey
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

  /** Browsers signed in as the bootstrap admin, each ready to post a registration of `credentialId` (options already fetched). */
  async function racingRegistrations(key: UnregisteredAuthenticator, count: number, credentialId: string) {
    return Promise.all(Array.from({ length: count }, async () => {
      const browser = new Browser();
      await browser.signIn(key, await browser.signInOptions());
      const options = await browser.request("GET", "/auth/passkey/generate-register-options");
      expect(options.status).toBe(200);
      const response = softAuthenticator(RP).attest(options.body.challenge, { credentialId });
      return () => browser.request("POST", "/auth/passkey/verify-registration", { response, name: "racing key" });
    }));
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
    // A second, unconfirmed key that signs in without user verification.
    const other = softAuthenticator(RP);
    expect((await admin.browser.enroll(other)).status).toBe(200);
    const keys = [
      { key: admin.key, userVerified: true, passkeyId: await passkeyIdOf(admin.key.credentialId) },
      { key: other, userVerified: false, passkeyId: await passkeyIdOf(other.credentialId) },
    ];
    for (let round = 0; round < 4; round++) {
      const attempts = Array.from({ length: 8 }, (_, i) => ({ ...keys[i % 2]!, browser: new Browser() }));
      const challenges = await Promise.all(attempts.map((a) => a.browser.signInOptions()));
      const sessions = await Promise.all(attempts.map((a, i) => a.browser.signIn(a.key, challenges[i]!, a.userVerified)));
      expect(new Set(sessions).size).toBe(attempts.length);
      for (const [i, sessionId] of sessions.entries()) {
        expect(await evidenceOf(sessionId)).toEqual({ ceremony: "sign-in", user_verified: attempts[i]!.userVerified, passkey_id: attempts[i]!.passkeyId });
      }
    }
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
