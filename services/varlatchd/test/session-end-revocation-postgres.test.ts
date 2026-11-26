// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { buildHumanAuth, type HumanAuth } from "../src/auth/humanauth.js";
import { createPgQuerier } from "../src/db/pg.js";
import { runMigrations } from "../src/db/migrate.js";
import { completePublicUrlChange, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import { consumeApproval, type ApprovalBinding, type ApprovalGate, type Requester } from "../src/domain/approvals.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { changeControl } from "../src/domain/securitycontrols.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { softAuthenticator, type UnregisteredAuthenticator } from "./helpers/soft-authenticator.js";


// Better Auth's session helper, as the revocation hook calls it: itself,
// unless a test makes it answer no session or fail.
const sessionHelper = vi.hoisted(() => ({ override: null as null | (() => Promise<unknown>) }));
vi.mock("better-auth/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("better-auth/api")>();
  return {
    ...actual,
    getSessionFromCtx: ((...args: Parameters<typeof actual.getSessionFromCtx>) =>
      sessionHelper.override ? sessionHelper.override() : actual.getSessionFromCtx(...args)) as typeof actual.getSessionFromCtx,
  };
});

/**
 * Signing out ends the dashboard's bearers (migration 43), through Better
 * Auth itself on real PostgreSQL: sign-out, revoke-session,
 * revoke-other-sessions, revoke-sessions and Better Auth's removal of an
 * expired session each revoke the browser credentials minted from the
 * sessions they delete, at once; other sessions' bearers and the CLI
 * handoff's credential keep working. Under concurrency: a sign-out waits
 * for an approval consumption that holds the session, and a consumption
 * waits for a sign-out in flight; a bearer minted while the session is
 * being deleted is refused or revoked, never left live.
 */
const url = process.env.VARLATCH_TEST_DATABASE_URL;
describe.skipIf(!url)("signing out revokes browser bearers on real PostgreSQL", () => {
  let admin: ReturnType<typeof createPgQuerier>;
  let db: ReturnType<typeof createPgQuerier>;
  let ctx: AppCtx;
  let humanAuth: HumanAuth;
  let app: ReturnType<typeof buildApp>;
  const database = `varlatch_signout_test_${process.pid}`;
  const rows = async (sql: string, params: unknown[] = []) => (await db.query(sql, params)).rows as any[];
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const deferred = () => {
    let resolve!: () => void;
    const promise = new Promise<void>((r) => { resolve = r; });
    return { promise, resolve };
  };

  beforeEach(async () => {
    admin = createPgQuerier(url!);
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${database}`);
    const target = new URL(url!);
    target.pathname = `/${database}`;
    db = createPgQuerier(target.toString());
    const connection = await db.connect();
    try { await runMigrations(connection); } finally { connection.release(); }
    ctx = { db, rootKek: Buffer.alloc(32, 43) };
    await ensureInstallation(ctx);
    humanAuth = buildHumanAuth({ ctx, databaseUrl: target.toString(), publicUrl: PUBLIC_URL });
    app = buildApp(ctx, { publicUrl: PUBLIC_URL, humanAuth, clientAddress: () => "203.0.113.7" });
  });
  afterEach(async () => {
    sessionHelper.override = null;
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
    sessionId = "";
    async request(method: string, path: string, body?: unknown) {
      const res = await app.request(`${PUBLIC_URL}${path}`, {
        method,
        headers: {
          Origin: RP.origin,
          ...(this.cookies.size ? { Cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ") } : {}),
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
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
    async signIn(key: UnregisteredAuthenticator) {
      const options = await this.request("GET", "/auth/passkey/generate-authenticate-options");
      expect(options.status).toBe(200);
      const res = await this.request("POST", "/auth/passkey/verify-authentication", { response: key.assert(options.body.challenge) });
      expect(res.status).toBe(200);
      this.sessionId = res.body.session.id as string;
      return this;
    }
    /** The dashboard's /v1 bearer from this browser's session. */
    async bearer() {
      const res = await this.request("POST", "/auth/varlatch-token");
      expect(res.status, JSON.stringify(res.body)).toBe(200);
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
  const works = async (token: string) => (await bearerCall("GET", "/v1/me/credentials", token)).status;
  const credentialIdOf = async (token: string) => {
    const items = (await bearerCall("GET", "/v1/me/credentials", token)).body.items as { id: string; current: boolean }[];
    return items.find((i) => i.current)!.id;
  };
  const sessionEndedLines = async () =>
    (await rows(
      `SELECT credential_id FROM audit_events
       WHERE event_type = 'credential.revoked' AND metadata->>'reason' = 'session-ended' ORDER BY credential_id`,
    )).map((r) => r.credential_id as string);

  /** Bootstrap through the enrollment page's ceremony: the first admin, their passkey, and their browser. */
  async function bootstrapAdmin() {
    const grant = await issueBootstrapGrant(ctx);
    const browser = new Browser();
    const key = softAuthenticator(RP);
    const options = await browser.request("GET", `/auth/passkey/generate-register-options?context=${encodeURIComponent(grant.token)}`);
    expect(options.status).toBe(200);
    const enrolled = await browser.request("POST", "/auth/passkey/verify-registration", {
      response: key.attest(options.body.challenge), name: "test key", createSession: true,
    });
    expect(enrolled.status).toBe(200);
    browser.sessionId = enrolled.body.session.id as string;
    const identityId = (await rows("SELECT identity_id FROM auth_user_links"))[0].identity_id as string;
    return { browser, key, identityId };
  }

  it("signing out revokes that session's bearers at once; another session's bearer and the CLI handoff keep working", async () => {
    const { browser, key } = await bootstrapAdmin();
    const other = await new Browser().signIn(key);
    const tab1 = await browser.bearer();
    const tab2 = await browser.bearer();
    const elsewhere = await other.bearer();
    // `varlatch login` through this browser: the handoff bearer becomes a CLI credential that links the session.
    const cli = await bearerCall("POST", "/v1/me/credentials/cli", await browser.bearer(), { ttlSeconds: 3600 });
    expect(cli.status).toBe(201);
    expect((await rows("SELECT auth_session_id FROM credentials WHERE id = $1", [cli.body.id]))[0].auth_session_id).toBe(browser.sessionId);
    for (const token of [tab1, tab2, elsewhere, cli.body.token]) expect(await works(token)).toBe(200);
    const revoked = [await credentialIdOf(tab1), await credentialIdOf(tab2)].sort();

    expect((await browser.request("POST", "/auth/sign-out", {})).status).toBe(200);

    expect(await rows(`SELECT id FROM "session" WHERE id = $1`, [browser.sessionId])).toEqual([]);
    expect(await works(tab1)).toBe(401);
    expect(await works(tab2)).toBe(401);
    expect(await works(elsewhere)).toBe(200);
    expect(await works(cli.body.token)).toBe(200);
    expect(await sessionEndedLines()).toEqual(revoked);
    expect((await browser.request("POST", "/auth/varlatch-token")).status).toBe(401);
  });

  it("revoke-session, revoke-other-sessions and revoke-sessions end the bearers of the sessions they end", async () => {
    const { browser: a, key } = await bootstrapAdmin();
    const [b, c, d] = [await new Browser().signIn(key), await new Browser().signIn(key), await new Browser().signIn(key)];
    const [ta, tb, tc, td] = [await a.bearer(), await b.bearer(), await c.bearer(), await d.bearer()];

    const dToken = (await rows(`SELECT token FROM "session" WHERE id = $1`, [d.sessionId]))[0].token as string;
    expect((await a.request("POST", "/auth/revoke-session", { token: dToken })).status).toBe(200);
    expect(await works(td)).toBe(401);
    for (const t of [ta, tb, tc]) expect(await works(t)).toBe(200);

    expect((await a.request("POST", "/auth/revoke-other-sessions", {})).status).toBe(200);
    expect(await works(tb)).toBe(401);
    expect(await works(tc)).toBe(401);
    expect(await works(ta)).toBe(200);

    const tb2 = await (await new Browser().signIn(key)).bearer();
    expect((await a.request("POST", "/auth/revoke-sessions", {})).status).toBe(200);
    expect(await works(ta)).toBe(401);
    expect(await works(tb2)).toBe(401);
    expect(await rows(`SELECT id FROM "session"`)).toEqual([]);
    expect(await rows("SELECT id FROM credentials WHERE kind = 'browser' AND revoked_at IS NULL")).toEqual([]);
  });

  it("an expired session that Better Auth removes takes its bearers with it", async () => {
    const { browser } = await bootstrapAdmin();
    const token = await browser.bearer();
    await db.query(`UPDATE "session" SET "expiresAt" = now() - interval '1 second' WHERE id = $1`, [browser.sessionId]);
    // An expired session mints nothing more.
    expect((await browser.request("POST", "/auth/varlatch-token")).status).toBe(401);
    // Better Auth deletes the expired session it was asked about.
    await browser.request("GET", "/auth/get-session");
    expect(await rows(`SELECT id FROM "session" WHERE id = $1`, [browser.sessionId])).toEqual([]);
    expect(await works(token)).toBe(401);
  });

  it("the public-URL change revokes every bearer once, with its own reason", async () => {
    const { browser, key } = await bootstrapAdmin();
    const other = await new Browser().signIn(key);
    const tokens = [await browser.bearer(), await other.bearer()];
    await completePublicUrlChange(ctx, { from: PUBLIC_URL, to: "https://elsewhere.test" });
    for (const t of tokens) expect(await works(t)).toBe(401);
    const lines = await rows("SELECT metadata->>'reason' AS reason FROM audit_events WHERE event_type = 'credential.revoked'");
    expect(lines.map((l) => l.reason)).toEqual(["public-url-changed", "public-url-changed"]);
  });

  it("a bearer minted while its session is signed out is refused or revoked, never left live", async () => {
    const { key } = await bootstrapAdmin();
    for (let round = 0; round < 8; round++) {
      const browser = await new Browser().signIn(key);
      const [minted, signedOut] = await Promise.all([
        browser.request("POST", "/auth/varlatch-token"),
        sleep(round % 4).then(() => browser.request("POST", "/auth/sign-out", {})),
      ]);
      expect(signedOut.status).toBe(200);
      expect([200, 401]).toContain(minted.status);
      if (minted.status === 200) expect(await works(minted.body.token)).toBe(401);
      expect(await rows("SELECT id FROM credentials WHERE kind = 'browser' AND revoked_at IS NULL AND auth_session_id = $1", [browser.sessionId])).toEqual([]);
    }
  });

  it("a sign-out whose deletion fails answers the failure, and keeps the session and its cookie", async () => {
    const { browser } = await bootstrapAdmin();
    const token = await browser.bearer();
    const cookies = new Map(browser.cookies);
    await db.query(`CREATE FUNCTION refuse_session_delete() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'injected session deletion failure'; END $$`);
    await db.query(`CREATE TRIGGER refuse_session_delete BEFORE DELETE ON "session" FOR EACH ROW EXECUTE FUNCTION refuse_session_delete()`);
    const errors = console.error;
    console.error = () => {};
    let refused: Awaited<ReturnType<Browser["request"]>>;
    try {
      refused = await browser.request("POST", "/auth/sign-out", {});
    } finally {
      console.error = errors;
    }
    expect(refused.status).toBe(500);
    // The cookie was not cleared, and the session and its bearer still live:
    // the dashboard says it could not sign out, which is the truth.
    expect(browser.cookies).toEqual(cookies);
    expect(await rows(`SELECT id FROM "session" WHERE id = $1`, [browser.sessionId])).toHaveLength(1);
    expect(await works(token)).toBe(200);

    await db.query(`DROP TRIGGER refuse_session_delete ON "session"`);
    expect((await browser.request("POST", "/auth/sign-out", {})).status).toBe(200);
    expect([...browser.cookies.keys()].filter((k) => k.includes("session_token"))).toEqual([]);
    expect(await rows(`SELECT id FROM "session" WHERE id = $1`, [browser.sessionId])).toEqual([]);
    expect(await works(token)).toBe(401);
  });

  it("a sign-out with the browser's cookies from another origin, or none, is refused", async () => {
    const { browser } = await bootstrapAdmin();
    const cookie = [...browser.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    for (const origin of [{ Origin: "https://evil.example" }, { Referer: "https://evil.example/page" }, {}]) {
      const res = await app.request(`${PUBLIC_URL}/auth/sign-out`, {
        method: "POST",
        headers: { ...origin, Cookie: cookie, "Content-Type": "application/json" },
        body: "{}",
      });
      expect(res.status, JSON.stringify(origin)).toBe(403);
      expect(res.headers.getSetCookie()).toEqual([]);
    }
    expect(await rows(`SELECT id FROM "session" WHERE id = $1`, [browser.sessionId])).toHaveLength(1);
  });

  it("a sign-out ends no session for a cookie whose signature does not verify, or under another name", async () => {
    const { browser } = await bootstrapAdmin();
    const [[name, value]] = [...browser.cookies].filter(([k]) => k.endsWith("session_token")) as [string, string][];
    expect(name).toBe("__Secure-better-auth.session_token");
    const signed = decodeURIComponent(value!);
    const token = signed.slice(0, signed.lastIndexOf("."));
    const signOutWith = (cookie: string) =>
      app.request(`${PUBLIC_URL}/auth/sign-out`, {
        method: "POST",
        headers: { Origin: RP.origin, Cookie: cookie, "Content-Type": "application/json" },
        body: "{}",
      });
    // The session's token with a signature that is not the server's.
    await signOutWith(`${name}=${encodeURIComponent(`${token}.${"A".repeat(43)}=`)}`);
    // Its genuine signed value under a cookie name the server does not use.
    await signOutWith(`better-auth.session_token=${value}`);
    // An unsigned token.
    await signOutWith(`${name}=${encodeURIComponent(token)}`);
    expect(await rows(`SELECT id FROM "session" WHERE id = $1`, [browser.sessionId])).toHaveLength(1);
    expect((await browser.request("POST", "/auth/varlatch-token")).status).toBe(200);
  });

  it("sign-out-others reads its session's expiry once its locks are held", async () => {
    const { browser: a, key } = await bootstrapAdmin();
    const b = await new Browser().signIn(key);
    const ta = await a.bearer();
    expect(await works(ta)).toBe(200);
    // The caller's session ends 1.5 seconds from now; another transaction
    // holds the other browser's session for 2 seconds, so sign-out-others
    // waits for that lock past its own session's end.
    await db.query(`UPDATE "session" SET "expiresAt" = clock_timestamp() + interval '1500 milliseconds' WHERE id = $1`, [a.sessionId]);
    const holder = await db.connect();
    let res: { status: number; body: any };
    try {
      await holder.query("BEGIN");
      await holder.query(`SELECT id FROM "session" WHERE id = $1 FOR UPDATE`, [b.sessionId]);
      const signingOut = bearerCall("POST", "/v1/me/sessions/sign-out-others", ta);
      await sleep(2000);
      await holder.query("COMMIT");
      res = await signingOut;
    } finally {
      holder.release();
    }
    expect(res.status, JSON.stringify(res.body)).toBe(401);
    expect(await rows(`SELECT id FROM "session" WHERE id = $1`, [b.sessionId])).toHaveLength(1);
  });

  it("sign-out-others waits for a CLI exchange of its own bearer, and then signs out nobody", async () => {
    const { browser: a, key } = await bootstrapAdmin();
    const b = await new Browser().signIn(key);
    const ta = await a.bearer();
    const tb = await b.bearer();
    // Used once, so the race's request does not also write its last use.
    expect(await works(ta)).toBe(200);
    const taId = await credentialIdOf(ta);
    // The exchange's revocation of the presenting bearer, not yet committed.
    const exchange = await db.connect();
    let res: { status: number; body: any };
    try {
      await exchange.query("BEGIN");
      await exchange.query("UPDATE credentials SET revoked_at = now() WHERE id = $1", [taId]);
      const signingOut = bearerCall("POST", "/v1/me/sessions/sign-out-others", ta);
      let waited = false;
      for (let i = 0; i < 200 && !waited; i++) {
        const waiting = await rows(
          "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'",
          [database],
        );
        waited = waiting[0].n >= 1;
        if (!waited) await sleep(25);
      }
      await exchange.query("COMMIT");
      res = await signingOut;
      expect(waited).toBe(true);
    } finally {
      exchange.release();
    }
    expect(res.status, JSON.stringify(res.body)).toBe(401);
    expect(await rows(`SELECT id FROM "session" WHERE id = $1`, [b.sessionId])).toHaveLength(1);
    expect(await works(tb)).toBe(200);
  });

  it("Better Auth's revoke-sessions and sign-out-others at once lock sessions in one order: neither fails", async () => {
    const { browser: x, key } = await bootstrapAdmin();
    const middle = await new Browser().signIn(key);
    const y = await new Browser().signIn(key);
    // Session ids in one order, their rows in the other: a scan meets
    // ses_3 first, the id order ses_1.
    for (const [browser, id] of [[y, "ses_3"], [middle, "ses_2"], [x, "ses_1"]] as const) {
      await db.query(`UPDATE "session" SET id = $2 WHERE id = $1`, [browser.sessionId, id]);
      browser.sessionId = id;
    }
    const tx = await x.bearer();
    expect(await works(tx)).toBe(200);
    const holder = await db.connect();
    let results: { status: number; body: any }[];
    try {
      await holder.query("BEGIN");
      await holder.query(`SELECT id FROM "session" WHERE id = 'ses_2' FOR UPDATE`);
      const both = Promise.all([
        bearerCall("POST", "/v1/me/sessions/sign-out-others", tx),
        y.request("POST", "/auth/revoke-sessions", {}),
      ]);
      for (let i = 0; i < 200; i++) {
        const waiting = await rows(
          "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'",
          [database],
        );
        if (waiting[0].n >= 2) break;
        await sleep(25);
      }
      await holder.query("COMMIT");
      results = await both;
    } finally {
      holder.release();
    }
    // Whichever took the first session first: revoke-sessions ends every
    // session, and sign-out-others either ended the others first or finds
    // its own session gone. Neither waits on the other in a cycle (which
    // PostgreSQL would end with an error).
    expect([200, 401], JSON.stringify(results)).toContain(results[0]!.status);
    expect(results[1]!.status, JSON.stringify(results)).toBe(200);
    expect(await rows(`SELECT id FROM "session"`)).toEqual([]);
    expect(await rows("SELECT id FROM credentials WHERE kind = 'browser' AND revoked_at IS NULL")).toEqual([]);
  });

  it("revoke-other-sessions from a browser signed out while it waits revokes nothing", async () => {
    const { browser: a, key } = await bootstrapAdmin();
    const b = await new Browser().signIn(key);
    const tb = await b.bearer();
    // Another browser's sign-out of a's session, not yet committed.
    const other = await db.connect();
    let res: Awaited<ReturnType<Browser["request"]>>;
    try {
      await other.query("BEGIN");
      await other.query(`DELETE FROM "session" WHERE id = $1`, [a.sessionId]);
      const revoking = a.request("POST", "/auth/revoke-other-sessions", {});
      let waited = false;
      for (let i = 0; i < 200 && !waited; i++) {
        const waiting = await rows(
          "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'",
          [database],
        );
        waited = waiting[0].n >= 1;
        if (!waited) await sleep(25);
      }
      await other.query("COMMIT");
      res = await revoking;
      expect(waited).toBe(true);
    } finally {
      other.release();
    }
    expect(res.status, JSON.stringify(res.body)).toBe(401);
    expect(await rows(`SELECT id FROM "session" WHERE id = $1`, [b.sessionId])).toHaveLength(1);
    expect(await works(tb)).toBe(200);
  });

  it("revoke-sessions and revoke-other-sessions end nothing (401) when the caller's session cannot be read", async () => {
    const { browser: a, key } = await bootstrapAdmin();
    const b = await new Browser().signIn(key);
    const ta = await a.bearer();
    const tb = await b.bearer();
    const quiet = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      for (const path of ["/auth/revoke-sessions", "/auth/revoke-other-sessions"]) {
        for (const unresolved of [async () => null, async () => { throw new Error("connection reset"); }]) {
          // The native handler reads the session again on its own: if the
          // hook let the request through, it would revoke in scan order.
          sessionHelper.override = unresolved;
          const res = await a.request("POST", path, {});
          sessionHelper.override = null;
          expect(res.status, `${path}: ${JSON.stringify(res.body)}`).toBe(401);
          expect(await rows(`SELECT id FROM "session" WHERE id = ANY($1) ORDER BY id`, [[a.sessionId, b.sessionId]])).toHaveLength(2);
          expect(await works(ta)).toBe(200);
          expect(await works(tb)).toBe(200);
        }
      }
    } finally {
      quiet.mockRestore();
    }
  });

  it("two browsers signing each other out at once: one of them stays signed in", async () => {
    const { browser: a, key } = await bootstrapAdmin();
    const b = await new Browser().signIn(key);
    const c = await new Browser().signIn(key);
    // Session ids in a known order: both sign-outs reach the third browser's
    // session first, where a lock holds them until both have authenticated.
    for (const [browser, id] of [[c, "ses_1"], [a, "ses_2"], [b, "ses_3"]] as const) {
      await db.query(`UPDATE "session" SET id = $2 WHERE id = $1`, [browser.sessionId, id]);
      browser.sessionId = id;
    }
    const [ta, tb] = [await a.bearer(), await b.bearer()];
    const holder = await db.connect();
    let results: { status: number; body: any }[];
    try {
      await holder.query("BEGIN");
      await holder.query(`SELECT id FROM "session" WHERE id = 'ses_1' FOR UPDATE`);
      const both = Promise.all([
        bearerCall("POST", "/v1/me/sessions/sign-out-others", ta),
        bearerCall("POST", "/v1/me/sessions/sign-out-others", tb),
      ]);
      for (let i = 0; i < 200; i++) {
        const waiting = await rows(
          "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'",
          [database],
        );
        if (waiting[0].n >= 2) break;
        await sleep(25);
      }
      await holder.query("COMMIT");
      results = await both;
    } finally {
      holder.release();
    }
    const statuses = results.map((r) => r.status).sort();
    expect(statuses, JSON.stringify(results)).toEqual([200, 401]);
    const survivor = results[0]!.status === 200 ? a : b;
    expect((await rows(`SELECT id FROM "session" ORDER BY id`)).map((r) => r.id)).toEqual([survivor.sessionId]);
    expect(await works(survivor === a ? ta : tb)).toBe(200);
  });

  describe("against an approval consumption (lock order: session, then credential, then audit)", () => {
    let identityId: string;
    let browser: Browser;
    let bearer: string;
    let approvalId: string;
    let orgId: string;
    let binding: ApprovalBinding;
    let requester: Requester;

    beforeEach(async () => {
      ({ browser, identityId } = await bootstrapAdmin());
      const cli = (await issueCredential(db, { identityId, kind: "cli" })).token;
      orgId = (await bearerCall("POST", "/v1/organizations", cli, { name: "Acme", slug: "acme" })).body.id;
      expect((await bearerCall("PATCH", "/v1/organizations/acme/security/controls/admin-step-up", cli, { mode: "report", expectedVersion: 0 })).status).toBe(200);
      bearer = await browser.bearer();
      const asked = await bearerCall("PATCH", "/v1/organizations/acme/security/controls/admin-step-up", bearer, { mode: "off", expectedVersion: 1 });
      expect(asked.body.error.code, JSON.stringify(asked.body)).toBe("STEP_UP_REQUIRED");
      approvalId = asked.body.error.details.approval.id as string;
      // Approved directly: the WebAuthn ceremony is covered elsewhere.
      const passkeyId = (await rows("SELECT id FROM passkey"))[0].id as string;
      await db.query(
        "UPDATE approval_intents SET approved_at = clock_timestamp(), approved_with_passkey_id = $2, approval_user_verified = true WHERE id = $1",
        [approvalId, passkeyId],
      );
      requester = {
        identityId, identityKind: "human", credentialId: await credentialIdOf(bearer), credentialKind: "browser", authSessionId: browser.sessionId,
      };
      binding = {
        operation: "security_control.change", organizationId: orgId, target: { control: "admin-step-up" },
        body: { mode: "off", config: null, expectedVersion: 1 }, query: {}, expectedVersion: 1, summary: { title: "", changes: [] },
      };
    });
    const change = (gate: ApprovalGate) =>
      changeControl(ctx, gate, {
        organizationId: orgId, control: "admin-step-up", mode: "off", expectedVersion: 1,
        actorIdentityId: identityId, requestId: "req_test", authorizeIn: async () => undefined,
      }).then((r) => r, (e) => e);
    const waitingOnLock = async (pattern: string) => {
      for (let i = 0; i < 200; i++) {
        const waiting = await rows(
          "SELECT 1 FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock' AND query ILIKE $2",
          [database, pattern],
        );
        if (waiting.length > 0) return true;
        await sleep(25);
      }
      return false;
    };

    it("a sign-out waits for a consumption that holds the session, then revokes the bearer", async () => {
      const consumed = deferred();
      const release = deferred();
      const changing = change({
        require: async (tx, b) => {
          const used = await consumeApproval(tx, ctx.rootKek, requester, approvalId, b);
          consumed.resolve();
          await release.promise;
          return used;
        },
      });
      await consumed.promise;
      const signOut = browser.request("POST", "/auth/sign-out", {});
      expect(await waitingOnLock("%delete from%session%")).toBe(true);
      release.resolve();
      expect(await changing).toMatchObject({ changed: true, control: { mode: "off" } });
      expect((await signOut).status).toBe(200);
      expect(await works(bearer)).toBe(401);
      // The change's audit committed first (after the setup's change to report); the revocation's after it.
      const order = await rows(
        `SELECT event_type, metadata->>'reason' AS reason FROM audit_events
         WHERE event_type IN ('security_control.changed', 'credential.revoked') ORDER BY event_order`,
      );
      expect(order.map((r) => r.reason ?? r.event_type)).toEqual(["security_control.changed", "security_control.changed", "session-ended"]);
    });

    it("a consumption waits for a sign-out in flight and finds the session ended", async () => {
      const other = await db.connect();
      try {
        await other.query("BEGIN");
        // The sign-out's delete: the session, then (trigger) the bearer, then its audit line, not yet committed.
        await other.query(`DELETE FROM "session" WHERE id = $1`, [browser.sessionId]);
        const changing = change({ require: (tx, b) => consumeApproval(tx, ctx.rootKek, requester, approvalId, b) });
        // The consumption's session lock, quoted or not.
        expect(await waitingOnLock("%from %session%for key share of s%")).toBe(true);
        await other.query("COMMIT");
        expect(await changing).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "session-ended" } });
      } finally {
        other.release();
      }
      expect(await works(bearer)).toBe(401);
      expect((await rows("SELECT mode FROM security_controls WHERE organization_id = $1 AND control = 'admin-step-up'", [orgId]))[0].mode).toBe("report");
    });
  });
});
