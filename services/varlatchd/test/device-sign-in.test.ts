// SPDX-License-Identifier: AGPL-3.0-or-later
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Maintenance } from "@varlatch/backup";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import { buildApp, type BuildAppOptions } from "../src/http/app.js";
import { PUBLIC_URL, RP, approvingHuman, deviceClient } from "./helpers/device-sign-in.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { registerSoftPasskey } from "./helpers/soft-authenticator.js";

/**
 * Device-authorization sign-in (design notes "Device-authorization
 * sign-in"): the CLI requests and polls, a human approves in the dashboard
 * with a fresh passkey assertion, the CLI collects one CLI credential. Each
 * protection is tested with its control. Real-Postgres races are in
 * device-sign-in-postgres.test.ts.
 */

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let peer = "203.0.113.7";
let adminId: string;
const client = deviceClient(() => app);

function build(options: BuildAppOptions = {}) {
  return buildApp(ctx, { publicUrl: PUBLIC_URL, clientAddress: () => peer, ...options });
}

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  adminId = (await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" })).identityId;
  peer = "203.0.113.7";
  app = build();
});
afterEach(async () => {
  await ctx.close();
});

async function rows(sql: string, params: unknown[] = []) {
  return (await ctx.db.query(sql, params)).rows as any[];
}
const signInRow = async (id?: string) => (await rows("SELECT * FROM device_sign_ins" + (id ? " WHERE id = $1" : ""), id ? [id] : []))[0];
const deviceCredentials = () => rows("SELECT * FROM credentials WHERE kind = 'cli'");

describe("requesting a sign-in", () => {
  it("returns a private device code, a typed user code, and the verification address; stores only the hash", async () => {
    const res = await client.start({ ttlSeconds: 3600, name: "laptop" });
    expect(res.status).toBe(201);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.body.deviceCode).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(res.body.userCode).toMatch(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
    expect(res.body).toMatchObject({ verificationUri: `${PUBLIC_URL}/device`, expiresIn: 600, interval: 5 });
    expect(res.body).not.toHaveProperty("verificationUriComplete");
    const row = await signInRow();
    expect(row).toMatchObject({ status: "pending", requested_ttl: 3600, requested_name: "laptop", requester_ip: peer, poll_interval: 5 });
    expect(row.requester_user_agent).toBe("varlatch-cli/0.14.0 (linux; x64)");
    expect(JSON.stringify(row)).not.toContain(res.body.deviceCode);
    // No credential exists before collection.
    expect(await deviceCredentials()).toHaveLength(0);
    const [audit] = await rows("SELECT * FROM audit_events WHERE event_type = 'authentication.device_requested'");
    expect(audit.resource.deviceSignInId).toBe(row.id);
    expect(JSON.stringify(await rows("SELECT * FROM audit_events"))).not.toContain(res.body.deviceCode);
  });

  it("applies ADR-0024's bounds to the credential lifetime", async () => {
    expect((await client.start({ ttlSeconds: 86_401 })).status).toBe(422);
    expect((await client.start({ ttlSeconds: 59 })).status).toBe(422);
    expect((await client.start()).status).toBe(201);
    expect((await signInRow()).requested_ttl).toBe(43_200);
  });

  it("caps pending sign-ins per peer; another peer is not affected (control)", async () => {
    for (let i = 0; i < 10; i++) expect((await client.start()).status).toBe(201);
    const capped = await client.start();
    expect(capped.status).toBe(429);
    expect(capped.body.error.code).toBe("RATE_LIMITED");
    peer = "198.51.100.1";
    expect((await client.start()).status).toBe(201);
  });

  it("caps pending sign-ins overall, and an expired one frees its slot (control)", async () => {
    await ctx.db.query(
      `INSERT INTO device_sign_ins (id, device_code_hash, user_code, requested_ttl, requester_ip, expires_at)
       SELECT 'dsi_' || g, md5(g::text), translate(lpad(g::text, 8, '0'), '0123456789', 'BCDFGHJKLM'), 60, 'peer-' || g,
              now() + interval '10 minutes'
       FROM generate_series(1, 1000) g`,
    );
    const capped = await client.start();
    expect(capped.status).toBe(429);
    expect(capped.body.error.code).toBe("RATE_LIMITED");
    await ctx.db.query("UPDATE device_sign_ins SET expires_at = now() - interval '1 second' WHERE id = 'dsi_1'");
    expect((await client.start()).status).toBe(201);
  });

  it("deletes sign-ins a day after they expired", async () => {
    const old = await client.start();
    await ctx.db.query("UPDATE device_sign_ins SET expires_at = now() - interval '25 hours', created_at = now() - interval '26 hours'");
    const recent = await client.start();
    expect(recent.status).toBe(201);
    expect(await rows("SELECT id FROM device_sign_ins")).toHaveLength(1);
    expect((await client.poll(old.body.deviceCode)).body.error.code).toBe("EXPIRED");
  });
});

describe("polling", () => {
  it("answers pending, and SLOW_DOWN with a growing interval when polled sooner than the interval", async () => {
    const { deviceCode } = (await client.start()).body;
    const first = await client.poll(deviceCode);
    expect(first.status).toBe(428);
    expect(first.body.error).toMatchObject({ code: "AUTHORIZATION_PENDING", details: { interval: 5 } });
    expect(first.headers.get("Cache-Control")).toBe("no-store");
    const fast = await client.poll(deviceCode);
    expect(fast.status).toBe(429);
    expect(fast.body.error).toMatchObject({ code: "SLOW_DOWN", details: { interval: 10 } });
    expect((await client.poll(deviceCode)).body.error.details.interval).toBe(15);
    // Control: a poll after the (grown) interval is an ordinary pending answer.
    await ctx.db.query("UPDATE device_sign_ins SET last_polled_at = now() - interval '16 seconds'");
    const patient = await client.poll(deviceCode);
    expect(patient.status).toBe(428);
    expect(patient.body.error.details.interval).toBe(15);
  });

  it("answers EXPIRED for an unknown or malformed device code", async () => {
    expect((await client.poll("A".repeat(43))).body.error.code).toBe("EXPIRED");
    expect((await client.poll("not a device code")).status).toBe(410);
    expect((await client.poll("")).status).toBe(422);
  });
});

describe("approving and collecting", () => {
  it("issues one CLI credential of the approving human, once; a second poll names it without the token", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const started = (await client.start({ ttlSeconds: 3600, name: "build box" })).body;
    const found = await client.lookup(human.token, started.userCode);
    expect(found.status).toBe(200);
    expect(found.headers.get("Cache-Control")).toBe("no-store");
    expect(found.body.signIn).toMatchObject({
      userCode: started.userCode,
      ttlSeconds: 3600,
      name: "build box",
      requesterIp: peer,
      requesterUserAgent: "varlatch-cli/0.14.0 (linux; x64)",
    });
    expect(found.body.approval.publicKey).toMatchObject({ rpId: RP.rpId, userVerification: "preferred" });
    expect(found.body.approval.publicKey.allowCredentials).toEqual([
      expect.objectContaining({ id: human.passkey.credentialId, type: "public-key" }),
    ]);
    const approved = await client.decide(human.token, started.userCode, "approve", human.passkey.assert(found.body.approval.publicKey.challenge));
    expect(approved.status).toBe(200);
    expect(approved.body).toEqual({ decision: "approved" });

    const before = Date.now();
    const collected = await client.poll(started.deviceCode);
    expect(collected.status).toBe(201);
    expect(collected.headers.get("Cache-Control")).toBe("no-store");
    expect(collected.body.token).toMatch(/^vlt_cli_/);
    expect(new Date(collected.body.expiresAt).getTime()).toBeGreaterThanOrEqual(before + 3600_000 - 1000);
    const [credential] = await deviceCredentials();
    expect(credential).toMatchObject({ id: collected.body.id, identity_id: adminId, name: "build box", client: "varlatch CLI 0.14.0 on Linux" });
    // The credential works as the approving human's CLI credential.
    const orgs = await app.request("/v1/organizations", { headers: { Authorization: `Bearer ${collected.body.token}` } });
    expect(orgs.status).toBe(200);

    const again = await client.poll(started.deviceCode);
    expect(again.status).toBe(410);
    expect(again.body.error).toMatchObject({ code: "CONSUMED", details: { credentialId: collected.body.id } });
    expect(JSON.stringify(again.body)).not.toContain(collected.body.token);
    expect(await deviceCredentials()).toHaveLength(1);

    const audit = await rows("SELECT event_type, actor_identity_id, credential_id, metadata FROM audit_events ORDER BY event_order");
    const types = audit.map((e) => e.event_type);
    expect(types).toEqual(expect.arrayContaining([
      "authentication.device_requested", "authentication.device_approved", "credential.issued", "authentication.device_collected",
    ]));
    expect(audit.find((e) => e.event_type === "authentication.device_approved").actor_identity_id).toBe(adminId);
    expect(audit.find((e) => e.event_type === "authentication.device_collected").credential_id).toBe(collected.body.id);
    expect(audit.find((e) => e.event_type === "credential.issued" && e.credential_id === collected.body.id).metadata)
      .toMatchObject({ kind: "cli", deviceSignInId: (await signInRow()).id, ttlSeconds: 3600 });
    const everything = JSON.stringify(await rows("SELECT * FROM audit_events"));
    expect(everything).not.toContain(collected.body.token);
    expect(everything).not.toContain(started.deviceCode);
    expect(everything).not.toContain(started.userCode.replace("-", ""));
  });

  it("compares the code case-insensitively with the dash optional", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const { userCode } = (await client.start()).body;
    expect((await client.lookup(human.token, userCode.toLowerCase())).status).toBe(200);
    expect((await client.lookup(human.token, ` ${userCode.replace("-", "")} `)).status).toBe(200);
  });

  it("records a denial; the CLI is told ACCESS_DENIED and nothing is issued", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const started = (await client.start()).body;
    const denied = await client.decide(human.token, started.userCode, "deny");
    expect(denied.status).toBe(200);
    expect(denied.body).toEqual({ decision: "denied" });
    const polled = await client.poll(started.deviceCode);
    expect(polled.status).toBe(403);
    expect(polled.body.error.code).toBe("ACCESS_DENIED");
    expect(await deviceCredentials()).toHaveLength(0);
    // Decided: the code no longer finds a pending sign-in.
    expect((await client.approve(human.token, started.userCode, human.passkey)).status).toBe(404);
    const [audit] = await rows("SELECT actor_identity_id FROM audit_events WHERE event_type = 'authentication.device_denied'");
    expect(audit.actor_identity_id).toBe(adminId);
  });

  it("expires: polls answer EXPIRED, codes stop matching, and approval after expiry issues nothing", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const started = (await client.start()).body;
    await ctx.db.query("UPDATE device_sign_ins SET expires_at = now() - interval '1 second'");
    expect((await client.lookup(human.token, started.userCode)).status).toBe(404);
    expect((await client.poll(started.deviceCode)).body.error.code).toBe("EXPIRED");
    expect((await signInRow()).status).toBe("expired");
  });

  it("issues nothing when the sign-in expires between approval and collection", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const started = (await client.start()).body;
    expect((await client.approve(human.token, started.userCode, human.passkey)).status).toBe(200);
    await ctx.db.query("UPDATE device_sign_ins SET expires_at = now() - interval '1 second'");
    const polled = await client.poll(started.deviceCode);
    expect(polled.status).toBe(410);
    expect(polled.body.error.code).toBe("EXPIRED");
    expect(await deviceCredentials()).toHaveLength(0);
  });
});

describe("approval needs a fresh passkey assertion bound to the sign-in, the identity, and the session", () => {
  it("refuses an approval without an assertion: a signed-in session alone is not enough", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const started = (await client.start()).body;
    const res = await client.decide(human.token, started.userCode, "approve");
    expect(res.status).toBe(422);
    expect((await signInRow()).status).toBe("pending");
  });

  it("refuses an assertion over a challenge the server did not issue", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const started = (await client.start()).body;
    await client.lookup(human.token, started.userCode);
    const res = await client.decide(human.token, started.userCode, "approve", human.passkey.assert("bm90LWlzc3VlZC1ieS10aGUtc2VydmVy"));
    expect(res.status).toBe(403);
    expect((await signInRow()).status).toBe("pending");
  });

  it("consumes a challenge on use: an invalid signature spends it, so the valid assertion over it is then refused", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const started = (await client.start()).body;
    const { challenge } = (await client.lookup(human.token, started.userCode)).body.approval.publicKey;
    const forged = await client.decide(human.token, started.userCode, "approve", human.passkey.assert(challenge, { tamper: true }));
    expect(forged.status).toBe(403);
    const replay = await client.decide(human.token, started.userCode, "approve", human.passkey.assert(challenge));
    expect(replay.status).toBe(403);
    expect((await signInRow()).status).toBe("pending");
    // Control: a fresh lookup issues a new challenge, which approves.
    expect((await client.approve(human.token, started.userCode, human.passkey)).status).toBe(200);
    const failures = await rows("SELECT metadata FROM audit_events WHERE event_type = 'authentication.failed'");
    expect(failures.map((f) => f.metadata)).toEqual([
      { method: "device-approval", reason: "invalid-assertion" },
      { method: "device-approval", reason: "challenge" },
    ]);
  });

  it("refuses a challenge issued for another sign-in", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const first = (await client.start()).body;
    const second = (await client.start()).body;
    const { challenge } = (await client.lookup(human.token, first.userCode)).body.approval.publicKey;
    await client.lookup(human.token, second.userCode);
    const res = await client.decide(human.token, second.userCode, "approve", human.passkey.assert(challenge));
    expect(res.status).toBe(403);
    expect((await rows("SELECT status FROM device_sign_ins")).map((r) => r.status)).toEqual(["pending", "pending"]);
  });

  it("refuses a challenge issued to another session of the same identity", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const otherSession = await human.session("another-session");
    const started = (await client.start()).body;
    const { challenge } = (await client.lookup(human.token, started.userCode)).body.approval.publicKey;
    const res = await client.decide(otherSession, started.userCode, "approve", human.passkey.assert(challenge));
    expect(res.status).toBe(403);
    // Control: a bearer re-minted from the SAME session may use it.
    const sameSession = await human.session(`session-${adminId}`);
    expect((await client.decide(sameSession, started.userCode, "approve", human.passkey.assert(challenge))).status).toBe(200);
  });

  it("refuses an assertion made with another identity's passkey, and a challenge issued to another identity", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const other = await approvingHuman(ctx, "Other");
    const started = (await client.start()).body;
    const mine = (await client.lookup(human.token, started.userCode)).body.approval.publicKey.challenge;
    // My challenge, the other identity's passkey.
    expect((await client.decide(human.token, started.userCode, "approve", other.passkey.assert(mine))).status).toBe(403);
    // The other identity's challenge, used in my session.
    const theirs = (await client.lookup(other.token, started.userCode)).body.approval.publicKey.challenge;
    expect((await client.decide(human.token, started.userCode, "approve", human.passkey.assert(theirs))).status).toBe(403);
    expect((await signInRow()).status).toBe("pending");
  });

  it("refuses a challenge issued to another identity under the same session id (the identity binding alone)", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const other = await approvingHuman(ctx, "Other");
    const started = (await client.start()).body;
    const { challenge } = (await client.lookup(human.token, started.userCode)).body.approval.publicKey;
    // The other identity's bearer carries the same session id, so only the identity binding tells them apart.
    const sameSessionId = await other.session(`session-${adminId}`);
    expect((await client.decide(sameSessionId, started.userCode, "approve", other.passkey.assert(challenge))).status).toBe(403);
    expect((await signInRow()).status).toBe("pending");
  });

  it("refuses an assertion for another origin or relying party", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const started = (await client.start()).body;
    let challenge = (await client.lookup(human.token, started.userCode)).body.approval.publicKey.challenge;
    expect((await client.decide(human.token, started.userCode, "approve", human.passkey.assert(challenge, { origin: "https://evil.test" }))).status).toBe(403);
    challenge = (await client.lookup(human.token, started.userCode)).body.approval.publicKey.challenge;
    expect((await client.decide(human.token, started.userCode, "approve", human.passkey.assert(challenge, { rpId: "evil.test" }))).status).toBe(403);
  });

  it("a newer lookup replaces the earlier unused challenge of the same session", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const started = (await client.start()).body;
    const earlier = (await client.lookup(human.token, started.userCode)).body.approval.publicKey.challenge;
    await client.lookup(human.token, started.userCode);
    expect((await client.decide(human.token, started.userCode, "approve", human.passkey.assert(earlier))).status).toBe(403);
  });

  it("offers no approval to a human without a passkey, who may still deny", async () => {
    const started = (await client.start()).body;
    const token = (await issueCredential(ctx.db, { identityId: adminId, kind: "browser", authSessionId: "s" })).token;
    const found = await client.lookup(token, started.userCode);
    expect(found.status).toBe(200);
    expect(found.body.approval).toBeNull();
    expect((await client.decide(token, started.userCode, "deny")).status).toBe(200);
  });
});

describe("only a human's dashboard session decides", () => {
  it("refuses service identities, CLI credentials, and bearers not minted from a session", async () => {
    const started = (await client.start()).body;
    await ctx.db.query("INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_a', 'acme', 'Acme', '{}')");
    await ctx.db.query("INSERT INTO identities (id, kind, name, organization_id) VALUES ('idn_svc', 'service', 'svc', 'org_a')");
    const service = (await issueCredential(ctx.db, { identityId: "idn_svc", kind: "service" })).token;
    const cli = (await issueCredential(ctx.db, { identityId: adminId, kind: "cli" })).token;
    const sessionless = (await issueCredential(ctx.db, { identityId: adminId, kind: "browser" })).token;
    for (const token of [service, cli, sessionless]) {
      const res = await client.lookup(token, started.userCode);
      expect(res.status).toBe(403);
      expect((await client.decide(token, started.userCode, "deny")).status).toBe(403);
    }
    // Unauthenticated: the bearer middleware answers.
    const anonymous = await app.request("/v1/auth/device/lookup", { method: "POST", body: JSON.stringify({ userCode: started.userCode }) });
    expect(anonymous.status).toBe(401);
    expect((await signInRow()).status).toBe("pending");
    // None of these counted as code attempts.
    expect(await rows("SELECT * FROM device_code_attempt_windows WHERE failures > 0")).toHaveLength(0);
  });
});

describe("persistent attempt limits on code entry", () => {
  async function wrongCodes(token: string, n: number) {
    for (let i = 0; i < n; i++) {
      const res = await client.lookup(token, "BBBB-BBBB");
      expect(res.status).toBe(404);
    }
  }

  it("locks an identity out after five wrong codes, across sessions and restarts; another identity is not locked (control)", async () => {
    const human = await approvingHuman(ctx, "Admin", adminId);
    const started = (await client.start()).body;
    await wrongCodes(human.token, 5);
    const locked = await client.lookup(human.token, started.userCode);
    expect(locked.status).toBe(429);
    expect(locked.body.error).toMatchObject({ code: "RATE_LIMITED", details: { retryAt: expect.any(String) } });
    // A fresh session of the same identity cannot reset it, nor can a restart.
    expect((await client.lookup(await human.session("fresh"), started.userCode)).status).toBe(429);
    app = build();
    expect((await client.lookup(human.token, started.userCode)).status).toBe(429);
    // Deny is refused too: the lockout covers code entry, whatever the decision.
    expect((await client.decide(human.token, started.userCode, "deny")).status).toBe(429);
    // Control: another identity, same peer, enters the correct code.
    peer = "198.51.100.2";
    const other = await approvingHuman(ctx, "Other");
    expect((await client.lookup(other.token, started.userCode)).status).toBe(200);
    // Control: once the window has passed, the correct code works again.
    peer = "203.0.113.7";
    await ctx.db.query("UPDATE device_code_attempt_windows SET window_started_at = now() - interval '11 minutes' WHERE scope = 'identity'");
    expect((await client.approve(human.token, started.userCode, human.passkey)).status).toBe(200);

    const rejected = await rows("SELECT actor_identity_id FROM audit_events WHERE event_type = 'authentication.device_code_rejected'");
    expect(rejected).toHaveLength(5);
    const lockedEvents = await rows("SELECT metadata FROM audit_events WHERE event_type = 'authentication.device_code_locked'");
    expect(lockedEvents.map((e) => e.metadata.scope)).toEqual(["identity"]);
  });

  it("locks a peer after twenty wrong codes from several identities; the same identities from another peer are not locked (control)", async () => {
    const started = (await client.start()).body;
    const humans = await Promise.all(Array.from({ length: 5 }, (_, i) => approvingHuman(ctx, `H${i}`)));
    for (const h of humans) await wrongCodes(h.token, 4);
    const fresh = await approvingHuman(ctx, "Fresh");
    expect((await client.lookup(fresh.token, started.userCode)).status).toBe(429);
    peer = "198.51.100.3";
    expect((await client.lookup(fresh.token, started.userCode)).status).toBe(200);
    expect((await rows("SELECT metadata FROM audit_events WHERE event_type = 'authentication.device_code_locked'")).map((e) => e.metadata.scope))
      .toEqual(["peer"]);
  });

  it("refuses code entry for everyone after a hundred wrong codes in total, until the window moves (control)", async () => {
    const started = (await client.start()).body;
    for (let p = 0; p < 25; p++) {
      peer = `192.0.2.${p}`;
      const h = await approvingHuman(ctx, `G${p}`);
      await wrongCodes(h.token, 4);
    }
    peer = "198.51.100.4";
    const bystander = await approvingHuman(ctx, "Bystander");
    expect((await client.lookup(bystander.token, started.userCode)).status).toBe(429);
    expect((await rows("SELECT metadata FROM audit_events WHERE event_type = 'authentication.device_code_locked'")).map((e) => e.metadata.scope))
      .toEqual(["global"]);
    await ctx.db.query("UPDATE device_code_attempt_windows SET window_started_at = now() - interval '11 minutes' WHERE scope = 'global'");
    expect((await client.lookup(bystander.token, started.userCode)).status).toBe(200);
  });
});

describe("availability", () => {
  it("advertises auth.device and serves the flow only over HTTPS, or on loopback in local development (control)", async () => {
    const meta = async () => (await (await app.request("/v1/meta")).json()).capabilities as string[];
    expect(await meta()).toContain("auth.device");
    for (const publicUrl of ["http://varlatch.example.com", undefined]) {
      app = build({ publicUrl });
      expect(await meta()).not.toContain("auth.device");
      const refused = await client.start();
      expect(refused.status).toBe(404);
      expect((await client.poll("A".repeat(43))).status).toBe(404);
    }
    for (const publicUrl of ["http://127.0.0.1:8686", "http://localhost:8787", "http://[::1]:8686"]) {
      app = build({ publicUrl });
      expect(await meta()).toContain("auth.device");
      const started = await client.start();
      expect(started.status).toBe(201);
      expect(started.body.verificationUri).toBe(`${new URL(publicUrl).origin}/device`);
    }
  });

  it("answers 503 during maintenance, like the rest of /v1", async () => {
    const maintenance = new Maintenance(mkdtempSync(join(tmpdir(), "varlatch-device-maintenance-")));
    maintenance.beginCapture(10_000);
    app = buildApp({ ...ctx, maintenance }, { publicUrl: PUBLIC_URL });
    for (const answer of [await client.start(), await client.poll("A".repeat(43))]) {
      expect(answer.status).toBe(503);
      expect(answer.body.error.code).toBe("MAINTENANCE");
    }
  });

  it("registers a passkey the way Better Auth stores it (helper sanity check)", async () => {
    const passkey = await registerSoftPasskey(ctx.db, adminId, RP);
    const [row] = await rows(`SELECT "publicKey", counter FROM passkey WHERE "credentialID" = $1`, [passkey.credentialId]);
    expect(row.counter).toBe(0);
    expect(Buffer.from(row.publicKey, "base64")[0]).toBe(0xa5);
  });
});
