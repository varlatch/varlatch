// SPDX-License-Identifier: AGPL-3.0-or-later
import { CAPABILITIES } from "@varlatch/protocol";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { ENFORCEABLE_CONTROLS, enforceCapability, resetControls } from "../src/domain/securitycontrols.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * passkey-verification enforced (ADR-0054 Decision 7, step 4.4), on
 * PGlite. Under `enforce`, an Organization access by a person's credential
 * whose sign-in evidence lacks user verification, or comes from a passkey
 * that is not trusted now, is refused with PASSKEY_VERIFICATION_REQUIRED.
 *
 * - The refusal replaces an authorization that would have allowed the
 *   request: every other denial answers first, existence hiding included.
 *   An outsider gets exactly the answers they got with the control off.
 * - Every /v1/organizations/:org route is covered, retrieval, validation
 *   and disclosure included; machine credentials never are (Capability
 *   exercise is a broker's), whatever the mode.
 * - It checks the requesting credential only: a member's removal, the
 *   exposure report and machine reach still compute other people's
 *   authority.
 * - An unconfirmed passkey's sign-in satisfies it only once the passkey is
 *   confirmed, through the browser session and the CLI handoff alike, and
 *   the evidence belongs to the session of the ceremony only.
 * - The Convex token leaves blocked Organizations out.
 * - Turning it on from a sign-in it would refuse is refused.
 */

const ORG = "/v1/organizations/acme";
const P = `${ORG}/projects/api`;
const E = `${P}/environments/production`;
const CONTROL = `${ORG}/security/controls/passkey-verification`;

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let orgId: string;
let adminId: string;
/** The admin's CLI credential: no sign-in evidence (as every credential from before the upgrade). */
let admin: string;
/** The admin's dashboard bearer for a sign-in with a trusted passkey that verified them. */
let verified: string;

type Answer = { status: number; body: any };

async function call(method: string, path: string, token: string, body?: unknown): Promise<Answer> {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  await accessCountsSettled();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

async function ok(method: string, path: string, token: string, body?: unknown): Promise<any> {
  const res = await call(method, path, token, body);
  expect(res.status, `${method} ${path}: ${JSON.stringify(res.body)}`).toBeLessThan(300);
  return res.body;
}

const rows = async (sql: string, params: unknown[] = []) => (await ctx.db.query(sql, params)).rows as any[];
const count = async (sql: string, params: unknown[] = []) => ((await rows(sql, params))[0] as { n: number }).n;

/** A refusal by passkey-verification, for this reason. */
function expectRefused(res: Answer, reason: "no-evidence" | "not-user-verified" | "untrusted-passkey" = "no-evidence") {
  expect(res.status, JSON.stringify(res.body)).toBe(403);
  expect(res.body.error).toMatchObject({ code: "PASSKEY_VERIFICATION_REQUIRED", details: { control: "passkey-verification", reason } });
}

async function person(name: string, role: "admin" | "member", organizationId = orgId) {
  const grant = await issueInviteGrant(ctx, { organizationId, role, name }, adminId);
  const { identityId } = await consumeSetupGrant(ctx, grant.token, {});
  return { id: identityId, cli: (await issueCredential(ctx.db, { identityId, kind: "cli" })).token };
}

/** A Better Auth session of this person, with the sign-in evidence of `key` (none: a sign-in from before the upgrade). */
async function session(identityId: string, evidence: { userVerified: boolean; key: SoftAuthenticator } | null) {
  const sessionId = `session-${identityId}-${Math.random().toString(36).slice(2)}`;
  await ctx.db.query(
    `INSERT INTO "session" (id, "expiresAt", token, "userId")
     SELECT $1, now() + interval '1 day', $1, better_auth_user_id FROM auth_user_links WHERE identity_id = $2`,
    [sessionId, identityId],
  );
  if (evidence) {
    await ctx.db.query(
      "INSERT INTO auth_session_evidence (session_id, ceremony, user_verified, passkey_id) VALUES ($1, 'sign-in', $2, $3)",
      [sessionId, evidence.userVerified, evidence.key.passkeyId],
    );
  }
  // The dashboard's bearer, minted again from the session cookie whenever it needs one.
  const mint = async () =>
    (await issueCredential(ctx.db, {
      identityId,
      kind: "browser",
      expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      authSessionId: sessionId,
    })).token;
  return { sessionId, bearer: await mint(), mint };
}

/** A dashboard bearer for a sign-in with this evidence, on a new passkey of that trust. */
async function browser(identityId: string, evidence: { userVerified: boolean; trust: "trusted" | "unconfirmed" } | null) {
  const key = await registerSoftPasskey(ctx.db, identityId, { ...RP, trust: evidence?.trust ?? "trusted" });
  return (await session(identityId, evidence ? { userVerified: evidence.userVerified, key } : null)).bearer;
}

/** A machine identity of the Organization with these actions everywhere. */
async function machine(name: string, actions: string[], kind = "service") {
  const created = await ok("POST", `${ORG}/identities`, verified, { name, kind });
  if (actions.length > 0) await ok("POST", `${ORG}/grants`, verified, { subjectIdentityId: created.id, scope: { kind: "organization" }, actions });
  return { id: created.id as string, token: created.credential as string };
}

async function setMode(mode: "off" | "report" | "enforce", path = CONTROL, by = verified) {
  if (mode === "off") {
    // Turning a control down needs an approval; the tests set it directly.
    await ctx.db.query("UPDATE security_controls SET mode = 'off', version = version + 1 WHERE control = 'passkey-verification' AND organization_id = (SELECT id FROM organizations WHERE slug = $1)", [path.split("/")[3]]);
    return;
  }
  const items = (await ok("GET", path.replace(/\/passkey-verification$/, ""), by)).items as { control: string; version: number }[];
  const current = items.find((i) => i.control === "passkey-verification")!;
  await ok("PATCH", path, by, { mode, expectedVersion: current.version });
}

const passkeyDenials = async () =>
  (await rows(
    `SELECT actor_identity_id, organization_id, action, metadata FROM audit_events
     WHERE event_type = 'authorization.denied' AND metadata::jsonb->>'reason' = 'passkey_verification_required' ORDER BY event_order`,
  )).map((r) => ({ actor: r.actor_identity_id, org: r.organization_id, action: r.action, metadata: typeof r.metadata === "string" ? JSON.parse(r.metadata) : r.metadata }));

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  adminId = (await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" })).identityId;
  admin = (await issueCredential(ctx.db, { identityId: adminId, kind: "cli" })).token;
  verified = await browser(adminId, { userVerified: true, trust: "trusted" });
  app = buildApp(ctx, { publicUrl: PUBLIC_URL });
  orgId = (await ok("POST", "/v1/organizations", admin, { name: "Acme", slug: "acme" })).id;
  await ok("POST", `${ORG}/projects`, admin, { name: "API", slug: "api", contractAuthority: "managed" });
  await ok("POST", `${P}/environments`, admin, { name: "production", tier: "production" });
  const revision = await ok("POST", `${P}/contract/revisions`, admin, {
    contract: { schemaVersion: 1, items: [{ name: "DB_PASS", required: { kind: "never" }, sensitive: true, type: "string" }] },
  });
  await ok("POST", `${P}/contract/revisions/${revision.id}/activate`, admin, {});
  await ok("PUT", `${E}/values/DB_PASS`, admin, { value: "hunter2-hunter2" });
});
afterEach(async () => {
  await ctx.close();
});

describe("which controls can enforce", () => {
  it("advertises security.enforce.passkey-verification, and offers enforce for it; admin-step-up still refuses it", async () => {
    const meta = (await call("GET", "/v1/meta", admin)).body.capabilities as string[];
    expect(meta).toContain("security.enforce.passkey-verification");
    expect(meta).not.toContain("security.enforce.admin-step-up");
    expect(CAPABILITIES.filter((c) => c.startsWith("security.enforce."))).toEqual([...ENFORCEABLE_CONTROLS].map(enforceCapability));
    const list = (await ok("GET", `${ORG}/security/controls`, admin)) as { items: { control: string; availableModes: string[] }[] };
    expect(list.items.find((i) => i.control === "passkey-verification")?.availableModes).toEqual(["off", "report", "enforce"]);
    const refused = await call("PATCH", `${ORG}/security/controls/admin-step-up`, verified, { mode: "enforce", expectedVersion: 0 });
    expect(refused.body.error.code).toBe("CONTROL_MODE_UNAVAILABLE");
  });
});

describe("turning it on", () => {
  it("is refused from a sign-in it would refuse, with nothing changed; allowed from one it accepts", async () => {
    const attempts: [string, Parameters<typeof expectRefused>[1]][] = [
      [admin, "no-evidence"],
      [await browser(adminId, { userVerified: false, trust: "trusted" }), "not-user-verified"],
      [await browser(adminId, { userVerified: true, trust: "unconfirmed" }), "untrusted-passkey"],
    ];
    for (const [token, reason] of attempts) {
      const res = await call("PATCH", CONTROL, token, { mode: "enforce", expectedVersion: 0 });
      expectRefused(res, reason);
      expect(res.body.error.details.change).toBe("refused");
      expect(res.body.error.message).toContain("would refuse your own sign-in");
    }
    expect(await count("SELECT count(*)::int AS n FROM security_controls")).toBe(0);
    expect(await count("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'security_control.changed'")).toBe(0);
    // Report mode is never refused: it changes no access.
    await ok("PATCH", CONTROL, admin, { mode: "report", expectedVersion: 0 });
    const on = await ok("PATCH", CONTROL, verified, { mode: "enforce", expectedVersion: 1 });
    expect(on).toMatchObject({ changed: true, loosened: false, control: { mode: "enforce", version: 2 } });
  });
});

describe("under enforce", () => {
  beforeEach(async () => {
    await setMode("enforce");
  });

  it("refuses a person's access without trusted, user-verified evidence, says why, and audits the refusal", async () => {
    expectRefused(await call("GET", ORG, admin), "no-evidence");
    expectRefused(await call("GET", ORG, await browser(adminId, null)), "no-evidence");
    expectRefused(await call("GET", ORG, await browser(adminId, { userVerified: false, trust: "trusted" })), "not-user-verified");
    expectRefused(await call("GET", ORG, await browser(adminId, { userVerified: true, trust: "unconfirmed" })), "untrusted-passkey");
    const refused = await call("GET", `${P}`, admin);
    expect(refused.body.error.message).toContain("Sign in again");
    // Accepted: a verified sign-in, and the CLI from a device sign-in approved with a trusted key that verified the person.
    await ok("GET", ORG, verified);
    const key = await registerSoftPasskey(ctx.db, adminId, { ...RP, trust: "trusted" });
    const device = await issueCredential(ctx.db, { identityId: adminId, kind: "cli", evidence: { userVerified: true, passkeyId: key.passkeyId } });
    await ok("GET", ORG, device.token);
    const unverifiedDevice = await issueCredential(ctx.db, { identityId: adminId, kind: "cli", evidence: { userVerified: false, passkeyId: key.passkeyId } });
    expectRefused(await call("GET", ORG, unverifiedDevice.token), "not-user-verified");
    // A removed key no longer counts.
    await ctx.db.query("DELETE FROM passkey WHERE id = $1", [key.passkeyId]);
    expectRefused(await call("GET", ORG, device.token), "untrusted-passkey");
    // Fail closed: any other kind of a person's credential carries no sign-in.
    const odd = await issueCredential(ctx.db, { identityId: adminId, kind: "service" });
    expectRefused(await call("GET", ORG, odd.token), "no-evidence");

    const denials = await passkeyDenials();
    expect(denials.map((d) => d.metadata.evidence)).toEqual([
      "no-evidence", "no-evidence", "not-user-verified", "untrusted-passkey", "no-evidence", "not-user-verified", "untrusted-passkey", "no-evidence",
    ]);
    expect(denials.every((d) => d.actor === adminId && d.org === orgId)).toBe(true);
    expect(denials[0]!.action).toBe("organization.read");
    // Enforcing counts nothing.
    expect(await count("SELECT count(*)::int AS n FROM security_control_counters")).toBe(0);
  });

  it("leaves other Organizations, the person's own account and their list of Organizations alone", async () => {
    await ok("POST", "/v1/organizations", admin, { name: "Beta", slug: "beta" });
    await ok("GET", "/v1/organizations/beta", admin);
    await ok("GET", "/v1/organizations/beta/projects", admin);
    await ok("GET", "/v1/me", admin);
    await ok("GET", "/v1/me/credentials", verified);
    const listed = (await ok("GET", "/v1/organizations", admin)).items.map((o: { slug: string }) => o.slug).sort();
    expect(listed).toEqual(["acme", "beta"]);
  });

  it("answers every other denial first: unknown Organizations and Projects, a member's missing permission, an outsider", async () => {
    // Unknown: not found, before anything is decided.
    expect((await call("GET", "/v1/organizations/nope", admin)).body.error.code).toBe("RESOURCE_NOT_FOUND");
    expect((await call("GET", `${ORG}/projects/nope`, admin)).body.error.code).toBe("RESOURCE_NOT_FOUND");
    expect((await call("GET", `${P}/environments/nope`, admin)).body.error.code).toBe("RESOURCE_NOT_FOUND");
    // A member asking for what they do not hold: the usual refusal.
    const bob = await person("Bob", "member");
    expect((await call("GET", `${ORG}/security/control-report`, bob.cli)).body.error.code).toBe("PERMISSION_DENIED");
    expect((await call("PATCH", ORG, bob.cli, { name: "Bob's" })).body.error.code).toBe("PERMISSION_DENIED");
    // What they do hold: refused for their sign-in.
    expectRefused(await call("GET", ORG, bob.cli));
    // An outsider: not found, as with the control off.
    await ok("POST", "/v1/organizations", admin, { name: "Beta", slug: "beta" });
    const olga = await person("Olga", "member", (await rows("SELECT id FROM organizations WHERE slug = 'beta'"))[0].id);
    expect(await call("GET", ORG, olga.cli)).toMatchObject({ status: 404, body: { error: { code: "RESOURCE_NOT_FOUND" } } });
    expect(await call("GET", `${P}`, olga.cli)).toMatchObject({ status: 404, body: { error: { code: "RESOURCE_NOT_FOUND" } } });
  });

  it("covers retrieval, validation, disclosure and writes, and discloses nothing", async () => {
    for (const [method, path, body] of [
      ["POST", `${E}/retrievals`, { mode: "strict" }],
      ["POST", `${E}/validate`, {}],
      ["POST", `${E}/disclosures`, { scope: "all-authorized-secrets" }],
      ["GET", `${E}/effective-configuration?include=values`, undefined],
      ["PUT", `${E}/values/DB_PASS`, { value: "changed-changed" }],
      ["PATCH", P, { name: "API gateway" }],
    ] as const) {
      const res = await call(method, path, admin, body);
      expectRefused(res);
      expect(JSON.stringify(res.body)).not.toContain("hunter2");
    }
    expect(await count("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'secret.disclosed'")).toBe(0);
    expect((await rows("SELECT name FROM projects"))[0].name).toBe("API");
    // The same, from a verified sign-in.
    expect((await call("POST", `${E}/retrievals`, verified, { mode: "strict" })).status).toBe(200);
    expect((await call("POST", `${E}/validate`, verified, {})).status).toBe(200);
    const disclosed = await ok("POST", `${E}/disclosures`, verified, { scope: "all-authorized-secrets" });
    expect(JSON.stringify(disclosed)).toContain("hunter2");
  });

  it("never affects machine credentials: a service reads, a broker issues and exercises a Capability", async () => {
    const bot = await machine("bot", ["organization.read", "config.metadata.read", "config.value.read", "secret.reveal"]);
    await ok("GET", ORG, bot.token);
    expect((await call("POST", `${E}/retrievals`, bot.token, { mode: "strict" })).status).toBe(200);
    const broker = await machine("broker", [], "broker");
    const agent = await ok("POST", `${ORG}/identities`, verified, { name: "agent", kind: "agent" });
    const projectId = (await rows("SELECT id FROM projects WHERE slug = 'api'"))[0].id as string;
    await ok("POST", `${ORG}/grants`, verified, { subjectIdentityId: agent.id, scope: { kind: "project", projectId }, actions: ["secret.use"] });
    const cap = await ok("POST", `${E}/capabilities`, broker.token, {
      agentIdentityId: agent.id, items: ["DB_PASS"], destinations: ["db.example.com"],
      targets: { DB_PASS: ["header:authorization"] }, ttlSeconds: 600, runId: "run_test",
    });
    const exercised = await ok("POST", `${E}/capabilities/${cap.id}/exercises`, broker.token, {
      capabilitySecret: cap.secret, destination: { host: "db.example.com", port: 443 }, placements: [{ item: "DB_PASS", target: "header:authorization" }],
    });
    expect(exercised.items[0]).toMatchObject({ name: "DB_PASS", value: "hunter2-hunter2" });
    expect(await passkeyDenials()).toEqual([]);
  });

  it("checks the requester only: a member's removal, the exposure report and machine reach still compute other people's authority", async () => {
    const bob = await person("Bob", "member");
    await ok("POST", `${ORG}/grants`, verified, { subjectIdentityId: bob.id, scope: { kind: "organization" }, actions: ["config.value.read"] });
    const bot = await machine("bot", ["config.metadata.read"]);
    // Bob's own sign-in carries no evidence: he is refused.
    expectRefused(await call("GET", ORG, bob.cli));
    // His authority, and the machine's, are still what they are.
    const reach = await ok("GET", `${ORG}/identities/${bot.id}/reach`, verified);
    expect(JSON.stringify(reach)).toContain("config.metadata.read");
    const review = await ok("GET", `${ORG}/members/${bob.id}/review`, verified);
    expect(review).toBeTruthy();
    expect((await call("GET", `${ORG}/members/${bob.id}/exposure`, verified)).status).toBe(200);
    await ok("DELETE", `${ORG}/members/${bob.id}`, verified);
    const captured = (await rows(
      `SELECT DISTINCT a.action FROM removal_authority a JOIN membership_removals r ON r.id = a.removal_id WHERE r.identity_id = $1 ORDER BY a.action`,
      [bob.id],
    )).map((r) => r.action);
    expect(captured).toContain("config.value.read");
  });

  it("is lifted by the host operator's reset", async () => {
    expectRefused(await call("GET", ORG, admin));
    await resetControls(ctx, { organization: "acme", controls: ["passkey-verification"] });
    await ok("GET", ORG, admin);
  });
});

describe("an unconfirmed passkey's sign-in", () => {
  it("satisfies it only once the passkey is confirmed, through the browser session and the CLI handoff alike; other sessions keep their own evidence", async () => {
    const ada = await person("Ada", "member");
    const trusted = await registerSoftPasskey(ctx.db, ada.id, { ...RP, trust: "trusted" });
    const added = await registerSoftPasskey(ctx.db, ada.id, { ...RP, trust: "unconfirmed" });
    const signedIn = await session(ada.id, { userVerified: true, key: added });
    const otherSession = await session(ada.id, null);
    await setMode("enforce");

    expectRefused(await call("GET", ORG, signedIn.bearer), "untrusted-passkey");
    // The CLI handoff from that session carries its evidence. It uses up
    // the dashboard's bearer, which the dashboard mints again from the session.
    const handoff = await ok("POST", "/v1/me/credentials/cli", signedIn.bearer, { ttlSeconds: 3600 });
    expectRefused(await call("GET", ORG, handoff.token), "untrusted-passkey");
    const dashboard = await signedIn.mint();
    expectRefused(await call("GET", ORG, dashboard), "untrusted-passkey");

    // Confirmed with a trusted passkey, in this session.
    const started = await ok("POST", `/v1/me/passkeys/${added.passkeyId}/confirmation/options`, dashboard);
    await ok("POST", `/v1/me/passkeys/${added.passkeyId}/confirmation`, dashboard, { assertion: trusted.assert(started.publicKey.challenge) });

    await ok("GET", ORG, dashboard);
    await ok("GET", ORG, handoff.token);
    // Another session of the same person did not inherit that sign-in's evidence.
    expectRefused(await call("GET", ORG, otherSession.bearer), "no-evidence");
    expectRefused(await call("GET", ORG, ada.cli), "no-evidence");
  });
});

describe("the Convex token", () => {
  it("leaves blocked Organizations out, keeps the others, counts report mode, and exempts machines", async () => {
    const beta = (await ok("POST", "/v1/organizations", admin, { name: "Beta", slug: "beta" })).id as string;
    const gamma = (await ok("POST", "/v1/organizations", admin, { name: "Gamma", slug: "gamma" })).id as string;
    const bot = await machine("bot", ["organization.read"]);
    await setMode("enforce");
    await setMode("report", "/v1/organizations/gamma/security/controls/passkey-verification");
    const orgIdsOf = async (token: string) => {
      const minted = await ok("POST", "/v1/tokens/convex", token);
      return (JSON.parse(Buffer.from(minted.token.split(".")[1], "base64url").toString()) as { orgIds: string[] }).orgIds.sort();
    };
    expect(await orgIdsOf(admin)).toEqual([beta, gamma].sort());
    expect(await orgIdsOf(verified)).toEqual([orgId, beta, gamma].sort());
    expect(await orgIdsOf(bot.token)).toEqual([orgId]);
    expect(await rows("SELECT organization_id, operation, reason, count::int AS count FROM security_control_counters")).toEqual([
      { organization_id: gamma, operation: "convex.token", reason: "no-evidence", count: 1 },
    ]);
  });
});

describe("every /v1/organizations/:org route", () => {
  const ROUTES = "/v1/organizations/:org";
  /** Each route, with acme, its Project and environment, and placeholders for the rest. */
  const entering = () =>
    app.routes
      .filter((r) => r.method !== "ALL" && (r.path === ROUTES || r.path.startsWith(`${ROUTES}/`)))
      .map((r) => ({
        key: `${r.method} ${r.path}`,
        method: r.method,
        path: r.path.replace(":org", "acme").replace(":project", "api").replace(":environment", "production").replace(/:[a-z]+/gi, "x"),
      }));

  async function answers(token: string) {
    const out = new Map<string, { status: number; code: string | null }>();
    for (const route of entering()) {
      const res = await app.request(route.path, {
        method: route.method,
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        ...(route.method === "GET" ? {} : { body: "{}" }),
      });
      const body = (await res.json().catch(() => null)) as { error?: { code: string } } | null;
      await accessCountsSettled();
      out.set(route.key, { status: res.status, code: body?.error?.code ?? null });
    }
    return out;
  }

  /** Everything a request could have changed, apart from refusals' audit events. */
  const state = async () =>
    JSON.stringify(await rows(
      `SELECT (SELECT count(*)::int FROM audit_events WHERE event_type <> 'authorization.denied') AS events,
              (SELECT count(*)::int FROM projects) AS projects, (SELECT count(*)::int FROM environments) AS environments,
              (SELECT count(*)::int FROM value_versions) AS versions, (SELECT count(*)::int FROM grants) AS grants,
              (SELECT count(*)::int FROM identities) AS identities, (SELECT count(*)::int FROM credentials) AS credentials,
              (SELECT count(*)::int FROM security_controls) AS controls, (SELECT count(*)::int FROM approval_intents) AS intents`,
    ));

  it("refuses a blocked admin on each route or answers an earlier refusal, and changes nothing", async () => {
    const bot = await machine("bot", ["organization.read"]);
    await setMode("enforce");
    const before = await state();
    const refusedFirst: string[] = [];
    const succeeded: string[] = [];
    for (const [route, answer] of await answers(admin)) {
      if (answer.status < 400) succeeded.push(`${route}: ${answer.status}`);
      else if (answer.code !== "PASSKEY_VERIFICATION_REQUIRED") refusedFirst.push(`${route}: ${answer.code}`);
    }
    expect(succeeded).toEqual([]);
    expect(await state()).toBe(before);
    // Every other route answers the refusal. These four answer a refusal
    // that came first and does not depend on the sign-in: a missing query
    // parameter and an empty body, checked before authorization, and the
    // broker-only Capability routes, which hide themselves from people.
    expect(refusedFirst.sort()).toEqual([
      "GET /v1/organizations/:org/config-items: VALIDATION_FAILED",
      "POST /v1/organizations/:org/projects/:project/environments/:environment/capabilities/:capability/exercises: RESOURCE_NOT_FOUND",
      "POST /v1/organizations/:org/projects/:project/environments/:environment/capabilities: RESOURCE_NOT_FOUND",
      "POST /v1/organizations/:org/projects/:project/environments: VALIDATION_FAILED",
    ]);
    // config-items, which authorizes without decide, with a query it accepts.
    expectRefused(await call("GET", `${ORG}/config-items?q=DB`, admin));
    // The project-only route and the environment route of Decision 7.
    expectRefused(await call("PATCH", P, admin, { name: "API gateway" }));
    expectRefused(await call("GET", E, admin));
    // The machine, by contrast, is never refused for it.
    expect([...(await answers(bot.token)).values()].some((a) => a.code === "PASSKEY_VERIFICATION_REQUIRED")).toBe(false);
  }, 60_000);

  it("gives an outsider and a machine exactly the answers they got with the control off", async () => {
    const bot = await machine("bot", ["organization.read", "config.metadata.read"]);
    const beta = (await ok("POST", "/v1/organizations", admin, { name: "Beta", slug: "beta" })).id as string;
    const outsider = await person("Olga", "member", beta);
    const off = { outsider: await answers(outsider.cli), bot: await answers(bot.token) };
    await setMode("enforce");
    const on = { outsider: await answers(outsider.cli), bot: await answers(bot.token) };
    for (const who of ["outsider", "bot"] as const) {
      const changed = [...on[who]].filter(([route, a]) => a.status !== off[who].get(route)?.status || a.code !== off[who].get(route)?.code);
      expect(changed, who).toEqual([]);
    }
    expect([...on.outsider.values()].some((a) => a.code === "PASSKEY_VERIFICATION_REQUIRED")).toBe(false);
  }, 60_000);
});
