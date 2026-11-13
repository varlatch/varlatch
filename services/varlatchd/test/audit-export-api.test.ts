// SPDX-License-Identifier: AGPL-3.0-or-later
import { createServer, type Server } from "node:http";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { buildApp } from "../src/http/app.js";
import { OutboundPolicy } from "../src/net/outbound.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * The audit export's routes (ADR-0056; capability audit.storage-export):
 * show, create, change, a new key, removal and the check, through HTTP.
 * The destination is a small store that honours If-None-Match and refuses
 * reads, as for a write-only key; the uploads themselves are tested against
 * MinIO in audit-export.test.ts.
 *
 * Covered: what each route answers and never answers (the key); the
 * approvals, always asked for loosening, a new key and removal, never for
 * creation and tightening; the machine-credential refusal; not-found after
 * the freeze and deletion refusals; the freeze (reads allowed); the
 * installation switch; passkey-verification before any intent; and nothing
 * observable without an export.
 */

const ORG = "/v1/organizations/acme";
const SECRET = "audit-export-secret-key-value-0001";

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let orgId: string;
let admin: { id: string; cli: string; web: string; key: SoftAuthenticator };
let store: { url: string; requests: number; close: () => Promise<void> };

async function call(method: string, path: string, token: string, body?: unknown, headers: Record<string, string> = {}) {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null, text };
}
const rows = async (sql: string, params: unknown[] = []) => (await ctx.db.query(sql, params)).rows as any[];
const intents = async () => (await rows("SELECT count(*)::int AS n FROM approval_intents"))[0].n as number;

const createBody = (over: Record<string, unknown> = {}) => ({
  destination: { endpoint: store.url, region: "us-east-1", bucket: "audit-bucket", prefix: "acme", pathStyle: true },
  credential: { accessKeyId: "AKIAEXPORT0001", secretAccessKey: SECRET },
  ...over,
});

/** Approve an intent as the admin, from the dashboard with the passkey. */
async function approve(approvalId: string) {
  const started = await call("POST", `/v1/me/approvals/${approvalId}/options`, admin.web);
  expect(started.status, started.text).toBe(200);
  const done = await call("POST", `/v1/me/approvals/${approvalId}/approve`, admin.web, {
    assertion: admin.key.assert(started.body.publicKey.challenge, { userVerified: true }),
  });
  expect(done.status, done.text).toBe(200);
}

/** A request that needs an approval: asked, approved, repeated with the header. */
async function withStepUp(method: string, path: string, body: unknown, operation: string) {
  const asked = await call(method, path, admin.cli, body);
  expect(asked.status, asked.text).toBe(403);
  expect(asked.body.error.code).toBe("STEP_UP_REQUIRED");
  const approval = asked.body.error.details.approval;
  expect(approval.operation).toBe(operation);
  expect(JSON.stringify(approval)).not.toContain(SECRET);
  await approve(approval.id);
  return { approvalId: approval.id as string, answer: await call(method, path, admin.cli, body, { "Varlatch-Approval": approval.id }) };
}

async function fakeStore(): Promise<typeof store> {
  const seen = new Set<string>();
  const counted = { requests: 0 };
  const server: Server = createServer((req, res) => {
    counted.requests++;
    req.resume();
    req.on("end", () => {
      const key = (req.url ?? "").split("?")[0]!;
      if (req.method === "PUT") {
        if (seen.has(key)) {
          res.writeHead(412, { "content-type": "application/xml" });
          res.end('<?xml version="1.0"?><Error><Code>PreconditionFailed</Code></Error>');
          return;
        }
        seen.add(key);
        res.writeHead(200, { ETag: '"0"' });
        res.end();
        return;
      }
      res.writeHead(403, { "content-type": "application/xml" });
      res.end(req.method === "HEAD" ? undefined : '<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>');
    });
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));
  const port = (server.address() as { port: number }).port;
  return {
    url: `http://127.0.0.1:${port}`,
    get requests() { return counted.requests; },
    close: () => new Promise<void>((done) => { server.closeAllConnections(); server.close(() => done()); }),
  };
}

function build(over: Partial<AppCtx> = {}) {
  app = buildApp({ ...ctx, ...over }, { publicUrl: PUBLIC_URL, clientAddress: () => "203.0.113.7" });
}

beforeEach(async () => {
  store = await fakeStore();
  const db = await migratedTestDb();
  // The store listens on loopback, which only an allow list entry opens (ADR-0057 Decision 5).
  ctx = { db, rootKek: generateKey(), close: db.close, outbound: new OutboundPolicy("127.0.0.1/32:*") };
  await ensureInstallation(ctx);
  const { identityId } = await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" });
  build();
  const cli = await issueCredential(ctx.db, { identityId, kind: "cli", name: "test cli" });
  const key = await registerSoftPasskey(ctx.db, identityId, { ...RP, trust: "trusted" });
  await ctx.db.query(
    `INSERT INTO "session" (id, "expiresAt", token, "userId")
     SELECT $1, now() + interval '1 day', $1, better_auth_user_id FROM auth_user_links WHERE identity_id = $2`,
    [`session-${identityId}`, identityId],
  );
  const web = await issueCredential(ctx.db, { identityId, kind: "browser", expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(), authSessionId: `session-${identityId}` });
  admin = { id: identityId, cli: cli.token, web: web.token, key };
  const created = await call("POST", "/v1/organizations", admin.cli, { name: "Acme", slug: "acme" });
  expect(created.status).toBe(201);
  orgId = created.body.id;
});

afterEach(async () => {
  await ctx.close();
  await store.close();
});

describe("with no export", () => {
  it("shows none, and the capability is advertised", async () => {
    expect((await call("GET", "/v1/meta", admin.cli)).body.capabilities).toContain("audit.storage-export");
    const shown = await call("GET", `${ORG}/audit-export`, admin.cli);
    expect(shown.status).toBe(200);
    expect(shown.body).toEqual({ enabled: true, export: null });
  });

  it("answers a change, a new key and removal with not-found, creating no intent and sending nothing", async () => {
    for (const [method, path, body] of [
      ["PATCH", `${ORG}/audit-export`, { expectedVersion: 1, retention: null }],
      ["PUT", `${ORG}/audit-export/credential`, { expectedVersion: 1, credential: createBody().credential }],
      ["DELETE", `${ORG}/audit-export?expectedVersion=1`, undefined],
    ] as const) {
      const res = await call(method, path, admin.cli, body);
      expect(res.status, `${method} ${path}: ${res.text}`).toBe(404);
      expect(res.body.error.code).toBe("RESOURCE_NOT_FOUND");
    }
    expect(await intents()).toBe(0);
    expect(store.requests).toBe(0);
  });
});

describe("the routes", () => {
  it("create, show, tighten, loosen with an approval, a new key and removal with approvals; never the key", async () => {
    const created = await call("POST", `${ORG}/audit-export`, admin.cli, createBody({ from: "now" }));
    expect(created.status, created.text).toBe(201);
    expect(created.body).toMatchObject({
      organizationId: orgId,
      state: "active",
      version: 1,
      destination: { endpoint: store.url, bucket: "audit-bucket", prefix: "acme/", pathStyle: true },
      retention: null,
      objectLock: "not-set",
      keyCanRead: false,
      lag: { pending: expect.any(Number) },
      unsupportedPlanFormat: null,
    });
    expect(await intents()).toBe(0);
    // A second one is refused.
    expect((await call("POST", `${ORG}/audit-export`, admin.cli, createBody())).body.error).toMatchObject({ code: "VALIDATION_FAILED", details: { reason: "export-exists" } });

    // Tightening (no retention to governance) needs no approval.
    const tightened = await call("PATCH", `${ORG}/audit-export`, admin.cli, { expectedVersion: 1, retention: { mode: "governance", days: 30 } });
    expect(tightened.status, tightened.text).toBe(200);
    expect(tightened.body).toMatchObject({ changed: true, loosened: false, export: { version: 2, retention: { mode: "governance", days: 30 } } });
    expect(await intents()).toBe(0);
    // A stale version is a conflict.
    expect((await call("PATCH", `${ORG}/audit-export`, admin.cli, { expectedVersion: 1, retention: { mode: "compliance", days: 30 } })).body.error.code).toBe("VERSION_CONFLICT");

    // Loosening (removing retention) asks; the approval completes it.
    const loosened = await withStepUp("PATCH", `${ORG}/audit-export`, { expectedVersion: 2, retention: null }, "audit_export.change");
    expect(loosened.answer.status, loosened.answer.text).toBe(200);
    expect(loosened.answer.body).toMatchObject({ changed: true, loosened: true, export: { version: 3, retention: null } });

    // A change of only some destination fields keeps the others.
    const moved = await withStepUp("PATCH", `${ORG}/audit-export`, { expectedVersion: 3, destination: { bucket: "audit-bucket-2" } }, "audit_export.change");
    expect(moved.answer.status, moved.answer.text).toBe(200);
    expect(moved.answer.body.export.destination).toEqual({ endpoint: store.url, region: "us-east-1", bucket: "audit-bucket-2", prefix: "acme/", pathStyle: true });
    expect(moved.answer.body.export.streamId).not.toBe(created.body.streamId);

    // A new key, always with an approval.
    const rekeyed = await withStepUp("PUT", `${ORG}/audit-export/credential`, {
      expectedVersion: 4, credential: { accessKeyId: "AKIAEXPORT0002", secretAccessKey: `${SECRET}-2` },
    }, "audit_export.change");
    expect(rekeyed.answer.status, rekeyed.answer.text).toBe(200);
    expect(rekeyed.answer.body.version).toBe(5);

    // Removal: expectedVersion is required, then an approval.
    expect((await call("DELETE", `${ORG}/audit-export`, admin.cli)).body.error.code).toBe("VALIDATION_FAILED");
    const removed = await withStepUp("DELETE", `${ORG}/audit-export?expectedVersion=5`, undefined, "audit_export.remove");
    expect(removed.answer.status, removed.answer.text).toBe(200);
    expect(removed.answer.body).toMatchObject({ state: "removed", lag: null });
    const after = await call("GET", `${ORG}/audit-export`, admin.cli);
    expect(after.body).toMatchObject({ enabled: true, export: { state: "removed", lag: null } });

    // The key is in no answer, approval or audit event.
    for (const text of [created.text, tightened.text, loosened.answer.text, moved.answer.text, rekeyed.answer.text, removed.answer.text, after.text]) {
      expect(text).not.toContain(SECRET);
      expect(text).not.toContain("secretAccessKey");
    }
    expect(JSON.stringify(await rows("SELECT summary FROM approval_intents"))).not.toContain(SECRET);
    expect(JSON.stringify(await rows("SELECT metadata, resource FROM audit_events"))).not.toContain(SECRET);
    expect((await rows("SELECT event_type FROM audit_events WHERE event_type LIKE 'audit_export.%' ORDER BY event_order")).map((r) => r.event_type)).toEqual([
      "audit_export.created", "audit_export.stream_started", "audit_export.changed", "audit_export.changed", "audit_export.changed",
      "audit_export.stream_started", "audit_export.credential_replaced", "audit_export.removed",
    ]);
  });

  it("a malformed approval header is refused, as for a Security Control change", async () => {
    expect((await call("POST", `${ORG}/audit-export`, admin.cli, createBody())).status).toBe(201);
    const res = await call("PATCH", `${ORG}/audit-export`, admin.cli, { expectedVersion: 1, retention: { mode: "governance", days: 1 } }, { "Varlatch-Approval": "not an id" });
    expect(res.body.error).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "not-found" } });
  });

  it("the check probes without saving; the stored key only goes to the export's own destination", async () => {
    const checked = await call("POST", `${ORG}/audit-export/check`, admin.cli, { destination: createBody().destination, credential: createBody().credential });
    expect(checked.status, checked.text).toBe(200);
    expect(checked.body).toEqual({ ok: true, message: null, conditionalCreation: true, objectLock: "not-set", keyCanRead: false, retentionReadable: null });
    expect(await rows("SELECT count(*)::int AS n FROM audit_exports")).toEqual([{ n: 0 }]);
    // Without a key and without an export: not found.
    expect((await call("POST", `${ORG}/audit-export/check`, admin.cli, { destination: createBody().destination })).body.error.code).toBe("RESOURCE_NOT_FOUND");
    expect((await call("POST", `${ORG}/audit-export`, admin.cli, createBody())).status).toBe(201);
    expect((await call("POST", `${ORG}/audit-export/check`, admin.cli, { destination: createBody().destination })).body).toMatchObject({ ok: true });
    const elsewhere = await call("POST", `${ORG}/audit-export/check`, admin.cli, { destination: { ...createBody().destination, bucket: "someone-elses" } });
    expect(elsewhere.body.error).toMatchObject({ code: "VALIDATION_FAILED", details: { reason: "stored-key-other-destination" } });
  });

  it("a probe that fails saves nothing and answers in fixed words", async () => {
    const refused = await call("POST", `${ORG}/audit-export`, admin.cli, createBody({ destination: { ...createBody().destination, endpoint: "http://127.0.0.1:1" } }));
    expect(refused.status).toBe(422);
    expect(refused.body.error.code).toBe("VALIDATION_FAILED");
    expect(refused.body.error.message).toMatch(/^The test write failed \(/);
    expect(await rows("SELECT count(*)::int AS n FROM audit_exports")).toEqual([{ n: 0 }]);
  });
});

describe("approvals bind the exact request", () => {
  it("a change that tightens one field and loosens another needs the approval", async () => {
    expect((await call("POST", `${ORG}/audit-export`, admin.cli, createBody({ retention: { mode: "governance", days: 30 } }))).status).toBe(201);
    // Stronger mode, fewer days: the shorter retention makes the whole change need it.
    const mixed = await call("PATCH", `${ORG}/audit-export`, admin.cli, { expectedVersion: 1, retention: { mode: "compliance", days: 10 } });
    expect(mixed.status, mixed.text).toBe(403);
    expect(mixed.body.error.code).toBe("STEP_UP_REQUIRED");
    expect(mixed.body.error.details.approval.summary.changes).toEqual([{ field: "retention", from: "governance, 30 days", to: "compliance, 10 days", loosens: true }]);
    // A destination change with a tightened retention too.
    const moved = await call("PATCH", `${ORG}/audit-export`, admin.cli, { expectedVersion: 1, destination: { bucket: "audit-bucket-2" }, retention: { mode: "compliance", days: 400 } });
    expect(moved.body.error.code).toBe("STEP_UP_REQUIRED");
    expect((await rows("SELECT version FROM audit_exports WHERE state = 'active'"))[0].version).toBe(1);
  });

  it("an approval for one PATCH body is refused for another body, for a new key and for removal", async () => {
    expect((await call("POST", `${ORG}/audit-export`, admin.cli, createBody({ retention: { mode: "governance", days: 30 } }))).status).toBe(201);
    const asked = await call("PATCH", `${ORG}/audit-export`, admin.cli, { expectedVersion: 1, retention: null });
    const approvalId = asked.body.error.details.approval.id as string;
    await approve(approvalId);
    const header = { "Varlatch-Approval": approvalId };
    for (const [method, path, body] of [
      ["PATCH", `${ORG}/audit-export`, { expectedVersion: 1, retention: { mode: "governance", days: 10 } }],
      ["PATCH", `${ORG}/audit-export`, { expectedVersion: 1, destination: { bucket: "audit-bucket-2" } }],
      ["PUT", `${ORG}/audit-export/credential`, { expectedVersion: 1, credential: createBody().credential }],
      ["DELETE", `${ORG}/audit-export?expectedVersion=1`, undefined],
    ] as const) {
      const res = await call(method, path, admin.cli, body, header);
      expect(res.body.error, `${method} ${path}: ${res.text}`).toMatchObject({ code: "APPROVAL_INVALID", details: { reason: "mismatch" } });
    }
    // Unused, it still completes exactly the request it was given for.
    expect(await rows("SELECT consumed_at FROM approval_intents WHERE id = $1", [approvalId])).toEqual([{ consumed_at: null }]);
    const done = await call("PATCH", `${ORG}/audit-export`, admin.cli, { expectedVersion: 1, retention: null }, header);
    expect(done.status, done.text).toBe(200);
    expect(done.body.export.retention).toBeNull();
  });
});

describe("refusals", () => {
  it("a destination change to a refused endpoint: answered before an approval is asked for, recorded once, and not at all for a refused sign-in", async () => {
    expect((await call("POST", `${ORG}/audit-export`, admin.cli, createBody())).status).toBe(201);
    const refusals = async () => (await rows("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'outbound.refused'"))[0].n as number;
    const moveToPrivate = { expectedVersion: 1, destination: { endpoint: "https://10.1.2.3" } };
    const refused = await call("PATCH", `${ORG}/audit-export`, admin.cli, moveToPrivate);
    expect(refused.status, refused.text).toBe(422);
    expect(refused.body.error).toMatchObject({ code: "VALIDATION_FAILED", details: { outbound: expect.any(String) } });
    expect(await intents()).toBe(0);
    expect(await refusals()).toBe(1);
    const recorded = (await rows("SELECT metadata FROM audit_events WHERE event_type = 'outbound.refused'"))[0].metadata;
    expect(typeof recorded === "string" ? JSON.parse(recorded) : recorded).toMatchObject({ purpose: "audit_export", phase: "configuration" });
    await ctx.db.query(
      `INSERT INTO security_controls (organization_id, control, mode, config, version, changed_by, changed_at)
       VALUES ($1, 'passkey-verification', 'enforce', NULL, 1, $2, now())`,
      [orgId, admin.id],
    );
    expect((await call("PATCH", `${ORG}/audit-export`, admin.cli, moveToPrivate)).body.error.code).toBe("PASSKEY_VERIFICATION_REQUIRED");
    expect(await refusals()).toBe(1);
    expect(await intents()).toBe(0);
    expect((await rows("SELECT version FROM audit_exports WHERE state = 'active'"))[0].version).toBe(1);
  });

  it("a person outside the organization gets not-found on every route, sending nothing", async () => {
    expect((await call("POST", `${ORG}/audit-export`, admin.cli, createBody())).status).toBe(201);
    expect((await call("POST", "/v1/organizations", admin.cli, { name: "Beta", slug: "beta" })).status).toBe(201);
    const betaId = (await rows("SELECT id FROM organizations WHERE slug = 'beta'"))[0].id as string;
    const grant = await issueInviteGrant(ctx, { organizationId: betaId, role: "admin", name: "Mallory" }, admin.id);
    const mallory = (await consumeSetupGrant(ctx, grant.token, {})).identityId;
    const token = (await issueCredential(ctx.db, { identityId: mallory, kind: "cli", name: "mallory" })).token;
    const requestsBefore = store.requests;
    for (const [method, path, body] of [
      ["GET", `${ORG}/audit-export`, undefined],
      ["POST", `${ORG}/audit-export`, createBody()],
      ["POST", `${ORG}/audit-export/check`, { destination: createBody().destination, credential: createBody().credential }],
      ["PATCH", `${ORG}/audit-export`, { expectedVersion: 1, retention: null }],
      ["PUT", `${ORG}/audit-export/credential`, { expectedVersion: 1, credential: createBody().credential }],
      ["DELETE", `${ORG}/audit-export?expectedVersion=1`, undefined],
    ] as const) {
      const res = await call(method, path, token, body);
      expect(res.status, `${method} ${path}: ${res.text}`).toBe(404);
      expect(res.body.error.code).toBe("RESOURCE_NOT_FOUND");
    }
    expect(await intents()).toBe(0);
    expect(store.requests).toBe(requestsBefore);
  });

  it("an endpoint the outbound policy refuses is answered after not-found and passkey-verification, and recorded once", async () => {
    const privateEndpoint = { ...createBody().destination, endpoint: "https://10.1.2.3" };
    const refusals = async () => (await rows("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'outbound.refused'"))[0].n as number;
    // No export, no key: the check's not-found comes first, and nothing is recorded.
    const missing = await call("POST", `${ORG}/audit-export/check`, admin.cli, { destination: privateEndpoint });
    expect(missing.status, missing.text).toBe(404);
    expect(await refusals()).toBe(0);
    // With a key: the check answers the refusal and records it once.
    const refusedCheck = await call("POST", `${ORG}/audit-export/check`, admin.cli, { destination: privateEndpoint, credential: createBody().credential });
    expect(refusedCheck.body).toMatchObject({ ok: false, conditionalCreation: null });
    expect(await refusals()).toBe(1);
    // Creating answers 422 and records it once: the transaction rolled back, the record stays.
    const refusedCreate = await call("POST", `${ORG}/audit-export`, admin.cli, createBody({ destination: privateEndpoint }));
    expect(refusedCreate.body.error).toMatchObject({ code: "VALIDATION_FAILED", details: { outbound: expect.any(String) } });
    expect(await refusals()).toBe(2);
    // A sign-in passkey-verification refuses gets that refusal, and nothing is recorded for the endpoint.
    await ctx.db.query(
      `INSERT INTO security_controls (organization_id, control, mode, config, version, changed_by, changed_at)
       VALUES ($1, 'passkey-verification', 'enforce', NULL, 1, $2, now())`,
      [orgId, admin.id],
    );
    for (const [path, body] of [
      [`${ORG}/audit-export`, createBody({ destination: privateEndpoint })],
      [`${ORG}/audit-export/check`, { destination: privateEndpoint, credential: createBody().credential }],
    ] as const) {
      expect((await call("POST", path, admin.cli, body)).body.error.code, path).toBe("PASSKEY_VERIFICATION_REQUIRED");
    }
    expect(await refusals()).toBe(2);
    expect(store.requests).toBe(0);
  });

  it("machine credentials are refused on every write, even holding organization.manage, without an intent", async () => {
    expect((await call("POST", `${ORG}/audit-export`, admin.cli, createBody())).status).toBe(201);
    const machine = await call("POST", `${ORG}/identities`, admin.cli, { name: "deployer", kind: "service" });
    expect(machine.status).toBe(201);
    const granted = await call("POST", `${ORG}/grants`, admin.cli, {
      subjectIdentityId: machine.body.id, scope: { kind: "organization" }, actions: ["organization.manage", "organization.read"],
    });
    expect(granted.status, granted.text).toBe(201);
    const token = machine.body.credential as string;
    // Reading is allowed: it holds organization.manage.
    expect((await call("GET", `${ORG}/audit-export`, token)).status).toBe(200);
    const requestsBefore = store.requests;
    for (const [method, path, body] of [
      ["POST", `${ORG}/audit-export`, createBody()],
      ["POST", `${ORG}/audit-export/check`, { destination: createBody().destination, credential: createBody().credential }],
      ["PATCH", `${ORG}/audit-export`, { expectedVersion: 1, retention: { mode: "compliance", days: 400 } }],
      ["PUT", `${ORG}/audit-export/credential`, { expectedVersion: 1, credential: createBody().credential }],
      ["DELETE", `${ORG}/audit-export?expectedVersion=1`, undefined],
    ] as const) {
      const res = await call(method, path, token, body);
      expect(res.status, `${method} ${path}`).toBe(403);
      expect(res.body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "machine-credential" } });
    }
    expect(await intents()).toBe(0);
    expect(store.requests).toBe(requestsBefore);
  });

  it("a member without organization.manage can neither read nor change it", async () => {
    const grant = await issueInviteGrant(ctx, { organizationId: orgId, role: "member", name: "Bob" }, admin.id);
    const bob = (await consumeSetupGrant(ctx, grant.token, {})).identityId;
    const cli = (await issueCredential(ctx.db, { identityId: bob, kind: "cli", name: "bob" })).token;
    expect((await call("GET", `${ORG}/audit-export`, cli)).status).toBe(403);
    expect((await call("POST", `${ORG}/audit-export`, cli, createBody())).status).toBe(403);
    expect(store.requests).toBe(0);
  });

  it("while frozen: reading is allowed, every write refused; delivery is the worker's (audit-export.test.ts)", async () => {
    expect((await call("POST", `${ORG}/audit-export`, admin.cli, createBody())).status).toBe(201);
    expect((await call("POST", `${ORG}/incident-freeze`, admin.cli, { reason: "A CI token leaked" })).status).toBeLessThan(300);
    expect((await call("GET", `${ORG}/audit-export`, admin.cli)).status).toBe(200);
    const requestsBefore = store.requests;
    for (const [method, path, body] of [
      ["POST", `${ORG}/audit-export/check`, { destination: createBody().destination }],
      ["PATCH", `${ORG}/audit-export`, { expectedVersion: 1, retention: null }],
      ["PUT", `${ORG}/audit-export/credential`, { expectedVersion: 1, credential: createBody().credential }],
      ["DELETE", `${ORG}/audit-export?expectedVersion=1`, undefined],
    ] as const) {
      expect((await call(method, path, admin.cli, body)).body.error.code, `${method} ${path}`).toBe("ORGANIZATION_FROZEN");
    }
    expect(await intents()).toBe(0);
    expect(store.requests).toBe(requestsBefore);
  });

  it("while a deletion is pending: refused before not-found, with or without an export", async () => {
    const grant = await issueInviteGrant(ctx, { organizationId: orgId, role: "admin", name: "Second" }, admin.id);
    await consumeSetupGrant(ctx, grant.token, {});
    expect((await call("POST", `${ORG}/deletion`, admin.cli, {})).status).toBeLessThan(300);
    expect((await call("GET", `${ORG}/audit-export`, admin.cli)).status).toBe(200);
    for (const [method, path, body] of [
      ["POST", `${ORG}/audit-export`, createBody()],
      ["PATCH", `${ORG}/audit-export`, { expectedVersion: 1, retention: null }],
      ["PUT", `${ORG}/audit-export/credential`, { expectedVersion: 1, credential: createBody().credential }],
      ["DELETE", `${ORG}/audit-export?expectedVersion=1`, undefined],
    ] as const) {
      expect((await call(method, path, admin.cli, body)).body.error.code, `${method} ${path}`).toBe("ORGANIZATION_DELETING");
    }
    expect(await intents()).toBe(0);
    expect(store.requests).toBe(0);
  });

  it("switched off by the host operator: shown as off, creating refused, removal still possible", async () => {
    expect((await call("POST", `${ORG}/audit-export`, admin.cli, createBody())).status).toBe(201);
    build({ auditExport: false });
    expect((await call("GET", `${ORG}/audit-export`, admin.cli)).body).toMatchObject({ enabled: false, export: { state: "active" } });
    expect((await call("PATCH", `${ORG}/audit-export`, admin.cli, { expectedVersion: 1, retention: { mode: "governance", days: 1 } })).body.error)
      .toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "audit-export-off" } });
    const removed = await withStepUp("DELETE", `${ORG}/audit-export?expectedVersion=1`, undefined, "audit_export.remove");
    expect(removed.answer.status, removed.answer.text).toBe(200);
    expect((await call("POST", `${ORG}/audit-export`, admin.cli, createBody())).body.error)
      .toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "audit-export-off" } });
  });

  it("passkey-verification at enforce refuses a sign-in it does not accept before any intent, probe or change", async () => {
    expect((await call("POST", `${ORG}/audit-export`, admin.cli, createBody())).status).toBe(201);
    await ctx.db.query(
      `INSERT INTO security_controls (organization_id, control, mode, config, version, changed_by, changed_at)
       VALUES ($1, 'passkey-verification', 'enforce', NULL, 1, $2, now())`,
      [orgId, admin.id],
    );
    const requestsBefore = store.requests;
    for (const [method, path, body] of [
      ["PATCH", `${ORG}/audit-export`, { expectedVersion: 1, retention: null }],
      ["PATCH", `${ORG}/audit-export`, { expectedVersion: 1, destination: { bucket: "elsewhere" } }],
      ["PUT", `${ORG}/audit-export/credential`, { expectedVersion: 1, credential: createBody().credential }],
      ["DELETE", `${ORG}/audit-export?expectedVersion=1`, undefined],
      ["POST", `${ORG}/audit-export/check`, { destination: createBody().destination }],
    ] as const) {
      const res = await call(method, path, admin.cli, body);
      expect(res.body.error?.code, `${method} ${path}: ${res.text}`).toBe("PASSKEY_VERIFICATION_REQUIRED");
    }
    expect(await intents()).toBe(0);
    expect(store.requests).toBe(requestsBefore);
    expect((await rows("SELECT version FROM audit_exports WHERE state = 'active'"))[0].version).toBe(1);
  });
});
