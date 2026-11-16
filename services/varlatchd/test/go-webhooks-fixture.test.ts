// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.7b's parity fixture (ADR-0059 step 4, feature-parity decisions 3
 * and 9), on the parity kit (go-fixture-kit.ts): audit webhooks, built
 * through this server's own /v1 API, a table of requests with this
 * server's answers (listWebhooks, createWebhook, updateWebhook,
 * revokeWebhook), and one delivery pass with the requests it sends.
 * go/server/webhooks' parity test replays both against varlatchd.
 *
 * The database: alice (the bootstrap Installation Admin); Organizations
 * made through /v1: acme (every control off), rep (admin-step-up at
 * report), enf (at enforce), frozen (an incident freeze), deleting (a
 * deletion scheduled, one webhook suspended by it) and beta. Webhooks in
 * each, made through /v1 before the controls, the freeze and the deletion:
 * filtered and not, to a public name, to a private name the allow list
 * opens, to a loopback address, to a name that does not resolve, one that
 * fails, one revoked. Then audit events in acme: a Project and an
 * environment, a Project deleted since (its events are not delivered) and
 * a deletion lifecycle event (not delivered either). People: bob (a
 * member of acme), carol (in none). Approval intents of alice's second CLI
 * credential in enf, bound to exact requests of the table. The signing
 * secrets the creations returned are kept in the file (`secrets`), so the
 * envelopes can be sealed again; the answers mask a new secret.
 *
 * The deliveries: on a copy of the file's rows, with the clock at
 * DELIVERY_AT, one pass of deliverWebhooksOnce through a recording fetch
 * that answers 500 for the path /fail and 200 otherwise. The file keeps
 * each request (webhookId, the target as fetch sends it, Content-Type,
 * the signature header, the body), ordered by webhook, and each webhook's
 * delivery state afterwards. The signature over the same body at the same
 * second is the proof that a server opened the secret this code sealed
 * (G3 at the database level for webhook secrets).
 *
 * Two files, one per release whose envelopes must open (G3):
 *   - webhooks-v0.22.0.json: every envelope sealed by this code;
 *   - webhooks-v0.21.0.json: the same rows with the canary, every
 *     Organization KEK and every webhook secret sealed again by v0.21.0's
 *     crypto code (git show at the tag).
 * With VARLATCH_GO_SEALED_WEBHOOKS=<file>, the same checks run on a file
 * the Go tests wrote (go test ./server/webhooks -run TestGoSealedFixture
 * -args -write-go-sealed=<file>): the same rows sealed again by Go, which
 * this server's own delivery must open (go.yml, go-binary job).
 *
 * Every run checks the committed files: their requests must be the
 * table's, and this server, on their rows, must give the recorded answers
 * and deliveries. After a change, regenerate them and commit the result:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-webhooks-fixture.test.ts
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { recordAuditEvent } from "../src/audit/events.js";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { newId } from "../src/db/ids.js";
import { approvalHash, canonicalJson, type ApprovalBinding } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { webhookCreateBinding, webhookDeleteBinding, webhookUpdateBinding } from "../src/domain/integrationstepup.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { deliverWebhooksOnce } from "../src/domain/webhooks.js";
import { OutboundPolicy, type Resolver } from "../src/net/outbound.js";
import { migratedTestDb } from "./helpers/pglite.js";
import {
  expectCurrentTable, expectSameAnswers, expectSameRows, exportRows, loadRows, record, resealWith, withIds,
  type Fixture, type RequestCase, type Row, type SideTable, type Table,
} from "./go-fixture-kit.js";

// The unwrapped app: some requests are outside the OpenAPI document on
// purpose (bodies that are not JSON, extra members).
const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const OUT_DIR = new URL("../../../go/server/paritytest/testdata/", import.meta.url);
const FILES = { "v0.22.0": "webhooks-v0.22.0.json", "v0.21.0": "webhooks-v0.21.0.json" } as const;

/** The public URL both servers run with: approvals need one. */
export const PUBLIC_URL = "http://127.0.0.1:8686";

/** The allow list and resolver both servers run with. */
export const ALLOW = "hooks.internal,127.0.0.1/32:*";
export const RESOLVE: Record<string, { address: string; family: 4 | 6 }[]> = {
  "hooks.public.example": [{ address: "93.184.216.34", family: 4 }],
  "hooks.internal": [{ address: "10.1.2.3", family: 4 }],
  "intranet.example": [{ address: "192.168.1.20", family: 4 }],
};
const resolve: Resolver = async (name) => {
  const a = RESOLVE[name];
  if (!a) throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${name}`), { code: "ENOTFOUND" });
  return a;
};
const policy = () => new OutboundPolicy(ALLOW, { resolve, log: () => {} });

/** The delivery pass's clock: the second every signature is made at. */
export const DELIVERY_AT = Date.parse("2026-06-01T12:00:00.000Z");

const TABLES: Table[] = [
  { name: "installation", orderBy: "id", random: ["kek_canary"] },
  { name: "identities", orderBy: "id" },
  { name: "credentials", orderBy: "id", random: ["token_hash"] },
  { name: "organizations", orderBy: "id", random: ["wrapped_org_kek"] },
  { name: "org_memberships", orderBy: "organization_id, identity_id" },
  { name: "projects", orderBy: "id" },
  { name: "environments", orderBy: "id" },
  { name: "security_controls", orderBy: "organization_id, control" },
  { name: "approval_intents", orderBy: "id", random: ["body_hash", "query_hash"] },
  { name: "organization_freezes", orderBy: "id" },
  { name: "organization_deletions", orderBy: "id" },
  { name: "webhooks", orderBy: "id", random: ["secret_envelope"] },
  // The control changes made through /v1 carry the build's request ids.
  { name: "audit_events", orderBy: "event_order", random: ["request_id"] },
];

const SIDE: SideTable[] = [
  {
    name: "webhooks", key: ["id"], sortBy: ["organization_id", "url"],
    volatile: ["secret_envelope", "created_at", "updated_at", "revoked_at", "cursor_occurred_at"],
  },
  { name: "approval_intents", key: ["id"], sortBy: ["organization_id", "operation", "target", "body_hash"], volatile: ["created_at", "expires_at", "consumed_at", "closed_at"] },
];

const ORG = "/v1/organizations";

/** Fixed approval intent ids: a request's Varlatch-Approval header names them. */
const aprId = (s: string) => `apr_${s.padEnd(26, "a")}`;
const APPROVALS = { create: aprId("create"), update: aprId("update"), revoke: aprId("revoke"), otherBody: aprId("otherbody") } as const;

/** The table of requests. */
function requestTable(): RequestCase[] {
  const approval = (id?: string) => (id !== undefined ? { headers: { "Varlatch-Approval": id } } : {});
  const list = (name: string, org: string, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "GET", path: `${ORG}/${org}/webhooks`, credential });
  const create = (name: string, org: string, body: unknown, credential = "alice", approvalId?: string): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/webhooks`, credential, body, masked: ["secret"], ...approval(approvalId) });
  const createRaw = (name: string, org: string, rawBody: string): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/webhooks`, credential: "alice", rawBody });
  const update = (name: string, org: string, hook: string, body: unknown, extra: Partial<RequestCase> = {}): Omit<RequestCase, "id"> =>
    ({ name, method: "PATCH", path: `${ORG}/${org}/webhooks/${hook}`, credential: "alice", body, ...extra });
  const revoke = (name: string, org: string, hook: string, extra: Partial<RequestCase> = {}): Omit<RequestCase, "id"> =>
    ({ name, method: "DELETE", path: `${ORG}/${org}/webhooks/${hook}`, credential: "alice", ...extra });
  const pub = "https://hooks.public.example";
  return withIds([
    // listWebhooks: organization.manage, existence hidden; inspection while frozen.
    list("list", "acme"),
    list("list by id", "{acmeId}"),
    list("list as a member", "acme", "bob"),
    list("list as an outsider", "acme", "carol"),
    list("list a frozen Organization", "frozen"),
    list("list an Organization being deleted", "deleting"),
    list("list an unknown Organization", "nope"),

    // createWebhook, controls off.
    create("create with event types", "acme", { url: `${pub}/c1?token=c1`, eventTypes: ["value.disclosed", "authentication.failed"] }),
    create("create for every event", "acme", { url: `${pub}/c2` }),
    create("create with duplicate event types", "acme", { url: `${pub}/c3`, eventTypes: ["b.b", "a.a", "b.b"] }),
    create("create to a private name the allow list opens", "acme", { url: "https://hooks.internal/c4?k=1" }),
    create("create to a loopback address", "acme", { url: "http://127.0.0.1:9/c5" }),
    create("create to a name that does not resolve", "acme", { url: "https://missing.example/c6" }),
    create("create with extra members", "acme", { url: `${pub}/c7`, extra: true }),
    create("create to a private name", "acme", { url: "https://intranet.example/x" }),
    create("create to a private address", "acme", { url: "https://10.0.0.7/x" }),
    create("create to the metadata address", "acme", { url: "http://169.254.169.254/latest" }),
    create("create over plain http", "acme", { url: "http://hooks.public.example/x" }),
    create("create, ftp", "acme", { url: "ftp://hooks.public.example/x" }),
    create("create, userinfo", "acme", { url: "https://u:p@hooks.public.example/x" }),
    create("create, a username only", "acme", { url: "https://u@hooks.public.example/x" }),
    create("create, not a URL", "acme", { url: "not a url" }),
    create("create, no URL", "acme", {}),
    create("create, an empty URL", "acme", { url: "" }),
    create("create, a URL of 2001 characters", "acme", { url: `${pub}/${"x".repeat(2001 - pub.length - 1)}` }),
    create("create, no event types", "acme", { url: `${pub}/x`, eventTypes: [] }),
    create("create, an empty event type", "acme", { url: `${pub}/x`, eventTypes: [""] }),
    create("create, 101 event types", "acme", { url: `${pub}/x`, eventTypes: Array.from({ length: 101 }, (_, i) => `t.${i}`) }),
    create("create, event types as a string", "acme", { url: `${pub}/x`, eventTypes: "value.disclosed" }),
    create("create, null event types", "acme", { url: `${pub}/x`, eventTypes: null }),
    create("create, every member wrong", "acme", { url: 5, eventTypes: [1] }),
    createRaw("create, a body that is not JSON", "acme", "{url:"),
    create("create, a URL with NUL", "acme", { url: `${pub}/a\u0000b` }),
    create("create as a member", "acme", { url: `${pub}/bob` }, "bob"),
    create("create as an outsider", "acme", { url: `${pub}/carol` }, "carol"),
    create("create in a frozen Organization", "frozen", { url: `${pub}/f` }),
    create("create in an Organization being deleted", "deleting", { url: `${pub}/d` }),
    create("create in an Organization being deleted, not a URL", "deleting", { url: "not a url" }),
    create("create in an unknown Organization", "nope", { url: `${pub}/n` }),
    create("create at report", "rep", { url: `${pub}/r` }),
    create("create at enforce, no approval", "enf", { url: `${pub}/e-ask` }),
    create("create at enforce, a refused URL", "enf", { url: "https://10.0.0.7/x" }),
    create("create at enforce, its approval", "enf", { url: `${pub}/approved?token=a` }, "alice2", APPROVALS.create),
    create("create at enforce, another request's approval", "enf", { url: `${pub}/e-other` }, "alice2", APPROVALS.otherBody),

    // updateWebhook, on acme's upd (version 1, event types project.created and environment.created).
    update("update, nothing", "acme", "{updId}", { expectedVersion: 1 }),
    update("update, the same event types reordered", "acme", "{updId}", { expectedVersion: 1, eventTypes: ["environment.created", "project.created"] }),
    update("update, a stale version", "acme", "{updId}", { expectedVersion: 1, eventTypes: null }),
    update("update the URL and every event", "acme", "{updId}", { expectedVersion: 2, url: `${pub}/upd2?token=t2`, eventTypes: null }),
    update("update the token only", "acme", "{updId}", { expectedVersion: 3, url: `${pub}/upd2?token=t3` }),
    update("update to a refused URL", "acme", "{updId}", { expectedVersion: 4, url: "https://intranet.example/upd" }),
    update("update the filter with a key", "acme", "{updId}", { expectedVersion: 4, eventTypes: ["project.created"] }, { headers: { "Idempotency-Key": "k-upd-1" } }),
    update("update the filter with a key again", "acme", "{updId}", { expectedVersion: 4, eventTypes: ["project.created"] }, { headers: { "Idempotency-Key": "k-upd-1" } }),
    update("update with the key and another body", "acme", "{updId}", { expectedVersion: 5, eventTypes: null }, { headers: { "Idempotency-Key": "k-upd-1" } }),
    // With a key, the claim answers before the URL's checks (they run inside withIdempotency).
    update("update with the key and a refused URL", "acme", "{updId}", { expectedVersion: 5, url: "https://intranet.example/k" }, { headers: { "Idempotency-Key": "k-upd-1" } }),
    update("update with the key and userinfo", "acme", "{updId}", { expectedVersion: 5, url: "https://u:p@hooks.public.example/k" }, { headers: { "Idempotency-Key": "k-upd-1" } }),
    // A refusal under a new key: refused, its record rolled back with the claim.
    update("update to a refused URL with a new key", "acme", "{updId}", { expectedVersion: 5, url: "https://intranet.example/k2" }, { headers: { "Idempotency-Key": "k-upd-2" } }),
    update("update with a key too long and an invalid URL", "acme", "{updId}", { expectedVersion: 5, url: "ftp://x" }, { headers: { "Idempotency-Key": "k".repeat(201) } }),
    // U+0000 in the endpoint's webhook id fails the claim's INSERT, before the URL's checks; with no key there is no claim.
    update("update a webhook id with NUL, a key and an invalid URL", "acme", "whk%00x", { expectedVersion: 1, url: "ftp://x" }, { headers: { "Idempotency-Key": "k-nul" } }),
    update("update a webhook id with NUL and an invalid URL", "acme", "whk%00x", { expectedVersion: 1, url: "ftp://x" }),
    update("update, version 0", "acme", "{updId}", { expectedVersion: 0 }),
    update("update, no version", "acme", "{updId}", { url: `${pub}/x` }),
    update("update, a version as a string", "acme", "{updId}", { expectedVersion: "5" }),
    update("update, no event types", "acme", "{updId}", { expectedVersion: 5, eventTypes: [] }),
    update("update, an empty URL", "acme", "{updId}", { expectedVersion: 5, url: "" }),
    update("update, userinfo", "acme", "{updId}", { expectedVersion: 5, url: "https://u:p@hooks.public.example/x" }),
    update("update a refused URL's filter", "acme", "{refusedId}", { expectedVersion: 1, eventTypes: ["project.created"] }),
    update("update an unknown webhook", "acme", "whk_unknownaaaaaaaaaaaaaaaaaa", { expectedVersion: 1, url: `${pub}/u` }),
    update("update a revoked webhook", "acme", "{oldId}", { expectedVersion: 1, url: `${pub}/u` }),
    update("update another Organization's webhook", "acme", "{betaId}", { expectedVersion: 1, eventTypes: null }),
    update("update as a member", "acme", "{updId}", { expectedVersion: 5, eventTypes: null }, { credential: "bob" }),
    update("update in a frozen Organization", "frozen", "{frozenId}", { expectedVersion: 1, eventTypes: null }),
    update("update in an Organization being deleted", "deleting", "{deletingId}", { expectedVersion: 1, eventTypes: null }),
    update("update at report", "rep", "{repId}", { expectedVersion: 1, eventTypes: ["project.created"] }),
    update("update at enforce, no approval", "enf", "{enfId}", { expectedVersion: 1, eventTypes: ["x.y"] }),
    update("update at enforce, a reordering", "enf", "{enfSetId}", { expectedVersion: 1, eventTypes: ["b.b", "a.a"] }),
    update("update at enforce, its approval", "enf", "{enfId}", { expectedVersion: 1, url: `${pub}/enf2` }, { credential: "alice2", headers: { "Varlatch-Approval": APPROVALS.update } }),

    // revokeWebhook.
    revoke("revoke", "acme", "{delId}"),
    revoke("revoke again", "acme", "{delId}"),
    revoke("revoke an unknown webhook", "acme", "whk_unknownaaaaaaaaaaaaaaaaaa"),
    revoke("revoke another Organization's webhook", "acme", "{betaId}"),
    revoke("revoke as a member", "acme", "{updId}", { credential: "bob" }),
    revoke("revoke in a frozen Organization", "frozen", "{frozenId}"),
    revoke("revoke in an Organization being deleted", "deleting", "{deletingId}"),
    revoke("revoke at report", "rep", "{repId}"),
    revoke("revoke at enforce, no approval", "enf", "{enfDelId}"),
    revoke("revoke at enforce, its approval", "enf", "{enfDelId}", { credential: "alice2", headers: { "Varlatch-Approval": APPROVALS.revoke } }),

    list("list afterwards", "acme"),
    list("list enf afterwards", "enf"),
  ]);
}

/** The webhooks build() makes, by name: their ids fill the table's paths. */
const NAMED = {
  updId: ["acme", `https://hooks.public.example/upd`],
  delId: ["acme", `https://hooks.public.example/del`],
  oldId: ["acme", `https://hooks.public.example/old`],
  refusedId: ["acme", `https://intranet.example/refused`],
  betaId: ["beta", `https://hooks.public.example/beta`],
  frozenId: ["frozen", `https://hooks.public.example/frozen`],
  deletingId: ["deleting", `https://hooks.public.example/deleting`],
  repId: ["rep", `https://hooks.public.example/rep`],
  enfId: ["enf", `https://hooks.public.example/enf`],
  enfSetId: ["enf", `https://hooks.public.example/enf-set`],
  enfDelId: ["enf", `https://hooks.public.example/enf-del`],
} as const;

/** Fills a request's placeholders from the file's rows. */
function fillPath(rows: Fixture["rows"]): (p: string) => string {
  const org = (slug: string) => rows.organizations!.find((o) => o.slug === slug)!.id as string;
  const pairs: [string, string][] = [["{acmeId}", org("acme")]];
  for (const [key, [slug, url]] of Object.entries(NAMED)) {
    const hook = rows.webhooks!.find((w) => w.organization_id === org(slug) && w.url === url);
    if (!hook) throw new Error(`no webhook ${url} in ${slug}`);
    pairs.push([`{${key}}`, hook.id as string]);
  }
  return (p) => pairs.reduce((out, [k, v]) => out.replaceAll(k, v), p);
}

type Call = (method: string, path: string, body?: unknown, token?: string) => Promise<any>;

async function build(): Promise<{ ctx: AppCtx & { close: () => Promise<void> }; tokens: Record<string, string>; secrets: Record<string, string> }> {
  const db = await migratedTestDb();
  const ctx = { db, rootKek: generateKey(), close: db.close, outbound: policy() };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId: alice } = await consumeSetupGrant(ctx, grant.token, { adminName: "Alice" });
  const aliceCredential = await issueCredential(ctx.db, { identityId: alice, kind: "cli" });
  // A second CLI credential: enf's approval intents are its own.
  const alice2 = await issueCredential(ctx.db, { identityId: alice, kind: "cli" });
  const tokens: Record<string, string> = { alice: aliceCredential.token, alice2: alice2.token };
  const app = buildApp(ctx, { publicUrl: PUBLIC_URL });
  const call: Call = async (method, path, body, token = tokens.alice) => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await res.text();
    if (res.status >= 300) throw new Error(`${method} ${path}: ${res.status} ${text}`);
    return text ? JSON.parse(text) : null;
  };
  const orgs: Record<string, string> = {};
  for (const slug of ["acme", "rep", "enf", "frozen", "deleting", "beta"]) {
    orgs[slug] = (await call("POST", ORG, { name: slug[0]!.toUpperCase() + slug.slice(1), slug })).id;
  }
  const secrets: Record<string, string> = {};
  const hook = async (org: string, url: string, eventTypes?: string[]) => {
    const created = await call("POST", `${ORG}/${org}/webhooks`, { url, ...(eventTypes ? { eventTypes } : {}) });
    secrets[created.id] = created.secret;
    return created.id as string;
  };
  const pub = "https://hooks.public.example";

  // acme: the table's webhooks, then the delivery pass's.
  await hook("acme", `${pub}/upd`, ["project.created", "environment.created"]);
  await hook("acme", `${pub}/del`);
  const old = await hook("acme", `${pub}/old`);
  await call("DELETE", `${ORG}/acme/webhooks/${old}`);
  await hook("acme", `${pub}/filtered?token=f1`, ["environment.created", "project.created"]);
  await hook("acme", "https://hooks.internal/all?k=1");
  await hook("acme", "http://127.0.0.1:9/loopback");
  await hook("acme", "https://missing.example/fail");
  await hook("acme", `${pub}/nothing`, ["value.disclosed"]);
  // A path that starts with "//": sent as a path, never as an absolute URL.
  await hook("acme", `${pub}//double/slash?x=1`);
  // A webhook to a URL the policy refuses, its URL changed directly
  // (createWebhook refuses it): delivery to it is refused at connection in
  // the server, and the recording fetch here sends it as any other.
  const refused = await hook("acme", `${pub}/refused`);
  await db.query("UPDATE webhooks SET url = 'https://intranet.example/refused' WHERE id = $1", [refused]);

  // acme's events: a Project with an environment, a Project deleted since,
  // a deletion lifecycle event.
  await call("POST", `${ORG}/acme/projects`, { slug: "api", name: "API", contractAuthority: "managed" });
  await call("POST", `${ORG}/acme/projects/api/environments`, { name: "staging", tier: "staging" });
  const gone = await call("POST", `${ORG}/acme/projects`, { slug: "gone", name: "Gone", contractAuthority: "managed" });
  await call("POST", `${ORG}/acme/projects/gone/environments`, { name: "dev", tier: "development" });
  await db.query("UPDATE projects SET deleted_at = '2026-03-03T00:00:00.000Z' WHERE id = $1", [gone.id]);
  await recordAuditEvent(db, { eventType: "organization.deletion_cancelled", decision: "info", actorIdentityId: alice, organizationId: orgs.acme });

  // People: bob a member of acme, carol in none.
  const person = async (name: string, org?: string) => {
    const id = newId("identity");
    await db.query("INSERT INTO identities (id, kind, name, created_at) VALUES ($1, 'human', $2, '2026-01-01T00:00:00.000Z')", [id, name]);
    if (org) await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, $2, 'member')", [orgs[org], id]);
    tokens[name] = (await issueCredential(ctx.db, { identityId: id, kind: "cli" })).token;
  };
  await person("bob", "acme");
  await person("carol");

  // The other Organizations' webhooks, before their controls, freeze and deletion.
  await hook("beta", `${pub}/beta`);
  await hook("frozen", `${pub}/frozen`);
  await hook("deleting", `${pub}/deleting`);
  const suspended = await hook("deleting", `${pub}/suspended`);
  await hook("rep", `${pub}/rep`);
  const enfHook = await hook("enf", `${pub}/enf`);
  await hook("enf", `${pub}/enf-set`, ["a.a", "b.b"]);
  const enfDel = await hook("enf", `${pub}/enf-del`);
  await call("POST", `${ORG}/beta/projects`, { slug: "web", name: "Web", contractAuthority: "managed" });

  await db.query(
    "INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', 'incident drill')",
    [newId("organizationFreeze"), orgs.frozen, alice],
  );
  const deletion = newId("organizationDeletion");
  await db.query(
    "INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', '2099-03-01T00:00:00.000Z', false)",
    [deletion, orgs.deleting, alice],
  );
  await db.query("UPDATE webhooks SET suspended_by_deletion = $1 WHERE id = $2", [deletion, suspended]);
  const set = (org: string, body: unknown) => call("PATCH", `${ORG}/${org}/security/controls/admin-step-up`, body);
  await set("rep", { mode: "report", expectedVersion: 0 });
  await set("enf", { mode: "report", expectedVersion: 0 });
  await set("enf", { mode: "enforce", expectedVersion: 1 });

  // Approval intents of alice's second CLI credential in enf, each binding
  // one request of the table exactly as the operation binds it.
  const intent = async (id: string, binding: ApprovalBinding) =>
    db.query(
      `INSERT INTO approval_intents
         (id, credential_id, identity_id, organization_id, operation, target, body_hash, query_hash, expected_version, summary, origin,
          created_at, expires_at, poll_interval, approved_at, approved_with_passkey_id, approval_user_verified)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10::jsonb, 'cli',
               '2026-01-10T00:00:00.000Z', '2099-01-01T00:00:00.000Z', 5, '2026-01-10T00:01:00.000Z', 'PasskeyConf001', true)`,
      [
        id, alice2.credentialId, alice, orgs.enf, binding.operation, canonicalJson(binding.target),
        approvalHash(ctx.rootKek, "body", binding.body), approvalHash(ctx.rootKek, "query", binding.query),
        binding.expectedVersion, JSON.stringify(binding.summary),
      ],
    );
  const enf = { id: orgs.enf!, name: "Enf" };
  await intent(APPROVALS.create, webhookCreateBinding(enf, { url: `${pub}/approved?token=a` }));
  await intent(APPROVALS.otherBody, webhookCreateBinding(enf, { url: `${pub}/something-else` }));
  await intent(APPROVALS.update, webhookUpdateBinding(enf, { id: enfHook, url: `${pub}/enf`, eventTypes: null, version: 1 }, { url: `${pub}/enf2`, eventTypes: null }, 1));
  await intent(APPROVALS.revoke, webhookDeleteBinding(enf, { id: enfDel, url: `${pub}/enf-del`, eventTypes: null, version: 1 }));
  await accessCountsSettled();
  return { ctx, tokens, secrets };
}

/** One delivery request, as the recording fetch saw it. */
export interface Delivery {
  webhookId: string;
  /** Origin, path and query, as fetch sends them. */
  target: string;
  contentType: string;
  signature: string;
  body: string;
}

/** The delivery pass on a copy of the file's rows: the requests, and each webhook's state afterwards. */
async function deliveries(f: Fixture): Promise<{ deliveries: Delivery[]; delivered: Row[] }> {
  const db = await loadRows(f.rows, TABLES);
  await db.query("UPDATE audit_position SET value = (SELECT coalesce(max(event_order), 0) FROM audit_events) WHERE singleton");
  const now = vi.spyOn(Date, "now").mockReturnValue(DELIVERY_AT);
  try {
    const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex"), outbound: policy() };
    const sent: Delivery[] = [];
    const recording = (async (input: string | URL, init?: RequestInit) => {
      const u = new URL(String(input));
      const headers = new Headers(init?.headers);
      const body = String(init?.body);
      sent.push({
        webhookId: (JSON.parse(body) as { webhookId: string }).webhookId,
        target: u.origin + u.pathname + u.search,
        contentType: headers.get("content-type") ?? "",
        signature: headers.get("x-varlatch-signature") ?? "",
        body,
      });
      return new Response(null, { status: u.pathname === "/fail" ? 500 : 200 });
    }) as typeof fetch;
    await deliverWebhooksOnce(ctx, recording);
    sent.sort((a, b) => (a.webhookId < b.webhookId ? -1 : a.webhookId > b.webhookId ? 1 : 0));
    const delivered = (await db.query(
      "SELECT id, failure_count, last_status, cursor_order::text AS cursor_order, cursor_event_id FROM webhooks ORDER BY id",
    )).rows as Row[];
    return { deliveries: sent, delivered };
  } finally {
    now.mockRestore();
    await db.close();
  }
}

/** The file's answers, recorded on its own rows. */
async function replay(f: Fixture): Promise<Awaited<ReturnType<typeof record>>> {
  const db = await loadRows(f.rows, TABLES);
  await db.query("UPDATE audit_position SET value = (SELECT coalesce(max(event_order), 0) FROM audit_events) WHERE singleton");
  try {
    const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex"), outbound: policy() };
    return await record(ctx, buildApp(ctx, { publicUrl: PUBLIC_URL }), f, f.requests, fillPath(f.rows));
  } finally {
    await db.close();
  }
}

type WebhooksFixture = Fixture & { secrets: Record<string, string>; deliveries: Delivery[]; delivered: Row[] };

describe.skipIf(process.env.VARLATCH_WRITE_GO_VECTORS !== "1")("writing the fixtures", () => {
  it("builds the database, records the answers and deliveries, and writes both files", async () => {
    const { ctx, tokens, secrets } = await build();
    try {
      const rows = await exportRows(ctx.db, TABLES);
      for (const ref of ["v0.22.0", "v0.21.0"] as const) {
        const fileRows = structuredClone(rows);
        if (ref === "v0.21.0") await resealWith(ref, ctx.rootKek, fileRows, () => "", (w) => secrets[w.id as string]!);
        const draft: WebhooksFixture = {
          comment: "Written by services/varlatchd/test/go-webhooks-fixture.test.ts from the TypeScript server's own answers; do not edit.",
          ref,
          serverVersion: SERVER_VERSION,
          rootKek: ctx.rootKek.toString("hex"),
          tokens,
          secrets,
          rows: fileRows,
          sideTables: SIDE,
          requests: requestTable().map((c) => ({ ...c, expect: { status: 0, headers: {}, body: "" }, audit: [], side: {} })),
          counters: [],
          deliveries: [],
          delivered: [],
        };
        const fixture = { ...draft, ...(await replay(draft)), ...(await deliveries(draft)) };
        writeFileSync(new URL(FILES[ref], OUT_DIR), JSON.stringify(fixture, null, 2) + "\n");
      }
    } finally {
      await ctx.close();
    }
  }, 600_000);
});

async function expectFixture(f: WebhooksFixture) {
  expect(f.serverVersion).toBe(SERVER_VERSION);
  expectCurrentTable(f, requestTable());
  expect(f.sideTables).toEqual(SIDE);
  expectSameAnswers(f, await replay(f));
  const got = await deliveries(f);
  expect(got.deliveries).toEqual(f.deliveries);
  expect(got.delivered).toEqual(f.delivered);
}

describe("the webhooks fixtures are this server's answers", () => {
  for (const [ref, file] of Object.entries(FILES)) {
    it(file, async () => {
      const f = JSON.parse(readFileSync(new URL(file, OUT_DIR), "utf8")) as WebhooksFixture;
      expect(f.ref).toBe(ref);
      await expectFixture(f);
      // The deliveries cover what they must: signed bodies for several
      // webhooks, a failure, nothing for the revoked, suspended, deleting
      // or refused-by-filter ones.
      expect(f.deliveries.length).toBeGreaterThanOrEqual(6);
      expect(f.delivered.some((r) => r.last_status === "500")).toBe(true);
      if (ref === "v0.22.0") {
        const { ctx } = await build();
        try {
          expectSameRows(TABLES, f.rows, await exportRows(ctx.db, TABLES));
        } finally {
          await ctx.close();
        }
      }
    }, 300_000);
  }
  const goSealed = process.env.VARLATCH_GO_SEALED_WEBHOOKS;
  it.skipIf(!goSealed)("webhook secrets the Go server sealed open here with the same deliveries", async () => {
    if (!existsSync(goSealed!)) throw new Error(`${goSealed}: no such file`);
    const f = JSON.parse(readFileSync(goSealed!, "utf8")) as WebhooksFixture;
    expect(f.comment).toMatch(/Go/);
    await expectFixture(f);
  }, 300_000);
});
