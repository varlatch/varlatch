// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.12b's parity fixture (ADR-0059 step 4, feature-parity decision 3),
 * on the parity kit (go-fixture-kit.ts): Organization deletion (ADR-0051
 * Decisions 4 to 8: scheduling under admin-step-up's organization.delete,
 * a second admin's approval, cancelling, the due run) and the audit-access
 * tombstone (Decision 8: a deleted Organization's audit for its readers,
 * the Installation Admin's list and reader removal), built through this
 * server's own /v1 API, a table of requests with this server's answers and
 * the rows each one changed. go/server/orgdeletion's parity test replays it
 * against varlatchd.
 *
 * The due run is not a request: the table's "run" entries go to
 * RUN_PATH, which both sides answer themselves, not with their server.
 * Its body names Organizations whose open deletion it makes due first
 * (scheduled 40 days earlier, due a second ago, on that side's own
 * clock); then one pass of the deletion loop runs (runDueDeletions), and
 * the answer is its outcomes. So its rows and events are compared like a
 * request's.
 *
 * The database: alice (the bootstrap Installation Admin) with a second CLI
 * credential (alice2, whose approval intent enf holds); dave, an admin of
 * acme and delta; bob, a member of acme (in its group ops) and of delta;
 * erin, a member of acme with audit.read through a Grant; frank, a
 * disabled member of acme; carol, in none. Organizations made through /v1:
 *   - acme: its deletion scheduled (3 days, approval required) through
 *     /v1 while it held a Project with values, a Capability, a Platform
 *     Connection with a live and a paused Sync Target, a webhook, an
 *     audit export (to the fake S3 server), a GitHub App with an
 *     unfinished registration, machine identities with credentials and an
 *     OIDC binding, a pending invitation, an open approval intent and a
 *     report counter;
 *   - beta: one admin, its deletion scheduled (no approval needed), a
 *     machine identity and a webhook that the cancel restores;
 *   - delta: two admins, a webhook, a machine, an invitation, a Sync
 *     Target and an App registration, scheduled in the table;
 *   - icy: frozen for an incident, with a deletion that needs no approval;
 *   - enf: admin-step-up at enforce; rep: at report.
 *
 * Every run checks the committed file: its requests must be the table's,
 * and this server, on the file's rows, must give the recorded answers;
 * the rows must still be what this code builds. After a change,
 * regenerate it and commit the result:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-org-deletion-fixture.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { newId } from "../src/db/ids.js";
import { approvalHash, canonicalJson, type ApprovalBinding } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { organizationDeleteBinding } from "../src/domain/deletionstepup.js";
import { runDueDeletions } from "../src/domain/orgdeletion.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { BUCKET, ENDPOINT, FakeS3, FixturePolicy, KEY_GOOD } from "./helpers/audit-export-fake.js";
import { migratedTestDb } from "./helpers/pglite.js";
import {
  expectCurrentTable, expectSameAnswers, expectSameRows, exportRows, loadRows, record, withIds,
  type Fixture, type RequestCase, type SideTable, type Table,
} from "./go-fixture-kit.js";

const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const FILE = new URL("../../../go/server/paritytest/testdata/org-deletion-v0.22.0.json", import.meta.url);

/** The public URL both servers run with: approvals need one. */
const PUBLIC_URL = "http://127.0.0.1:8686";

/** The due run's path, answered by each side itself (see the top). */
export const RUN_PATH = "/__fixture/run-due-deletions";

const TABLES: Table[] = [
  { name: "installation", orderBy: "id", random: ["kek_canary"] },
  { name: "identities", orderBy: "id" },
  { name: "credentials", orderBy: "id", random: ["token_hash"] },
  { name: "setup_grants", orderBy: "id", random: ["token_hash"] },
  { name: "organizations", orderBy: "id", random: ["wrapped_org_kek"] },
  { name: "org_memberships", orderBy: "organization_id, identity_id" },
  { name: "roles", orderBy: "id" },
  { name: "groups", orderBy: "id" },
  { name: "group_members", orderBy: "group_id, identity_id" },
  { name: "grants", orderBy: "id" },
  { name: "projects", orderBy: "id" },
  { name: "contract_revisions", orderBy: "id" },
  { name: "environments", orderBy: "id" },
  { name: "env_values", orderBy: "id" },
  { name: "value_versions", orderBy: "id", random: ["payload", "wrapped_dek"] },
  { name: "capabilities", orderBy: "id" },
  { name: "github_apps", orderBy: "id" },
  { name: "github_app_registrations", orderBy: "state_hash" },
  { name: "platform_connections", orderBy: "id" },
  { name: "sync_targets", orderBy: "id" },
  { name: "webhooks", orderBy: "id" },
  { name: "oidc_bindings", orderBy: "id" },
  { name: "audit_exports", orderBy: "id", random: ["credential_envelope"] },
  { name: "security_controls", orderBy: "organization_id, control" },
  { name: "security_control_counters", orderBy: "organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour" },
  { name: "approval_intents", orderBy: "id", random: ["body_hash", "query_hash"] },
  { name: "organization_freezes", orderBy: "id" },
  { name: "organization_deletions", orderBy: "id" },
  { name: "audit_events", orderBy: "event_order", random: ["request_id"] },
];

const SIDE: SideTable[] = [
  { name: "organizations", key: ["id"], sortBy: ["slug"], volatile: ["wrapped_org_kek", "deleted_at", "org_kek_destroyed_at"] },
  {
    name: "organization_deletions", key: ["id"], sortBy: ["organization_id", "scheduled_at"],
    volatile: ["scheduled_at", "run_after", "approved_at", "cancelled_at", "completed_at"],
  },
  { name: "identities", key: ["id"], sortBy: ["name"], volatile: ["created_at", "last_seen_at"] },
  { name: "credentials", key: ["id"], sortBy: ["identity_id", "kind", "name"], volatile: ["token_hash", "created_at", "expires_at", "revoked_at", "last_used_at"] },
  { name: "setup_grants", key: ["id"], sortBy: ["invite_organization_id", "invite_name"], volatile: ["token_hash", "created_at", "expires_at", "revoked_at"] },
  { name: "org_memberships", key: ["organization_id", "identity_id"], sortBy: ["organization_id", "identity_id"], volatile: ["created_at", "removed_at"] },
  { name: "membership_removals", key: ["id"], sortBy: ["organization_id", "identity_id"], volatile: ["removed_at"] },
  { name: "removal_authority", key: ["removal_id", "environment_id", "action", "source"], sortBy: ["environment_id", "action", "source"], volatile: [] },
  { name: "grants", key: ["id"], sortBy: ["organization_id", "scope", "actions"], volatile: ["created_at", "revoked_at"] },
  { name: "group_members", key: ["group_id", "identity_id"], sortBy: ["group_id", "identity_id"], volatile: ["created_at"] },
  { name: "audit_tombstone_readers", key: ["organization_id", "identity_id"], sortBy: ["organization_id", "identity_id"], volatile: ["added_at", "removed_at"] },
  { name: "projects", key: ["id"], sortBy: ["organization_id", "slug", "deleted_at"], volatile: ["created_at", "deleted_at"] },
  { name: "environments", key: ["id"], sortBy: ["project_id", "name", "deleted_at"], volatile: ["created_at", "deleted_at"] },
  { name: "env_values", key: ["id"], sortBy: ["environment_id", "item_name"], volatile: ["deleted_at"] },
  { name: "value_versions", key: ["id"], sortBy: ["value_id", "version"], volatile: ["erased_at"] },
  { name: "capabilities", key: ["id"], sortBy: ["organization_id", "run_id"], volatile: ["revoked_at"] },
  { name: "github_apps", key: ["id"], sortBy: ["organization_id", "slug"], volatile: ["removed_at", "updated_at"] },
  { name: "github_app_registrations", key: ["state_hash"], sortBy: ["organization_id", "account_login"], volatile: [] },
  { name: "platform_connections", key: ["id"], sortBy: ["organization_id", "name"], volatile: ["created_at", "updated_at", "revoked_at"] },
  { name: "sync_targets", key: ["id"], sortBy: ["organization_id", "canonical_destination"], volatile: ["updated_at", "revoked_at"] },
  { name: "webhooks", key: ["id"], sortBy: ["organization_id", "url"], volatile: ["created_at", "updated_at", "revoked_at"] },
  { name: "oidc_bindings", key: ["id"], sortBy: ["organization_id", "identity_id", "issuer", "subject"], volatile: ["created_at", "revoked_at"] },
  {
    name: "audit_exports", key: ["id"], sortBy: ["organization_id", "state"],
    volatile: ["credential_envelope", "stream_started_at", "conditional_checked_at", "created_at", "updated_at", "removed_at", "drain_deadline"],
  },
  {
    name: "security_control_counters",
    key: ["organization_id", "control", "config_version", "operation", "actor_identity_id", "reason", "bucket_hour"],
    sortBy: ["organization_id", "control", "config_version", "operation", "actor_identity_id", "reason"],
    volatile: ["bucket_hour", "first_seen", "last_seen", "emitted_at"],
  },
  { name: "approval_intents", key: ["id"], sortBy: ["organization_id", "operation", "target", "body_hash"], volatile: ["created_at", "expires_at", "consumed_at", "closed_at"] },
];

const ORG = "/v1/organizations";

/** Fixed approval intent ids: a request's Varlatch-Approval header names them. */
const aprId = (s: string) => `apr_${s.padEnd(26, "a")}`;
const APPROVALS = { enf: aprId("enf"), open: aprId("open") } as const;

/** A deletion id no row has. */
const UNKNOWN_DELETION = "odl_aaaaaaaaaaaaaaaaaaaaaaaaaa";

/** The table of requests. */
function requestTable(): RequestCase[] {
  const get = (name: string, path: string, credential = "alice"): Omit<RequestCase, "id"> => ({ name, method: "GET", path, credential });
  const schedule = (name: string, org: string, body: unknown, extra: Partial<RequestCase> = {}): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/deletion`, credential: "alice", body, ...extra });
  const act = (name: string, org: string, deletion: string, verb: "approve" | "cancel", credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/deletion/${deletion}/${verb}`, credential });
  const run = (name: string, age: string[]): Omit<RequestCase, "id"> => ({ name, method: "POST", path: RUN_PATH, credential: "none", body: { age } });
  const tomb = (name: string, suffix: string, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "GET", path: `/v1/deleted-organizations/{acmeId}/audit-events${suffix}`, credential });
  const removeReader = (name: string, identity: string, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "DELETE", path: `/v1/installation/deleted-organizations/{acmeId}/readers/${identity}`, credential });
  return withIds([
    // Reading the request.
    get("get delta's deletion, none", `${ORG}/delta/deletion`),
    get("get acme's deletion", `${ORG}/acme/deletion`),
    get("get acme's deletion as a member", `${ORG}/acme/deletion`, "bob"),
    get("get acme's deletion as an outsider", `${ORG}/acme/deletion`, "carol"),

    // Scheduling: who may, and the body.
    schedule("schedule as a member", "delta", {}, { credential: "bob" }),
    schedule("schedule as an outsider", "delta", {}, { credential: "carol" }),
    schedule("schedule as a machine", "delta", {}, { credential: "deltasvc" }),
    schedule("schedule, afterDays 0", "delta", { afterDays: 0 }),
    schedule("schedule, afterDays 31", "delta", { afterDays: 31 }),
    schedule("schedule, afterDays 1.5", "delta", { afterDays: 1.5 }),
    schedule("schedule, afterDays a string", "delta", { afterDays: "3" }),
    schedule("schedule, an unknown member", "delta", { afterDays: 3, when: "now" }),
    schedule("schedule, a body that is not an object", "delta", [3]),
    schedule("schedule in a frozen Organization", "icy", {}),
    schedule("schedule delta", "delta", { afterDays: 2 }),
    schedule("schedule delta again", "delta", {}),
    get("get delta's deletion", `${ORG}/delta/deletion`),
    { name: "create a Project while deleting", method: "POST", path: `${ORG}/delta/projects`, credential: "alice",
      body: { slug: "late", name: "Late", contractAuthority: "managed" } },

    // The second admin's approval.
    act("approve as the requester", "acme", "{acmeDeletion}", "approve"),
    act("approve as a member", "acme", "{acmeDeletion}", "approve", "bob"),
    act("approve as an outsider", "acme", "{acmeDeletion}", "approve", "carol"),
    act("approve an unknown request", "acme", UNKNOWN_DELETION, "approve", "dave"),
    act("approve another Organization's request", "acme", "{betaDeletion}", "approve", "dave"),
    act("approve", "acme", "{acmeDeletion}", "approve", "dave"),
    act("approve again", "acme", "{acmeDeletion}", "approve", "dave"),
    act("approve a request that needs none", "beta", "{betaDeletion}", "approve"),
    act("approve in a frozen Organization", "icy", "{icyDeletion}", "approve"),

    // Cancelling.
    act("cancel as a member", "acme", "{acmeDeletion}", "cancel", "bob"),
    act("cancel an unknown request", "beta", UNKNOWN_DELETION, "cancel"),
    act("cancel", "beta", "{betaDeletion}", "cancel"),
    act("cancel again", "beta", "{betaDeletion}", "cancel"),
    get("get beta's deletion afterwards", `${ORG}/beta/deletion`),

    // admin-step-up's organization.delete.
    schedule("schedule at report", "rep", {}),
    schedule("schedule at enforce, no approval", "enf", {}),
    schedule("schedule at enforce, a machine credential", "enf", {}, { credential: "enfsvc" }),
    schedule("schedule at enforce, another body than approved", "enf", { afterDays: 8 }, { credential: "alice2", headers: { "Varlatch-Approval": APPROVALS.enf } }),
    schedule("schedule at enforce, its approval", "enf", { afterDays: 7 }, { credential: "alice2", headers: { "Varlatch-Approval": APPROVALS.enf } }),

    // The due run: acme runs; delta waits for its approval, icy for the
    // freeze's lift; enf is not due.
    run("the due run", ["acme", "delta", "icy"]),
    run("the due run again", ["delta", "icy"]),
    get("get acme afterwards", `${ORG}/acme`),
    get("get acme's deletion afterwards", `${ORG}/acme/deletion`),
    get("list the Organizations afterwards", `${ORG}`),

    // The tombstone.
    tomb("read acme's audit as an admin reader", "?limit=500"),
    tomb("read acme's audit as a Grant's reader", "?limit=500", "erin"),
    tomb("read acme's audit as a member who could not read it", "", "bob"),
    tomb("read acme's audit as an outsider", "", "carol"),
    tomb("read acme's audit, a cursor that is not one", "?cursor=%25%25"),
    tomb("export acme's audit", "/export"),
    tomb("export acme's audit as an outsider", "/export", "carol"),
    get("read a live Organization's tombstone", "/v1/deleted-organizations/{betaId}/audit-events"),
    get("list the tombstones", "/v1/installation/deleted-organizations"),
    get("list the tombstones, not an Installation Admin", "/v1/installation/deleted-organizations", "dave"),
    removeReader("remove a reader, not an Installation Admin", "{erinId}", "dave"),
    removeReader("remove a reader", "{erinId}"),
    removeReader("remove the reader again", "{erinId}"),
    removeReader("remove someone who never was a reader", "{bobId}"),
    tomb("read acme's audit as the removed reader", "", "erin"),
    get("list the tombstones afterwards", "/v1/installation/deleted-organizations"),
  ]);
}

/** Fills a request's placeholders from the file's rows. */
function fillPath(rows: Fixture["rows"]): (p: string) => string {
  const org = (slug: string) => rows.organizations!.find((o) => o.slug === slug)!.id as string;
  const deletion = (slug: string) => rows.organization_deletions!.find((d) => d.organization_id === org(slug))!.id as string;
  const person = (name: string) => rows.identities!.find((i) => i.name === name && i.kind === "human")!.id as string;
  const pairs: [string, string][] = [
    ["{acmeDeletion}", deletion("acme")], ["{betaDeletion}", deletion("beta")], ["{icyDeletion}", deletion("icy")],
    ["{acmeId}", org("acme")], ["{betaId}", org("beta")], ["{erinId}", person("erin")], ["{bobId}", person("bob")],
  ];
  return (p) => pairs.reduce((out, [k, v]) => out.replaceAll(k, v), p);
}

type Call = (method: string, path: string, body?: unknown, token?: string) => Promise<any>;

const item = (name: string, sensitive: boolean) => ({ name, required: { kind: "never" }, sensitive, type: "string" });

async function build(fake: FakeS3): Promise<{ ctx: AppCtx & { close: () => Promise<void> }; tokens: Record<string, string> }> {
  const db = await migratedTestDb();
  const ctx = { db, rootKek: generateKey(), close: db.close, outbound: new FixturePolicy(fake), auditExport: true };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId: alice } = await consumeSetupGrant(ctx, grant.token, { adminName: "Alice" });
  const alice2 = await issueCredential(ctx.db, { identityId: alice, kind: "cli" });
  const tokens: Record<string, string> = { alice: (await issueCredential(ctx.db, { identityId: alice, kind: "cli" })).token, alice2: alice2.token };
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
  for (const slug of ["acme", "beta", "delta", "icy", "enf", "rep"]) {
    orgs[slug] = (await call("POST", ORG, { name: slug[0]!.toUpperCase() + slug.slice(1), slug })).id;
  }
  const people: Record<string, string> = { alice };
  const person = async (name: string, memberships: [string, "admin" | "member"][], disabled = false) => {
    const id = newId("identity");
    await db.query("INSERT INTO identities (id, kind, name, disabled, created_at) VALUES ($1, 'human', $2, $3, '2026-01-01T00:00:00.000Z')", [id, name, disabled]);
    for (const [org, role] of memberships) {
      await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, $2, $3)", [orgs[org], id, role]);
    }
    if (!disabled) tokens[name] = (await issueCredential(ctx.db, { identityId: id, kind: "cli" })).token;
    people[name] = id;
    return id;
  };
  await person("dave", [["acme", "admin"], ["delta", "admin"]]);
  const bob = await person("bob", [["acme", "member"], ["delta", "member"]]);
  const erin = await person("erin", [["acme", "member"]]);
  await person("frank", [["acme", "member"]], true);
  await person("carol", []);

  // erin reads acme's audit through a Grant; bob is in acme's group ops.
  await call("POST", `${ORG}/acme/grants`, { subjectIdentityId: erin, scope: { kind: "organization" }, actions: ["audit.read"] });
  const ops = await call("POST", `${ORG}/acme/groups`, { name: "ops" });
  await call("POST", `${ORG}/acme/groups/${ops.id}/members`, { identityId: bob });

  const machine = async (org: string, name: string, kind: string) => {
    const m = await call("POST", `${ORG}/${org}/identities`, { name, kind });
    tokens[name] = m.credential;
    return m.id as string;
  };
  const svc = await machine("acme", "svc", "service");
  const broker = await machine("acme", "broker", "broker");
  const agent = await machine("acme", "agent", "agent");
  await machine("beta", "betasvc", "service");
  await machine("delta", "deltasvc", "service");
  await machine("enf", "enfsvc", "service");

  // acme's Project, values (one with two versions), and a Capability.
  const app1 = await call("POST", `${ORG}/acme/projects`, { slug: "app", name: "App", contractAuthority: "git" });
  await call("POST", `${ORG}/acme/projects/app/environments`, { name: "development", tier: "development" });
  const rev = await call("POST", `${ORG}/acme/projects/app/contract/revisions`, { contract: { schemaVersion: 1, items: [item("API_KEY", true)] } });
  await call("POST", `${ORG}/acme/projects/app/contract/revisions/${rev.id}/activate`);
  for (const value of ["one", "two"]) await call("PUT", `${ORG}/acme/projects/app/environments/development/values/API_KEY`, { value });
  const dev = (await db.query("SELECT id FROM environments WHERE project_id = $1", [app1.id])).rows[0].id as string;
  await db.query(
    `INSERT INTO capabilities (id, organization_id, broker_identity_id, agent_identity_id, project_id, environment_id, items, destinations,
       targets, secret_hash, run_id, expires_at, created_by, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'run-1', '2099-01-01T00:00:00.000Z', $3, '2026-02-01T00:00:00.000Z')`,
    [newId("capability"), orgs.acme, broker, agent, app1.id, dev, ["API_KEY"], ["api.example.com:443"], JSON.stringify({ API_KEY: ["header:authorization"] }), "0".repeat(64)],
  );

  // Rows nothing here opens: Connections and Sync Targets, webhooks, a
  // GitHub App and registrations, an OIDC binding, a report counter.
  const connection = async (org: string) => {
    const id = newId("platformConnection");
    await db.query(
      `INSERT INTO platform_connections (id, organization_id, platform, base_identity, name, created_by, created_at, credential_envelope)
       VALUES ($1, $2, 'coolify', 'https://coolify.example.com', 'Coolify', $3, '2026-02-01T00:00:00.000Z', '{"fixture":"not opened"}'::jsonb)`,
      [id, orgs[org], alice],
    );
    return id;
  };
  const target = async (org: string, project: string, env: string, conn: string, destination: string, state: string) =>
    db.query(
      `INSERT INTO sync_targets (id, organization_id, project_id, environment_id, connection_id, destination, canonical_destination, mapping,
         created_by, created_at, state, generation, lease_expires_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, '{}'::jsonb, $8, '2026-02-01T00:00:00.000Z', $9, 3, '2026-02-01T01:00:00.000Z', '2026-02-01T00:00:00.000Z')`,
      [newId("syncTarget"), orgs[org], project, env, conn, JSON.stringify({ application: destination }), `coolify:${destination}`, alice, state],
    );
  const acmeConnection = await connection("acme");
  await target("acme", app1.id, dev, acmeConnection, "acme-live", "active");
  await target("acme", app1.id, dev, acmeConnection, "acme-paused", "paused");
  const deltaProject = await call("POST", `${ORG}/delta/projects`, { slug: "web", name: "Web", contractAuthority: "managed" });
  await call("POST", `${ORG}/delta/projects/web/environments`, { name: "development", tier: "development" });
  const deltaDev = (await db.query("SELECT id FROM environments WHERE project_id = $1", [deltaProject.id])).rows[0].id as string;
  await target("delta", deltaProject.id, deltaDev, await connection("delta"), "delta-live", "active");
  for (const org of ["acme", "beta", "delta"]) {
    await db.query(
      `INSERT INTO webhooks (id, organization_id, url, secret_envelope, created_by, created_at, cursor_occurred_at)
       VALUES ($1, $2, $3, '{"fixture":"not opened"}'::jsonb, $4, '2026-02-01T00:00:00.000Z', '2026-02-01T00:00:00.000Z')`,
      [newId("webhook"), orgs[org], `https://hooks.example.com/${org}`, alice],
    );
  }
  await db.query(
    `INSERT INTO github_apps (id, organization_id, github_app_id, slug, client_id, owner_login, owner_id, owner_type, key_envelope, created_by, created_at)
     VALUES ($1, $2, 101, 'acme-varlatch', 'Iv1.acme', 'acme-inc', 501, 'organization', '{"fixture":"not opened"}'::jsonb, $3, '2026-02-01T00:00:00.000Z')`,
    [newId("githubApp"), orgs.acme, alice],
  );
  for (const org of ["acme", "delta"]) {
    await db.query(
      `INSERT INTO github_app_registrations (id, state_hash, organization_id, actor_identity_id, account_login, account_type, created_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, 'organization', '2026-02-01T00:00:00.000Z', '2099-02-01T00:00:00.000Z')`,
      [newId("githubAppRegistration"), `${org}-state-hash`.padEnd(64, "0"), orgs[org], alice, `${org}-inc`],
    );
  }
  await db.query(
    `INSERT INTO oidc_bindings (id, identity_id, organization_id, issuer, audience, subject, created_by, created_at)
     VALUES ($1, $2, $3, 'https://token.actions.githubusercontent.com', 'varlatch', 'repo:acme/app:ref:refs/heads/main', $4, '2026-02-01T00:00:00.000Z')`,
    [newId("oidcBinding"), svc, orgs.acme, alice],
  );
  await db.query(
    `INSERT INTO security_control_counters (organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour, count, first_seen, last_seen)
     VALUES ($1, 'admin-step-up', 1, 'project.delete', $2, 'no-approval', '2026-02-01T00:00:00.000Z', 2, '2026-02-01T00:10:00.000Z', '2026-02-01T00:20:00.000Z')`,
    [orgs.acme, alice],
  );

  // acme's audit export, to the fake S3 server; its key is drained at the run.
  await call("POST", `${ORG}/acme/audit-export`, {
    destination: { endpoint: ENDPOINT, region: "us-east-1", bucket: BUCKET, prefix: "logs", pathStyle: true },
    credential: { accessKeyId: KEY_GOOD, secretAccessKey: "fixture-secret" },
    retention: null,
  });

  // Pending invitations of acme and delta.
  for (const org of ["acme", "delta"]) await call("POST", `${ORG}/${org}/invitations`, { role: "member", name: `${org} guest` });

  // Controls, and the freeze.
  const set = (org: string, body: unknown) => call("PATCH", `${ORG}/${org}/security/controls/admin-step-up`, body);
  await set("rep", { mode: "report", expectedVersion: 0 });
  await set("enf", { mode: "report", expectedVersion: 0 });
  await set("enf", { mode: "enforce", expectedVersion: 1 });
  await db.query(
    "INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', 'incident drill')",
    [newId("organizationFreeze"), orgs.icy, alice],
  );
  await db.query(
    "INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', '2099-03-01T00:00:00.000Z', false)",
    [newId("organizationDeletion"), orgs.icy, alice],
  );

  // Approval intents of alice's second CLI credential: enf's binds its
  // scheduling exactly as the operation binds it; acme's stays open until
  // the deletion closes it.
  const intent = async (id: string, org: string, binding: ApprovalBinding, approved: boolean) =>
    db.query(
      `INSERT INTO approval_intents
         (id, credential_id, identity_id, organization_id, operation, target, body_hash, query_hash, expected_version, summary, origin,
          created_at, expires_at, poll_interval, approved_at, approved_with_passkey_id, approval_user_verified)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10::jsonb, 'cli',
               '2026-01-10T00:00:00.000Z', '2099-01-01T00:00:00.000Z', 5, $11, $12, $13)`,
      [
        id, alice2.credentialId, alice, orgs[org], binding.operation, canonicalJson(binding.target),
        approvalHash(ctx.rootKek, "body", binding.body), approvalHash(ctx.rootKek, "query", binding.query),
        binding.expectedVersion, JSON.stringify(binding.summary),
        approved ? "2026-01-10T00:01:00.000Z" : null, approved ? "PasskeyConf001" : null, approved ? true : null,
      ],
    );
  await intent(APPROVALS.enf, "enf", organizationDeleteBinding({ id: orgs.enf!, name: "Enf" }, 7, 1), true);
  await intent(APPROVALS.open, "acme", organizationDeleteBinding({ id: orgs.acme!, name: "Acme" }, 7, 2), false);

  // acme's and beta's deletions, scheduled through /v1.
  await call("POST", `${ORG}/acme/deletion`, { afterDays: 3 });
  await call("POST", `${ORG}/beta/deletion`, {});
  await accessCountsSettled();
  // Last use long ago, so a replay records the first use whenever it runs.
  await db.query("UPDATE identities SET last_seen_at = '2026-01-15T00:00:00.000Z' WHERE last_seen_at > '2026-03-02T00:00:00.000Z'");
  await db.query("UPDATE credentials SET last_used_at = '2026-01-15T00:00:00.000Z' WHERE last_used_at > '2026-03-02T00:00:00.000Z'");
  return { ctx, tokens };
}

/** A deleted Organization's audit page, and its export. */
const TOMBSTONE_PAGE = /^\/v1\/deleted-organizations\/[^/]+\/audit-events(\?|$)/;
const TOMBSTONE_EXPORT = /^\/v1\/deleted-organizations\/[^/]+\/audit-events\/export(\?|$)/;

/** An export's NDJSON with every event's request id masked. */
export function exportMasked(text: string): string {
  return text.split("\n").map((line) => (line === "" ? line : JSON.stringify(masked(JSON.parse(line) as Item)))).join("\n");
}

type Item = { occurredAt: string; eventType: string; resource: { identityId?: string } | null; requestId: string | null };

/** An event of a tombstone page or export with its request id masked: the table's requests get new ones each run. */
const masked = (e: Item): Item => ({ ...e, requestId: e.requestId === null ? null : "{requestId}" });

/**
 * A tombstone page as both sides compare it: every event's request id
 * masked, and its ties in a fixed order. Events of one transaction share
 * their time, and the server orders them by their random ids, so on both
 * sides those are ordered by type, then the identity they name (the file's
 * ids), the rest kept newest first. go/server/orgdeletion's parity test
 * does the same.
 */
export function tiesInOrder(body: string): string {
  const page = JSON.parse(body) as { items?: Item[] };
  if (!Array.isArray(page.items)) return body;
  page.items = page.items.map(masked);
  const key = (e: Item) => `${e.eventType}\u0000${e.resource?.identityId ?? ""}`;
  // The page is newest first already: events of different times keep
  // their places; a tie is ordered by its key.
  const at = new Map(page.items.map((e, i) => [e, i]));
  page.items.sort((a, b) => {
    if (a.occurredAt !== b.occurredAt) return at.get(a)! - at.get(b)!;
    return key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0;
  });
  return JSON.stringify(page);
}

/** The app, with RUN_PATH answered by the due run (see the top). */
function withRun(ctx: AppCtx, app: { request: (path: string, init: RequestInit) => Response | Promise<Response> }) {
  return {
    request: async (path: string, init: RequestInit): Promise<Response> => {
      if (TOMBSTONE_PAGE.test(path) || TOMBSTONE_EXPORT.test(path)) {
        const res = await app.request(path, init);
        if (res.status !== 200) return res;
        const text = await res.text();
        const body = TOMBSTONE_PAGE.test(path) ? tiesInOrder(text) : exportMasked(text);
        return new Response(body, { status: res.status, headers: res.headers });
      }
      if (path !== RUN_PATH) return app.request(path, init);
      const { age } = JSON.parse(String(init.body)) as { age: string[] };
      await ctx.db.query(
        `UPDATE organization_deletions d SET scheduled_at = d.scheduled_at - interval '40 days', run_after = now() - interval '1 second'
         FROM organizations o WHERE o.id = d.organization_id AND o.slug = ANY($1) AND d.cancelled_at IS NULL AND d.completed_at IS NULL`,
        [age],
      );
      const done = await runDueDeletions(ctx);
      return new Response(JSON.stringify({ deletions: done }), { status: 200, headers: { "Content-Type": "application/json" } });
    },
  };
}

/** The file's answers, recorded on its own rows. */
async function replay(f: Fixture): Promise<Awaited<ReturnType<typeof record>>> {
  const db = await loadRows(f.rows, TABLES);
  await db.query("UPDATE audit_position SET value = (SELECT coalesce(max(event_order), 0) FROM audit_events) WHERE singleton");
  try {
    const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex") };
    return await record(ctx, withRun(ctx, buildApp(ctx, { publicUrl: PUBLIC_URL })), f, f.requests, fillPath(f.rows));
  } finally {
    await db.close();
  }
}

describe.skipIf(process.env.VARLATCH_WRITE_GO_VECTORS !== "1")("writing the fixture", () => {
  it("builds the database, records the answers and writes the file", async () => {
    const fake = new FakeS3();
    await fake.start();
    const { ctx, tokens } = await build(fake);
    try {
      const draft: Fixture = {
        comment: "Written by services/varlatchd/test/go-org-deletion-fixture.test.ts from the TypeScript server's own answers; do not edit.",
        ref: "v0.22.0",
        serverVersion: SERVER_VERSION,
        rootKek: ctx.rootKek.toString("hex"),
        tokens,
        rows: await exportRows(ctx.db, TABLES),
        sideTables: SIDE,
        requests: requestTable().map((c) => ({ ...c, expect: { status: 0, headers: {}, body: "" }, audit: [], side: {} })),
        counters: [],
      };
      writeFileSync(FILE, JSON.stringify({ ...draft, ...(await replay(draft)) }, null, 2) + "\n");
    } finally {
      await ctx.close();
      await fake.stop();
    }
  }, 600_000);
});

describe("the organization deletion fixture is this server's answers", () => {
  it("org-deletion-v0.22.0.json", async () => {
    const f = JSON.parse(readFileSync(FILE, "utf8")) as Fixture;
    expect(f.serverVersion).toBe(SERVER_VERSION);
    expectCurrentTable(f, requestTable());
    expect(f.sideTables).toEqual(SIDE);
    expectSameAnswers(f, await replay(f));
    // The due run ended acme, and only acme, with everything it held.
    const run = f.requests.find((r) => r.name === "the due run")!;
    const done = JSON.parse(run.expect.body).deletions as Record<string, unknown>[];
    expect(done).toHaveLength(1);
    expect(done[0]).toMatchObject({
      members: 5, readers: 3, projects: 1, versionsErased: 2, targetsRevoked: 2, identitiesRetired: 3,
      webhooksRemoved: 1, connectionsRevoked: 1, githubAppRemoved: true,
    });
    const fake = new FakeS3();
    await fake.start();
    const { ctx } = await build(fake);
    try {
      expectSameRows(TABLES, f.rows, await exportRows(ctx.db, TABLES));
    } finally {
      await ctx.close();
      await fake.stop();
    }
  }, 300_000);
});
