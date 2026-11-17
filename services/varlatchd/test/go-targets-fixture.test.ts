// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.9c's parity fixture (ADR-0059 step 4, feature-parity decision 3),
 * on the parity kit (go-fixture-kit.ts): Sync Targets, built through this
 * server's own /v1 API, and a table of requests with this server's
 * answers: listOrgSyncTargets, listSyncTargets, createSyncTarget,
 * getSyncTarget, updateSyncTarget, pauseSyncTarget, resumeSyncTarget and
 * revokeSyncTarget. go/server/syncs' parity test replays it against
 * varlatchd. None of these operations calls a platform.
 *
 * The database: alice (the bootstrap Installation Admin); Organizations
 * acme, frozen (a Target, then an incident freeze), deleting (a Target,
 * then a deletion scheduled) and beta. In acme: a Project whose active
 * Contract has a Secret (DATABASE_URL) and a plain item (PORT), with
 * production, dev and staging; Connections on GitHub (two), Coolify, one
 * revoked, and one on a GitHub App removed since (rows written directly);
 * Targets in every state (active, paused, stopped by its failure budget,
 * stopped by a revoked Connection), one with redeploy debt, one with a
 * ledger, notes, drift and a live run. People: bob (a member with a Grant
 * of config.sync.manage on the Organization and no disclosure), carl (a
 * member with config.sync.manage and config.value.read on production),
 * dave (a member), carol (in none).
 *
 * After a change, regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-targets-fixture.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { encryptGitHubAppKey } from "../src/crypto/hierarchy.js";
import { newId } from "../src/db/ids.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { orgKekOf, type OrgRow } from "../src/domain/orgs.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { OutboundPolicy, type Resolver } from "../src/net/outbound.js";
import { migratedTestDb } from "./helpers/pglite.js";
import {
  expectCurrentTable, expectSameAnswers, expectSameRows, exportRows, loadRows, record, withIds,
  type Fixture, type RequestCase, type SideTable, type Table,
} from "./go-fixture-kit.js";

const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const FILE = new URL("../../../go/server/paritytest/testdata/targets-v0.22.0.json", import.meta.url);
export const PUBLIC_URL = "http://127.0.0.1:8686";
const COOLIFY = "https://coolify.public.example";
const resolve: Resolver = async (name) => {
  if (name === "coolify.public.example") return [{ address: "93.184.216.40", family: 4 }];
  throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${name}`), { code: "ENOTFOUND" });
};
const policy = () => new OutboundPolicy("", { resolve, log: () => {} });

const TABLES: Table[] = [
  { name: "installation", orderBy: "id", random: ["kek_canary"] },
  { name: "identities", orderBy: "id" },
  { name: "credentials", orderBy: "id", random: ["token_hash"] },
  { name: "organizations", orderBy: "id", random: ["wrapped_org_kek"] },
  { name: "org_memberships", orderBy: "organization_id, identity_id" },
  { name: "projects", orderBy: "id" },
  { name: "environments", orderBy: "id" },
  { name: "contract_revisions", orderBy: "id" },
  { name: "grants", orderBy: "id" },
  { name: "security_controls", orderBy: "organization_id, control" },
  { name: "organization_freezes", orderBy: "id" },
  { name: "organization_deletions", orderBy: "id" },
  { name: "github_apps", orderBy: "id", random: ["key_envelope"] },
  { name: "platform_connections", orderBy: "id", random: ["credential_envelope"] },
  { name: "sync_targets", orderBy: "id" },
  { name: "sync_ledger", orderBy: "target_id, dest_name" },
  { name: "sync_runs", orderBy: "target_id, generation" },
  { name: "member_integrations", orderBy: "organization_id, identity_id, kind, resource_id" },
  { name: "audit_events", orderBy: "event_order", random: ["request_id"] },
];

const SIDE: SideTable[] = [
  { name: "sync_targets", key: ["id"], sortBy: ["organization_id", "canonical_destination"], volatile: ["created_at", "updated_at", "revoked_at"] },
  { name: "sync_ledger", key: ["target_id", "dest_name"], sortBy: ["target_id", "dest_name"], volatile: ["updated_at"] },
  { name: "member_integrations", key: ["organization_id", "identity_id", "kind", "resource_id"], sortBy: ["organization_id", "kind", "changes"], volatile: ["first_at", "last_at"] },
];

const ORG = "/v1/organizations";
const ENV = (org: string, env: string) => `${ORG}/${org}/projects/api/environments/${env}/sync-targets`;

/** The table of requests. */
function requestTable(): RequestCase[] {
  const listOrg = (name: string, org: string, credential = "alice"): Omit<RequestCase, "id"> => ({ name, method: "GET", path: `${ORG}/${org}/sync-targets`, credential });
  const list = (name: string, org: string, env: string, credential = "alice"): Omit<RequestCase, "id"> => ({ name, method: "GET", path: ENV(org, env), credential });
  const create = (name: string, org: string, env: string, body: unknown, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: ENV(org, env), credential, body });
  const createRaw = (name: string, rawBody: string): Omit<RequestCase, "id"> => ({ name, method: "POST", path: ENV("acme", "production"), credential: "alice", rawBody });
  const get = (name: string, org: string, env: string, target: string, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "GET", path: `${ENV(org, env)}/${target}`, credential });
  const update = (name: string, env: string, target: string, body: unknown, credential = "alice", org = "acme"): Omit<RequestCase, "id"> =>
    ({ name, method: "PATCH", path: `${ENV(org, env)}/${target}`, credential, body });
  const state = (name: string, env: string, target: string, verb: "pause" | "resume", credential = "alice", org = "acme", query = ""): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ENV(org, env)}/${target}/${verb}${query}`, credential, body: {} });
  const revoke = (name: string, env: string, target: string, credential = "alice", org = "acme"): Omit<RequestCase, "id"> =>
    ({ name, method: "DELETE", path: `${ENV(org, env)}/${target}`, credential });
  const gh = "{gh}";
  return withIds([
    // listOrgSyncTargets and listSyncTargets.
    listOrg("list the Organization's", "acme"),
    listOrg("list by id", "{acmeId}"),
    listOrg("list with a Grant", "acme", "bob"),
    listOrg("list as a member", "acme", "dave"),
    listOrg("list with an environment Grant", "acme", "carl"),
    listOrg("list a frozen Organization's", "frozen"),
    listOrg("list as an outsider", "acme", "carol"),
    list("list production's", "acme", "production"),
    list("list dev's", "acme", "dev"),
    list("list with an environment Grant, production", "acme", "production", "carl"),
    list("list with an environment Grant, dev", "acme", "dev", "carl"),
    list("list an unknown environment's", "acme", "nope"),
    list("list a frozen Organization's environment", "frozen", "production"),

    // createSyncTarget.
    create("create a wildcard", "acme", "staging", { connectionId: gh, destination: { repo: "New-One" }, mapping: { kind: "wildcard" } }),
    create("create with exclusions", "acme", "staging", { connectionId: gh, destination: { repo: "excl", environment: "prod" }, mapping: { kind: "wildcard", exclude: ["Z_*", "A", "Z_*", "DEBUG_*"] }, removeOrphans: true }),
    create("create explicit items", "acme", "staging", { connectionId: gh, destination: { repo: "explicit" }, mapping: { kind: "explicit", items: [{ name: "DATABASE_URL", rename: "db_url" }, { name: "PORT" }] }, redeploy: true }),
    create("create on Coolify", "acme", "staging", { connectionId: "{coolify}", destination: { applicationUuid: "app-new-1", buildTime: true, platformExpands: ["B", "A"] }, mapping: { kind: "wildcard" } }),
    create("create, a claimed destination", "acme", "staging", { connectionId: gh, destination: { repo: "api" }, mapping: { kind: "wildcard" } }),
    create("create, an invalid destination", "acme", "staging", { connectionId: gh, destination: { repo: "a/b" }, mapping: { kind: "wildcard" } }),
    create("create, an invalid exclusion", "acme", "staging", { connectionId: gh, destination: { repo: "x1" }, mapping: { kind: "wildcard", exclude: ["*"] } }),
    create("create, a duplicate item", "acme", "staging", { connectionId: gh, destination: { repo: "x2" }, mapping: { kind: "explicit", items: [{ name: "PORT" }, { name: "PORT" }] } }),
    create("create, two items to one name", "acme", "staging", { connectionId: gh, destination: { repo: "x3" }, mapping: { kind: "explicit", items: [{ name: "PORT" }, { name: "OTHER", rename: "port" }] } }),
    create("create, a name GitHub refuses", "acme", "staging", { connectionId: gh, destination: { repo: "x4" }, mapping: { kind: "explicit", items: [{ name: "PORT", rename: "github_token" }] } }),
    create("create, a name a Coolify service sets", "acme", "staging", { connectionId: "{coolify}", destination: { serviceUuid: "svc-new-1" }, mapping: { kind: "explicit", items: [{ name: "PORT", rename: "SERVICE_URL_APP" }] } }),
    create("create, an unknown Connection", "acme", "staging", { connectionId: "pcn_unknownaaaaaaaaaaaaaaaaaaa", destination: { repo: "x5" }, mapping: { kind: "wildcard" } }),
    create("create, a revoked Connection", "acme", "staging", { connectionId: "{revokedConn}", destination: { repo: "x6" }, mapping: { kind: "wildcard" } }),
    create("create, a removed App's Connection", "acme", "staging", { connectionId: "{appConn}", destination: { repo: "x7" }, mapping: { kind: "wildcard" } }),
    create("create, no mapping", "acme", "staging", { connectionId: gh, destination: { repo: "x8" } }),
    create("create, another mapping kind", "acme", "staging", { connectionId: gh, destination: { repo: "x8" }, mapping: { kind: "all" } }),
    create("create, no items", "acme", "staging", { connectionId: gh, destination: { repo: "x8" }, mapping: { kind: "explicit", items: [] } }),
    create("create, a destination that is not a record", "acme", "staging", { connectionId: gh, destination: "api", mapping: { kind: "wildcard" } }),
    create("create, an empty exclusion", "acme", "staging", { connectionId: gh, destination: { repo: "x8" }, mapping: { kind: "wildcard", exclude: [""] } }),
    createRaw("create, a body that is not JSON", "{nope"),
    create("create with a Grant, no disclosure", "acme", "staging", { connectionId: gh, destination: { repo: "bob" }, mapping: { kind: "wildcard" } }, "bob"),
    create("create a plain item with an environment Grant", "acme", "production", { connectionId: gh, destination: { repo: "carl" }, mapping: { kind: "explicit", items: [{ name: "PORT" }] } }, "carl"),
    create("create a Secret with an environment Grant", "acme", "production", { connectionId: gh, destination: { repo: "carl2" }, mapping: { kind: "explicit", items: [{ name: "DATABASE_URL" }] } }, "carl"),
    create("create as a member", "acme", "staging", { connectionId: gh, destination: { repo: "dave" }, mapping: { kind: "wildcard" } }, "dave"),
    create("create in a frozen Organization", "frozen", "production", { connectionId: "{frozenConn}", destination: { repo: "f" }, mapping: { kind: "wildcard" } }),
    create("create in an Organization being deleted", "deleting", "production", { connectionId: "{deletingConn}", destination: { repo: "d" }, mapping: { kind: "wildcard" } }),

    // getSyncTarget.
    get("get a Target with its ledger", "acme", "production", "{tApi}"),
    get("get a Target with notes, drift and a run", "acme", "dev", "{tCoolify}"),
    get("get a Target from another environment", "acme", "dev", "{tApi}"),
    get("get an unknown Target", "acme", "production", "snt_unknownaaaaaaaaaaaaaaaaaaa"),
    get("get as a member", "acme", "production", "{tApi}", "dave"),

    // updateSyncTarget.
    update("update, a stale version", "production", "{tApi}", { expectedVersion: 2, removeOrphans: true }),
    update("update, no version", "production", "{tApi}", { removeOrphans: true }),
    update("update, an operational toggle", "production", "{tApi}", { expectedVersion: 1, removeOrphans: true }),
    update("update, a narrowing exclusion", "production", "{tApi}", { expectedVersion: 2, mapping: { kind: "wildcard", exclude: ["DEBUG_*"] } }),
    update("update, a widening without disclosure", "production", "{tApi}", { expectedVersion: 3, mapping: { kind: "wildcard" } }, "bob"),
    update("update, a widening", "production", "{tApi}", { expectedVersion: 3, mapping: { kind: "wildcard" } }),
    update("update, explicit items", "dev", "{tWeb}", { expectedVersion: 1, mapping: { kind: "explicit", items: [{ name: "DATABASE_URL" }, { name: "PORT", rename: "HTTP_PORT" }] } }),
    update("update, fewer items", "dev", "{tWeb}", { expectedVersion: 2, mapping: { kind: "explicit", items: [{ name: "PORT", rename: "HTTP_PORT" }] } }),
    update("update, a new destination keeping its items", "dev", "{tWeb}", { expectedVersion: 3, destination: { repo: "web2" } }),
    update("update, a destination that is claimed", "dev", "{tWeb}", { expectedVersion: 4, destination: { repo: "api" } }),
    update("update, explicit to wildcard with a Grant (a development environment)", "dev", "{tWeb}", { expectedVersion: 4, mapping: { kind: "wildcard" } }, "bob"),
    update("update, a new Coolify destination", "dev", "{tCoolify}", { expectedVersion: 1, destination: { applicationUuid: "app-uuid-9" } }),
    update("update, re-point to another GitHub Connection", "production", "{tApi}", { expectedVersion: 4, connectionId: "{gh2}" }),
    update("update, re-point across platforms", "production", "{tApi}", { expectedVersion: 5, connectionId: "{coolify}" }),
    update("update, re-point across platforms with a destination", "production", "{tApi}", { expectedVersion: 5, connectionId: "{coolify}", destination: { applicationUuid: "app-uuid-7" } }),
    update("update, re-point to a revoked Connection", "production", "{tApi}", { expectedVersion: 5, connectionId: "{revokedConn}" }),
    update("update, redeploy off", "production", "{tRedeploy}", { expectedVersion: 1, redeploy: false }),
    update("update, an invalid destination", "production", "{tApi}", { expectedVersion: 5, destination: { repo: "" } }),
    update("update, a Target from another environment", "dev", "{tApi}", { expectedVersion: 5, removeOrphans: false }),
    update("update as a member", "production", "{tApi}", { expectedVersion: 5, removeOrphans: false }, "dave"),
    update("update in a frozen Organization", "production", "{frozenTarget}", { expectedVersion: 1, removeOrphans: true }, "alice", "frozen"),

    // pauseSyncTarget, resumeSyncTarget.
    state("pause", "production", "{tPause}", "pause"),
    state("pause again", "production", "{tPause}", "pause"),
    state("pause and wait, no run", "production", "{tApi}", "pause", "alice", "acme", "?wait=true"),
    state("pause a stopped Target", "production", "{tBudget}", "pause"),
    state("pause in a frozen Organization", "production", "{frozenTarget}", "pause", "alice", "frozen"),
    state("pause as a member", "production", "{tPause}", "pause", "dave"),
    state("resume", "production", "{tPause}", "resume"),
    state("resume a Target its failure budget stopped", "production", "{tBudget}", "resume"),
    state("resume a Target whose Connection was revoked", "production", "{tRevokedConn}", "resume"),
    state("resume in a frozen Organization", "production", "{frozenTarget}", "resume", "alice", "frozen"),
    state("resume an unknown Target", "production", "snt_unknownaaaaaaaaaaaaaaaaaaa", "resume"),

    // revokeSyncTarget.
    revoke("revoke", "dev", "{tWeb}"),
    revoke("revoke again", "dev", "{tWeb}"),
    revoke("revoke in a frozen Organization", "production", "{frozenTarget}", "alice", "frozen"),
    revoke("revoke in an Organization being deleted", "production", "{deletingTarget}", "alice", "deleting"),
    revoke("revoke as a member", "production", "{tApi}", "dave"),
    create("create on the released destination", "acme", "staging", { connectionId: gh, destination: { repo: "web2" }, mapping: { kind: "wildcard" } }),

    listOrg("list afterwards", "acme"),
  ]);
}

const CONNECTIONS = { gh: ["acme", "GitHub"], gh2: ["acme", "GitHub 2"], coolify: ["acme", "Coolify"], revokedConn: ["acme", "Revoked"], appConn: ["acme", "App"], frozenConn: ["frozen", "Frozen"], deletingConn: ["deleting", "Deleting"] } as const;
const TARGETS = {
  tApi: "[\"github-actions\",\"acme\",\"api\"]",
  tWeb: "[\"github-actions\",\"acme\",\"web\"]",
  tCoolify: "[\"coolify\",\"https://coolify.public.example\",\"app-uuid-1\"]",
  tPause: "[\"github-actions\",\"acme\",\"pause\"]",
  tBudget: "[\"github-actions\",\"acme\",\"budget\"]",
  tRevokedConn: "[\"github-actions\",\"acme\",\"orphan\"]",
  tRedeploy: "[\"github-actions\",\"acme\",\"redeploy\"]",
  frozenTarget: "[\"github-actions\",\"acme\",\"frozen\"]",
  deletingTarget: "[\"github-actions\",\"acme\",\"deleting\"]",
} as const;

function fillPath(rows: Fixture["rows"]): (p: string) => string {
  const org = (slug: string) => rows.organizations!.find((o) => o.slug === slug)!.id as string;
  const pairs: [string, string][] = [["{acmeId}", org("acme")]];
  for (const [key, [slug, name]] of Object.entries(CONNECTIONS)) {
    const c = rows.platform_connections!.find((r) => r.organization_id === org(slug) && r.name === name);
    if (!c) throw new Error(`no Connection ${name}`);
    pairs.push([`{${key}}`, c.id as string]);
  }
  for (const [key, canonical] of Object.entries(TARGETS)) {
    const t = rows.sync_targets!.find((r) => r.canonical_destination === canonical);
    if (!t) throw new Error(`no Target ${canonical}`);
    pairs.push([`{${key}}`, t.id as string]);
  }
  return (p) => pairs.reduce((out, [k, v]) => out.replaceAll(k, v), p);
}

type Call = (method: string, path: string, body?: unknown, token?: string) => Promise<any>;

async function build() {
  const db = await migratedTestDb();
  const ctx = { db, rootKek: generateKey(), close: db.close, outbound: policy() };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId: alice } = await consumeSetupGrant(ctx, grant.token, { adminName: "Alice" });
  const tokens: Record<string, string> = { alice: (await issueCredential(ctx.db, { identityId: alice, kind: "cli" })).token };
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
  const envs: Record<string, string> = {};
  const items = [["DATABASE_URL", true], ["PORT", false], ["OTHER", false]].map(([name, sensitive]) => ({ name, required: { kind: "never" }, sensitive, type: "string" }));
  for (const slug of ["acme", "frozen", "deleting", "beta"]) {
    orgs[slug] = (await call("POST", ORG, { name: slug[0]!.toUpperCase() + slug.slice(1), slug })).id;
    const P = `${ORG}/${slug}/projects/api`;
    await call("POST", `${ORG}/${slug}/projects`, { slug: "api", name: "API", contractAuthority: "managed" });
    for (const [name, tier] of [["production", "production"], ["dev", "development"], ["staging", "staging"]]) {
      const env = await call("POST", `${P}/environments`, { name, tier });
      if (slug === "acme") envs[name!] = env.id;
    }
    const revision = await call("POST", `${P}/contract/revisions`, { contract: { schemaVersion: 1, items } });
    await call("POST", `${P}/contract/revisions/${revision.id}/activate`, {});
  }
  const connection = async (org: string, name: string, platform: string, baseIdentity: string) =>
    (await call("POST", `${ORG}/${org}/platform-connections`, { platform, baseIdentity, name, credential: `fixture-${name.toLowerCase().replace(/ /g, "-")}` })).id as string;
  const gh = await connection("acme", "GitHub", "github-actions", "acme");
  await connection("acme", "GitHub 2", "github-actions", "acme");
  const coolify = await connection("acme", "Coolify", "coolify", COOLIFY);
  const revoked = await connection("acme", "Revoked", "github-actions", "acme");
  const frozenConn = await connection("frozen", "Frozen", "github-actions", "acme");
  const deletingConn = await connection("deleting", "Deleting", "github-actions", "acme");

  // The App Connection, its App removed since (rows written directly).
  const acmeRow = (await db.query("SELECT * FROM organizations WHERE id = $1", [orgs.acme])).rows[0] as OrgRow;
  const appId = newId("githubApp");
  await db.query(
    `INSERT INTO github_apps (id, organization_id, github_app_id, slug, client_id, owner_login, owner_id, owner_type, key_envelope, created_by, created_at)
     VALUES ($1, $2, 424242, 'varlatch-acme', 'Iv1.fixture', 'acme', 9001, 'organization', $3, $4, '2026-01-02T00:00:00.000Z')`,
    [appId, orgs.acme, JSON.stringify(encryptGitHubAppKey(orgKekOf(ctx, acmeRow), orgs.acme!, appId, "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n")), alice],
  );
  await db.query(
    `INSERT INTO platform_connections (id, organization_id, platform, base_identity, name, credential_kind, github_app_id, github_installation_id, created_by, created_at)
     VALUES ($1, $2, 'github-actions', 'acme', 'App', 'github-app', $3, 77, $4, '2026-01-02T00:00:01.000Z')`,
    [newId("platformConnection"), orgs.acme, appId, alice],
  );
  await db.query("UPDATE github_apps SET removed_at = '2026-01-03T00:00:00.000Z', key_envelope = NULL WHERE id = $1", [appId]);

  const target = async (org: string, env: string, connectionId: string, destination: unknown, mapping: unknown, extra: Record<string, unknown> = {}) =>
    (await call("POST", ENV(org, env), { connectionId, destination, mapping, ...extra })).id as string;
  const tApi = await target("acme", "production", gh, { repo: "api" }, { kind: "wildcard" });
  await target("acme", "dev", gh, { repo: "web" }, { kind: "explicit", items: [{ name: "PORT" }] });
  const tCoolify = await target("acme", "dev", coolify, { applicationUuid: "app-uuid-1" }, { kind: "wildcard" });
  await target("acme", "production", gh, { repo: "pause" }, { kind: "wildcard" });
  const tBudget = await target("acme", "production", gh, { repo: "budget" }, { kind: "wildcard" });
  await target("acme", "production", revoked, { repo: "orphan" }, { kind: "wildcard" });
  const tRedeploy = await target("acme", "production", gh, { repo: "redeploy" }, { kind: "wildcard" }, { redeploy: true });
  await target("frozen", "production", frozenConn, { repo: "frozen" }, { kind: "wildcard" });
  await target("deleting", "production", deletingConn, { repo: "deleting" }, { kind: "wildcard" });
  await call("DELETE", `${ORG}/acme/platform-connections/${revoked}`);
  await db.query(
    "UPDATE sync_targets SET state = 'disabled', disabled_reason = 'failure-budget-exhausted', failure_count = 5, last_result = 'HTTP 500' WHERE id = $1",
    [tBudget],
  );
  await db.query("UPDATE sync_targets SET redeploy_owed = 3, redeploy_paid = 1 WHERE id = $1", [tRedeploy]);
  for (const [name, state, error] of [["API_KEY", "written", null], ["DEBUG", "failed-write", "HTTP 500"], ["OLD", "tombstone", null]] as const) {
    await db.query(
      "INSERT INTO sync_ledger (target_id, dest_name, fingerprint, state, generation, updated_at, last_error) VALUES ($1, $2, 'fp', $3, 0, '2026-02-05T00:00:00.000Z', $4)",
      [tApi, name, state, error],
    );
  }
  await db.query(
    "INSERT INTO sync_ledger (target_id, dest_name, fingerprint, state, generation, updated_at) VALUES ($1, 'PORT', 'fp', 'written', 0, '2026-02-05T00:00:00.000Z')",
    [tCoolify],
  );
  await db.query(
    `UPDATE sync_targets SET last_notes = '[{"code":"shadowed","name":"PORT","containers":["web"]}]'::jsonb,
       last_drift_at = '2026-02-03T00:00:00.000Z', last_drift_count = 1, last_drift_names = '["PORT"]'::jsonb, last_drift_event_id = 'evt_driftaaaaaaaaaaaaaaaaaaaaa'
     WHERE id = $1`,
    [tCoolify],
  );
  await db.query("INSERT INTO sync_runs (target_id, generation, started_at, deadline) VALUES ($1, 0, '2026-02-04T00:00:00.000Z', '2099-01-01T00:00:00.000Z')", [tCoolify]);

  // People.
  const person = async (name: string, org?: string) => {
    const id = newId("identity");
    await db.query("INSERT INTO identities (id, kind, name, created_at) VALUES ($1, 'human', $2, '2026-01-01T00:00:00.000Z')", [id, name]);
    if (org) await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, $2, 'member')", [orgs[org], id]);
    tokens[name] = (await issueCredential(ctx.db, { identityId: id, kind: "cli" })).token;
    return id;
  };
  const bob = await person("bob", "acme");
  const carl = await person("carl", "acme");
  await person("dave", "acme");
  await person("carol");
  await call("POST", `${ORG}/acme/grants`, { subjectIdentityId: bob, scope: { kind: "organization" }, actions: ["config.sync.manage"] });
  const projectId = (await call("GET", `${ORG}/acme/projects/api`)).id as string;
  await call("POST", `${ORG}/acme/grants`, {
    subjectIdentityId: carl,
    scope: { kind: "environments", projectId, selector: { kind: "environments", environmentIds: [envs.production] } },
    actions: ["config.sync.manage", "config.value.read"],
  });

  await db.query(
    "INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', 'incident drill')",
    [newId("organizationFreeze"), orgs.frozen, alice],
  );
  await db.query(
    "INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', '2099-03-01T00:00:00.000Z', false)",
    [newId("organizationDeletion"), orgs.deleting, alice],
  );
  await accessCountsSettled();
  return { ctx, tokens };
}

/** The file's answers, recorded on its own rows. */
async function replay(f: Fixture): Promise<{ requests: Fixture["requests"]; counters: Fixture["counters"] }> {
  const db = await loadRows(f.rows, TABLES);
  await db.query("UPDATE audit_position SET value = (SELECT coalesce(max(event_order), 0) FROM audit_events) WHERE singleton");
  try {
    const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex"), outbound: policy() };
    return await record(ctx, buildApp(ctx, { publicUrl: PUBLIC_URL }), f, f.requests, fillPath(f.rows));
  } finally {
    await db.close();
  }
}

describe.skipIf(process.env.VARLATCH_WRITE_GO_VECTORS !== "1")("writing the fixture", () => {
  it("builds the database, records the answers and writes the file", async () => {
    const { ctx, tokens } = await build();
    try {
      const draft: Fixture = {
        comment: "Written by services/varlatchd/test/go-targets-fixture.test.ts from the TypeScript server's own answers; do not edit.",
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
    }
  }, 600_000);
});

describe("the targets fixture is this server's answers", () => {
  it("targets-v0.22.0.json", async () => {
    const f = JSON.parse(readFileSync(FILE, "utf8")) as Fixture;
    expect(f.serverVersion).toBe(SERVER_VERSION);
    expectCurrentTable(f, requestTable());
    expect(f.sideTables).toEqual(SIDE);
    expectSameAnswers(f, await replay(f));
    const { ctx } = await build();
    try {
      expectSameRows(TABLES, f.rows, await exportRows(ctx.db, TABLES));
    } finally {
      await ctx.close();
    }
  }, 300_000);
});
