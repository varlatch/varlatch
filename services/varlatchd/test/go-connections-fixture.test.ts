// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.9b's parity fixture (ADR-0059 step 4, feature-parity decisions 3
 * and 9), on the parity kit (go-fixture-kit.ts): Platform Connections,
 * built through this server's own /v1 API, and a table of requests with
 * this server's answers: listPlatformConnections, createPlatformConnection,
 * checkPlatformAccess, listPlatformDestinations, getPlatformConnection,
 * replacePlatformCredential and revokePlatformConnection.
 * go/server/syncs' parity test replays it against varlatchd.
 *
 * The platforms answer through the app's syncFetch (SyncClient in Go): a
 * fake GitHub (api.github.com), Coolify (https://coolify.public.example)
 * and Convex (https://happy-animal-123.convex.cloud), each by path and by
 * the credential it is sent (one with "rejected" in it is refused, one
 * with "expiring" says when it expires). Each request's requests to them
 * (method, URL, Authorization, body) are kept in the file and must be the
 * same: a check or a listing with a stored credential sends what the
 * Connection's envelope opens to (G3 at the database level for Platform
 * Connection credentials). The outbound policy resolves the platforms'
 * names (coolify.internal to a private address, which it refuses).
 *
 * The database: alice (the bootstrap Installation Admin) and her second
 * CLI credential (alice2, whose approval intents in enf bind exact
 * requests); Organizations acme (every control off), rep (admin-step-up
 * at report), enf (at enforce), frozen (a Connection, then an incident
 * freeze), deleting (a Connection, then a deletion scheduled) and beta.
 * In acme: Connections to each platform, one whose token reports its
 * expiry, and one on a GitHub App installation (its App row written
 * directly: step 4.10 makes them); a Project with two environments and
 * Sync Targets on the GitHub and Coolify Connections, one stopped by a
 * credential rejection, one with a live run, notes and drift. People: bob
 * (a member with a Grant of config.sync.manage, and no disclosure), dave
 * (a member), carol (in none). The credentials are in the file
 * (`credentials`), so the envelopes can be sealed again.
 *
 * Not in the table: what mints a token from a GitHub App (creating an App
 * Connection, its checks and listings), which step 4.10 builds in Go.
 *
 * Two files, one per release whose envelopes must open (G3):
 *   - connections-v0.22.0.json: every envelope sealed by this code;
 *   - connections-v0.21.0.json: the same rows with the canary, every
 *     Organization KEK, every Connection credential and the App's key
 *     sealed again by v0.21.0's crypto code.
 * With VARLATCH_GO_SEALED_CONNECTIONS=<file>, the same checks run on a file
 * the Go tests wrote (go test ./server/syncs -run TestGoSealedFixture -args
 * -write-go-sealed=<file>), sealed again by Go (go.yml).
 *
 * After a change, regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-connections-fixture.test.ts
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { encryptGitHubAppKey } from "../src/crypto/hierarchy.js";
import { newId } from "../src/db/ids.js";
import { approvalHash, canonicalJson, type ApprovalBinding } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import {
  connectionCreateBinding, connectionDeleteBinding, connectionReplaceCredentialBinding, readConnection,
} from "../src/domain/integrationstepup.js";
import { orgKekOf, type OrgRow } from "../src/domain/orgs.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { OutboundPolicy, type Resolver } from "../src/net/outbound.js";
import { migratedTestDb } from "./helpers/pglite.js";
import {
  expectCurrentTable, expectSameAnswers, expectSameRows, exportRows, loadRows, record, resealWith, withIds,
  type Fixture, type RawAnswer, type RequestCase, type SideTable, type Table,
} from "./go-fixture-kit.js";

const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const OUT_DIR = new URL("../../../go/server/paritytest/testdata/", import.meta.url);
const FILES = { "v0.22.0": "connections-v0.22.0.json", "v0.21.0": "connections-v0.21.0.json" } as const;

/** The public URL both servers run with: approvals need one. */
export const PUBLIC_URL = "http://127.0.0.1:8686";

/** The names the fixture's outbound policy resolves (Go: the same). */
export const RESOLVE: Record<string, { address: string; family: 4 | 6 }[]> = {
  "coolify.public.example": [{ address: "93.184.216.40", family: 4 }],
  "happy-animal-123.convex.cloud": [{ address: "93.184.216.41", family: 4 }],
  "coolify.internal": [{ address: "10.1.2.40", family: 4 }],
};
const resolve: Resolver = async (name) => {
  const a = RESOLVE[name];
  if (!a) throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${name}`), { code: "ENOTFOUND" });
  return a;
};
const policy = () => new OutboundPolicy("", { resolve, log: () => {} });

/** The GitHub public key the fake answers with (any 32 bytes). */
export const GITHUB_KEY = Buffer.alloc(32, 9).toString("base64");
export const EXPIRES = "2026-09-01 12:00:00 UTC";

/**
 * The fake platforms: a request is logged as "METHOD URL AUTHORIZATION
 * [BODY]" and answered by host, path and credential.
 */
export function platforms(log: string[]): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    const headers = new Headers(init?.headers);
    const auth = headers.get("authorization") ?? "";
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? init.body : "";
    log.push(`${method} ${url.href} ${auth}${body ? ` ${body}` : ""}`);
    const json = (status: number, b: unknown, extra: Record<string, string> = {}) =>
      new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json", ...extra } });
    const rejected = auth.includes("rejected");
    if (url.host === "api.github.com") {
      if (rejected) return json(401, { message: "Bad credentials" });
      const expiry: Record<string, string> = auth.includes("expiring") ? { "github-authentication-token-expiration": EXPIRES } : {};
      const repo = (name: string, priv = false, extra: Record<string, unknown> = {}) => ({ name, owner: { login: "acme" }, private: priv, ...extra });
      if (url.pathname === "/users/acme") return json(200, { login: "acme", type: "Organization" }, expiry);
      if (url.pathname === "/orgs/acme/repos") return json(200, [repo("api"), repo("web", true), repo("old", false, { archived: true })], expiry);
      if (url.pathname.endsWith("/public-key")) {
        return url.pathname.includes("/missing/") ? json(404, { message: "Not Found" }) : json(200, { key_id: "k1", key: GITHUB_KEY }, expiry);
      }
      if (url.pathname === "/repos/acme/api") return json(200, { name: "api" }, expiry);
      return json(404, { message: "Not Found" });
    }
    if (url.host === "coolify.public.example") {
      if (rejected) return json(401, { message: "Unauthenticated." });
      if (url.pathname === "/api/v1/version") return new Response("4.0.0-beta.420", { status: 200 });
      if (url.pathname === "/api/v1/applications") {
        return json(200, [{ uuid: "app-uuid-1", name: "Web", fqdn: "https://web.example.com,https://www.example.com" }, { uuid: "app-uuid-2", name: "api", fqdn: null }]);
      }
      if (url.pathname === "/api/v1/services") return json(200, [{ uuid: "svc-uuid-1", name: "Stack" }]);
      if (url.pathname === "/api/v1/applications/app-uuid-1") return json(200, { uuid: "app-uuid-1", name: "Web" });
      if (url.pathname === "/api/v1/services/svc-uuid-1") return json(200, { uuid: "svc-uuid-1", name: "Stack", applications: [{ name: "web" }], databases: [{ name: "db" }] });
      if (url.pathname === "/api/v1/services/svc-uuid-1/envs") return json(200, [{ key: "A", value: "1" }, { key: "B" }]);
      return json(404, { message: "Not found." });
    }
    if (url.host === "happy-animal-123.convex.cloud") {
      if (rejected) return json(401, { code: "BadAdminKey" });
      if (url.pathname === "/api/check_admin_key") return json(200, { success: true });
      return json(404, {});
    }
    throw new TypeError("fetch failed");
  }) as typeof fetch;
}

const TABLES: Table[] = [
  { name: "installation", orderBy: "id", random: ["kek_canary"] },
  { name: "identities", orderBy: "id" },
  { name: "credentials", orderBy: "id", random: ["token_hash"] },
  { name: "organizations", orderBy: "id", random: ["wrapped_org_kek"] },
  { name: "org_memberships", orderBy: "organization_id, identity_id" },
  { name: "projects", orderBy: "id" },
  { name: "environments", orderBy: "id" },
  { name: "grants", orderBy: "id" },
  { name: "security_controls", orderBy: "organization_id, control" },
  { name: "approval_intents", orderBy: "id", random: ["body_hash", "query_hash"] },
  { name: "organization_freezes", orderBy: "id" },
  { name: "organization_deletions", orderBy: "id" },
  { name: "github_apps", orderBy: "id", random: ["key_envelope"] },
  { name: "platform_connections", orderBy: "id", random: ["credential_envelope"] },
  { name: "sync_targets", orderBy: "id" },
  { name: "sync_runs", orderBy: "target_id, generation" },
  { name: "member_integrations", orderBy: "organization_id, identity_id, kind, resource_id" },
  { name: "audit_events", orderBy: "event_order", random: ["request_id"] },
];

const SIDE: SideTable[] = [
  {
    name: "platform_connections", key: ["id"], sortBy: ["organization_id", "name"],
    volatile: ["credential_envelope", "created_at", "updated_at", "revoked_at", "credential_expiry_seen_at"],
  },
  { name: "sync_targets", key: ["id"], sortBy: ["organization_id", "canonical_destination"], volatile: ["updated_at"] },
  { name: "member_integrations", key: ["organization_id", "identity_id", "kind", "resource_id"], sortBy: ["organization_id", "kind", "changes"], volatile: ["first_at", "last_at"] },
  { name: "approval_intents", key: ["id"], sortBy: ["organization_id", "operation", "target", "body_hash"], volatile: ["created_at", "expires_at", "consumed_at", "closed_at"] },
];

const ORG = "/v1/organizations";
const aprId = (s: string) => `apr_${s.padEnd(26, "a")}`;
const APPROVALS = { create: aprId("create"), replace: aprId("replace"), revoke: aprId("revoke"), otherBody: aprId("otherbody") } as const;

const GH = { platform: "github-actions", baseIdentity: "acme" };
const COOLIFY = "https://coolify.public.example";
const CONVEX = "https://happy-animal-123.convex.cloud";

/** The table of requests. */
function requestTable(): RequestCase[] {
  const approval = (id?: string) => (id !== undefined ? { credential: "alice2", headers: { "Varlatch-Approval": id } } : {});
  const at = (org: string, rest = "") => `${ORG}/${org}/platform-connections${rest}`;
  const list = (name: string, org: string, credential = "alice"): Omit<RequestCase, "id"> => ({ name, method: "GET", path: at(org), credential });
  const create = (name: string, org: string, body: unknown, credential = "alice", approvalId?: string): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: at(org), credential, body, ...approval(approvalId) });
  const createRaw = (name: string, org: string, rawBody: string): Omit<RequestCase, "id"> => ({ name, method: "POST", path: at(org), credential: "alice", rawBody });
  const check = (name: string, org: string, body: unknown, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: at(org, "/check"), credential, body });
  const destinations = (name: string, org: string, body: unknown, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: at(org, "/destinations"), credential, body });
  const get = (name: string, org: string, connection: string, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "GET", path: at(org, `/${connection}`), credential });
  const replace = (name: string, org: string, connection: string, body: unknown, credential = "alice", approvalId?: string): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: at(org, `/${connection}/credential`), credential, body, ...approval(approvalId) });
  const revoke = (name: string, org: string, connection: string, credential = "alice", approvalId?: string): Omit<RequestCase, "id"> =>
    ({ name, method: "DELETE", path: at(org, `/${connection}`), credential, ...approval(approvalId) });
  return withIds([
    // listPlatformConnections: config.sync.manage, existence hidden; inspection while frozen.
    list("list", "acme"),
    list("list by id", "{acmeId}"),
    list("list with a Grant", "acme", "bob"),
    list("list as a member", "acme", "dave"),
    list("list as an outsider", "acme", "carol"),
    list("list a frozen Organization", "frozen"),
    list("list an Organization being deleted", "deleting"),
    list("list an unknown Organization", "nope"),

    // createPlatformConnection.
    create("create on GitHub", "beta", { ...GH, baseIdentity: " @Acme ", name: "GitHub", credential: "github_pat_fixture_new" }),
    create("create on Coolify", "beta", { platform: "coolify", baseIdentity: "https://Coolify.Public.Example/", name: "Coolify", credential: "coolify_token_new" }),
    create("create on Convex", "beta", { platform: "convex", baseIdentity: CONVEX, name: "Convex", credential: "convex_key_new", credentialKind: "token" }),
    create("create to a name that does not resolve", "beta", { platform: "coolify", baseIdentity: "https://missing.example", name: "Missing", credential: "t" }),
    create("create to a private name", "beta", { platform: "coolify", baseIdentity: "https://coolify.internal", name: "Internal", credential: "t" }),
    create("create to a private address", "beta", { platform: "convex", baseIdentity: "https://10.0.0.7", name: "Private", credential: "t" }),
    create("create, an unknown platform", "beta", { platform: "generic-url", baseIdentity: "https://x.example", name: "X", credential: "t" }),
    create("create, an invalid owner", "beta", { ...GH, baseIdentity: "not a login!", name: "X", credential: "t" }),
    create("create, plain http", "beta", { platform: "coolify", baseIdentity: "http://coolify.public.example", name: "X", credential: "t" }),
    create("create, a path", "beta", { platform: "coolify", baseIdentity: `${COOLIFY}/x`, name: "X", credential: "t" }),
    create("create, a blank credential", "beta", { ...GH, name: "X", credential: "   " }),
    create("create, a name with NUL", "beta", { ...GH, name: "a\u0000b", credential: "t" }),
    create("create, no credential", "beta", { ...GH, name: "X" }),
    create("create, every member wrong", "beta", { platform: 5, baseIdentity: "", name: "x".repeat(201), credential: "x".repeat(10_001) }),
    create("create, another credential kind", "beta", { ...GH, name: "X", credential: "t", credentialKind: "oauth" }),
    create("create, an extra member", "beta", { ...GH, name: "Extra", credential: "github_pat_fixture_extra", extra: true }),
    create("create on an App, no installation", "beta", { credentialKind: "github-app", name: "App" }),
    create("create on an App, installation 0", "beta", { credentialKind: "github-app", installationId: 0, name: "App" }),
    create("create on an App, a fraction", "beta", { credentialKind: "github-app", installationId: 1.5, name: "" }),
    create("create on an App, too large", "beta", { credentialKind: "github-app", installationId: 2 ** 60, name: "App" }),
    createRaw("create, a body that is not JSON", "beta", "{nope"),
    createRaw("create, an array", "beta", "[]"),
    create("create with a Grant", "beta", { ...GH, name: "Bob's", credential: "github_pat_fixture_bob" }, "bob"),
    create("create as a member", "acme", { ...GH, name: "X", credential: "t" }, "dave"),
    create("create as an outsider", "acme", { ...GH, name: "X", credential: "t" }, "carol"),
    create("create in a frozen Organization", "frozen", { ...GH, name: "X", credential: "t" }),
    create("create in an Organization being deleted", "deleting", { ...GH, name: "X", credential: "t" }),
    create("create in an Organization being deleted, an unknown platform", "deleting", { platform: "nope", baseIdentity: "x", name: "X", credential: "t" }),
    create("create in an unknown Organization", "nope", { ...GH, name: "X", credential: "t" }),
    create("create at report", "rep", { ...GH, name: "Rep", credential: "github_pat_fixture_rep" }),
    create("create at enforce, no approval", "enf", { ...GH, name: "Enf", credential: "github_pat_fixture_ask" }),
    create("create at enforce, a refused base identity", "enf", { platform: "coolify", baseIdentity: "https://coolify.internal", name: "Enf", credential: "t" }),
    create("create at enforce, its approval", "enf", { ...GH, name: "Approved", credential: "github_pat_fixture_approved" }, "alice", APPROVALS.create),
    create("create at enforce, another request's approval", "enf", { ...GH, name: "Other", credential: "github_pat_fixture_other" }, "alice", APPROVALS.otherBody),

    // checkPlatformAccess.
    check("check the stored GitHub credential", "acme", { connectionId: "{gh}" }),
    check("check a repository", "acme", { connectionId: "{gh}", destination: { repo: "API" } }),
    check("check an environment", "acme", { connectionId: "{gh}", destination: { repo: "api", environment: "prod" } }),
    check("check a missing repository", "acme", { connectionId: "{gh}", destination: { repo: "missing" } }),
    check("check a missing environment", "acme", { connectionId: "{gh}", destination: { repo: "missing", environment: "prod" } }),
    check("check, an empty destination", "acme", { connectionId: "{gh}", destination: { repo: "", environment: null } }),
    check("check, an invalid destination", "acme", { connectionId: "{gh}", destination: { repo: "a/b" } }),
    check("check a replacement", "acme", { connectionId: "{gh}", credential: "github_pat_fixture_rejected" }),
    check("check a token that expires", "acme", { connectionId: "{ghExpiring}" }),
    check("check a token that expires, again", "acme", { connectionId: "{ghExpiring}", destination: { repo: "api" } }),
    check("check a replacement that expires", "acme", { connectionId: "{gh}", credential: "github_pat_fixture_expiring2" }),
    check("check a new credential", "acme", { ...GH, credential: "github_pat_fixture_fresh" }),
    check("check a new Coolify application", "acme", { platform: "coolify", baseIdentity: COOLIFY, credential: "coolify_token_fresh", destination: { applicationUuid: "app-uuid-1" } }),
    check("check the stored Coolify credential on a service", "acme", { connectionId: "{coolify}", destination: { serviceUuid: "svc-uuid-1" } }),
    check("check the stored Coolify credential", "acme", { connectionId: "{coolify}" }),
    check("check the stored Convex key", "acme", { connectionId: "{convex}" }),
    check("check a rejected Convex key", "acme", { platform: "convex", baseIdentity: CONVEX, credential: "convex_rejected" }),
    check("check a private name", "acme", { platform: "coolify", baseIdentity: "https://coolify.internal", credential: "t" }),
    check("check an unknown Connection", "acme", { connectionId: "pcn_unknownaaaaaaaaaaaaaaaaaaa" }),
    check("check both", "acme", { connectionId: "{gh}", platform: "github-actions" }),
    check("check nothing", "acme", { platform: "github-actions" }),
    check("check, a blank credential", "acme", { connectionId: "{gh}", credential: "  " }),
    check("check, a destination that is not a record", "acme", { connectionId: "{gh}", destination: ["api"] }),
    check("check, an unknown platform", "acme", { platform: "nope", baseIdentity: "x", credential: "t" }),
    check("check the App Connection with a credential", "acme", { connectionId: "{app}", credential: "t" }),
    check("check with a Grant", "acme", { connectionId: "{gh}" }, "bob"),
    check("check as a member", "acme", { connectionId: "{gh}" }, "dave"),
    check("check in a frozen Organization", "frozen", { connectionId: "{frozenConn}" }),
    check("check in an Organization being deleted", "deleting", { connectionId: "{deletingConn}" }),

    // listPlatformDestinations.
    destinations("list GitHub repositories", "acme", { connectionId: "{gh}" }),
    destinations("list repositories, a token that expires", "acme", { connectionId: "{ghExpiring}" }),
    destinations("list Coolify resources", "acme", { connectionId: "{coolify}" }),
    destinations("list with a new rejected credential", "acme", { ...GH, credential: "github_pat_fixture_rejected" }),
    destinations("list Convex", "acme", { connectionId: "{convex}" }),
    destinations("list a private name", "acme", { platform: "coolify", baseIdentity: "https://coolify.internal", credential: "t" }),
    destinations("list the App Connection with a credential", "acme", { connectionId: "{app}", credential: "t" }),
    destinations("list nothing", "acme", {}),
    destinations("list as a member", "acme", { connectionId: "{gh}" }, "dave"),

    // getPlatformConnection.
    get("get the GitHub Connection", "acme", "{gh}"),
    get("get the Coolify Connection", "acme", "{coolify}"),
    get("get the App Connection", "acme", "{app}"),
    get("get an unknown Connection", "acme", "pcn_unknownaaaaaaaaaaaaaaaaaaa"),
    get("get another Organization's", "beta", "{gh}"),
    get("get as a member", "acme", "{gh}", "dave"),
    get("get in a frozen Organization", "frozen", "{frozenConn}"),

    // replacePlatformCredential.
    replace("replace, a stale version", "acme", "{gh}", { credential: "github_pat_fixture_r1", expectedVersion: 2 }),
    replace("replace, a blank credential", "acme", "{gh}", { credential: " ", expectedVersion: 1 }),
    replace("replace, no version", "acme", "{gh}", { credential: "github_pat_fixture_r1" }),
    replace("replace the App Connection's", "acme", "{app}", { credential: "t", expectedVersion: 1 }),
    replace("replace without disclosure authority", "acme", "{gh}", { credential: "github_pat_fixture_bob", expectedVersion: 1 }, "bob"),
    replace("replace", "acme", "{gh}", { credential: "github_pat_fixture_r1", expectedVersion: 1 }),
    replace("replace again", "acme", "{gh}", { credential: "github_pat_fixture_r2", expectedVersion: 2 }),
    check("check the replaced credential", "acme", { connectionId: "{gh}" }),
    replace("replace an unknown Connection", "acme", "pcn_unknownaaaaaaaaaaaaaaaaaaa", { credential: "t", expectedVersion: 1 }),
    replace("replace as a member", "acme", "{gh}", { credential: "t", expectedVersion: 3 }, "dave"),
    replace("replace in a frozen Organization", "frozen", "{frozenConn}", { credential: "t", expectedVersion: 1 }),
    replace("replace in an Organization being deleted", "deleting", "{deletingConn}", { credential: "t", expectedVersion: 1 }),
    replace("replace at enforce, no approval", "enf", "{enfConn}", { credential: "github_pat_fixture_enf2", expectedVersion: 1 }),
    replace("replace at enforce, its approval", "enf", "{enfConn}", { credential: "github_pat_fixture_enf2", expectedVersion: 1 }, "alice", APPROVALS.replace),

    // revokePlatformConnection.
    revoke("revoke the Coolify Connection", "acme", "{coolify}"),
    revoke("revoke it again", "acme", "{coolify}"),
    get("get a revoked Connection", "acme", "{coolify}"),
    revoke("revoke the App Connection", "acme", "{app}"),
    revoke("revoke as a member", "acme", "{gh}", "dave"),
    revoke("revoke in a frozen Organization", "frozen", "{frozenConn}"),
    revoke("revoke in an Organization being deleted", "deleting", "{deletingConn}"),
    revoke("revoke at report", "rep", "{repConn}"),
    revoke("revoke at enforce, no approval", "enf", "{enfDel}"),
    revoke("revoke at enforce, its approval", "enf", "{enfDel}", "alice", APPROVALS.revoke),

    list("list afterwards", "acme"),
    list("list enf afterwards", "enf"),
  ]);
}

/** The Connections build() makes, by Organization and name: their ids fill the table's paths. */
const NAMED = {
  gh: ["acme", "GitHub"],
  ghExpiring: ["acme", "Expiring"],
  coolify: ["acme", "Coolify"],
  convex: ["acme", "Convex"],
  app: ["acme", "App"],
  frozenConn: ["frozen", "Frozen"],
  deletingConn: ["deleting", "Deleting"],
  repConn: ["rep", "Rep conn"],
  enfConn: ["enf", "Enf conn"],
  enfDel: ["enf", "Enf del"],
} as const;

function fillPath(rows: Fixture["rows"]): (p: string) => string {
  const org = (slug: string) => rows.organizations!.find((o) => o.slug === slug)!.id as string;
  const pairs: [string, string][] = [["{acmeId}", org("acme")]];
  for (const [key, [slug, name]] of Object.entries(NAMED)) {
    const c = rows.platform_connections!.find((r) => r.organization_id === org(slug) && r.name === name);
    if (!c) throw new Error(`no Connection ${name} in ${slug}`);
    pairs.push([`{${key}}`, c.id as string]);
  }
  return (p) => pairs.reduce((out, [k, v]) => out.replaceAll(k, v), p);
}

type Call = (method: string, path: string, body?: unknown, token?: string) => Promise<any>;

/** The App's private key (no step here reads it). */
const APP_KEY = "-----BEGIN PRIVATE KEY-----\nfixture-app-key\n-----END PRIVATE KEY-----\n";

async function build() {
  const db = await migratedTestDb();
  const ctx = { db, rootKek: generateKey(), close: db.close, outbound: policy() };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId: alice } = await consumeSetupGrant(ctx, grant.token, { adminName: "Alice" });
  const aliceCredential = await issueCredential(ctx.db, { identityId: alice, kind: "cli" });
  const alice2 = await issueCredential(ctx.db, { identityId: alice, kind: "cli" });
  const tokens: Record<string, string> = { alice: aliceCredential.token, alice2: alice2.token };
  const log: string[] = [];
  const app = buildApp(ctx, { publicUrl: PUBLIC_URL, syncFetch: platforms(log) });
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
  const credentials: Record<string, string> = {};
  const connection = async (org: string, name: string, platform: string, baseIdentity: string, credential: string) => {
    const created = await call("POST", `${ORG}/${org}/platform-connections`, { platform, baseIdentity, name, credential });
    credentials[created.id] = credential;
    return created.id as string;
  };
  const gh = await connection("acme", "GitHub", "github-actions", "acme", "github_pat_fixture_stored");
  await connection("acme", "Expiring", "github-actions", "acme", "github_pat_fixture_expiring");
  const coolify = await connection("acme", "Coolify", "coolify", COOLIFY, "coolify_token_stored");
  await connection("acme", "Convex", "convex", CONVEX, "convex_key_stored");
  await connection("frozen", "Frozen", "github-actions", "acme", "github_pat_fixture_frozen");
  await connection("deleting", "Deleting", "github-actions", "acme", "github_pat_fixture_deleting");
  await connection("rep", "Rep conn", "github-actions", "acme", "github_pat_fixture_rep_stored");
  const enfConn = await connection("enf", "Enf conn", "github-actions", "acme", "github_pat_fixture_enf");
  const enfDel = await connection("enf", "Enf del", "convex", CONVEX, "convex_key_enf");

  // The App Connection, its App written directly (step 4.10 registers them).
  const acmeRow = (await db.query("SELECT * FROM organizations WHERE id = $1", [orgs.acme])).rows[0] as OrgRow;
  const appId = newId("githubApp");
  await db.query(
    `INSERT INTO github_apps (id, organization_id, github_app_id, slug, client_id, owner_login, owner_id, owner_type, key_envelope, created_by, created_at)
     VALUES ($1, $2, 424242, 'varlatch-acme', 'Iv1.fixture', 'acme', 9001, 'organization', $3, $4, '2026-01-02T00:00:00.000Z')`,
    [appId, orgs.acme, JSON.stringify(encryptGitHubAppKey(orgKekOf(ctx, acmeRow), orgs.acme!, appId, APP_KEY)), alice],
  );
  await db.query(
    `INSERT INTO platform_connections (id, organization_id, platform, base_identity, name, credential_kind, github_app_id, github_installation_id, created_by, created_at)
     VALUES ($1, $2, 'github-actions', 'acme', 'App', 'github-app', $3, 77, $4, '2026-01-02T00:00:01.000Z')`,
    [newId("platformConnection"), orgs.acme, appId, alice],
  );

  // A Project with two environments, and Targets on GitHub and Coolify.
  await call("POST", `${ORG}/acme/projects`, { slug: "api", name: "API", contractAuthority: "managed" });
  await call("POST", `${ORG}/acme/projects/api/environments`, { name: "production", tier: "production" });
  await call("POST", `${ORG}/acme/projects/api/environments`, { name: "dev", tier: "development" });
  const target = async (env: string, connectionId: string, destination: unknown, mapping: unknown) =>
    (await call("POST", `${ORG}/acme/projects/api/environments/${env}/sync-targets`, { connectionId, destination, mapping })).id as string;
  await target("production", gh, { repo: "api" }, { kind: "wildcard" });
  const stopped = await target("dev", gh, { repo: "web" }, { kind: "explicit", items: [{ name: "DATABASE_URL" }] });
  const failing = await target("production", gh, { repo: "docs", environment: "prod" }, { kind: "wildcard", exclude: ["DEBUG_*"] });
  const running = await target("dev", coolify, { applicationUuid: "app-uuid-1", buildTime: "true" }, { kind: "wildcard" });
  await db.query(
    "UPDATE sync_targets SET state = 'disabled', disabled_reason = 'failure-budget-exhausted', failure_count = 5, last_result = 'GitHub public key fetch failed (401)', last_attempt_at = '2026-02-01T00:00:00.000Z' WHERE id = $1",
    [stopped],
  );
  await db.query("UPDATE sync_targets SET failure_count = 2, last_result = 'HTTP 403', last_attempt_at = '2026-02-02T00:00:00.000Z' WHERE id = $1", [failing]);
  await db.query(
    `UPDATE sync_targets SET last_notes = '[{"code":"held","name":"X","reason":"r"},{"code":"usage-unchecked","reason":"why"}]'::jsonb,
       last_drift_at = '2026-02-03T00:00:00.000Z', last_drift_count = 2, last_drift_names = '["A","B"]'::jsonb, last_drift_event_id = 'evt_driftaaaaaaaaaaaaaaaaaaaaa'
     WHERE id = $1`,
    [running],
  );
  await db.query("INSERT INTO sync_runs (target_id, generation, started_at, deadline) VALUES ($1, 0, '2026-02-04T00:00:00.000Z', '2099-01-01T00:00:00.000Z')", [running]);

  // People: bob a member with a Grant of config.sync.manage, dave a member, carol in none.
  const person = async (name: string, org?: string) => {
    const id = newId("identity");
    await db.query("INSERT INTO identities (id, kind, name, created_at) VALUES ($1, 'human', $2, '2026-01-01T00:00:00.000Z')", [id, name]);
    if (org) await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, $2, 'member')", [orgs[org], id]);
    tokens[name] = (await issueCredential(ctx.db, { identityId: id, kind: "cli" })).token;
    return id;
  };
  const bob = await person("bob", "acme");
  await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, $2, 'member')", [orgs.beta, bob]);
  await person("dave", "acme");
  await person("carol");
  for (const org of ["acme", "beta"]) {
    await call("POST", `${ORG}/${org}/grants`, { subjectIdentityId: bob, scope: { kind: "organization" }, actions: ["config.sync.manage"] });
  }

  await db.query(
    "INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', 'incident drill')",
    [newId("organizationFreeze"), orgs.frozen, alice],
  );
  await db.query(
    "INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', '2099-03-01T00:00:00.000Z', false)",
    [newId("organizationDeletion"), orgs.deleting, alice],
  );
  const set = (org: string, body: unknown) => call("PATCH", `${ORG}/${org}/security/controls/admin-step-up`, body);
  await set("rep", { mode: "report", expectedVersion: 0 });
  await set("enf", { mode: "report", expectedVersion: 0 });
  await set("enf", { mode: "enforce", expectedVersion: 1 });

  // Approval intents of alice2 in enf, each binding one request of the table.
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
  const enf = { id: orgs.enf! };
  await intent(APPROVALS.create, connectionCreateBinding(enf, { ...GH, name: "Approved", credential: "github_pat_fixture_approved" }));
  await intent(APPROVALS.otherBody, connectionCreateBinding(enf, { ...GH, name: "Other", credential: "github_pat_fixture_something_else" }));
  await intent(APPROVALS.replace, await connectionReplaceCredentialBinding(db, enf, (await readConnection(db, orgs.enf!, enfConn))!, "github_pat_fixture_enf2", 1));
  await intent(APPROVALS.revoke, await connectionDeleteBinding(db, enf, (await readConnection(db, orgs.enf!, enfDel))!));
  await accessCountsSettled();
  return { ctx, tokens, credentials };
}

type ConnectionsFixture = Fixture & { credentials: Record<string, string>; appKey: string; exchanges: Record<string, string[]> };

/** The file's answers, recorded on its own rows, with each request's requests to the platforms. */
async function replay(f: Fixture): Promise<{ requests: Fixture["requests"]; counters: Fixture["counters"]; exchanges: Record<string, string[]> }> {
  const db = await loadRows(f.rows, TABLES);
  await db.query("UPDATE audit_position SET value = (SELECT coalesce(max(event_order), 0) FROM audit_events) WHERE singleton");
  const exchanges: Record<string, string[]> = {};
  const log: string[] = [];
  try {
    const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex"), outbound: policy() };
    const recorded = await record(ctx, buildApp(ctx, { publicUrl: PUBLIC_URL, syncFetch: platforms(log) }), f, f.requests, fillPath(f.rows),
      (c: RequestCase, _raw: RawAnswer) => {
        if (log.length > 0) exchanges[c.id] = log.splice(0);
      });
    return { ...recorded, exchanges };
  } finally {
    await db.close();
  }
}

describe.skipIf(process.env.VARLATCH_WRITE_GO_VECTORS !== "1")("writing the fixtures", () => {
  it("builds the database, records the answers and exchanges, and writes both files", async () => {
    const { ctx, tokens, credentials } = await build();
    try {
      const rows = await exportRows(ctx.db, TABLES);
      for (const ref of ["v0.22.0", "v0.21.0"] as const) {
        const fileRows = structuredClone(rows);
        if (ref === "v0.21.0") {
          await resealWith(ref, ctx.rootKek, fileRows, () => "", undefined, {
            credentialOf: (c) => credentials[c.id as string]!,
            appKeyOf: () => APP_KEY,
          });
        }
        const draft: ConnectionsFixture = {
          comment: "Written by services/varlatchd/test/go-connections-fixture.test.ts from the TypeScript server's own answers; do not edit.",
          ref,
          serverVersion: SERVER_VERSION,
          rootKek: ctx.rootKek.toString("hex"),
          tokens,
          credentials,
          appKey: APP_KEY,
          rows: fileRows,
          sideTables: SIDE,
          requests: requestTable().map((c) => ({ ...c, expect: { status: 0, headers: {}, body: "" }, audit: [], side: {} })),
          counters: [],
          exchanges: {},
        };
        writeFileSync(new URL(FILES[ref], OUT_DIR), JSON.stringify({ ...draft, ...(await replay(draft)) }, null, 2) + "\n");
      }
    } finally {
      await ctx.close();
    }
  }, 600_000);
});

async function expectFixture(f: ConnectionsFixture) {
  expect(f.serverVersion).toBe(SERVER_VERSION);
  expectCurrentTable(f, requestTable());
  expect(f.sideTables).toEqual(SIDE);
  const got = await replay(f);
  expectSameAnswers(f, got);
  expect(got.exchanges).toEqual(f.exchanges);
}

describe("the connections fixtures are this server's answers", () => {
  for (const [ref, file] of Object.entries(FILES)) {
    it(file, async () => {
      const f = JSON.parse(readFileSync(new URL(file, OUT_DIR), "utf8")) as ConnectionsFixture;
      expect(f.ref).toBe(ref);
      await expectFixture(f);
      // The stored credentials went out: each check and listing with one sends it.
      const sent = Object.values(f.exchanges).flat();
      for (const stored of ["github_pat_fixture_stored", "github_pat_fixture_expiring", "coolify_token_stored", "convex_key_stored"]) {
        expect(sent.some((line) => line.includes(stored)), stored).toBe(true);
      }
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
  const goSealed = process.env.VARLATCH_GO_SEALED_CONNECTIONS;
  it.skipIf(!goSealed)("Platform Connection credentials the Go server sealed open here with the same exchanges", async () => {
    if (!existsSync(goSealed!)) throw new Error(`${goSealed}: no such file`);
    const f = JSON.parse(readFileSync(goSealed!, "utf8")) as ConnectionsFixture;
    expect(f.comment).toMatch(/Go/);
    await expectFixture(f);
  }, 300_000);
});
