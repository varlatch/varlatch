// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.10b's parity fixture (ADR-0059 step 4, feature-parity decision 3),
 * on the parity kit (go-fixture-kit.ts): what the Organization's GitHub App
 * does once it is there (ADR-0047 Decisions 2 to 5), and a table of
 * requests with this server's answers: listGitHubAppInstallations,
 * createPlatformConnection on an installation, checkPlatformAccess and
 * listPlatformDestinations with App Connections (installation tokens
 * minted per use), and rotateGitHubAppKey. go/server/githubapps'
 * TestMintFixtures replays it against varlatchd.
 *
 * GitHub answers through the app's syncFetch (SyncClient in Go): a fake
 * api.github.com. Requests signed as an App (an RS256 JWT issued as its
 * client id) must verify against one of the App's keys (the fixture's
 * github-app-keys.json: beta and other); the import key is refused, and
 * the conversion key makes GitHub fail. Installation tokens are
 * "minted-<installation>-<repository or all>", and each repository read
 * answers only a token minted for it. Each request's requests to GitHub
 * are kept ("METHOD URL AUTHORIZATION BODY", a JWT as
 * jwt(iss=…,key=…,window=…)) and must be the same.
 *
 * The database: alice (the bootstrap Installation Admin) and her second
 * CLI credential (alice2, whose approval intents in enf bind exact
 * requests); dave, a member of acme with a Grant of config.sync.manage
 * only; bob, a member of acme; carol, in none. Organizations acme (an App,
 * Connections on installations 77, 78 (uninstalled), 79 (a 422 for any
 * one repository) and 80 (GitHub fails), and a Sync Target on 77's with a
 * wildcard mapping), enf (admin-step-up at enforce, an App), rep (at
 * report, an App), removed (its App removed, a Connection left on it),
 * noapp, frozen (an App, an incident freeze) and deleting (a deletion
 * scheduled).
 *
 * Two files: github-mint-v0.22.0.json (every envelope sealed by this code)
 * and github-mint-v0.21.0.json (the same rows sealed again by v0.21.0's
 * crypto code).
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-github-mint-fixture.test.ts
 */
import { createPublicKey, verify } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { encryptGitHubAppKey } from "../src/crypto/hierarchy.js";
import { newId } from "../src/db/ids.js";
import { approvalHash, canonicalJson, type ApprovalBinding } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { appConnectionCreateBinding, githubAppReplaceKeyBinding } from "../src/domain/integrationstepup.js";
import { orgKekOf, type OrgRow } from "../src/domain/orgs.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { migratedTestDb } from "./helpers/pglite.js";
import {
  expectCurrentTable, expectSameAnswers, expectSameRows, exportRows, loadRows, record, resealWith, withIds,
  type Fixture, type RawAnswer, type RequestCase, type SideTable, type Table,
} from "./go-fixture-kit.js";

const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const OUT_DIR = new URL("../../../go/server/paritytest/testdata/", import.meta.url);
const FILES = { "v0.22.0": "github-mint-v0.22.0.json", "v0.21.0": "github-mint-v0.21.0.json" } as const;

/** The public URL both servers run with. */
const PUBLIC_URL = "http://127.0.0.1:8686";

/** The keys go-github-app-fixture.test.ts wrote once. */
type Keys = { conversion: string; import: string; beta: string; other: string };
const KEYS = JSON.parse(readFileSync(new URL("github-app-keys.json", OUT_DIR), "utf8")) as Keys;

/** The Apps, by client id: their GitHub id and the keys GitHub holds for them. */
const APPS: Record<string, { appId: number; keys: (keyof Keys)[] }> = {
  "Iv1.acme": { appId: 2002, keys: ["beta", "other"] },
  "Iv1.enf": { appId: 3003, keys: ["beta", "other"] },
  "Iv1.rep": { appId: 5005, keys: ["beta", "other"] },
  "Iv1.frozen": { appId: 6006, keys: ["beta", "other"] },
};

/** The installations, by id: whose they are, and how GitHub treats them. */
const INSTALLATIONS: Record<number, {
  client: string; account: string; type?: "Organization" | "User"; appId?: number; suspended?: boolean; refusesRepos?: boolean; fails?: boolean;
  selection?: "all" | "selected"; repos: { name: string; private?: boolean; archived?: boolean }[];
}> = {
  77: { client: "Iv1.acme", account: "acme-inc", repos: [{ name: "web", private: true }, { name: "api" }, { name: "old", archived: true }] },
  79: { client: "Iv1.acme", account: "acme-inc", refusesRepos: true, selection: "selected", repos: [{ name: "web", private: true }] },
  80: { client: "Iv1.acme", account: "acme-inc", fails: true, repos: [] },
  81: { client: "Iv1.acme", account: "acme-inc", suspended: true, repos: [] },
  82: { client: "Iv1.acme", account: "acme-inc", appId: 9999, repos: [] },
  83: { client: "Iv1.acme", account: "alice-personal", type: "User", repos: [] },
  91: { client: "Iv1.enf", account: "enf-inc", repos: [{ name: "site" }] },
  95: { client: "Iv1.rep", account: "rep-inc", repos: [{ name: "app" }] },
};

/** Which of the fixture's keys signed a JWT, by its signature; "?" for none. */
function signer(jwt: string): string {
  const [h, p, s] = jwt.split(".");
  if (!h || !p || !s) return "?";
  for (const [name, pem] of Object.entries(KEYS)) {
    if (verify("RSA-SHA256", Buffer.from(`${h}.${p}`), createPublicKey(pem), Buffer.from(s, "base64url"))) return name;
  }
  return "?";
}

function claimsOf(jwt: string): { iss: string; iat: number; exp: number } | null {
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

/** A request's Authorization as the log keeps it: a JWT by its claims and signer, anything else as it is. */
function authLine(auth: string): string {
  const jwt = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const c = claimsOf(jwt);
  if (!c) return auth;
  return `Bearer jwt(iss=${c.iss},key=${signer(jwt)},window=${c.exp - c.iat})`;
}

/** The fake GitHub: a request is logged as "METHOD URL AUTHORIZATION BODY" and answered by path. */
function github(log: string[]): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    const headers = new Headers(init?.headers);
    const auth = headers.get("authorization") ?? "";
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? init.body : "";
    log.push(`${method} ${url.href} ${authLine(auth)}${body ? ` ${body}` : ""}`);
    const json = (status: number, b: unknown, extra: Record<string, string> = {}) =>
      new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json", ...extra } });
    const notFound = () => json(404, { message: "Not Found" });
    if (url.host !== "api.github.com") throw new TypeError("fetch failed");
    const path = url.pathname;

    // Signed as an App.
    if (path === "/app" || path.startsWith("/app/")) {
      const jwt = auth.startsWith("Bearer ") ? auth.slice(7) : "";
      const c = claimsOf(jwt);
      if (!c) return json(401, { message: "A JSON web token could not be decoded" });
      // GitHub's clock is the JWT's own (iat + 60): a valid request at GitHub's time.
      const date = { date: new Date((c.iat + 60) * 1000).toUTCString() };
      const app = APPS[c.iss];
      const key = signer(jwt);
      if (key === "conversion") return json(500, { message: "Server Error" }, date);
      if (!app || !app.keys.includes(key as keyof Keys)) return json(401, { message: "Bad credentials" }, date);
      const mine = (id: number) => INSTALLATIONS[id]?.client === c.iss ? INSTALLATIONS[id] : undefined;
      const entry = (id: number) => {
        const i = INSTALLATIONS[id]!;
        return {
          id, app_id: i.appId ?? app.appId, account: { login: i.account, id: 500 + id, type: i.type ?? "Organization" },
          repository_selection: i.selection ?? "all", suspended_at: i.suspended ? "2026-02-01T00:00:00Z" : null,
        };
      };
      if (method === "GET" && path === "/app") {
        return json(200, { id: app.appId, slug: c.iss.slice(4), client_id: c.iss }, date);
      }
      // The listing: the App's own installations (82, another App's, is read alone).
      if (method === "GET" && path === "/app/installations") {
        const ids = url.searchParams.get("page") === "1" ? Object.keys(INSTALLATIONS).map(Number).filter((id) => mine(id) && INSTALLATIONS[id]!.appId === undefined) : [];
        return json(200, ids.map(entry), date);
      }
      const one = /^\/app\/installations\/(\d+)$/.exec(path);
      if (method === "GET" && one) return mine(Number(one[1])) ? json(200, entry(Number(one[1])), date) : notFound();
      const tokens = /^\/app\/installations\/(\d+)\/access_tokens$/.exec(path);
      if (method === "POST" && tokens) {
        const id = Number(tokens[1]);
        const i = mine(id);
        if (!i) return notFound();
        if (i.fails) return json(500, { message: "Server Error" });
        const narrowed = JSON.parse(body || "{}") as { repositories?: string[] };
        if (narrowed.repositories && i.refusesRepos) return json(422, { message: "There is at least one repository that does not exist or is not accessible to the parent installation." });
        return json(201, { token: `minted-${id}-${narrowed.repositories?.join("+") ?? "all"}`, expires_at: "2026-09-01T13:00:00Z" });
      }
      return notFound();
    }

    // With an installation token.
    const minted = /^Bearer minted-(\d+)-(.+)$/.exec(auth);
    if (!minted) return json(401, { message: "Bad credentials" });
    const inst = INSTALLATIONS[Number(minted[1])]!;
    const scope = minted[2]!;
    if (method === "GET" && path === "/installation/repositories") {
      const perPage = Number(url.searchParams.get("per_page") ?? "30");
      const page = Number(url.searchParams.get("page") ?? "1");
      const repos = inst.repos.slice((page - 1) * perPage, page * perPage).map((r) => ({
        name: r.name, full_name: `${inst.account}/${r.name}`, owner: { login: inst.account }, private: r.private === true, archived: r.archived === true,
      }));
      return json(200, { total_count: inst.repos.length, repository_selection: inst.selection ?? "all", repositories: repos });
    }
    if (method === "GET" && path === `/users/${inst.account}`) return json(200, { login: inst.account, type: inst.type ?? "Organization" });
    const repoPath = /^\/repos\/([^/]+)\/([^/]+)(\/.*)?$/.exec(path);
    if (method === "GET" && repoPath && repoPath[1] === inst.account) {
      const [, , repo, rest] = repoPath;
      const known = repo === "public" || inst.repos.some((r) => r.name === repo);
      if (!known || (scope !== "all" && scope !== repo)) return notFound();
      if (!rest) return json(200, { full_name: `${inst.account}/${repo}`, private: repo !== "public" });
      if (scope === "all") return json(403, { message: "Resource not accessible by integration" });
      const env = /^\/environments\/([^/]+)\/secrets\/public-key$/.exec(rest);
      if (rest === "/actions/secrets/public-key" || (env && env[1] === "prod")) return json(200, { key_id: "568250167242549743", key: Buffer.alloc(32, 9).toString("base64") });
      return notFound();
    }
    return notFound();
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
  { name: "audit_events", orderBy: "event_order", random: ["request_id"] },
];

const SIDE: SideTable[] = [
  { name: "github_apps", key: ["id"], sortBy: ["organization_id", "github_app_id"], volatile: ["key_envelope", "created_at", "updated_at", "removed_at"] },
  { name: "platform_connections", key: ["id"], sortBy: ["organization_id", "name"], volatile: ["credential_envelope", "created_at", "updated_at", "revoked_at"] },
  { name: "sync_targets", key: ["id"], sortBy: ["organization_id", "canonical_destination"], volatile: ["updated_at"] },
  {
    name: "security_control_counters",
    key: ["organization_id", "control", "config_version", "operation", "actor_identity_id", "reason", "bucket_hour"],
    sortBy: ["organization_id", "control", "config_version", "operation", "actor_identity_id", "reason"],
    volatile: ["bucket_hour", "first_seen", "last_seen", "emitted_at"],
  },
  { name: "approval_intents", key: ["id"], sortBy: ["organization_id", "operation", "target", "body_hash"], volatile: ["created_at", "expires_at", "consumed_at", "closed_at"] },
];

const ORG = "/v1/organizations";
const aprId = (s: string) => `apr_${s.padEnd(26, "a")}`;
const APPROVALS = { create: aprId("create"), rotate: aprId("rotate") } as const;

/** The table of requests. */
function requestTable(): RequestCase[] {
  const installations = (name: string, org: string, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "GET", path: `${ORG}/${org}/github-app/installations`, credential });
  const create = (name: string, org: string, body: unknown, extra: Partial<RequestCase> = {}): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/platform-connections`, credential: "alice", body: { credentialKind: "github-app", ...(body as object) }, ...extra });
  const check = (name: string, org: string, body: unknown): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/platform-connections/check`, credential: "alice", body });
  const destinations = (name: string, org: string, body: unknown): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/platform-connections/destinations`, credential: "alice", body });
  const rotate = (name: string, org: string, body: unknown, extra: Partial<RequestCase> = {}): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/github-app/key`, credential: "alice", body, ...extra });
  const approval = (id: string) => ({ credential: "alice2", headers: { "Varlatch-Approval": id } });
  return withIds([
    // The installations.
    installations("list the installations", "acme"),
    installations("list as a member", "acme", "bob"),
    installations("list as an outsider", "acme", "carol"),
    installations("list with no App", "noapp"),
    installations("list in a frozen Organization", "frozen"),
    installations("list in an Organization being deleted", "deleting"),
    installations("list at report", "rep"),

    // Checks and listings: installation tokens minted per use.
    check("check the App Connection", "acme", { connectionId: "{main}" }),
    check("check a repository", "acme", { connectionId: "{main}", destination: { repo: "web" } }),
    check("check a repository's environment", "acme", { connectionId: "{main}", destination: { repo: "web", environment: "prod" } }),
    check("check an environment that is not there", "acme", { connectionId: "{main}", destination: { repo: "web", environment: "nope" } }),
    check("check a repository outside the installation", "acme", { connectionId: "{main}", destination: { repo: "elsewhere" } }),
    check("check, the App uninstalled", "acme", { connectionId: "{gone}" }),
    check("check, a 422 for a repository nowhere", "acme", { connectionId: "{picky}", destination: { repo: "gone" } }),
    check("check, a 422 for a public repository outside it", "acme", { connectionId: "{picky}", destination: { repo: "public" } }),
    check("check, a 422 for a repository in it", "acme", { connectionId: "{picky}", destination: { repo: "web" } }),
    check("check the installation of the 422s", "acme", { connectionId: "{picky}" }),
    check("check, GitHub fails to mint", "acme", { connectionId: "{broken}" }),
    check("check a Connection of a removed App", "removed", { connectionId: "{orphan}" }),
    destinations("list the installation's repositories", "acme", { connectionId: "{main}" }),
    destinations("list, the App uninstalled", "acme", { connectionId: "{gone}" }),
    destinations("list a Connection of a removed App", "removed", { connectionId: "{orphan}" }),

    // Key rotation.
    rotate("rotate, not an RSA key", "acme", { privateKey: "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n", expectedVersion: 1 }),
    rotate("rotate, version 0", "acme", { privateKey: KEYS.other, expectedVersion: 0 }),
    rotate("rotate, a stale version", "acme", { privateKey: KEYS.other, expectedVersion: 2 }),
    rotate("rotate, a key GitHub does not hold", "acme", { privateKey: KEYS.import, expectedVersion: 1 }),
    rotate("rotate, GitHub fails", "acme", { privateKey: KEYS.conversion, expectedVersion: 1 }),
    rotate("rotate without disclosure authority", "acme", { privateKey: KEYS.other, expectedVersion: 1 }, { credential: "dave" }),
    rotate("rotate", "acme", { privateKey: KEYS.other, expectedVersion: 1 }),
    rotate("rotate again at the old version", "acme", { privateKey: KEYS.other, expectedVersion: 1 }),
    check("check with the new key", "acme", { connectionId: "{main}", destination: { repo: "web" } }),
    installations("list with the new key", "acme"),
    rotate("rotate with no App", "noapp", { privateKey: KEYS.other, expectedVersion: 1 }),
    rotate("rotate in a frozen Organization", "frozen", { privateKey: KEYS.other, expectedVersion: 1 }),
    rotate("rotate in an Organization being deleted", "deleting", { privateKey: KEYS.other, expectedVersion: 1 }),
    rotate("rotate at enforce, no approval", "enf", { privateKey: KEYS.other, expectedVersion: 1 }),
    rotate("rotate at enforce, its approval", "enf", { privateKey: KEYS.other, expectedVersion: 1 }, approval(APPROVALS.rotate)),
    rotate("rotate at report", "rep", { privateKey: KEYS.other, expectedVersion: 1 }),

    // App Connections (after the rotations: their ids are the replay's own,
    // and a rotation lists the App's Connections in id order).
    create("create on an installation", "acme", { installationId: 77, name: "Second" }),
    create("create on a user's installation", "acme", { installationId: 83, name: "Personal" }),
    create("create on a suspended installation", "acme", { installationId: 81, name: "Suspended" }),
    create("create on an installation of no App", "acme", { installationId: 78, name: "Nowhere" }),
    create("create, GitHub answers for another App", "acme", { installationId: 82, name: "Foreign" }),
    create("create, installation 0", "acme", { installationId: 0, name: "Zero" }),
    create("create with no App", "noapp", { installationId: 77, name: "None" }),
    create("create in a frozen Organization", "frozen", { installationId: 77, name: "Frozen" }),
    create("create in an Organization being deleted", "deleting", { installationId: 77, name: "Deleting" }),
    create("create as a member", "acme", { installationId: 77, name: "Bob's" }, { credential: "bob" }),
    create("create at enforce, no approval", "enf", { installationId: 91, name: "Approved" }),
    create("create at enforce, its approval", "enf", { installationId: 91, name: "Approved" }, approval(APPROVALS.create)),
    create("create at report", "rep", { installationId: 95, name: "Reported" }),
  ]);
}

/** Fills a request's placeholders from the file's rows. */
function fillPath(rows: Fixture["rows"]): (p: string) => string {
  const conn = (name: string) => rows.platform_connections!.find((c) => c.name === name)!.id as string;
  const pairs: [string, string][] = [["{main}", conn("Main")], ["{gone}", conn("Gone")], ["{picky}", conn("Picky")], ["{broken}", conn("Broken")], ["{orphan}", conn("Orphan")]];
  return (p) => pairs.reduce((o, [k, v]) => o.replaceAll(k, v), p);
}

type Call = (method: string, path: string, body?: unknown, token?: string) => Promise<any>;

async function build(): Promise<{ ctx: AppCtx & { close: () => Promise<void> }; tokens: Record<string, string> }> {
  const db = await migratedTestDb();
  const ctx = { db, rootKek: generateKey(), close: db.close };
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
  for (const slug of ["acme", "enf", "rep", "removed", "noapp", "frozen", "deleting"]) {
    orgs[slug] = (await call("POST", ORG, { name: slug[0]!.toUpperCase() + slug.slice(1), slug })).id;
  }
  const row = async (slug: string) => (await db.query("SELECT * FROM organizations WHERE id = $1", [orgs[slug]])).rows[0] as OrgRow;
  const people: Record<string, string> = { alice };
  for (const [name, member] of [["bob", true], ["dave", true], ["carol", false]] as const) {
    const id = newId("identity");
    await db.query("INSERT INTO identities (id, kind, name, created_at) VALUES ($1, 'human', $2, '2026-01-01T00:00:00.000Z')", [id, name]);
    if (member) await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, $2, 'member')", [orgs.acme, id]);
    tokens[name] = (await issueCredential(ctx.db, { identityId: id, kind: "cli" })).token;
    people[name] = id;
  }
  await call("POST", `${ORG}/acme/grants`, { subjectIdentityId: people.dave, scope: { kind: "organization" }, actions: ["config.sync.manage"] });

  // The Apps, all on the beta key, and their Connections.
  const apps: Record<string, { id: string; githubAppId: number; slug: string; version: number }> = {};
  const writeApp = async (slug: string, githubAppId: number, removed = false) => {
    const id = newId("githubApp");
    await db.query(
      `INSERT INTO github_apps (id, organization_id, github_app_id, slug, client_id, owner_login, owner_id, owner_type, key_envelope, created_by, created_at, removed_at)
       VALUES ($1, $2, $3, $4, $5, 'acme-inc', 501, 'organization', $6, $7, '2026-01-02T00:00:00.000Z', $8)`,
      [id, orgs[slug], githubAppId, `varlatch-${slug}`, `Iv1.${slug}`,
        removed ? null : JSON.stringify(encryptGitHubAppKey(orgKekOf(ctx, await row(slug)), orgs[slug]!, id, KEYS.beta)), alice,
        removed ? "2026-02-01T00:00:00.000Z" : null],
    );
    apps[slug] = { id, githubAppId, slug: `varlatch-${slug}`, version: 1 };
    return id;
  };
  const connection = async (slug: string, appRowId: string, installation: number, name: string, account = "acme-inc") => {
    const id = newId("platformConnection");
    await db.query(
      `INSERT INTO platform_connections (id, organization_id, platform, base_identity, name, credential_kind, github_app_id, github_installation_id, created_by, created_at)
       VALUES ($1, $2, 'github-actions', $3, $4, 'github-app', $5, $6, $7, '2026-01-02T00:00:01.000Z')`,
      [id, orgs[slug], account, name, appRowId, installation, alice],
    );
    return id;
  };
  const acmeApp = await writeApp("acme", 2002);
  const main = await connection("acme", acmeApp, 77, "Main");
  await connection("acme", acmeApp, 78, "Gone");
  await connection("acme", acmeApp, 79, "Picky");
  await connection("acme", acmeApp, 80, "Broken");
  await writeApp("enf", 3003);
  await writeApp("rep", 5005);
  await writeApp("frozen", 6006);
  const removedApp = await writeApp("removed", 7007, true);
  await connection("removed", removedApp, 77, "Orphan");

  // A Sync Target on Main: a wildcard mapping, so a rotation needs disclosure authority over its environment.
  const project = await call("POST", `${ORG}/acme/projects`, { slug: "web", name: "Web", contractAuthority: "managed" });
  await call("POST", `${ORG}/acme/projects/web/environments`, { name: "production", tier: "production" });
  const env = (await db.query("SELECT id FROM environments WHERE project_id = $1", [project.id])).rows[0].id as string;
  await db.query(
    `INSERT INTO sync_targets (id, organization_id, project_id, environment_id, connection_id, destination, canonical_destination, mapping, needs_sync, next_attempt_at, created_by, created_at)
     VALUES ($1, $2, $3, $4, $5, '{"repo":"web"}'::jsonb, '["github-actions","acme-inc","web"]', '{"kind":"wildcard"}'::jsonb, false, '2026-03-01T00:00:00.000Z', $6, '2026-01-02T00:00:02.000Z')`,
    [newId("syncTarget"), orgs.acme, project.id, env, main, alice],
  );

  // Controls, the freeze and the deletion.
  const set = (org: string, body: unknown) => call("PATCH", `${ORG}/${org}/security/controls/admin-step-up`, body);
  await set("rep", { mode: "report", expectedVersion: 0 });
  await set("enf", { mode: "report", expectedVersion: 0 });
  await set("enf", { mode: "enforce", expectedVersion: 1 });
  await db.query(
    "INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', 'incident drill')",
    [newId("organizationFreeze"), orgs.frozen, alice],
  );
  await db.query(
    "INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', '2099-03-01T00:00:00.000Z', false)",
    [newId("organizationDeletion"), orgs.deleting, alice],
  );

  // Approval intents of alice's second CLI credential in enf, each binding one request exactly as the operation binds it.
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
  const enfRow = await row("enf");
  await intent(APPROVALS.create, appConnectionCreateBinding(enfRow, apps.enf!, { installationId: 91, name: "Approved" }));
  await intent(APPROVALS.rotate, await githubAppReplaceKeyBinding(db, enfRow, apps.enf!, KEYS.other, 1));
  await accessCountsSettled();
  // Last use long ago, so a replay records the first use whenever it runs.
  await db.query("UPDATE identities SET last_seen_at = '2026-01-15T00:00:00.000Z' WHERE last_seen_at > '2026-03-02T00:00:00.000Z'");
  await db.query("UPDATE credentials SET last_used_at = '2026-01-15T00:00:00.000Z' WHERE last_used_at > '2026-03-02T00:00:00.000Z'");
  return { ctx, tokens };
}

type MintFixture = Fixture & { exchanges: Record<string, string[]> };

/** The file's answers, recorded on its own rows, with each request's requests to GitHub. */
async function replay(f: Fixture): Promise<{ requests: Fixture["requests"]; counters: Fixture["counters"]; exchanges: Record<string, string[]> }> {
  const db = await loadRows(f.rows, TABLES);
  await db.query("UPDATE audit_position SET value = (SELECT coalesce(max(event_order), 0) FROM audit_events) WHERE singleton");
  const exchanges: Record<string, string[]> = {};
  const log: string[] = [];
  try {
    const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex") };
    const recorded = await record(ctx, buildApp(ctx, { publicUrl: PUBLIC_URL, syncFetch: github(log) }), f, f.requests, fillPath(f.rows),
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
    const { ctx, tokens } = await build();
    try {
      const rows = await exportRows(ctx.db, TABLES);
      for (const ref of ["v0.22.0", "v0.21.0"] as const) {
        const fileRows = structuredClone(rows);
        if (ref === "v0.21.0") await resealWith(ref, ctx.rootKek, fileRows, () => "", undefined, { appKeyOf: () => KEYS.beta });
        const draft: MintFixture = {
          comment: "Written by services/varlatchd/test/go-github-mint-fixture.test.ts from the TypeScript server's own answers; do not edit.",
          ref,
          serverVersion: SERVER_VERSION,
          rootKek: ctx.rootKek.toString("hex"),
          tokens,
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

describe("the GitHub App minting fixtures are this server's answers", () => {
  for (const [ref, file] of Object.entries(FILES)) {
    it(file, async () => {
      const f = JSON.parse(readFileSync(new URL(file, OUT_DIR), "utf8")) as MintFixture;
      expect(f.ref).toBe(ref);
      expect(f.serverVersion).toBe(SERVER_VERSION);
      expectCurrentTable(f, requestTable());
      expect(f.sideTables).toEqual(SIDE);
      const got = await replay(f);
      expectSameAnswers(f, got);
      expect(got.exchanges).toEqual(f.exchanges);
      // The rotation took: a token is minted with the new key afterwards.
      const after = f.requests.find((r) => r.name === "check with the new key")!;
      expect(f.exchanges[after.id]!.some((l) => l.includes("iss=Iv1.acme,key=other"))).toBe(true);
      expect(f.requests.find((r) => r.name === "rotate")!.expect.status).toBe(200);
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
});
