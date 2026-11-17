// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.10a's parity fixture (ADR-0059 step 4, feature-parity decisions 3
 * and 9), on the parity kit (go-fixture-kit.ts): the Organization's GitHub
 * App (ADR-0047), built through this server's own /v1 API and rows written
 * directly, and a table of requests with this server's answers:
 * getGitHubApp, startGitHubAppRegistration, completeGitHubAppRegistration,
 * attachGitHubAppRegistration, discardGitHubAppRegistration,
 * importGitHubApp and removeGitHubApp, and the registration sweep.
 * go/server/githubapps' parity test replays it against varlatchd.
 *
 * GitHub answers through the app's syncFetch (SyncClient in Go): a fake
 * api.github.com that answers a code exchange by its code, and GET /app by
 * the JWT's issuer once its RS256 signature verifies against one of the
 * fixture's keys. Each request's requests to it are kept ("METHOD URL
 * AUTHORIZATION"), a JWT as jwt(iss=…,key=…,window=…) with the key it was
 * signed with, and must be the same. The keys are
 * go/server/paritytest/testdata/github-app-keys.json, written once.
 *
 * The sweep is not a request: the table's "sweep" entries go to
 * SWEEP_PATH, which both sides answer themselves with one pass of the
 * sweep (sweepExpiredRegistrations).
 *
 * The database: alice (the bootstrap Installation Admin) and her second
 * CLI credential (alice2, whose approval intents in enf and enfimp bind
 * exact requests); dave, a member of acme with a Grant of
 * config.sync.manage; bob, a member of acme; carol, in none. Organizations
 * acme (controls off), imp (for imports), beta (an App, a Connection on
 * it and a Sync Target), enf and enfimp (admin-step-up at enforce, enf with
 * svc, a service identity holding config.sync.manage), rep (at report),
 * frozen (an incident freeze) and deleting (a deletion scheduled).
 * Registrations written directly with known states: in acme, fresh ones
 * for each code, an expired one, one consumed, one converted and pending
 * (its key sealed by this server), one pending past its hour, one to
 * discard, and dave's; in enf one fresh and one pending; in rep one fresh;
 * in beta one pending past its hour, for the sweep.
 *
 * Three files: github-app-v0.22.0.json (every envelope sealed by this
 * code), github-app-v0.21.0.json (the same rows sealed again by v0.21.0's
 * crypto code), and, with VARLATCH_GO_SEALED_GITHUB_APP=<file>, a file the
 * Go tests wrote (go test ./server/githubapps -run TestGoSealedFixture
 * -args -write-go-sealed=<file>), sealed again by Go, which this server
 * must answer the same (G3, go-to-ts: an attachment opens a pending key Go
 * sealed).
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-github-app-fixture.test.ts
 */
import { createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { hashToken, issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { encryptGitHubAppKey } from "../src/crypto/hierarchy.js";
import { newId } from "../src/db/ids.js";
import { approvalHash, canonicalJson, type ApprovalBinding } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { sweepExpiredRegistrations } from "../src/domain/githubapps.js";
import { githubAppImportBinding, githubAppRegisterBinding } from "../src/domain/integrationstepup.js";
import { orgKekOf, type OrgRow } from "../src/domain/orgs.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { migratedTestDb } from "./helpers/pglite.js";
import {
  expectCurrentTable, expectSameAnswers, expectSameRows, exportRows, loadRows, record, resealWith, withIds,
  type Fixture, type RawAnswer, type RequestCase, type SideTable, type Table,
} from "./go-fixture-kit.js";

const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const OUT_DIR = new URL("../../../go/server/paritytest/testdata/", import.meta.url);
const FILES = { "v0.22.0": "github-app-v0.22.0.json", "v0.21.0": "github-app-v0.21.0.json" } as const;
const KEYS_FILE = new URL("github-app-keys.json", OUT_DIR);

/** The public URL both servers run with: loopback http, so registration is allowed. */
const PUBLIC_URL = "http://127.0.0.1:8686";

/** The sweep's path, answered by each side itself (see the top). */
export const SWEEP_PATH = "/__fixture/sweep-github-app-registrations";

/** The fixture's RSA keys, PKCS #1 as GitHub issues them: written once, then read. */
type Keys = { conversion: string; import: string; beta: string; other: string };
function keys(): Keys {
  if (existsSync(KEYS_FILE)) return JSON.parse(readFileSync(KEYS_FILE, "utf8")) as Keys;
  const make = () => generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs1", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } }).privateKey;
  const k: Keys = { conversion: make(), import: make(), beta: make(), other: make() };
  writeFileSync(KEYS_FILE, JSON.stringify(k, null, 2) + "\n");
  return k;
}
const KEYS = keys();

/** GitHub's account of each Organization's registrations. */
const ACCOUNT = { login: "acme-inc", type: "organization" as const };

/** The Apps the fake hands over, by code. */
const CONVERSIONS: Record<string, { id: number; slug: string; clientId: string; owner: { login: string; id: number; type: "Organization" | "User" } }> = {
  "code-good": { id: 1001, slug: "varlatch-acme-good", clientId: "Iv1.acmegood", owner: { login: "acme-inc", id: 501, type: "Organization" } },
  "code-mismatch": { id: 1002, slug: "varlatch-acme-personal", clientId: "Iv1.personal", owner: { login: "alice-personal", id: 777, type: "User" } },
  "code-inuse": { id: 2002, slug: "varlatch-beta", clientId: "Iv1.beta", owner: { login: "acme-inc", id: 501, type: "Organization" } },
  "code-enf": { id: 3003, slug: "varlatch-enf", clientId: "Iv1.enf", owner: { login: "acme-inc", id: 501, type: "Organization" } },
  "code-rep": { id: 5005, slug: "varlatch-rep", clientId: "Iv1.rep", owner: { login: "acme-inc", id: 501, type: "Organization" } },
};

/** The Apps GET /app answers for, by the JWT's issuer (the App id), and the key each must be signed with. */
const IMPORTS: Record<string, { key: keyof Keys; status?: number; permissions?: Record<string, unknown>; id?: number }> = {
  "4004": { key: "import", permissions: { secrets: "write", environments: "write", metadata: "read", actions: "read", checks: "write" } },
  "4005": { key: "import", status: 401 },
  "4006": { key: "import", permissions: { secrets: "write", metadata: "read" } },
  "4007": { key: "import", status: 500 },
  "4008": { key: "import", permissions: { secrets: "write", environments: "write", metadata: "read" }, id: 9999 },
  "2002": { key: "import", permissions: { secrets: "write", environments: "write", metadata: "admin" } },
  "4010": { key: "import", permissions: { secrets: "admin", environments: "write", metadata: "read" } },
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

/** A request's Authorization as the log keeps it: a JWT by its claims and signer, anything else as it is. */
export function authLine(auth: string): string {
  const jwt = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (jwt.split(".").length !== 3) return auth;
  const payload = JSON.parse(Buffer.from(jwt.split(".")[1]!, "base64url").toString("utf8")) as { iss: string; iat: number; exp: number };
  return `Bearer jwt(iss=${payload.iss},key=${signer(jwt)},window=${payload.exp - payload.iat})`;
}

/** The fake GitHub: a request is logged as "METHOD URL AUTHORIZATION" and answered by path. */
export function github(log: string[]): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    const headers = new Headers(init?.headers);
    const auth = headers.get("authorization") ?? "";
    const method = init?.method ?? "GET";
    log.push(`${method} ${url.href} ${authLine(auth)}`);
    const json = (status: number, b: unknown, extra: Record<string, string> = {}) =>
      new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json", ...extra } });
    if (url.host !== "api.github.com") throw new TypeError("fetch failed");
    const conversion = /^\/app-manifests\/([^/]+)\/conversions$/.exec(url.pathname);
    if (method === "POST" && conversion) {
      const code = decodeURIComponent(conversion[1]!);
      if (code === "code-noanswer") throw new TypeError("fetch failed");
      if (code === "code-used") return json(422, { message: "Validation Failed" });
      if (code === "code-garbage") return json(201, { id: "not-an-app" });
      const c = CONVERSIONS[code];
      if (!c) return json(404, { message: "Not Found" });
      return json(201, { id: c.id, slug: c.slug, client_id: c.clientId, pem: KEYS.conversion, owner: c.owner, client_secret: "never-read", webhook_secret: null });
    }
    if (method === "GET" && url.pathname === "/app") {
      const jwt = auth.startsWith("Bearer ") ? auth.slice(7) : "";
      const parts = jwt.split(".");
      if (parts.length !== 3) return json(401, { message: "A JSON web token could not be decoded" });
      const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as { iss: string; iat: number };
      const app = IMPORTS[payload.iss];
      // GitHub's clock is the JWT's own (iat + 60): a valid request at GitHub's time.
      const date = new Date((payload.iat + 60) * 1000).toUTCString();
      if (!app || signer(jwt) !== app.key || app.status === 401) return json(401, { message: "Bad credentials" }, { date });
      if (app.status) return json(app.status, { message: "Server Error" }, { date });
      return json(200, {
        id: app.id ?? Number(payload.iss), slug: `imported-${payload.iss}`, client_id: `Iv1.imported${payload.iss}`,
        owner: { login: "acme-inc", id: 501, type: "Organization" }, permissions: app.permissions,
      }, { date });
    }
    return json(404, { message: "Not Found" });
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
  { name: "github_app_registrations", orderBy: "state_hash", random: ["pending_key_envelope"] },
  { name: "platform_connections", orderBy: "id", random: ["credential_envelope"] },
  { name: "sync_targets", orderBy: "id" },
  { name: "audit_events", orderBy: "event_order", random: ["request_id"] },
];

const SIDE: SideTable[] = [
  { name: "github_apps", key: ["id"], sortBy: ["organization_id", "github_app_id"], volatile: ["key_envelope", "created_at", "updated_at", "removed_at"] },
  {
    name: "github_app_registrations", key: ["state_hash"], sortBy: ["organization_id", "account_login", "created_at"],
    volatile: ["state_hash", "created_at", "expires_at", "consumed_at", "converted_at", "pending_expires_at", "pending_key_envelope", "ended_at"],
  },
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
const APPROVALS = { attach: aprId("attach"), import: aprId("import") } as const;

/** The states of the registrations written directly. */
const STATES = {
  good: "state-good", mismatch: "state-mismatch", used: "state-used", garbage: "state-garbage", noanswer: "state-noanswer",
  expired: "state-expired", consumed: "state-consumed", inuse: "state-inuse", enf: "state-enf", rep: "state-rep",
} as const;

/** The table of requests. */
function requestTable(): RequestCase[] {
  const get = (name: string, org: string, credential = "alice"): Omit<RequestCase, "id"> => ({ name, method: "GET", path: `${ORG}/${org}/github-app`, credential });
  const start = (name: string, org: string, body: unknown, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/github-app/registrations`, credential, body, masked: ["state", "action"] });
  const complete = (name: string, org: string, state: string, code: string, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/github-app/registrations/complete`, credential, body: { state, code } });
  const attach = (name: string, org: string, reg: string, extra: Partial<RequestCase> = {}): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/github-app/registrations/${reg}/attach`, credential: "alice", ...extra });
  const discard = (name: string, org: string, reg: string, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "DELETE", path: `${ORG}/${org}/github-app/registrations/${reg}`, credential });
  const imp = (name: string, org: string, body: unknown, extra: Partial<RequestCase> = {}): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/github-app/import`, credential: "alice", body, ...extra });
  const remove = (name: string, org: string, query: string, extra: Partial<RequestCase> = {}): Omit<RequestCase, "id"> =>
    ({ name, method: "DELETE", path: `${ORG}/${org}/github-app${query}`, credential: "alice", ...extra });
  const approval = (id: string) => ({ credential: "alice2", headers: { "Varlatch-Approval": id } });
  return withIds([
    get("get, no App", "acme"),
    get("get as a member", "acme", "bob"),
    get("get as an outsider", "acme", "carol"),
    get("get beta's", "beta"),

    // Start.
    start("start, a login GitHub has no such name for", "acme", { account: { login: "acme inc!", type: "organization" } }),
    start("start, an account type that is not one", "acme", { account: { login: "acme-inc", type: "team" } }),
    start("start, no account", "acme", {}),
    start("start", "acme", { account: ACCOUNT }),
    start("start on a user account", "acme", { account: { login: "alice-personal", type: "user" } }),
    start("start in a frozen Organization", "frozen", { account: ACCOUNT }),
    start("start in an Organization being deleted", "deleting", { account: ACCOUNT }),
    start("start in an Organization with an App", "beta", { account: ACCOUNT }),

    // The callback: the conversion, and its refusals.
    complete("complete, no such state", "acme", "state-nope", "code-good"),
    complete("complete, a state too long", "acme", "s".repeat(201), "code-good"),
    complete("complete an expired registration", "acme", STATES.expired, "code-good"),
    complete("complete a consumed registration", "acme", STATES.consumed, "code-good"),
    complete("complete, GitHub refuses the code", "acme", STATES.used, "code-used"),
    complete("complete again after the refusal", "acme", STATES.used, "code-used"),
    complete("complete, an answer that is not GitHub's", "acme", STATES.garbage, "code-garbage"),
    complete("complete, no answer", "acme", STATES.noanswer, "code-noanswer"),
    complete("complete again after no answer", "acme", STATES.noanswer, "code-noanswer"),
    complete("complete, the App on another account", "acme", STATES.mismatch, "code-mismatch"),
    complete("complete, an App another Organization uses", "acme", STATES.inuse, "code-inuse"),
    complete("complete another person's registration", "acme", STATES.good, "code-good", "dave"),

    // Attachment of the pending conversions.
    attach("attach another person's registration", "acme", "{daveReg}"),
    attach("attach an unknown registration", "acme", "ghr_aaaaaaaaaaaaaaaaaaaaaaaaaa"),
    attach("attach a registration past its hour", "acme", "{lapsedReg}"),
    attach("attach it again", "acme", "{lapsedReg}"),
    attach("attach", "acme", "{pendingReg}"),
    attach("attach again", "acme", "{pendingReg}"),
    get("get afterwards", "acme"),
    complete("complete with an App already attached", "acme", STATES.good, "code-good"),
    complete("complete it again", "acme", STATES.good, "code-good"),

    // Discard.
    discard("discard an unknown registration", "acme", "ghr_aaaaaaaaaaaaaaaaaaaaaaaaaa"),
    discard("discard another person's registration", "acme", "{daveReg}"),
    discard("discard one not converted yet", "acme", "{consumedReg}"),
    discard("discard", "acme", "{discardReg}"),
    discard("discard again", "acme", "{discardReg}"),
    discard("discard the attached one", "acme", "{pendingReg}"),

    // admin-step-up's github_app.register.
    complete("complete at enforce as a machine", "enf", STATES.enf, "code-enf", "svc"),
    complete("complete at enforce", "enf", STATES.enf, "code-enf"),
    attach("attach at enforce, no approval", "enf", "{enfPendingReg}"),
    attach("attach at enforce, its approval", "enf", "{enfPendingReg}", approval(APPROVALS.attach)),
    complete("complete at report", "rep", STATES.rep, "code-rep"),

    // Import.
    imp("import, not an RSA key", "imp", { appId: 4004, privateKey: "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n" }),
    imp("import, an App id that is not one", "imp", { appId: 0, privateKey: KEYS.import }),
    imp("import, GitHub refuses the key", "imp", { appId: 4005, privateKey: KEYS.import }),
    imp("import, a key of another App", "imp", { appId: 4004, privateKey: KEYS.other }),
    imp("import, GitHub fails", "imp", { appId: 4007, privateKey: KEYS.import }),
    imp("import, an App missing a permission", "imp", { appId: 4006, privateKey: KEYS.import }),
    imp("import, GitHub answers for another App", "imp", { appId: 4008, privateKey: KEYS.import }),
    imp("import an App another Organization uses", "imp", { appId: 2002, privateKey: KEYS.import }),
    imp("import", "imp", { appId: 4004, privateKey: KEYS.import }),
    imp("import again", "imp", { appId: 4004, privateKey: KEYS.import }),
    get("get the imported App", "imp"),
    imp("import at enforce, no approval", "enfimp", { appId: 4010, privateKey: KEYS.import }),
    imp("import at enforce, its approval", "enfimp", { appId: 4010, privateKey: KEYS.import }, approval(APPROVALS.import)),

    // Removal.
    remove("remove, no appId", "imp", ""),
    remove("remove another App than the live one", "imp", "?appId=gha_aaaaaaaaaaaaaaaaaaaaaaaaaa"),
    remove("remove", "imp", "?appId={impApp}"),
    remove("remove again", "imp", "?appId={impApp}"),
    get("get after the removal", "imp"),
    remove("remove beta's, with its Connection and Target", "beta", "?appId={betaApp}"),

    // The sweep.
    { name: "the sweep", method: "POST", path: SWEEP_PATH, credential: "none", body: {} },
    { name: "the sweep again", method: "POST", path: SWEEP_PATH, credential: "none", body: {} },
  ]);
}

/** Fills a request's placeholders from the file's rows. */
function fillPath(rows: Fixture["rows"]): (p: string) => string {
  const org = (slug: string) => rows.organizations!.find((o) => o.slug === slug)!.id as string;
  const reg = (state: string) => rows.github_app_registrations!.find((r) => r.state_hash === hashToken(state))!.id as string;
  const app = (slug: string) => rows.github_apps!.find((a) => a.organization_id === org(slug))?.id as string | undefined;
  const pairs: [string, string][] = [
    ["{daveReg}", reg("state-dave")], ["{lapsedReg}", reg("state-lapsed")], ["{pendingReg}", reg("state-pending")],
    ["{consumedReg}", reg(STATES.consumed)], ["{discardReg}", reg("state-discard")], ["{enfPendingReg}", reg("state-enf-pending")],
    ["{betaApp}", app("beta") ?? ""],
  ];
  return (p) => {
    let out = pairs.reduce((o, [k, v]) => o.replaceAll(k, v), p);
    if (out.includes("{impApp}")) {
      // The App the import created: the only one ever in imp, by the replay's rows.
      out = out.replaceAll("{impApp}", impApp);
    }
    return out;
  };
}

/** The imported App's id in the replay running now (the import creates it). */
let impApp = "";

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
  for (const slug of ["acme", "imp", "beta", "enf", "enfimp", "rep", "frozen", "deleting"]) {
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
  const svc = await call("POST", `${ORG}/enf/identities`, { name: "svc", kind: "service" });
  tokens.svc = svc.credential;
  await call("POST", `${ORG}/enf/grants`, { subjectIdentityId: svc.id, scope: { kind: "organization" }, actions: ["config.sync.manage"] });

  // beta's App, a Connection on it, and a Sync Target on that Connection.
  const betaApp = newId("githubApp");
  await db.query(
    `INSERT INTO github_apps (id, organization_id, github_app_id, slug, client_id, owner_login, owner_id, owner_type, key_envelope, created_by, created_at)
     VALUES ($1, $2, 2002, 'varlatch-beta', 'Iv1.beta', 'acme-inc', 501, 'organization', $3, $4, '2026-01-02T00:00:00.000Z')`,
    [betaApp, orgs.beta, JSON.stringify(encryptGitHubAppKey(orgKekOf(ctx, await row("beta")), orgs.beta!, betaApp, KEYS.beta)), alice],
  );
  const betaConnection = newId("platformConnection");
  await db.query(
    `INSERT INTO platform_connections (id, organization_id, platform, base_identity, name, credential_kind, github_app_id, github_installation_id, created_by, created_at)
     VALUES ($1, $2, 'github-actions', 'acme-inc', 'App', 'github-app', $3, 77, $4, '2026-01-02T00:00:01.000Z')`,
    [betaConnection, orgs.beta, betaApp, alice],
  );
  const project = await call("POST", `${ORG}/beta/projects`, { slug: "web", name: "Web", contractAuthority: "managed" });
  await call("POST", `${ORG}/beta/projects/web/environments`, { name: "development", tier: "development" });
  const env = (await db.query("SELECT id FROM environments WHERE project_id = $1", [project.id])).rows[0].id as string;
  await db.query(
    `INSERT INTO sync_targets (id, organization_id, project_id, environment_id, connection_id, destination, canonical_destination, mapping, created_by, created_at)
     VALUES ($1, $2, $3, $4, $5, '{"repo":"web"}'::jsonb, 'github-actions:acme-inc/web', '{}'::jsonb, $6, '2026-01-02T00:00:02.000Z')`,
    [newId("syncTarget"), orgs.beta, project.id, env, betaConnection, alice],
  );

  // Registrations, with known states. A converted one holds GitHub's
  // conversion as pending, its key sealed under the registration's id.
  const reg = async (slug: string, state: string, actor: string, opts: { expires?: string; consumed?: string; pending?: { appId: number; slug: string; expires: string } } = {}) => {
    const id = newId("githubAppRegistration");
    const org = await row(slug);
    const p = opts.pending;
    await db.query(
      `INSERT INTO github_app_registrations (id, state_hash, organization_id, actor_identity_id, account_login, account_type, created_at, expires_at, consumed_at,
         converted_at, pending_expires_at, pending_github_app_id, pending_slug, pending_client_id, pending_owner_login, pending_owner_id, pending_owner_type, pending_key_envelope)
       VALUES ($1, $2, $3, $4, 'acme-inc', 'organization', '2026-03-01T00:00:00.000Z', $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
      [
        id, hashToken(state), org.id, actor, opts.expires ?? "2099-01-01T00:00:00.000Z", p ? "2026-03-01T00:05:00.000Z" : (opts.consumed ?? null),
        p ? "2026-03-01T00:05:00.000Z" : null, p?.expires ?? null, p?.appId ?? null, p?.slug ?? null, p ? `Iv1.${p.slug}` : null,
        p ? "acme-inc" : null, p ? 501 : null, p ? "organization" : null,
        p ? JSON.stringify(encryptGitHubAppKey(orgKekOf(ctx, org), org.id, id, KEYS.conversion)) : null,
      ],
    );
    return id;
  };
  for (const s of [STATES.good, STATES.mismatch, STATES.used, STATES.garbage, STATES.noanswer, STATES.inuse]) await reg("acme", s, alice);
  await reg("acme", STATES.expired, alice, { expires: "2026-03-01T01:00:00.000Z" });
  await reg("acme", STATES.consumed, alice, { consumed: "2026-03-01T00:10:00.000Z" });
  await reg("acme", "state-pending", alice, { pending: { appId: 1009, slug: "varlatch-acme", expires: "2099-01-01T00:00:00.000Z" } });
  await reg("acme", "state-lapsed", alice, { pending: { appId: 1010, slug: "varlatch-acme-late", expires: "2026-03-01T01:05:00.000Z" } });
  await reg("acme", "state-discard", alice, { pending: { appId: 1011, slug: "varlatch-acme-discard", expires: "2099-01-01T00:00:00.000Z" } });
  await reg("acme", "state-dave", people.dave!, { pending: { appId: 1012, slug: "varlatch-acme-dave", expires: "2099-01-01T00:00:00.000Z" } });
  await reg("enf", STATES.enf, alice);
  const enfPending = await reg("enf", "state-enf-pending", alice, { pending: { appId: 3009, slug: "varlatch-enf-pending", expires: "2099-01-01T00:00:00.000Z" } });
  await reg("rep", STATES.rep, alice);
  await reg("beta", "state-sweep", alice, { pending: { appId: 2009, slug: "varlatch-beta-old", expires: "2026-03-01T01:05:00.000Z" } });

  // Controls, the freeze and the deletion.
  const set = (org: string, body: unknown) => call("PATCH", `${ORG}/${org}/security/controls/admin-step-up`, body);
  await set("rep", { mode: "report", expectedVersion: 0 });
  for (const org of ["enf", "enfimp"]) {
    await set(org, { mode: "report", expectedVersion: 0 });
    await set(org, { mode: "enforce", expectedVersion: 1 });
  }
  await db.query(
    "INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', 'incident drill')",
    [newId("organizationFreeze"), orgs.frozen, alice],
  );
  await db.query(
    "INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', '2099-03-01T00:00:00.000Z', false)",
    [newId("organizationDeletion"), orgs.deleting, alice],
  );

  // Approval intents of alice's second CLI credential, each binding one
  // request exactly as the operation binds it.
  const intent = async (id: string, org: string, binding: ApprovalBinding) =>
    db.query(
      `INSERT INTO approval_intents
         (id, credential_id, identity_id, organization_id, operation, target, body_hash, query_hash, expected_version, summary, origin,
          created_at, expires_at, poll_interval, approved_at, approved_with_passkey_id, approval_user_verified)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10::jsonb, 'cli',
               '2026-01-10T00:00:00.000Z', '2099-01-01T00:00:00.000Z', 5, '2026-01-10T00:01:00.000Z', 'PasskeyConf001', true)`,
      [
        id, alice2.credentialId, alice, orgs[org], binding.operation, canonicalJson(binding.target),
        approvalHash(ctx.rootKek, "body", binding.body), approvalHash(ctx.rootKek, "query", binding.query),
        binding.expectedVersion, JSON.stringify(binding.summary),
      ],
    );
  const enfRow = await row("enf");
  await intent(APPROVALS.attach, "enf", githubAppRegisterBinding(enfRow, {
    registrationId: enfPending, githubAppId: 3009, slug: "varlatch-enf-pending", clientId: "Iv1.varlatch-enf-pending",
    owner: { login: "acme-inc", id: 501, type: "organization" },
  }));
  await intent(APPROVALS.import, "enfimp", githubAppImportBinding(await row("enfimp"), { appId: 4010, privateKey: KEYS.import }));
  await accessCountsSettled();
  // Last use long ago, so a replay records the first use whenever it runs.
  await db.query("UPDATE identities SET last_seen_at = '2026-01-15T00:00:00.000Z' WHERE last_seen_at > '2026-03-02T00:00:00.000Z'");
  await db.query("UPDATE credentials SET last_used_at = '2026-01-15T00:00:00.000Z' WHERE last_used_at > '2026-03-02T00:00:00.000Z'");
  return { ctx, tokens };
}

/** The app, with SWEEP_PATH answered by the sweep (see the top). */
function withSweep(ctx: AppCtx, app: { request: (path: string, init: RequestInit) => Response | Promise<Response> }) {
  return {
    request: async (path: string, init: RequestInit): Promise<Response> => {
      if (path !== SWEEP_PATH) return app.request(path, init);
      const ended = await sweepExpiredRegistrations(ctx);
      return new Response(JSON.stringify({ ended }), { status: 200, headers: { "Content-Type": "application/json" } });
    },
  };
}

type AppFixture = Fixture & { exchanges: Record<string, string[]> };

/** The file's answers, recorded on its own rows, with each request's requests to GitHub. */
async function replay(f: Fixture): Promise<{ requests: Fixture["requests"]; counters: Fixture["counters"]; exchanges: Record<string, string[]> }> {
  const db = await loadRows(f.rows, TABLES);
  await db.query("UPDATE audit_position SET value = (SELECT coalesce(max(event_order), 0) FROM audit_events) WHERE singleton");
  const exchanges: Record<string, string[]> = {};
  const log: string[] = [];
  impApp = "";
  try {
    const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex") };
    const recorded = await record(ctx, withSweep(ctx, buildApp(ctx, { publicUrl: PUBLIC_URL, syncFetch: github(log) })), f, f.requests, fillPath(f.rows),
      (c: RequestCase, raw: RawAnswer) => {
        if (log.length > 0) exchanges[c.id] = log.splice(0);
        if (c.name === "import" && raw.statuses[0] === 201) impApp = (JSON.parse(raw.bodies[0]!) as { app: { id: string } }).app.id;
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
        if (ref === "v0.21.0") {
          await resealWith(ref, ctx.rootKek, fileRows, () => "", undefined, {
            appKeyOf: () => KEYS.beta,
            pendingKeyOf: () => KEYS.conversion,
          });
        }
        const draft: AppFixture = {
          comment: "Written by services/varlatchd/test/go-github-app-fixture.test.ts from the TypeScript server's own answers; do not edit.",
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

async function expectFixture(f: AppFixture) {
  expect(f.serverVersion).toBe(SERVER_VERSION);
  expectCurrentTable(f, requestTable());
  expect(f.sideTables).toEqual(SIDE);
  const got = await replay(f);
  expectSameAnswers(f, got);
  expect(got.exchanges).toEqual(f.exchanges);
}

describe("the GitHub App fixtures are this server's answers", () => {
  for (const [ref, file] of Object.entries(FILES)) {
    it(file, async () => {
      const f = JSON.parse(readFileSync(new URL(file, OUT_DIR), "utf8")) as AppFixture;
      expect(f.ref).toBe(ref);
      await expectFixture(f);
      // The pending key opened at the attachment, and the import's JWT was signed with the key it was given.
      const attached = f.requests.find((r) => r.name === "attach")!;
      expect(attached.expect.status).toBe(201);
      expect(Object.values(f.exchanges).flat().some((l) => l.includes("iss=4004,key=import,window=600"))).toBe(true);
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
  const goSealed = process.env.VARLATCH_GO_SEALED_GITHUB_APP;
  it.skipIf(!goSealed)("GitHub App keys the Go server sealed open here with the same answers and exchanges", async () => {
    if (!existsSync(goSealed!)) throw new Error(`${goSealed}: no such file`);
    const f = JSON.parse(readFileSync(goSealed!, "utf8")) as AppFixture;
    expect(f.comment).toMatch(/Go/);
    await expectFixture(f);
  }, 300_000);
});
