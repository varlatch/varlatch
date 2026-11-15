// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.3's parity fixture (ADR-0059 step 4, feature-parity decision 3),
 * on the parity kit (go-fixture-kit.ts): Security Controls, step-up
 * approvals, the report counters and their hourly summaries, built through
 * this server's own /v1 API, and a table of requests with this server's
 * answers. 4.3a records listSecurityControls, changeSecurityControl,
 * securityControlReport and securityApprovalKeys; the later pull requests
 * of 4.3 add theirs to the same file. go/server/security's parity test
 * replays it against varlatchd.
 *
 * The database: alice (the bootstrap Installation Admin) and Organizations
 * made through /v1: sec (every control off), rep (every control at report),
 * enf (requirement-protection, admin-step-up and credential-lifetime at
 * enforce, passkey-verification at report), frozen (an incident freeze),
 * deleting (a deletion scheduled), guard (passkey-verification at enforce)
 * and gone (its deletion completed). The controls are set through /v1
 * where a change can be made without an approval (tightening); what needs
 * a passkey (guard's enforce, which would refuse alice's own sign-in, the
 * freeze, the deletions) is written directly. In sec: bob, a member; dave,
 * an admin with passkeys of each kind of trust; erin, an admin without
 * one; frank, a disabled admin; a service identity. carol belongs to none.
 * Approval intents of alice's second CLI credential for rep, approved or not,
 * bound to exact requests of the table. Report counters of past hours,
 * summarized or not, in rep and gone.
 *
 * Beside the requests, the file records the summary worker's pass over
 * its rows (`summaries`): the security_control.would_block events it
 * writes and the counter rows it leaves.
 *
 * Every run checks the committed file: its requests must be the table's,
 * and this server, on the file's rows, must give the recorded answers and
 * summaries. After a change, regenerate it and commit the result:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-security-fixture.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { newId } from "../src/db/ids.js";
import { approvalHash, canonicalJson } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { accessCountsSettled, runSecurityReportWorker } from "../src/domain/securityreport.js";
import { migratedTestDb } from "./helpers/pglite.js";
import {
  canonical, expectCurrentTable, expectSameAnswers, expectSameRows, exportRows, loadRows, Normalizer, record, withIds,
  type Fixture, type RequestCase, type Row, type SideTable, type Table,
} from "./go-fixture-kit.js";

// The unwrapped app: some requests are outside the OpenAPI document on
// purpose (bodies that are not JSON, extra members).
const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const FILE = new URL("../../../go/server/paritytest/testdata/security-v0.22.0.json", import.meta.url);

/** The public URL both servers run with: approvals need one. */
export const PUBLIC_URL = "http://127.0.0.1:8686";

const TABLES: Table[] = [
  { name: "installation", orderBy: "id", random: ["kek_canary"] },
  { name: "identities", orderBy: "id" },
  { name: "user", orderBy: "id" },
  { name: "auth_user_links", orderBy: "better_auth_user_id" },
  { name: "passkey", orderBy: "id" },
  { name: "passkey_provenance", orderBy: "passkey_id" },
  { name: "credentials", orderBy: "id", random: ["token_hash"] },
  { name: "organizations", orderBy: "id", random: ["wrapped_org_kek"] },
  { name: "org_memberships", orderBy: "organization_id, identity_id" },
  { name: "projects", orderBy: "id" },
  { name: "contract_revisions", orderBy: "id" },
  { name: "environments", orderBy: "id" },
  { name: "env_values", orderBy: "id" },
  { name: "value_versions", orderBy: "id", random: ["payload", "wrapped_dek"] },
  { name: "security_controls", orderBy: "organization_id, control" },
  { name: "security_control_counters", orderBy: "organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour" },
  // The intents' hashes are keyed by the build's random Root KEK.
  { name: "approval_intents", orderBy: "id", random: ["body_hash", "query_hash"] },
  { name: "organization_freezes", orderBy: "id" },
  { name: "organization_deletions", orderBy: "id" },
];

const SIDE: SideTable[] = [
  { name: "organizations", key: ["id"], sortBy: ["slug"] },
  { name: "security_controls", key: ["organization_id", "control"], sortBy: ["organization_id", "control"], volatile: ["changed_at"] },
  {
    name: "security_control_counters",
    key: ["organization_id", "control", "config_version", "operation", "actor_identity_id", "reason", "bucket_hour"],
    sortBy: ["organization_id", "control", "config_version", "operation", "actor_identity_id", "reason"],
    volatile: ["bucket_hour", "first_seen", "last_seen", "emitted_at"],
  },
  { name: "approval_intents", key: ["id"], sortBy: ["organization_id", "operation", "target", "body_hash"], volatile: ["created_at", "expires_at", "consumed_at"] },
];

const ORG = "/v1/organizations";

/** Fixed approval intent ids: a request's Varlatch-Approval header names them. */
const aprId = (s: string) => `apr_${s.padEnd(26, "a")}`;
const APPROVALS = {
  repOff: aprId("repoff"),
  pending: aprId("pending"),
  other: aprId("otherbody"),
  unknown: aprId("unknown"),
  export: aprId("export"),
} as const;

const LIFETIME_REP = { defaultTtlSeconds: 3600, maxTtlSeconds: 86_400 };
const LIFETIME_ENF = { defaultTtlSeconds: 600, maxTtlSeconds: 7200 };

/** The table of requests. */
function requestTable(): RequestCase[] {
  const list = (name: string, org: string, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "GET", path: `${ORG}/${org}/security/controls`, credential });
  const change = (name: string, org: string, control: string, body: unknown, credential = "alice", approval?: string): Omit<RequestCase, "id"> => ({
    name, method: "PATCH", path: `${ORG}/${org}/security/controls/${control}`, credential, body,
    ...(approval !== undefined ? { headers: { "Varlatch-Approval": approval } } : {}),
  });
  const raw = (name: string, org: string, control: string, rawBody: string): Omit<RequestCase, "id"> =>
    ({ name, method: "PATCH", path: `${ORG}/${org}/security/controls/${control}`, credential: "alice", rawBody });
  const report = (name: string, org: string, query = "", credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "GET", path: `${ORG}/${org}/security/control-report${query}`, credential });
  const keys = (name: string, org: string, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "GET", path: `${ORG}/${org}/security/approval-keys`, credential });
  const exp = (name: string, org: string, body: unknown, credential = "alice", approval?: string): Omit<RequestCase, "id"> => ({
    name, method: "POST", path: `${ORG}/${org}/projects/api/environments/production/disclosures`, credential, body,
    ...(approval !== undefined ? { headers: { "Varlatch-Approval": approval } } : {}),
  });
  return withIds([
    // listSecurityControls.
    list("list, every control off", "sec"),
    list("list, every control at report", "rep"),
    list("list, three at enforce", "enf"),
    list("list by id", "{secId}"),
    list("list as a member", "sec", "bob"),
    list("list as an admin", "sec", "dave"),
    list("list as an outsider", "sec", "carol"),
    list("list as its service identity", "sec", "ci"),
    list("list an unknown Organization", "nope"),
    list("list a frozen Organization", "frozen"),
    list("list an Organization being deleted", "deleting"),
    list("list under passkey-verification enforce", "guard"),
    list("list an Organization whose deletion completed", "gone"),
    list("list without a credential", "sec", "none"),
    // changeSecurityControl: tightening needs no approval.
    change("tighten admin-step-up to report", "sec", "admin-step-up", { mode: "report", expectedVersion: 0 }),
    change("the same state again", "sec", "admin-step-up", { mode: "report", expectedVersion: 1 }),
    change("a stale expected version", "sec", "admin-step-up", { mode: "enforce", expectedVersion: 0 }),
    change("tighten admin-step-up to enforce", "sec", "admin-step-up", { mode: "enforce", expectedVersion: 1 }),
    change("credential-lifetime at report without configuration", "sec", "credential-lifetime", { mode: "report", expectedVersion: 0 }),
    change("credential-lifetime configured while off", "sec", "credential-lifetime", { config: { defaultTtlSeconds: 900, maxTtlSeconds: 3600 }, expectedVersion: 0 }),
    change("credential-lifetime to report, keeping its configuration", "sec", "credential-lifetime", { mode: "report", expectedVersion: 1 }),
    change("credential-lifetime shrunk", "sec", "credential-lifetime", { config: { defaultTtlSeconds: 600, maxTtlSeconds: 1800 }, expectedVersion: 2 }),
    change("credential-lifetime grown, no approval", "sec", "credential-lifetime", { config: { defaultTtlSeconds: 600, maxTtlSeconds: 7200 }, expectedVersion: 3 }),
    change("credential-lifetime cleared at report", "sec", "credential-lifetime", { config: null, expectedVersion: 3 }),
    change("credential-lifetime off and cleared, no approval", "sec", "credential-lifetime", { mode: "off", config: null, expectedVersion: 3 }),
    change("credential-lifetime enforce with a bigger default, no approval", "sec", "credential-lifetime", { mode: "enforce", config: { defaultTtlSeconds: 900, maxTtlSeconds: 1800 }, expectedVersion: 3 }),
    change("configuration for requirement-protection", "sec", "requirement-protection", { mode: "report", config: { defaultTtlSeconds: 1, maxTtlSeconds: 2 }, expectedVersion: 0 }),
    change("configuration with its default above its maximum", "sec", "credential-lifetime", { config: { defaultTtlSeconds: 10, maxTtlSeconds: 5 }, expectedVersion: 3 }),
    change("requirement-protection to enforce", "sec", "requirement-protection", { mode: "enforce", expectedVersion: 0 }),
    change("turn admin-step-up off, no approval", "sec", "admin-step-up", { mode: "off", expectedVersion: 2 }),
    change("turn admin-step-up off at a stale version", "sec", "admin-step-up", { mode: "off", expectedVersion: 1 }),
    change("passkey-verification to enforce from an unverified sign-in", "sec", "passkey-verification", { mode: "enforce", expectedVersion: 0 }),
    change("passkey-verification to report", "sec", "passkey-verification", { mode: "report", expectedVersion: 0 }),
    change("an unknown control", "sec", "everything", { mode: "report", expectedVersion: 0 }),
    change("an encoded control name", "sec", "%70asskey-verification", { mode: "report", expectedVersion: 1 }),
    change("as a member", "sec", "admin-step-up", { mode: "report", expectedVersion: 2 }, "bob"),
    change("as an outsider", "sec", "admin-step-up", { mode: "report", expectedVersion: 2 }, "carol"),
    change("as its service identity", "sec", "admin-step-up", { mode: "report", expectedVersion: 2 }, "ci"),
    change("as an admin", "sec", "requirement-protection", { mode: "enforce", expectedVersion: 1 }, "dave"),
    change("without a credential", "sec", "admin-step-up", { mode: "report", expectedVersion: 2 }, "none"),
    change("an unknown Organization", "nope", "admin-step-up", { mode: "report", expectedVersion: 0 }),
    change("a frozen Organization, tightening", "frozen", "requirement-protection", { mode: "report", expectedVersion: 0 }),
    change("a frozen Organization, loosening without an approval", "frozen", "admin-step-up", { mode: "off", expectedVersion: 1 }),
    change("an Organization being deleted", "deleting", "admin-step-up", { mode: "report", expectedVersion: 0 }),
    change("under passkey-verification enforce", "guard", "admin-step-up", { mode: "report", expectedVersion: 0 }),
    change("an Organization whose deletion completed", "gone", "admin-step-up", { mode: "report", expectedVersion: 0 }),
    // The body's zod schema.
    change("no expected version", "sec", "admin-step-up", { mode: "report" }),
    change("a negative expected version", "sec", "admin-step-up", { mode: "report", expectedVersion: -1 }),
    change("a fractional expected version", "sec", "admin-step-up", { mode: "report", expectedVersion: 1.5 }),
    change("an expected version beyond a safe integer", "sec", "admin-step-up", { mode: "report", expectedVersion: 2 ** 53 }),
    change("a string expected version", "sec", "admin-step-up", { mode: "report", expectedVersion: "2" }),
    change("an unknown mode", "sec", "admin-step-up", { mode: "on", expectedVersion: 2 }),
    change("a null mode", "sec", "admin-step-up", { mode: null, expectedVersion: 2 }),
    change("an extra member", "sec", "admin-step-up", { mode: "report", expectedVersion: 2, reason: "drill" }),
    change("two extra members", "sec", "admin-step-up", { mode: "report", expectedVersion: 2, a: 1, b: 2 }),
    change("an empty configuration", "sec", "credential-lifetime", { config: {}, expectedVersion: 3 }),
    change("a configuration out of range, with an extra member", "sec", "credential-lifetime", { config: { defaultTtlSeconds: 0, maxTtlSeconds: 315_360_001, x: 1 }, expectedVersion: 3 }),
    change("a configuration of the wrong types", "sec", "credential-lifetime", { config: { defaultTtlSeconds: 1.5, maxTtlSeconds: "1" }, expectedVersion: 3 }),
    change("huge configuration numbers", "sec", "credential-lifetime", { config: { defaultTtlSeconds: 1e300, maxTtlSeconds: -1e300 }, expectedVersion: 3 }),
    change("a configuration that is an array", "sec", "credential-lifetime", { config: [], expectedVersion: 3 }),
    change("everything wrong at once", "sec", "admin-step-up", { mode: "x", config: 1, zz: 1 }),
    change("an array body", "sec", "admin-step-up", [1]),
    change("a null body", "sec", "admin-step-up", null),
    raw("not JSON", "sec", "admin-step-up", "mode=report"),
    raw("an empty body", "sec", "admin-step-up", ""),
    raw("a duplicate member", "sec", "admin-step-up", '{"mode":"x","expectedVersion":2,"mode":"enforce"}'),
    // Loosening with an approval (Varlatch-Approval); rep's intents were
    // asked for by alice's second CLI credential (alice2).
    change("loosen with an approval of another request", "rep", "passkey-verification", { mode: "off", expectedVersion: 1 }, "alice2", APPROVALS.other),
    change("loosen with a pending approval", "rep", "requirement-protection", { mode: "off", expectedVersion: 1 }, "alice2", APPROVALS.pending),
    change("loosen with a malformed approval header", "rep", "admin-step-up", { mode: "off", expectedVersion: 1 }, "alice2", "not-an-approval"),
    change("loosen with an unknown approval", "rep", "admin-step-up", { mode: "off", expectedVersion: 1 }, "alice2", APPROVALS.unknown),
    change("loosen with an approval another credential asked for", "rep", "admin-step-up", { mode: "off", expectedVersion: 1 }, "alice", APPROVALS.repOff),
    change("loosen with someone else's approval", "sec", "admin-step-up", { mode: "off", expectedVersion: 2 }, "dave", APPROVALS.repOff),
    change("loosen with an approval, at a stale version", "rep", "admin-step-up", { mode: "off", expectedVersion: 0 }, "alice2", APPROVALS.repOff),
    change("loosen with its approval", "rep", "admin-step-up", { mode: "off", expectedVersion: 1 }, "alice2", APPROVALS.repOff),
    change("the approval used again", "rep", "requirement-protection", { mode: "off", expectedVersion: 1 }, "alice2", APPROVALS.repOff),
    change("tighten with an approval it does not need", "rep", "admin-step-up", { mode: "report", expectedVersion: 2 }, "alice2", APPROVALS.pending),
    change("loosen, no approval, in an Organization at report", "rep", "requirement-protection", { mode: "off", expectedVersion: 1 }, "alice2"),
    change("a sixth open approval of one credential", "sec", "requirement-protection", { mode: "report", expectedVersion: 1 }),
    change("tighten, in an Organization at enforce", "enf", "credential-lifetime", { config: { defaultTtlSeconds: 300, maxTtlSeconds: 3600 }, expectedVersion: 1 }),
    // securityControlReport: rep's counts include this table's own accesses.
    report("report", "rep"),
    report("report of one day", "rep", "?days=1"),
    report("report of 30 days", "rep", "?days=30"),
    report("report of 0 days", "rep", "?days=0"),
    report("report of 31 days", "rep", "?days=31"),
    report("report of 100 days", "rep", "?days=100"),
    report("report, days not a number", "rep", "?days=abc"),
    report("report, days empty", "rep", "?days="),
    report("report, days twice", "rep", "?days=2&days=abc"),
    report("report, every control off", "sec"),
    report("report as a member", "sec", "", "bob"),
    report("report as an outsider", "rep", "", "carol"),
    report("report of a frozen Organization", "frozen"),
    report("report of an Organization being deleted", "deleting"),
    report("report under passkey-verification enforce", "guard"),
    report("report of an unknown Organization", "nope"),
    // securityApprovalKeys.
    keys("approval keys", "sec"),
    keys("approval keys, no admin with a passkey", "rep"),
    keys("approval keys as a member", "sec", "bob"),
    keys("approval keys as an admin", "sec", "dave"),
    keys("approval keys as an outsider", "sec", "carol"),
    keys("approval keys of a frozen Organization", "frozen"),
    keys("approval keys of an unknown Organization", "nope"),
    // An export under admin-step-up's enforce (exportstepup.ts, step
    // 4.3b), in enf. alice2 holds an approved intent for exporting
    // S from enf's api/production.
    exp("export, no approval", "enf", { scope: "all-authorized-secrets", purpose: "export" }, "alice2"),
    exp("export with its approval", "enf", { items: ["S", "S"], purpose: "export" }, "alice2", APPROVALS.export),
    exp("export, the approval used again", "enf", { items: ["S"], purpose: "export" }, "alice2", APPROVALS.export),
    exp("export, a malformed approval header", "enf", { items: ["S"], purpose: "export" }, "alice2", "not-an-approval"),
    exp("export, an approval for another set", "enf", { items: ["S", "T"], purpose: "export" }, "alice2", APPROVALS.pending),
    exp("export of nothing needs no approval", "enf", { items: ["NOPE"], purpose: "export" }, "alice2"),
    exp("a disclosure that is not an export", "enf", { items: ["S"] }, "alice2", "not-an-approval"),
    exp("a scan", "enf", { items: ["T"], purpose: "scan" }, "alice2"),
    // (No export under report here: its count before the audit insert's
    // locks is the lock-order inversion of the Go defects register, which
    // this suite's lock tracer refuses. go/server/values covers the count.)
    // The report and the controls after the table's changes.
    list("list after the changes", "sec"),
    report("report after the changes", "rep"),
    report("enf's report after the exports", "enf"),
  ]);
}

/** Fills a request's placeholders: {secId}. */
function fillPath(rows: Record<string, Row[]>): (p: string) => string {
  const sec = rows.organizations!.find((o) => o.slug === "sec")!.id as string;
  return (p) => p.replaceAll("{secId}", sec);
}

type Call = (method: string, path: string, body?: unknown) => Promise<any>;

async function build(): Promise<{ ctx: AppCtx & { close: () => Promise<void> }; tokens: Record<string, string> }> {
  const db = await migratedTestDb();
  const ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId: alice } = await consumeSetupGrant(ctx, grant.token, { adminName: "Alice" });
  const aliceCredential = await issueCredential(ctx.db, { identityId: alice, kind: "cli" });
  // A second CLI credential: rep's approval intents are its own.
  const alice2 = await issueCredential(ctx.db, { identityId: alice, kind: "cli" });
  const tokens: Record<string, string> = { alice: aliceCredential.token, alice2: alice2.token };
  const app = buildApp(ctx, { publicUrl: PUBLIC_URL });
  const call: Call = async (method, path, body) => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${tokens.alice}`, "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await res.text();
    if (res.status >= 300) throw new Error(`${method} ${path}: ${res.status} ${text}`);
    return text ? JSON.parse(text) : null;
  };
  const orgs: Record<string, string> = {};
  for (const slug of ["sec", "rep", "enf", "frozen", "deleting", "guard", "gone"]) {
    orgs[slug] = (await call("POST", ORG, { name: slug[0]!.toUpperCase() + slug.slice(1), slug })).id;
  }
  // A Project with two Secrets in enf and rep, for the exports, before any
  // control applies.
  const projects: Record<string, { project: string; env: string }> = {};
  for (const org of ["enf", "rep"]) {
    const project = (await call("POST", `${ORG}/${org}/projects`, { name: "API", slug: "api", contractAuthority: "managed" })).id;
    const env = (await call("POST", `${ORG}/${org}/projects/api/environments`, { name: "production", tier: "production" })).id;
    const secret = (name: string) => ({ name, required: { kind: "never" }, sensitive: true, type: "string" });
    const rev = await call("POST", `${ORG}/${org}/projects/api/contract/revisions`, {
      contract: { schemaVersion: 1, items: [secret("S"), secret("T")] }, provenance: { source: "build" },
    });
    await call("POST", `${ORG}/${org}/projects/api/contract/revisions/${rev.id}/activate`);
    for (const [item, value] of [["S", "s-value"], ["T", "t-value"]]) {
      await call("PUT", `${ORG}/${org}/projects/api/environments/production/values/${item}`, { value: `${org}-${value}` });
    }
    projects[org] = { project, env };
  }
  const set = (org: string, control: string, body: unknown) => call("PATCH", `${ORG}/${org}/security/controls/${control}`, body);
  // rep's passkey-verification last: from then on its accesses are counted.
  for (const control of ["requirement-protection", "admin-step-up"]) await set("rep", control, { mode: "report", expectedVersion: 0 });
  await set("rep", "credential-lifetime", { mode: "report", config: LIFETIME_REP, expectedVersion: 0 });
  await set("rep", "passkey-verification", { mode: "report", expectedVersion: 0 });
  await set("enf", "requirement-protection", { mode: "enforce", expectedVersion: 0 });
  await set("enf", "admin-step-up", { mode: "report", expectedVersion: 0 });
  await set("enf", "admin-step-up", { mode: "enforce", expectedVersion: 1 });
  await set("enf", "credential-lifetime", { mode: "enforce", config: LIFETIME_ENF, expectedVersion: 0 });
  await set("enf", "passkey-verification", { mode: "report", expectedVersion: 0 });
  await set("frozen", "admin-step-up", { mode: "report", expectedVersion: 0 });

  const person = async (name: string, opts: { role?: "member" | "admin"; disabled?: boolean } = {}) => {
    const id = newId("identity");
    await db.query("INSERT INTO identities (id, kind, name, disabled, created_at) VALUES ($1, 'human', $2, $3, '2026-01-01T00:00:00.000Z')", [id, name, opts.disabled ?? false]);
    if (opts.role) await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, $2, $3)", [orgs.sec, id, opts.role]);
    if (!opts.disabled) tokens[name] = (await issueCredential(ctx.db, { identityId: id, kind: "cli" })).token;
    return id;
  };
  await person("bob", { role: "member" });
  await person("carol");
  const dave = await person("dave", { role: "admin" });
  await person("erin", { role: "admin" });
  await person("frank", { role: "admin", disabled: true });
  const ci = await call("POST", `${ORG}/sec/identities`, { name: "deploy", kind: "service" });
  tokens.ci = ci.credential;
  tokens.invalid = "vlt_cli_" + "x".repeat(40);

  // dave's passkeys: trusted by confirmation, trusted at setup, unconfirmed
  // with and without a provenance row, one without a name or a time.
  await db.query(`INSERT INTO "user" (id, name, email, "createdAt", "updatedAt") VALUES ('UserDave00001', 'dave', 'dave@varlatch.placeholder.invalid', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`);
  await db.query("INSERT INTO auth_user_links (better_auth_user_id, identity_id, created_at) VALUES ('UserDave00001', $1, '2026-01-01T00:00:00.000Z')", [dave]);
  const passkey = async (id: string, name: string | null, createdAt: string | null) =>
    db.query(
      `INSERT INTO passkey (id, name, "publicKey", "userId", "credentialID", counter, "deviceType", "backedUp", "createdAt")
       VALUES ($1, $2, 'pk', 'UserDave00001', $3, 0, 'singleDevice', false, $4)`,
      [id, name, `cred-${id}`, createdAt],
    );
  await passkey("PasskeySetup01", "Laptop", "2026-01-02T00:00:00.000Z");
  await passkey("PasskeyConf001", "Phone", "2026-01-03T00:00:00.000Z");
  await passkey("PasskeyUncon01", "Old key", "2026-01-01T00:00:00.000Z");
  await passkey("PasskeyBare001", null, null);
  await passkey("PasskeyConf002", "Tablet", "2026-01-04T00:00:00.000Z");
  await db.query(
    `INSERT INTO passkey_provenance (passkey_id, trust, trusted_via, trusted_at, setup_grant_kind, confirmed_by_passkey_id, recorded_at) VALUES
       ('PasskeySetup01', 'trusted', 'setup-grant', '2026-01-02T00:00:00.000Z', 'invite', NULL, '2026-01-02T00:00:00.000Z'),
       ('PasskeyConf001', 'trusted', 'confirmed', '2026-02-05T08:00:00.000Z', NULL, 'PasskeySetup01', '2026-02-05T08:00:00.000Z'),
       ('PasskeyConf002', 'trusted', 'confirmed', '2026-02-03T08:00:00.000Z', NULL, 'PasskeySetup01', '2026-02-03T08:00:00.000Z'),
       ('PasskeyUncon01', 'unconfirmed', NULL, NULL, NULL, NULL, '2026-01-01T00:00:00.000Z')`,
  );

  // Report counters of past hours: due for a summary, already summarized
  // long ago (past retention), and a deleted Organization's.
  const counter = async (org: string, control: string, version: number, operation: string, actor: string, reason: string, hour: string, count: number, emitted: string | null) =>
    db.query(
      `INSERT INTO security_control_counters
         (organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour, count, first_seen, last_seen, emitted_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $7::timestamptz + interval '5 minutes', $7::timestamptz + interval '50 minutes', $9)`,
      [org, control, version, operation, actor, reason, hour, count, emitted],
    );
  await counter(orgs.rep!, "admin-step-up", 1, "grant.create", alice, "no-approval", "2026-03-01T10:00:00.000Z", 3, null);
  await counter(orgs.rep!, "admin-step-up", 1, "grant.create", alice, "no-approval", "2026-03-01T11:00:00.000Z", 1, null);
  await counter(orgs.rep!, "credential-lifetime", 1, "credential.issue", ci.id, "would-default", "2026-03-01T11:00:00.000Z", 2, null);
  await counter(orgs.rep!, "passkey-verification", 1, "organization.read", dave, "no-evidence", "2026-02-01T09:00:00.000Z", 4, "2026-02-01T10:15:00.000Z");
  await counter(orgs.gone!, "admin-step-up", 1, "grant.create", alice, "no-approval", "2026-03-01T10:00:00.000Z", 1, null);

  // Approval intents of alice's second CLI credential in rep. Each binds one
  // request of the table exactly as changeControl binds it.
  // (An expired intent is left out: createApproval's sweep deletes intents a
  // day past their expiry, which a fixed time cannot stay short of.)
  const intent = async (id: string, control: string, body: unknown, expectedVersion: number, state: { approved: boolean }) =>
    db.query(
      `INSERT INTO approval_intents
         (id, credential_id, identity_id, organization_id, operation, target, body_hash, query_hash, expected_version, summary, origin,
          created_at, expires_at, poll_interval, approved_at, approved_with_passkey_id, approval_user_verified)
       VALUES ($1, $2, $3, $4, 'security_control.change', $5::jsonb, $6, $7, $8, $9::jsonb, 'cli',
               '2026-01-10T00:00:00.000Z', $10, 5, $11, $12, $13)`,
      [
        id, alice2.credentialId, alice, orgs.rep, canonicalJson({ control }), approvalHash(ctx.rootKek, "body", body),
        approvalHash(ctx.rootKek, "query", {}), expectedVersion,
        JSON.stringify({ title: `Turn off the ${control} security control of Rep`, changes: [{ field: "mode", from: "report", to: "off", loosens: true }] }),
        "2099-01-01T00:00:00.000Z",
        state.approved ? "2026-01-10T00:01:00.000Z" : null, state.approved ? "PasskeyConf001" : null, state.approved ? true : null,
      ],
    );
  await intent(APPROVALS.repOff, "admin-step-up", { mode: "off", config: null, expectedVersion: 1 }, 1, { approved: true });
  await intent(APPROVALS.pending, "requirement-protection", { mode: "off", config: null, expectedVersion: 1 }, 1, { approved: false });
  await intent(APPROVALS.other, "passkey-verification", { mode: "off", config: null, expectedVersion: 0 }, 0, { approved: true });
  // An approved export of S from enf's api/production (exportBinding).
  await db.query(
    `INSERT INTO approval_intents
       (id, credential_id, identity_id, organization_id, operation, target, body_hash, query_hash, expected_version, summary, origin,
        created_at, expires_at, poll_interval, approved_at, approved_with_passkey_id, approval_user_verified)
     VALUES ($1, $2, $3, $4, 'secret.export', $5::jsonb, $6, $7, NULL, $8::jsonb, 'cli',
             '2026-01-10T00:00:00.000Z', '2099-01-01T00:00:00.000Z', 5, '2026-01-10T00:01:00.000Z', 'PasskeyConf001', true)`,
    [
      APPROVALS.export, alice2.credentialId, alice, orgs.enf, canonicalJson({ projectId: projects.enf!.project, environmentId: projects.enf!.env }),
      approvalHash(ctx.rootKek, "body", { purpose: "export", mode: "items", requested: ["S"], disclosed: ["S"] }),
      approvalHash(ctx.rootKek, "query", {}), JSON.stringify({ title: "Export S", changes: [] }),
    ],
  );

  await db.query(
    "INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', 'incident drill')",
    [newId("organizationFreeze"), orgs.frozen, alice],
  );
  // Enforcing passkey-verification from alice's sign-in (no passkey
  // evidence) would refuse her own requests: written directly.
  await db.query("INSERT INTO security_controls (organization_id, control, mode, version, changed_by) VALUES ($1, 'passkey-verification', 'enforce', 3, $2)", [orgs.guard, alice]);
  await db.query(
    "INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', '2099-03-01T00:00:00.000Z', false)",
    [newId("organizationDeletion"), orgs.deleting, alice],
  );
  await db.query(
    "INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required, completed_at) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', '2026-03-02T00:00:00.000Z', false, '2026-03-02T00:00:01.000Z')",
    [newId("organizationDeletion"), orgs.gone, alice],
  );
  await db.query("UPDATE organizations SET deleted_at = '2026-03-02T00:00:01.000Z', wrapped_org_kek = NULL, org_kek_destroyed_at = '2026-03-02T00:00:01.000Z' WHERE id = $1", [orgs.gone]);
  await accessCountsSettled();
  return { ctx, tokens };
}

const AUDIT_COLUMNS =
  "event_type, actor_identity_id, credential_id, organization_id, action, resource, decision, authz, tailnet, listener, request_id, metadata, client, schema_version";

/** The summary worker's pass over a file's rows: the events it wrote and the counter rows it left. */
interface Summaries {
  emitted: number;
  deleted: number;
  audit: Row[];
  counters: Row[];
}

async function summarize(ctx: AppCtx, rows: Record<string, Row[]>): Promise<Summaries> {
  const norm = new Normalizer(rows);
  const { emitted, deleted } = await runSecurityReportWorker(ctx);
  const audit = ((await ctx.db.query(`SELECT ${AUDIT_COLUMNS} FROM audit_events WHERE event_type = 'security_control.would_block' ORDER BY event_order`)).rows as Row[])
    .map((r) => norm.value(r) as Row);
  const counters = (await exportRows(ctx.db, [TABLES.find((t) => t.name === "security_control_counters")!])).security_control_counters!
    .map((r) => norm.value({ ...r, count: Number(r.count) }) as Row);
  return { emitted, deleted, audit, counters };
}

/** The file's answers and summaries, recorded on its own rows. */
async function replay(f: Fixture): Promise<Awaited<ReturnType<typeof record>> & { summaries: Summaries }> {
  const db = await loadRows(f.rows, TABLES);
  try {
    const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex") };
    const recorded = await record(ctx, buildApp(ctx, { publicUrl: PUBLIC_URL }), f, f.requests, fillPath(f.rows));
    const fresh = await loadRows(f.rows, TABLES);
    try {
      return { ...recorded, summaries: await summarize({ db: fresh, rootKek: ctx.rootKek }, f.rows) };
    } finally {
      await fresh.close();
    }
  } finally {
    await db.close();
  }
}

type SecurityFixture = Fixture & { summaries: Summaries };

describe.skipIf(process.env.VARLATCH_WRITE_GO_VECTORS !== "1")("writing the fixture", () => {
  it("builds the database, records the answers and the summaries, and writes the file", async () => {
    const { ctx, tokens } = await build();
    try {
      const rows = await exportRows(ctx.db, TABLES);
      const draft: Fixture = {
        comment: "Written by services/varlatchd/test/go-security-fixture.test.ts from the TypeScript server's own answers; do not edit.",
        ref: "v0.22.0",
        serverVersion: SERVER_VERSION,
        rootKek: ctx.rootKek.toString("hex"),
        tokens,
        rows,
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

describe("the security fixture is this server's answers", () => {
  it("security-v0.22.0.json", async () => {
    const f = JSON.parse(readFileSync(FILE, "utf8")) as SecurityFixture;
    expect(f.ref).toBe("v0.22.0");
    expect(f.serverVersion).toBe(SERVER_VERSION);
    expectCurrentTable(f, requestTable());
    expect(f.sideTables).toEqual(SIDE);
    const got = await replay(f);
    expectSameAnswers(f, got);
    expect(got.summaries).toEqual(f.summaries);
    // What the summaries cover: two due rows summarized, the old summary
    // and the deleted Organization's row past retention.
    expect([f.summaries.emitted, f.summaries.deleted]).toEqual([3, 2]);
    // The file's rows are still what the setup builds.
    const { ctx } = await build();
    try {
      expectSameRows(TABLES, f.rows, await exportRows(ctx.db, TABLES));
    } finally {
      await ctx.close();
    }
  }, 180_000);

  it("the approvals in the file bind the requests that use them", () => {
    const f = JSON.parse(readFileSync(FILE, "utf8")) as SecurityFixture;
    const used = f.requests.find((r) => r.name === "loosen with its approval")!;
    expect(used.expect.status).toBe(200);
    expect(canonical(JSON.parse(used.expect.body).changed)).toBe("true");
  });
});
