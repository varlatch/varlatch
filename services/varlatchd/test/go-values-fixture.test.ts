// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The read path of values on both servers (ADR-0059 step 3.6, gate G3 and
 * the parity of getEffectiveConfiguration and discloseSecrets).
 *
 * A database is built through this server's own /v1 API, the way an
 * installation fills it: Organizations, a Project with root, preview and
 * expired environments, an active Contract, values with references,
 * escapes, cycles, inheritance and a rotation in progress, Grants of
 * several shapes, a machine identity and an Agent Run credential, a
 * Tailnet Requirement, an incident freeze, Security Controls, rotations
 * whose window has passed or that completed, a machine that may use
 * Secrets but not reveal them, and assisted-mode requests. Then a table of
 * requests (requestTable) runs against it, and the file records, for
 * each, this server's answer (status, the headers that matter, the body
 * byte for byte) and the audit events, exposure rows and report counts it
 * wrote. The rows are exported as PostgreSQL holds them, the
 * installation's Root KEK canary included: the readiness request makes
 * each server open it (G3 at the database level for the canary).
 *
 * go/server/values loads the rows through the schema mapping
 * (go/server/db/mapping.json), as the migration will copy them, runs the
 * same requests against the Go server and requires the same answers.
 *
 * Two files, one per release whose envelopes must open (G3):
 *   - values-v0.22.0.json: every envelope sealed by this code;
 *   - values-v0.21.0.json: the same rows, the canary and every
 *     Organization KEK and value sealed again by v0.21.0's crypto code (services/varlatchd/src/crypto
 *     at the tag, loaded with git show), which is what a v0.21.0
 *     installation's data is after its upgrade to 0.22.0: no migration
 *     between the two touches a ciphertext.
 *
 * Here, every run checks that each committed file's requests are
 * requestTable()'s, by id (a request added, removed or changed without
 * regenerating fails), loads its rows into a fresh database and requires
 * this server to give the recorded answers again, so a file never drifts
 * from this code. With VARLATCH_GO_SEALED_VALUES=<file>, the same
 * check runs on a file the Go tests wrote (go test ./server/values -run
 * TestGoSealedFixture -args -write-go-sealed=<file>): the same rows with
 * the canary and every Organization KEK and value sealed again by the Go
 * code, so this
 * server's own read path opens what Go sealed (go.yml, go-binary job).
 *
 * After a change, regenerate both files and commit them:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-values-fixture.test.ts
 *
 * (v0.21.0's sources come from git: the tag must be fetched.)
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { decryptValue, unwrapOrgKek } from "../src/crypto/hierarchy.js";
import type { Envelope } from "../src/crypto/aead.js";
import { newId } from "../src/db/ids.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { resealWith } from "./go-fixture-kit.js";

// The unwrapped app, as go-parity.test.ts uses it: some of the table's
// requests are outside the OpenAPI document on purpose (a body with both
// items and scope, extra members, bodies that are not JSON), which the
// document check every other test runs does not model.
const { buildApp } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const OUT_DIR = new URL("../../../go/server/values/testdata/", import.meta.url);
/** The conformance runner's seed Contract (scripts/conformance/run.mjs seed), in a Project of its own. */
const SEED_CONTRACT = {
  schemaVersion: 1,
  items: [
    { name: "DATABASE_URL", required: { kind: "always" }, sensitive: true, type: "url" },
    { name: "PORT", required: { kind: "always" }, sensitive: false, type: "number", defaultValue: "3000" },
    { name: "API_KEY", required: { kind: "selector", selector: { kind: "tier", tier: "production" } }, sensitive: true, type: "string" },
    { name: "PUBLIC_URL", required: { kind: "never" }, sensitive: false, type: "string" },
  ],
};
const FILES = { "v0.22.0": "values-v0.22.0.json", "v0.21.0": "values-v0.21.0.json" } as const;

/** The tables the read path reads, in an order that satisfies their foreign keys once each is sorted (rowOrder). */
const TABLES = [
  // The Root KEK canary (G3 at the database level: both servers check it
  // with the readiness request below).
  "installation",
  "identities",
  "user",
  "auth_user_links",
  "credentials",
  "organizations",
  "org_memberships",
  "projects",
  "environments",
  "contract_revisions",
  "env_values",
  "value_versions",
  "grants",
  "requirements",
  "security_controls",
  "organization_freezes",
] as const;

/** Rows in an order their self-references allow: parents and previous versions first. */
const ORDER_BY: Record<string, string> = {
  installation: "id",
  identities: "id",
  user: "id",
  auth_user_links: "better_auth_user_id",
  credentials: "id",
  organizations: "id",
  org_memberships: "organization_id, identity_id",
  projects: "id",
  environments: "(parent_environment_id IS NOT NULL), id",
  contract_revisions: "id",
  env_values: "id",
  value_versions: "created_at, id",
  grants: "id",
  requirements: "id",
  security_controls: "organization_id, control",
  organization_freezes: "id",
};

type Row = Record<string, unknown>;
type Credential = "alice" | "bob" | "carol" | "dave" | "erin" | "ci" | "viewer" | "runner" | "agent" | "none" | "invalid";

/** The CLI's User-Agent, and in assisted mode (ADR-0043 Decision 3). */
const CLI_AGENT = "varlatch-cli/0.22.0 (linux; x64)";
const ASSISTED_AGENT = "varlatch-cli/0.22.0 (linux; x64; assisted)";

interface RequestCase {
  /** Stable: the method and the name, unique in the table. */
  id: string;
  name: string;
  method: "GET" | "POST";
  path: string;
  credential: Credential;
  /** A JSON body, or the exact text of one that is not JSON. */
  body?: unknown;
  rawBody?: string;
  /** The User-Agent sent (CLI_AGENT when absent). */
  userAgent?: string;
}

interface Recorded extends RequestCase {
  expect: { status: number; headers: Record<string, string>; body: string };
  audit: Row[];
  exposure: Row[];
}

interface Fixture {
  comment: string;
  ref: string;
  rootKek: string;
  tokens: Record<string, string>;
  plaintexts: Record<string, string>;
  rows: Record<string, Row[]>;
  requests: Recorded[];
  counters: Row[];
}

const json = (v: unknown): unknown => (v instanceof Date ? v.toISOString() : v);
const REQUEST_ID = "{requestId}";

const ORG = "/v1/organizations/acme/projects/api/environments";

/** The table of requests, the same for both releases. */
function requestTable(ids: { devId: string }): RequestCase[] {
  const all = { scope: "all-authorized-secrets" };
  const cases: Omit<RequestCase, "id">[] = [
    // Readiness: the loaded Root KEK opens the installation's canary.
    { name: "readiness", method: "GET", path: "/readyz", credential: "none" },
    // Effective configuration: metadata, values, purposes, parameters.
    { name: "metadata only", method: "GET", path: `${ORG}/development/effective-configuration`, credential: "alice" },
    { name: "with values", method: "GET", path: `${ORG}/development/effective-configuration?include=values`, credential: "alice" },
    { name: "values for an export", method: "GET", path: `${ORG}/development/effective-configuration?include=values&purpose=export`, credential: "alice" },
    { name: "values for a scan", method: "GET", path: `${ORG}/development/effective-configuration?include=values&purpose=scan`, credential: "alice" },
    { name: "an unknown purpose", method: "GET", path: `${ORG}/development/effective-configuration?include=values&purpose=backup`, credential: "alice" },
    { name: "an include that is not values", method: "GET", path: `${ORG}/development/effective-configuration?include=everything`, credential: "alice" },
    { name: "the environment by id", method: "GET", path: `${ORG}/${ids.devId}/effective-configuration?include=values`, credential: "alice" },
    { name: "the Organization and Project by id", method: "GET", path: `/v1/organizations/{orgId}/projects/{projectId}/environments/development/effective-configuration`, credential: "alice" },
    { name: "a preview inherits", method: "GET", path: `${ORG}/development%2Fpr-7/effective-configuration?include=values`, credential: "alice" },
    { name: "an expired preview", method: "GET", path: `${ORG}/development%2Fpr-old/effective-configuration`, credential: "alice" },
    { name: "an unknown environment", method: "GET", path: `${ORG}/nowhere/effective-configuration`, credential: "alice" },
    { name: "an unknown project", method: "GET", path: `/v1/organizations/acme/projects/nope/environments/development/effective-configuration`, credential: "alice" },
    { name: "an unknown organization", method: "GET", path: `/v1/organizations/nope/projects/api/environments/development/effective-configuration`, credential: "alice" },
    { name: "an encoded environment name", method: "GET", path: `${ORG}/develop%6dent/effective-configuration`, credential: "alice" },
    { name: "a Tailnet Requirement on values", method: "GET", path: `${ORG}/production/effective-configuration?include=values`, credential: "alice" },
    { name: "a Tailnet Requirement, metadata", method: "GET", path: `${ORG}/production/effective-configuration`, credential: "alice" },
    { name: "a member with a project grant", method: "GET", path: `${ORG}/development/effective-configuration?include=values`, credential: "bob" },
    { name: "an outsider", method: "GET", path: `${ORG}/development/effective-configuration?include=values`, credential: "carol" },
    { name: "a member without grants", method: "GET", path: `${ORG}/development/effective-configuration?include=values`, credential: "dave" },
    { name: "a tier grant, inside", method: "GET", path: `${ORG}/development/effective-configuration?include=values`, credential: "erin" },
    { name: "a tier grant, outside", method: "GET", path: `${ORG}/staging/effective-configuration?include=values`, credential: "erin" },
    { name: "a machine", method: "GET", path: `${ORG}/development/effective-configuration?include=values`, credential: "ci" },
    { name: "a machine that reads metadata only", method: "GET", path: `${ORG}/development/effective-configuration?include=values`, credential: "viewer" },
    { name: "a machine outside its Organization", method: "GET", path: `/v1/organizations/reported/projects/api/environments/development/effective-configuration`, credential: "viewer" },
    { name: "an agent run", method: "GET", path: `${ORG}/development/effective-configuration`, credential: "agent" },
    { name: "no credential", method: "GET", path: `${ORG}/development/effective-configuration`, credential: "none" },
    { name: "an invalid credential", method: "GET", path: `${ORG}/development/effective-configuration`, credential: "invalid" },
    { name: "a frozen organization", method: "GET", path: `/v1/organizations/frozen/projects/api/environments/development/effective-configuration`, credential: "alice" },
    { name: "passkey-verification enforced", method: "GET", path: `/v1/organizations/guarded/projects/api/environments/development/effective-configuration?include=values`, credential: "alice" },
    { name: "passkey-verification reported", method: "GET", path: `/v1/organizations/reported/projects/api/environments/development/effective-configuration?include=values`, credential: "alice" },
    { name: "secret.use without reveal", method: "GET", path: `${ORG}/development/effective-configuration?include=values`, credential: "runner" },
    { name: "assisted mode", method: "GET", path: `${ORG}/development/effective-configuration?include=values`, credential: "alice", userAgent: ASSISTED_AGENT },
    { name: "an empty environment", method: "GET", path: `${ORG}/staging/effective-configuration?include=values`, credential: "alice" },
    // Disclosures.
    { name: "every authorized Secret", method: "POST", path: `${ORG}/development/disclosures`, credential: "alice", body: all },
    { name: "named Secrets, some unknown", method: "POST", path: `${ORG}/development/disclosures`, credential: "alice", body: { items: ["DATABASE_URL", "PORT", "MISSING", "TOKEN", "DATABASE_URL"] } },
    { name: "a scan", method: "POST", path: `${ORG}/development/disclosures`, credential: "alice", body: { ...all, purpose: "scan" } },
    { name: "an export of named Secrets", method: "POST", path: `${ORG}/development/disclosures`, credential: "alice", body: { items: ["DB_PASS"], purpose: "export" } },
    { name: "an unknown purpose", method: "POST", path: `${ORG}/development/disclosures`, credential: "alice", body: { ...all, purpose: "backup" } },
    { name: "an empty body", method: "POST", path: `${ORG}/development/disclosures`, credential: "alice", body: {} },
    { name: "no items", method: "POST", path: `${ORG}/development/disclosures`, credential: "alice", body: { items: [] } },
    { name: "an empty item name", method: "POST", path: `${ORG}/development/disclosures`, credential: "alice", body: { items: [""] } },
    { name: "items that are not strings", method: "POST", path: `${ORG}/development/disclosures`, credential: "alice", body: { items: [1, "A"] } },
    { name: "both items and scope", method: "POST", path: `${ORG}/development/disclosures`, credential: "alice", body: { items: ["DB_PASS"], scope: "all-authorized-secrets" } },
    { name: "another scope", method: "POST", path: `${ORG}/development/disclosures`, credential: "alice", body: { scope: "everything" } },
    { name: "an array body", method: "POST", path: `${ORG}/development/disclosures`, credential: "alice", body: ["DB_PASS"] },
    { name: "null", method: "POST", path: `${ORG}/development/disclosures`, credential: "alice", body: null },
    { name: "not JSON", method: "POST", path: `${ORG}/development/disclosures`, credential: "alice", rawBody: "items=DB_PASS" },
    { name: "extra members", method: "POST", path: `${ORG}/development/disclosures`, credential: "alice", body: { ...all, reason: "audit" } },
    { name: "a preview's Secrets", method: "POST", path: `${ORG}/development%2Fpr-7/disclosures`, credential: "alice", body: all },
    { name: "an expired preview", method: "POST", path: `${ORG}/development%2Fpr-old/disclosures`, credential: "alice", body: all },
    { name: "an unknown environment", method: "POST", path: `${ORG}/nowhere/disclosures`, credential: "alice", body: all },
    { name: "a Tailnet Requirement", method: "POST", path: `${ORG}/production/disclosures`, credential: "alice", body: all },
    { name: "a member with a project grant", method: "POST", path: `${ORG}/development/disclosures`, credential: "bob", body: all },
    { name: "a member, not JSON", method: "POST", path: `${ORG}/development/disclosures`, credential: "bob", rawBody: "{" },
    { name: "an outsider", method: "POST", path: `${ORG}/development/disclosures`, credential: "carol", body: all },
    { name: "a member without grants", method: "POST", path: `${ORG}/development/disclosures`, credential: "dave", body: all },
    { name: "a member with a tier grant", method: "POST", path: `${ORG}/development/disclosures`, credential: "erin", body: all },
    { name: "a machine", method: "POST", path: `${ORG}/development/disclosures`, credential: "ci", body: all },
    { name: "a machine, named", method: "POST", path: `${ORG}/production/disclosures`, credential: "ci", body: { items: ["API_KEY"] } },
    { name: "a machine that reads metadata only", method: "POST", path: `${ORG}/development/disclosures`, credential: "viewer", body: all },
    { name: "a machine that reads metadata only, not JSON", method: "POST", path: `${ORG}/development/disclosures`, credential: "viewer", rawBody: "{" },
    { name: "a machine outside its Organization", method: "POST", path: `/v1/organizations/reported/projects/api/environments/development/disclosures`, credential: "viewer", body: all },
    { name: "an agent run", method: "POST", path: `${ORG}/development/disclosures`, credential: "agent", body: all },
    { name: "a frozen organization", method: "POST", path: `/v1/organizations/frozen/projects/api/environments/development/disclosures`, credential: "alice", body: all },
    { name: "passkey-verification enforced", method: "POST", path: `/v1/organizations/guarded/projects/api/environments/development/disclosures`, credential: "alice", body: all },
    { name: "passkey-verification reported", method: "POST", path: `/v1/organizations/reported/projects/api/environments/development/disclosures`, credential: "alice", body: all },
    { name: "secret.use without reveal", method: "POST", path: `${ORG}/development/disclosures`, credential: "runner", body: all },
    { name: "assisted mode", method: "POST", path: `${ORG}/development/disclosures`, credential: "alice", body: all, userAgent: ASSISTED_AGENT },
    { name: "rotation boundaries", method: "POST", path: `${ORG}/development/disclosures`, credential: "alice", body: { items: ["TOKEN", "TOKEN_EXPIRED", "TOKEN_DONE"] } },
    { name: "an environment with no Secrets", method: "POST", path: `${ORG}/staging/disclosures`, credential: "alice", body: all },
  ];
  const out = cases.map((c) => ({ id: `${c.method} ${c.name}`, ...c }));
  if (new Set(out.map((c) => c.id)).size !== out.length) throw new Error("requestTable: two requests share an id");
  return out;
}

const CONTRACT_ITEMS: [string, boolean][] = [
  ["DATABASE_URL", true],
  ["DB_PASS", true],
  ["DB_HOST", false],
  ["PORT", false],
  ["PUBLIC_URL", false],
  ["GREETING", false],
  ["LOOP_A", false],
  ["LOOP_B", false],
  ["ESCAPED", true],
  ["DEEP", true],
  ["API_KEY", true],
  ["TOKEN", true],
  // Rotation boundaries: a window that has passed, and a completed rotation.
  ["TOKEN_EXPIRED", true],
  ["TOKEN_DONE", true],
  ["UNICODE", true],
  ["GONE", true],
];

/** Values per environment: references, escapes, a cycle, a reference through a plain value, text beyond ASCII. */
const VALUES: Record<string, [string, string][]> = {
  development: [
    ["DB_HOST", "db.internal"],
    ["DB_PASS", "hunter2-hunter2"],
    ["DATABASE_URL", "postgres://app:${DB_PASS}@${DB_HOST}/app?ssl=${MISSING}"],
    ["PORT", "3000"],
    ["PUBLIC_URL", "https://app.example"],
    ["GREETING", "hello from ${PUBLIC_URL} ($${PORT} stays)"],
    ["LOOP_A", "a<${LOOP_B}>"],
    ["LOOP_B", "b<${LOOP_A}>"],
    ["ESCAPED", "$${DB_PASS} and ${DB_PASS}"],
    ["DEEP", "${GREETING} / ${API_KEY}"],
    ["API_KEY", "ak-dev-0001"],
    ["TOKEN", "tok-old-old-old"],
    ["TOKEN_EXPIRED", "exp-old-old-old"],
    ["TOKEN_DONE", "done-old-old-old"],
    ["UNICODE", "héllo wörld ✓ 𝄞"],
    ["STRAY", "not in the contract"],
    ["GONE", "deleted soon"],
  ],
  production: [
    ["DATABASE_URL", "postgres://prod"],
    ["API_KEY", "ak-prod-0001"],
    ["PORT", "443"],
  ],
  "development%2Fpr-7": [["DB_PASS", "preview-pass"]],
  staging: [["PORT", "8080"]],
};

async function build(): Promise<{ ctx: AppCtx & { close: () => Promise<void> }; tokens: Record<string, string>; plaintexts: Record<string, string>; ids: { devId: string; orgId: string; projectId: string } }> {
  const db = await migratedTestDb();
  const ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId: alice } = await consumeSetupGrant(ctx, grant.token, { adminName: "Alice" });
  const tokens: Record<string, string> = { alice: (await issueCredential(ctx.db, { identityId: alice, kind: "cli" })).token };
  const app = buildApp(ctx);
  const call = async (method: string, path: string, body?: unknown, token = tokens.alice) => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await res.text();
    if (res.status >= 300) throw new Error(`${method} ${path}: ${res.status} ${text}`);
    return text ? JSON.parse(text) : null;
  };
  const items = CONTRACT_ITEMS.map(([name, sensitive]) => ({ name, required: { kind: "never" }, sensitive, type: "string" }));

  const ids = { devId: "", orgId: "", projectId: "" };
  for (const slug of ["acme", "frozen", "guarded", "reported"]) {
    const org = await call("POST", "/v1/organizations", { name: slug[0]!.toUpperCase() + slug.slice(1), slug });
    const project = await call("POST", `/v1/organizations/${slug}/projects`, { name: "API", slug: "api", contractAuthority: "managed" });
    const P = `/v1/organizations/${slug}/projects/api`;
    const dev = await call("POST", `${P}/environments`, { name: "development", tier: "development" });
    if (slug === "acme") {
      ids.devId = dev.id;
      ids.orgId = org.id;
      ids.projectId = project.id;
      await call("POST", `${P}/environments`, { name: "production", tier: "production" });
      await call("POST", `${P}/environments`, { name: "staging", tier: "staging" });
      await call("POST", `${P}/environments`, { name: "development/pr-7", kind: "preview", parentEnvironmentId: dev.id, expiresAt: "2099-01-01T00:00:00.000Z" });
      await call("POST", `${P}/environments`, { name: "development/pr-old", kind: "preview", parentEnvironmentId: dev.id, expiresAt: "2099-01-01T00:00:00.000Z" });
    }
    const revision = await call("POST", `${P}/contract/revisions`, { contract: { schemaVersion: 1, items } });
    await call("POST", `${P}/contract/revisions/${revision.id}/activate`, {});
    for (const [env, values] of Object.entries(VALUES)) {
      if (slug !== "acme" && env !== "development") continue;
      for (const [name, value] of values) await call("PUT", `${P}/environments/${env}/values/${name}`, { value });
    }
    if (slug === "acme") {
      await call("DELETE", `${P}/environments/development/values/GONE`);
      await call("POST", `${P}/environments/development/values/TOKEN/rotations`, { value: "tok-new-new-new" });
      await call("POST", `${P}/environments/development/values/TOKEN_EXPIRED/rotations`, { value: "exp-new-new-new" });
      await call("POST", `${P}/environments/development/values/TOKEN_DONE/rotations`, { value: "done-new-new-new" });
      await call("POST", `${P}/environments/development/values/TOKEN_DONE/rotations/complete`, {});
    }
  }
  // The runner's seed Contract, pushed to a Project of its own.
  await call("POST", "/v1/organizations/acme/projects", { name: "Seed", slug: "seed", contractAuthority: "git" });
  await call("POST", "/v1/organizations/acme/projects/seed/contract/revisions", { contract: SEED_CONTRACT });
  // Fixed times, so the file holds whatever day the Go tests run: the
  // rotation window open, one preview expired.
  await db.query("UPDATE env_values SET rotation_deadline = '2099-06-01T00:00:00.000Z' WHERE rotation_deadline IS NOT NULL");
  // A rotation whose window has passed: its retiring version is no longer
  // returned (lazy expiry, ADR-0027 §4).
  await db.query("UPDATE env_values SET rotation_deadline = '2001-06-01T00:00:00.000Z' WHERE item_name = 'TOKEN_EXPIRED'");
  await db.query("UPDATE environments SET expires_at = '2001-01-01T00:00:00.000Z' WHERE name = 'development/pr-old'");

  // People: bob is a member with a Grant on the Project, carol is no
  // member, dave is a member without Grants, erin is a member with a Grant
  // on the development tier.
  const person = async (name: string, member: boolean) => {
    const id = newId("identity");
    await db.query("INSERT INTO identities (id, kind, name, created_at) VALUES ($1, 'human', $2, '2026-01-01T00:00:00.000Z')", [id, name]);
    if (member) await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, $2, 'member')", [ids.orgId, id]);
    tokens[name] = (await issueCredential(ctx.db, { identityId: id, kind: "cli" })).token;
    return id;
  };
  const bob = await person("bob", true);
  await person("carol", false);
  await person("dave", true);
  const erin = await person("erin", true);
  await call("POST", "/v1/organizations/acme/grants", {
    subjectIdentityId: bob,
    scope: { kind: "project", projectId: ids.projectId },
    actions: ["config.metadata.read", "config.value.read"],
  });
  await call("POST", "/v1/organizations/acme/grants", {
    subjectIdentityId: erin,
    scope: { kind: "environments", projectId: ids.projectId, selector: { kind: "tier", tier: "development" } },
    actions: ["config.metadata.read", "secret.reveal"],
  });
  const ci = await call("POST", "/v1/organizations/acme/identities", { name: "deploy", kind: "service" });
  tokens.ci = ci.credential;
  await call("POST", "/v1/organizations/acme/grants", {
    subjectIdentityId: ci.id,
    scope: { kind: "project", projectId: ids.projectId },
    actions: ["config.metadata.read", "config.value.read", "secret.reveal"],
  });
  const viewer = await call("POST", "/v1/organizations/acme/identities", { name: "viewer", kind: "service" });
  tokens.viewer = viewer.credential;
  await call("POST", "/v1/organizations/acme/grants", {
    subjectIdentityId: viewer.id,
    scope: { kind: "project", projectId: ids.projectId },
    actions: ["config.metadata.read"],
  });
  // A machine that may use Secrets but not reveal them.
  const runner = await call("POST", "/v1/organizations/acme/identities", { name: "runner", kind: "service" });
  tokens.runner = runner.credential;
  await call("POST", "/v1/organizations/acme/grants", {
    subjectIdentityId: runner.id,
    scope: { kind: "project", projectId: ids.projectId },
    actions: ["config.metadata.read", "secret.use"],
  });
  const agent = await call("POST", "/v1/organizations/acme/identities", { name: "helper", kind: "agent" });
  tokens.agent = (await issueCredential(ctx.db, { identityId: agent.id, kind: "agent-run" })).token;
  await call("POST", "/v1/organizations/acme/grants", {
    subjectIdentityId: agent.id,
    scope: { kind: "project", projectId: ids.projectId },
    actions: ["config.metadata.read"],
  });
  tokens.invalid = "vlt_cli_" + "x".repeat(40);
  await call("POST", "/v1/organizations/acme/requirements", {
    kind: "tailnet",
    target: { kind: "tier", tier: "production" },
    selector: { tailnet: "example.ts.net", tags: ["tag:prod"] },
  });

  // The incident freeze and the Security Controls, as rows: the routes
  // that set them need passkey approvals.
  const orgId = async (slug: string) => ((await db.query("SELECT id FROM organizations WHERE slug = $1", [slug])).rows[0] as { id: string }).id;
  await db.query(
    "INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', 'incident drill')",
    [newId("organizationFreeze"), await orgId("frozen"), alice],
  );
  const control = async (slug: string, name: string, mode: string) =>
    db.query("INSERT INTO security_controls (organization_id, control, mode, version, changed_by) VALUES ($1, $2, $3, 3, $4)", [await orgId(slug), name, mode, alice]);
  await control("guarded", "passkey-verification", "enforce");
  await control("reported", "passkey-verification", "report");
  await control("acme", "admin-step-up", "report");

  // Every plaintext, by version, for the G3 checks.
  const plaintexts: Record<string, string> = {};
  const rows = (await db.query(
    `SELECT v.id, v.value_id, v.payload, v.wrapped_dek, e.project_id, o.id AS org_id, o.wrapped_org_kek
     FROM value_versions v JOIN env_values ev ON ev.id = v.value_id JOIN environments e ON e.id = ev.environment_id
     JOIN projects p ON p.id = e.project_id JOIN organizations o ON o.id = p.organization_id`,
  )).rows as { id: string; value_id: string; payload: Envelope; wrapped_dek: Envelope; org_id: string; wrapped_org_kek: Envelope }[];
  for (const r of rows) {
    const orgKek = unwrapOrgKek(ctx.rootKek, r.wrapped_org_kek, r.org_id);
    plaintexts[r.id] = decryptValue(orgKek, r.org_id, r.value_id, r.id, { payload: r.payload, wrappedDek: r.wrapped_dek }).toString("utf8");
  }
  return { ctx, tokens, plaintexts, ids };
}

async function exportRows(db: AppCtx["db"]): Promise<Record<string, Row[]>> {
  const out: Record<string, Row[]> = {};
  for (const table of TABLES) {
    const res = await db.query(`SELECT * FROM "${table}" ORDER BY ${ORDER_BY[table]}`);
    out[table] = (res.rows as Row[]).map((r) => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, json(v)])));
  }
  return out;
}

/** Load a file's rows into a fresh database, as they were exported. */
async function loadRows(rows: Record<string, Row[]>): Promise<AppCtx["db"] & { close: () => Promise<void> }> {
  const db = await migratedTestDb();
  // Rows in the file's order; foreign keys are the source database's, so
  // the triggers that check them are not needed here.
  await db.query("SET session_replication_role = replica");
  for (const table of TABLES) {
    for (const row of rows[table] ?? []) {
      const cols = Object.keys(row);
      const values = cols.map((c) => {
        const v = row[c];
        return v !== null && typeof v === "object" && !Array.isArray(v) ? JSON.stringify(v) : v;
      });
      await db.query(
        `INSERT INTO "${table}" (${cols.map((c) => `"${c}"`).join(", ")}) VALUES (${cols.map((_, i) => `$${i + 1}`).join(", ")})`,
        values,
      );
    }
  }
  await db.query("SET session_replication_role = DEFAULT");
  return db;
}

/** Run the table against a database, recording each answer and what it wrote. */
async function record(ctx: AppCtx, tokens: Record<string, string>, cases: RequestCase[], ids: { orgId: string; projectId: string }): Promise<{ requests: Recorded[]; counters: Row[] }> {
  const app = buildApp(ctx);
  const out: Recorded[] = [];
  const last = async (sql: string) => Number(((await ctx.db.query(sql)).rows[0] as { n: string | number | null }).n ?? 0);
  for (const c of cases) {
    const before = await last("SELECT max(event_order) AS n FROM audit_events");
    const exposureBefore = new Set(
      ((await ctx.db.query("SELECT identity_id, version_id, environment_id, way FROM member_exposure")).rows as Row[]).map((r) => JSON.stringify(r)),
    );
    const headers: Record<string, string> = { "Content-Type": "application/json", "User-Agent": c.userAgent ?? CLI_AGENT };
    if (c.credential !== "none") headers.Authorization = `Bearer ${tokens[c.credential]}`;
    const path = c.path.replace("{orgId}", ids.orgId).replace("{projectId}", ids.projectId);
    const init: RequestInit = { method: c.method, headers };
    if (c.rawBody !== undefined) init.body = c.rawBody;
    else if ("body" in c) init.body = JSON.stringify(c.body);
    const res = await app.request(path, init);
    const requestId = res.headers.get("X-Request-Id") ?? "";
    const text = (await res.text()).replaceAll(requestId, REQUEST_ID);
    const kept: Record<string, string> = {};
    for (const h of ["Cache-Control", "Retry-After", "Content-Type", "Varlatch-Credential-Expires"]) {
      const v = res.headers.get(h);
      if (v !== null) kept[h] = v;
    }
    await accessCountsSettled();
    const audit = ((await ctx.db.query(
      `SELECT event_type, actor_identity_id, credential_id, organization_id, action, resource, decision, authz, tailnet, listener, request_id, metadata, client, schema_version
       FROM audit_events WHERE event_order > $1 ORDER BY event_order`,
      [before],
    )).rows as Row[]).map((r) => ({ ...r, request_id: r.request_id === requestId ? REQUEST_ID : r.request_id }));
    const exposure = ((await ctx.db.query(
      "SELECT organization_id, identity_id, version_id, item_name, environment_id, way FROM member_exposure ORDER BY identity_id, version_id, environment_id, way",
    )).rows as Row[]).filter((r) => {
      const { organization_id: _o, item_name: _i, ...key } = r;
      return !exposureBefore.has(JSON.stringify(key));
    });
    out.push({ ...c, expect: { status: res.status, headers: kept, body: text }, audit, exposure });
  }
  const counters = ((await ctx.db.query(
    "SELECT organization_id, control, config_version, operation, actor_identity_id, reason, count FROM security_control_counters ORDER BY organization_id, control, operation, actor_identity_id, reason",
  )).rows as Row[]).map((r) => ({ ...r, count: Number(r.count) }));
  return { requests: out, counters };
}

function readFixture(path: string): Fixture {
  return JSON.parse(readFileSync(path, "utf8")) as Fixture;
}

/** The recorded answers, with the ids of the database they came from. */
async function replay(f: Fixture): Promise<{ requests: Recorded[]; counters: Row[] }> {
  const db = await loadRows(f.rows);
  try {
    const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex") };
    const org = f.rows.organizations!.find((o) => o.slug === "acme")!;
    const project = f.rows.projects!.find((p) => p.organization_id === org.id && p.slug === "api")!;
    return await record(ctx, f.tokens, f.requests, { orgId: org.id as string, projectId: project.id as string });
  } finally {
    await db.close();
  }
}

/** The request definitions of a file, by id, without its answers. */
function definitions(cases: RequestCase[]): Map<string, RequestCase> {
  return new Map(cases.map((c) => [c.id, { id: c.id, name: c.name, method: c.method, path: c.path, credential: c.credential,
    ...("body" in c ? { body: c.body } : {}), ...(c.rawBody !== undefined ? { rawBody: c.rawBody } : {}), ...(c.userAgent !== undefined ? { userAgent: c.userAgent } : {}) }]));
}

/**
 * A committed file's requests must be requestTable()'s: a request added,
 * removed or changed here, and not regenerated, fails (the ids of the
 * file's own database fill the table).
 */
function expectCurrentTable(f: Fixture) {
  const org = f.rows.organizations!.find((o) => o.slug === "acme")!;
  const project = f.rows.projects!.find((p) => p.organization_id === org.id && p.slug === "api")!;
  const dev = f.rows.environments!.find((e) => e.project_id === project.id && e.name === "development")!;
  const want = definitions(requestTable({ devId: dev.id as string }));
  const have = definitions(f.requests);
  expect([...have.keys()].sort(), "the file's requests are not requestTable()'s: regenerate it").toEqual([...want.keys()].sort());
  for (const [id, def] of want) expect(have.get(id), `${id}: changed since the file was written; regenerate it`).toEqual(def);
}

function expectSameAnswers(f: Fixture, got: { requests: Recorded[]; counters: Row[] }) {
  // Exposure rows by key only: timestamps and the backfill differ.
  for (const [i, want] of f.requests.entries()) {
    const have = got.requests[i]!;
    expect({ name: want.name, ...have.expect }).toEqual({ name: want.name, ...want.expect });
    expect({ name: want.name, audit: have.audit }).toEqual({ name: want.name, audit: want.audit });
    expect({ name: want.name, exposure: have.exposure }).toEqual({ name: want.name, exposure: want.exposure });
  }
  expect(got.counters).toEqual(f.counters);
}

describe.skipIf(process.env.VARLATCH_WRITE_GO_VECTORS !== "1")("writing the fixtures", () => {
  it("builds the database, records the answers and writes both files", async () => {
    const { ctx, tokens, plaintexts, ids } = await build();
    try {
      const rows = await exportRows(ctx.db);
      const cases = requestTable(ids);
      for (const ref of ["v0.22.0", "v0.21.0"] as const) {
        const fileRows = structuredClone(rows);
        if (ref === "v0.21.0") await resealWith(ref, ctx.rootKek, fileRows, (version) => plaintexts[version.id as string]!);
        const draft: Fixture = {
          comment: "Written by services/varlatchd/test/go-values-fixture.test.ts from the TypeScript server's own answers; do not edit.",
          ref,
          rootKek: ctx.rootKek.toString("hex"),
          tokens,
          plaintexts,
          rows: fileRows,
          requests: cases.map((c) => ({ ...c, expect: { status: 0, headers: {}, body: "" }, audit: [], exposure: [] })),
          counters: [],
        };
        // The answers come from the file's own rows, loaded the way the
        // check below loads them.
        const recorded = await replay(draft);
        const fixture: Fixture = { ...draft, ...recorded };
        writeFileSync(new URL(FILES[ref], OUT_DIR), JSON.stringify(fixture, null, 2) + "\n");
      }
    } finally {
      await ctx.close();
    }
  }, 300_000);
});

describe("the fixtures are this server's answers", () => {
  for (const file of Object.values(FILES)) {
    it(file, async () => {
      const f = readFixture(new URL(file, OUT_DIR).pathname);
      expectCurrentTable(f);
      expectSameAnswers(f, await replay(f));
    }, 120_000);
  }
  const goSealed = process.env.VARLATCH_GO_SEALED_VALUES;
  it.skipIf(!goSealed)("values the Go server sealed open here with the same answers", async () => {
    if (!existsSync(goSealed!)) throw new Error(`${goSealed}: no such file`);
    const f = readFixture(goSealed!);
    expect(f.comment).toMatch(/Go/);
    expectCurrentTable(f);
    expectSameAnswers(f, await replay(f));
  }, 120_000);
});
