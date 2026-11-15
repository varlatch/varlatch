// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.1's parity fixture (ADR-0059 step 4, feature-parity decision 3),
 * on the parity kit (go-fixture-kit.ts): Organizations, Projects,
 * Environments, Contracts and values, built through this server's own /v1
 * API, and a table of requests with this server's answers. 4.1a records
 * the Organization operations (createOrganization, getOrganization,
 * renameOrganization), 4.1b the Contract operations (getActiveContract,
 * getContractRevision, pushContractRevision, activateContractRevision);
 * the later pull requests of 4.1 add theirs to the same file.
 * go/server/orgs's parity test replays it against varlatchd.
 *
 * The database: alice (the bootstrap Installation Admin) and Organizations
 * made through /v1: acme, frozen (an incident freeze), guarded
 * (passkey-verification at enforce), reported (at report) and deleting (a
 * deletion scheduled); bob, a member of acme; carol, a member of none; a
 * service identity of acme, which may read acme/api's Contract; an agent
 * of acme with an Agent Run credential; Projects in the Organizations,
 * their Contract revisions pushed and activated through /v1 (REVISIONS,
 * PUSHED). Rows the routes that set them need passkey approvals for (the
 * freeze, the controls, the deletion) are written directly. Two writes
 * run under an Idempotency-Key, so the rows hold claims this server
 * stored, which requests replay (the migration copies them, step 7).
 *
 * Two files (FILES): the rows as this code sealed them, and the same rows
 * sealed again by v0.21.0's code; the same requests, the same answers.
 *
 * Every run checks the committed file: its requests must be the table's,
 * and this server, on the file's rows, must give the recorded answers.
 * After a change, regenerate it and commit the result:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-core-fixture.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { newId } from "../src/db/ids.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { createHash } from "node:crypto";
import { canonicalJson } from "@varlatch/contract";
import { checkDigests, expectCurrentTable, expectSameAnswers, expectSameRows, exportRows, loadRows, record, resealWith, withIds, type Fixture, type RequestCase, type Row, type SideTable, type Table } from "./go-fixture-kit.js";
import type { Envelope } from "../src/crypto/aead.js";
import { decryptValue, unwrapOrgKek } from "../src/crypto/hierarchy.js";

// The unwrapped app: some requests are outside the OpenAPI document on
// purpose (bodies that are not JSON, extra members).
const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

/**
 * One file per release whose envelopes must open (G3): core-v0.22.0.json
 * as this code sealed the rows; core-v0.21.0.json the same rows and
 * requests with the canary, every Organization KEK and every value
 * version sealed again by v0.21.0's crypto code (resealWith; the tag must
 * be fetched to regenerate it).
 */
const FILES = {
  "v0.22.0": new URL("../../../go/server/paritytest/testdata/core-v0.22.0.json", import.meta.url),
  "v0.21.0": new URL("../../../go/server/paritytest/testdata/core-v0.21.0.json", import.meta.url),
} as const;
const FILE = FILES["v0.22.0"];

const TABLES: Table[] = [
  { name: "installation", orderBy: "id", random: ["kek_canary"] },
  { name: "identities", orderBy: "id" },
  { name: "user", orderBy: "id", random: ["id"] },
  { name: "auth_user_links", orderBy: "better_auth_user_id", random: ["better_auth_user_id"] },
  { name: "credentials", orderBy: "id", random: ["token_hash"] },
  { name: "organizations", orderBy: "id", random: ["wrapped_org_kek"] },
  { name: "org_memberships", orderBy: "organization_id, identity_id" },
  { name: "grants", orderBy: "id" },
  { name: "requirements", orderBy: "id" },
  { name: "security_controls", orderBy: "organization_id, control" },
  { name: "organization_freezes", orderBy: "id" },
  { name: "organization_deletions", orderBy: "id" },
  { name: "projects", orderBy: "id" },
  // A Contract that names an environment hashes its random ID.
  { name: "contract_revisions", orderBy: "id", random: ["content_hash"] },
  { name: "environments", orderBy: "id" },
  { name: "env_values", orderBy: "id" },
  { name: "capabilities", orderBy: "id" },
  { name: "value_versions", orderBy: "id", random: ["payload", "wrapped_dek"] },
  // An Idempotency-Key's digest is keyed by the build's random Root KEK.
  { name: "idempotency_keys", orderBy: "identity_id, endpoint, idempotency_key", random: ["body_hash"] },
];

const SIDE: SideTable[] = [
  { name: "organizations", key: ["id"], sortBy: ["slug"], volatile: ["created_at", "wrapped_org_kek"] },
  { name: "org_memberships", key: ["organization_id", "identity_id"], sortBy: ["organization_id", "identity_id"], volatile: ["created_at"] },
  { name: "projects", key: ["id"], sortBy: ["organization_id", "slug"], volatile: ["created_at"] },
  { name: "contract_revisions", key: ["id"], sortBy: ["project_id", "content_hash"], volatile: ["created_at"] },
  { name: "environments", key: ["id"], sortBy: ["project_id", "name", "deleted_at"], volatile: ["created_at", "deleted_at"] },
  { name: "env_values", key: ["id"], sortBy: ["environment_id", "item_name"], volatile: ["created_at", "deleted_at", "rotation_deadline", "rotation_started_at"] },
  { name: "capabilities", key: ["id"], sortBy: ["environment_id", "run_id"], volatile: ["revoked_at"] },
  { name: "value_versions", key: ["id"], sortBy: ["value_id", "previous_version_id"], volatile: ["payload", "wrapped_dek", "created_at"] },
  { name: "idempotency_keys", key: ["identity_id", "endpoint", "idempotency_key"], sortBy: ["identity_id", "endpoint", "idempotency_key"], volatile: ["created_at"] },
];

/** The CLI in assisted mode (ADR-0043 Decision 3): its requests are attributed so. */
const ASSISTED_AGENT = "varlatch-cli/0.22.0 (linux; x64; assisted)";

const ORG = "/v1/organizations";

/** The table of requests. */
function requestTable(): RequestCase[] {
  const create = (name: string, credential: string, body: unknown): Omit<RequestCase, "id"> => ({ name, method: "POST", path: ORG, credential, body });
  const get = (name: string, org: string, credential = "alice"): Omit<RequestCase, "id"> => ({ name, method: "GET", path: `${ORG}/${org}`, credential });
  const rename = (name: string, org: string, credential: string, body: unknown): Omit<RequestCase, "id"> => ({ name, method: "PATCH", path: `${ORG}/${org}`, credential, body });
  return withIds([
    // createOrganization.
    create("create", "alice", { name: "New Co", slug: "newco" }),
    create("create, the same slug again", "alice", { name: "Again", slug: "newco" }),
    create("create, an existing Organization's slug", "alice", { name: "X", slug: "acme" }),
    create("create, an invalid slug", "alice", { name: "X", slug: "Bad_Slug" }),
    create("create, a slug starting with a dash", "alice", { name: "X", slug: "-x" }),
    create("create, a slug of 64 characters", "alice", { name: "X", slug: "a".repeat(64) }),
    create("create, a slug of 63 characters", "alice", { name: "Long", slug: "b".repeat(63) }),
    create("create, a slug ending in a newline", "alice", { name: "X", slug: "acme2\n" }),
    create("create, no name", "alice", { slug: "x1" }),
    create("create, an empty name", "alice", { name: "", slug: "x2" }),
    create("create, a name of 201 characters", "alice", { name: "n".repeat(201), slug: "x3" }),
    create("create, a name of 200 characters beyond ASCII", "alice", { name: "é".repeat(198) + "𝄞", slug: "unicode" }),
    // zod counts code points: 200 astral characters are 400 UTF-16 units.
    create("create, a name of 200 emoji", "alice", { name: "😀".repeat(200), slug: "emoji" }),
    create("create, a name of 201 emoji", "alice", { name: "😀".repeat(201), slug: "emoji2" }),
    create("create, a name that is not a string", "alice", { name: 42, slug: "x4" }),
    create("create, a slug that is not a string", "alice", { name: "X", slug: null }),
    create("create, an empty object", "alice", {}),
    create("create, an array", "alice", ["newco"]),
    { name: "create, not JSON", method: "POST", path: ORG, credential: "alice", rawBody: "slug=x" },
    create("create, extra members", "alice", { name: "Extra", slug: "extra", id: "org_mine" }),
    create("create by a member", "bob", { name: "Bob's", slug: "bobs" }),
    create("create by a machine", "ci", { name: "Machine", slug: "machine" }),
    create("create by an agent run", "agent", { name: "Agent", slug: "agent" }),
    create("create without a credential", "none", { name: "None", slug: "none" }),
    // PostgreSQL refuses U+0000 in text: 500, nothing written. A lone
    // surrogate reaches the text column as U+FFFD. Sent as text: a JSON
    // round trip would rewrite them.
    { name: "create, U+0000 in the name", method: "POST", path: ORG, credential: "alice", rawBody: '{"name":"a\\u0000b","slug":"nul"}' },
    { name: "create, a duplicate slug and U+0000 in the name", method: "POST", path: ORG, credential: "alice", rawBody: '{"name":"a\\u0000b","slug":"acme"}' },
    { name: "create, a lone surrogate in the name", method: "POST", path: ORG, credential: "alice", rawBody: '{"name":"a\\ud800b","slug":"surrogate"}' },
    { ...create("create in assisted mode", "alice", { name: "Assisted", slug: "assisted" }), userAgent: ASSISTED_AGENT },
    create("create, a deleted Organization's slug", "alice", { name: "Again", slug: "gone" }),
    { ...create("create, the same slug twice at once", "alice", { name: "Twice", slug: "twice" }), concurrent: 2 },
    create("create with an invalid credential", "invalid", { name: "None", slug: "none" }),
    // getOrganization.
    get("get by slug", "acme"),
    get("get by id", "{orgId}"),
    get("get as a member", "acme", "bob"),
    get("get as an outsider", "acme", "carol"),
    get("get as its service identity", "acme", "ci"),
    get("get as its agent", "acme", "agent"),
    get("get an unknown Organization", "nope"),
    get("get a frozen Organization", "frozen"),
    get("get a frozen Organization as an outsider", "frozen", "carol"),
    get("get under passkey-verification enforce", "guarded"),
    get("get under passkey-verification report", "reported"),
    get("get an Organization being deleted", "deleting"),
    get("get the new Organization", "newco"),
    get("get, with a query", "acme?include=everything"),
    get("get, an encoded slug", "ac%6De"),
    get("get without a credential", "acme", "none"),
    get("get an Organization whose deletion completed", "gone"),
    get("get a deleted Organization by id", "{goneId}"),
    // renameOrganization.
    rename("rename", "acme", "alice", { name: "  Acme Robotics  " }),
    rename("rename, extra members", "acme", "alice", { name: "Acme", slug: "other" }),
    rename("rename, only spaces", "acme", "alice", { name: "   " }),
    rename("rename, 201 characters after trimming", "acme", "alice", { name: ` ${"x".repeat(201)} ` }),
    rename("rename, 200 characters after trimming", "acme", "alice", { name: ` ${"y".repeat(200)} ` }),
    rename("rename, a name that is not a string", "acme", "alice", { name: 42 }),
    rename("rename, null", "acme", "alice", { name: null }),
    rename("rename, no name", "acme", "alice", {}),
    { name: "rename, not JSON", method: "PATCH", path: `${ORG}/acme`, credential: "alice", rawBody: "{" },
    rename("rename as a member", "acme", "bob", { name: "By Bob" }),
    rename("rename as an outsider", "acme", "carol", { name: "By Carol" }),
    { name: "rename as an outsider, not JSON", method: "PATCH", path: `${ORG}/acme`, credential: "carol", rawBody: "{" },
    rename("rename as its service identity", "acme", "ci", { name: "By CI" }),
    rename("rename as its agent", "acme", "agent", { name: "By the agent" }),
    rename("rename a frozen Organization", "frozen", "alice", { name: "Thawed" }),
    rename("rename an Organization being deleted", "deleting", "alice", { name: "Kept" }),
    rename("rename under passkey-verification enforce", "guarded", "alice", { name: "Guarded" }),
    rename("rename under passkey-verification report", "reported", "alice", { name: "Reported Inc" }),
    rename("rename an unknown Organization", "nope", "alice", { name: "Nobody" }),
    rename("rename an Organization whose deletion completed", "gone", "alice", { name: "Back" }),
    { name: "rename, U+0000 in the name", method: "PATCH", path: `${ORG}/acme`, credential: "alice", rawBody: '{"name":"a\\u0000b"}' },
    { name: "rename, a lone surrogate in the name", method: "PATCH", path: `${ORG}/acme`, credential: "alice", rawBody: '{"name":"a\\ud800b"}' },
    { ...rename("rename in assisted mode", "acme", "alice", { name: "Acme Assisted" }), userAgent: ASSISTED_AGENT },
    rename("rename by id", "{orgId}", "alice", { name: "Acme by id" }),
    get("get after the renames", "acme"),
    create("create after the renames", "alice", { name: "Acme Robotics", slug: "acme-robotics" }),
    ...contractRequests(),
    ...projectRequests(),
    ...valueRequests(),
    ...checkRequests(),
    ...rotationRequests(),
  ]);
}

// ---- Contracts (step 4.1b)

const item = (name: string, extra: Record<string, unknown> = {}) => ({ name, required: { kind: "always" }, sensitive: false, type: "string", ...extra });
const doc = (items: unknown[], more: Record<string, unknown> = {}) => ({ schemaVersion: 1, items, ...more });

/**
 * The revisions build() pushes, each holding a marker item of its own
 * (its key here) that a request path names as {rev:KEY}.
 */
const REVISIONS = {
  // acme/api: API_V1 active, API_V2 pushed after it.
  API_V1: doc([
    item("API_URL", { type: "url", description: "Where the API listens" }),
    item("API_V1", { required: { kind: "never" } }),
    item("LOG_LEVEL", { type: "enum", enumValues: ["info", "debug"], defaultValue: "info" }),
  ]),
  API_V2: doc([
    item("API_URL", { type: "url", sensitive: true, required: { kind: "selector", selector: { kind: "tier", tier: "production" } } }),
    item("API_V2", { rotationHint: "Rotate in the console", rotationGraceSeconds: 3600 }),
    item("LOG_LEVEL", { type: "enum", enumValues: ["info", "debug", "trace"], defaultValue: "info" }),
    item("PORT", { type: "integer", example: "8080" }),
  ]),
  // acme/pinned: pinned to semantics version 2 and active; a version 3 one pushed.
  PINNED_V2: doc([item("PINNED_V2"), item("FLAG", { type: "boolean" })], { semanticsVersion: 2 }),
  PINNED_V3: doc([item("PINNED_V3"), item("FLAG", { type: "boolean", sensitive: true }), item("COUNT", { type: "integer" })], { semanticsVersion: 3 }),
  // acme/fresh: one revision, never activated.
  FRESH_V1: doc([item("FRESH_V1")]),
  // The guarded Organizations' Projects: one active, one pushed.
  FROZEN_V1: doc([item("FROZEN_V1")]),
  FROZEN_V2: doc([item("FROZEN_V2")]),
  GUARDED_V1: doc([item("GUARDED_V1")]),
  GUARDED_V2: doc([item("GUARDED_V2")]),
  REPORTED_V1: doc([item("REPORTED_V1")]),
  REPORTED_V2: doc([item("REPORTED_V2")]),
  DELETING_V1: doc([item("DELETING_V1")]),
  DELETING_V2: doc([item("DELETING_V2")]),
} as const;

/** Where build() pushes each revision, and whether it activates it. */
const PUSHED: [keyof typeof REVISIONS, string, string, boolean][] = [
  ["API_V1", "acme", "api", true],
  ["API_V2", "acme", "api", false],
  ["PINNED_V2", "acme", "pinned", true],
  ["PINNED_V3", "acme", "pinned", false],
  ["FRESH_V1", "acme", "fresh", false],
  ["FROZEN_V1", "frozen", "app", true],
  ["FROZEN_V2", "frozen", "app", false],
  ["GUARDED_V1", "guarded", "app", true],
  ["GUARDED_V2", "guarded", "app", false],
  ["REPORTED_V1", "reported", "app", true],
  ["REPORTED_V2", "reported", "app", false],
  ["DELETING_V1", "deleting", "app", true],
  ["DELETING_V2", "deleting", "app", false],
];

/** The Projects build() creates: Organization, slug, contract authority. */
const PROJECTS: [string, string, "git" | "managed"][] = [
  ["acme", "api", "managed"],
  ["acme", "empty", "git"],
  ["acme", "pinned", "git"],
  ["acme", "fresh", "managed"],
  ["frozen", "app", "git"],
  ["guarded", "app", "git"],
  ["reported", "app", "git"],
  ["deleting", "app", "git"],
  ["gone", "app", "git"],
];

/**
 * A request's placeholders, in its path and its body: {rev:KEY},
 * {project:SLUG}, {env:PROJECT/NAME}, {ver:PROJECT/ENVIRONMENT/ITEM} (the
 * value's current version) and {cursor:PROJECT/ITEM} (a search cursor after
 * that hit), acme's, as the file's rows hold them.
 */
function fillPath(rows: Record<string, Row[]>): (p: string) => string {
  const orgOf = (slug: string) => rows.organizations!.find((o) => o.slug === slug)!.id as string;
  return (p) =>
    p
      .replace("{orgId}", orgOf("acme"))
      .replace("{goneId}", orgOf("gone"))
      .replace(/\{project:([a-z]+)\}/g, (_m, slug: string) => rows.projects!.find((r) => r.organization_id === orgOf("acme") && r.slug === slug && r.deleted_at === null)!.id as string)
      .replace(/\{cursor:([a-z0-9-]+)\/([A-Z][A-Z0-9_]*)\}/g, (_m, slug: string, name: string) => {
        const project = rows.projects!.find((r) => r.organization_id === orgOf("acme") && r.slug === slug && r.deleted_at === null)!;
        return Buffer.from(JSON.stringify([slug, name, project.id]), "utf8").toString("base64url");
      })
      .replace(/\{ver:([a-z0-9-]+)\/([^}]+)\/([A-Z][A-Z0-9_]*)\}/g, (_m, slug: string, name: string, item: string) => {
        const project = rows.projects!.find((r) => r.organization_id === orgOf("acme") && r.slug === slug && r.deleted_at === null)!;
        const env = rows.environments!.find((e) => e.project_id === project.id && e.name === name && e.deleted_at === null)!;
        const value = rows.env_values!.find((v) => v.environment_id === env.id && v.item_name === item);
        if (!value?.current_version_id) throw new Error(`no current version of ${slug}/${name}/${item}`);
        return value.current_version_id as string;
      })
      .replace(/\{env:([a-z0-9-]+)\/([^}]+)\}/g, (_m, slug: string, name: string) => {
        const project = rows.projects!.find((r) => r.organization_id === orgOf("acme") && r.slug === slug && r.deleted_at === null)!;
        const env = rows.environments!.find((e) => e.project_id === project.id && e.name === name && e.deleted_at === null);
        if (!env) throw new Error(`no environment ${slug}/${name}`);
        return env.id as string;
      })
      .replace(/\{rev:([A-Z0-9_]+)\}/g, (_m, key: string) => {
        const rev = rows.contract_revisions!.find((r) => (r.contract as { items: { name: string }[] }).items.some((i) => i.name === key));
        if (!rev) throw new Error(`no revision holds ${key}`);
        return rev.id as string;
      });
}

function contractRequests(): Omit<RequestCase, "id">[] {
  const P = (project: string, org = "acme") => `${ORG}/${org}/projects/${project}`;
  const active = (name: string, project: string, credential = "alice", org = "acme"): Omit<RequestCase, "id"> => ({ name, method: "GET", path: `${P(project, org)}/contract`, credential });
  const revision = (name: string, project: string, rev: string, credential = "alice", org = "acme"): Omit<RequestCase, "id"> => ({
    name, method: "GET", path: `${P(project, org)}/contract/revisions/${rev}`, credential,
  });
  const push = (name: string, project: string, body: unknown, credential = "alice", org = "acme"): Omit<RequestCase, "id"> => ({
    name, method: "POST", path: `${P(project, org)}/contract/revisions`, credential, body,
  });
  const pushRaw = (name: string, project: string, rawBody: string): Omit<RequestCase, "id"> => ({ name, method: "POST", path: `${P(project)}/contract/revisions`, credential: "alice", rawBody });
  const activate = (name: string, project: string, rev: string, credential = "alice", org = "acme"): Omit<RequestCase, "id"> => ({
    name, method: "POST", path: `${P(project, org)}/contract/revisions/${rev}/activate`, credential,
  });
  const NEW = doc([item("NEW_ITEM", { description: "Pushed by a request" })]);
  // API_V1 again: its items and members in another order, a duplicate enum
  // value. The same canonical form, so the same revision.
  const API_V1_SHUFFLED = {
    items: [
      { type: "enum", enumValues: ["debug", "info", "debug"], defaultValue: "info", sensitive: false, required: { kind: "always" }, name: "LOG_LEVEL" },
      item("API_V1", { required: { kind: "never" } }),
      item("API_URL", { type: "url", description: "Where the API listens" }),
    ],
    schemaVersion: 1,
  };
  return [
    // getActiveContract.
    active("contract", "api"),
    active("contract, none active", "empty"),
    active("contract, a pinned semantics version", "pinned"),
    active("contract, the Project by id", "{project:api}"),
    active("contract, the Organization by id", "api", "alice", "{orgId}"),
    active("contract, as a member", "api", "bob"),
    active("contract, as an outsider", "api", "carol"),
    active("contract, as its service identity with contract.read", "api", "ci"),
    active("contract, as its service identity elsewhere", "pinned", "ci"),
    active("contract, as its agent", "api", "agent"),
    active("contract, without a credential", "api", "none"),
    active("contract, an unknown Project", "nope"),
    active("contract, an unknown Project as an outsider", "nope", "carol"),
    active("contract, an unknown Organization", "api", "alice", "nope"),
    active("contract, a frozen Organization", "app", "alice", "frozen"),
    active("contract, under passkey-verification enforce", "app", "alice", "guarded"),
    active("contract, under passkey-verification report", "app", "alice", "reported"),
    active("contract, an Organization being deleted", "app", "alice", "deleting"),
    active("contract, an Organization whose deletion completed", "app", "alice", "gone"),
    // getContractRevision.
    revision("revision, the active one", "api", "{rev:API_V1}"),
    revision("revision, not active", "api", "{rev:API_V2}"),
    revision("revision, semantics version 3 pinned", "pinned", "{rev:PINNED_V3}"),
    revision("revision, unknown", "api", "crev_nope"),
    revision("revision, another Project's", "empty", "{rev:API_V1}"),
    revision("revision, an encoded id", "api", "%7Brev%7D"),
    revision("revision, as a member", "api", "{rev:API_V2}", "bob"),
    revision("revision, as an outsider", "api", "{rev:API_V2}", "carol"),
    revision("revision, as its agent", "api", "{rev:API_V2}", "agent"),
    revision("revision, under passkey-verification enforce", "app", "{rev:GUARDED_V2}", "alice", "guarded"),
    // pushContractRevision.
    push("push", "api", { contract: NEW }),
    push("push, the same Contract again", "api", { contract: NEW }),
    push("push, the active Contract in another order", "api", { contract: API_V1_SHUFFLED }),
    push("push, with provenance", "api", { contract: doc([item("PROVENANCE")]), provenance: { commit: "4f2a9c1", source: "ci", "😀": "é" } }),
    push("push, provenance not an object", "api", { contract: NEW, provenance: "main" }),
    push("push, provenance an array", "api", { contract: NEW, provenance: ["main"] }),
    push("push, provenance values not strings", "api", { contract: NEW, provenance: { a: 1, b: "x", c: null, d: { e: "f" } } }),
    push("push, provenance null", "api", { contract: NEW, provenance: null }),
    // JSON.parse makes __proto__ an own member; zod's record skips it
    // (neither checked nor stored), its object strips it. Sent as text.
    pushRaw("push, provenance with only __proto__", "api", '{"contract":{"schemaVersion":1,"items":[{"name":"PROTO_A","required":{"kind":"always"},"sensitive":false,"type":"string"}]},"provenance":{"__proto__":1}}'),
    pushRaw("push, provenance with __proto__ and a member", "api", '{"contract":{"schemaVersion":1,"items":[{"name":"PROTO_B","required":{"kind":"always"},"sensitive":false,"type":"string"}]},"provenance":{"__proto__":"x","source":"ci"}}'),
    pushRaw("push, provenance with __proto__ and a member that is not a string", "api", '{"contract":{"schemaVersion":1,"items":[]},"provenance":{"__proto__":"x","a":1}}'),
    pushRaw("push, __proto__ in the body", "api", '{"contract":{"schemaVersion":1,"items":[{"name":"PROTO_C","required":{"kind":"always"},"sensitive":false,"type":"string"}]},"__proto__":{"provenance":1}}'),
    pushRaw("push, the contract only under __proto__", "api", '{"__proto__":{"contract":{"schemaVersion":1,"items":[]}}}'),
    pushRaw("push, __proto__ in the Contract", "api", '{"contract":{"schemaVersion":1,"items":[],"__proto__":1}}'),
    push("push, extra members", "api", { contract: doc([item("EXTRA")]), extra: true }),
    push("push, an invalid Contract", "api", { contract: { schemaVersion: 2, items: [{ name: "lower case", type: "text" }], other: 1 } }),
    push("push, a reserved name", "api", { contract: doc([item("PATH")]) }),
    push("push, no contract member", "api", {}),
    push("push, contract null", "api", { contract: null }),
    push("push, a body that is an array", "api", [{ contract: NEW }]),
    push("push, a body that is a string", "api", "contract"),
    pushRaw("push, not JSON", "api", "{"),
    push("push, an integer at the active version 2", "pinned", { contract: doc([item("PINNED_V2"), item("COUNT", { type: "integer" })]) }),
    push("push, unpinned at the active version 2", "pinned", { contract: doc([item("UNPINNED")]) }),
    push("push, pinned to version 1", "pinned", { contract: doc([item("ONE")], { semanticsVersion: 1 }) }),
    push("push, an unsupported semantics version", "pinned", { contract: doc([item("FOUR")], { semanticsVersion: 4 }) }),
    push("push, an integer where nothing is active", "empty", { contract: doc([item("COUNT", { type: "integer" })]) }),
    push("push, a Contract with no items", "empty", { contract: doc([]) }),
    pushRaw("push, U+0000 in a description", "api", '{"contract":{"schemaVersion":1,"items":[{"name":"NUL","required":{"kind":"always"},"sensitive":false,"type":"string","description":"a\\u0000b"}]}}'),
    pushRaw("push, a lone surrogate in a description", "api", '{"contract":{"schemaVersion":1,"items":[{"name":"LONE","required":{"kind":"always"},"sensitive":false,"type":"string","description":"a\\ud800b"}]}}'),
    pushRaw("push, U+0000 in provenance", "api", '{"contract":{"schemaVersion":1,"items":[]},"provenance":{"commit":"a\\u0000b"}}'),
    pushRaw("push, a lone surrogate in an enum value", "api", '{"contract":{"schemaVersion":1,"items":[{"name":"E","required":{"kind":"always"},"sensitive":false,"type":"enum","enumValues":["\\udc00","a"]}]}}'),
    push("push as a member", "api", { contract: doc([item("BY_BOB")]) }, "bob"),
    push("push as an outsider", "api", { contract: doc([item("BY_CAROL")]) }, "carol"),
    push("push as its service identity with contract.read", "api", { contract: doc([item("BY_CI")]) }, "ci"),
    push("push as its agent", "api", { contract: doc([item("BY_AGENT")]) }, "agent"),
    push("push without a credential", "api", { contract: doc([item("BY_NONE")]) }, "none"),
    push("push as an outsider, an invalid Contract", "api", { contract: null }, "carol"),
    push("push to an unknown Project", "nope", { contract: NEW }),
    push("push to a frozen Organization", "app", { contract: doc([item("FROZEN_NEW")]) }, "alice", "frozen"),
    push("push under passkey-verification enforce", "app", { contract: doc([item("GUARDED_NEW")]) }, "alice", "guarded"),
    push("push under passkey-verification enforce, an invalid Contract", "app", { contract: null }, "alice", "guarded"),
    push("push under passkey-verification report", "app", { contract: doc([item("REPORTED_NEW")]) }, "alice", "reported"),
    push("push to an Organization being deleted", "app", { contract: doc([item("DELETING_NEW")]) }, "alice", "deleting"),
    { ...push("push in assisted mode", "api", { contract: doc([item("ASSISTED")]) }), userAgent: ASSISTED_AGENT },
    { ...push("push, the same new Contract twice at once", "api", { contract: doc([item("TWICE")]) }), concurrent: 2 },
    // activateContractRevision.
    activate("activate, the first revision of a Project", "fresh", "{rev:FRESH_V1}"),
    activate("activate", "api", "{rev:API_V2}"),
    activate("activate, the active revision again", "api", "{rev:API_V2}"),
    activate("activate, back to the earlier one", "api", "{rev:API_V1}"),
    activate("activate, a later semantics version", "pinned", "{rev:PINNED_V3}"),
    activate("activate, unknown", "api", "crev_nope"),
    activate("activate, another Project's", "empty", "{rev:API_V1}"),
    activate("activate as a member", "api", "{rev:API_V2}", "bob"),
    activate("activate as an outsider", "api", "{rev:API_V2}", "carol"),
    activate("activate as its service identity with contract.read", "api", "{rev:API_V2}", "ci"),
    activate("activate as its agent", "api", "{rev:API_V2}", "agent"),
    activate("activate in a frozen Organization", "app", "{rev:FROZEN_V2}", "alice", "frozen"),
    activate("activate under passkey-verification enforce", "app", "{rev:GUARDED_V2}", "alice", "guarded"),
    activate("activate under passkey-verification enforce, unknown", "app", "crev_nope", "alice", "guarded"),
    activate("activate under passkey-verification report", "app", "{rev:REPORTED_V2}", "alice", "reported"),
    activate("activate in an Organization being deleted", "app", "{rev:DELETING_V2}", "alice", "deleting"),
    activate("activate in an unknown Project", "nope", "{rev:API_V2}"),
    { ...activate("activate in assisted mode", "api", "{rev:API_V2}"), userAgent: ASSISTED_AGENT },
    // Each diffs against what it replaces: one API_V2 to API_V1, the other API_V1 to itself.
    { ...activate("activate, twice at once", "api", "{rev:API_V1}"), concurrent: 2 },
    active("contract, after the activations", "api"),
    active("contract, the first activation", "fresh"),
  ];
}

// ---- Projects and environments, and the installation reads (step 4.1c)

type Call = (method: string, path: string, body?: unknown, headers?: Record<string, string>) => Promise<any>;

/**
 * The environments build() makes through /v1, and what only rows can say:
 * acme/api's development, staging and production roots, development/alice
 * (personal), development/pr-1 (a preview that expires in 2099) and
 * development/old (one that expired in 2020); a tailnet Requirement on the
 * production tier; acme/refs, whose active Contract names its development
 * root in a requiredness selector, and whose staging root holds a value
 * and two Capabilities (one revoked);
 * acme/oldp, a deleted Project; and a development root in each guarded
 * Organization's app.
 */
async function buildEnvironments(db: AppCtx["db"], call: Call, alice: string) {
  const P = (org: string, project: string) => `${ORG}/${org}/projects/${project}/environments`;
  const ids: Record<string, string> = {};
  for (const [name, tier] of [["development", "development"], ["staging", "staging"], ["production", "production"]] as const) {
    ids[name] = (await call("POST", P("acme", "api"), { name, tier })).id;
  }
  await call("POST", P("acme", "api"), { name: "development/alice", parentEnvironmentId: ids.development });
  await call("POST", P("acme", "api"), { name: "development/pr-1", parentEnvironmentId: "development", kind: "preview", expiresAt: "2099-01-01T00:00:00.000Z" });
  await call("POST", P("acme", "api"), { name: "development/old", parentEnvironmentId: "development", kind: "preview", expiresAt: "2020-01-01T00:00:00Z" });
  for (const org of ["frozen", "guarded", "reported", "deleting"]) {
    await call("POST", P(org, "app"), { name: "development", tier: "development" });
    await call("POST", P(org, "app"), { name: "development/pr-1", parentEnvironmentId: "development", kind: "preview" });
  }
  await call("POST", `${ORG}/acme/projects`, { name: "Refs", slug: "refs", contractAuthority: "git" });
  const refsDev = (await call("POST", P("acme", "refs"), { name: "development", tier: "development" })).id;
  const refsStaging = (await call("POST", P("acme", "refs"), { name: "staging", tier: "staging" })).id;
  const refs = await call("POST", `${ORG}/acme/projects/refs/contract/revisions`, {
    contract: doc([
      item("REFERENCED", { required: { kind: "selector", selector: { kind: "environments", environmentIds: [refsDev] } } }),
      item("ALSO_REFERENCED", { required: { kind: "selector", selector: { kind: "environments", environmentIds: [refsDev, "envz_other"] } } }),
    ]),
  });
  await call("POST", `${ORG}/acme/projects/refs/contract/revisions/${refs.id}/activate`);
  await call("POST", `${ORG}/acme/projects`, { name: "Old", slug: "oldp", contractAuthority: "git" });
  await db.query("UPDATE projects SET deleted_at = '2026-03-03T00:00:00.000Z' WHERE slug = 'oldp'");
  await call("POST", `${ORG}/acme/requirements`, {
    kind: "tailnet",
    target: { kind: "tier", tier: "production" },
    selector: { tailnet: "example.ts.net", tags: ["tag:prod"] },
  });
  // A value and two Capabilities (one revoked already) on refs/staging, as
  // rows (their routes are later slices'): its removal soft-deletes the
  // value and revokes the live Capability.
  const refsProject = (await db.query("SELECT id, organization_id FROM projects WHERE slug = 'refs'")).rows[0] as { id: string; organization_id: string };
  await db.query("INSERT INTO env_values (id, environment_id, item_name) VALUES ($1, $2, 'API_URL')", [newId("value"), refsStaging]);
  for (const [run, revoked] of [["run-live", null], ["run-revoked", "2026-03-04T00:00:00.000Z"]] as const) {
    await db.query(
      `INSERT INTO capabilities (id, organization_id, broker_identity_id, agent_identity_id, project_id, environment_id, items, destinations, secret_hash, run_id, expires_at, revoked_at, created_by)
       VALUES ($1, $2, $3, $3, $4, $5, ARRAY['API_URL'], ARRAY[]::text[], 'sha256:00', $6, '2099-01-01T00:00:00.000Z', $7, $3)`,
      [newId("capability"), refsProject.organization_id, alice, refsProject.id, refsStaging, run, revoked],
    );
  }
}

function projectRequests(): Omit<RequestCase, "id">[] {
  const P = (org = "acme") => `${ORG}/${org}/projects`;
  const list = (name: string, credential = "alice", org = "acme"): Omit<RequestCase, "id"> => ({ name, method: "GET", path: P(org), credential });
  const create = (name: string, body: unknown, credential = "alice", org = "acme"): Omit<RequestCase, "id"> => ({ name, method: "POST", path: P(org), credential, body });
  const createRaw = (name: string, rawBody: string): Omit<RequestCase, "id"> => ({ name, method: "POST", path: P(), credential: "alice", rawBody });
  const get = (name: string, project: string, credential = "alice", org = "acme"): Omit<RequestCase, "id"> => ({ name, method: "GET", path: `${P(org)}/${project}`, credential });
  const rename = (name: string, project: string, body: unknown, credential = "alice", org = "acme"): Omit<RequestCase, "id"> => ({
    name, method: "PATCH", path: `${P(org)}/${project}`, credential, body,
  });
  const renameRaw = (name: string, rawBody: string): Omit<RequestCase, "id"> => ({ name, method: "PATCH", path: `${P()}/api`, credential: "alice", rawBody });
  const E = (project = "api", org = "acme") => `${P(org)}/${project}/environments`;
  const envs = (name: string, project = "api", credential = "alice", org = "acme"): Omit<RequestCase, "id"> => ({ name, method: "GET", path: E(project, org), credential });
  const newEnv = (name: string, body: unknown, credential = "alice", project = "api", org = "acme"): Omit<RequestCase, "id"> => ({
    name, method: "POST", path: E(project, org), credential, body,
  });
  const env = (name: string, environment: string, credential = "alice", project = "api", org = "acme"): Omit<RequestCase, "id"> => ({
    name, method: "GET", path: `${E(project, org)}/${environment}`, credential,
  });
  const del = (name: string, environment: string, credential = "alice", project = "api", org = "acme"): Omit<RequestCase, "id"> => ({
    name, method: "DELETE", path: `${E(project, org)}/${environment}`, credential,
  });
  const install = (name: string, what: "release" | "backups", credential = "alice"): Omit<RequestCase, "id"> => ({
    name, method: "GET", path: `/v1/installation/${what}`, credential,
  });
  return [
    // listProjects.
    list("projects"),
    list("projects, the Organization by id", "alice", "{orgId}"),
    list("projects as a member", "bob"),
    list("projects as an outsider", "carol"),
    list("projects as its service identity", "ci"),
    list("projects as its agent", "agent"),
    list("projects without a credential", "none"),
    list("projects of an unknown Organization", "alice", "nope"),
    list("projects of a frozen Organization", "alice", "frozen"),
    list("projects under passkey-verification enforce", "alice", "guarded"),
    list("projects under passkey-verification report", "alice", "reported"),
    list("projects of an Organization being deleted", "alice", "deleting"),
    list("projects of an Organization whose deletion completed", "alice", "gone"),
    // createProject.
    create("create a Project", { name: "Web", slug: "web", contractAuthority: "managed" }),
    create("create a Project, the same slug again", { name: "Web again", slug: "web", contractAuthority: "git" }),
    create("create a Project, an invalid slug", { name: "X", slug: "Bad_Slug", contractAuthority: "git" }),
    create("create a Project, a slug of 64 characters", { name: "X", slug: "p".repeat(64), contractAuthority: "git" }),
    create("create a Project, a slug of 63 characters", { name: "Long", slug: "q".repeat(63), contractAuthority: "git" }),
    create("create a Project, a slug ending in a newline", { name: "X", slug: "web2\n", contractAuthority: "git" }),
    create("create a Project, an empty name", { name: "", slug: "x1", contractAuthority: "git" }),
    create("create a Project, a name of 201 characters", { name: "n".repeat(201), slug: "x2", contractAuthority: "git" }),
    create("create a Project, a name of 200 emoji", { name: "😀".repeat(200), slug: "emoji", contractAuthority: "git" }),
    create("create a Project, no contract authority", { name: "X", slug: "x3" }),
    create("create a Project, an unknown contract authority", { name: "X", slug: "x4", contractAuthority: "svn" }),
    create("create a Project, every member wrong", { name: 1, slug: null, contractAuthority: true }),
    create("create a Project, an array", [{ name: "X", slug: "x5", contractAuthority: "git" }]),
    createRaw("create a Project, not JSON", "{"),
    create("create a Project, extra members", { name: "Extra", slug: "extra", contractAuthority: "git", id: "prj_mine", organizationId: "org_other" }),
    create("create a Project as a member", { name: "Bob's", slug: "bobs", contractAuthority: "git" }, "bob"),
    create("create a Project as an outsider", { name: "Carol's", slug: "carols", contractAuthority: "git" }, "carol"),
    create("create a Project as an outsider, an invalid body", {}, "carol"),
    create("create a Project as its service identity", { name: "CI", slug: "ci", contractAuthority: "git" }, "ci"),
    create("create a Project as its agent", { name: "Agent", slug: "agent", contractAuthority: "git" }, "agent"),
    create("create a Project without a credential", { name: "None", slug: "none", contractAuthority: "git" }, "none"),
    create("create a Project in a frozen Organization", { name: "X", slug: "x6", contractAuthority: "git" }, "alice", "frozen"),
    create("create a Project under passkey-verification enforce", { name: "X", slug: "x7", contractAuthority: "git" }, "alice", "guarded"),
    create("create a Project under passkey-verification report", { name: "Reported", slug: "reported", contractAuthority: "git" }, "alice", "reported"),
    create("create a Project in an Organization being deleted", { name: "X", slug: "x8", contractAuthority: "git" }, "alice", "deleting"),
    create("create a Project in an unknown Organization", { name: "X", slug: "x9", contractAuthority: "git" }, "alice", "nope"),
    createRaw("create a Project, U+0000 in the name", '{"name":"a\\u0000b","slug":"nul","contractAuthority":"git"}'),
    createRaw("create a Project, a lone surrogate in the name", '{"name":"a\\ud800b","slug":"lone","contractAuthority":"git"}'),
    { ...create("create a Project in assisted mode", { name: "Assisted", slug: "assisted", contractAuthority: "git" }), userAgent: ASSISTED_AGENT },
    { ...create("create a Project, the same slug twice at once", { name: "Twice", slug: "twice", contractAuthority: "git" }), concurrent: 2 },
    // getProject.
    get("project", "api"),
    get("project by id", "{project:api}"),
    get("project, an encoded slug", "ap%69"),
    get("project, a deleted one", "oldp"),
    get("project, unknown", "nope"),
    get("project as a member", "api", "bob"),
    get("project as an outsider", "api", "carol"),
    get("project as its service identity", "api", "ci"),
    get("project as its agent", "api", "agent"),
    get("project in a frozen Organization", "app", "alice", "frozen"),
    get("project under passkey-verification enforce", "app", "alice", "guarded"),
    get("project under passkey-verification report", "app", "alice", "reported"),
    get("project in an Organization being deleted", "app", "alice", "deleting"),
    get("project, the new one", "web"),
    // renameProject.
    rename("rename a Project", "api", { name: "API Gateway" }),
    rename("rename a Project, extra members", "api", { name: "API", slug: "other" }),
    rename("rename a Project, 200 characters", "web", { name: "w".repeat(200) }),
    rename("rename a Project, 201 characters", "web", { name: "w".repeat(201) }),
    rename("rename a Project, 200 emoji", "web", { name: "😀".repeat(200) }),
    rename("rename a Project, 100 emoji", "web", { name: "😀".repeat(100) }),
    rename("rename a Project, empty", "api", { name: "" }),
    rename("rename a Project, only spaces", "api", { name: "   " }),
    rename("rename a Project, not a string", "api", { name: 7 }),
    rename("rename a Project, no name", "api", {}),
    renameRaw("rename a Project, not JSON", "{"),
    renameRaw("rename a Project, U+0000 in the name", '{"name":"a\\u0000b"}'),
    renameRaw("rename a Project, a lone surrogate in the name", '{"name":"a\\ud800b"}'),
    rename("rename a Project as a member", "api", { name: "By Bob" }, "bob"),
    rename("rename a Project as an outsider", "api", { name: "By Carol" }, "carol"),
    rename("rename a Project as its service identity", "api", { name: "By CI" }, "ci"),
    rename("rename a Project as its agent", "api", { name: "By the agent" }, "agent"),
    rename("rename a Project, unknown", "nope", { name: "Nobody" }),
    rename("rename a Project, a deleted one", "oldp", { name: "Back" }),
    rename("rename a Project in a frozen Organization", "app", { name: "Thawed" }, "alice", "frozen"),
    rename("rename a Project under passkey-verification enforce", "app", { name: "Guarded" }, "alice", "guarded"),
    rename("rename a Project under passkey-verification report", "app", { name: "Reported app" }, "alice", "reported"),
    rename("rename a Project in an Organization being deleted", "app", { name: "Kept" }, "alice", "deleting"),
    rename("rename a Project by id", "{project:api}", { name: "API by id" }),
    { ...rename("rename a Project in assisted mode", "api", { name: "API assisted" }), userAgent: ASSISTED_AGENT },
    { ...rename("rename a Project twice at once", "refs", { name: "Refs renamed" }), concurrent: 2 },
    get("project after the renames", "api"),
    list("projects after the changes"),
    // listEnvironments.
    envs("environments"),
    envs("environments as a member", "api", "bob"),
    envs("environments as an outsider", "api", "carol"),
    envs("environments as its service identity", "api", "ci"),
    envs("environments as its agent", "api", "agent"),
    envs("environments of a Project with none", "web"),
    envs("environments of an unknown Project", "nope"),
    envs("environments of a deleted Project", "oldp"),
    envs("environments in a frozen Organization", "app", "alice", "frozen"),
    envs("environments under passkey-verification enforce", "app", "alice", "guarded"),
    envs("environments under passkey-verification report", "app", "alice", "reported"),
    // createEnvironment: roots.
    newEnv("create a root", { name: "qa", tier: "staging" }),
    newEnv("create a root, no tier", { name: "qa2" }),
    newEnv("create a root, personal", { name: "qa3", tier: "staging", kind: "personal" }),
    newEnv("create a root, shared named", { name: "qa4", tier: "staging", kind: "shared" }),
    newEnv("create a root, an invalid name", { name: "Bad Name", tier: "staging" }),
    newEnv("create a root, a name with a slash", { name: "a/b", tier: "staging" }),
    newEnv("create a root, a name of 64 characters", { name: "e".repeat(64), tier: "staging" }),
    newEnv("create a root, a name that exists", { name: "development", tier: "development" }),
    newEnv("create a root, an unknown tier", { name: "qa5", tier: "prod" }),
    newEnv("create a root, expiring", { name: "qa6", tier: "staging", expiresAt: "2099-01-01T00:00:00Z" }),
    newEnv("create a root, an empty parent", { name: "qa7", tier: "development", parentEnvironmentId: "" }),
    newEnv("create a root, every member wrong", { name: "", tier: 1, kind: "temporary", parentEnvironmentId: 2, expiresAt: "tomorrow" }),
    newEnv("create a root, no name", { tier: "staging" }),
    newEnv("create a root, null members", { name: "qa8", tier: null }),
    newEnv("create an environment, an array", [{ name: "qa9", tier: "staging" }]),
    { name: "create an environment, not JSON", method: "POST", path: E(), credential: "alice", rawBody: "{" },
    newEnv("create a root, extra members", { name: "qa10", tier: "staging", ownerIdentityId: "idn_other", id: "env_mine" }),
    // createEnvironment: derived.
    newEnv("create a derived environment", { name: "development/bob", parentEnvironmentId: "development" }),
    newEnv("create a preview", { name: "staging/pr-2", parentEnvironmentId: "staging", kind: "preview", expiresAt: "2099-06-30T12:34:56.1234567Z" }),
    newEnv("create a preview, a fraction rounded up", { name: "staging/pr-3", parentEnvironmentId: "staging", kind: "preview", expiresAt: "2099-06-30T12:34:56.9999996Z" }),
    newEnv("create a preview, half a microsecond", { name: "staging/pr-4", parentEnvironmentId: "staging", kind: "preview", expiresAt: "2099-06-30T12:34:56.0000005Z" }),
    newEnv("create a preview, a fraction of 128 digits", { name: "staging/pr-12", parentEnvironmentId: "staging", kind: "preview", expiresAt: `2099-06-30T12:34:56.${"9".repeat(128)}Z` }),
    newEnv("create a preview, a fraction of 129 digits", { name: "staging/pr-13", parentEnvironmentId: "staging", kind: "preview", expiresAt: `2099-06-30T12:34:56.${"9".repeat(129)}Z` }),
    newEnv("create a preview, a fraction of 200 digits, under report", { name: "development/pr-14", parentEnvironmentId: "development", kind: "preview", expiresAt: `2099-01-01T00:00:00.${"9".repeat(200)}Z` }, "alice", "app", "reported"),
    newEnv("create a preview, a leap day", { name: "staging/pr-5", parentEnvironmentId: "staging", kind: "preview", expiresAt: "2096-02-29T00:00:00Z" }),
    newEnv("create a preview, not a leap day", { name: "staging/pr-6", parentEnvironmentId: "staging", kind: "preview", expiresAt: "2097-02-29T00:00:00Z" }),
    newEnv("create a preview, year 0", { name: "staging/pr-7", parentEnvironmentId: "staging", kind: "preview", expiresAt: "0000-01-01T00:00:00Z" }),
    newEnv("create a preview, a date only", { name: "staging/pr-8", parentEnvironmentId: "staging", kind: "preview", expiresAt: "2099-01-01" }),
    newEnv("create a preview, an offset", { name: "staging/pr-9", parentEnvironmentId: "staging", kind: "preview", expiresAt: "2099-01-01T00:00:00+02:00" }),
    newEnv("create a preview, no seconds", { name: "staging/pr-10", parentEnvironmentId: "staging", kind: "preview", expiresAt: "2099-01-01T00:00Z" }),
    newEnv("create a preview, a number", { name: "staging/pr-11", parentEnvironmentId: "staging", kind: "preview", expiresAt: 4070908800000 }),
    newEnv("create a preview of production", { name: "production/pr-1", parentEnvironmentId: "production", kind: "preview" }),
    newEnv("create a personal environment of production", { name: "production/alice", parentEnvironmentId: "production" }),
    newEnv("create a derived environment, shared", { name: "development/shared", parentEnvironmentId: "development", kind: "shared" }),
    newEnv("create a derived environment, another tier", { name: "development/x", parentEnvironmentId: "development", tier: "staging" }),
    newEnv("create a derived environment, its own tier named", { name: "development/y", parentEnvironmentId: "development", tier: "development" }),
    newEnv("create a derived environment of a derived one", { name: "development/alice/z", parentEnvironmentId: "development/alice" }),
    newEnv("create a derived environment, another parent's name", { name: "staging/z", parentEnvironmentId: "development" }),
    newEnv("create a derived environment, no suffix", { name: "development/", parentEnvironmentId: "development" }),
    newEnv("create a derived environment, an unknown parent", { name: "nope/z", parentEnvironmentId: "nope" }),
    newEnv("create a derived environment, expiring personal", { name: "development/exp", parentEnvironmentId: "development", expiresAt: "2099-01-01T00:00:00Z" }),
    newEnv("create a derived environment, the name exists", { name: "development/alice", parentEnvironmentId: "development" }),
    // createEnvironment: who and where.
    newEnv("create a root as a member", { name: "bobs", tier: "development" }, "bob"),
    newEnv("create a derived environment as a member", { name: "development/bob2", parentEnvironmentId: "development" }, "bob"),
    newEnv("create a derived environment of production as a member", { name: "production/pr-2", parentEnvironmentId: "production", kind: "preview" }, "bob"),
    newEnv("create an environment as an outsider", { name: "carols", tier: "development" }, "carol"),
    newEnv("create an environment as an outsider, an invalid body", { name: "" }, "carol"),
    newEnv("create an environment as an outsider, an unknown parent", { name: "nope/z", parentEnvironmentId: "nope" }, "carol"),
    newEnv("create an environment as its service identity", { name: "ci", tier: "development" }, "ci"),
    newEnv("create an environment as its agent", { name: "agents", tier: "development" }, "agent"),
    newEnv("create an environment without a credential", { name: "none", tier: "development" }, "none"),
    newEnv("create an environment in an unknown Project", { name: "x", tier: "development" }, "alice", "nope"),
    newEnv("create an environment in a deleted Project", { name: "x", tier: "development" }, "alice", "oldp"),
    newEnv("create an environment in a frozen Organization", { name: "x", tier: "development" }, "alice", "app", "frozen"),
    newEnv("create a root under passkey-verification enforce", { name: "x", tier: "development" }, "alice", "app", "guarded"),
    newEnv("create a root under passkey-verification enforce, an invalid name", { name: "Bad", tier: "development" }, "alice", "app", "guarded"),
    newEnv("create a derived environment under passkey-verification enforce, invalid", { name: "staging/x", parentEnvironmentId: "development" }, "alice", "app", "guarded"),
    newEnv("create a derived environment under passkey-verification enforce, an unknown parent", { name: "nope/x", parentEnvironmentId: "nope" }, "alice", "app", "guarded"),
    newEnv("create a root under passkey-verification report", { name: "qa", tier: "staging" }, "alice", "app", "reported"),
    newEnv("create an environment in an Organization being deleted", { name: "x", tier: "development" }, "alice", "app", "deleting"),
    { ...newEnv("create an environment in assisted mode", { name: "assisted", tier: "development" }), userAgent: ASSISTED_AGENT },
    { ...newEnv("create an environment twice at once", { name: "twice", tier: "development" }), concurrent: 2 },
    // getEnvironment.
    env("environment", "development"),
    env("environment by id", "{env:api/development}"),
    env("environment, production with its Requirement", "production"),
    env("environment, production as a member", "production", "bob"),
    env("environment, a derived one encoded", "development%2Falice"),
    env("environment, a derived one encoded twice", "development%252Falice"),
    env("environment, an escape that does not decode", "%25E0%25A4%25A"),
    env("environment, an expired preview", "development%2Fold"),
    env("environment, unknown", "nope"),
    env("environment, unknown in an unknown Project", "nope", "alice", "nope"),
    env("environment as a member", "development", "bob"),
    env("environment as an outsider", "development", "carol"),
    env("environment as its service identity", "development", "ci"),
    env("environment as its agent", "development", "agent"),
    env("environment in a frozen Organization", "development", "alice", "app", "frozen"),
    env("environment under passkey-verification enforce", "development", "alice", "app", "guarded"),
    env("environment under passkey-verification report", "development", "alice", "app", "reported"),
    // deleteEnvironment.
    del("delete a preview", "development%2Fpr-1"),
    del("delete it again", "development%2Fpr-1"),
    del("delete an expired preview", "development%2Fold"),
    del("delete a root with derived environments", "development"),
    del("delete a root the active Contract names", "development", "alice", "refs"),
    del("delete a root the active Contract does not name, with a value and Capabilities", "staging", "alice", "refs"),
    del("delete an unknown environment", "nope"),
    del("delete an environment as a member, a root", "qa", "bob"),
    del("delete an environment as a member, a derived one", "development%2Fbob", "bob"),
    del("delete an environment as an outsider", "qa", "carol"),
    del("delete an environment as its service identity", "qa", "ci"),
    del("delete an environment as its agent", "qa", "agent"),
    del("delete an environment without a credential", "qa", "none"),
    del("delete an environment in a frozen Organization", "development%2Fpr-1", "alice", "app", "frozen"),
    del("delete an environment under passkey-verification enforce", "development%2Fpr-1", "alice", "app", "guarded"),
    del("delete an environment under passkey-verification report", "development%2Fpr-1", "alice", "app", "reported"),
    del("delete an environment in an Organization being deleted", "development%2Fpr-1", "alice", "app", "deleting"),
    { ...del("delete an environment in assisted mode", "qa"), userAgent: ASSISTED_AGENT },
    { ...del("delete an environment twice at once", "twice"), concurrent: 2 },
    envs("environments after the changes"),
    newEnv("create a derived environment, a deleted parent", { name: "staging/x", parentEnvironmentId: "staging", kind: "preview" }, "alice", "refs"),
    newEnv("create a root, a deleted root's name", { name: "staging", tier: "staging" }, "alice", "refs"),
    newEnv("create a derived environment, a deleted one's name", { name: "development/old", parentEnvironmentId: "development", kind: "preview" }),
    // The installation reads.
    install("installation release", "release"),
    install("installation release as a member", "release", "bob"),
    install("installation release as its service identity", "release", "ci"),
    install("installation release without a credential", "release", "none"),
    install("installation backups", "backups"),
    install("installation backups as a member", "backups", "bob"),
    install("installation backups as its agent", "backups", "agent"),
    // A deleted Project's slug is free again.
    create("create a Project, a deleted Project's slug", { name: "Old again", slug: "oldp", contractAuthority: "git" }),
    get("project, the slug's new Project", "oldp"),
  ];
}

// ---- Values: setValue, deleteValue, applyChangeSet (step 4.1d)

/**
 * The values build() writes through /v1: acme/api's development holds
 * API_URL, LOG_LEVEL, DB_HOST, DATABASE_URL (which references DB_HOST) and
 * a deleted OLD_ITEM; development/alice overrides LOG_LEVEL; staging holds
 * API_URL; production/expired is a preview that expired in 2020; each
 * guarded Organization's app/development holds ITEM.
 */
async function buildValues(call: Call) {
  const V = (org: string, project: string, env: string, item: string) =>
    `${ORG}/${org}/projects/${project}/environments/${encodeURIComponent(env)}/values/${item}`;
  for (const [env, item, value] of [
    ["development", "API_URL", "https://dev.example.com"],
    ["development", "LOG_LEVEL", "debug"],
    ["development", "DB_HOST", "db.dev"],
    ["development", "DATABASE_URL", "postgres://${DB_HOST}/app"],
    ["development", "OLD_ITEM", "gone soon"],
    ["development/alice", "LOG_LEVEL", "trace"],
    ["staging", "API_URL", "https://staging.example.com"],
  ] as const) {
    await call("PUT", V("acme", "api", env, item), { value });
  }
  await call("DELETE", V("acme", "api", "development", "OLD_ITEM"));
  await call("POST", `${ORG}/acme/projects/api/environments`, { name: "production/expired", parentEnvironmentId: "production", kind: "preview", expiresAt: "2020-01-01T00:00:00Z" });
  for (const org of ["frozen", "guarded", "reported", "deleting"]) {
    await call("PUT", V(org, "app", "development", "ITEM"), { value: `${org} value` });
  }
  // Claims this server stores (idempotency_keys: the body's digest and the
  // stored response), which the migration copies (ADR-0059 step 7): a
  // request with the same key and body replays from them.
  await call("PUT", V("acme", "api", "development", "STORED"), { value: "stored by TypeScript" }, { "Idempotency-Key": "ts-stored" });
  await call("POST", `${ORG}/acme/projects/api/environments/development/changes`, { changes: [{ op: "set", item: "STORED_CS", value: "cs" }] }, { "Idempotency-Key": "ts-stored-cs" });
}

function valueRequests(): Omit<RequestCase, "id">[] {
  const E = (env: string, project = "api", org = "acme") => `${ORG}/${org}/projects/${project}/environments/${env}`;
  const put = (name: string, env: string, item: string, body: unknown, credential = "alice", org = "acme", project = org === "acme" ? "api" : "app"): Omit<RequestCase, "id"> => ({
    name, method: "PUT", path: `${E(env, project, org)}/values/${item}`, credential, body,
  });
  const putRaw = (name: string, env: string, item: string, rawBody: string): Omit<RequestCase, "id"> => ({ name, method: "PUT", path: `${E(env)}/values/${item}`, credential: "alice", rawBody });
  const keyed = (c: Omit<RequestCase, "id">, key: string): Omit<RequestCase, "id"> => ({ ...c, headers: { "Idempotency-Key": key } });
  const del = (name: string, env: string, item: string, credential = "alice", org = "acme", project = org === "acme" ? "api" : "app"): Omit<RequestCase, "id"> => ({
    name, method: "DELETE", path: `${E(env, project, org)}/values/${item}`, credential,
  });
  const changes = (name: string, env: string, body: unknown, credential = "alice", org = "acme", project = org === "acme" ? "api" : "app"): Omit<RequestCase, "id"> => ({
    name, method: "POST", path: `${E(env, project, org)}/changes`, credential, body,
  });
  const set = (item: string, value: string, expectedVersionId?: string) => ({ op: "set", item, value, ...(expectedVersionId ? { expectedVersionId } : {}) });
  const drop = (item: string, expectedVersionId?: string) => ({ op: "delete", item, ...(expectedVersionId ? { expectedVersionId } : {}) });
  // The stateDigest covers versions earlier requests made: masked.
  const read = (name: string, env: string, credential = "alice"): Omit<RequestCase, "id"> => ({
    name, method: "GET", path: `${E(env)}/effective-configuration?include=values`, credential, masked: ["stateDigest"],
  });
  return [
    // setValue.
    put("set a value", "development", "NEW_ITEM", { value: "one" }),
    put("set a value again", "development", "NEW_ITEM", { value: "two" }),
    put("set a value, its expected version", "development", "API_URL", { value: "https://dev2.example.com", expectedVersionId: "{ver:api/development/API_URL}" }),
    put("set a value, a stale expected version", "development", "API_URL", { value: "https://dev3.example.com", expectedVersionId: "{ver:api/development/API_URL}" }),
    put("set a value, an expected version for a new item", "development", "BRAND_NEW", { value: "x", expectedVersionId: "ver_aaaaaaaaaaaaaaaaaaaaaaaaaa" }),
    put("set a value, a deleted one again", "development", "OLD_ITEM", { value: "back" }),
    put("set a value, empty", "development", "EMPTY", { value: "" }),
    putRaw("set a value, U+0000 in it", "development", "NUL_VALUE", '{"value":"a\\u0000b"}'),
    putRaw("set a value, a lone surrogate in it", "development", "LONE_VALUE", '{"value":"a\\ud800b"}'),
    put("set a value, beyond ASCII", "development", "UNICODE", { value: "héllo ✓ 😀" }),
    put("set a value with a reference", "development", "SERVICE_URL", { value: "${API_URL}/v1 and $${LITERAL}" }),
    put("set a value, an encoded name", "development", "PLAIN%5FITEM", { value: "plain" }),
    put("set a value, an invalid name", "development", "lower_case", { value: "x" }),
    put("set a value, a name starting with a digit", "development", "1ITEM", { value: "x" }),
    put("set a value, a reserved name", "development", "VARLATCH_RUN_CONTEXT", { value: "x" }),
    put("set a value, no value", "development", "X1", {}),
    put("set a value, a number", "development", "X2", { value: 7 }),
    put("set a value, a null expected version", "development", "X3", { value: "x", expectedVersionId: null }),
    put("set a value, an array", "development", "X4", ["x"]),
    putRaw("set a value, not JSON", "development", "X5", "{"),
    put("set a value, extra members", "development", "EXTRA", { value: "x", versionId: "ver_mine", sensitive: false }),
    put("set a value in a derived environment", "development%2Falice", "API_URL", { value: "https://alice.example.com" }),
    put("set a value in a removed environment", "development%2Fpr-1", "X6", { value: "x" }),
    put("set a value in an unknown environment", "nope", "X7", { value: "x" }),
    put("set a value in an expired environment", "production%2Fexpired", "X8", { value: "x" }),
    put("set a value, an invalid name in an expired environment", "production%2Fexpired", "lower", { value: "x" }),
    put("set a value as a member", "development", "BY_BOB", { value: "bob" }, "bob"),
    put("set a value in production as a member", "production", "BY_BOB", { value: "bob" }, "bob"),
    put("set a value as an outsider", "development", "BY_CAROL", { value: "carol" }, "carol"),
    put("set a value as an outsider, an invalid body", "development", "BY_CAROL", {}, "carol"),
    put("set a value as its service identity", "development", "BY_CI", { value: "ci" }, "ci"),
    put("set a value as its agent", "development", "BY_AGENT", { value: "agent" }, "agent"),
    put("set a value without a credential", "development", "BY_NONE", { value: "none" }, "none"),
    put("set a value in a frozen Organization", "development", "ITEM", { value: "x" }, "alice", "frozen"),
    put("set a value under passkey-verification enforce", "development", "ITEM", { value: "x" }, "alice", "guarded"),
    put("set a value under passkey-verification report", "development", "ITEM", { value: "reported again" }, "alice", "reported"),
    put("set a value in an Organization being deleted", "development", "ITEM", { value: "x" }, "alice", "deleting"),
    { ...put("set a value in assisted mode", "development", "ASSISTED", { value: "assisted" }), userAgent: ASSISTED_AGENT },
    // setValue under an Idempotency-Key.
    keyed(put("set a value with a key", "development", "KEYED", { value: "k1" }), "key-1"),
    keyed(put("set a value with a key, replayed", "development", "KEYED", { value: "k1" }), "key-1"),
    // Another text, the same parsed body: zod strips the extra member, so the digest is the same.
    { name: "set a value with a key, replayed with an extra member", method: "PUT", path: `${E("development")}/values/KEYED`, credential: "alice", rawBody: '{"note":"x","value":"k1"}', headers: { "Idempotency-Key": "key-1" } },
    keyed(put("set a value with a key, another body", "development", "KEYED", { value: "k2" }), "key-1"),
    keyed(put("set a value with a key, another item", "development", "KEYED_TOO", { value: "k1" }), "key-1"),
    put("set a value without the key, the same item", "development", "KEYED", { value: "k3" }),
    keyed(put("set a value with a key, replayed after a change", "development", "KEYED", { value: "k1" }), "key-1"),
    keyed(put("set a value with a key, its expected version stale", "development", "API_URL", { value: "x", expectedVersionId: "{ver:api/development/API_URL}" }), "key-stale"),
    keyed(put("set a value with a key, after its refusal", "development", "API_URL", { value: "x", expectedVersionId: "{ver:api/development/API_URL}" }), "key-stale"),
    keyed(put("set a value, a key of 200 characters", "development", "LONG_KEY", { value: "x" }), "k".repeat(200)),
    keyed(put("set a value, a key of 201 characters", "development", "LONG_KEY", { value: "y" }), "k".repeat(201)),
    keyed(put("set a value, an empty key", "development", "EMPTY_KEY", { value: "x" }), ""),
    keyed(put("set a value with a key, an invalid name", "development", "lower", { value: "x" }), "key-invalid"),
    keyed(put("set a value with a key, under passkey-verification enforce", "development", "ITEM", { value: "x" }, "alice", "guarded"), "key-guarded"),
    keyed(put("set a value with a key, under passkey-verification report", "development", "ITEM", { value: "keyed report" }, "alice", "reported"), "key-reported"),
    keyed(put("set a value with a key, under report, replayed", "development", "ITEM", { value: "keyed report" }, "alice", "reported"), "key-reported"),
    { ...keyed(put("set a value with a key, twice at once", "development", "TWICE", { value: "t" }), "key-twice"), concurrent: 2 },
    // deleteValue.
    del("delete a value", "development", "NEW_ITEM"),
    del("delete a value again", "development", "NEW_ITEM"),
    del("delete a value that never was", "development", "NEVER"),
    del("delete a value, an invalid name", "development", "lower_case"),
    del("delete a value inherited from the parent", "development%2Falice", "DB_HOST"),
    del("delete a value in an expired environment", "production%2Fexpired", "NEVER"),
    del("delete a value in a removed environment", "development%2Fpr-1", "NEVER"),
    del("delete a value as a member", "development", "BY_BOB", "bob"),
    del("delete a value in production as a member", "production", "NEVER", "bob"),
    del("delete a value as an outsider", "development", "API_URL", "carol"),
    del("delete a value as its agent", "development", "API_URL", "agent"),
    del("delete a value in a frozen Organization", "development", "ITEM", "alice", "frozen"),
    del("delete a value under passkey-verification enforce", "development", "ITEM", "alice", "guarded"),
    del("delete a value under passkey-verification enforce, not there", "development", "NEVER", "alice", "guarded"),
    del("delete a value under passkey-verification report", "development", "ITEM", "alice", "reported"),
    del("delete a value in an Organization being deleted", "development", "ITEM", "alice", "deleting"),
    // applyChangeSet.
    changes("apply a change set", "development", { changes: [set("CS_ONE", "1"), set("CS_TWO", "2"), drop("EMPTY")] }),
    changes("apply a change set, expected versions", "development", { changes: [set("LOG_LEVEL", "info", "{ver:api/development/LOG_LEVEL}"), drop("DB_HOST", "{ver:api/development/DB_HOST}")] }),
    changes("apply a change set, every kind of conflict", "development", {
      changes: [set("LOG_LEVEL", "warn", "{ver:api/development/LOG_LEVEL}"), drop("NEVER"), drop("NEVER_TWO", "ver_bbbbbbbbbbbbbbbbbbbbbbbbbb"), set("CS_NEW", "x", "ver_cccccccccccccccccccccccccc"), drop("OLD_ITEM")],
    }),
    changes("apply a change set, a deleted value set again", "development", { changes: [set("DB_HOST", "db2.dev")] }),
    changes("apply a change set, members in another order and extra", "development", { changes: [{ value: "z", item: "CS_ORDER", op: "set", note: "x" }], other: true }),
    changes("apply a change set, an item twice", "development", { changes: [set("CS_DUP", "1"), drop("CS_DUP")] }),
    changes("apply a change set, an invalid name", "development", { changes: [set("CS_OK", "1"), set("bad name", "2")] }),
    changes("apply a change set, a reserved name", "development", { changes: [set("VARLATCH_RUN_CONTEXT", "x")] }),
    changes("apply a change set, empty", "development", { changes: [] }),
    changes("apply a change set, 200 changes", "development", { changes: Array.from({ length: 200 }, (_, i) => set(`BULK_${i}`, String(i))) }),
    changes("apply a change set, 201 changes", "development", { changes: Array.from({ length: 201 }, (_, i) => set(`BULK_${i}`, "x")) }),
    changes("apply a change set, 201 changes, every one wrong", "development", { changes: Array.from({ length: 201 }, () => ({ op: "move" })) }),
    changes("apply a change set, wrong elements", "development", { changes: [1, null, [], {}, { op: "SET" }, { op: "set" }, { op: "set", item: "", value: 1, expectedVersionId: null }, { op: "delete", item: 5 }] }),
    changes("apply a change set, no changes", "development", {}),
    changes("apply a change set, changes not an array", "development", { changes: { op: "set" } }),
    changes("apply a change set, an array body", "development", [set("A", "1")]),
    { name: "apply a change set, not JSON", method: "POST", path: `${E("development")}/changes`, credential: "alice", rawBody: "[" },
    { name: "apply a change set, U+0000 and a lone surrogate", method: "POST", path: `${E("development")}/changes`, credential: "alice", rawBody: '{"changes":[{"op":"set","item":"CS_NUL","value":"a\\u0000b"},{"op":"set","item":"CS_LONE","value":"\\udc00"}]}' },
    changes("apply a change set in an expired environment", "production%2Fexpired", { changes: [set("A", "1")] }),
    changes("apply a change set in an expired environment, invalid", "production%2Fexpired", { changes: [] }),
    changes("apply a change set as a member", "development", { changes: [set("CS_BOB", "b")] }, "bob"),
    changes("apply a change set in production as a member", "production", { changes: [set("CS_BOB", "b")] }, "bob"),
    changes("apply a change set as an outsider", "development", { changes: [set("CS_CAROL", "c")] }, "carol"),
    changes("apply a change set as its agent", "development", { changes: [set("CS_AGENT", "a")] }, "agent"),
    changes("apply a change set in a frozen Organization", "development", { changes: [set("ITEM", "x")] }, "alice", "frozen"),
    changes("apply a change set under passkey-verification enforce", "development", { changes: [set("ITEM", "x")] }, "alice", "guarded"),
    changes("apply a change set under passkey-verification report", "development", { changes: [set("CS_REPORTED", "r")] }, "alice", "reported"),
    changes("apply a change set in an Organization being deleted", "development", { changes: [set("ITEM", "x")] }, "alice", "deleting"),
    { ...changes("apply a change set in assisted mode", "development", { changes: [set("CS_ASSISTED", "a")] }), userAgent: ASSISTED_AGENT },
    keyed(changes("apply a change set with a key", "development", { changes: [set("CS_KEYED", "k"), drop("CS_ONE")] }), "key-cs"),
    keyed(changes("apply a change set with a key, replayed", "development", { changes: [set("CS_KEYED", "k"), drop("CS_ONE")] }), "key-cs"),
    keyed(changes("apply a change set with a key, another body", "development", { changes: [set("CS_KEYED", "other")] }), "key-cs"),
    keyed(changes("apply a change set with a key, another environment", "staging", { changes: [set("CS_KEYED", "k"), drop("CS_ONE")] }), "key-cs"),
    // The claims the build stored through this server: a replay answers
    // the stored response and writes nothing; another body conflicts with
    // the stored digest; the same key is another identity's own (a new
    // write).
    keyed(put("replay a claim the TypeScript server stored", "development", "STORED", { value: "stored by TypeScript" }), "ts-stored"),
    keyed(put("replay a stored claim, another body", "development", "STORED", { value: "other" }), "ts-stored"),
    keyed(put("a stored claim's key, another identity", "development", "STORED", { value: "stored by TypeScript" }, "bob"), "ts-stored"),
    keyed(changes("replay a change set the TypeScript server stored", "development", { changes: [set("STORED_CS", "cs")] }), "ts-stored-cs"),
    keyed(changes("replay a stored change set, another body", "development", { changes: [set("STORED_CS", "other")] }), "ts-stored-cs"),
    keyed(changes("a stored change set's key, another identity", "development", { changes: [set("STORED_CS", "cs")] }, "bob"), "ts-stored-cs"),
    { ...changes("apply a guarded change set twice at once", "staging", { changes: [set("API_URL", "https://race.example.com", "{ver:api/staging/API_URL}")] }), concurrent: 2 },
    // What the writes left, through the read path.
    read("values after the writes", "development"),
    read("values after the writes, a derived environment", "development%2Falice"),
    read("values after the writes, as a member", "development", "bob"),
  ];
}

// ---- Validation, strict retrieval and search (step 4.1d)

/**
 * acme/checks: a Contract that exercises every verdict (an integer, a URL,
 * an enum, a required Secret, a Secret that references a non-sensitive
 * value, a reference cycle, a production-only requirement), its values in
 * development, development/child and production, and two service
 * identities with partial grants on it: "reader" may read non-sensitive
 * values, "revealer" only Secrets (so a Secret referencing a non-sensitive
 * value is unresolved for want of authority). And acme/plain, a Project
 * without a Contract.
 */
async function buildChecks(call: Call, tokens: Record<string, string>) {
  const P = `${ORG}/acme/projects/checks`;
  const project = await call("POST", `${ORG}/acme/projects`, { name: "Checks", slug: "checks", contractAuthority: "git" });
  for (const [name, tier] of [["development", "development"], ["production", "production"]] as const) {
    await call("POST", `${P}/environments`, { name, tier });
  }
  await call("POST", `${P}/environments`, { name: "development/child", parentEnvironmentId: "development" });
  const rev = await call("POST", `${P}/contract/revisions`, {
    contract: {
      schemaVersion: 1,
      semanticsVersion: 3,
      items: [
        item("PORT", { type: "integer" }),
        item("SITE_URL", { type: "url" }),
        item("MODE", { type: "enum", enumValues: ["fast", "safe"] }),
        item("API_TOKEN", { sensitive: true }),
        item("DB_PASSWORD", { sensitive: true, required: { kind: "never" } }),
        item("CALLBACK", { sensitive: true, required: { kind: "never" } }),
        item("LOOP_A", { required: { kind: "never" } }),
        item("LOOP_B", { required: { kind: "never" } }),
        item("PROD_ONLY", { required: { kind: "selector", selector: { kind: "tier", tier: "production" } } }),
        item("OPTIONAL", { required: { kind: "never" } }),
        item("FLAG", { type: "boolean", required: { kind: "never" } }),
      ],
    },
  });
  await call("POST", `${P}/contract/revisions/${rev.id}/activate`);
  const V = (env: string, name: string) => `${P}/environments/${encodeURIComponent(env)}/values/${name}`;
  for (const [env, name, value] of [
    ["development", "PORT", "8080"],
    ["development", "SITE_URL", "https://checks.example.com"],
    ["development", "MODE", "fast"],
    ["development", "API_TOKEN", "tok-${MODE}"],
    ["development", "CALLBACK", "${SITE_URL}/callback"],
    ["development", "LOOP_A", "${LOOP_B}"],
    ["development", "LOOP_B", "${LOOP_A}"],
    ["development", "FLAG", "maybe"],
    ["development/child", "PORT", "not a port"],
    ["development/child", "MODE", "slow"],
    ["production", "PORT", "443"],
    ["production", "SITE_URL", "https://checks.example.com"],
    ["production", "API_TOKEN", "prod-token"],
  ] as const) {
    await call("PUT", V(env, name), { value });
  }
  // acme/plain: an environment with a value, and no Contract.
  await call("POST", `${ORG}/acme/projects`, { name: "Plain", slug: "plain", contractAuthority: "git" });
  await call("POST", `${ORG}/acme/projects/plain/environments`, { name: "development", tier: "development" });
  await call("PUT", `${ORG}/acme/projects/plain/environments/development/values/ANYTHING`, { value: "x" });
  for (const [name, actions] of [
    ["reader", ["config.metadata.read", "config.value.read", "environment.read"]],
    ["revealer", ["config.metadata.read", "secret.reveal", "environment.read"]],
  ] as const) {
    const identity = await call("POST", `${ORG}/acme/identities`, { name, kind: "service" });
    tokens[name] = identity.credential;
    await call("POST", `${ORG}/acme/grants`, { subjectIdentityId: identity.id, scope: { kind: "project", projectId: project.id }, actions });
  }
}

function checkRequests(): Omit<RequestCase, "id">[] {
  const E = (env: string, project = "checks", org = "acme") => `${ORG}/${org}/projects/${project}/environments/${env}`;
  const validate = (name: string, env: string, credential = "alice", project = "checks", org = "acme"): Omit<RequestCase, "id"> => ({
    name, method: "POST", path: `${E(env, project, org)}/validate`, credential,
  });
  const strict = (name: string, env: string, body: unknown, credential = "alice", project = "checks", org = "acme"): Omit<RequestCase, "id"> => ({
    name, method: "POST", path: `${E(env, project, org)}/retrievals`, credential, body,
  });
  const search = (name: string, query: string, credential = "alice", org = "acme"): Omit<RequestCase, "id"> => ({
    name, method: "GET", path: `${ORG}/${org}/config-items${query}`, credential,
  });
  return [
    // validateEnvironment.
    validate("validate", "development"),
    validate("validate a derived environment", "development%2Fchild"),
    validate("validate production, a Requirement on its values", "production"),
    validate("validate as a member", "development", "bob"),
    validate("validate production as a member", "production", "bob"),
    validate("validate as a reader of values", "development", "reader"),
    validate("validate as a revealer of Secrets", "development", "revealer"),
    validate("validate as an outsider", "development", "carol"),
    validate("validate as its service identity without grants here", "development", "ci"),
    validate("validate as its agent", "development", "agent"),
    validate("validate without a credential", "development", "none"),
    validate("validate an environment without a Contract", "development", "alice", "plain"),
    validate("validate an unknown environment", "nope"),
    validate("validate an expired environment", "production%2Fexpired", "alice", "api"),
    validate("validate in a frozen Organization", "development", "alice", "app", "frozen"),
    validate("validate under passkey-verification enforce", "development", "alice", "app", "guarded"),
    validate("validate under passkey-verification report", "development", "alice", "app", "reported"),
    validate("validate in an Organization being deleted", "development", "alice", "app", "deleting"),
    { ...validate("validate with a body", "development"), body: { ignored: true } },
    // strictRetrieval.
    strict("strict retrieval", "development", { mode: "strict" }),
    strict("preflight", "development", { mode: "preflight" }),
    strict("strict retrieval of a derived environment", "development%2Fchild", { mode: "strict" }),
    strict("strict retrieval of production, a Requirement on its values", "production", { mode: "strict" }),
    strict("strict retrieval as a member", "development", { mode: "strict" }, "bob"),
    strict("strict retrieval of production as a member", "production", { mode: "strict" }, "bob"),
    strict("strict retrieval as a reader of values", "development", { mode: "strict" }, "reader"),
    strict("strict retrieval as a revealer of Secrets", "development", { mode: "strict" }, "revealer"),
    strict("preflight as a revealer of Secrets", "development", { mode: "preflight" }, "revealer"),
    strict("strict retrieval as an outsider", "development", { mode: "strict" }, "carol"),
    strict("strict retrieval as an outsider, an invalid body", "development", {}, "carol"),
    strict("strict retrieval as its service identity, the contract only", "development", { mode: "strict" }, "ci", "api"),
    strict("strict retrieval as its agent", "development", { mode: "strict" }, "agent"),
    strict("strict retrieval, an unknown mode", "development", { mode: "lenient" }),
    strict("strict retrieval, no mode", "development", {}),
    strict("strict retrieval, an array", "development", [{ mode: "strict" }]),
    { name: "strict retrieval, not JSON", method: "POST", path: `${E("development")}/retrievals`, credential: "alice", rawBody: "{" },
    { name: "strict retrieval, not JSON, as an outsider", method: "POST", path: `${E("development")}/retrievals`, credential: "carol", rawBody: "{" },
    strict("strict retrieval, extra members", "development", { mode: "strict", items: ["PORT"] }),
    strict("strict retrieval without a Contract", "development", { mode: "strict" }, "alice", "plain"),
    { ...strict("strict retrieval after the writes", "development", { mode: "strict" }, "alice", "api"), masked: ["stateDigest", "stateDigests"] },
    strict("strict retrieval of an expired environment", "production%2Fexpired", { mode: "strict" }, "alice", "api"),
    strict("strict retrieval of an unknown environment", "nope", { mode: "strict" }),
    strict("strict retrieval in a frozen Organization", "development", { mode: "strict" }, "alice", "app", "frozen"),
    strict("strict retrieval under passkey-verification enforce", "development", { mode: "strict" }, "alice", "app", "guarded"),
    // The value requests wrote here too: digests over fresh versions.
    { ...strict("strict retrieval under passkey-verification report", "development", { mode: "strict" }, "alice", "app", "reported"), masked: ["stateDigest", "stateDigests"] },
    strict("strict retrieval in an Organization being deleted", "development", { mode: "strict" }, "alice", "app", "deleting"),
    // searchConfigItems.
    search("search", "?q=url"),
    search("search, upper case", "?q=SITE"),
    search("search, a name exactly", "?q=API_TOKEN"),
    search("search, an underscore is literal", "?q=_"),
    search("search, a percent sign is literal", "?q=%25"),
    search("search, no match", "?q=nothing-here"),
    search("search, a character that lowers to two", "?q=%C4%B0"),
    search("search, no q", ""),
    search("search, an empty q", "?q="),
    search("search, q of 256 characters", `?q=${"a".repeat(256)}`),
    search("search, q of 257 characters", `?q=${"a".repeat(257)}`),
    search("search, q of 128 emoji", `?q=${encodeURIComponent("😀".repeat(128))}`),
    search("search, q of 129 emoji", `?q=${encodeURIComponent("😀".repeat(129))}`),
    search("search, q given twice", "?q=PORT&q=url"),
    search("search, q with a plus", "?q=SITE+URL"),
    search("search, limit 1", "?q=_&limit=1"),
    search("search, limit 100", "?q=_&limit=100"),
    search("search, limit 0", "?q=_&limit=0"),
    search("search, limit 101", "?q=_&limit=101"),
    search("search, limit 1.5", "?q=_&limit=1.5"),
    search("search, limit 2.0", "?q=_&limit=2.0"),
    search("search, limit with spaces", "?q=_&limit=%202%20"),
    search("search, limit in hex", "?q=_&limit=0x2"),
    search("search, limit as an exponent", "?q=_&limit=2e0"),
    search("search, limit empty", "?q=_&limit="),
    search("search, limit not a number", "?q=_&limit=two"),
    search("search, limit Infinity", "?q=_&limit=Infinity"),
    search("search, limit with a sign", "?q=_&limit=%2B3"),
    search("search, a cursor", "?q=_&limit=2&cursor={cursor:api/API_URL}"),
    search("search, the last page", "?q=_&limit=100&cursor={cursor:checks/SITE_URL}"),
    search("search, an invalid cursor", "?q=_&cursor=abc"),
    search("search, a cursor of two parts", `?q=_&cursor=${Buffer.from(JSON.stringify(["a", "b"])).toString("base64url")}`),
    search("search, a cursor of numbers", `?q=_&cursor=${Buffer.from(JSON.stringify([1, 2, 3])).toString("base64url")}`),
    search("search, a cursor in standard base64", `?q=_&cursor=${encodeURIComponent(Buffer.from(JSON.stringify(["api", "A", "b"])).toString("base64"))}`),
    search("search as a member", "?q=_", "bob"),
    search("search as a reader of one Project", "?q=_", "reader"),
    search("search as its service identity, no metadata", "?q=_", "ci"),
    search("search as its agent", "?q=_", "agent"),
    search("search as an outsider", "?q=_", "carol"),
    search("search as an outsider, an invalid q", "", "carol"),
    search("search without a credential", "?q=_", "none"),
    search("search an unknown Organization", "?q=_", "alice", "nope"),
    search("search a frozen Organization", "?q=_", "alice", "frozen"),
    search("search under passkey-verification enforce", "?q=_", "alice", "guarded"),
    search("search under passkey-verification report", "?q=_", "alice", "reported"),
    search("search an Organization being deleted", "?q=_", "alice", "deleting"),
  ];
}

async function build(): Promise<{ ctx: AppCtx & { close: () => Promise<void> }; tokens: Record<string, string> }> {
  const db = await migratedTestDb();
  const ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId: alice } = await consumeSetupGrant(ctx, grant.token, { adminName: "Alice" });
  const tokens: Record<string, string> = { alice: (await issueCredential(ctx.db, { identityId: alice, kind: "cli" })).token };
  const app = buildApp(ctx);
  const call: Call = async (method, path, body, headers = {}) => {
    const res = await app.request(path, {
      method,
      headers: { Authorization: `Bearer ${tokens.alice}`, "Content-Type": "application/json", ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await res.text();
    if (res.status >= 300) throw new Error(`${method} ${path}: ${res.status} ${text}`);
    return text ? JSON.parse(text) : null;
  };
  const orgs: Record<string, string> = {};
  for (const slug of ["acme", "frozen", "guarded", "reported", "deleting", "gone"]) {
    orgs[slug] = (await call("POST", ORG, { name: slug[0]!.toUpperCase() + slug.slice(1), slug })).id;
  }
  for (const [org, slug, contractAuthority] of PROJECTS) {
    await call("POST", `${ORG}/${org}/projects`, { name: slug[0]!.toUpperCase() + slug.slice(1), slug, contractAuthority });
  }
  for (const [key, org, project, activate] of PUSHED) {
    const rev = await call("POST", `${ORG}/${org}/projects/${project}/contract/revisions`, { contract: REVISIONS[key], provenance: { source: "build" } });
    if (activate) await call("POST", `${ORG}/${org}/projects/${project}/contract/revisions/${rev.id}/activate`);
  }
  // Step 4.1c's environments, before the freeze, controls and deletions
  // below would refuse them.
  await buildEnvironments(db, call, alice);
  await buildValues(call);
  await buildRotations(db, call);
  const person = async (name: string, member: boolean) => {
    const id = newId("identity");
    await db.query("INSERT INTO identities (id, kind, name, created_at) VALUES ($1, 'human', $2, '2026-01-01T00:00:00.000Z')", [id, name]);
    if (member) await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, $2, 'member')", [orgs.acme, id]);
    tokens[name] = (await issueCredential(ctx.db, { identityId: id, kind: "cli" })).token;
  };
  await person("bob", true);
  await person("carol", false);
  const ci = await call("POST", `${ORG}/acme/identities`, { name: "deploy", kind: "service" });
  tokens.ci = ci.credential;
  const api = await call("GET", `${ORG}/acme/projects/api`);
  await call("POST", `${ORG}/acme/grants`, { subjectIdentityId: ci.id, scope: { kind: "project", projectId: api.id }, actions: ["contract.read"] });
  const agent = await call("POST", `${ORG}/acme/identities`, { name: "helper", kind: "agent" });
  tokens.agent = (await issueCredential(ctx.db, { identityId: agent.id, kind: "agent-run" })).token;
  await buildChecks(call, tokens);
  tokens.invalid = "vlt_cli_" + "x".repeat(40);
  await db.query(
    "INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', 'incident drill')",
    [newId("organizationFreeze"), orgs.frozen, alice],
  );
  await db.query("INSERT INTO security_controls (organization_id, control, mode, version, changed_by) VALUES ($1, 'passkey-verification', 'enforce', 3, $2)", [orgs.guarded, alice]);
  await db.query("INSERT INTO security_controls (organization_id, control, mode, version, changed_by) VALUES ($1, 'passkey-verification', 'report', 3, $2)", [orgs.reported, alice]);
  await db.query(
    "INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', '2099-03-01T00:00:00.000Z', false)",
    [newId("organizationDeletion"), orgs.deleting, alice],
  );
  // A deletion that ran: the Organization deleted, its KEK destroyed, as
  // the deletion worker leaves it (orgdeletion.ts).
  await db.query(
    "INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required, completed_at) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', '2026-03-02T00:00:00.000Z', false, '2026-03-02T00:00:01.000Z')",
    [newId("organizationDeletion"), orgs.gone, alice],
  );
  await db.query("UPDATE organizations SET deleted_at = '2026-03-02T00:00:01.000Z', wrapped_org_kek = NULL, org_kek_destroyed_at = '2026-03-02T00:00:01.000Z' WHERE id = $1", [orgs.gone]);
  return { ctx, tokens };
}

// ---- Rotation (step 4.2)

/**
 * acme/rotate, for dual-phase rotation (ADR-0027): development and
 * production, a Contract naming HINTED (a Secret with a 3600-second grace
 * hint, ADR-0053) and PLAINV (not sensitive), and values in development.
 * Rotations as build() leaves them: LIVE in flight (its deadline fixed in
 * 2099), PAST and PASTC past their window (still pinned), DONE completed,
 * SUPERSEDED begun and then written over; GONE deleted.
 */
async function buildRotations(db: AppCtx["db"], call: Call) {
  const P = `${ORG}/acme/projects/rotate`;
  await call("POST", `${ORG}/acme/projects`, { name: "Rotate", slug: "rotate", contractAuthority: "git" });
  for (const [name, tier] of [["development", "development"], ["production", "production"]] as const) {
    await call("POST", `${P}/environments`, { name, tier });
  }
  const rev = await call("POST", `${P}/contract/revisions`, {
    contract: doc([
      item("HINTED", { sensitive: true, required: { kind: "never" }, rotationGraceSeconds: 3600 }),
      item("PLAINV", { required: { kind: "never" } }),
    ]),
  });
  await call("POST", `${P}/contract/revisions/${rev.id}/activate`);
  const V = (env: string, name: string) => `${P}/environments/${env}/values/${name}`;
  for (const name of ["LIVE", "PAST", "PASTC", "DONE", "SUPERSEDED", "HINTED", "GRACED", "DEFAULTED", "PLAINV", "MAXED", "EXTRA", "GONE", "BOBS", "RACE"]) {
    await call("PUT", V("development", name), { value: `${name.toLowerCase()}-1` });
  }
  await call("PUT", V("production", "PRODV"), { value: "prodv-1" });
  // In the Organization at passkey-verification report, an item no other
  // request writes.
  await call("PUT", `${ORG}/reported/projects/app/environments/development/values/ROTME`, { value: "rotme-1" });
  await call("DELETE", V("development", "GONE"));
  for (const name of ["LIVE", "PAST", "PASTC", "DONE", "SUPERSEDED"]) {
    await call("POST", `${V("development", name)}/rotations`, { value: `${name.toLowerCase()}-2` });
  }
  await call("POST", `${V("development", "DONE")}/rotations/complete`);
  await call("PUT", V("development", "SUPERSEDED"), { value: "superseded-3" });
  // Fixed deadlines, so the file holds whatever day it is replayed: one in
  // flight, two past their window.
  const rows = `SELECT v.id FROM env_values v JOIN environments e ON e.id = v.environment_id JOIN projects p ON p.id = e.project_id
    WHERE p.slug = 'rotate' AND e.name = 'development' AND v.item_name = $1`;
  await db.query(`UPDATE env_values SET rotation_deadline = '2099-06-01T00:00:00.000Z' WHERE id = (${rows})`, ["LIVE"]);
  for (const name of ["PAST", "PASTC"]) {
    await db.query(`UPDATE env_values SET rotation_started_at = '2019-12-31T00:00:00.000Z', rotation_deadline = '2020-01-01T00:00:00.000Z' WHERE id = (${rows})`, [name]);
  }
}

function rotationRequests(): Omit<RequestCase, "id">[] {
  const E = (env: string, project = "rotate", org = "acme") => `${ORG}/${org}/projects/${project}/environments/${env}`;
  const begin = (name: string, env: string, itemName: string, body: unknown, credential = "alice", project = "rotate", org = "acme"): Omit<RequestCase, "id"> => ({
    name, method: "POST", path: `${E(env, project, org)}/values/${itemName}/rotations`, credential, body,
  });
  const complete = (name: string, env: string, itemName: string, credential = "alice", project = "rotate", org = "acme"): Omit<RequestCase, "id"> => ({
    name, method: "POST", path: `${E(env, project, org)}/values/${itemName}/rotations/complete`, credential,
  });
  const read = (name: string, masked?: string[]): Omit<RequestCase, "id"> => ({
    name, method: "GET", path: `${E("development")}/effective-configuration?include=values`, credential: "alice", ...(masked ? { masked } : {}),
  });
  const disclose = (name: string, items: string[], masked?: string[]): Omit<RequestCase, "id"> => ({
    name, method: "POST", path: `${E("development")}/disclosures`, credential: "alice", body: { items }, ...(masked ? { masked } : {}),
  });
  const all = ["LIVE", "PAST", "PASTC", "DONE", "SUPERSEDED", "HINTED", "GRACED", "DEFAULTED", "PLAINV", "MAXED"];
  return [
    // As built: one in flight, two past their window, one completed, one superseded.
    read("rotations as built"),
    disclose("disclose rotations as built", all),
    // beginRotation.
    begin("begin a rotation while one is in flight", "development", "LIVE", { value: "live-3" }),
    begin("begin a rotation past its window", "development", "PAST", { value: "past-3" }),
    begin("begin a rotation, its expected version", "development", "DONE", { value: "done-3", expectedVersionId: "{ver:rotate/development/DONE}" }),
    begin("begin a rotation, a stale expected version", "development", "SUPERSEDED", { value: "x", expectedVersionId: "ver_aaaaaaaaaaaaaaaaaaaaaaaaaa" }),
    begin("begin a rotation, the Contract's grace", "development", "HINTED", { value: "hinted-2" }),
    begin("begin a rotation, its own grace", "development", "GRACED", { value: "graced-2", graceSeconds: 120 }),
    begin("begin a rotation, the default grace", "development", "DEFAULTED", { value: "defaulted-2" }),
    begin("begin a rotation of a non-sensitive item", "development", "PLAINV", { value: "plainv-2" }),
    begin("begin a rotation, the longest grace", "development", "MAXED", { value: "maxed-2", graceSeconds: 2_592_000 }),
    begin("begin a rotation, extra members", "development", "EXTRA", { value: "extra-2", note: "x", retiringVersionId: "ver_mine" }),
    begin("begin a rotation, a grace of 0", "development", "RACE", { value: "x", graceSeconds: 0 }),
    begin("begin a rotation, a grace beyond 30 days", "development", "RACE", { value: "x", graceSeconds: 2_592_001 }),
    begin("begin a rotation, a fractional grace", "development", "RACE", { value: "x", graceSeconds: 1.5 }),
    begin("begin a rotation, a grace as a string", "development", "RACE", { value: "x", graceSeconds: "60" }),
    begin("begin a rotation, a null grace", "development", "RACE", { value: "x", graceSeconds: null }),
    begin("begin a rotation, no value", "development", "RACE", {}),
    begin("begin a rotation, a number", "development", "RACE", { value: 7 }),
    begin("begin a rotation, a null expected version", "development", "RACE", { value: "x", expectedVersionId: null }),
    begin("begin a rotation, an array", "development", "RACE", ["x"]),
    { name: "begin a rotation, not JSON", method: "POST", path: `${E("development")}/values/RACE/rotations`, credential: "alice", rawBody: "{" },
    begin("begin a rotation of an item never set", "development", "NEVER", { value: "x" }),
    begin("begin a rotation of a deleted value", "development", "GONE", { value: "x" }),
    begin("begin a rotation, an invalid name", "development", "lower", { value: "x" }),
    begin("begin a rotation, a reserved name", "development", "VARLATCH_RUN_CONTEXT", { value: "x" }),
    begin("begin a rotation in a derived environment", "development%2Falice", "LOG_LEVEL", { value: "debug" }, "alice", "api"),
    begin("begin a rotation in an expired environment", "production%2Fexpired", "ANYTHING", { value: "x" }, "alice", "api"),
    begin("begin a rotation in a removed environment", "development%2Fpr-1", "ANYTHING", { value: "x" }, "alice", "api"),
    begin("begin a rotation in an unknown environment", "nope", "LIVE", { value: "x" }),
    begin("begin a rotation as a member", "development", "BOBS", { value: "bobs-2" }, "bob"),
    begin("begin a rotation in production as a member", "production", "PRODV", { value: "x" }, "bob"),
    begin("begin a rotation as an outsider", "development", "LIVE", { value: "x" }, "carol"),
    begin("begin a rotation as an outsider, an invalid body", "development", "LIVE", {}, "carol"),
    begin("begin a rotation as its service identity", "development", "API_URL", { value: "x" }, "ci", "api"),
    begin("begin a rotation as its agent", "development", "LIVE", { value: "x" }, "agent"),
    begin("begin a rotation without a credential", "development", "LIVE", { value: "x" }, "none"),
    begin("begin a rotation in a frozen Organization", "development", "ITEM", { value: "x" }, "alice", "app", "frozen"),
    begin("begin a rotation under passkey-verification enforce", "development", "ITEM", { value: "x" }, "alice", "app", "guarded"),
    begin("begin a rotation under passkey-verification report", "development", "ROTME", { value: "rotme-2" }, "alice", "app", "reported"),
    begin("begin a rotation in an Organization being deleted", "development", "ITEM", { value: "x" }, "alice", "app", "deleting"),
    { ...begin("begin a rotation twice at once", "development", "RACE", { value: "race-2" }), concurrent: 2 },
    // completeRotation.
    complete("complete a rotation in flight", "development", "LIVE"),
    complete("complete a rotation again", "development", "LIVE"),
    complete("complete a rotation past its window", "development", "PASTC"),
    { ...complete("complete a rotation, a body is ignored", "development", "DONE"), body: { ignored: true } },
    complete("complete a rotation of an item never set", "development", "NEVER"),
    complete("complete a rotation of a deleted value", "development", "GONE"),
    complete("complete a rotation, an invalid name", "development", "lower"),
    complete("complete a rotation in an expired environment", "production%2Fexpired", "ANYTHING", "alice", "api"),
    complete("complete a rotation in an unknown environment", "nope", "LIVE"),
    complete("complete a rotation as a member", "development", "BOBS", "bob"),
    complete("complete a rotation as an outsider", "development", "PAST", "carol"),
    complete("complete a rotation as its agent", "development", "PAST", "agent"),
    complete("complete a rotation without a credential", "development", "PAST", "none"),
    complete("complete a rotation in a frozen Organization", "development", "ITEM", "alice", "app", "frozen"),
    complete("complete a rotation under passkey-verification enforce", "development", "ITEM", "alice", "app", "guarded"),
    complete("complete a rotation under passkey-verification report", "development", "ROTME", "alice", "app", "reported"),
    complete("complete a rotation in an Organization being deleted", "development", "ITEM", "alice", "app", "deleting"),
    // A plain write or a deletion supersedes a rotation in flight.
    { name: "a plain write over a rotation in flight", method: "PUT", path: `${E("development")}/values/PAST`, credential: "alice", body: { value: "past-4" } },
    { name: "a deletion of a value in rotation", method: "DELETE", path: `${E("development")}/values/PLAINV`, credential: "alice" },
    begin("begin a rotation of the value just deleted", "development", "PLAINV", { value: "x" }),
    // What the requests left, through the read path.
    read("rotations after the requests", ["stateDigest"]),
    disclose("disclose rotations after the requests", all, ["stateDigest", "stateDigests"]),
  ];
}

/** The file's answers, recorded on its own rows. */
async function replay(f: Fixture) {
  const db = await loadRows(f.rows, TABLES);
  try {
    const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex") };
    return await record(ctx, () => buildApp(ctx), f, f.requests, fillPath(f.rows));
  } finally {
    await db.close();
  }
}

/** Each value version's plaintext, opened with this code from the rows. */
function plaintexts(rows: Record<string, Row[]>, rootKek: Buffer): (version: Row) => string {
  const orgOf = new Map(rows.organizations!.map((o) => [o.id, o]));
  const projectOf = new Map(rows.projects!.map((p) => [p.id, p]));
  const envOf = new Map(rows.environments!.map((e) => [e.id, e]));
  const valueOf = new Map(rows.env_values!.map((v) => [v.id, v]));
  return (version) => {
    const value = valueOf.get(version.value_id)!;
    const orgId = projectOf.get(envOf.get(value.environment_id)!.project_id)!.organization_id as string;
    const orgKek = unwrapOrgKek(rootKek, orgOf.get(orgId)!.wrapped_org_kek as Envelope, orgId);
    const sealed = { payload: version.payload as Envelope, wrappedDek: version.wrapped_dek as Envelope };
    return decryptValue(orgKek, orgId, value.id as string, version.id as string, sealed).toString("utf8");
  };
}

describe.skipIf(process.env.VARLATCH_WRITE_GO_VECTORS !== "1")("writing the fixture", () => {
  it("builds the database, records the answers and writes both files", async () => {
    const { ctx, tokens } = await build();
    try {
      const rows = await exportRows(ctx.db, TABLES);
      for (const [ref, file] of Object.entries(FILES)) {
        const fileRows = structuredClone(rows);
        if (ref === "v0.21.0") await resealWith(ref, ctx.rootKek, fileRows, plaintexts(rows, ctx.rootKek));
        const draft: Fixture = {
          comment: "Written by services/varlatchd/test/go-core-fixture.test.ts from the TypeScript server's own answers; do not edit.",
          ref,
          serverVersion: SERVER_VERSION,
          rootKek: ctx.rootKek.toString("hex"),
          tokens,
          rows: fileRows,
          sideTables: SIDE,
          requests: requestTable().map((c) => ({ ...c, expect: { status: 0, headers: {}, body: "" }, audit: [], side: {} })),
          counters: [],
        };
        writeFileSync(file, JSON.stringify({ ...draft, ...(await replay(draft)) }, null, 2) + "\n");
      }
    } finally {
      await ctx.close();
    }
  }, 600_000);
});

describe("the fixture is this server's answers", () => {
  it("the rows check keeps relationships: a moved membership, a moved auth link or swapped IDs fail it, a consistent renaming does not", () => {
    const f = JSON.parse(readFileSync(FILE, "utf8")) as Fixture;
    const idOf = (slug: string) => f.rows.organizations!.find((o) => o.slug === slug)!.id as string;
    const fails = (mutate: (rows: Record<string, Row[]>) => void) => {
      const copy = structuredClone(f.rows);
      mutate(copy);
      expect(() => expectSameRows(TABLES, f.rows, copy)).toThrow();
    };
    // A membership moved to another Organization.
    fails((rows) => {
      const m = rows.org_memberships!.find((r) => r.role === "member")!;
      m.organization_id = idOf("frozen");
    });
    // Two Organizations swap IDs (their memberships, controls and freezes stay).
    fails((rows) => {
      const [a, b] = [rows.organizations!.find((o) => o.slug === "acme")!, rows.organizations!.find((o) => o.slug === "frozen")!];
      [a.id, b.id] = [b.id, a.id];
    });
    // Random columns keep their relationships too: two users and their
    // auth links (the committed file's user tables are empty, so they are
    // added here). A link moved to the other user fails the check; the two
    // users swapping ids everywhere does not.
    const person = (name: string) => f.rows.identities!.find((i) => i.name === name)!.id as string;
    const withUsers = structuredClone(f.rows);
    withUsers.user = [
      { id: "UserAlpha0001", name: "Alice", email: "alice@example.test" },
      { id: "UserBeta00002", name: "Bob", email: "bob@example.test" },
    ];
    withUsers.auth_user_links = [
      { better_auth_user_id: "UserAlpha0001", identity_id: person("Alice") },
      { better_auth_user_id: "UserBeta00002", identity_id: person("bob") },
    ];
    expectSameRows(TABLES, withUsers, structuredClone(withUsers));
    const moved = structuredClone(withUsers);
    moved.auth_user_links![1]!.better_auth_user_id = "UserAlpha0001";
    expect(() => expectSameRows(TABLES, withUsers, moved)).toThrow();
    const swapped = JSON.parse(JSON.stringify(withUsers).replaceAll("UserAlpha0001", "SWAP-MARK").replaceAll("UserBeta00002", "UserAlpha0001").replaceAll("SWAP-MARK", "UserBeta00002")) as Record<string, Row[]>;
    expectSameRows(TABLES, withUsers, swapped);
    // Every ID renamed consistently is the same database.
    const renamed = JSON.parse(JSON.stringify(f.rows).replace(/\b([a-z]{3,4})_([a-z2-7]{26})\b/g, (_m, p: string, rest: string) => `${p}_${[...rest].reverse().join("")}`)) as Record<string, Row[]>;
    expectSameRows(TABLES, f.rows, renamed);
  });

  it("checkDigests accepts digests that are their manifest's and refuses one that is not", () => {
    const manifest = {
      manifestVersion: 1, projectId: "prj_a", environment: { id: "env_a" }, contract: null,
      items: [{ name: "A", source: "self", valueRowId: "val_a", versionId: "ver_a", retiringVersionId: "ver_b" }],
    };
    const sha = (v: unknown) => `sha256:${createHash("sha256").update(canonicalJson(v), "utf8").digest("hex")}`;
    const good = {
      manifest,
      stateDigest: sha(manifest),
      stateDigests: {
        environment: sha({ projectId: "prj_a", environment: { id: "env_a" } }),
        contract: sha(null),
        items: sha([{ name: "A", source: "self", valueRowId: "val_a", versionId: "ver_a" }]),
        rotation: sha([{ name: "A", retiringVersionId: "ver_b" }]),
      },
    };
    checkDigests(JSON.stringify(good), "good");
    expect(() => checkDigests(JSON.stringify({ ...good, stateDigest: sha({}) }), "bad")).toThrow(/stateDigest/);
    expect(() => checkDigests(JSON.stringify({ ...good, stateDigests: { ...good.stateDigests, items: sha([]) } }), "bad")).toThrow(/stateDigests/);
  });

  for (const [ref, file] of Object.entries(FILES)) {
    it(`core-${ref}.json`, async () => {
      const f = JSON.parse(readFileSync(file, "utf8")) as Fixture;
      expect(f.ref).toBe(ref);
      expect(f.serverVersion).toBe(SERVER_VERSION);
      expectCurrentTable(f, requestTable());
      expect(f.sideTables).toEqual(SIDE);
      expectSameAnswers(f, await replay(f));
      // The file's rows are still what the setup builds (envelopes aside).
      const { ctx } = await build();
      try {
        expectSameRows(TABLES, f.rows, await exportRows(ctx.db, TABLES));
      } finally {
        await ctx.close();
      }
    }, 180_000);
  }

  it("core-v0.21.0.json is core-v0.22.0.json's rows and requests, every envelope sealed again, the claims this server stored kept", () => {
    const [now, old] = [FILES["v0.22.0"], FILES["v0.21.0"]].map((u) => JSON.parse(readFileSync(u, "utf8")) as Fixture);
    const sealed: Record<string, string[]> = { installation: ["kek_canary"], organizations: ["wrapped_org_kek"], value_versions: ["payload", "wrapped_dek"] };
    const without = (rows: Record<string, Row[]>) =>
      Object.fromEntries(Object.entries(rows).map(([t, rs]) => [t, rs.map((r) => Object.fromEntries(Object.entries(r).filter(([c]) => !(sealed[t] ?? []).includes(c))))]));
    expect(without(old.rows)).toEqual(without(now.rows));
    // The same requests and answers; the rows a request wrote carry each
    // file's own envelopes.
    const answers = (f: Fixture) => f.requests.map(({ side: _side, ...r }) => r);
    expect(answers(old)).toEqual(answers(now));
    expect(old.rootKek).toBe(now.rootKek);
    for (const [t, cols] of Object.entries(sealed)) {
      for (const [i, r] of old.rows[t]!.entries()) {
        for (const c of cols) if (r[c] !== null) expect(r[c], `${t}[${i}].${c}`).not.toEqual(now.rows[t]![i]![c]);
      }
    }
    expect(now.rows.idempotency_keys!.map((r) => r.idempotency_key).sort()).toEqual(["ts-stored", "ts-stored-cs"]);
  });
});
