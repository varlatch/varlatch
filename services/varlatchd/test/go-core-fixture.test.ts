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
 * freeze, the controls, the deletion) are written directly.
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
import { expectCurrentTable, expectSameAnswers, expectSameRows, exportRows, loadRows, record, withIds, type Fixture, type RequestCase, type Row, type SideTable, type Table } from "./go-fixture-kit.js";

// The unwrapped app: some requests are outside the OpenAPI document on
// purpose (bodies that are not JSON, extra members).
const { buildApp } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const FILE = new URL("../../../go/server/paritytest/testdata/core-v0.22.0.json", import.meta.url);

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
];

const SIDE: SideTable[] = [
  { name: "organizations", key: ["id"], sortBy: ["slug"], volatile: ["created_at", "wrapped_org_kek"] },
  { name: "org_memberships", key: ["organization_id", "identity_id"], sortBy: ["organization_id", "identity_id"], volatile: ["created_at"] },
  { name: "projects", key: ["id"], sortBy: ["organization_id", "slug"], volatile: ["created_at"] },
  { name: "contract_revisions", key: ["id"], sortBy: ["project_id", "content_hash"], volatile: ["created_at"] },
  { name: "environments", key: ["id"], sortBy: ["project_id", "name", "deleted_at"], volatile: ["created_at", "deleted_at"] },
  { name: "env_values", key: ["id"], sortBy: ["environment_id", "item_name"], volatile: ["deleted_at"] },
  { name: "capabilities", key: ["id"], sortBy: ["environment_id", "run_id"], volatile: ["revoked_at"] },
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

/** A request path's placeholders: {rev:KEY}, {project:SLUG} and {env:PROJECT/NAME} (acme's). */
function fillPath(rows: Record<string, Row[]>): (p: string) => string {
  const orgOf = (slug: string) => rows.organizations!.find((o) => o.slug === slug)!.id as string;
  return (p) =>
    p
      .replace("{orgId}", orgOf("acme"))
      .replace("{goneId}", orgOf("gone"))
      .replace(/\{project:([a-z]+)\}/g, (_m, slug: string) => rows.projects!.find((r) => r.organization_id === orgOf("acme") && r.slug === slug && r.deleted_at === null)!.id as string)
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

type Call = (method: string, path: string, body?: unknown) => Promise<any>;

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

async function build(): Promise<{ ctx: AppCtx & { close: () => Promise<void> }; tokens: Record<string, string> }> {
  const db = await migratedTestDb();
  const ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId: alice } = await consumeSetupGrant(ctx, grant.token, { adminName: "Alice" });
  const tokens: Record<string, string> = { alice: (await issueCredential(ctx.db, { identityId: alice, kind: "cli" })).token };
  const app = buildApp(ctx);
  const call = async (method: string, path: string, body?: unknown) => {
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

/** The file's answers, recorded on its own rows. */
async function replay(f: Fixture) {
  const db = await loadRows(f.rows, TABLES);
  try {
    const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex") };
    return await record(ctx, buildApp(ctx), f, f.requests, fillPath(f.rows));
  } finally {
    await db.close();
  }
}

describe.skipIf(process.env.VARLATCH_WRITE_GO_VECTORS !== "1")("writing the fixture", () => {
  it("builds the database, records the answers and writes the file", async () => {
    const { ctx, tokens } = await build();
    try {
      const draft: Fixture = {
        comment: "Written by services/varlatchd/test/go-core-fixture.test.ts from the TypeScript server's own answers; do not edit.",
        ref: "v0.22.0",
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
  }, 300_000);
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

  it("core-v0.22.0.json", async () => {
    const f = JSON.parse(readFileSync(FILE, "utf8")) as Fixture;
    expectCurrentTable(f, requestTable());
    expect(f.sideTables).toEqual(SIDE);
    expectSameAnswers(f, await replay(f));
    // The file's rows are still what the setup builds.
    const { ctx } = await build();
    try {
      expectSameRows(TABLES, f.rows, await exportRows(ctx.db, TABLES));
    } finally {
      await ctx.close();
    }
  }, 120_000);
});
