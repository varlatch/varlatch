// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.6's parity fixture (ADR-0059 step 4, feature-parity decision 3),
 * on the parity kit (go-fixture-kit.ts): broker Capabilities, built through
 * this server's own /v1 API, and a table of requests with this server's
 * answers (issueCapability, listCapabilities, revokeCapability,
 * exerciseCapability). go/server/capabilities' parity test replays it
 * against varlatchd.
 *
 * The database: alice (the bootstrap Installation Admin), bob (a member of
 * cap), carol (in none). Organizations made through /v1: cap, frozen (an
 * incident freeze), deleting (a deletion scheduled) and other. In cap: two
 * Brokers, a service, and Agents with a project Grant of secret.use and
 * config.value.read (agent), of secret.use only (noread), with none
 * (nogrant), and disabled (off); a Requirement on the production tier; the
 * Project api with development and production, a Contract with Secrets and
 * plain items, values that reference each other, one in a rotation whose
 * window is open until 2099. Capabilities are inserted with known secrets
 * (an issuance's secret is random, and masked in its answer): live,
 * revoked, expired (2026), without targets, for each Agent, another
 * Broker's, one in production, and one in frozen and in deleting. The
 * state digests of development and production, which a precondition names,
 * are kept in the file (`digests`): they are the rows', so they hold on
 * every replay.
 *
 * Every run checks the committed file: its requests must be the table's,
 * and this server, on its rows, must give the recorded answers. After a
 * change, regenerate it and commit the result:
 *
 * A Capability has no use count, so none is ever exhausted; a later Grant
 * change is the Agent's Grant removed between two exercises.
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-capabilities-fixture.test.ts
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { newId } from "../src/db/ids.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { migratedTestDb } from "./helpers/pglite.js";
import {
  expectCurrentTable, expectSameAnswers, expectSameRows, exportRows, loadRows, record, withIds,
  type Fixture, type RequestCase, type SideTable, type Table,
} from "./go-fixture-kit.js";

// The unwrapped app: some requests are outside the OpenAPI document on
// purpose (bodies that are not JSON, extra members).
const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const FILE = new URL("../../../go/server/paritytest/testdata/capabilities-v0.22.0.json", import.meta.url);

const TABLES: Table[] = [
  { name: "installation", orderBy: "id", random: ["kek_canary"] },
  { name: "identities", orderBy: "id" },
  { name: "credentials", orderBy: "id", random: ["token_hash"] },
  { name: "organizations", orderBy: "id", random: ["wrapped_org_kek"] },
  { name: "org_memberships", orderBy: "organization_id, identity_id" },
  { name: "grants", orderBy: "id" },
  { name: "requirements", orderBy: "id" },
  { name: "organization_freezes", orderBy: "id" },
  { name: "organization_deletions", orderBy: "id" },
  { name: "projects", orderBy: "id" },
  { name: "contract_revisions", orderBy: "id" },
  { name: "environments", orderBy: "id" },
  { name: "env_values", orderBy: "id" },
  { name: "value_versions", orderBy: "id", random: ["payload", "wrapped_dek"] },
  { name: "capabilities", orderBy: "id" },
  // The build's own requests carry its request ids.
  { name: "audit_events", orderBy: "event_order", random: ["request_id"] },
];

const SIDE: SideTable[] = [
  { name: "grants", key: ["id"], sortBy: ["organization_id", "subject_identity_id"], volatile: ["created_at", "revoked_at"] },
  {
    name: "capabilities", key: ["id"], sortBy: ["organization_id", "environment_id", "run_id"],
    volatile: ["secret_hash", "expires_at", "created_at", "revoked_at"],
  },
];

const ORG = "/v1/organizations";
const E = (env = "development", org = "cap") => `${ORG}/${org}/projects/api/environments/${env}/capabilities`;

/** The Capabilities build() inserts, by name: their known secrets. */
const SECRET = (name: string) => `vlt_cap_known_${name}`;
const CAPS = ["live", "revoked", "expired", "untargeted", "noread", "nogrant", "theirs", "prod", "frozen", "deleting"] as const;

/** A digest no state has. */
const STALE = `sha256:${"0".repeat(64)}`;

/** The table of requests. */
function requestTable(): RequestCase[] {
  const issue = (name: string, body: unknown, credential = "broker", env = "development", org = "cap"): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: E(env, org), credential, body, masked: ["secret"] });
  const issueRaw = (name: string, rawBody: string, credential = "broker"): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: E(), credential, rawBody });
  // A body with an own "__proto__" member: JSON text, the key written as PROTO and renamed.
  const issueProto = (name: string, body: unknown): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: E(), credential: "broker", rawBody: JSON.stringify(body).replaceAll('"PROTO"', '"__proto__"'), masked: ["secret"] });
  const list = (name: string, credential: string, env = "development", org = "cap"): Omit<RequestCase, "id"> =>
    ({ name, method: "GET", path: E(env, org), credential });
  const revoke = (name: string, cap: string, credential = "broker", env = "development", org = "cap"): Omit<RequestCase, "id"> =>
    ({ name, method: "DELETE", path: `${E(env, org)}/${cap}`, credential });
  const exercise = (name: string, cap: string, body: unknown, credential = "broker", env = "development", org = "cap"): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${E(env, org)}/${cap}/exercises`, credential, body });
  const base = {
    agentIdentityId: "{idn:agent}", items: ["SECRET_A"], destinations: ["api.example.com"],
    targets: { SECRET_A: ["header:Authorization"] }, ttlSeconds: 600,
  };
  const pre = (env = "development", over: Record<string, unknown> = {}) => ({
    projectId: "{project:api}", environmentId: `{env:${env}}`, stateDigest: `{digest:${env}}`,
    stateDigests: { environment: `{digest:${env}:environment}`, contract: `{digest:${env}:contract}`, items: `{digest:${env}:items}`, rotation: `{digest:${env}:rotation}` },
    ...over,
  });
  const live = (over: Record<string, unknown> = {}) => ({
    capabilitySecret: SECRET("live"), destination: { host: "api.example.com", port: 443 },
    placements: [{ item: "SECRET_A", target: "header:authorization" }], ...over,
  });
  const ex = (cap: string, over: Record<string, unknown> = {}) => ({ ...live(over), capabilitySecret: SECRET(cap) });
  return withIds([
    // issueCapability.
    issue("issue", {
      agentIdentityId: "{idn:agent}", items: ["SECRET_B", "SECRET_A"], destinations: ["API.Example.com.", "*.svc.example:8443", "[::1]:8080", "10.0.0.1"],
      targets: { SECRET_B: ["header:X-Key"], SECRET_A: ["query:key", "header:Authorization", "json:/a~1b/0", "form:k"] }, ttlSeconds: 3600, runId: "run-1",
    }),
    issue("issue with an item twice", { ...base, items: ["SECRET_A", "SECRET_A"] }),
    issue("issue for an Agent without secret.use", { ...base, agentIdentityId: "{idn:nogrant}" }),
    issue("issue, the longest lifetime", { ...base, ttlSeconds: 86_400 }),
    issue("issue, an empty run id", { ...base, runId: "" }),
    issue("issue with a precondition", { ...base, items: ["SECRET_A", "SECRET_NOVAL", "PLAIN_URL"], targets: { SECRET_A: ["header:a"], SECRET_NOVAL: ["header:b"], PLAIN_URL: ["header:c"] }, precondition: pre() }),
    issue("issue with a precondition, an Agent without secret.use", { ...base, agentIdentityId: "{idn:nogrant}", precondition: pre() }),
    issue("issue with a precondition, a Requirement", { ...base, precondition: pre("production") }, "broker", "production"),
    issue("issue with a precondition, two categories changed", { ...base, precondition: pre("development", { stateDigest: STALE, stateDigests: { environment: "{digest:development:environment}", contract: "{digest:development:contract}", items: STALE, rotation: STALE } }) }),
    issue("issue with a precondition, only the digest changed", { ...base, precondition: pre("development", { stateDigest: STALE }) }),
    issue("issue with a precondition naming another environment", { ...base, precondition: pre("production") }),
    issue("issue with a precondition, U+0000 in the Agent", { ...base, agentIdentityId: "a\u0000b", precondition: pre() }),
    issue("issue with a precondition, an unknown Agent", { ...base, agentIdentityId: "idn_unknownaaaaaaaaaaaaaaaaaaa", precondition: pre() }),
    issue("issue, a precondition without a category", { ...base, precondition: { ...pre(), stateDigests: { environment: STALE } } }),
    issue("issue, a precondition with another category", { ...base, precondition: { ...pre(), stateDigests: { ...pre().stateDigests, other: STALE, "1": STALE } } }),
    issue("issue, a precondition with bad digests", { ...base, precondition: { ...pre(), stateDigest: "sha256:XYZ", stateDigests: { ...pre().stateDigests, rotation: "md5:1" } } }),
    issue("issue, a precondition's digests as an array", { ...base, precondition: { ...pre(), stateDigests: [] } }),
    issue("issue, no targets", { ...base, targets: undefined }),
    issue("issue, targets naming another item", { ...base, targets: { SECRET_A: ["header:a"], OTHER: ["header:b"] } }),
    issue("issue, an item without a target", { ...base, items: ["SECRET_A", "SECRET_B"] }),
    issue("issue, five targets", { ...base, targets: { SECRET_A: ["header:a", "header:b", "header:c", "header:d", "header:e"] } }),
    issue("issue, nine targets", { ...base, targets: { SECRET_A: Array.from({ length: 9 }, (_, i) => `header:h${i}`) } }),
    issue("issue, a target repeated", { ...base, targets: { SECRET_A: ["header:X-A", "header:x-a"] } }),
    issue("issue, a transport-owned header", { ...base, targets: { SECRET_A: ["header:Content-Type"] } }),
    issue("issue, an x-forwarded header", { ...base, targets: { SECRET_A: ["header:X-Forwarded-For"] } }),
    issue("issue, a bad header name", { ...base, targets: { SECRET_A: ["header:a b"] } }),
    issue("issue, an empty query name", { ...base, targets: { SECRET_A: ["query:"] } }),
    issue("issue, a form name of 257 characters", { ...base, targets: { SECRET_A: [`form:${"f".repeat(257)}`] } }),
    issue("issue, a form name of 256 characters, astral", { ...base, targets: { SECRET_A: [`form:${"\u{1F600}".repeat(128)}`] } }),
    issue("issue, a control character", { ...base, targets: { SECRET_A: ["query:a\u0007"] } }),
    issue("issue, a JSON Pointer without /", { ...base, targets: { SECRET_A: ["json:a"] } }),
    issue("issue, a bad ~ escape", { ...base, targets: { SECRET_A: ["json:/a~2"] } }),
    issue("issue, a ~ at the end", { ...base, targets: { SECRET_A: ["json:/a~"] } }),
    issue("issue, an unknown kind", { ...base, targets: { SECRET_A: ["cookie:a"] } }),
    issue("issue, no kind", { ...base, targets: { SECRET_A: ["authorization"] } }),
    issue("issue, a JSON Pointer with U+0000", { ...base, targets: { SECRET_A: ["json:/a\u0000"] } }),
    issue("issue, a query name with a lone surrogate", { ...base, targets: { SECRET_A: ["query:\ud800"] } }),
    issue("issue, a __proto__ target member", { ...base, targets: JSON.parse('{"__proto__":["header:p"],"SECRET_A":["header:a"]}') }),
    issueProto("issue, a __proto__ target member alone", { ...base, targets: { PROTO: ["header:p"] } }),
    issueProto("issue, a __proto__ target member that is not an array, beside an item", { ...base, targets: { PROTO: "bad", SECRET_A: ["header:a"] } }),
    issueProto("issue, a precondition's digests with a __proto__ member", { ...base, precondition: { ...pre(), stateDigests: { ...pre().stateDigests, PROTO: STALE } } }),
    issueProto("issue, a precondition's digests with only a __proto__ member", { ...base, precondition: { ...pre(), stateDigests: { PROTO: STALE } } }),
    issue("issue, targets as an array", { ...base, targets: [] }),
    issue("issue, targets null", { ...base, targets: null }),
    issue("issue, a target that is not a string", { ...base, targets: { SECRET_A: [1] } }),
    issue("issue, an invalid item name", { ...base, items: ["lower"], targets: { lower: ["header:a"] } }),
    issue("issue, an invalid destination", { ...base, destinations: ["https://api.example.com/x"] }),
    issue("issue, a destination wildcard in the middle", { ...base, destinations: ["a.*.example.com"] }),
    issue("issue, no items", { ...base, items: [] }),
    issue("issue, an empty item", { ...base, items: [""] }),
    issue("issue, 201 items", { ...base, items: Array.from({ length: 201 }, (_, i) => `I${i}`) }),
    issue("issue, 51 destinations", { ...base, destinations: Array.from({ length: 51 }, (_, i) => `d${i}.example.com`) }),
    issue("issue, a lifetime of a day and a second", { ...base, ttlSeconds: 86_401 }),
    issue("issue, a lifetime of 0", { ...base, ttlSeconds: 0 }),
    issue("issue, a negative lifetime", { ...base, ttlSeconds: -5 }),
    issue("issue, a fractional lifetime", { ...base, ttlSeconds: 1.5 }),
    issue("issue, a lifetime as a string", { ...base, ttlSeconds: "60" }),
    issue("issue, a lifetime beyond the safe integers", { ...base, ttlSeconds: 1e300 }),
    issueRaw("issue, a lifetime of -Infinity", JSON.stringify({ ...base, ttlSeconds: 0 }).replace('"ttlSeconds":0', '"ttlSeconds":-1e400')),
    issue("issue, a run id of 201 characters", { ...base, runId: "r".repeat(201) }),
    issue("issue, a run id with U+0000", { ...base, runId: "r\u0000" }),
    issue("issue, a run id with a lone surrogate", { ...base, runId: "r\ud800" }),
    issue("issue, every member wrong", { agentIdentityId: 1, items: "SECRET_A", destinations: [1], targets: { A: "x" }, ttlSeconds: null, runId: 2 }),
    issue("issue, no body members", {}),
    issueRaw("issue, a body that is not JSON", "{"),
    issue("issue for an unknown Agent", { ...base, agentIdentityId: "idn_unknownaaaaaaaaaaaaaaaaaaa" }),
    issue("issue for a service", { ...base, agentIdentityId: "{idn:svc}" }),
    issue("issue for a disabled Agent", { ...base, agentIdentityId: "{idn:off}" }),
    issue("issue for another Organization's Agent", { ...base, agentIdentityId: "{idn:oagent}" }),
    issue("issue, U+0000 in the Agent", { ...base, agentIdentityId: "a\u0000b" }),
    issue("issue as a person", base, "alice"),
    issueRaw("issue as a person, a body that is not JSON", "{", "alice"),
    issue("issue as a service", base, "svc"),
    issue("issue as another Organization's Broker", base, "obroker"),
    issue("issue in an unknown environment", base, "broker", "staging"),
    issue("issue in a frozen Organization", { ...base, agentIdentityId: "{idn:fagent}" }, "fbroker", "development", "frozen"),
    issue("issue in an Organization being deleted", { ...base, agentIdentityId: "{idn:dagent}" }, "dbroker", "development", "deleting"),
    issue("issue in an Organization being deleted, an invalid item", { ...base, agentIdentityId: "{idn:dagent}", items: ["x"] }, "dbroker", "development", "deleting"),

    // listCapabilities: a Broker's own; anyone else policy.read.
    list("list as the Broker", "broker"),
    list("list as the other Broker", "broker2"),
    list("list as the Installation Admin", "alice"),
    list("list as a member", "bob"),
    list("list as an outsider", "carol"),
    list("list as a service", "svc"),
    list("list as another Organization's Broker", "obroker"),
    list("list production", "alice", "production"),
    list("list in a frozen Organization", "fbroker", "development", "frozen"),
    list("list in an Organization being deleted", "dbroker", "development", "deleting"),
    list("list in an unknown environment", "broker", "staging"),

    // exerciseCapability.
    exercise("exercise", "{cap:live}", live({ placements: [
      { item: "SECRET_B", target: "header:x-key" }, { item: "SECRET_A", target: "header:authorization" }, { item: "SECRET_A", target: "query:key" },
    ] })),
    exercise("exercise with references", "{cap:live}", live({ placements: [{ item: "SECRET_REF", target: "header:x-ref" }, { item: "SECRET_SREF", target: "header:x-sref" }] })),
    exercise("exercise a bound Secret without a value", "{cap:live}", live({ placements: [{ item: "SECRET_NOVAL", target: "header:x-noval" }, { item: "SECRET_A", target: "header:authorization" }] })),
    exercise("exercise through a wildcard", "{cap:live}", live({ destination: { host: "Deep.A.svc.example", port: 8443 } })),
    exercise("exercise, the wildcard's apex", "{cap:live}", live({ destination: { host: "svc.example", port: 8443 } })),
    exercise("exercise, another port", "{cap:live}", live({ destination: { host: "api.example.com", port: 80 } })),
    exercise("exercise, an IP literal", "{cap:live}", live({ destination: { host: "127.0.0.1", port: 443 } })),
    exercise("exercise, a placement it does not hold", "{cap:live}", live({ placements: [{ item: "SECRET_A", target: "header:x-other" }] })),
    exercise("exercise, a placement of another item", "{cap:live}", live({ placements: [{ item: "SECRET_UNBOUND", target: "header:x" }] })),
    exercise("exercise, a placement named constructor", "{cap:live}", live({ placements: [{ item: "constructor", target: "header:x" }] })),
    exercise("exercise, a placement named toString", "{cap:live}", live({ placements: [{ item: "toString", target: "header:x" }] })),
    exercise("exercise, no placements", "{cap:live}", live({ placements: [] })),
    exercise("exercise, placements absent", "{cap:live}", { capabilitySecret: SECRET("live"), destination: { host: "api.example.com", port: 443 } }),
    exercise("exercise, a reference to an unbound Secret", "{cap:live}", live({ placements: [{ item: "SECRET_UNB_REF", target: "header:x-unb" }] })),
    exercise("exercise, a reference to nothing", "{cap:live}", live({ placements: [{ item: "SECRET_MISS", target: "header:x-miss" }] })),
    exercise("exercise, a reference to itself", "{cap:live}", live({ placements: [{ item: "SECRET_LOOP", target: "header:x-loop" }] })),
    exercise("exercise, a wrong secret", "{cap:live}", live({ capabilitySecret: "vlt_cap_wrong" })),
    exercise("exercise as the other Broker", "{cap:live}", live(), "broker2"),
    exercise("exercise as a person", "{cap:live}", live(), "alice"),
    exercise("exercise as a person, an empty body", "{cap:live}", {}, "alice"),
    exercise("exercise as a service", "{cap:live}", live(), "svc"),
    exercise("exercise as another Organization's Broker", "{cap:live}", live(), "obroker"),
    exercise("exercise in another environment", "{cap:live}", live(), "broker", "production"),
    exercise("exercise an unknown Capability", "cap_unknownaaaaaaaaaaaaaaaaaaa", live()),
    exercise("exercise, U+0000 in the Capability", "a%00b", live()),
    exercise("exercise a revoked Capability", "{cap:revoked}", ex("revoked")),
    exercise("exercise an expired Capability", "{cap:expired}", ex("expired")),
    exercise("exercise a Capability without targets", "{cap:untargeted}", ex("untargeted")),
    exercise("exercise for an Agent who may not read plain values", "{cap:noread}", ex("noread", { placements: [{ item: "SECRET_REF", target: "header:x-ref" }] })),
    exercise("exercise for an Agent who may not read plain values, no reference", "{cap:noread}", ex("noread")),
    exercise("exercise for an Agent without secret.use", "{cap:nogrant}", ex("nogrant")),
    exercise("exercise another Broker's Capability", "{cap:theirs}", ex("theirs"), "broker2"),
    exercise("exercise under a Requirement", "{cap:prod}", ex("prod"), "broker", "production"),
    exercise("exercise in a frozen Organization", "{cap:frozen}", ex("frozen"), "fbroker", "development", "frozen"),
    exercise("exercise in an Organization being deleted", "{cap:deleting}", ex("deleting"), "dbroker", "development", "deleting"),
    exercise("exercise, no secret", "{cap:live}", { destination: { host: "api.example.com", port: 443 } }),
    exercise("exercise, an empty secret", "{cap:live}", live({ capabilitySecret: "" })),
    exercise("exercise, port 0", "{cap:live}", live({ destination: { host: "api.example.com", port: 0 } })),
    exercise("exercise, port 65536", "{cap:live}", live({ destination: { host: "api.example.com", port: 65_536 } })),
    exercise("exercise, a port as a string", "{cap:live}", live({ destination: { host: "api.example.com", port: "443" } })),
    exercise("exercise, a fractional port", "{cap:live}", live({ destination: { host: "api.example.com", port: 443.5 } })),
    exercise("exercise, an empty host", "{cap:live}", live({ destination: { host: "", port: 443 } })),
    exercise("exercise, no destination", "{cap:live}", { capabilitySecret: SECRET("live") }),
    exercise("exercise, an empty placement", "{cap:live}", live({ placements: [{ item: "", target: "" }] })),
    exercise("exercise, 201 placements", "{cap:live}", live({ placements: Array.from({ length: 201 }, () => ({ item: "SECRET_A", target: "header:authorization" })) })),
    exercise("exercise, a host with U+0000", "{cap:live}", live({ destination: { host: "a\u0000b", port: 443 } })),
    { name: "exercise, a body that is not JSON", method: "POST", path: `${E()}/{cap:live}/exercises`, credential: "broker", rawBody: "{" },
    { name: "exercise as a person, a body that is not JSON", method: "POST", path: `${E()}/{cap:live}/exercises`, credential: "alice", rawBody: "{" },

    // A later Grant change: the Agent's Grant removed, the same exercise denied.
    exercise("exercise before the Agent's Grant is removed", "{cap:theirs}", ex("theirs"), "broker2"),
    { name: "remove the Agent's Grant", method: "DELETE", path: `${ORG}/cap/grants/{grant:agent}`, credential: "alice" },
    exercise("exercise after the Agent's Grant was removed", "{cap:theirs}", ex("theirs"), "broker2"),

    // revokeCapability: a Broker's own; anyone else policy.manage.
    revoke("revoke as a member", "{cap:theirs}", "bob"),
    revoke("revoke as an outsider", "{cap:theirs}", "carol"),
    revoke("revoke another Broker's Capability", "{cap:theirs}"),
    revoke("revoke", "{cap:live}"),
    revoke("revoke again", "{cap:live}"),
    exercise("exercise after the revocation", "{cap:live}", live()),
    revoke("revoke as the Installation Admin, through another environment", "{cap:theirs}", "alice", "production"),
    revoke("revoke an unknown Capability", "cap_unknownaaaaaaaaaaaaaaaaaaa"),
    revoke("revoke, U+0000 in the Capability", "a%00b"),
    revoke("revoke as a service", "{cap:noread}", "svc"),
    revoke("revoke in an unknown environment", "{cap:noread}", "broker", "staging"),
    revoke("revoke in a frozen Organization", "{cap:frozen}", "fbroker", "development", "frozen"),
    revoke("revoke in an Organization being deleted", "{cap:deleting}", "dbroker", "development", "deleting"),
    list("list as the Installation Admin afterwards", "alice"),
  ]);
}

/** Fills a request's placeholders from the file's rows and digests. */
function fillPath(rows: Fixture["rows"], digests: Digests): (p: string) => string {
  const org = (slug: string) => rows.organizations!.find((o) => o.slug === slug)!.id as string;
  const project = rows.projects!.find((p) => p.organization_id === org("cap") && p.slug === "api")!;
  const resolve = (kind: string, arg: string): string => {
    switch (kind) {
      case "idn":
        return rows.identities!.find((i) => i.name === arg)!.id as string;
      case "cap":
        return rows.capabilities!.find((c) => c.run_id === `known-${arg}`)!.id as string;
      case "grant": {
        const subject = rows.identities!.find((i) => i.name === arg)!.id;
        return rows.grants!.find((g) => g.subject_identity_id === subject)!.id as string;
      }
      case "project":
        return project.id as string;
      case "env":
        return rows.environments!.find((e) => e.project_id === project.id && e.name === arg)!.id as string;
      case "digest": {
        const [env, category] = arg.split(":") as [string, string | undefined];
        return category ? digests[env]!.stateDigests[category]! : digests[env]!.stateDigest;
      }
    }
    throw new Error(`unknown placeholder ${kind}`);
  };
  return (p) => p.replace(/\{(idn|cap|grant|project|env|digest):([^}]+)\}/g, (_, kind: string, arg: string) => resolve(kind, arg));
}

type Digests = Record<string, { stateDigest: string; stateDigests: Record<string, string> }>;
type Call = (method: string, path: string, body?: unknown, token?: string) => Promise<any>;

const item = (name: string, sensitive: boolean) => ({ name, required: { kind: "never" }, sensitive, type: "string" });

async function build(): Promise<{ ctx: AppCtx & { close: () => Promise<void> }; tokens: Record<string, string>; digests: Digests }> {
  const db = await migratedTestDb();
  const ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId: alice } = await consumeSetupGrant(ctx, grant.token, { adminName: "Alice" });
  const tokens: Record<string, string> = { alice: (await issueCredential(ctx.db, { identityId: alice, kind: "cli" })).token };
  const app = buildApp(ctx, { publicUrl: "http://127.0.0.1:8686" });
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
  for (const slug of ["cap", "frozen", "deleting", "other"]) {
    orgs[slug] = (await call("POST", ORG, { name: slug[0]!.toUpperCase() + slug.slice(1), slug })).id;
  }
  for (const [name, member] of [["bob", true], ["carol", false]] as const) {
    const id = newId("identity");
    await db.query("INSERT INTO identities (id, kind, name, created_at) VALUES ($1, 'human', $2, '2026-01-01T00:00:00.000Z')", [id, name]);
    if (member) await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, $2, 'member')", [orgs.cap, id]);
    tokens[name] = (await issueCredential(ctx.db, { identityId: id, kind: "cli" })).token;
  }
  const ids: Record<string, string> = {};
  const machine = async (org: string, name: string, kind: string) => {
    const m = await call("POST", `${ORG}/${org}/identities`, { name, kind });
    ids[name] = m.id;
    tokens[name] = m.credential;
    return m.id as string;
  };
  await machine("cap", "broker", "broker");
  await machine("cap", "broker2", "broker");
  await machine("cap", "svc", "service");
  for (const name of ["agent", "noread", "nogrant", "off"]) await machine("cap", name, "agent");
  await db.query("UPDATE identities SET disabled = true WHERE id = $1", [ids.off]);
  await machine("other", "obroker", "broker");
  await machine("other", "oagent", "agent");

  // cap's Project: development and production, a Contract, values.
  const P = `${ORG}/cap/projects/api`;
  const project = await call("POST", `${ORG}/cap/projects`, { name: "API", slug: "api", contractAuthority: "git" });
  for (const tier of ["development", "production"]) await call("POST", `${P}/environments`, { name: tier, tier });
  const rev = await call("POST", `${P}/contract/revisions`, {
    contract: {
      schemaVersion: 1,
      items: [
        ...["SECRET_A", "SECRET_B", "SECRET_REF", "SECRET_SREF", "SECRET_NOVAL", "SECRET_UNBOUND", "SECRET_UNB_REF", "SECRET_MISS", "SECRET_LOOP"].map((n) => item(n, true)),
        item("PLAIN_URL", false), item("PLAIN_HOST", false),
      ],
    },
  });
  await call("POST", `${P}/contract/revisions/${rev.id}/activate`);
  const V = (env: string, name: string) => `${P}/environments/${env}/values/${name}`;
  for (const [env, name, value] of [
    ["development", "SECRET_A", "a-secret"],
    ["development", "SECRET_B", "b-old"],
    ["development", "SECRET_REF", "${PLAIN_URL}/v1"],
    ["development", "SECRET_SREF", "pre-${SECRET_B}-$${ESCAPED}"],
    ["development", "SECRET_UNBOUND", "unbound"],
    ["development", "SECRET_UNB_REF", "x-${SECRET_UNBOUND}"],
    ["development", "SECRET_MISS", "x-${NOPE}"],
    ["development", "SECRET_LOOP", "loop-${SECRET_LOOP}"],
    ["development", "PLAIN_URL", "https://${PLAIN_HOST}"],
    ["development", "PLAIN_HOST", "api.example.com"],
    ["production", "SECRET_A", "prod-a"],
  ] as const) {
    await call("PUT", V(env, name), { value });
  }
  // SECRET_B in a rotation, its window open until 2099.
  await call("POST", `${V("development", "SECRET_B")}/rotations`, { value: "b-new" });
  await db.query(
    `UPDATE env_values SET rotation_deadline = '2099-06-01T00:00:00.000Z' WHERE item_name = 'SECRET_B'
       AND environment_id = (SELECT id FROM environments WHERE project_id = $1 AND name = 'development')`,
    [project.id],
  );
  const envId = async (orgId: string, name: string) =>
    (await db.query("SELECT e.id FROM environments e JOIN projects p ON p.id = e.project_id WHERE p.organization_id = $1 AND p.slug = 'api' AND e.name = $2", [orgId, name])).rows[0].id as string;

  // Grants: agent may use and read across the Project; noread may only use.
  const projectGrant = (subject: string, actions: string[]) =>
    call("POST", `${ORG}/cap/grants`, { subjectIdentityId: subject, scope: { kind: "project", projectId: project.id }, actions });
  await projectGrant(ids.agent!, ["secret.use", "config.value.read"]);
  await projectGrant(ids.noread!, ["secret.use"]);
  await call("POST", `${ORG}/cap/requirements`, { kind: "tailnet", target: { kind: "tier", tier: "production" }, selector: { tailnet: "cap.ts.net", tags: ["tag:prod"] } });

  // frozen and deleting: a Broker, an Agent and a Project each.
  for (const slug of ["frozen", "deleting"]) {
    await machine(slug, `${slug[0]}broker`, "broker");
    await machine(slug, `${slug[0]}agent`, "agent");
    await call("POST", `${ORG}/${slug}/projects`, { name: "API", slug: "api", contractAuthority: "git" });
    await call("POST", `${ORG}/${slug}/projects/api/environments`, { name: "development", tier: "development" });
  }

  // The Capabilities, with known secrets.
  const capability = async (name: string, org: string, env: string, broker: string, agent: string, extra: { targets?: unknown; expires?: string; revoked?: string } = {}) => {
    const projectId = (await db.query("SELECT id FROM projects WHERE organization_id = $1 AND slug = 'api'", [orgs[org]])).rows[0].id;
    const targets = extra.targets === undefined
      ? {
          SECRET_A: ["header:authorization", "query:key"], SECRET_B: ["header:x-key"], SECRET_REF: ["header:x-ref"], SECRET_SREF: ["header:x-sref"],
          SECRET_NOVAL: ["header:x-noval"], SECRET_UNB_REF: ["header:x-unb"], SECRET_MISS: ["header:x-miss"], SECRET_LOOP: ["header:x-loop"],
        }
      : extra.targets;
    await db.query(
      `INSERT INTO capabilities (id, organization_id, broker_identity_id, agent_identity_id, project_id, environment_id, items, destinations,
         targets, secret_hash, run_id, expires_at, revoked_at, created_by, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $3, '2026-02-01T00:00:00.000Z')`,
      [
        newId("capability"), orgs[org], ids[broker], ids[agent], projectId, await envId(orgs[org]!, env),
        ["SECRET_A", "SECRET_B", "SECRET_REF", "SECRET_SREF", "SECRET_NOVAL", "SECRET_UNB_REF", "SECRET_MISS", "SECRET_LOOP"],
        ["api.example.com:443", "*.svc.example:8443"],
        targets === null ? null : JSON.stringify(targets), createHash("sha256").update(SECRET(name), "utf8").digest("hex"), `known-${name}`,
        extra.expires ?? "2099-01-01T00:00:00.000Z", extra.revoked ?? null,
      ],
    );
  };
  await capability("live", "cap", "development", "broker", "agent");
  await capability("revoked", "cap", "development", "broker", "agent", { revoked: "2026-02-02T00:00:00.000Z" });
  await capability("expired", "cap", "development", "broker", "agent", { expires: "2026-01-01T00:00:00.000Z" });
  await capability("untargeted", "cap", "development", "broker", "agent", { targets: null });
  await capability("noread", "cap", "development", "broker", "noread");
  await capability("nogrant", "cap", "development", "broker", "nogrant");
  await capability("theirs", "cap", "development", "broker2", "agent");
  await capability("prod", "cap", "production", "broker", "agent");
  await capability("frozen", "frozen", "development", "fbroker", "fagent");
  await capability("deleting", "deleting", "development", "dbroker", "dagent");

  // The freeze and the deletion, last.
  await db.query(
    "INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', 'incident drill')",
    [newId("organizationFreeze"), orgs.frozen, alice],
  );
  await db.query(
    "INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', '2099-03-01T00:00:00.000Z', false)",
    [newId("organizationDeletion"), orgs.deleting, alice],
  );

  // The digests a precondition names: the rows' own.
  const digests: Digests = {};
  for (const env of ["development", "production"]) {
    const r = await call("POST", `${P}/environments/${env}/retrievals`, { mode: "preflight" });
    digests[env] = { stateDigest: r.stateDigest, stateDigests: r.stateDigests };
  }
  await accessCountsSettled();
  return { ctx, tokens, digests };
}

type CapabilitiesFixture = Fixture & { digests: Digests };

/** The file's answers, recorded on its own rows. */
async function replay(f: CapabilitiesFixture): Promise<Awaited<ReturnType<typeof record>>> {
  const db = await loadRows(f.rows, TABLES);
  await db.query("UPDATE audit_position SET value = (SELECT coalesce(max(event_order), 0) FROM audit_events) WHERE singleton");
  try {
    const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex") };
    return await record(ctx, buildApp(ctx, { publicUrl: "http://127.0.0.1:8686" }), f, f.requests, fillPath(f.rows, f.digests));
  } finally {
    await db.close();
  }
}

describe.skipIf(process.env.VARLATCH_WRITE_GO_VECTORS !== "1")("writing the fixture", () => {
  it("builds the database, records the answers and writes the file", async () => {
    const { ctx, tokens, digests } = await build();
    try {
      const draft: CapabilitiesFixture = {
        comment: "Written by services/varlatchd/test/go-capabilities-fixture.test.ts from the TypeScript server's own answers; do not edit.",
        ref: "v0.22.0",
        serverVersion: SERVER_VERSION,
        rootKek: ctx.rootKek.toString("hex"),
        tokens,
        digests,
        rows: await exportRows(ctx.db, TABLES),
        sideTables: SIDE,
        requests: requestTable().map((c) => ({ ...c, expect: { status: 0, headers: {}, body: "" }, audit: [], side: {} })),
        counters: [],
      };
      const fixture = { ...draft, ...(await replay(draft)) };
      writeFileSync(FILE, JSON.stringify(fixture, null, 2) + "\n");
    } finally {
      await ctx.close();
    }
  }, 600_000);
});

describe("the capabilities fixture is this server's answers", () => {
  it("capabilities-v0.22.0.json", async () => {
    const f = JSON.parse(readFileSync(FILE, "utf8")) as CapabilitiesFixture;
    expect(f.serverVersion).toBe(SERVER_VERSION);
    expectCurrentTable(f, requestTable());
    expect(f.sideTables).toEqual(SIDE);
    expectSameAnswers(f, await replay(f));
    // The table reaches what it must: an issuance, an exercise with a
    // rotation's retiring value and expanded references, every denial.
    const status = (name: string) => f.requests.find((r) => r.name === name)!.expect.status;
    expect(status("issue")).toBe(201);
    expect(status("issue with a precondition")).toBe(201);
    expect(status("issue with a precondition, two categories changed")).toBe(409);
    expect(status("exercise")).toBe(200);
    expect(status("exercise with references")).toBe(200);
    expect(status("exercise before the Agent's Grant is removed")).toBe(200);
    expect(status("exercise after the Agent's Grant was removed")).toBe(403);
    expect(f.requests.find((r) => r.name === "exercise")!.expect.body).toContain("retiring");
    for (const reason of ["revoked", "expired", "destination-mismatch", "capability-without-targets", "placement-not-targeted", "authz-denied", "unresolved-reference"]) {
      expect(f.requests.some((r) => r.expect.body.includes(`"reason":"${reason}"`)), reason).toBe(true);
    }
    const { ctx } = await build();
    try {
      expectSameRows(TABLES, f.rows, await exportRows(ctx.db, TABLES));
    } finally {
      await ctx.close();
    }
  }, 300_000);
});
