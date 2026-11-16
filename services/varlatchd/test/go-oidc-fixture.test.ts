// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.8's parity fixture (ADR-0059 step 4, feature-parity decision 3),
 * on the parity kit (go-fixture-kit.ts): OIDC workload identity, built
 * through this server's own /v1 API, and a table of requests with this
 * server's answers: listOidcBindings, createOidcBinding, revokeOidcBinding
 * and exchangeOidcToken. go/server/oidc's parity test replays it against
 * varlatchd.
 *
 * The issuers answer through the app's oidcFetch (OIDCFetch in Go):
 * https://issuer.example serves its discovery document and a JWKS of the
 * key that signed the file's tokens; https://down.example answers 503;
 * https://refused.example goes to the outbound policy, which refuses it
 * (its name resolves to a private address). The file keeps every URL each
 * request fetched (`fetched`), which must be the same: the verifier's
 * caches run across the table, as a server's do.
 *
 * The database: alice (the bootstrap admin) and her second CLI credential
 * (alice2, whose approval intents bind exact requests); acme, with machine
 * identities deployer, worker and other (ci and service), a retired one,
 * their bindings, and bob (a member); enf, admin-step-up at enforce; frozen,
 * an identity with a binding, then an incident freeze. The tokens are
 * signed when the file is written and kept in it (`oidc.tokens`); the table
 * names them as {oidc:<name>}.
 *
 * After a change, regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-oidc-fixture.test.ts
 */
import { createSign, generateKeyPairSync } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { clearJwksCache } from "../src/auth/oidc.js";
import { generateKey } from "../src/crypto/aead.js";
import { newId } from "../src/db/ids.js";
import { approvalHash, canonicalJson, type ApprovalBinding } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { oidcBindingCreateBinding, oidcBindingDeleteBinding } from "../src/domain/identitystepup.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { OutboundPolicy, type Resolver } from "../src/net/outbound.js";
import { migratedTestDb } from "./helpers/pglite.js";
import {
  expectCurrentTable, expectSameAnswers, expectSameRows, exportRows, loadRows, record, withIds,
  type Fixture, type RawAnswer, type RequestCase, type SideTable, type Table,
} from "./go-fixture-kit.js";

const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const FILE = new URL("../../../go/server/paritytest/testdata/oidc-v0.22.0.json", import.meta.url);

export const PUBLIC_URL = "http://127.0.0.1:8686";
const ISSUER = "https://issuer.example";
const DOWN = "https://down.example";
const REFUSED = "https://refused.example";
/** The names the fixture's outbound policy resolves (Go: the same). */
const RESOLVE: Record<string, { address: string; family: 4 | 6 }[]> = {
  "issuer.example": [{ address: "93.184.215.14", family: 4 }],
  "down.example": [{ address: "93.184.215.15", family: 4 }],
  "refused.example": [{ address: "10.0.0.9", family: 4 }],
};
const resolve: Resolver = async (name) => {
  const a = RESOLVE[name];
  if (!a) throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${name}`), { code: "ENOTFOUND" });
  return a;
};

const TABLES: Table[] = [
  { name: "installation", orderBy: "id", random: ["kek_canary"] },
  { name: "identities", orderBy: "id" },
  { name: "credentials", orderBy: "id", random: ["token_hash"] },
  { name: "organizations", orderBy: "id", random: ["wrapped_org_kek"] },
  { name: "org_memberships", orderBy: "organization_id, identity_id" },
  { name: "security_controls", orderBy: "organization_id, control" },
  { name: "security_control_counters", orderBy: "organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour" },
  { name: "approval_intents", orderBy: "id", random: ["body_hash", "query_hash"] },
  { name: "organization_freezes", orderBy: "id" },
  { name: "oidc_bindings", orderBy: "id" },
];

const SIDE: SideTable[] = [
  { name: "oidc_bindings", key: ["id"], sortBy: ["organization_id", "identity_id", "issuer", "subject"], volatile: ["created_at", "revoked_at"] },
  {
    name: "credentials", key: ["id"], sortBy: ["identity_id", "kind", "name"],
    volatile: ["token_hash", "created_at", "expires_at", "revoked_at", "last_used_at"],
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
const aprId = (s: string) => `apr_${s.padEnd(26, "a")}`;
const APPROVALS = { create: aprId("oidccreate"), revoke: aprId("oidcrevoke") } as const;
const ENF_BINDING = { issuer: ISSUER, audience: "varlatch", subject: "enf:*" };

/** The table of requests. {deployer}, {worker}, {alice}, {b8}, {fb1}, {eci}, {eb1} and {acmeId} are filled from the rows. */
function requestTable(): RequestCase[] {
  const bindings = (identity: string, org = "acme") => `${ORG}/${org}/identities/${identity}/oidc-bindings`;
  const list = (name: string, identity: string, credential = "alice", org = "acme"): Omit<RequestCase, "id"> =>
    ({ name, method: "GET", path: bindings(identity, org), credential });
  const create = (name: string, body: unknown, extra: Partial<RequestCase> = {}): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: bindings("{deployer}"), credential: "alice", ...(body === undefined ? {} : { body }), ...extra });
  const revoke = (name: string, identity: string, binding: string, extra: Partial<RequestCase> = {}): Omit<RequestCase, "id"> =>
    ({ name, method: "DELETE", path: `${bindings(identity)}/${binding}`, credential: "alice", ...extra });
  const exchange = (name: string, body: unknown, extra: Partial<RequestCase> = {}): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: "/v1/oidc/token", credential: "none", ...(body === undefined ? {} : { body }), masked: ["token"], ...extra });
  const token = (t: string, organization = "acme", more: Record<string, unknown> = {}) => ({ token: `{oidc:${t}}`, organization, ...more });
  const good = { issuer: ISSUER, audience: "aud-new", subject: "new:*" };
  const approval = (id: string) => ({ credential: "alice2", headers: { "Varlatch-Approval": id } });
  return withIds([
    // listOidcBindings: identity.manage, a machine identity, inspection while frozen.
    list("list", "{deployer}"),
    list("list as a member", "{deployer}", "bob"),
    list("list a person's", "{alice}"),
    list("list an unknown identity's", "idn_unknownaaaaaaaaaaaaaaaaaa"),
    list("list in a frozen Organization", "{fci}", "alice", "frozen"),

    // createOidcBinding: zod, the issuer's validation, the policy, then the protected operation.
    create("create, not JSON", undefined, { rawBody: "{nope" }),
    create("create, an empty body", {}),
    create("create, claims that are an array", { ...good, claims: [] }),
    create("create, a claim that is a number", { ...good, claims: { n: 1, "2": "x" } }),
    create("create, an empty issuer", { ...good, issuer: "" }),
    create("create, an issuer that is not a URL", { ...good, issuer: "not a url" }),
    create("create, an http issuer", { ...good, issuer: "http://issuer.example" }),
    create("create, an issuer with a query", { ...good, issuer: "https://issuer.example/?x=1" }),
    create("create, an issuer at a private address", { ...good, issuer: "https://10.0.0.5" }),
    create("create", { ...good, claims: { ref: "refs/heads/main", "1": "one", env: "prod" }, extra: true }),
    create("create, no claims", { ...good, subject: "plain" }),
    create("create as a member", good, { credential: "bob" }),
    { ...create("create for a person", good), path: bindings("{alice}") },
    { ...create("create in a frozen Organization", good), path: bindings("{fci}", "frozen") },
    { ...create("create under enforce", ENF_BINDING), path: bindings("{eci}", "enf") },
    { ...create("create under enforce, its approval", ENF_BINDING, approval(APPROVALS.create)), path: bindings("{eci}", "enf") },

    // revokeOidcBinding.
    revoke("revoke", "{deployer}", "{b8}"),
    revoke("revoke again", "{deployer}", "{b8}"),
    revoke("revoke an unknown binding", "{deployer}", "oib_unknownaaaaaaaaaaaaaaaaaa"),
    revoke("revoke another identity's binding", "{worker}", "{b8}"),
    { ...revoke("revoke in a frozen Organization", "{fci}", "{fb2}"), path: `${bindings("{fci}", "frozen")}/{fb2}` },
    { ...revoke("revoke under enforce", "{eci}", "{eb1}"), path: `${bindings("{eci}", "enf")}/{eb1}` },
    { ...revoke("revoke under enforce, its approval", "{eci}", "{eb1}", approval(APPROVALS.revoke)), path: `${bindings("{eci}", "enf")}/{eb1}` },

    // exchangeOidcToken.
    exchange("exchange, not JSON", undefined, { rawBody: "{nope" }),
    exchange("exchange, an empty body", {}),
    exchange("exchange, a ttl of 0", token("good", "acme", { ttlSeconds: 0 })),
    exchange("exchange, a fractional ttl", token("good", "acme", { ttlSeconds: 1.5 })),
    exchange("exchange, a ttl over an hour", token("good", "acme", { ttlSeconds: 3601 })),
    exchange("exchange, a malformed token", { token: "nope", organization: "acme" }),
    exchange("exchange, an unknown issuer", token("unknownIssuer")),
    exchange("exchange, an unknown Organization", token("good", "nope")),
    exchange("exchange", token("good")),
    exchange("exchange by the Organization's id, an hour", token("good", "{acmeId}", { ttlSeconds: 3600 })),
    exchange("exchange, an audience in an array", token("audArray", "acme", { ttlSeconds: 60 })),
    exchange("exchange, another audience", token("wrongAudience")),
    exchange("exchange, the claims a binding asks for", token("worker")),
    exchange("exchange, a claim that differs", token("workerOtherEnv")),
    exchange("exchange, bindings of two identities", token("shared")),
    exchange("exchange, an expired token", token("expired")),
    exchange("exchange, a bad signature", token("badSignature")),
    exchange("exchange, an unknown key", token("unknownKey")),
    exchange("exchange, a retired identity's binding", token("retired")),
    exchange("exchange, a revoked binding", token("revoked")),
    exchange("exchange, an issuer that is down", token("down")),
    exchange("exchange, an issuer the policy refuses", token("refused")),
    exchange("exchange in a frozen Organization", token("frozen", "frozen")),
    exchange("exchange, a null payload", token("nullPayload")),
    exchange("exchange again: the keys are cached", token("good", "acme", { ttlSeconds: 1 })),
  ]);
}

type OidcFixture = Fixture & { oidc: { jwks: unknown[]; tokens: Record<string, string> }; fetched: Record<string, string[]> };

/** The tokens of the table, signed by a new key, and its JWKS. */
function mint() {
  const key = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwks = [{ ...(key.publicKey.export({ format: "jwk" }) as Record<string, unknown>), kid: "k1", alg: "RS256", use: "sig" }];
  const b64 = (o: unknown) => Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url");
  const exp = 4_102_444_800; // 2100-01-01
  const sign = (claims: unknown, kid = "k1", k = key.privateKey, rawPayload?: string) => {
    const h = b64({ alg: "RS256", kid, typ: "JWT" });
    const p = rawPayload ?? b64(claims);
    const s = createSign("RSA-SHA256");
    s.update(`${h}.${p}`);
    return `${h}.${p}.${s.sign(k).toString("base64url")}`;
  };
  const c = (sub: string, more: Record<string, unknown> = {}, iss = ISSUER) => ({ iss, aud: "varlatch", sub, iat: 1_763_000_000, exp, ...more });
  const good = sign(c("repo:acme/api:ref:refs/heads/main"));
  const tokens: Record<string, string> = {
    good,
    unknownIssuer: sign(c("x", {}, "https://nobody.example")),
    audArray: sign(c("repo:acme/api:pull/7", { aud: ["other", "varlatch"] })),
    wrongAudience: sign(c("repo:acme/api:x", { aud: "nope" })),
    worker: sign(c("svc:worker", { aud: "worker-aud", ref: "refs/heads/main", env: "prod" })),
    workerOtherEnv: sign(c("svc:worker", { aud: "worker-aud", ref: "refs/heads/main", env: "dev" })),
    shared: sign(c("repo:acme/shared")),
    expired: sign(c("repo:acme/api:x", { exp: 1_600_000_000 })),
    badSignature: `${good.slice(0, -6)}AAAAAA`,
    unknownKey: sign(c("repo:acme/api:x"), "k9", other.privateKey),
    retired: sign(c("retired:1")),
    revoked: sign(c("revoked:1")),
    down: sign(c("x", {}, DOWN)),
    refused: sign(c("x", {}, REFUSED)),
    frozen: sign(c("frozen:1")),
    nullPayload: sign(null, "k1", key.privateKey, b64("null")),
  };
  return { jwks, tokens };
}

/** The issuers, through the app's oidcFetch; each URL recorded. */
function issuers(jwks: unknown[], policy: OutboundPolicy, fetched: string[]): typeof fetch {
  const refused = policy.fetch("oidc");
  return (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    const u = String(input);
    fetched.push(u);
    if (u.startsWith(REFUSED)) return refused(input, init);
    if (u === `${ISSUER}/.well-known/openid-configuration`) return Response.json({ issuer: ISSUER, jwks_uri: `${ISSUER}/jwks` });
    if (u === `${ISSUER}/jwks`) return Response.json({ keys: jwks });
    if (u.startsWith(DOWN)) return new Response(null, { status: 503 });
    return new Response(null, { status: 404 });
  }) as typeof fetch;
}

function fillPath(rows: Fixture["rows"], tokens: Record<string, string>): (p: string) => string {
  const org = (slug: string) => rows.organizations!.find((o) => o.slug === slug)!.id as string;
  const identity = (name: string) => rows.identities!.find((i) => i.name === name)!.id as string;
  const binding = (subject: string) => rows.oidc_bindings!.find((b) => b.subject === subject)!.id as string;
  const fills: Record<string, string> = {
    "{acmeId}": org("acme"), "{deployer}": identity("deployer"), "{worker}": identity("worker"), "{alice}": identity("Alice"),
    "{fci}": identity("fci"), "{eci}": identity("eci"), "{b8}": binding("revoked:*"), "{fb2}": binding("frozen-revoke:*"),
    "{eb1}": binding("enf-old:*"),
  };
  for (const [name, t] of Object.entries(tokens)) fills[`{oidc:${name}}`] = t;
  return (p) => Object.entries(fills).reduce((s, [k, v]) => s.replaceAll(k, v), p);
}

async function build(minted: ReturnType<typeof mint>) {
  const db = await migratedTestDb();
  const outbound = new OutboundPolicy("", { resolve, log: () => {} });
  const ctx = { db, rootKek: generateKey(), close: db.close, outbound };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId: alice } = await consumeSetupGrant(ctx, grant.token, { adminName: "Alice" });
  const aliceCredential = await issueCredential(ctx.db, { identityId: alice, kind: "cli" });
  const alice2 = await issueCredential(ctx.db, { identityId: alice, kind: "cli" });
  const tokens: Record<string, string> = { alice: aliceCredential.token, alice2: alice2.token };
  const app = buildApp(ctx, { publicUrl: PUBLIC_URL, oidcFetch: issuers(minted.jwks, outbound, []) });
  const call = async (method: string, path: string, body?: unknown) => {
    const res = await app.request(path, {
      method, headers: { Authorization: `Bearer ${tokens.alice}`, "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await res.text();
    if (res.status >= 300) throw new Error(`${method} ${path}: ${res.status} ${text}`);
    return text ? JSON.parse(text) : null;
  };
  const orgs: Record<string, string> = {};
  for (const slug of ["acme", "enf", "frozen"]) orgs[slug] = (await call("POST", ORG, { name: slug, slug })).id;
  const machine = async (org: string, name: string, kind: string) => (await call("POST", `${ORG}/${org}/identities`, { name, kind })) as { id: string };
  const bind = async (org: string, identity: string, body: Record<string, unknown>) =>
    (await call("POST", `${ORG}/${org}/identities/${identity}/oidc-bindings`, body)) as { id: string };
  const v = (subject: string, more: Record<string, unknown> = {}) => ({ issuer: ISSUER, audience: "varlatch", subject, ...more });

  const deployer = await machine("acme", "deployer", "ci");
  const worker = await machine("acme", "worker", "service");
  const other = await machine("acme", "other", "ci");
  const retired = await machine("acme", "retired", "ci");
  await bind("acme", deployer.id, v("repo:acme/api:*"));
  await bind("acme", worker.id, v("svc:worker", { audience: "worker-aud", claims: { ref: "refs/heads/main", env: "prod" } }));
  await bind("acme", other.id, v("repo:acme/shared"));
  await bind("acme", deployer.id, v("repo:acme/*"));
  await bind("acme", retired.id, v("retired:*"));
  await call("POST", `${ORG}/acme/identities/${retired.id}/retire`);
  await bind("acme", deployer.id, v("revoked:*"));
  await bind("acme", deployer.id, { issuer: DOWN, audience: "varlatch", subject: "x" });
  // A binding whose issuer's name moved to a private address after it was made.
  await db.query(
    "INSERT INTO oidc_bindings (id, identity_id, organization_id, issuer, audience, subject, claims, created_by, created_at) VALUES ($1, $2, $3, $4, 'varlatch', 'x', NULL, $5, '2026-03-01T00:00:00.000Z')",
    [newId("oidcBinding"), deployer.id, orgs.acme, REFUSED, alice],
  );
  const bob = newId("identity");
  await db.query("INSERT INTO identities (id, kind, name, created_at) VALUES ($1, 'human', 'Bob', '2026-01-01T00:00:00.000Z')", [bob]);
  await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, $2, 'member')", [orgs.acme, bob]);
  tokens.bob = (await issueCredential(ctx.db, { identityId: bob, kind: "cli" })).token;

  // frozen: an identity with bindings, then the freeze.
  const fci = await machine("frozen", "fci", "ci");
  await bind("frozen", fci.id, v("frozen:*"));
  await bind("frozen", fci.id, v("frozen-revoke:*"));
  await db.query(
    "INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', 'incident drill')",
    [newId("organizationFreeze"), orgs.frozen, alice],
  );

  // enf: an identity with a binding, then admin-step-up at enforce, and
  // alice2's approved intents for one creation and one revocation.
  const eci = await machine("enf", "eci", "ci");
  const eb1 = await bind("enf", eci.id, v("enf-old:*"));
  await call("PATCH", `${ORG}/enf/security/controls/admin-step-up`, { mode: "report", expectedVersion: 0 });
  await call("PATCH", `${ORG}/enf/security/controls/admin-step-up`, { mode: "enforce", expectedVersion: 1 });
  const intent = async (id: string, binding: ApprovalBinding) =>
    db.query(
      `INSERT INTO approval_intents
         (id, credential_id, identity_id, organization_id, operation, target, body_hash, query_hash, expected_version, summary, origin,
          created_at, expires_at, poll_interval, approved_at, approved_with_passkey_id, approval_user_verified)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, NULL, $9::jsonb, 'cli',
               '2026-01-10T00:00:00.000Z', '2099-01-01T00:00:00.000Z', 5, '2026-01-10T00:01:00.000Z', 'PasskeyConf001', true)`,
      [
        id, alice2.credentialId, alice, orgs.enf, binding.operation, canonicalJson(binding.target),
        approvalHash(ctx.rootKek, "body", binding.body), approvalHash(ctx.rootKek, "query", binding.query), JSON.stringify(binding.summary),
      ],
    );
  const eciRef = { id: eci.id, name: "eci", kind: "ci", disabled: false, suspendedByDeletion: false };
  await intent(APPROVALS.create, oidcBindingCreateBinding({ id: orgs.enf! }, eciRef, ENF_BINDING));
  await intent(APPROVALS.revoke, oidcBindingDeleteBinding({ id: orgs.enf! }, eciRef, { id: eb1.id, ...v("enf-old:*") }));
  await accessCountsSettled();
  await db.query("UPDATE identities SET last_seen_at = '2026-01-15T00:00:00.000Z' WHERE last_seen_at > '2026-03-02T00:00:00.000Z'");
  await db.query("UPDATE credentials SET last_used_at = '2026-01-15T00:00:00.000Z' WHERE last_used_at > '2026-03-02T00:00:00.000Z'");
  return { ctx, tokens };
}

/** The file's answers, recorded on its own rows, with the URLs each request fetched. */
async function replay(f: OidcFixture): Promise<Awaited<ReturnType<typeof record>> & { fetched: Record<string, string[]> }> {
  clearJwksCache();
  const db = await loadRows(f.rows, TABLES);
  const fetched: Record<string, string[]> = {};
  const log: string[] = [];
  try {
    const outbound = new OutboundPolicy("", { resolve, log: () => {} });
    const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex"), outbound };
    const app = buildApp(ctx, { publicUrl: PUBLIC_URL, oidcFetch: issuers(f.oidc.jwks, outbound, log) });
    const recorded = await record(ctx, app, f, f.requests, fillPath(f.rows, f.oidc.tokens), (c: RequestCase, _raw: RawAnswer) => {
      if (log.length > 0) fetched[c.id] = log.splice(0);
    });
    return { ...recorded, fetched };
  } finally {
    await db.close();
    clearJwksCache();
  }
}

describe.skipIf(process.env.VARLATCH_WRITE_GO_VECTORS !== "1")("writing the fixture", () => {
  it("builds the database, records the answers and writes the file", async () => {
    const minted = mint();
    const { ctx, tokens } = await build(minted);
    try {
      const draft: OidcFixture = {
        comment: "Written by services/varlatchd/test/go-oidc-fixture.test.ts from the TypeScript server's own answers; do not edit.",
        ref: "v0.22.0",
        serverVersion: SERVER_VERSION,
        rootKek: ctx.rootKek.toString("hex"),
        tokens,
        rows: await exportRows(ctx.db, TABLES),
        sideTables: SIDE,
        requests: requestTable().map((c) => ({ ...c, expect: { status: 0, headers: {}, body: "" }, audit: [], side: {} })),
        counters: [],
        oidc: minted,
        fetched: {},
      };
      writeFileSync(FILE, JSON.stringify({ ...draft, ...(await replay(draft)) }, null, 2) + "\n");
    } finally {
      await ctx.close();
    }
  }, 600_000);
});

describe("the OIDC fixture is this server's answers", () => {
  it("oidc-v0.22.0.json", async () => {
    const f = JSON.parse(readFileSync(FILE, "utf8")) as OidcFixture;
    expect(f.ref).toBe("v0.22.0");
    expect(f.serverVersion).toBe(SERVER_VERSION);
    expectCurrentTable(f, requestTable());
    expect(f.sideTables).toEqual(SIDE);
    const got = await replay(f);
    expectSameAnswers(f, got);
    expect(got.fetched).toEqual(f.fetched);
    const { ctx } = await build(f.oidc);
    try {
      expectSameRows(TABLES, f.rows, await exportRows(ctx.db, TABLES));
    } finally {
      await ctx.close();
    }
  }, 300_000);
});
