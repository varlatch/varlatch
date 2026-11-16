// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.13a's parity fixture (ADR-0059 step 4, feature-parity decision 3),
 * on the parity kit (go-fixture-kit.ts): the tailnet listeners' HTTP side,
 * with stand-in device checks. Each listener the table names is an app of
 * its own, as `serve` builds them (cli.ts): no public URL, no human
 * authentication, a resolver that answers a fixed resolution, and, for the
 * browser endpoint, its gate. go/server/httpserver's tailnet parity test
 * replays the table against varlatchd with the same listeners.
 *
 * The database: alice (the bootstrap Installation Admin), bob (a member of
 * tn). In tn: the Project api with development and production, a Contract
 * with a Secret and a plain item, their values in both environments;
 * Requirements: the production tier needs a tag:prod device of corp.ts.net,
 * the development environment alice@example.com's own device; a Broker, an
 * Agent with secret.use and a Capability in production (a known secret).
 *
 * The listeners: ordinary (with the browser endpoint's URL, as every
 * listener has it); tn-prod (a tag:prod device), tn-user (alice's
 * untagged device), tn-ci (a tag:ci device), tn-shared and tn-unavailable
 * (refused, with those reasons); browser (the browser endpoint, a tag:prod
 * device) and browser-refused (the browser endpoint, unrecognized).
 *
 * Every run checks the committed file: its requests must be the table's,
 * and this server, on its rows, must give the recorded answers. After a
 * change, regenerate it and commit the result:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-tailnet-fixture.test.ts
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import type { TailnetContext } from "../src/authz/evaluate.js";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { newId } from "../src/db/ids.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import type { WhoisResult } from "../src/tailnet/whois.js";
import { migratedTestDb } from "./helpers/pglite.js";
import {
  expectCurrentTable, expectSameAnswers, expectSameRows, exportRows, loadRows, record, withIds,
  type Fixture, type RequestCase, type SideTable, type Table,
} from "./go-fixture-kit.js";

const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const FILE = new URL("../../../go/server/paritytest/testdata/tailnet-v0.22.0.json", import.meta.url);

/** The public URL of the ordinary listener; the tailnet listeners have none. */
export const PUBLIC_URL = "http://127.0.0.1:8686";
/** The browser endpoint, as every listener reports it. */
export const BROWSER = { host: "varlatch.corp.ts.net", port: 8443, origins: ["https://dash.example.com"] };
export const BROWSER_ENDPOINT = `https://${BROWSER.host}:${BROWSER.port}`;

const prod: TailnetContext = { tailnet: "corp.ts.net", nodeId: "nProd1CNTRL", nodeName: "build-1", tags: ["tag:prod"] };
/** The stand-in device checks, by listener. */
export const LISTENERS: Record<string, { result: WhoisResult; browser?: boolean }> = {
  "tn-prod": { result: { ok: true, context: prod } },
  "tn-user": { result: { ok: true, context: { tailnet: "corp.ts.net", nodeId: "nLaptopCNTRL", nodeName: "laptop", tags: [], userLogin: "alice@example.com" } } },
  "tn-ci": { result: { ok: true, context: { tailnet: "corp.ts.net", nodeId: "nCi1CNTRL", nodeName: "ci-1", tags: ["tag:ci"] } } },
  "tn-shared": { result: { ok: false, reason: "shared" } },
  "tn-unavailable": { result: { ok: false, reason: "resolver-unavailable" } },
  browser: { result: { ok: true, context: prod }, browser: true },
  "browser-refused": { result: { ok: false, reason: "unrecognized" }, browser: true },
};

const TABLES: Table[] = [
  { name: "installation", orderBy: "id", random: ["kek_canary"] },
  { name: "identities", orderBy: "id" },
  { name: "credentials", orderBy: "id", random: ["token_hash"] },
  { name: "organizations", orderBy: "id", random: ["wrapped_org_kek"] },
  { name: "org_memberships", orderBy: "organization_id, identity_id" },
  { name: "grants", orderBy: "id" },
  { name: "requirements", orderBy: "id" },
  { name: "projects", orderBy: "id" },
  { name: "contract_revisions", orderBy: "id" },
  { name: "environments", orderBy: "id" },
  { name: "env_values", orderBy: "id" },
  { name: "value_versions", orderBy: "id", random: ["payload", "wrapped_dek"] },
  { name: "capabilities", orderBy: "id" },
  { name: "audit_events", orderBy: "event_order", random: ["request_id"] },
];
const SIDE: SideTable[] = [];

const ORG = "/v1/organizations";
const ENV = (env: string) => `${ORG}/tn/projects/api/environments/${env}`;
const CAP_SECRET = "vlt_cap_known_tailnet";

function requestTable(): RequestCase[] {
  const get = (name: string, path: string, listener?: string, credential = "alice", headers?: Record<string, string>): Omit<RequestCase, "id"> =>
    ({ name, method: "GET", path, credential, ...(listener ? { listener } : {}), ...(headers ? { headers } : {}) });
  const browserGet = (name: string, path: string, headers: Record<string, string> = {}, listener = "browser"): Omit<RequestCase, "id"> =>
    get(name, path, listener, "alice", { Host: `${BROWSER.host}:${BROWSER.port}`, ...headers });
  const read = (env: string) => `${ENV(env)}/effective-configuration?include=values`;
  const disclose = (name: string, env: string, listener?: string): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ENV(env)}/disclosures`, credential: "alice", body: { items: ["SECRET"] }, ...(listener ? { listener } : {}) });
  const exercise = (name: string, listener?: string): Omit<RequestCase, "id"> => ({
    name, method: "POST", path: `${ENV("production")}/capabilities/{cap}/exercises`, credential: "broker",
    body: { capabilitySecret: CAP_SECRET, destination: { host: "api.example.com", port: 443 }, placements: [{ item: "SECRET", target: "header:authorization" }] },
    ...(listener ? { listener } : {}),
  });
  const preflight = (name: string, headers: Record<string, string>, path = read("production")): Omit<RequestCase, "id"> =>
    ({ name, method: "OPTIONS", path, credential: "none", listener: "browser", headers: { Host: BROWSER.host, ...headers } });
  return withIds([
    // What every listener says about the tailnet (/v1/meta's
    // tailnet.browser-reads: the Go server's own test, its document being
    // the Go server's).
    get("the browser endpoint's URL", "/v1/tailnet/endpoint"),
    get("the browser endpoint's URL on a tailnet listener", "/v1/tailnet/endpoint", "tn-prod"),
    get("the listeners report", "/v1/installation/listeners"),
    get("the listeners report as a member", "/v1/installation/listeners", undefined, "bob"),
    get("the listeners report on a tailnet listener", "/v1/installation/listeners", "tn-prod"),

    // Who am I, with the device.
    get("me", "/v1/me"),
    get("me on a tagged device", "/v1/me", "tn-prod"),
    get("me on a person's device", "/v1/me", "tn-user"),
    get("me from a shared device", "/v1/me", "tn-shared"),
    get("me when the node cannot say", "/v1/me", "tn-unavailable"),

    // The device check: only on the browser endpoint.
    browserGet("the device", "/v1/tailnet/context"),
    browserGet("no device", "/v1/tailnet/context", {}, "browser-refused"),
    get("the device on the plain tailnet listener", "/v1/tailnet/context", "tn-prod"),
    get("the device on the ordinary listener", "/v1/tailnet/context"),

    // Requirements, against each listener's device.
    get("production on the ordinary listener", read("production")),
    get("production from a tag:prod device", read("production"), "tn-prod"),
    get("production from a tag:ci device", read("production"), "tn-ci"),
    get("production from a shared device", read("production"), "tn-shared"),
    get("production when the node cannot say", read("production"), "tn-unavailable"),
    get("development from alice's device", read("development"), "tn-user"),
    get("development from a tag:prod device", read("development"), "tn-prod"),
    disclose("disclose production from a tag:prod device", "production", "tn-prod"),
    disclose("disclose production from a tag:ci device", "production", "tn-ci"),
    disclose("disclose production on the ordinary listener", "production"),
    exercise("exercise in production on the ordinary listener"),
    exercise("exercise in production from a tag:ci device", "tn-ci"),
    exercise("exercise in production from a tag:prod device", "tn-prod"),

    // The browser endpoint's gate.
    browserGet("production through the browser endpoint", read("production")),
    browserGet("production from the dashboard's origin", read("production"), { Origin: BROWSER.origins[0]! }),
    browserGet("production from another origin", read("production"), { Origin: "https://evil.example.com" }),
    browserGet("a route pages may not call, from the dashboard's origin", "/v1/me", { Origin: BROWSER.origins[0]! }),
    browserGet("the device from the dashboard's origin", "/v1/tailnet/context", { Origin: BROWSER.origins[0]! }),
    get("another host name", read("production"), "browser", "alice", { Host: "elsewhere.corp.ts.net" }),
    get("no host name", read("production"), "browser", "alice"),
    browserGet("the host name in capitals", read("production"), { Host: BROWSER.host.toUpperCase() }),
    preflight("a preflight from the dashboard's origin", { Origin: BROWSER.origins[0]!, "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization" }),
    preflight("a preflight asking for Varlatch-Approval", { Origin: BROWSER.origins[0]!, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "Authorization, Content-Type, Varlatch-Approval" },
      `${ENV("production")}/disclosures`),
    preflight("a preflight for a POST to a read route", { Origin: BROWSER.origins[0]!, "Access-Control-Request-Method": "POST" }),
    preflight("a preflight from another origin", { Origin: "https://evil.example.com", "Access-Control-Request-Method": "GET" }),
    preflight("a preflight for a method pages may not use", { Origin: BROWSER.origins[0]!, "Access-Control-Request-Method": "DELETE" }),
  ]);
}

/** Fills a request's placeholders from the file's rows. */
function fillPath(rows: Fixture["rows"]): (p: string) => string {
  const cap = rows.capabilities!.find((c) => c.run_id === "known-tailnet")!.id as string;
  return (p) => p.replaceAll("{cap}", cap);
}

/** The app for a listener's name, as cli.ts builds each listener's. */
function appFor(ctx: AppCtx) {
  return (listener?: string) => {
    if (listener === undefined) return buildApp(ctx, { publicUrl: PUBLIC_URL, browserEndpoint: BROWSER_ENDPOINT });
    const l = LISTENERS[listener];
    if (!l) throw new Error(`no listener ${listener}`);
    return buildApp(ctx, {
      resolveTailnetContext: async () => l.result,
      browserEndpoint: BROWSER_ENDPOINT,
      ...(l.browser ? { tailnetBrowser: BROWSER } : {}),
    });
  };
}

type Call = (method: string, path: string, body?: unknown, token?: string) => Promise<any>;

async function build(): Promise<{ ctx: AppCtx & { close: () => Promise<void> }; tokens: Record<string, string> }> {
  const db = await migratedTestDb();
  const ctx = { db, rootKek: generateKey(), close: db.close };
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
  const org = (await call("POST", ORG, { name: "Tailnet", slug: "tn" })).id as string;
  const bob = newId("identity");
  await db.query("INSERT INTO identities (id, kind, name, created_at) VALUES ($1, 'human', 'bob', '2026-01-01T00:00:00.000Z')", [bob]);
  await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, $2, 'member')", [org, bob]);
  tokens.bob = (await issueCredential(ctx.db, { identityId: bob, kind: "cli" })).token;

  const P = `${ORG}/tn/projects/api`;
  const project = await call("POST", `${ORG}/tn/projects`, { name: "API", slug: "api", contractAuthority: "git" });
  for (const tier of ["development", "production"]) await call("POST", `${P}/environments`, { name: tier, tier });
  const item = (name: string, sensitive: boolean) => ({ name, required: { kind: "never" }, sensitive, type: "string" });
  const rev = await call("POST", `${P}/contract/revisions`, { contract: { schemaVersion: 1, items: [item("SECRET", true), item("PLAIN", false)] } });
  await call("POST", `${P}/contract/revisions/${rev.id}/activate`);
  for (const env of ["development", "production"]) {
    await call("PUT", `${P}/environments/${env}/values/SECRET`, { value: `${env}-secret` });
    await call("PUT", `${P}/environments/${env}/values/PLAIN`, { value: `${env}-plain` });
  }
  const envId = async (name: string) =>
    (await db.query("SELECT id FROM environments WHERE project_id = $1 AND name = $2", [project.id, name])).rows[0].id as string;
  await call("POST", `${ORG}/tn/requirements`, { kind: "tailnet", target: { kind: "tier", tier: "production" }, selector: { tailnet: "corp.ts.net", tags: ["tag:prod"] } });
  await call("POST", `${ORG}/tn/requirements`, {
    kind: "tailnet", target: { kind: "environments", environmentIds: [await envId("development")] }, selector: { tailnet: "corp.ts.net", users: ["alice@example.com"] },
  });

  // A Broker and an Agent with secret.use, and a Capability in production.
  const broker = await call("POST", `${ORG}/tn/identities`, { name: "broker", kind: "broker" });
  tokens.broker = broker.credential;
  const agent = await call("POST", `${ORG}/tn/identities`, { name: "agent", kind: "agent" });
  await call("POST", `${ORG}/tn/grants`, { subjectIdentityId: agent.id, scope: { kind: "project", projectId: project.id }, actions: ["secret.use"] });
  await db.query(
    `INSERT INTO capabilities (id, organization_id, broker_identity_id, agent_identity_id, project_id, environment_id, items, destinations,
       targets, secret_hash, run_id, expires_at, created_by, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'known-tailnet', '2099-01-01T00:00:00.000Z', $3, '2026-02-01T00:00:00.000Z')`,
    [newId("capability"), org, broker.id, agent.id, project.id, await envId("production"), ["SECRET"], ["api.example.com:443"],
      JSON.stringify({ SECRET: ["header:authorization"] }), createHash("sha256").update(CAP_SECRET, "utf8").digest("hex")],
  );
  await accessCountsSettled();
  return { ctx, tokens };
}

async function replay(f: Fixture): Promise<Awaited<ReturnType<typeof record>>> {
  const db = await loadRows(f.rows, TABLES);
  await db.query("UPDATE audit_position SET value = (SELECT coalesce(max(event_order), 0) FROM audit_events) WHERE singleton");
  try {
    const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex") };
    return await record(ctx, appFor(ctx), f, f.requests, fillPath(f.rows));
  } finally {
    await db.close();
  }
}

describe.skipIf(process.env.VARLATCH_WRITE_GO_VECTORS !== "1")("writing the fixture", () => {
  it("builds the database, records the answers and writes the file", async () => {
    const { ctx, tokens } = await build();
    try {
      const draft: Fixture = {
        comment: "Written by services/varlatchd/test/go-tailnet-fixture.test.ts from the TypeScript server's own answers; do not edit.",
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

describe("the tailnet fixture is this server's answers", () => {
  it("tailnet-v0.22.0.json", async () => {
    const f = JSON.parse(readFileSync(FILE, "utf8")) as Fixture;
    expect(f.serverVersion).toBe(SERVER_VERSION);
    expectCurrentTable(f, requestTable());
    expect(f.sideTables).toEqual(SIDE);
    expectSameAnswers(f, await replay(f));
    const status = (name: string) => f.requests.find((r) => r.name === name)!.expect.status;
    expect(status("production from a tag:prod device")).toBe(200);
    expect(status("production on the ordinary listener")).toBe(403);
    expect(status("exercise in production from a tag:prod device")).toBe(200);
    const { ctx } = await build();
    try {
      expectSameRows(TABLES, f.rows, await exportRows(ctx.db, TABLES));
    } finally {
      await ctx.close();
    }
  }, 300_000);
});
