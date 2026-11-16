// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.7a's parity fixture (ADR-0059 step 4, feature-parity decision 3),
 * on the parity kit (go-fixture-kit.ts): the outbound policy's two pages,
 * getInstallationOutbound and refusedDestinations, with this server's
 * answers. go/server/outbound's parity test replays it against varlatchd
 * with the same allow list and the same resolver.
 *
 * The database: alice (the bootstrap Installation Admin); Organizations
 * acme, beta, frozen (an incident freeze) and gone (deleted), made through
 * /v1. bob is a member of acme; carol belongs to none. acme's configured
 * destinations, written directly (createWebhook refuses what the policy
 * refuses): webhooks to a public name, to a private name the allow list
 * opens, to a private name on another port, over plain http, to a literal
 * private address, to a name that resolves to the metadata address, to a
 * name that does not resolve, to a name with a private and a public
 * answer, and a revoked one; a Coolify Connection to a private name, a
 * Convex one to a public name, a GitHub one (never checked); an OIDC
 * issuer on a private name. beta and frozen each have one refused webhook,
 * gone one too. outbound.refused events for some of them, dated in 2099
 * (always within the last 30 days of any replay) and in 2020 (never).
 *
 * The resolver is the table RESOLVE (both servers use the same one), and
 * the allow list ALLOW.
 *
 * Every run checks the committed file: its requests must be the table's,
 * and this server, on the file's rows, must give the recorded answers.
 * After a change, regenerate it and commit the result:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-outbound-fixture.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { newId } from "../src/db/ids.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { OutboundPolicy, type Resolver } from "../src/net/outbound.js";
import { migratedTestDb } from "./helpers/pglite.js";
import {
  expectCurrentTable, expectSameAnswers, expectSameRows, exportRows, loadRows, record, withIds,
  type Fixture, type RequestCase, type SideTable, type Table,
} from "./go-fixture-kit.js";

const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const FILE = new URL("../../../go/server/paritytest/testdata/outbound-v0.22.0.json", import.meta.url);

/** The allow list both servers run with. */
export const ALLOW = "private.example,hooks.internal:8443,127.0.0.1/32:*";

/** The resolver both servers run with: a name's answers, or no answer (ENOTFOUND). */
export const RESOLVE: Record<string, { address: string; family: 4 | 6 }[]> = {
  "hooks.public.example": [{ address: "93.184.216.34", family: 4 }, { address: "2606:2800:220:1::1", family: 6 }],
  "private.example": [{ address: "10.0.0.5", family: 4 }],
  "hooks.internal": [{ address: "10.1.2.3", family: 4 }],
  "intranet.example": [{ address: "192.168.1.20", family: 4 }],
  "plain.example": [{ address: "93.184.216.35", family: 4 }],
  "meta.example": [{ address: "169.254.169.254", family: 4 }],
  "mixed.example": [{ address: "10.9.9.9", family: 4 }, { address: "93.184.216.36", family: 4 }],
  "coolify.internal": [{ address: "172.16.4.4", family: 4 }],
  "convex.public.example": [{ address: "93.184.216.37", family: 4 }],
  "issuer.internal": [{ address: "100.64.1.1", family: 4 }],
};

const resolve: Resolver = async (name) => {
  const a = RESOLVE[name];
  if (!a) throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${name}`), { code: "ENOTFOUND" });
  return a;
};

const policy = () => new OutboundPolicy(ALLOW, { resolve, log: () => {} });

const TABLES: Table[] = [
  { name: "installation", orderBy: "id", random: ["kek_canary"] },
  { name: "identities", orderBy: "id" },
  { name: "credentials", orderBy: "id", random: ["token_hash"] },
  { name: "organizations", orderBy: "id", random: ["wrapped_org_kek"] },
  { name: "org_memberships", orderBy: "organization_id, identity_id" },
  { name: "organization_freezes", orderBy: "id" },
  { name: "webhooks", orderBy: "id" },
  { name: "platform_connections", orderBy: "id" },
  { name: "oidc_bindings", orderBy: "id" },
  { name: "audit_events", orderBy: "event_order" },
];

const SIDE: SideTable[] = [];

const ORG = "/v1/organizations";

function requestTable(): RequestCase[] {
  const installation = (name: string, credential: string): Omit<RequestCase, "id"> =>
    ({ name, method: "GET", path: "/v1/installation/outbound", credential });
  const refused = (name: string, org: string, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "GET", path: `${ORG}/${org}/security/refused-destinations`, credential });
  return withIds([
    installation("the installation's outbound policy", "alice"),
    installation("the installation's outbound policy as a member", "bob"),
    installation("the installation's outbound policy as an outsider", "carol"),
    refused("acme's refused destinations", "acme"),
    refused("acme's refused destinations by id", "{acmeId}"),
    refused("beta's refused destinations", "beta"),
    refused("a frozen Organization's refused destinations", "frozen"),
    refused("a deleted Organization's refused destinations", "gone"),
    refused("an unknown Organization's refused destinations", "nope"),
    refused("acme's refused destinations as a member", "acme", "bob"),
    refused("acme's refused destinations as an outsider", "acme", "carol"),
  ]);
}

/** Fills a request's placeholders from the file's rows. */
function fillPath(rows: Fixture["rows"]): (p: string) => string {
  const acme = rows.organizations!.find((o) => o.slug === "acme")!.id as string;
  return (p) => p.replaceAll("{acmeId}", acme);
}

type Call = (method: string, path: string, body?: unknown) => Promise<any>;

async function build(): Promise<{ ctx: AppCtx & { close: () => Promise<void> }; tokens: Record<string, string> }> {
  const db = await migratedTestDb();
  const ctx = { db, rootKek: generateKey(), close: db.close, outbound: policy() };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId: alice } = await consumeSetupGrant(ctx, grant.token, { adminName: "Alice" });
  const tokens: Record<string, string> = { alice: (await issueCredential(ctx.db, { identityId: alice, kind: "cli" })).token };
  const app = buildApp(ctx, {});
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
  for (const slug of ["acme", "beta", "frozen", "gone"]) {
    orgs[slug] = (await call("POST", ORG, { name: slug[0]!.toUpperCase() + slug.slice(1), slug })).id;
  }
  const person = async (name: string, org?: string) => {
    const id = newId("identity");
    await db.query("INSERT INTO identities (id, kind, name, created_at) VALUES ($1, 'human', $2, '2026-01-01T00:00:00.000Z')", [id, name]);
    if (org) await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, $2, 'member')", [orgs[org], id]);
    tokens[name] = (await issueCredential(ctx.db, { identityId: id, kind: "cli" })).token;
    return id;
  };
  await person("bob", "acme");
  await person("carol");

  let n = 0;
  const at = () => `2026-01-02T00:00:${String(n++).padStart(2, "0")}.000Z`;
  const webhooks: Record<string, string> = {};
  const webhook = async (org: string, name: string, url: string, revoked = false) => {
    const id = newId("webhook");
    webhooks[name] = id;
    await db.query(
      `INSERT INTO webhooks (id, organization_id, url, secret_envelope, created_by, created_at, cursor_occurred_at, revoked_at)
       VALUES ($1, $2, $3, '{"formatVersion":1}'::jsonb, $4, $5, '2026-01-01T00:00:00.000Z', $6)`,
      [id, orgs[org], url, alice, at(), revoked ? "2026-01-03T00:00:00.000Z" : null],
    );
    return id;
  };
  await webhook("acme", "public", "https://hooks.public.example/x");
  await webhook("acme", "allowed", "https://private.example/hook?secret=1");
  await webhook("acme", "other port", "https://hooks.internal/hook");
  await webhook("acme", "on its port", "https://hooks.internal:8443/hook");
  await webhook("acme", "intranet", "https://intranet.example/hook");
  await webhook("acme", "plain", "http://plain.example/hook");
  await webhook("acme", "literal", "https://10.0.0.7/hook");
  await webhook("acme", "literal v6", "https://[fd12::7]:9443/hook");
  await webhook("acme", "literal loopback", "http://127.0.0.1:9000/hook");
  await webhook("acme", "literal metadata", "https://169.254.169.254/latest");
  await webhook("acme", "metadata", "https://meta.example/hook");
  await webhook("acme", "missing", "https://missing.example/hook");
  await webhook("acme", "mixed", "https://mixed.example/hook");
  await webhook("acme", "revoked", "https://intranet.example/old", true);
  await webhook("beta", "beta", "https://intranet.example:8080/beta");
  await webhook("frozen", "frozen", "https://intranet.example/frozen");
  await webhook("gone", "gone", "https://intranet.example/gone");
  const connection = async (org: string, platform: string, base: string, name: string) => {
    const id = newId("platformConnection");
    await db.query(
      `INSERT INTO platform_connections (id, organization_id, platform, base_identity, name, credential_envelope, created_by, created_at)
       VALUES ($1, $2, $3, $4, $5, '{"formatVersion":1}'::jsonb, $6, $7)`,
      [id, orgs[org], platform, base, name, alice, at()],
    );
    return id;
  };
  const coolify = await connection("acme", "coolify", "https://coolify.internal", "Coolify lab");
  await connection("acme", "convex", "https://convex.public.example", "Convex prod");
  await connection("acme", "github-actions", "acme/api", "GitHub");
  const workload = newId("identity");
  await db.query("INSERT INTO identities (id, kind, name, organization_id, created_at) VALUES ($1, 'workload', 'deploy', $2, '2026-01-01T00:00:00.000Z')", [workload, orgs.acme]);
  const binding = newId("oidcBinding");
  await db.query(
    `INSERT INTO oidc_bindings (id, identity_id, organization_id, issuer, audience, subject, created_by, created_at)
     VALUES ($1, $2, $3, 'https://issuer.internal', 'varlatch', 'repo:acme/api', $4, $5)`,
    [binding, workload, orgs.acme, alice, at()],
  );
  await db.query(
    "INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', 'incident drill')",
    [newId("organizationFreeze"), orgs.frozen, alice],
  );
  await db.query("UPDATE organizations SET deleted_at = '2026-03-02T00:00:00.000Z', wrapped_org_kek = NULL, org_kek_destroyed_at = '2026-03-02T00:00:00.000Z' WHERE id = $1", [orgs.gone]);

  // outbound.refused events: within any replay's last 30 days (2099), and
  // never (2020); two for one destination (the earliest counts), one on
  // another port than the configured one, one for the Connection.
  const refusal = async (when: string, org: string, resource: Record<string, string>, host: string, port: number, reason = "private_address") =>
    db.query(
      `INSERT INTO audit_events (id, event_type, occurred_at, organization_id, resource, decision, metadata)
       VALUES ($1, 'outbound.refused', $2, $3, $4::jsonb, 'deny', $5::jsonb)`,
      [newId("auditEvent"), when, orgs[org], JSON.stringify(resource),
        JSON.stringify({ purpose: "webhook", phase: "connection", scheme: "https", host, port, reason })],
    );
  await refusal("2099-01-02T00:00:00.000Z", "acme", { webhookId: webhooks.intranet! }, "intranet.example", 443);
  await refusal("2099-01-01T00:00:00.000Z", "acme", { webhookId: webhooks.intranet! }, "intranet.example", 443);
  await refusal("2099-01-01T00:00:00.000Z", "acme", { webhookId: webhooks["other port"]! }, "hooks.internal", 8443, "port");
  await refusal("2099-01-03T00:00:00.000Z", "acme", { connectionId: coolify }, "coolify.internal", 443);
  await refusal("2020-01-01T00:00:00.000Z", "acme", { oidcBindingId: binding }, "issuer.internal", 443);
  await refusal("2099-01-01T00:00:00.000Z", "beta", { webhookId: webhooks.beta! }, "intranet.example", 8080);
  return { ctx, tokens };
}

/** The file's answers, recorded on its own rows. */
async function replay(f: Fixture): Promise<Awaited<ReturnType<typeof record>>> {
  const db = await loadRows(f.rows, TABLES);
  await db.query("UPDATE audit_position SET value = (SELECT coalesce(max(event_order), 0) FROM audit_events) WHERE singleton");
  try {
    const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex"), outbound: policy() };
    return await record(ctx, buildApp(ctx, {}), f, f.requests, fillPath(f.rows));
  } finally {
    await db.close();
  }
}

describe.skipIf(process.env.VARLATCH_WRITE_GO_VECTORS !== "1")("writing the fixture", () => {
  it("builds the database, records the answers and writes the file", async () => {
    const { ctx, tokens } = await build();
    try {
      const rows = await exportRows(ctx.db, TABLES);
      const draft: Fixture = {
        comment: "Written by services/varlatchd/test/go-outbound-fixture.test.ts from the TypeScript server's own answers; do not edit.",
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

describe("the outbound fixture is this server's answers", () => {
  it("outbound-v0.22.0.json", async () => {
    const f = JSON.parse(readFileSync(FILE, "utf8")) as Fixture;
    expect(f.ref).toBe("v0.22.0");
    expect(f.serverVersion).toBe(SERVER_VERSION);
    expectCurrentTable(f, requestTable());
    expect(f.sideTables).toEqual(SIDE);
    expectSameAnswers(f, await replay(f));
    const { ctx } = await build();
    try {
      expectSameRows(TABLES, f.rows, await exportRows(ctx.db, TABLES));
    } finally {
      await ctx.close();
    }
  }, 180_000);
});
