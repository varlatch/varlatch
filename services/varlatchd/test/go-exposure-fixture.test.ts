// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.5b's parity fixture (ADR-0059 step 4, feature-parity decision 3),
 * on the parity kit (go-fixture-kit.ts): the exposure report and revocation
 * confirmations (ADR-0052 Decisions 6 and 7), built through this server's
 * own /v1 API, and a table of requests with this server's answers.
 * go/server/people's parity test replays it against varlatchd.
 *
 * The database: alice (the bootstrap Installation Admin) and Organizations
 * exp, frozen and other. In exp, a Project api with development, staging
 * and production, an active Contract (one item with a rotation hint), and
 * values in every state a received version can be in: current, replaced,
 * retiring (until 2099), past its rotation deadline, of a deleted value,
 * of a deleted environment, unknown here. People: bob and dave (members),
 * carol (removed by alice, so her removal recorded an authority snapshot
 * with a Requirement), erin (in none). What bob and carol received is
 * written to the exposure index directly, every way, at pinned times (the
 * index writes themselves are the audit vectors' and the values fixture's);
 * one version is already confirmed.
 *
 * Every time the rows hold keeps its meaning whenever the file is
 * replayed: the retiring version's deadline is in 2099.
 *
 * Paths and bodies name rows by what they are: {org:SLUG}, {idn:NAME},
 * {ver:ENV/ITEM/N} (the N-th version, oldest first, of exp's api value).
 *
 * Every run checks the committed file: its requests must be the table's,
 * and this server, on the file's rows, must give the recorded answers.
 * After a change, regenerate it and commit the result:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-exposure-fixture.test.ts
 */
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
  type Fixture, type RequestCase, type Row, type SideTable, type Table,
} from "./go-fixture-kit.js";

// The unwrapped app: some requests are outside the OpenAPI document on
// purpose (bodies that are not JSON, extra members).
const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const FILE = new URL("../../../go/server/paritytest/testdata/exposure-v0.22.0.json", import.meta.url);

/** The public URL both servers run with. */
export const PUBLIC_URL = "http://127.0.0.1:8686";

const TABLES: Table[] = [
  { name: "installation", orderBy: "id", random: ["kek_canary"] },
  { name: "identities", orderBy: "id" },
  { name: "user", orderBy: "id" },
  { name: "auth_user_links", orderBy: "better_auth_user_id" },
  { name: "credentials", orderBy: "id", random: ["token_hash"] },
  { name: "organizations", orderBy: "id", random: ["wrapped_org_kek"] },
  { name: "org_memberships", orderBy: "organization_id, identity_id" },
  { name: "projects", orderBy: "id" },
  { name: "environments", orderBy: "id" },
  { name: "contract_revisions", orderBy: "id", random: ["content_hash"] },
  { name: "env_values", orderBy: "id" },
  { name: "value_versions", orderBy: "id", random: ["payload", "wrapped_dek"] },
  { name: "grants", orderBy: "id" },
  { name: "requirements", orderBy: "id" },
  { name: "membership_removals", orderBy: "id" },
  { name: "removal_authority", orderBy: "removal_id, environment_id, action, source" },
  { name: "removal_requirements", orderBy: "removal_id, requirement_id" },
  { name: "removal_conditions", orderBy: "removal_id, environment_id, requirement_id" },
  { name: "member_exposure", orderBy: "organization_id, identity_id, version_id, environment_id, way" },
  { name: "exposure_confirmations", orderBy: "organization_id, version_id" },
  { name: "organization_freezes", orderBy: "id" },
];

const SIDE: SideTable[] = [
  { name: "exposure_confirmations", key: ["organization_id", "version_id"], sortBy: ["version_id"], volatile: ["confirmed_at"] },
];

const ORG = "/v1/organizations";
const P = "exp/projects/api";

/** The table of requests. */
function requestTable(): RequestCase[] {
  const get = (name: string, path: string, credential = "alice"): Omit<RequestCase, "id"> => ({ name, method: "GET", path: `${ORG}/${path}`, credential });
  const confirm = (name: string, member: string, body: unknown, credential = "alice", org = "exp"): Omit<RequestCase, "id"> => ({
    name, method: "POST", path: `${ORG}/${org}/members/${member}/exposure/confirmations`, credential, body,
  });
  return withIds([
    // The report.
    get("bob's exposure", "exp/members/{idn:bob}/exposure"),
    get("bob's exposure by the Organization's id", "{org:exp}/members/{idn:bob}/exposure"),
    get("a former member's exposure", "exp/members/{idn:carol}/exposure"),
    get("your own exposure", "exp/members/me/exposure"),
    get("a member with nothing received", "exp/members/{idn:dave}/exposure"),
    get("a person never a member", "exp/members/{idn:erin}/exposure"),
    get("an unknown person", "exp/members/idn_unknownaaaaaaaaaaaaaaaaaaa/exposure"),
    get("U+0000 in the id", "exp/members/a%00b/exposure"),
    get("as a member", "exp/members/{idn:bob}/exposure", "dave"),
    get("as an outsider", "exp/members/{idn:bob}/exposure", "erin"),
    get("in a frozen Organization", "frozen/members/{idn:bob}/exposure"),
    get("in an unknown Organization", "nope/members/{idn:bob}/exposure"),

    // Confirmations.
    confirm("confirm the current version", "{idn:bob}", { versionId: "{ver:development/API_KEY/2}" }),
    confirm("confirm it again", "{idn:bob}", { versionId: "{ver:development/API_KEY/2}" }),
    confirm("confirm one confirmed before, as a member who can write there", "{idn:bob}", { versionId: "{ver:development/API_KEY/1}" }, "dave"),
    confirm("confirm in production as a member", "{idn:bob}", { versionId: "{ver:production/DB_URL/1}" }, "bob"),
    confirm("confirm your own, in production", "me", { versionId: "{ver:production/DB_URL/1}" }, "bob"),
    confirm("confirm a deleted value's version", "{idn:bob}", { versionId: "{ver:development/OLD/1}" }),
    confirm("confirm a deleted environment's version as a member", "{idn:bob}", { versionId: "{ver:temp/TEMP/1}" }, "dave"),
    confirm("confirm a deleted environment's version", "{idn:bob}", { versionId: "{ver:temp/TEMP/1}" }),
    confirm("confirm a version unknown here", "{idn:bob}", { versionId: "vv_unknownaaaaaaaaaaaaaaaaaaaaa" }),
    confirm("confirm a former member's version", "{idn:carol}", { versionId: "{ver:production/DB_URL/1}" }),
    confirm("confirm a version not received", "{idn:bob}", { versionId: "{ver:staging/API_KEY/2}" }),
    confirm("confirm for a person never a member", "{idn:erin}", { versionId: "{ver:development/API_KEY/2}" }),
    confirm("confirm, an empty version", "{idn:bob}", { versionId: "" }),
    confirm("confirm, a version of 201 characters", "{idn:bob}", { versionId: "v".repeat(201) }),
    confirm("confirm, an extra member", "{idn:bob}", { versionId: "{ver:development/API_KEY/2}", note: "x" }),
    confirm("confirm, no version", "{idn:bob}", {}),
    confirm("confirm, U+0000 in the version", "{idn:bob}", { versionId: "a\u0000b" }),
    confirm("confirm, U+0000 in the member", "a%00b", { versionId: "{ver:development/API_KEY/2}" }),
    { name: "confirm, a body that is not JSON", method: "POST", path: `${ORG}/exp/members/{idn:bob}/exposure/confirmations`, credential: "alice", rawBody: "{" },
    confirm("confirm in a frozen Organization", "{idn:bob}", { versionId: "x" }, "alice", "frozen"),
    confirm("confirm as an outsider", "{idn:bob}", { versionId: "{ver:development/API_KEY/2}" }, "erin"),
    get("bob's exposure after the confirmations", "exp/members/{idn:bob}/exposure"),
  ]);
}

/** The placeholders of the table, from the file's rows. */
function fillPath(rows: Record<string, Row[]>): (p: string) => string {
  const org = (slug: string) => rows.organizations!.find((o) => o.slug === slug)!.id as string;
  const resolve = (kind: string, arg: string): string => {
    switch (kind) {
      case "org":
        return org(arg);
      case "idn":
        return rows.identities!.find((i) => i.name === arg)!.id as string;
      case "ver": {
        const [env, item, n] = arg.split("/") as [string, string, string];
        const project = rows.projects!.find((p) => p.organization_id === org("exp") && p.slug === "api")!.id;
        const e = rows.environments!.find((x) => x.project_id === project && x.name === env)!.id;
        const value = rows.env_values!.find((v) => v.environment_id === e && v.item_name === item)!.id;
        const versions = rows.value_versions!.filter((v) => v.value_id === value).sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)));
        return versions[Number(n) - 1]!.id as string;
      }
    }
    throw new Error(`unknown placeholder ${kind}`);
  };
  return (p) => p.replace(/\{(org|idn|ver):([^}]+)\}/g, (_, kind: string, arg: string) => resolve(kind, arg));
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
  const orgs: Record<string, string> = {};
  for (const slug of ["exp", "frozen", "other"]) {
    orgs[slug] = (await call("POST", ORG, { name: slug[0]!.toUpperCase() + slug.slice(1), slug })).id;
  }
  const ids: Record<string, string> = {};
  const person = async (name: string, memberships: string[]) => {
    const id = newId("identity");
    await db.query("INSERT INTO identities (id, kind, name, created_at) VALUES ($1, 'human', $2, '2026-01-01T00:00:00.000Z')", [id, name]);
    for (const org of memberships) {
      await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, $2, 'member')", [orgs[org], id]);
    }
    tokens[name] = (await issueCredential(ctx.db, { identityId: id, kind: "cli" })).token;
    ids[name] = id;
    return id;
  };
  await person("bob", ["exp", "frozen"]);
  await person("carol", ["exp"]);
  await person("dave", ["exp"]);
  await person("erin", []);

  // exp: a Project, its environments, a Contract with a rotation hint.
  const project = (await call("POST", `${ORG}/exp/projects`, { name: "API", slug: "api", contractAuthority: "managed" })).id as string;
  for (const [name, tier] of [["development", "development"], ["staging", "staging"], ["production", "production"], ["temp", "development"]] as const) {
    await call("POST", `${ORG}/${P}/environments`, { name, tier });
  }
  const item = (name: string, extra: Record<string, unknown> = {}) => ({ name, required: { kind: "never" }, sensitive: false, type: "string", ...extra });
  const rev = await call("POST", `${ORG}/${P}/contract/revisions`, {
    contract: { schemaVersion: 1, items: [item("API_KEY", { sensitive: true, rotationHint: "Rotate it in the provider's console" }), item("DB_URL"), item("OLD"), item("TEMP")] },
  });
  await call("POST", `${ORG}/${P}/contract/revisions/${rev.id}/activate`);
  const put = (env: string, name: string, value: string) => call("PUT", `${ORG}/${P}/environments/${env}/values/${name}`, { value });
  await put("development", "API_KEY", "a1");
  await put("development", "API_KEY", "a2");
  await put("staging", "API_KEY", "s1");
  await put("staging", "API_KEY", "s2");
  await put("production", "DB_URL", "d1");
  await put("development", "OLD", "o1");
  await call("DELETE", `${ORG}/${P}/environments/development/values/OLD`);
  await put("temp", "TEMP", "t1");
  await call("DELETE", `${ORG}/${P}/environments/temp`);
  const env = async (name: string) => (await db.query("SELECT id FROM environments WHERE project_id = $1 AND name = $2", [project, name])).rows[0]!.id as string;
  const value = async (envName: string, itemName: string) =>
    (await db.query("SELECT id FROM env_values WHERE environment_id = $1 AND item_name = $2", [await env(envName), itemName])).rows[0]!.id as string;
  const version = async (envName: string, itemName: string, n: number) =>
    (await db.query("SELECT id FROM value_versions WHERE value_id = $1 ORDER BY created_at, id", [await value(envName, itemName)])).rows[n - 1]!.id as string;
  // Rotations: staging's first version retiring until 2099; development's
  // first past its deadline.
  await db.query("UPDATE env_values SET retiring_version_id = $2, rotation_deadline = '2099-01-01T00:00:00.000Z' WHERE id = $1",
    [await value("staging", "API_KEY"), await version("staging", "API_KEY", 1)]);
  await db.query("UPDATE env_values SET retiring_version_id = $2, rotation_deadline = '2026-01-02T00:00:00.000Z' WHERE id = $1",
    [await value("development", "API_KEY"), await version("development", "API_KEY", 1)]);

  // carol: a Grant and a Requirement on production, then her removal.
  await call("POST", `${ORG}/exp/grants`, {
    subjectIdentityId: ids.carol, scope: { kind: "environments", projectId: project, selector: { kind: "tier", tier: "production" } }, actions: ["config.value.read"],
  });
  await call("POST", `${ORG}/exp/requirements`, { kind: "tailnet", target: { kind: "tier", tier: "production" }, selector: { tailnet: "example.ts.net", tags: ["tag:prod"] } });
  await call("DELETE", `${ORG}/exp/members/${ids.carol}`);

  // What bob and carol received, every way, at pinned times.
  const received = async (who: string, envName: string, versionId: string, itemName: string, way: string, day: number) =>
    db.query(
      `INSERT INTO member_exposure (organization_id, identity_id, version_id, item_name, environment_id, way, first_at, last_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [orgs.exp, ids[who], versionId, itemName, await env(envName), way, `2026-01-${String(day).padStart(2, "0")}T00:00:00.000Z`, `2026-01-${String(day + 1).padStart(2, "0")}T00:00:00.000Z`],
    );
  await received("bob", "development", await version("development", "API_KEY", 2), "API_KEY", "revealed", 10);
  await received("bob", "development", await version("development", "API_KEY", 2), "API_KEY", "export", 12);
  await received("bob", "development", await version("development", "API_KEY", 1), "API_KEY", "delivered", 3);
  await received("bob", "staging", await version("staging", "API_KEY", 1), "API_KEY", "export", 5);
  await received("bob", "production", await version("production", "DB_URL", 1), "DB_URL", "revealed", 6);
  await received("bob", "development", await version("development", "OLD", 1), "OLD", "written", 7);
  await received("bob", "temp", await version("temp", "TEMP", 1), "TEMP", "revealed", 8);
  await received("bob", "development", "vv_unknownaaaaaaaaaaaaaaaaaaaaa", "GONE", "revealed", 9);
  await received("carol", "production", await version("production", "DB_URL", 1), "DB_URL", "revealed", 4);
  await received("carol", "development", await version("development", "API_KEY", 2), "API_KEY", "written", 11);
  // One version confirmed before.
  await db.query(
    "INSERT INTO exposure_confirmations (organization_id, version_id, identity_id, actor_identity_id, confirmed_at) VALUES ($1, $2, $3, $4, '2026-01-20T00:00:00.000Z')",
    [orgs.exp, await version("development", "API_KEY", 1), ids.bob, alice],
  );

  await db.query(
    "INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', 'incident drill')",
    [newId("organizationFreeze"), orgs.frozen, alice],
  );

  await accessCountsSettled();
  await db.query("UPDATE identities SET last_seen_at = '2026-01-15T00:00:00.000Z' WHERE last_seen_at > '2026-03-02T00:00:00.000Z'");
  await db.query("UPDATE credentials SET last_used_at = '2026-01-15T00:00:00.000Z' WHERE last_used_at > '2026-03-02T00:00:00.000Z'");
  return { ctx, tokens };
}

/** The file's answers, recorded on its own rows. */
async function replay(f: Fixture): Promise<Awaited<ReturnType<typeof record>>> {
  const db = await loadRows(f.rows, TABLES);
  try {
    const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex") };
    return await record(ctx, buildApp(ctx, { publicUrl: PUBLIC_URL }), f, f.requests, fillPath(f.rows));
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
        comment: "Written by services/varlatchd/test/go-exposure-fixture.test.ts from the TypeScript server's own answers; do not edit.",
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

describe("the exposure fixture is this server's answers", () => {
  it("exposure-v0.22.0.json", async () => {
    const f = JSON.parse(readFileSync(FILE, "utf8")) as Fixture;
    expect(f.ref).toBe("v0.22.0");
    expect(f.serverVersion).toBe(SERVER_VERSION);
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
  }, 180_000);
});
