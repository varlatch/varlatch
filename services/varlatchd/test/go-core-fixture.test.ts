// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.1's parity fixture (ADR-0059 step 4, feature-parity decision 3),
 * on the parity kit (go-fixture-kit.ts): Organizations, Projects,
 * Environments, Contracts and values, built through this server's own /v1
 * API, and a table of requests with this server's answers. 4.1a records
 * the Organization operations (createOrganization, getOrganization,
 * renameOrganization); the later pull requests of 4.1 add theirs to the
 * same file. go/server/orgs's parity test replays it against varlatchd.
 *
 * The database: alice (the bootstrap Installation Admin) and Organizations
 * made through /v1: acme, frozen (an incident freeze), guarded
 * (passkey-verification at enforce), reported (at report) and deleting (a
 * deletion scheduled); bob, a member of acme; carol, a member of none; a
 * service identity of acme and an agent of acme with an Agent Run
 * credential. Rows the routes that set them need passkey approvals for
 * (the freeze, the controls, the deletion) are written directly.
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
import { expectCurrentTable, expectSameAnswers, exportRows, loadRows, record, withIds, type Fixture, type RequestCase, type SideTable, type Table } from "./go-fixture-kit.js";

// The unwrapped app: some requests are outside the OpenAPI document on
// purpose (bodies that are not JSON, extra members).
const { buildApp } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const FILE = new URL("../../../go/server/paritytest/testdata/core-v0.22.0.json", import.meta.url);

const TABLES: Table[] = [
  { name: "installation", orderBy: "id" },
  { name: "identities", orderBy: "id" },
  { name: "user", orderBy: "id" },
  { name: "auth_user_links", orderBy: "better_auth_user_id" },
  { name: "credentials", orderBy: "id" },
  { name: "organizations", orderBy: "id" },
  { name: "org_memberships", orderBy: "organization_id, identity_id" },
  { name: "grants", orderBy: "id" },
  { name: "requirements", orderBy: "id" },
  { name: "security_controls", orderBy: "organization_id, control" },
  { name: "organization_freezes", orderBy: "id" },
  { name: "organization_deletions", orderBy: "id" },
];

const SIDE: SideTable[] = [
  { name: "organizations", orderBy: "id", volatile: ["created_at", "wrapped_org_kek"] },
  { name: "org_memberships", orderBy: "organization_id, identity_id", volatile: ["created_at"] },
];

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
    rename("rename by id", "{orgId}", "alice", { name: "Acme by id" }),
    get("get after the renames", "acme"),
    create("create after the renames", "alice", { name: "Acme Robotics", slug: "acme-robotics" }),
  ]);
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
  for (const slug of ["acme", "frozen", "guarded", "reported", "deleting"]) {
    orgs[slug] = (await call("POST", ORG, { name: slug[0]!.toUpperCase() + slug.slice(1), slug })).id;
  }
  const person = async (name: string, member: boolean) => {
    const id = newId("identity");
    await db.query("INSERT INTO identities (id, kind, name, created_at) VALUES ($1, 'human', $2, '2026-01-01T00:00:00.000Z')", [id, name]);
    if (member) await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, $2, 'member')", [orgs.acme, id]);
    tokens[name] = (await issueCredential(ctx.db, { identityId: id, kind: "cli" })).token;
  };
  await person("bob", true);
  await person("carol", false);
  tokens.ci = (await call("POST", `${ORG}/acme/identities`, { name: "deploy", kind: "service" })).credential;
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
  return { ctx, tokens };
}

/** The file's answers, recorded on its own rows. */
async function replay(f: Fixture) {
  const db = await loadRows(f.rows, TABLES);
  try {
    const ctx: AppCtx = { db, rootKek: Buffer.from(f.rootKek, "hex") };
    const orgId = f.rows.organizations!.find((o) => o.slug === "acme")!.id as string;
    return await record(ctx, buildApp(ctx), f, f.requests, (p) => p.replace("{orgId}", orgId));
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
  it("core-v0.22.0.json", async () => {
    const f = JSON.parse(readFileSync(FILE, "utf8")) as Fixture;
    expectCurrentTable(f, requestTable());
    expect(f.sideTables).toEqual(SIDE);
    expectSameAnswers(f, await replay(f));
  }, 120_000);
});
