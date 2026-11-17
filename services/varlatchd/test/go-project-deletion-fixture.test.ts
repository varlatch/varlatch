// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.12a's parity fixture (ADR-0059 step 4, feature-parity decision 3),
 * on the parity kit (go-fixture-kit.ts): deleteProject (ADR-0051 Decision
 * 2, admin-step-up's project.delete), built through this server's own /v1
 * API, a table of requests with this server's answers and the rows each
 * one changed. go/server/projects' parity test replays it against
 * varlatchd.
 *
 * The database: alice (the bootstrap Installation Admin) with a second CLI
 * credential (alice2, whose approval intents enf holds); Organizations made
 * through /v1: acme (every control off), rep (admin-step-up at report),
 * enf (at enforce), frozen (an incident freeze), deleting (a deletion
 * scheduled) and beta. People: bob (a member of acme), carol (in none);
 * svc, a service identity of enf with project.manage on its Project.
 *
 * acme's Project full holds what a deletion ends: root environments
 * development and production, development's derived environment
 * development/feature-x, an environment deleted before (its value deleted with it),
 * values with several versions and one in a rotation, Capabilities (live
 * and revoked), Sync Targets on a Platform Connection (live and revoked),
 * and a link from Team core (which also links keep). empty has no
 * environment; keep stays. beta, rep, enf, frozen and deleting each have a
 * Project with an environment.
 *
 * Every run checks the committed file: its requests must be the table's,
 * and this server, on the file's rows, must give the recorded answers;
 * the rows must still be what this code builds. After a change,
 * regenerate it and commit the result:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-project-deletion-fixture.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { newId } from "../src/db/ids.js";
import { approvalHash, canonicalJson, type ApprovalBinding } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { projectDeleteBinding, readProjectForDeletion } from "../src/domain/deletionstepup.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { migratedTestDb } from "./helpers/pglite.js";
import {
  expectCurrentTable, expectSameAnswers, expectSameRows, exportRows, loadRows, record, withIds,
  type Fixture, type RequestCase, type SideTable, type Table,
} from "./go-fixture-kit.js";

const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const FILE = new URL("../../../go/server/paritytest/testdata/project-deletion-v0.22.0.json", import.meta.url);

/** The public URL both servers run with: approvals need one. */
const PUBLIC_URL = "http://127.0.0.1:8686";

const TABLES: Table[] = [
  { name: "installation", orderBy: "id", random: ["kek_canary"] },
  { name: "identities", orderBy: "id" },
  { name: "credentials", orderBy: "id", random: ["token_hash"] },
  { name: "organizations", orderBy: "id", random: ["wrapped_org_kek"] },
  { name: "org_memberships", orderBy: "organization_id, identity_id" },
  { name: "groups", orderBy: "id" },
  { name: "grants", orderBy: "id" },
  { name: "projects", orderBy: "id" },
  { name: "team_projects", orderBy: "team_id, project_id" },
  { name: "contract_revisions", orderBy: "id" },
  { name: "environments", orderBy: "id" },
  { name: "env_values", orderBy: "id" },
  { name: "value_versions", orderBy: "id", random: ["payload", "wrapped_dek"] },
  { name: "capabilities", orderBy: "id" },
  { name: "platform_connections", orderBy: "id" },
  { name: "sync_targets", orderBy: "id" },
  { name: "security_controls", orderBy: "organization_id, control" },
  { name: "approval_intents", orderBy: "id", random: ["body_hash", "query_hash"] },
  { name: "organization_freezes", orderBy: "id" },
  { name: "organization_deletions", orderBy: "id" },
  { name: "audit_events", orderBy: "event_order", random: ["request_id"] },
];

const SIDE: SideTable[] = [
  { name: "projects", key: ["id"], sortBy: ["organization_id", "slug", "deleted_at"], volatile: ["created_at", "deleted_at"] },
  { name: "environments", key: ["id"], sortBy: ["project_id", "name", "deleted_at"], volatile: ["created_at", "deleted_at"] },
  { name: "env_values", key: ["id"], sortBy: ["environment_id", "item_name"], volatile: ["deleted_at"] },
  { name: "value_versions", key: ["id"], sortBy: ["value_id", "version"], volatile: ["erased_at"] },
  { name: "capabilities", key: ["id"], sortBy: ["run_id"], volatile: ["revoked_at"] },
  { name: "sync_targets", key: ["id"], sortBy: ["canonical_destination"], volatile: ["revoked_at", "updated_at"] },
  { name: "team_projects", key: ["team_id", "project_id"], sortBy: ["team_id", "project_id"] },
  { name: "approval_intents", key: ["id"], sortBy: ["organization_id", "operation", "target", "body_hash"], volatile: ["created_at", "expires_at", "consumed_at", "closed_at"] },
];

const ORG = "/v1/organizations";

/** Fixed approval intent ids: a request's Varlatch-Approval header names them. */
const aprId = (s: string) => `apr_${s.padEnd(26, "a")}`;
const APPROVALS = { ep: aprId("ep"), ep2: aprId("eptwo") } as const;

/** The table of requests. */
function requestTable(): RequestCase[] {
  const del = (name: string, org: string, project: string, extra: Partial<RequestCase> = {}): Omit<RequestCase, "id"> =>
    ({ name, method: "DELETE", path: `${ORG}/${org}/projects/${project}`, credential: "alice", ...extra });
  const get = (name: string, path: string, credential = "alice"): Omit<RequestCase, "id"> => ({ name, method: "GET", path, credential });
  const approval = (id: string) => ({ headers: { "Varlatch-Approval": id } });
  return withIds([
    // Refused before anything changes: existence hidden from who may not manage it.
    del("delete as a member", "acme", "full", { credential: "bob" }),
    del("delete as an outsider", "acme", "full", { credential: "carol" }),
    del("delete an unknown Project", "acme", "nope"),
    del("delete another Organization's Project by id", "acme", "{betaWebId}"),
    del("delete in an unknown Organization", "nope", "full"),
    del("delete in a frozen Organization", "frozen", "fp"),
    del("delete in an Organization being deleted", "deleting", "dp"),

    // The deletion, and what it leaves.
    del("delete", "acme", "full"),
    del("delete again", "acme", "full"),
    get("get the deleted Project", `${ORG}/acme/projects/full`),
    get("list its environments", `${ORG}/acme/projects/full/environments`),
    get("list the Projects afterwards", `${ORG}/acme/projects`),
    get("list the Team's Projects afterwards", `${ORG}/acme/teams/{coreTeamId}/projects`),
    del("delete a Project without environments, by id", "acme", "{emptyId}"),
    { name: "create a Project with the deleted slug", method: "POST", path: `${ORG}/acme/projects`, credential: "alice",
      body: { slug: "full", name: "Full again", contractAuthority: "managed" } },

    // admin-step-up's project.delete.
    del("delete at report", "rep", "rp"),
    del("delete at enforce, no approval", "enf", "ep"),
    del("delete at enforce, another request's approval", "enf", "ep", { credential: "alice2", ...approval(APPROVALS.ep2) }),
    del("delete at enforce, a malformed approval", "enf", "ep", { credential: "alice2", headers: { "Varlatch-Approval": "not-an-approval" } }),
    del("delete at enforce, a machine credential", "enf", "ep", { credential: "svc" }),
    del("delete at enforce, its approval", "enf", "ep", { credential: "alice2", ...approval(APPROVALS.ep) }),
    del("delete at enforce, its approval again", "enf", "ep", { credential: "alice2", ...approval(APPROVALS.ep) }),
    get("list enf's Projects afterwards", `${ORG}/enf/projects`),
  ]);
}

/** Fills a request's placeholders from the file's rows. */
function fillPath(rows: Fixture["rows"]): (p: string) => string {
  const org = (slug: string) => rows.organizations!.find((o) => o.slug === slug)!.id as string;
  const project = (orgSlug: string, slug: string) =>
    rows.projects!.find((p) => p.organization_id === org(orgSlug) && p.slug === slug && p.deleted_at === null)!.id as string;
  const team = rows.groups!.find((g) => g.organization_id === org("acme") && g.name === "core")!.id as string;
  const pairs: [string, string][] = [["{betaWebId}", project("beta", "web")], ["{emptyId}", project("acme", "empty")], ["{coreTeamId}", team]];
  return (p) => pairs.reduce((out, [k, v]) => out.replaceAll(k, v), p);
}

type Call = (method: string, path: string, body?: unknown, token?: string) => Promise<any>;

const item = (name: string, sensitive: boolean) => ({ name, required: { kind: "never" }, sensitive, type: "string" });

async function build(): Promise<{ ctx: AppCtx & { close: () => Promise<void> }; tokens: Record<string, string> }> {
  const db = await migratedTestDb();
  const ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId: alice } = await consumeSetupGrant(ctx, grant.token, { adminName: "Alice" });
  const alice2 = await issueCredential(ctx.db, { identityId: alice, kind: "cli" });
  const tokens: Record<string, string> = { alice: (await issueCredential(ctx.db, { identityId: alice, kind: "cli" })).token, alice2: alice2.token };
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
  for (const slug of ["acme", "rep", "enf", "frozen", "deleting", "beta"]) {
    orgs[slug] = (await call("POST", ORG, { name: slug[0]!.toUpperCase() + slug.slice(1), slug })).id;
  }
  for (const [name, member] of [["bob", true], ["carol", false]] as const) {
    const id = newId("identity");
    await db.query("INSERT INTO identities (id, kind, name, created_at) VALUES ($1, 'human', $2, '2026-01-01T00:00:00.000Z')", [id, name]);
    if (member) await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1, $2, 'member')", [orgs.acme, id]);
    tokens[name] = (await issueCredential(ctx.db, { identityId: id, kind: "cli" })).token;
  }
  const project = async (org: string, slug: string, envs: string[] = []) => {
    const p = await call("POST", `${ORG}/${org}/projects`, { slug, name: slug.toUpperCase(), contractAuthority: "git" });
    for (const tier of envs) await call("POST", `${ORG}/${org}/projects/${slug}/environments`, { name: tier, tier });
    return p.id as string;
  };

  // acme/full: environments, values and their versions, a rotation.
  const full = await project("acme", "full", ["development", "production"]);
  const P = `${ORG}/acme/projects/full`;
  const envId = async (name: string) =>
    (await db.query("SELECT id FROM environments WHERE project_id = $1 AND name = $2 AND deleted_at IS NULL", [full, name])).rows[0].id as string;
  await call("POST", `${P}/environments`, { name: "development/feature-x", kind: "preview", parentEnvironmentId: await envId("development") });
  const featureX = await envId("development/feature-x");
  await call("POST", `${P}/environments`, { name: "old", tier: "development" });
  const rev = await call("POST", `${P}/contract/revisions`, {
    contract: { schemaVersion: 1, items: [item("SECRET_A", true), item("SECRET_B", true), item("PLAIN", false)] },
  });
  await call("POST", `${P}/contract/revisions/${rev.id}/activate`);
  const V = (env: string, name: string) => `${P}/environments/${env}/values/${name}`;
  for (const [env, name, value] of [
    ["development", "SECRET_A", "a-1"], ["development", "SECRET_A", "a-2"], ["development", "SECRET_B", "b-old"],
    ["development", "PLAIN", "plain"], ["production", "SECRET_A", "prod-a"], [featureX, "SECRET_A", "feature"],
    ["old", "SECRET_A", "old-a"],
  ] as const) {
    await call("PUT", V(env, name), { value });
  }
  await call("POST", `${V("development", "SECRET_B")}/rotations`, { value: "b-new" });
  await call("DELETE", `${P}/environments/old`);

  // Capabilities on its environments, live and revoked, by acme's Broker for its Agent.
  const machine = async (org: string, name: string, kind: string) => {
    const m = await call("POST", `${ORG}/${org}/identities`, { name, kind });
    tokens[name] = m.credential;
    return m.id as string;
  };
  const broker = await machine("acme", "broker", "broker");
  const agent = await machine("acme", "agent", "agent");
  const capability = async (run: string, env: string, revoked: string | null) =>
    db.query(
      `INSERT INTO capabilities (id, organization_id, broker_identity_id, agent_identity_id, project_id, environment_id, items, destinations,
         targets, secret_hash, run_id, expires_at, revoked_at, created_by, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, '2099-01-01T00:00:00.000Z', $12, $3, '2026-02-01T00:00:00.000Z')`,
      [newId("capability"), orgs.acme, broker, agent, full, await envId(env), ["SECRET_A"], ["api.example.com:443"],
        JSON.stringify({ SECRET_A: ["header:authorization"] }), "0".repeat(64), run, revoked],
    );
  await capability("dev-live", "development", null);
  await capability("prod-live", "production", null);
  await capability("dev-revoked", "development", "2026-02-02T00:00:00.000Z");

  // A Platform Connection and Sync Targets of the Project, live and revoked
  // (written directly: nothing here opens the credential).
  const connection = newId("platformConnection");
  await db.query(
    `INSERT INTO platform_connections (id, organization_id, platform, base_identity, name, created_by, created_at, credential_envelope)
     VALUES ($1, $2, 'coolify', 'https://coolify.example.com', 'Coolify', $3, '2026-02-01T00:00:00.000Z', '{"fixture":"not opened"}'::jsonb)`,
    [connection, orgs.acme, alice],
  );
  const target = async (destination: string, env: string, revoked: string | null) =>
    db.query(
      `INSERT INTO sync_targets (id, organization_id, project_id, environment_id, connection_id, destination, canonical_destination, mapping,
         created_by, created_at, revoked_at, generation, lease_expires_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, '{}'::jsonb, $8, '2026-02-01T00:00:00.000Z', $9, 3, '2026-02-01T01:00:00.000Z', '2026-02-01T00:00:00.000Z')`,
      [newId("syncTarget"), orgs.acme, full, await envId(env), connection, JSON.stringify({ application: destination }), `coolify:${destination}`, alice, revoked],
    );
  await target("app-dev", "development", null);
  await target("app-prod", "production", null);
  await target("app-gone", "development", "2026-02-02T00:00:00.000Z");

  // acme's other Projects, and Team core linking full and keep.
  await project("acme", "empty");
  const keep = await project("acme", "keep", ["development"]);
  const team = await call("POST", `${ORG}/acme/teams`, { name: "core" });
  for (const id of [full, keep]) await call("POST", `${ORG}/acme/teams/${team.id}/projects`, { projectId: id });

  // The other Organizations' Projects.
  await project("beta", "web", ["development"]);
  await project("rep", "rp", ["development"]);
  const ep = await project("enf", "ep", ["development", "production"]);
  const ep2 = await project("enf", "ep2", ["development"]);
  await project("frozen", "fp", ["development"]);
  await project("deleting", "dp", ["development"]);
  // svc: a service identity of enf with project.manage on ep, made before the control.
  const svc = await machine("enf", "svc", "service");
  await call("POST", `${ORG}/enf/grants`, { subjectIdentityId: svc, scope: { kind: "project", projectId: ep }, actions: ["project.manage"] });

  const set = (org: string, body: unknown) => call("PATCH", `${ORG}/${org}/security/controls/admin-step-up`, body);
  await set("rep", { mode: "report", expectedVersion: 0 });
  await set("enf", { mode: "report", expectedVersion: 0 });
  await set("enf", { mode: "enforce", expectedVersion: 1 });
  await db.query(
    "INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', 'incident drill')",
    [newId("organizationFreeze"), orgs.frozen, alice],
  );
  await db.query(
    "INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', '2099-03-01T00:00:00.000Z', false)",
    [newId("organizationDeletion"), orgs.deleting, alice],
  );

  // Approval intents of alice's second CLI credential in enf, each binding
  // one deletion exactly as the operation binds it.
  const intent = async (id: string, binding: ApprovalBinding) =>
    db.query(
      `INSERT INTO approval_intents
         (id, credential_id, identity_id, organization_id, operation, target, body_hash, query_hash, expected_version, summary, origin,
          created_at, expires_at, poll_interval, approved_at, approved_with_passkey_id, approval_user_verified)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10::jsonb, 'cli',
               '2026-01-10T00:00:00.000Z', '2099-01-01T00:00:00.000Z', 5, '2026-01-10T00:01:00.000Z', 'PasskeyConf001', true)`,
      [
        id, alice2.credentialId, alice, orgs.enf, binding.operation, canonicalJson(binding.target),
        approvalHash(ctx.rootKek, "body", binding.body), approvalHash(ctx.rootKek, "query", binding.query),
        binding.expectedVersion, JSON.stringify(binding.summary),
      ],
    );
  const enf = { id: orgs.enf! };
  await intent(APPROVALS.ep, projectDeleteBinding(enf, (await readProjectForDeletion(db, orgs.enf!, ep))!));
  await intent(APPROVALS.ep2, projectDeleteBinding(enf, (await readProjectForDeletion(db, orgs.enf!, ep2))!));
  await accessCountsSettled();
  return { ctx, tokens };
}

/** The file's answers, recorded on its own rows. */
async function replay(f: Fixture): Promise<Awaited<ReturnType<typeof record>>> {
  const db = await loadRows(f.rows, TABLES);
  await db.query("UPDATE audit_position SET value = (SELECT coalesce(max(event_order), 0) FROM audit_events) WHERE singleton");
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
      const draft: Fixture = {
        comment: "Written by services/varlatchd/test/go-project-deletion-fixture.test.ts from the TypeScript server's own answers; do not edit.",
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

describe("the project deletion fixture is this server's answers", () => {
  it("project-deletion-v0.22.0.json", async () => {
    const f = JSON.parse(readFileSync(FILE, "utf8")) as Fixture;
    expect(f.serverVersion).toBe(SERVER_VERSION);
    expectCurrentTable(f, requestTable());
    expect(f.sideTables).toEqual(SIDE);
    expectSameAnswers(f, await replay(f));
    // The deletion ended what it must.
    const deleted = f.requests.find((r) => r.name === "delete")!;
    expect(deleted.expect.status).toBe(200);
    expect(JSON.parse(deleted.expect.body)).toMatchObject({ environments: 3, capabilitiesRevoked: 2, targetsRevoked: 2, teamLinksRemoved: 1 });
    const { ctx } = await build();
    try {
      expectSameRows(TABLES, f.rows, await exportRows(ctx.db, TABLES));
    } finally {
      await ctx.close();
    }
  }, 300_000);
});

