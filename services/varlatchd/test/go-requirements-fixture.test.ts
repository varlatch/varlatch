// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.4c's parity fixture (ADR-0059 step 4, feature-parity decision 3),
 * on the parity kit (go-fixture-kit.ts): Tailnet Requirements (listed,
 * created, changed in place under an Idempotency-Key, revoked, protected
 * by requirement-protection) and the access reports (machine reach, the
 * credential review, the caller's own Organization permissions), built
 * through this server's own /v1 API, and a table of requests with this
 * server's answers. go/server/access' parity test replays it against
 * varlatchd.
 *
 * The database: alice (the bootstrap Installation Admin) and Organizations
 * made through /v1: req (every control off), rep (requirement-protection
 * at report), enf (requirement-protection at enforce), frozen (an incident
 * freeze), deleting (a deletion scheduled) and other. In each of req, rep
 * and enf: Projects api (development, staging, production, a preview of
 * development and an expired one) and web (development), a deleted
 * Project; Requirements on a tier and on Environments (one revoked); a
 * service identity with Grants of every scope (one through a group and a
 * role), a CI machine with none, a retired machine, a Broker and an Agent.
 * In req, a machine whose credentials take every state the review tells
 * apart. People: bob (a member), dave (an admin, who asks for approvals in
 * enf), erin (a former member), carol (in none). Approval intents of
 * alice's second CLI credential in enf, bound to exact requests of the
 * table.
 *
 * The review reads times against now, so every time the file holds keeps
 * its meaning however late it is replayed: uses long past (idle), expiry
 * long past or far ahead, no use at all. A credential expiring within the
 * warning window cannot be pinned so; Go's access tests cover it.
 *
 * Paths name rows by what they are: {org:SLUG}, {idn:NAME}, {prj:ORG:SLUG},
 * {env:ORG:PROJECT/NAME} and {req:ORG:TAILNET}, the Requirement whose
 * selector names that tailnet.
 *
 * Every run checks the committed file: its requests must be the table's,
 * and this server, on the file's rows, must give the recorded answers.
 * After a change, regenerate it and commit the result:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-requirements-fixture.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { newId } from "../src/db/ids.js";
import { approvalHash, canonicalJson, type ApprovalBinding } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { readRequirement, requirementRevokeBinding, requirementUpdateBinding } from "../src/domain/requirementprotection.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { migratedTestDb } from "./helpers/pglite.js";
import {
  expectCurrentTable, expectSameAnswers, expectSameRows, exportRows, loadRows, record, withIds,
  type Fixture, type RequestCase, type Row, type SideTable, type Table,
} from "./go-fixture-kit.js";

// The unwrapped app: some requests are outside the OpenAPI document on
// purpose (bodies that are not JSON, extra members).
const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const FILE = new URL("../../../go/server/paritytest/testdata/requirements-v0.22.0.json", import.meta.url);

/** The public URL both servers run with: approvals need one. */
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
  { name: "roles", orderBy: "id" },
  { name: "groups", orderBy: "id" },
  { name: "group_members", orderBy: "group_id, identity_id" },
  { name: "team_projects", orderBy: "team_id, project_id" },
  { name: "grants", orderBy: "id" },
  { name: "requirements", orderBy: "id" },
  { name: "security_controls", orderBy: "organization_id, control" },
  { name: "security_control_counters", orderBy: "organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour" },
  // The intents' hashes are keyed by the build's random Root KEK.
  { name: "approval_intents", orderBy: "id", random: ["body_hash", "query_hash"] },
  { name: "organization_freezes", orderBy: "id" },
  { name: "organization_deletions", orderBy: "id" },
  { name: "idempotency_keys", orderBy: "identity_id, endpoint, idempotency_key" },
];

const SIDE: SideTable[] = [
  { name: "requirements", key: ["id"], sortBy: ["organization_id", "target", "config", "revoked_at"], volatile: ["created_at", "updated_at", "revoked_at"] },
  {
    name: "security_control_counters",
    key: ["organization_id", "control", "config_version", "operation", "actor_identity_id", "reason", "bucket_hour"],
    sortBy: ["organization_id", "control", "config_version", "operation", "actor_identity_id", "reason"],
    volatile: ["bucket_hour", "first_seen", "last_seen", "emitted_at"],
  },
  { name: "approval_intents", key: ["id"], sortBy: ["organization_id", "operation", "target", "body_hash"], volatile: ["created_at", "expires_at", "consumed_at", "closed_at"] },
];

const ORG = "/v1/organizations";

/** Fixed approval intent ids: a request's Varlatch-Approval header names them. */
const aprId = (s: string) => `apr_${s.padEnd(26, "a")}`;
const APPROVALS = {
  update: aprId("requpdate"),
  revoke: aprId("reqrevoke"),
  otherBody: aprId("reqotherbody"),
  pending: aprId("reqpending"),
} as const;

const TAILNET = "example.ts.net";

/** The table of requests. */
function requestTable(): RequestCase[] {
  type H = Record<string, string>;
  const headers = (approval?: string, key?: string): { headers?: H } => {
    const h: H = {};
    if (approval !== undefined) h["Varlatch-Approval"] = approval;
    if (key !== undefined) h["Idempotency-Key"] = key;
    return Object.keys(h).length ? { headers: h } : {};
  };
  const get = (name: string, path: string, credential = "alice"): Omit<RequestCase, "id"> => ({ name, method: "GET", path: `${ORG}/${path}`, credential });
  const send = (name: string, method: string, path: string, body?: unknown, credential = "alice", approval?: string, key?: string): Omit<RequestCase, "id"> => ({
    name, method, path: `${ORG}/${path}`, credential, ...(body !== undefined ? { body } : {}), ...headers(approval, key),
  });
  const raw = (name: string, method: string, path: string, rawBody: string): Omit<RequestCase, "id"> => ({ name, method, path: `${ORG}/${path}`, credential: "alice", rawBody });
  const create = (name: string, org: string, body: unknown, credential = "alice") => send(name, "POST", `${org}/requirements`, body, credential);
  const patch = (name: string, org: string, mark: string, body: unknown, credential = "alice", approval?: string, key?: string) =>
    send(name, "PATCH", `${org}/requirements/{req:${org}:${mark}}`, body, credential, approval, key);
  const tier = { kind: "tier", tier: "production" };
  const tags = (tailnet: string, ...t: string[]) => ({ tailnet, tags: t.length ? t : ["tag:ci"] });
  return withIds([
    // Lists.
    get("requirements", "req/requirements"),
    get("requirements by id", "{org:req}/requirements"),
    get("requirements as a member", "req/requirements", "bob"),
    get("requirements as an outsider", "req/requirements", "carol"),
    get("requirements of a frozen Organization", "frozen/requirements"),
    get("requirements of an Organization being deleted", "deleting/requirements"),
    get("requirements of an unknown Organization", "nope/requirements"),

    // Creating: never protected.
    create("a tier", "req", { kind: "tailnet", target: tier, selector: tags("new-tier.ts.net", "tag:prod", "tag:ops") }),
    create("environments", "req", { kind: "tailnet", target: { kind: "environments", environmentIds: ["{env:req:api/staging}", "{env:req:web/development}"] }, selector: { tailnet: "new-envs.ts.net", users: ["alice@example.com"], nodes: ["n1"] } }),
    create("every selector list, extra members", "req", { kind: "tailnet", extra: 1, target: { kind: "tier", tier: "staging", extra: 2 }, selector: { nodes: ["n2"], users: ["u@x"], tags: ["tag:a", "tag:a"], tailnet: "new-all.ts.net", extra: 3 } }),
    create("another Organization's environment", "req", { kind: "tailnet", target: { kind: "environments", environmentIds: ["{env:other:api/development}"] }, selector: tags("new-other.ts.net") }),
    create("an unknown environment", "req", { kind: "tailnet", target: { kind: "environments", environmentIds: ["env_unknownaaaaaaaaaaaaaaaaaaa"] }, selector: tags("new-unknown.ts.net") }),
    create("no kind", "req", { target: tier, selector: tags(TAILNET) }),
    create("another kind", "req", { kind: "acl", target: tier, selector: tags(TAILNET) }),
    create("no target", "req", { kind: "tailnet", selector: tags(TAILNET) }),
    create("an unknown target kind", "req", { kind: "tailnet", target: { kind: "project" }, selector: tags(TAILNET) }),
    create("an unknown tier", "req", { kind: "tailnet", target: { kind: "tier", tier: "prod" }, selector: tags(TAILNET) }),
    create("no environment", "req", { kind: "tailnet", target: { kind: "environments", environmentIds: [] }, selector: tags(TAILNET) }),
    create("environments that are not a list", "req", { kind: "tailnet", target: { kind: "environments", environmentIds: "env_x" }, selector: tags(TAILNET) }),
    create("an environment id that is not a string", "req", { kind: "tailnet", target: { kind: "environments", environmentIds: [1] }, selector: tags(TAILNET) }),
    create("no selector", "req", { kind: "tailnet", target: tier }),
    create("an empty tailnet", "req", { kind: "tailnet", target: tier, selector: { tailnet: "", tags: ["tag:ci"] } }),
    create("no tailnet", "req", { kind: "tailnet", target: tier, selector: { tags: ["tag:ci"] } }),
    create("a selector naming nothing", "req", { kind: "tailnet", target: tier, selector: { tailnet: TAILNET } }),
    create("a selector of empty lists", "req", { kind: "tailnet", target: tier, selector: { tailnet: TAILNET, tags: [], users: [], nodes: [] } }),
    create("tags that are not a list", "req", { kind: "tailnet", target: tier, selector: { tailnet: TAILNET, tags: "tag:ci" } }),
    create("a tag that is not a string", "req", { kind: "tailnet", target: tier, selector: { tailnet: TAILNET, tags: [7] } }),
    create("several issues", "req", { kind: "acl", target: { kind: "tier" }, selector: { tailnet: "" } }),
    create("an array", "req", []),
    create("null", "req", null),
    raw("a body that is not JSON", "POST", "req/requirements", "{"),
    // PostgreSQL refuses U+0000 and a lone surrogate in jsonb.
    create("U+0000 in the tailnet", "req", { kind: "tailnet", target: tier, selector: tags("a\u0000b") }),
    create("U+0000 in an environment id", "req", { kind: "tailnet", target: { kind: "environments", environmentIds: ["a\u0000b"] }, selector: tags("new-nul.ts.net") }),
    create("a lone surrogate in a tag", "req", { kind: "tailnet", target: tier, selector: { tailnet: "new-surrogate.ts.net", tags: ["a\ud800b"] } }),
    create("as a member", "req", { kind: "tailnet", target: tier, selector: tags("new-bob.ts.net") }, "bob"),
    create("in a frozen Organization", "frozen", { kind: "tailnet", target: tier, selector: tags("new-frozen.ts.net") }),
    create("in an Organization being deleted", "deleting", { kind: "tailnet", target: tier, selector: tags("new-deleting.ts.net") }),
    create("in an unknown Organization", "nope", { kind: "tailnet", target: tier, selector: tags("new-nope.ts.net") }),

    // Changing in place.
    patch("change the selector", "req", "edit.ts.net", { expectedVersion: 1, selector: tags("edit.ts.net", "tag:edited") }, "alice", undefined, "edit-1"),
    patch("change it again, the same key", "req", "edit.ts.net", { expectedVersion: 1, selector: tags("edit.ts.net", "tag:edited") }, "alice", undefined, "edit-1"),
    patch("the same key, another body", "req", "edit.ts.net", { expectedVersion: 1, selector: tags("edit.ts.net", "tag:other") }, "alice", undefined, "edit-1"),
    patch("an old version", "req", "edit.ts.net", { expectedVersion: 1, selector: tags("edit.ts.net", "tag:late") }),
    patch("change the target", "req", "edit.ts.net", { expectedVersion: 2, target: { kind: "environments", environmentIds: ["{env:req:api/development}", "{env:req:api/development}"] } }),
    patch("change both", "req", "edit.ts.net", { expectedVersion: 3, target: tier, selector: { tailnet: "edit.ts.net", users: ["b@x", "a@x"] } }),
    patch("the same selector, another text", "req", "edit.ts.net", { expectedVersion: 4, selector: { users: ["a@x", "b@x"], tailnet: "edit.ts.net" } }),
    patch("the same target, nothing else", "req", "edit.ts.net", { expectedVersion: 5, target: tier }),
    patch("only the version", "req", "edit.ts.net", { expectedVersion: 5 }),
    patch("a selector naming nothing", "req", "edit.ts.net", { expectedVersion: 5, selector: { tailnet: "edit.ts.net", tags: [] } }),
    patch("no version", "req", "edit.ts.net", { selector: tags("edit.ts.net") }),
    patch("version 0", "req", "edit.ts.net", { expectedVersion: 0 }),
    patch("a fractional version", "req", "edit.ts.net", { expectedVersion: 1.5 }),
    patch("a version as a string", "req", "edit.ts.net", { expectedVersion: "5" }),
    patch("an invalid target", "req", "edit.ts.net", { expectedVersion: 5, target: { kind: "tier", tier: "qa" } }),
    send("change an unknown Requirement", "PATCH", "req/requirements/req_unknownaaaaaaaaaaaaaaaaaaa", { expectedVersion: 1 }),
    patch("change a revoked Requirement", "req", "revoked.ts.net", { expectedVersion: 1, selector: tags("revoked.ts.net") }),
    send("change another Organization's Requirement", "PATCH", "req/requirements/{req:other:other.ts.net}", { expectedVersion: 1 }),
    send("change, U+0000 in the id", "PATCH", "req/requirements/a%00b", { expectedVersion: 1 }),
    send("change, U+0000 in the id, a key", "PATCH", "req/requirements/a%00b", { expectedVersion: 1 }, "alice", undefined, "nul-requirement"),
    patch("change, U+0000 in the tailnet", "req", "edit.ts.net", { expectedVersion: 5, selector: tags("a\u0000b") }),
    patch("change, a key of 201 characters", "req", "edit.ts.net", { expectedVersion: 5 }, "alice", undefined, "k".repeat(201)),
    patch("change as a member", "req", "edit.ts.net", { expectedVersion: 5, selector: tags("edit.ts.net", "tag:bob") }, "bob"),
    patch("change in a frozen Organization", "frozen", "frozen.ts.net", { expectedVersion: 1, selector: tags("frozen.ts.net", "tag:x") }),
    raw("change, a body that is not JSON", "PATCH", "req/requirements/{req:req:edit.ts.net}", "nope"),
    get("requirements after the changes", "req/requirements"),

    // Revoking.
    send("revoke a Requirement", "DELETE", "req/requirements/{req:req:remove.ts.net}"),
    send("revoke it again", "DELETE", "req/requirements/{req:req:remove.ts.net}"),
    send("revoke an unknown Requirement", "DELETE", "req/requirements/req_unknownaaaaaaaaaaaaaaaaaaa"),
    send("revoke another Organization's Requirement", "DELETE", "req/requirements/{req:other:other.ts.net}"),
    send("revoke, U+0000 in the id", "DELETE", "req/requirements/a%00b"),
    send("revoke as a member", "DELETE", "req/requirements/{req:req:edit.ts.net}", undefined, "bob"),
    send("revoke in a frozen Organization", "DELETE", "frozen/requirements/{req:frozen:frozen.ts.net}"),

    // At report: counted, done anyway; never for creating.
    create("report: create", "rep", { kind: "tailnet", target: tier, selector: tags("rep-new.ts.net") }),
    patch("report: change", "rep", "edit.ts.net", { expectedVersion: 1, selector: tags("edit.ts.net", "tag:rep") }),
    patch("report: the same meaning, another text", "rep", "edit.ts.net", { expectedVersion: 2, selector: { tags: ["tag:rep"], tailnet: "edit.ts.net" } }),
    patch("report: only the version", "rep", "edit.ts.net", { expectedVersion: 3 }),
    send("report: revoke", "DELETE", "rep/requirements/{req:rep:remove.ts.net}"),

    // At enforce: asked for, then consumed.
    create("enforce: create", "enf", { kind: "tailnet", target: tier, selector: tags("enf-new.ts.net") }, "dave"),
    patch("enforce: change, no approval", "enf", "edit.ts.net", { expectedVersion: 1, selector: tags("edit.ts.net", "tag:enf") }, "dave"),
    patch("enforce: the same meaning, no approval", "enf", "edit.ts.net", { expectedVersion: 1, selector: { tags: ["tag:ci"], tailnet: "edit.ts.net" } }, "dave"),
    patch("enforce: only the version", "enf", "edit.ts.net", { expectedVersion: 2 }, "dave"),
    patch("enforce: loosen the target, no approval", "enf", "envs.ts.net", { expectedVersion: 1, target: { kind: "environments", environmentIds: ["{env:enf:api/development}"] } }, "dave"),
    patch("enforce: U+0000 in an environment id", "enf", "envs.ts.net", { expectedVersion: 1, target: { kind: "environments", environmentIds: ["a\u0000b"] } }, "dave"),
    patch("enforce: a lone surrogate in a tag", "enf", "envs.ts.net", { expectedVersion: 1, selector: { tailnet: "envs.ts.net", tags: ["a\ud800b"] } }, "dave"),
    send("enforce: revoke, no approval", "DELETE", "enf/requirements/{req:enf:remove.ts.net}", undefined, "dave"),
    patch("enforce: a machine asks", "enf", "approve.ts.net", { expectedVersion: 1, selector: tags("approve.ts.net", "tag:machine") }, "enf-admin-svc"),
    patch("enforce: change, its approval", "enf", "approve.ts.net", { expectedVersion: 1, selector: tags("approve.ts.net", "tag:approved") }, "alice2", APPROVALS.update, "approved-1"),
    patch("enforce: change, its approval, the same key", "enf", "approve.ts.net", { expectedVersion: 1, selector: tags("approve.ts.net", "tag:approved") }, "alice2", APPROVALS.update, "approved-1"),
    patch("enforce: change, its approval again", "enf", "approve.ts.net", { expectedVersion: 2, selector: tags("approve.ts.net", "tag:approved", "tag:x") }, "alice2", APPROVALS.update),
    patch("enforce: another request's approval", "enf", "approve.ts.net", { expectedVersion: 2, selector: tags("approve.ts.net", "tag:else") }, "alice2", APPROVALS.otherBody),
    patch("enforce: an approval not given yet", "enf", "approve.ts.net", { expectedVersion: 2, selector: tags("approve.ts.net", "tag:pending") }, "alice2", APPROVALS.pending),
    patch("enforce: a malformed approval", "enf", "approve.ts.net", { expectedVersion: 2, selector: tags("approve.ts.net", "tag:pending") }, "alice2", "not-an-id"),
    send("enforce: revoke, its approval", "DELETE", "enf/requirements/{req:enf:revoke.ts.net}", undefined, "alice2", APPROVALS.revoke),
    get("enforce: requirements after the changes", "enf/requirements"),

    // Machine reach.
    get("reach of a service", "req/identities/{idn:req-svc}/reach"),
    get("reach of a machine with no Grants", "req/identities/{idn:req-ci}/reach"),
    get("reach of a retired machine", "req/identities/{idn:req-retired}/reach"),
    get("reach of a Broker", "req/identities/{idn:req-broker}/reach"),
    get("reach of an Agent", "req/identities/{idn:req-agent}/reach"),
    get("reach of a suspended machine", "deleting/identities/{idn:deleting-svc}/reach"),
    get("reach of a member", "req/identities/{idn:bob}/reach"),
    get("reach of a former member", "req/identities/{idn:erin}/reach"),
    get("reach of a person never here", "req/identities/{idn:carol}/reach"),
    get("reach of another Organization's machine", "req/identities/{idn:other-svc}/reach"),
    get("reach of an unknown identity", "req/identities/idn_unknownaaaaaaaaaaaaaaaaaaa/reach"),
    get("reach, U+0000 in the id", "req/identities/a%00b/reach"),
    get("reach as a member", "req/identities/{idn:req-svc}/reach", "bob"),
    get("reach in a frozen Organization", "frozen/identities/{idn:frozen-svc}/reach"),
    get("reach as the machine itself", "req/identities/{idn:req-svc}/reach", "req-svc"),

    // The credential review.
    get("credential review", "req/security/credential-review"),
    get("credential review of an Organization being deleted", "deleting/security/credential-review"),
    get("credential review of a frozen Organization", "frozen/security/credential-review"),
    get("credential review as a member", "req/security/credential-review", "bob"),
    get("credential review as an outsider", "req/security/credential-review", "carol"),

    // The caller's own permissions.
    get("permissions of an admin", "req/me/permissions"),
    get("permissions of a member", "req/me/permissions", "bob"),
    get("permissions of an admin in enf", "enf/me/permissions", "dave"),
    get("permissions of a machine", "req/me/permissions", "req-svc"),
    get("permissions of a machine with none", "req/me/permissions", "req-broker"),
    get("permissions of a former member", "req/me/permissions", "erin"),
    get("permissions of an outsider", "req/me/permissions", "carol"),
    get("permissions of another Organization's machine", "req/me/permissions", "other-svc"),
    get("permissions in a frozen Organization", "frozen/me/permissions"),
    get("permissions in an Organization being deleted", "deleting/me/permissions"),
  ]);
}

/** The placeholders of the table, from the file's rows. */
function fillPath(rows: Record<string, Row[]>): (p: string) => string {
  const org = (slug: string) => rows.organizations!.find((o) => o.slug === slug)!.id as string;
  const parse = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v) as Record<string, unknown>;
  const resolve = (kind: string, arg: string): string => {
    const [a, b] = arg.split(":") as [string, string | undefined];
    switch (kind) {
      case "org":
        return org(a);
      case "idn":
        return rows.identities!.find((i) => i.name === a)!.id as string;
      case "prj":
        return rows.projects!.find((p) => p.organization_id === org(a) && p.slug === b)!.id as string;
      case "env": {
        const [project, env] = b!.split("/") as [string, string];
        const pid = rows.projects!.find((p) => p.organization_id === org(a) && p.slug === project)!.id;
        return rows.environments!.find((e) => e.project_id === pid && e.name === env)!.id as string;
      }
      case "req":
        return rows.requirements!.find((r) => r.organization_id === org(a) && parse(r.config).tailnet === b)!.id as string;
    }
    throw new Error(`unknown placeholder ${kind}`);
  };
  return (p) => p.replace(/\{(org|idn|prj|env|req):([^}]+)\}/g, (_, kind: string, arg: string) => resolve(kind, arg));
}

type Call = (method: string, path: string, body?: unknown, token?: string) => Promise<any>;

async function build(): Promise<{ ctx: AppCtx & { close: () => Promise<void> }; tokens: Record<string, string> }> {
  const db = await migratedTestDb();
  const ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const grant = await issueBootstrapGrant(ctx);
  const { identityId: alice } = await consumeSetupGrant(ctx, grant.token, { adminName: "Alice" });
  const aliceCredential = await issueCredential(ctx.db, { identityId: alice, kind: "cli" });
  // A second CLI credential: enf's approval intents are its own.
  const alice2 = await issueCredential(ctx.db, { identityId: alice, kind: "cli" });
  const tokens: Record<string, string> = { alice: aliceCredential.token, alice2: alice2.token };
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
  for (const slug of ["req", "rep", "enf", "frozen", "deleting", "other"]) {
    orgs[slug] = (await call("POST", ORG, { name: slug[0]!.toUpperCase() + slug.slice(1), slug })).id;
  }
  // People: bob a member, dave an admin of enf, erin a former member, carol in none.
  const person = async (name: string, memberships: [string, "member" | "admin", boolean?][]) => {
    const id = newId("identity");
    await db.query("INSERT INTO identities (id, kind, name, created_at) VALUES ($1, 'human', $2, '2026-01-01T00:00:00.000Z')", [id, name]);
    for (const [org, role, removed] of memberships) {
      await db.query("INSERT INTO org_memberships (organization_id, identity_id, role, removed_at) VALUES ($1, $2, $3, $4)",
        [orgs[org], id, role, removed ? "2026-02-01T00:00:00.000Z" : null]);
    }
    tokens[name] = (await issueCredential(ctx.db, { identityId: id, kind: "cli" })).token;
    return id;
  };
  await person("bob", [["req", "member"], ["rep", "member"], ["enf", "member"]]);
  await person("carol", []);
  await person("dave", [["req", "member"], ["enf", "admin"]]);
  await person("erin", [["req", "member", true]]);

  const envId = async (orgId: string, project: string, name: string) =>
    (await db.query("SELECT e.id FROM environments e JOIN projects p ON p.id = e.project_id WHERE p.organization_id = $1 AND p.slug = $2 AND e.name = $3",
      [orgId, project, name])).rows[0]!.id as string;
  const machine = async (org: string, name: string, kind: string) => {
    const m = await call("POST", `${ORG}/${org}/identities`, { name, kind });
    tokens[name] = m.credential;
    return m.id as string;
  };

  const structure = async (slug: string) => {
    const org = slug;
    const svc = await machine(org, `${slug}-svc`, "service");
    const projects: Record<string, string> = {};
    for (const p of ["api", "web"]) {
      projects[p] = (await call("POST", `${ORG}/${org}/projects`, { name: p.toUpperCase(), slug: p, contractAuthority: "managed" })).id;
    }
    for (const [name, tier] of [["development", "development"], ["staging", "staging"], ["production", "production"]] as const) {
      await call("POST", `${ORG}/${org}/projects/api/environments`, { name, tier });
    }
    await call("POST", `${ORG}/${org}/projects/web/environments`, { name: "development", tier: "development" });
    const dev = await envId(orgs[slug]!, "api", "development");
    // A preview of development, and an expired one.
    await call("POST", `${ORG}/${org}/projects/api/environments`, { name: "development/pr-1", kind: "preview", parentEnvironmentId: dev });
    await call("POST", `${ORG}/${org}/projects/api/environments`, { name: "development/pr-2", kind: "preview", parentEnvironmentId: dev });
    await db.query("UPDATE environments SET expires_at = '2026-02-01T00:00:00.000Z' WHERE id = $1", [await envId(orgs[slug]!, "api", "development/pr-2")]);
    // A deleted Project.
    const old = (await call("POST", `${ORG}/${org}/projects`, { name: "Old", slug: "old", contractAuthority: "managed" })).id;
    await db.query("UPDATE projects SET deleted_at = '2026-03-01T00:00:00.000Z' WHERE id = $1", [old]);

    // Requirements: a tier, Environments, and the ones the table edits.
    const req = (target: unknown, selector: unknown) => call("POST", `${ORG}/${org}/requirements`, { kind: "tailnet", target, selector });
    await req({ kind: "tier", tier: "production" }, { tailnet: TAILNET, tags: ["tag:prod"] });
    await req({ kind: "environments", environmentIds: [dev] }, { tailnet: "dev net", users: ["alice@example.com"], nodes: ["n-dev"] });
    await req({ kind: "environments", environmentIds: [await envId(orgs[slug]!, "api", "staging")] }, { tailnet: "envs.ts.net", tags: ["tag:ci"] });
    for (const t of ["edit.ts.net", "remove.ts.net", "approve.ts.net", "revoke.ts.net"]) await req({ kind: "tier", tier: "staging" }, { tailnet: t, tags: ["tag:ci"] });
    const revoked = await req({ kind: "tier", tier: "development" }, { tailnet: "revoked.ts.net", tags: ["tag:ci"] });
    await call("DELETE", `${ORG}/${org}/requirements/${revoked.id}`);

    // The service's Grants: every scope, one through a group and a role.
    const g = (body: unknown) => call("POST", `${ORG}/${org}/grants`, body);
    await g({ subjectIdentityId: svc, scope: { kind: "organization" }, actions: ["organization.read", "identity.read"] });
    await g({ subjectIdentityId: svc, scope: { kind: "project", projectId: projects.api }, actions: ["project.read", "contract.read"] });
    await g({ subjectIdentityId: svc, scope: { kind: "environments", projectId: projects.api, selector: { kind: "tier", tier: "production" } }, actions: ["environment.read", "config.value.read", "secret.reveal"] });
    await g({ subjectIdentityId: svc, scope: { kind: "environments", projectId: projects.api, selector: { kind: "environments", environmentIds: [dev] } }, actions: ["config.metadata.read", "secret.use"] });
    const role = (await call("POST", `${ORG}/${org}/roles`, { name: "web-reader", actions: ["project.read", "environment.read", "config.value.read"] })).id;
    const devs = (await call("POST", `${ORG}/${org}/groups`, { name: "devs" })).id;
    await call("POST", `${ORG}/${org}/groups/${devs}/members`, { identityId: svc });
    await g({ subjectGroupId: devs, scope: { kind: "project", projectId: projects.web }, roleId: role });

    await machine(org, `${slug}-ci`, "ci");
    const retired = await machine(org, `${slug}-retired`, "service");
    await g({ subjectIdentityId: retired, scope: { kind: "organization" }, actions: ["organization.read"] });
    await call("POST", `${ORG}/${org}/identities/${retired}/retire`);
    await machine(org, `${slug}-broker`, "broker");
    const agent = await machine(org, `${slug}-agent`, "agent");
    await g({ subjectIdentityId: agent, scope: { kind: "environments", projectId: projects.api, selector: { kind: "tier", tier: "production" } }, actions: ["config.value.read"] });
  };
  for (const slug of ["req", "rep", "enf"]) await structure(slug);

  // req: a machine whose credentials take every state the review tells
  // apart, with times whose meaning does not change with the date.
  const rev = await machine("req", "req-review", "service"); // its first: never used, no expiry
  const issue = async (body: Record<string, unknown>, token = tokens.alice) => (await call("POST", `${ORG}/req/identities/${rev}/credentials`, body, token)).id as string;
  const cred = async (name: string, set: string, body: Record<string, unknown> = {}) => {
    const id = await issue({ name, ...body });
    await db.query(`UPDATE credentials SET ${set} WHERE id = $1`, [id]);
  };
  await cred("idle", "last_used_at = '2026-01-01T00:00:00.000Z', expires_at = '2099-01-01T00:00:00.000Z'");
  await cred("idle-forever", "last_used_at = '2026-01-01T00:00:00.000Z'");
  // Used "in 2099": never idle, whenever the file is replayed.
  await cred("fine", "last_used_at = '2099-01-01T00:00:00.000Z', expires_at = '2099-06-01T00:00:00.000Z'");
  await cred("expired", "expires_at = '2026-02-01T00:00:00.000Z'");
  await cred("expired-revoked", "expires_at = '2026-02-01T00:00:00.000Z', revoked_at = '2026-02-02T00:00:00.000Z'");
  await cred("used-up", "use_count = 1, expires_at = '2099-01-01T00:00:00.000Z'", { maxUses: 1 });
  await cred("revoked", "revoked_at = '2026-02-02T00:00:00.000Z'");
  // Short-lived kinds, left out of the review.
  await db.query(
    "INSERT INTO credentials (id, identity_id, kind, token_hash, expires_at, created_at) VALUES ($1, $2, 'oidc', $3, '2099-01-01T00:00:00.000Z', '2026-01-02T00:00:00.000Z')",
    [newId("credential"), rev, `oidc-${newId("credential")}`],
  );
  await call("POST", `${ORG}/req/identities/${await (async () => (await db.query("SELECT id FROM identities WHERE name = 'req-agent'")).rows[0]!.id)()}/credentials`,
    { ttlSeconds: 600, runId: "run-1" }, tokens["req-broker"]);
  // Its expiry is minutes away: long past instead, so it counts as no live
  // credential however late the file is replayed.
  await db.query("UPDATE credentials SET expires_at = '2026-02-01T00:00:00.000Z' WHERE kind = 'agent-run'");
  // A credential another machine issued.
  const ci = (await db.query("SELECT id FROM identities WHERE name = 'req-ci'")).rows[0]!.id as string;
  await db.query("UPDATE credentials SET issued_by = $1 WHERE identity_id = $2 AND name = 'idle'", [ci, rev]);

  // other: a machine and a Requirement; frozen and deleting: a machine and a Requirement each.
  await machine("other", "other-svc", "service");
  const otherProject = (await call("POST", `${ORG}/other/projects`, { name: "API", slug: "api", contractAuthority: "managed" })).id;
  void otherProject;
  await call("POST", `${ORG}/other/projects/api/environments`, { name: "development", tier: "development" });
  await call("POST", `${ORG}/other/requirements`, { kind: "tailnet", target: { kind: "tier", tier: "production" }, selector: { tailnet: "other.ts.net", tags: ["tag:x"] } });
  for (const slug of ["frozen", "deleting"]) {
    const m = await machine(slug, `${slug}-svc`, "service");
    await call("POST", `${ORG}/${slug}/grants`, { subjectIdentityId: m, scope: { kind: "organization" }, actions: ["organization.read"] });
    await call("POST", `${ORG}/${slug}/requirements`, { kind: "tailnet", target: { kind: "tier", tier: "production" }, selector: { tailnet: `${slug}.ts.net`, tags: ["tag:x"] } });
  }
  await db.query(
    "INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', 'incident drill')",
    [newId("organizationFreeze"), orgs.frozen, alice],
  );
  const deletion = newId("organizationDeletion");
  await db.query(
    "INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', '2099-03-01T00:00:00.000Z', false)",
    [deletion, orgs.deleting, alice],
  );
  // The deletion suspends its machines.
  await db.query("UPDATE identities SET disabled = true, suspended_by_deletion = $1 WHERE organization_id = $2", [deletion, orgs.deleting]);

  // enf: an admin machine (a Grant of policy.manage), to ask as a machine.
  const adminSvc = await machine("enf", "enf-admin-svc", "service");
  await call("POST", `${ORG}/enf/grants`, { subjectIdentityId: adminSvc, scope: { kind: "organization" }, actions: ["policy.manage", "organization.read"] });

  // The controls: rep at report, enf at enforce.
  const set = (org: string, body: unknown) => call("PATCH", `${ORG}/${org}/security/controls/requirement-protection`, body);
  await set("rep", { mode: "report", expectedVersion: 0 });
  await set("enf", { mode: "report", expectedVersion: 0 });
  await set("enf", { mode: "enforce", expectedVersion: 1 });

  // Approval intents of alice's second CLI credential in enf, each binding
  // one request of the table exactly as the operation binds it.
  const enf = { id: orgs.enf! };
  const requirement = async (tailnet: string) => {
    const id = (await db.query("SELECT id FROM requirements WHERE organization_id = $1 AND config->>'tailnet' = $2", [enf.id, tailnet])).rows[0]!.id as string;
    return (await readRequirement(db, enf.id, id))!;
  };
  const intent = async (aid: string, binding: ApprovalBinding, approved: boolean) =>
    db.query(
      `INSERT INTO approval_intents
         (id, credential_id, identity_id, organization_id, operation, target, body_hash, query_hash, expected_version, summary, origin,
          created_at, expires_at, poll_interval, approved_at, approved_with_passkey_id, approval_user_verified)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10::jsonb, 'cli',
               '2026-01-10T00:00:00.000Z', '2099-01-01T00:00:00.000Z', 5, $11, $12, $13)`,
      [
        aid, alice2.credentialId, alice, enf.id, binding.operation, canonicalJson(binding.target),
        approvalHash(ctx.rootKek, "body", binding.body), approvalHash(ctx.rootKek, "query", binding.query), binding.expectedVersion,
        JSON.stringify(binding.summary),
        approved ? "2026-01-10T00:01:00.000Z" : null, approved ? "PasskeyConf001" : null, approved ? true : null,
      ],
    );
  const approve = await requirement("approve.ts.net");
  const next = (...t: string[]) => ({ target: approve.target, selector: { tailnet: "approve.ts.net", tags: t } });
  await intent(APPROVALS.update, await requirementUpdateBinding(db, enf, approve, next("tag:approved"), 1), true);
  await intent(APPROVALS.otherBody, await requirementUpdateBinding(db, enf, approve, next("tag:something-else"), 2), true);
  await intent(APPROVALS.pending, await requirementUpdateBinding(db, enf, approve, next("tag:pending"), 2), false);
  await intent(APPROVALS.revoke, await requirementRevokeBinding(db, enf, await requirement("revoke.ts.net")), true);

  await accessCountsSettled();
  // The setup's sign-ins leave last-seen and last-used times a minute at
  // most from a replay run at once: an old time instead, which every
  // replay's first use moves on.
  await db.query("UPDATE identities SET last_seen_at = '2026-01-15T00:00:00.000Z' WHERE last_seen_at > '2026-03-02T00:00:00.000Z'");
  await db.query("UPDATE credentials SET last_used_at = '2026-01-15T00:00:00.000Z' WHERE last_used_at > '2026-03-02T00:00:00.000Z' AND last_used_at < '2099-01-01T00:00:00.000Z'");
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
        comment: "Written by services/varlatchd/test/go-requirements-fixture.test.ts from the TypeScript server's own answers; do not edit.",
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

describe("the requirements fixture is this server's answers", () => {
  it("requirements-v0.22.0.json", async () => {
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
