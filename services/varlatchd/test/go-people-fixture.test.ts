// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.5a's parity fixture (ADR-0059 step 4, feature-parity decision 3),
 * on the parity kit (go-fixture-kit.ts): invitations (listed, issued,
 * revoked), members (reviewed, promoted, demoted, removed, leaving) and the
 * profile a person edits, built through this server's own /v1 API, and a
 * table of requests with this server's answers. go/server/people's parity
 * test replays it against varlatchd.
 *
 * The database: alice (the bootstrap Installation Admin) and Organizations
 * made through /v1: ppl (every control off), rep (admin-step-up at
 * report), enf (admin-step-up at enforce), solo (alice its only admin),
 * frozen (an incident freeze), deleting (a deletion scheduled) and other.
 * In ppl, rep and enf: Projects api (development, production), a Grant and
 * a Requirement, and people to promote, demote, remove and let leave. In
 * ppl, pam also has a group, a Grant, invitations she issued, and things
 * she set up (a Sync Target, a connection and one she changed, a webhook,
 * an OIDC binding, a machine credential she issued, a personal
 * environment), so removing her records an authority snapshot and a
 * review. Invitations in every state, with pinned times. People: bob (a
 * member), dave (an admin), erin (a former member), carol (in none).
 * Approval intents of alice's second CLI credential in enf, bound to exact
 * requests of the table.
 *
 * Every time the rows hold keeps its meaning whenever the file is
 * replayed: invitations still pending expire in 2099, expired ones
 * expired in 2026.
 *
 * Paths name rows by what they are: {org:SLUG}, {idn:NAME},
 * {inv:ORG:NAME} (the invitation of that invitee name).
 *
 * Every run checks the committed file: its requests must be the table's,
 * and this server, on the file's rows, must give the recorded answers.
 * After a change, regenerate it and commit the result:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-people-fixture.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { newId } from "../src/db/ids.js";
import { approvalHash, canonicalJson, type ApprovalBinding } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { inviteAdminBinding, memberRemoveBinding, memberRoleBinding, readMember, removalCounts } from "../src/domain/peoplestepup.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { encodeCursor } from "../src/http/support.js";
import { migratedTestDb } from "./helpers/pglite.js";
import {
  expectCurrentTable, expectSameAnswers, expectSameRows, exportRows, loadRows, record, withIds,
  type Fixture, type RequestCase, type Row, type SideTable, type Table,
} from "./go-fixture-kit.js";

// The unwrapped app: some requests are outside the OpenAPI document on
// purpose (bodies that are not JSON, extra members).
const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const FILE = new URL("../../../go/server/paritytest/testdata/people-v0.22.0.json", import.meta.url);

/** The public URL both servers run with: approvals need one. */
export const PUBLIC_URL = "http://127.0.0.1:8686";

const TABLES: Table[] = [
  { name: "installation", orderBy: "id", random: ["kek_canary"] },
  { name: "identities", orderBy: "id" },
  { name: "user", orderBy: "id" },
  { name: "auth_user_links", orderBy: "better_auth_user_id" },
  { name: "credentials", orderBy: "id", random: ["token_hash"] },
  { name: "setup_grants", orderBy: "id", random: ["token_hash"] },
  { name: "organizations", orderBy: "id", random: ["wrapped_org_kek"] },
  { name: "org_memberships", orderBy: "organization_id, identity_id" },
  { name: "projects", orderBy: "id" },
  { name: "environments", orderBy: "id" },
  { name: "roles", orderBy: "id" },
  { name: "groups", orderBy: "id" },
  { name: "group_members", orderBy: "group_id, identity_id" },
  { name: "grants", orderBy: "id" },
  { name: "requirements", orderBy: "id" },
  { name: "platform_connections", orderBy: "id" },
  { name: "sync_targets", orderBy: "id" },
  { name: "member_integrations", orderBy: "organization_id, identity_id, kind, resource_id" },
  { name: "webhooks", orderBy: "id" },
  { name: "oidc_bindings", orderBy: "id" },
  { name: "membership_removals", orderBy: "id" },
  { name: "removal_authority", orderBy: "removal_id, environment_id, action, source" },
  { name: "removal_requirements", orderBy: "removal_id, requirement_id" },
  { name: "removal_conditions", orderBy: "removal_id, environment_id, requirement_id" },
  { name: "security_controls", orderBy: "organization_id, control" },
  { name: "security_control_counters", orderBy: "organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour" },
  // The intents' hashes are keyed by the build's random Root KEK.
  { name: "approval_intents", orderBy: "id", random: ["body_hash", "query_hash"] },
  { name: "organization_freezes", orderBy: "id" },
  { name: "organization_deletions", orderBy: "id" },
];

const SIDE: SideTable[] = [
  { name: "setup_grants", key: ["id"], sortBy: ["invite_organization_id", "invite_name", "revoked_at"], volatile: ["token_hash", "created_at", "expires_at", "revoked_at"] },
  { name: "org_memberships", key: ["organization_id", "identity_id"], sortBy: ["organization_id", "identity_id"], volatile: ["created_at", "removed_at"] },
  { name: "membership_removals", key: ["id"], sortBy: ["organization_id", "identity_id"], volatile: ["removed_at"] },
  { name: "removal_authority", key: ["removal_id", "environment_id", "action", "source"], sortBy: ["environment_id", "action", "source"], volatile: [] },
  { name: "removal_requirements", key: ["removal_id", "requirement_id"], sortBy: ["requirement_id"], volatile: [] },
  { name: "removal_conditions", key: ["removal_id", "environment_id", "requirement_id"], sortBy: ["environment_id", "requirement_id"], volatile: [] },
  { name: "grants", key: ["id"], sortBy: ["organization_id", "scope", "actions"], volatile: ["created_at", "revoked_at"] },
  { name: "group_members", key: ["group_id", "identity_id"], sortBy: ["group_id", "identity_id"], volatile: ["created_at"] },
  { name: "identities", key: ["id"], sortBy: ["name"], volatile: ["created_at", "last_seen_at"] },
  { name: "user", key: ["id"], sortBy: ["email"], volatile: ["createdAt", "updatedAt"] },
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
  inviteAdmin: aprId("inviteadmin"),
  promote: aprId("promote"),
  demote: aprId("demote"),
  remove: aprId("remove"),
  otherBody: aprId("otherbody"),
  pending: aprId("pending"),
} as const;

/** Invitations' pinned creation times, for cursors that name them. */
const T = (n: number) => `2026-01-0${n}T00:00:00.000Z`;
const cursorAt = (time: string, id: string) => encodeCursor([time, id]);

/** The table of requests. */
function requestTable(): RequestCase[] {
  type H = Record<string, string>;
  const headers = (approval?: string): { headers?: H } => (approval !== undefined ? { headers: { "Varlatch-Approval": approval } } : {});
  const get = (name: string, path: string, credential = "alice"): Omit<RequestCase, "id"> => ({ name, method: "GET", path: `${ORG}/${path}`, credential });
  const send = (name: string, method: string, path: string, body?: unknown, credential = "alice", approval?: string): Omit<RequestCase, "id"> => ({
    name, method, path: `${ORG}/${path}`, credential, ...(body !== undefined ? { body } : {}), ...headers(approval),
  });
  const raw = (name: string, method: string, path: string, rawBody: string): Omit<RequestCase, "id"> => ({ name, method, path: `${ORG}/${path}`, credential: "alice", rawBody });
  const invite = (name: string, org: string, body: unknown, credential = "alice", approval?: string): Omit<RequestCase, "id"> => ({
    ...send(name, "POST", `${org}/invitations`, body, credential, approval), masked: ["token"],
  });
  const profile = (name: string, body: unknown, credential = "alice"): Omit<RequestCase, "id"> => ({ name, method: "PATCH", path: "/v1/me/profile", credential, body });
  return withIds([
    // Listing invitations.
    get("invitations", "ppl/invitations"),
    get("invitations by id", "{org:ppl}/invitations"),
    get("every invitation", "ppl/invitations?status=all"),
    get("invitations, two a page", "ppl/invitations?status=all&limit=2"),
    get("invitations after a cursor", `ppl/invitations?status=all&cursor=${cursorAt("2026-01-03 00:00:00+00", "sgr_zzzzzzzzzzzzzzzzzzzzzzzzzz")}`),
    get("invitations after a cursor in another form", `ppl/invitations?status=all&cursor=${cursorAt("2026-01-03", "sgr_zzzzzzzzzzzzzzzzzzzzzzzzzz")}`),
    get("invitations, a cursor PostgreSQL cannot read", `ppl/invitations?status=all&cursor=${cursorAt("not a time", "x")}`),
    get("invitations, a cursor of one part", `ppl/invitations?cursor=${encodeCursor(["2026-01-03 00:00:00+00"])}`),
    get("invitations, a cursor that is not one", "ppl/invitations?cursor=nope"),
    get("invitations, an empty cursor", "ppl/invitations?cursor="),
    get("invitations, an unknown status", "ppl/invitations?status=revoked"),
    get("invitations, an empty status", "ppl/invitations?status="),
    get("invitations, limit 0", "ppl/invitations?limit=0"),
    get("invitations, limit 501", "ppl/invitations?limit=501"),
    get("invitations, limit 1000", "ppl/invitations?limit=1000"),
    get("invitations, a limit that is not a number", "ppl/invitations?limit=two"),
    get("invitations, limit 007", "ppl/invitations?status=all&limit=007"),
    get("invitations as a member", "ppl/invitations", "bob"),
    get("invitations as an outsider", "ppl/invitations", "carol"),
    get("invitations of a frozen Organization", "frozen/invitations"),
    get("invitations of an unknown Organization", "nope/invitations"),

    // Issuing invitations.
    invite("invite a member", "ppl", { name: "Nina", role: "member" }),
    invite("invite an admin", "ppl", { name: "Omar", role: "admin" }),
    invite("invite, extra members", "ppl", { name: "Pia", role: "member", extra: true }),
    invite("invite, a name of 101 emoji", "ppl", { name: "\u{1F600}".repeat(101), role: "member" }),
    invite("invite, an empty name", "ppl", { name: "", role: "member" }),
    invite("invite, a name of 201 characters", "ppl", { name: "n".repeat(201), role: "member" }),
    invite("invite, an unknown role", "ppl", { name: "Ann", role: "owner" }),
    invite("invite, nothing", "ppl", {}),
    invite("invite, U+0000 in the name", "ppl", { name: "a\u0000b", role: "member" }),
    raw("invite, a body that is not JSON", "POST", "ppl/invitations", "{"),
    invite("invite as a member", "ppl", { name: "Bea", role: "member" }, "bob"),
    invite("invite as a machine", "ppl", { name: "Cal", role: "admin" }, "ppl-admin-svc"),
    invite("invite in a frozen Organization", "frozen", { name: "Dee", role: "member" }),
    invite("invite in an Organization being deleted", "deleting", { name: "Eve", role: "member" }),

    // Revoking invitations.
    send("revoke a pending invitation", "DELETE", "ppl/invitations/{inv:ppl:Pending-1}"),
    send("revoke it again", "DELETE", "ppl/invitations/{inv:ppl:Pending-1}"),
    send("revoke a consumed invitation", "DELETE", "ppl/invitations/{inv:ppl:Consumed}"),
    send("revoke an expired invitation", "DELETE", "ppl/invitations/{inv:ppl:Expired}"),
    send("revoke an unknown invitation", "DELETE", "ppl/invitations/sgr_unknownaaaaaaaaaaaaaaaaaaa"),
    send("revoke another Organization's invitation", "DELETE", "ppl/invitations/{inv:other:Other}"),
    send("revoke, U+0000 in the id", "DELETE", "ppl/invitations/a%00b"),
    send("revoke as a member", "DELETE", "ppl/invitations/{inv:ppl:Pending-2}", undefined, "bob"),
    send("revoke in a frozen Organization", "DELETE", "frozen/invitations/{inv:frozen:Frozen}"),
    get("every invitation after the changes", "ppl/invitations?status=all"),

    // The review before a removal.
    get("review a member", "ppl/members/{idn:pam}/review"),
    get("review yourself", "ppl/members/me/review", "bob"),
    get("review someone else as a member", "ppl/members/{idn:quinn}/review", "bob"),
    get("review a former member", "ppl/members/{idn:erin}/review"),
    get("review an unknown person", "ppl/members/idn_unknownaaaaaaaaaaaaaaaaaaa/review"),
    get("review, U+0000 in the id", "ppl/members/a%00b/review"),
    get("review in a frozen Organization", "frozen/members/{idn:bob}/review"),
    get("review as an outsider", "ppl/members/{idn:pam}/review", "carol"),

    // Role changes.
    send("promote a member", "PATCH", "ppl/members/{idn:sam}", { role: "admin" }),
    send("promote them again", "PATCH", "ppl/members/{idn:sam}", { role: "admin" }),
    send("demote an admin", "PATCH", "ppl/members/{idn:ross}", { role: "member" }),
    send("demote the last admin", "PATCH", "solo/members/me", { role: "member" }),
    send("change a role, an unknown role", "PATCH", "ppl/members/{idn:sam}", { role: "owner" }),
    send("change a role, an extra member", "PATCH", "ppl/members/{idn:sam}", { role: "admin", note: "x" }),
    send("change a role, extra members", "PATCH", "ppl/members/{idn:sam}", { note: "x", role: "nope", other: 1 }),
    raw("change a role, a body that is not JSON", "PATCH", "ppl/members/{idn:sam}", "{"),
    send("change an unknown person's role", "PATCH", "ppl/members/idn_unknownaaaaaaaaaaaaaaaaaaa", { role: "admin" }),
    send("change a former member's role", "PATCH", "ppl/members/{idn:erin}", { role: "admin" }),
    send("change a role as a member", "PATCH", "ppl/members/{idn:sam}", { role: "member" }, "bob"),
    send("change a role as a machine", "PATCH", "ppl/members/{idn:sam}", { role: "member" }, "ppl-admin-svc"),
    send("change a role, U+0000 in the id", "PATCH", "ppl/members/a%00b", { role: "admin" }),
    send("promote in a frozen Organization", "PATCH", "frozen/members/{idn:bob}", { role: "admin" }),
    send("demote in a frozen Organization", "PATCH", "frozen/members/{idn:dave}", { role: "member" }),

    // Removal and leaving.
    send("remove a member", "DELETE", "ppl/members/{idn:pam}"),
    send("remove them again", "DELETE", "ppl/members/{idn:pam}"),
    send("leave", "DELETE", "ppl/members/me", undefined, "lea"),
    send("leave as the last admin", "DELETE", "solo/members/me"),
    send("remove the last admin", "DELETE", "solo/members/{idn:Alice}"),
    send("remove as a member", "DELETE", "ppl/members/{idn:quinn}", undefined, "bob"),
    send("remove as a machine", "DELETE", "ppl/members/{idn:quinn}", undefined, "ppl-admin-svc"),
    send("remove an unknown person", "DELETE", "ppl/members/idn_unknownaaaaaaaaaaaaaaaaaaa"),
    send("remove, U+0000 in the id", "DELETE", "ppl/members/a%00b"),
    send("remove in a frozen Organization", "DELETE", "frozen/members/{idn:bob}"),
    send("remove in an Organization being deleted", "DELETE", "deleting/members/{idn:bob}"),
    get("pam's grants after her removal", "ppl/grants"),
    get("invitations after pam's removal", "ppl/invitations?status=all"),

    // At report: counted, done anyway.
    invite("report: invite an admin", "rep", { name: "Rex", role: "admin" }),
    invite("report: invite a member", "rep", { name: "Ria", role: "member" }),
    send("report: promote", "PATCH", "rep/members/{idn:sam}", { role: "admin" }),
    send("report: demote", "PATCH", "rep/members/{idn:ross}", { role: "member" }),
    send("report: remove", "DELETE", "rep/members/{idn:quinn}"),
    send("report: leave", "DELETE", "rep/members/me", undefined, "lea"),

    // At enforce: asked for, then consumed.
    invite("enforce: invite an admin, no approval", "enf", { name: "Ace", role: "admin" }, "dave"),
    invite("enforce: invite a member, no approval", "enf", { name: "Ava", role: "member" }, "dave"),
    send("enforce: promote, no approval", "PATCH", "enf/members/{idn:sam}", { role: "admin" }, "dave"),
    send("enforce: promote an admin, no approval", "PATCH", "enf/members/{idn:ross}", { role: "admin" }, "dave"),
    send("enforce: remove, no approval", "DELETE", "enf/members/{idn:quinn}", undefined, "dave"),
    send("enforce: leave", "DELETE", "enf/members/me", undefined, "lea"),
    invite("enforce: a machine asks", "enf", { name: "Bot", role: "admin" }, "enf-admin-svc"),
    invite("enforce: invite an admin, its approval", "enf", { name: "Approved", role: "admin" }, "alice2", APPROVALS.inviteAdmin),
    invite("enforce: invite an admin, its approval again", "enf", { name: "Approved", role: "admin" }, "alice2", APPROVALS.inviteAdmin),
    invite("enforce: another request's approval", "enf", { name: "Someone", role: "admin" }, "alice2", APPROVALS.otherBody),
    invite("enforce: an approval not given yet", "enf", { name: "Pending", role: "admin" }, "alice2", APPROVALS.pending),
    invite("enforce: a malformed approval", "enf", { name: "Pending", role: "admin" }, "alice2", "nope"),
    send("enforce: promote, its approval", "PATCH", "enf/members/{idn:sam}", { role: "admin" }, "alice2", APPROVALS.promote),
    send("enforce: demote, its approval", "PATCH", "enf/members/{idn:ross}", { role: "member" }, "alice2", APPROVALS.demote),
    send("enforce: remove, its approval", "DELETE", "enf/members/{idn:quinn}", undefined, "alice2", APPROVALS.remove),

    // The profile.
    profile("rename yourself", { name: "Bobby" }, "bob"),
    profile("set an image", { image: "data:image/png;base64,iVBORw0KGgo=" }, "bob"),
    profile("set an https image", { image: "HTTPS://img.example/a.png" }, "bob"),
    profile("clear the image", { image: null }, "bob"),
    profile("both, extra members", { name: "Bob", image: "https://img.example/b.png", extra: 1 }, "bob"),
    profile("change nothing", {}, "bob"),
    profile("an image of another scheme", { image: "http://img.example/a.png" }, "bob"),
    profile("an image that is not one", { image: "data:text/plain;base64,aGk=" }, "bob"),
    profile("an image over 100KB", { image: `data:image/png;${"é".repeat(52_000)}` }, "bob"),
    profile("an image over 102,400 characters", { image: `https://${"a".repeat(102_400)}` }, "bob"),
    profile("an image that is a number", { image: 7 }, "bob"),
    profile("an empty name", { name: "" }, "bob"),
    profile("a name of 201 characters", { name: "b".repeat(201) }, "bob"),
    profile("a name that is null", { name: null }, "bob"),
    profile("U+0000 in the name", { name: "a\u0000b" }, "bob"),
    profile("U+0000 in the image", { image: "https://a\u0000b" }, "bob"),
    profile("a machine", { name: "Robot" }, "ppl-admin-svc"),
    { name: "a profile body that is not JSON", method: "PATCH", path: "/v1/me/profile", credential: "bob", rawBody: "{" },
  ]);
}

/** The placeholders of the table, from the file's rows. */
function fillPath(rows: Record<string, Row[]>): (p: string) => string {
  const org = (slug: string) => rows.organizations!.find((o) => o.slug === slug)!.id as string;
  const resolve = (kind: string, arg: string): string => {
    const [a, b] = arg.split(":") as [string, string | undefined];
    switch (kind) {
      case "org":
        return org(a);
      case "idn":
        return rows.identities!.find((i) => i.name === a)!.id as string;
      case "inv":
        return rows.setup_grants!.find((g) => g.invite_organization_id === org(a) && g.invite_name === b)!.id as string;
    }
    throw new Error(`unknown placeholder ${kind}`);
  };
  return (p) => p.replace(/\{(org|idn|inv):([^}]+)\}/g, (_, kind: string, arg: string) => resolve(kind, arg));
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
  for (const slug of ["ppl", "rep", "enf", "solo", "frozen", "deleting", "other"]) {
    orgs[slug] = (await call("POST", ORG, { name: slug[0]!.toUpperCase() + slug.slice(1), slug })).id;
  }
  // People, each with an account (a profile) and a CLI credential.
  const ids: Record<string, string> = { alice };
  const person = async (name: string, memberships: [string, "member" | "admin", boolean?][]) => {
    const id = newId("identity");
    await db.query("INSERT INTO identities (id, kind, name, created_at) VALUES ($1, 'human', $2, '2026-01-01T00:00:00.000Z')", [id, name]);
    const userId = `user_${name}`;
    await db.query(`INSERT INTO "user" (id, name, email, "emailVerified", "createdAt", "updatedAt") VALUES ($1, $2, $3, true, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`,
      [userId, name, `${name}@example.com`]);
    await db.query("INSERT INTO auth_user_links (better_auth_user_id, identity_id) VALUES ($1, $2)", [userId, id]);
    for (const [org, role, removed] of memberships) {
      await db.query("INSERT INTO org_memberships (organization_id, identity_id, role, removed_at) VALUES ($1, $2, $3, $4)",
        [orgs[org], id, role, removed ? "2026-02-01T00:00:00.000Z" : null]);
    }
    tokens[name] = (await issueCredential(ctx.db, { identityId: id, kind: "cli" })).token;
    ids[name] = id;
    return id;
  };
  const all = (role: "member" | "admin"): [string, "member" | "admin"][] => [["ppl", role], ["rep", role], ["enf", role]];
  await person("bob", [...all("member"), ["frozen", "member"], ["deleting", "member"]]);
  await person("carol", []);
  await person("dave", [...all("admin"), ["frozen", "admin"]]);
  await person("erin", [["ppl", "member", true]]);
  await person("pam", [["ppl", "member"]]);
  for (const name of ["quinn", "sam", "lea"]) await person(name, all("member"));
  await person("ross", all("admin"));

  const machine = async (org: string, name: string, kind = "service") => {
    const m = await call("POST", `${ORG}/${org}/identities`, { name, kind });
    tokens[name] = m.credential;
    ids[name] = m.id;
    return m.id as string;
  };
  const structure = async (slug: string) => {
    const org = slug;
    await call("POST", `${ORG}/${org}/projects`, { name: "API", slug: "api", contractAuthority: "managed" });
    for (const [name, tier] of [["development", "development"], ["production", "production"]] as const) {
      await call("POST", `${ORG}/${org}/projects/api/environments`, { name, tier });
    }
    await call("POST", `${ORG}/${org}/requirements`, { kind: "tailnet", target: { kind: "tier", tier: "production" }, selector: { tailnet: "example.ts.net", tags: ["tag:prod"] } });
  };
  for (const slug of ["ppl", "rep", "enf"]) await structure(slug);

  // ppl: what pam set up and holds.
  const pam = ids.pam!;
  const ppl = orgs.ppl!;
  const project = (await db.query("SELECT id FROM projects WHERE organization_id = $1 AND slug = 'api'", [ppl])).rows[0]!.id as string;
  const env = async (name: string) => (await db.query("SELECT id FROM environments WHERE project_id = $1 AND name = $2", [project, name])).rows[0]!.id as string;
  const production = await env("production");
  await call("POST", `${ORG}/ppl/grants`, {
    subjectIdentityId: pam, scope: { kind: "environments", projectId: project, selector: { kind: "tier", tier: "production" } }, actions: ["config.value.read", "secret.reveal"],
  });
  const devs = (await call("POST", `${ORG}/ppl/groups`, { name: "devs" })).id;
  await call("POST", `${ORG}/ppl/groups/${devs}/members`, { identityId: pam });
  const reader = (await call("POST", `${ORG}/ppl/roles`, { name: "reader", actions: ["config.metadata.read"] })).id;
  await call("POST", `${ORG}/ppl/grants`, { subjectGroupId: devs, scope: { kind: "project", projectId: project }, roleId: reader });
  const svc = await machine("ppl", "ppl-svc");
  // A machine credential pam issued, a personal environment she owns.
  await db.query("UPDATE credentials SET issued_by = $1 WHERE identity_id = $2", [pam, svc]);
  await db.query(
    `INSERT INTO environments (id, project_id, name, kind, tier, parent_environment_id, owner_identity_id, created_at)
     VALUES ($1, $2, 'development/pam', 'personal', 'development', $3, $4, '2026-01-05T00:00:00.000Z')`,
    [newId("environment"), project, await env("development"), pam],
  );
  // A connection and a Sync Target she created, one connection she changed,
  // a webhook and an OIDC binding she made.
  const connection = (name: string, by: string | null) =>
    db.query(
      `INSERT INTO platform_connections (id, organization_id, platform, base_identity, name, credential_envelope, created_by, created_at)
       VALUES ($1, $2, 'vercel', 'team-x', $3, '{}'::jsonb, $4, '2026-01-05T00:00:00.000Z') RETURNING id`,
      [newId("platformConnection"), ppl, name, by],
    ).then((r) => (r.rows[0] as { id: string }).id);
  const mine = await connection("pam's", pam);
  const theirs = await connection("someone's", null);
  await db.query(
    `INSERT INTO sync_targets (id, organization_id, project_id, environment_id, connection_id, destination, canonical_destination, mapping, created_by, created_at)
     VALUES ($1, $2, $3, $4, $5, '{}'::jsonb, 'vercel:x', '{}'::jsonb, $6, '2026-01-05T00:00:00.000Z')`,
    [newId("syncTarget"), ppl, project, production, mine, pam],
  );
  await db.query(
    `INSERT INTO member_integrations (organization_id, identity_id, kind, resource_id, changes, first_at, last_at)
     VALUES ($1, $2, 'connection', $3, ARRAY['credential_replaced','credential_replaced'], '2026-01-06T00:00:00.000Z', '2026-01-07T00:00:00.000Z')`,
    [ppl, pam, theirs],
  );
  await db.query(
    `INSERT INTO webhooks (id, organization_id, url, secret_envelope, cursor_occurred_at, created_by, created_at)
     VALUES ($1, $2, 'https://Hooks.Example:443/in', '{}'::jsonb, '2026-01-05T00:00:00.000Z', $3, '2026-01-05T00:00:00.000Z')`,
    [newId("webhook"), ppl, pam],
  );
  await db.query(
    `INSERT INTO oidc_bindings (id, identity_id, organization_id, issuer, audience, subject, created_by, created_at)
     VALUES ($1, $2, $3, 'https://token.actions.githubusercontent.com', 'varlatch', 'repo:x', $4, '2026-01-05T00:00:00.000Z')`,
    [newId("oidcBinding"), svc, ppl, pam],
  );

  // Invitations in every state, at pinned times: pending ones expire in
  // 2099, the expired one in 2026; pam issued two that her removal revokes.
  const invitation = async (org: string, name: string, n: number, by: string, set = "", expires = "2099-01-01T00:00:00.000Z") => {
    const id = (await call("POST", `${ORG}/${org}/invitations`, { name, role: "member" })).id as string;
    await db.query(`UPDATE setup_grants SET created_at = $2, expires_at = $4, created_by = $3 ${set} WHERE id = $1`, [id, T(n), by, expires]);
  };
  await invitation("ppl", "Pending-1", 1, alice);
  await invitation("ppl", "Pending-2", 2, alice);
  await invitation("ppl", "Consumed", 3, alice, ", consumed_at = '2026-01-04T00:00:00.000Z'");
  await invitation("ppl", "Revoked", 4, alice, ", revoked_at = '2026-01-04T00:00:00.000Z'");
  await invitation("ppl", "Expired", 5, alice, "", "2026-01-06T00:00:00.000Z");
  await invitation("ppl", "By pam", 6, pam);
  await invitation("ppl", "Also by pam", 7, pam);
  await invitation("other", "Other", 1, alice);
  await invitation("frozen", "Frozen", 1, alice);

  // ppl and enf: an admin machine (identity.manage), to ask as a machine.
  for (const org of ["ppl", "enf"]) {
    const m = await machine(org, `${org}-admin-svc`);
    await call("POST", `${ORG}/${org}/grants`, { subjectIdentityId: m, scope: { kind: "organization" }, actions: ["identity.manage", "organization.read"] });
  }

  await db.query(
    "INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', 'incident drill')",
    [newId("organizationFreeze"), orgs.frozen, alice],
  );
  await db.query(
    "INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', '2099-03-01T00:00:00.000Z', false)",
    [newId("organizationDeletion"), orgs.deleting, alice],
  );

  // The controls: rep at report, enf at enforce.
  const set = (org: string, body: unknown) => call("PATCH", `${ORG}/${org}/security/controls/admin-step-up`, body);
  await set("rep", { mode: "report", expectedVersion: 0 });
  await set("enf", { mode: "report", expectedVersion: 0 });
  await set("enf", { mode: "enforce", expectedVersion: 1 });

  // Approval intents of alice's second CLI credential in enf, each binding
  // one request of the table exactly as the operation binds it.
  const enf = { id: orgs.enf!, name: "Enf" };
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
  await intent(APPROVALS.inviteAdmin, inviteAdminBinding(enf, { name: "Approved" }), true);
  await intent(APPROVALS.otherBody, inviteAdminBinding(enf, { name: "Someone else" }), true);
  await intent(APPROVALS.pending, inviteAdminBinding(enf, { name: "Pending" }), false);
  await intent(APPROVALS.promote, memberRoleBinding(enf, (await readMember(db, enf.id, ids.sam!))!, "admin"), true);
  await intent(APPROVALS.demote, memberRoleBinding(enf, (await readMember(db, enf.id, ids.ross!))!, "member"), true);
  const quinn = (await readMember(db, enf.id, ids.quinn!))!;
  await intent(APPROVALS.remove, memberRemoveBinding(enf, quinn, await removalCounts(db, enf.id, ids.quinn!)), true);

  await accessCountsSettled();
  // The setup's sign-ins leave last-seen and last-used times a minute at
  // most from a replay run at once: an old time instead, which every
  // replay's first use moves on.
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
        comment: "Written by services/varlatchd/test/go-people-fixture.test.ts from the TypeScript server's own answers; do not edit.",
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

describe("the people fixture is this server's answers", () => {
  it("people-v0.22.0.json", async () => {
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
