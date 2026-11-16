// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.4b's parity fixture (ADR-0059 step 4, feature-parity decision 3),
 * on the parity kit (go-fixture-kit.ts): Grants, Roles, Groups and Teams,
 * their memberships and Team-Project links, built through this server's
 * own /v1 API, and a table of requests with this server's answers.
 * go/server/access' parity test replays it against varlatchd.
 *
 * The database: alice (the bootstrap Installation Admin) and Organizations
 * made through /v1: acc (every control off), rep (admin-step-up at
 * report), enf (admin-step-up at enforce), frozen (an incident freeze),
 * deleting (a deletion scheduled) and other. In each of acc, rep and enf:
 * Projects api (development, production) and web, a deleted Project, a
 * service identity, roles, a group and a team with members and a Project,
 * and Grants of every shape (a preset to an identity, an environment
 * selector, a tier, a team scope, a role to a group), one revoked. People:
 * bob (a member), dave (an admin, who asks for approvals in enf, as do
 * ask1 and ask2), erin (a former member), carol (in none). Approval intents
 * of alice's second CLI credential in enf, bound to exact requests of the
 * table.
 *
 * Paths name rows by what they are: {org:SLUG}, {idn:NAME}, {role:ORG:NAME},
 * {group:ORG:NAME} (groups and teams), {prj:ORG:SLUG}, {env:ORG:PROJECT/NAME}
 * and {grant:ORG:MARK}, the Grant whose actions include MARK or whose role
 * is named MARK.
 *
 * Every run checks the committed file: its requests must be the table's,
 * and this server, on the file's rows, must give the recorded answers.
 * After a change, regenerate it and commit the result:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-access-fixture.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { newId } from "../src/db/ids.js";
import { approvalHash, canonicalJson, type ApprovalBinding } from "../src/domain/approvals.js";
import {
  grantCreateBinding, grantReplaceBinding, grantRevokeBinding, groupCreateBinding, groupDeleteBinding, groupUpdateBinding,
  memberAddBinding, memberRemoveBinding, readGrant, readGroup, readLiveProject, readPerson, readRole, roleCreateBinding,
  roleDeleteBinding, roleUpdateBinding, teamProjectAddBinding, teamProjectRemoveBinding,
} from "../src/domain/accessstepup.js";
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

const FILE = new URL("../../../go/server/paritytest/testdata/access-v0.22.0.json", import.meta.url);

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
  { name: "security_controls", orderBy: "organization_id, control" },
  { name: "security_control_counters", orderBy: "organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour" },
  // The intents' hashes are keyed by the build's random Root KEK.
  { name: "approval_intents", orderBy: "id", random: ["body_hash", "query_hash"] },
  { name: "organization_freezes", orderBy: "id" },
  { name: "organization_deletions", orderBy: "id" },
  { name: "idempotency_keys", orderBy: "identity_id, endpoint, idempotency_key" },
];

const SIDE: SideTable[] = [
  { name: "grants", key: ["id"], sortBy: ["organization_id", "scope", "actions", "role_id", "revoked_at"], volatile: ["created_at", "revoked_at"] },
  { name: "roles", key: ["id"], sortBy: ["organization_id", "name", "revoked_at"], volatile: ["created_at", "updated_at", "revoked_at"] },
  { name: "groups", key: ["id"], sortBy: ["organization_id", "name", "revoked_at"], volatile: ["created_at", "updated_at", "revoked_at"] },
  { name: "group_members", key: ["group_id", "identity_id"], sortBy: ["group_id", "identity_id"], volatile: ["created_at"] },
  { name: "team_projects", key: ["team_id", "project_id"], sortBy: ["team_id", "project_id"], volatile: ["created_at"] },
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
  grantCreate: aprId("grantcreate"),
  grantReplace: aprId("grantreplace"),
  grantRevoke: aprId("grantrevoke"),
  roleCreate: aprId("rolecreate"),
  roleUpdate: aprId("roleupdate"),
  roleDelete: aprId("roledelete"),
  groupCreate: aprId("groupcreate"),
  groupUpdate: aprId("groupupdate"),
  teamDelete: aprId("teamdelete"),
  memberAdd: aprId("memberadd"),
  memberRemove: aprId("memberremove"),
  projectAdd: aprId("projectadd"),
  projectRemove: aprId("projectremove"),
  otherBody: aprId("otherbody"),
  pending: aprId("pending"),
} as const;

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
  const grant = (name: string, org: string, body: unknown, credential = "alice", approval?: string) => send(name, "POST", `${org}/grants`, body, credential, approval);
  const svc = (org: string) => `{idn:${org}-svc}`;
  const orgScope = { kind: "organization" };
  return withIds([
    // Lists.
    get("grants", "acc/grants"),
    get("grants by id", "{org:acc}/grants"),
    get("grants as a member", "acc/grants", "bob"),
    get("grants as an outsider", "acc/grants", "carol"),
    get("grants of a frozen Organization", "frozen/grants"),
    get("grants of an unknown Organization", "nope/grants"),
    get("roles", "acc/roles"),
    get("roles as a member", "acc/roles", "bob"),
    get("groups", "acc/groups"),
    get("teams", "acc/teams"),
    get("group members", "acc/groups/{group:acc:devs}/members"),
    get("team members", "acc/teams/{group:acc:backend}/members"),
    get("a team's members through the groups route", "acc/groups/{group:acc:backend}/members"),
    get("members of an unknown group", "acc/groups/grp_unknownaaaaaaaaaaaaaaaaaaaa/members"),
    get("members of a deleted group", "acc/groups/{group:acc:gone}/members"),
    get("team projects", "acc/teams/{group:acc:backend}/projects"),
    get("projects of a group through the teams route", "acc/teams/{group:acc:devs}/projects"),
    get("projects of an unknown team", "acc/teams/tem_unknownaaaaaaaaaaaaaaaaaaaa/projects"),
    get("roles of a frozen Organization", "frozen/roles"),

    // createGrant: every shape.
    grant("a preset to an identity, organization-wide", "acc", { subjectIdentityId: "{idn:bob}", scope: orgScope, actions: ["organization.read", "project.read"] }),
    grant("a Project scope", "acc", { subjectIdentityId: svc("acc"), scope: { kind: "project", projectId: "{prj:acc:api}" }, actions: ["config.metadata.read"] }),
    grant("environments by id", "acc", {
      subjectIdentityId: svc("acc"),
      scope: { kind: "environments", projectId: "{prj:acc:api}", selector: { kind: "environments", environmentIds: ["{env:acc:api/production}", "{env:acc:api/development}", "{env:acc:api/production}"] } },
      actions: ["config.value.read", "config.metadata.read", "config.value.read"],
    }),
    grant("environments by tier", "acc", { subjectGroupId: "{group:acc:devs}", scope: { kind: "environments", projectId: "{prj:acc:web}", selector: { kind: "tier", tier: "staging" } }, roleId: "{role:acc:reader}" }),
    grant("a team scope", "acc", { subjectGroupId: "{group:acc:devs}", scope: { kind: "team", teamId: "{group:acc:backend}" }, actions: ["project.read"] }),
    grant("a role to a group", "acc", { subjectGroupId: "{group:acc:backend}", scope: orgScope, roleId: "{role:acc:writer}" }),
    grant("extra members, kept out", "acc", { subjectIdentityId: "{idn:dave}", scope: { kind: "project", projectId: "{prj:acc:web}", extra: 1 }, actions: ["project.read"], note: "x" }),
    grant("scope members in another order", "acc", { subjectIdentityId: "{idn:dave}", scope: { projectId: "{prj:acc:api}", kind: "project" }, actions: ["fx.order"] }),
    grant("an unknown action", "acc", { subjectIdentityId: "{idn:dave}", scope: orgScope, actions: ["no.such-action"] }),
    grant("a Project of another Organization", "acc", { subjectIdentityId: "{idn:dave}", scope: { kind: "project", projectId: "{prj:other:api}" }, actions: ["fx.otherproject"] }),
    grant("an unknown role", "acc", { subjectIdentityId: "{idn:dave}", scope: orgScope, roleId: "rol_unknownaaaaaaaaaaaaaaaaaaa" }),
    grant("an unknown group", "acc", { subjectGroupId: "grp_unknownaaaaaaaaaaaaaaaaaaa", scope: orgScope, actions: ["project.read"] }),
    grant("a person not a member", "acc", { subjectIdentityId: "{idn:carol}", scope: orgScope, actions: ["project.read"] }),
    grant("a former member", "acc", { subjectIdentityId: "{idn:erin}", scope: orgScope, actions: ["project.read"] }),
    grant("another Organization's machine", "acc", { subjectIdentityId: svc("other"), scope: orgScope, actions: ["project.read"] }),
    grant("an unknown identity", "acc", { subjectIdentityId: "idn_unknownaaaaaaaaaaaaaaaaaaa", scope: orgScope, actions: ["project.read"] }),
    // createGrant: zod and requireOneOfEach.
    grant("no scope", "acc", { subjectIdentityId: "{idn:bob}", actions: ["project.read"] }),
    grant("an unknown scope kind", "acc", { subjectIdentityId: "{idn:bob}", scope: { kind: "everything" }, actions: ["project.read"] }),
    grant("a Project scope without its Project", "acc", { subjectIdentityId: "{idn:bob}", scope: { kind: "project" }, actions: ["project.read"] }),
    grant("a scope that is not an object", "acc", { subjectIdentityId: "{idn:bob}", scope: "organization", actions: ["project.read"] }),
    grant("a null scope", "acc", { subjectIdentityId: "{idn:bob}", scope: null, actions: ["project.read"] }),
    grant("no environment", "acc", { subjectIdentityId: "{idn:bob}", scope: { kind: "environments", projectId: "{prj:acc:api}", selector: { kind: "environments", environmentIds: [] } }, actions: ["project.read"] }),
    grant("no environment, and no actions", "acc", { subjectIdentityId: "{idn:bob}", scope: { kind: "environments", projectId: "{prj:acc:api}", selector: { kind: "environments", environmentIds: [] } }, actions: [] }),
    grant("an environment id that is not a string", "acc", { subjectIdentityId: "{idn:bob}", scope: { kind: "environments", projectId: "{prj:acc:api}", selector: { kind: "environments", environmentIds: [1] } }, actions: ["project.read"] }),
    grant("an unknown tier", "acc", { subjectIdentityId: "{idn:bob}", scope: { kind: "environments", projectId: "{prj:acc:api}", selector: { kind: "tier", tier: "qa" } }, actions: ["project.read"] }),
    grant("no selector", "acc", { subjectIdentityId: "{idn:bob}", scope: { kind: "environments", projectId: "{prj:acc:api}" }, actions: ["project.read"] }),
    grant("an unknown scope, and no actions", "acc", { subjectIdentityId: "{idn:bob}", scope: { kind: "x" }, actions: [] }),
    grant("an action that is not a string", "acc", { subjectIdentityId: "{idn:bob}", scope: orgScope, actions: ["project.read", 1] }),
    grant("actions that are not an array", "acc", { subjectIdentityId: "{idn:bob}", scope: orgScope, actions: "project.read" }),
    grant("no actions", "acc", { subjectIdentityId: "{idn:bob}", scope: orgScope, actions: [] }),
    grant("a subject of the wrong type", "acc", { subjectIdentityId: 5, subjectGroupId: [], scope: orgScope, actions: ["project.read"] }),
    grant("a null subject", "acc", { subjectIdentityId: null, scope: orgScope, actions: ["project.read"] }),
    grant("no subject", "acc", { scope: orgScope, actions: ["project.read"] }),
    grant("both subjects", "acc", { subjectIdentityId: "{idn:bob}", subjectGroupId: "{group:acc:devs}", scope: orgScope, actions: ["project.read"] }),
    grant("an empty subject", "acc", { subjectIdentityId: "", scope: orgScope, actions: ["project.read"] }),
    grant("an empty subject beside a group", "acc", { subjectIdentityId: "", subjectGroupId: "{group:acc:devs}", scope: orgScope, actions: ["fx.emptysubject"] }),
    grant("no permission", "acc", { subjectIdentityId: "{idn:bob}", scope: orgScope }),
    grant("both permissions", "acc", { subjectIdentityId: "{idn:bob}", scope: orgScope, actions: ["project.read"], roleId: "{role:acc:reader}" }),
    grant("an empty role beside actions", "acc", { subjectIdentityId: "{idn:bob}", scope: orgScope, actions: ["fx.emptyrole"], roleId: "" }),
    grant("an array", "acc", []),
    raw("a body that is not JSON", "POST", "acc/grants", "{"),
    // PostgreSQL refuses U+0000 in text and jsonb, and a lone surrogate in jsonb.
    grant("U+0000 in a Project scope", "acc", { subjectIdentityId: svc("acc"), scope: { kind: "project", projectId: "a\u0000b" }, actions: ["project.read"] }),
    grant("U+0000 in an environment id", "acc", { subjectIdentityId: svc("acc"), scope: { kind: "environments", projectId: "{prj:acc:api}", selector: { kind: "environments", environmentIds: ["a\u0000b"] } }, actions: ["project.read"] }),
    grant("U+0000 in a team scope", "acc", { subjectIdentityId: svc("acc"), scope: { kind: "team", teamId: "a\u0000b" }, actions: ["project.read"] }),
    grant("a lone surrogate in a Project scope", "acc", { subjectIdentityId: svc("acc"), scope: { kind: "project", projectId: "a\ud800b" }, actions: ["project.read"] }),
    grant("U+0000 in an action", "acc", { subjectIdentityId: svc("acc"), scope: orgScope, actions: ["a\u0000b"] }),
    grant("a lone surrogate in an action", "acc", { subjectIdentityId: svc("acc"), scope: orgScope, actions: ["a\ud800b"] }),
    grant("U+0000 in the subject", "acc", { subjectIdentityId: "a\u0000b", scope: orgScope, actions: ["project.read"] }),
    grant("U+0000 in the group", "acc", { subjectGroupId: "a\u0000b", scope: orgScope, actions: ["project.read"] }),
    grant("U+0000 in the role", "acc", { subjectIdentityId: svc("acc"), scope: orgScope, roleId: "a\u0000b" }),
    send("revoke, U+0000 in the id", "DELETE", "acc/grants/a%00b"),
    grant("as a member", "acc", { subjectIdentityId: "{idn:bob}", scope: orgScope, actions: ["project.read"] }, "bob"),
    grant("in a frozen Organization", "frozen", { subjectIdentityId: svc("frozen"), scope: orgScope, actions: ["project.read"] }),
    grant("in an Organization being deleted", "deleting", { subjectIdentityId: svc("deleting"), scope: orgScope, actions: ["project.read"] }),

    // deleteGrant.
    send("revoke a Grant", "DELETE", "acc/grants/{grant:acc:fx.revokeme}"),
    send("revoke it again", "DELETE", "acc/grants/{grant:acc:fx.revokeme}"),
    send("revoke an unknown Grant", "DELETE", "acc/grants/grt_unknownaaaaaaaaaaaaaaaaaaa"),
    send("revoke another Organization's Grant", "DELETE", "acc/grants/{grant:other:fx.othergrant}"),
    send("revoke as a member", "DELETE", "acc/grants/{grant:acc:fx.keep}", undefined, "bob"),
    send("revoke in a frozen Organization", "DELETE", "frozen/grants/{grant:frozen:fx.frozengrant}"),

    // replaceGrant.
    send("replace a Grant", "POST", "acc/grants/{grant:acc:fx.replaceme}/replace", { subjectIdentityId: svc("acc"), scope: orgScope, roleId: "{role:acc:reader}" }, "alice", undefined, "replace-1"),
    send("replace it again, the same key", "POST", "acc/grants/{grant:acc:fx.replaceme}/replace", { subjectIdentityId: svc("acc"), scope: orgScope, roleId: "{role:acc:reader}" }, "alice", undefined, "replace-1"),
    send("the same key, another body", "POST", "acc/grants/{grant:acc:fx.replaceme}/replace", { subjectIdentityId: svc("acc"), scope: orgScope, actions: ["project.read"] }, "alice", undefined, "replace-1"),
    send("replace a replaced Grant", "POST", "acc/grants/{grant:acc:fx.replaceme}/replace", { subjectIdentityId: svc("acc"), scope: orgScope, actions: ["project.read"] }),
    send("replace with the same declaration", "POST", "acc/grants/{grant:acc:fx.same}/replace", {
      subjectIdentityId: svc("acc"), scope: { kind: "project", projectId: "{prj:acc:api}" }, actions: ["fx.same", "config.metadata.read", "fx.same"],
    }),
    send("replace an unknown Grant", "POST", "acc/grants/grt_unknownaaaaaaaaaaaaaaaaaaa/replace", { subjectIdentityId: svc("acc"), scope: orgScope, actions: ["project.read"] }),
    send("replace for a subject not a member", "POST", "acc/grants/{grant:acc:fx.keep}/replace", { subjectIdentityId: "{idn:carol}", scope: orgScope, actions: ["project.read"] }),
    send("replace, a key of 201 characters", "POST", "acc/grants/{grant:acc:fx.keep}/replace", { subjectIdentityId: svc("acc"), scope: orgScope, actions: ["project.read"] }, "alice", undefined, "k".repeat(201)),
    send("replace, an invalid declaration", "POST", "acc/grants/{grant:acc:fx.keep}/replace", { subjectIdentityId: svc("acc"), scope: { kind: "team" }, actions: ["project.read"] }),
    send("replace, U+0000 in the scope", "POST", "acc/grants/{grant:acc:fx.keep}/replace", { subjectIdentityId: svc("acc"), scope: { kind: "project", projectId: "a\u0000b" }, actions: ["project.read"] }, "alice", undefined, "replace-nul"),
    send("replace as a member", "POST", "acc/grants/{grant:acc:fx.keep}/replace", { subjectIdentityId: svc("acc"), scope: orgScope, actions: ["project.read"] }, "bob"),

    // Roles.
    send("create a role", "POST", "acc/roles", { name: "auditor", actions: ["organization.read", "audit.read", "organization.read"] }),
    send("create a role, a name taken", "POST", "acc/roles", { name: "reader", actions: ["project.read"] }),
    send("create a role, no actions", "POST", "acc/roles", { name: "empty", actions: [] }),
    send("create a role, an empty name", "POST", "acc/roles", { name: "", actions: ["project.read"] }),
    send("create a role, a name of 101 emoji", "POST", "acc/roles", { name: "\u{1F511}".repeat(101), actions: ["project.read"] }),
    send("create a role, extra members", "POST", "acc/roles", { name: "extra", actions: ["project.read"], kind: "x" }),
    send("create a role, nothing", "POST", "acc/roles", {}),
    raw("create a role, a body that is not JSON", "POST", "acc/roles", "x"),
    send("create a role, U+0000 in the name", "POST", "acc/roles", { name: "a\u0000b", actions: ["project.read"] }),
    send("create a role, U+0000 in an action", "POST", "acc/roles", { name: "nulaction", actions: ["a\u0000b"] }),
    send("create a role, a lone surrogate in an action", "POST", "acc/roles", { name: "surrogate", actions: ["a\ud800b"] }),
    send("create a role as a member", "POST", "acc/roles", { name: "bobs", actions: ["project.read"] }, "bob"),
    send("rename a role", "PATCH", "acc/roles/{role:acc:renameme}", { expectedVersion: 1, name: "renamed" }, "alice", undefined, "role-1"),
    send("rename it again, the same key", "PATCH", "acc/roles/{role:acc:renameme}", { expectedVersion: 1, name: "renamed" }, "alice", undefined, "role-1"),
    send("change a role's actions", "PATCH", "acc/roles/{role:acc:renameme}", { expectedVersion: 2, actions: ["project.read", "config.metadata.read"] }),
    send("reorder a role's actions", "PATCH", "acc/roles/{role:acc:renameme}", { actions: ["config.metadata.read", "project.read"], expectedVersion: 3 }),
    send("a role patch that changes nothing", "PATCH", "acc/roles/{role:acc:renameme}", { expectedVersion: 4, actions: ["config.metadata.read", "project.read"] }),
    send("a role patch at an old version", "PATCH", "acc/roles/{role:acc:renameme}", { expectedVersion: 1, name: "late" }),
    send("rename a role to a name taken", "PATCH", "acc/roles/{role:acc:renameme}", { expectedVersion: 4, name: "reader" }),
    send("rename a role, U+0000 in the name", "PATCH", "acc/roles/{role:acc:renameme}", { expectedVersion: 4, name: "a\u0000b" }),
    send("change a role, U+0000 in an action", "PATCH", "acc/roles/{role:acc:renameme}", { expectedVersion: 4, actions: ["a\u0000b"] }),
    send("a role patch without a version", "PATCH", "acc/roles/{role:acc:renameme}", { name: "x" }),
    send("a role patch, version 0", "PATCH", "acc/roles/{role:acc:renameme}", { expectedVersion: 0, actions: [] }),
    send("a role patch, a fractional version", "PATCH", "acc/roles/{role:acc:renameme}", { expectedVersion: 1.5 }),
    send("patch an unknown role", "PATCH", "acc/roles/rol_unknownaaaaaaaaaaaaaaaaaaa", { expectedVersion: 1, name: "x" }),
    send("delete a role", "DELETE", "acc/roles/{role:acc:deleteme}"),
    send("delete it again", "DELETE", "acc/roles/{role:acc:deleteme}"),
    send("delete an unknown role", "DELETE", "acc/roles/rol_unknownaaaaaaaaaaaaaaaaaaa"),
    get("roles after the changes", "acc/roles"),

    // Groups and teams.
    send("create a group", "POST", "acc/groups", { name: "ops" }),
    send("create a team", "POST", "acc/teams", { name: "platform" }),
    send("create a group, a name taken by a team", "POST", "acc/groups", { name: "backend" }),
    send("create a team, a name taken by a group", "POST", "acc/teams", { name: "devs" }),
    send("create a group, an empty name", "POST", "acc/groups", { name: "" }),
    send("create a group, a name of 201 characters", "POST", "acc/groups", { name: "n".repeat(201) }),
    send("create a group, a name of 101 emoji", "POST", "acc/groups", { name: "\u{1F511}".repeat(101) }),
    send("create a group as a member", "POST", "acc/groups", { name: "bobs" }, "bob"),
    send("create a group, U+0000 in the name", "POST", "acc/groups", { name: "a\u0000b" }),
    send("rename a group", "PATCH", "acc/groups/{group:acc:renamegroup}", { expectedVersion: 1, name: "renamed-group" }),
    send("rename a group, keeping its name", "PATCH", "acc/groups/{group:acc:renamegroup}", { expectedVersion: 2, name: "renamed-group" }),
    send("rename a group, U+0000 in the name", "PATCH", "acc/groups/{group:acc:renamegroup}", { expectedVersion: 2, name: "a\u0000b" }),
    send("rename a group at an old version", "PATCH", "acc/groups/{group:acc:renamegroup}", { expectedVersion: 1, name: "late" }),
    send("rename a team through the groups route", "PATCH", "acc/groups/{group:acc:backend}", { expectedVersion: 1, name: "x" }),
    send("rename a team", "PATCH", "acc/teams/{group:acc:renameteam}", { expectedVersion: 1, name: "renamed-team" }, "alice", undefined, "team-1"),
    send("rename a team to a group's name", "PATCH", "acc/teams/{group:acc:renameteam}", { expectedVersion: 2, name: "devs" }),
    send("delete a team through the groups route", "DELETE", "acc/groups/{group:acc:deleteteam}"),
    send("delete a group through the teams route", "DELETE", "acc/teams/{group:acc:deletegroup}"),
    send("delete an unknown team", "DELETE", "acc/teams/tem_unknownaaaaaaaaaaaaaaaaaaaa"),
    get("groups after the changes", "acc/groups"),
    get("teams after the changes", "acc/teams"),

    // Memberships.
    send("add a machine to a group", "POST", "acc/groups/{group:acc:devs}/members", { identityId: "{idn:acc-ci}" }),
    send("add a member to a team", "POST", "acc/teams/{group:acc:backend}/members", { identityId: "{idn:dave}" }),
    send("add a current member", "POST", "acc/groups/{group:acc:devs}/members", { identityId: "{idn:bob}" }),
    send("add a disabled machine", "POST", "acc/groups/{group:acc:devs}/members", { identityId: "{idn:acc-retired}" }),
    send("add a former member", "POST", "acc/groups/{group:acc:devs}/members", { identityId: "{idn:erin}" }),
    send("add an outsider", "POST", "acc/groups/{group:acc:devs}/members", { identityId: "{idn:carol}" }),
    send("add another Organization's machine", "POST", "acc/groups/{group:acc:devs}/members", { identityId: svc("other") }),
    send("add to an unknown group", "POST", "acc/groups/grp_unknownaaaaaaaaaaaaaaaaaaaa/members", { identityId: "{idn:bob}" }),
    send("add to a deleted group", "POST", "acc/groups/{group:acc:gone}/members", { identityId: "{idn:bob}" }),
    send("add, no identity", "POST", "acc/groups/{group:acc:devs}/members", {}),
    send("add, an identity that is not a string", "POST", "acc/groups/{group:acc:devs}/members", { identityId: 7 }),
    send("add as a member", "POST", "acc/groups/{group:acc:devs}/members", { identityId: "{idn:dave}" }, "bob"),
    send("add, U+0000 in the identity", "POST", "acc/groups/{group:acc:devs}/members", { identityId: "a\u0000b" }),
    send("remove a member", "DELETE", "acc/groups/{group:acc:devs}/members/{idn:acc-svc}"),
    send("remove it again", "DELETE", "acc/groups/{group:acc:devs}/members/{idn:acc-svc}"),
    send("remove a team member through the groups route", "DELETE", "acc/groups/{group:acc:backend}/members/{idn:bob}"),
    send("remove from an unknown group", "DELETE", "acc/groups/grp_unknownaaaaaaaaaaaaaaaaaaaa/members/{idn:bob}"),
    get("group members after the changes", "acc/groups/{group:acc:devs}/members"),

    // Team-Project links.
    send("give a team a Project", "POST", "acc/teams/{group:acc:backend}/projects", { projectId: "{prj:acc:web}" }),
    send("give it again", "POST", "acc/teams/{group:acc:backend}/projects", { projectId: "{prj:acc:web}" }),
    send("give a deleted Project", "POST", "acc/teams/{group:acc:backend}/projects", { projectId: "{prj:acc:old}" }),
    send("give another Organization's Project", "POST", "acc/teams/{group:acc:backend}/projects", { projectId: "{prj:other:api}" }),
    send("give a group a Project", "POST", "acc/teams/{group:acc:devs}/projects", { projectId: "{prj:acc:web}" }),
    send("give, no Project", "POST", "acc/teams/{group:acc:backend}/projects", { project: "x" }),
    send("give, U+0000 in the Project", "POST", "acc/teams/{group:acc:backend}/projects", { projectId: "a\u0000b" }),
    send("take a Project from a team", "DELETE", "acc/teams/{group:acc:backend}/projects/{prj:acc:api}"),
    send("take it again", "DELETE", "acc/teams/{group:acc:backend}/projects/{prj:acc:api}"),
    send("take from an unknown team", "DELETE", "acc/teams/tem_unknownaaaaaaaaaaaaaaaaaaaa/projects/{prj:acc:api}"),
    get("team projects after the changes", "acc/teams/{group:acc:backend}/projects"),
    get("grants after the changes", "acc/grants"),

    // At report: counted, done anyway.
    grant("report: a Grant", "rep", { subjectIdentityId: svc("rep"), scope: orgScope, actions: ["project.read"] }),
    send("report: revoke a Grant", "DELETE", "rep/grants/{grant:rep:fx.revokeme}"),
    send("report: replace a Grant", "POST", "rep/grants/{grant:rep:fx.replaceme}/replace", { subjectIdentityId: svc("rep"), scope: orgScope, actions: ["fx.replaced"] }),
    send("report: replace with the same declaration", "POST", "rep/grants/{grant:rep:fx.same}/replace", { subjectIdentityId: svc("rep"), scope: { kind: "project", projectId: "{prj:rep:api}" }, actions: ["fx.same", "config.metadata.read"] }),
    send("report: a role", "POST", "rep/roles", { name: "auditor", actions: ["audit.read"] }),
    send("report: rename a role", "PATCH", "rep/roles/{role:rep:renameme}", { expectedVersion: 1, name: "renamed" }),
    send("report: reorder a role's actions", "PATCH", "rep/roles/{role:rep:reader}", { expectedVersion: 1, actions: ["project.read", "organization.read"] }),
    send("report: delete a role", "DELETE", "rep/roles/{role:rep:deleteme}"),
    send("report: a team", "POST", "rep/teams", { name: "platform" }),
    send("report: rename a group", "PATCH", "rep/groups/{group:rep:devs}", { expectedVersion: 1, name: "developers" }),
    send("report: delete a team", "DELETE", "rep/teams/{group:rep:deleteteam}"),
    send("report: add a member", "POST", "rep/groups/{group:rep:devs}/members", { identityId: "{idn:dave}" }),
    send("report: add a current member", "POST", "rep/groups/{group:rep:devs}/members", { identityId: "{idn:bob}" }),
    send("report: remove a member", "DELETE", "rep/groups/{group:rep:devs}/members/{idn:bob}"),
    send("report: give a team a Project", "POST", "rep/teams/{group:rep:backend}/projects", { projectId: "{prj:rep:web}" }),
    send("report: take a Project", "DELETE", "rep/teams/{group:rep:backend}/projects/{prj:rep:api}"),

    // At enforce: asked for, then consumed.
    grant("enforce: a Grant, no approval", "enf", { subjectIdentityId: svc("enf"), scope: orgScope, actions: ["project.read"] }, "dave"),
    grant("enforce: U+0000 in a Project scope", "enf", { subjectIdentityId: svc("enf"), scope: { kind: "project", projectId: "a\u0000b" }, actions: ["project.read"] }, "dave"),
    grant("enforce: U+0000 in the subject", "enf", { subjectIdentityId: "a\u0000b", scope: orgScope, actions: ["project.read"] }, "dave"),
    send("enforce: revoke, no approval", "DELETE", "enf/grants/{grant:enf:fx.revokeme}", undefined, "dave"),
    send("enforce: replace, no approval", "POST", "enf/grants/{grant:enf:fx.replaceme}/replace", { subjectIdentityId: svc("enf"), scope: orgScope, actions: ["fx.replaced"] }, "dave"),
    send("enforce: replace with the same declaration", "POST", "enf/grants/{grant:enf:fx.same}/replace", { subjectIdentityId: svc("enf"), scope: { kind: "project", projectId: "{prj:enf:api}" }, actions: ["config.metadata.read", "fx.same"] }, "dave"),
    send("enforce: a role, no approval", "POST", "enf/roles", { name: "asked", actions: ["audit.read"] }, "dave"),
    send("enforce: a role, U+0000 in the name", "POST", "enf/roles", { name: "a\u0000b", actions: ["audit.read"] }, "dave"),
    send("enforce: a role, U+0000 in an action", "POST", "enf/roles", { name: "nulasked", actions: ["a\u0000b"] }, "dave"),
    send("enforce: a role, a name taken", "POST", "enf/roles", { name: "reader", actions: ["audit.read"] }, "ask1"),
    send("enforce: rename a role, no approval", "PATCH", "enf/roles/{role:enf:renameme}", { expectedVersion: 1, name: "asked" }, "ask1"),
    send("enforce: reorder a role's actions", "PATCH", "enf/roles/{role:enf:reader}", { expectedVersion: 1, actions: ["project.read", "organization.read"] }, "ask1"),
    send("enforce: delete a role, no approval", "DELETE", "enf/roles/{role:enf:deleteme}", undefined, "ask1"),
    send("enforce: a group, no approval", "POST", "enf/groups", { name: "asked" }, "ask1"),
    send("enforce: rename a group, keeping its name", "PATCH", "enf/groups/{group:enf:devs}", { expectedVersion: 1, name: "devs" }, "ask2"),
    send("enforce: add a member, no approval", "POST", "enf/groups/{group:enf:devs}/members", { identityId: "{idn:dave}" }, "ask2"),
    send("enforce: add a member, U+0000 in the identity", "POST", "enf/groups/{group:enf:devs}/members", { identityId: "a\u0000b" }, "ask2"),
    send("enforce: U+0000 in the group's id", "PATCH", "enf/groups/a%00b", { expectedVersion: 1, name: "x" }, "ask2"),
    send("enforce: add a current member", "POST", "enf/groups/{group:enf:devs}/members", { identityId: "{idn:bob}" }, "ask2"),
    send("enforce: remove a member that is not one", "DELETE", "enf/groups/{group:enf:devs}/members/{idn:carol}", undefined, "ask2"),
    send("enforce: give a team its Project again", "POST", "enf/teams/{group:enf:backend}/projects", { projectId: "{prj:enf:api}" }, "ask2"),
    send("enforce: take a Project, no approval", "DELETE", "enf/teams/{group:enf:backend}/projects/{prj:enf:api}", undefined, "ask2"),
    grant("enforce: a machine asks", "enf", { subjectIdentityId: svc("enf"), scope: orgScope, actions: ["project.read"] }, "enf-admin-svc"),
    grant("enforce: a Grant, its approval", "enf", { subjectIdentityId: svc("enf"), scope: orgScope, actions: ["fx.approved"] }, "alice2", APPROVALS.grantCreate),
    grant("enforce: a Grant, its approval again", "enf", { subjectIdentityId: svc("enf"), scope: orgScope, actions: ["fx.approved"] }, "alice2", APPROVALS.grantCreate),
    grant("enforce: a Grant, another request's approval", "enf", { subjectIdentityId: svc("enf"), scope: orgScope, actions: ["fx.other"] }, "alice2", APPROVALS.otherBody),
    grant("enforce: a Grant, an approval not given yet", "enf", { subjectIdentityId: svc("enf"), scope: orgScope, actions: ["fx.pending"] }, "alice2", APPROVALS.pending),
    send("enforce: replace, its approval", "POST", "enf/grants/{grant:enf:fx.approvedreplace}/replace", { subjectIdentityId: svc("enf"), scope: orgScope, roleId: "{role:enf:reader}" }, "alice2", APPROVALS.grantReplace, "enf-replace"),
    send("enforce: revoke, its approval", "DELETE", "enf/grants/{grant:enf:fx.approvedrevoke}", undefined, "alice2", APPROVALS.grantRevoke),
    send("enforce: a role, its approval", "POST", "enf/roles", { name: "approved", actions: ["audit.read", "organization.read"] }, "alice2", APPROVALS.roleCreate),
    send("enforce: change a role, its approval", "PATCH", "enf/roles/{role:enf:approvedupdate}", { expectedVersion: 1, actions: ["project.read", "config.value.read"] }, "alice2", APPROVALS.roleUpdate),
    send("enforce: delete a role, its approval", "DELETE", "enf/roles/{role:enf:approveddelete}", undefined, "alice2", APPROVALS.roleDelete),
    send("enforce: a group, its approval", "POST", "enf/groups", { name: "approved" }, "alice2", APPROVALS.groupCreate),
    send("enforce: rename a group, its approval", "PATCH", "enf/groups/{group:enf:approvedrename}", { expectedVersion: 1, name: "approved-renamed" }, "alice2", APPROVALS.groupUpdate),
    send("enforce: delete a team, its approval", "DELETE", "enf/teams/{group:enf:approveddelete}", undefined, "alice2", APPROVALS.teamDelete),
    send("enforce: add a member, its approval", "POST", "enf/groups/{group:enf:devs}/members", { identityId: "{idn:enf-svc}" }, "alice2", APPROVALS.memberAdd),
    send("enforce: remove a member, its approval", "DELETE", "enf/groups/{group:enf:devs}/members/{idn:bob}", undefined, "alice2", APPROVALS.memberRemove),
    send("enforce: give a team a Project, its approval", "POST", "enf/teams/{group:enf:backend}/projects", { projectId: "{prj:enf:web}" }, "alice2", APPROVALS.projectAdd),
    send("enforce: take a Project, its approval", "DELETE", "enf/teams/{group:enf:backend}/projects/{prj:enf:api}", undefined, "alice2", APPROVALS.projectRemove),
    send("enforce: a malformed approval", "POST", "enf/groups", { name: "malformed" }, "alice2", "not-an-approval"),
    get("enf grants after the changes", "enf/grants"),
  ]);
}

/** The table's placeholders, from the file's rows. */
function fillPath(rows: Record<string, Row[]>): (p: string) => string {
  const org = (slug: string) => rows.organizations!.find((o) => o.slug === slug)!.id as string;
  const actionsOf = (v: unknown): string[] => (Array.isArray(v) ? (v as string[]) : typeof v === "string" ? (JSON.parse(v) as string[]) : []);
  const resolve = (kind: string, arg: string): string => {
    const [a, b] = arg.split(":") as [string, string | undefined];
    switch (kind) {
      case "org":
        return org(a);
      case "idn":
        return rows.identities!.find((i) => i.name === a)!.id as string;
      case "role":
        return rows.roles!.find((r) => r.organization_id === org(a) && r.name === b)!.id as string;
      case "group":
        return rows.groups!.find((g) => g.organization_id === org(a) && g.name === b)!.id as string;
      case "prj":
        return rows.projects!.find((p) => p.organization_id === org(a) && p.slug === b)!.id as string;
      case "env": {
        const [project, env] = b!.split("/") as [string, string];
        const pid = rows.projects!.find((p) => p.organization_id === org(a) && p.slug === project)!.id;
        return rows.environments!.find((e) => e.project_id === pid && e.name === env)!.id as string;
      }
      case "grant": {
        const roles = new Map(rows.roles!.map((r) => [r.id as string, r.name as string]));
        return rows.grants!.find((g) => g.organization_id === org(a) && (actionsOf(g.actions).includes(b!) || roles.get(g.role_id as string) === b))!.id as string;
      }
    }
    throw new Error(`unknown placeholder ${kind}`);
  };
  return (p) => p.replace(/\{(org|idn|role|group|prj|env|grant):([^}]+)\}/g, (_, kind: string, arg: string) => resolve(kind, arg));
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
  for (const slug of ["acc", "rep", "enf", "frozen", "deleting", "other"]) {
    orgs[slug] = (await call("POST", ORG, { name: slug[0]!.toUpperCase() + slug.slice(1), slug })).id;
  }
  // People: bob a member, dave and the askers admins, erin a former member, carol in none.
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
  const bob = await person("bob", [["acc", "member"], ["rep", "member"], ["enf", "member"]]);
  await person("carol", []);
  const dave = await person("dave", [["acc", "member"], ["rep", "member"], ["enf", "admin"]]);
  await person("erin", [["acc", "member", true]]);
  await person("ask1", [["enf", "admin"]]);
  await person("ask2", [["enf", "admin"]]);

  const structure = async (slug: string) => {
    const org = slug;
    const svc = await call("POST", `${ORG}/${org}/identities`, { name: `${slug}-svc`, kind: "service" });
    tokens[`${slug}-svc`] = svc.credential;
    const projects: Record<string, string> = {};
    for (const p of ["api", "web"]) {
      projects[p] = (await call("POST", `${ORG}/${org}/projects`, { name: p.toUpperCase(), slug: p, contractAuthority: "managed" })).id;
    }
    for (const e of [["development", "development"], ["production", "production"]]) {
      await call("POST", `${ORG}/${org}/projects/api/environments`, { name: e[0], tier: e[1] });
    }
    const role = async (name: string, actions: string[]) => (await call("POST", `${ORG}/${org}/roles`, { name, actions })).id as string;
    const reader = await role("reader", ["organization.read", "project.read"]);
    await role("writer", ["config.value.write", "config.value.read"]);
    for (const r of ["renameme", "deleteme", "approvedupdate", "approveddelete"]) await role(r, ["project.read"]);
    const group = async (name: string, kind: "group" | "team") => (await call("POST", `${ORG}/${org}/${kind}s`, { name })).id as string;
    const devs = await group("devs", "group");
    const backend = await group("backend", "team");
    for (const g of ["renamegroup", "deletegroup", "gone", "approvedrename"]) await group(g, "group");
    for (const t of ["renameteam", "deleteteam", "approveddelete"]) await group(t, "team");
    await call("DELETE", `${ORG}/${org}/groups/${(await db.query("SELECT id FROM groups WHERE organization_id = $1 AND name = 'gone'", [orgs[slug]])).rows[0]!.id}`);
    for (const m of [svc.id, bob]) await call("POST", `${ORG}/${org}/groups/${devs}/members`, { identityId: m });
    await call("POST", `${ORG}/${org}/teams/${backend}/members`, { identityId: bob });
    await call("POST", `${ORG}/${org}/teams/${backend}/projects`, { projectId: projects.api });
    const g = (body: unknown) => call("POST", `${ORG}/${org}/grants`, body);
    const orgScope = { kind: "organization" };
    await g({ subjectIdentityId: svc.id, scope: orgScope, actions: ["fx.keep"] });
    const revokeme = await g({ subjectIdentityId: svc.id, scope: orgScope, actions: ["fx.revokeme"] });
    await g({ subjectIdentityId: svc.id, scope: orgScope, actions: ["fx.replaceme"] });
    await g({ subjectIdentityId: svc.id, scope: { kind: "project", projectId: projects.api }, actions: ["config.metadata.read", "fx.same"] });
    await g({ subjectGroupId: devs, scope: { kind: "team", teamId: backend }, roleId: reader });
    await g({ subjectIdentityId: svc.id, scope: orgScope, actions: ["fx.approvedreplace"] });
    await g({ subjectIdentityId: svc.id, scope: orgScope, actions: ["fx.approvedrevoke"] });
    // A Grant already revoked, for the lists.
    const gone = await g({ subjectIdentityId: svc.id, scope: orgScope, actions: ["fx.revoked"] });
    await call("DELETE", `${ORG}/${org}/grants/${gone.id}`);
    void revokeme;
    // A deleted Project.
    const old = (await call("POST", `${ORG}/${org}/projects`, { name: "Old", slug: "old", contractAuthority: "managed" })).id;
    await db.query("UPDATE projects SET deleted_at = '2026-03-01T00:00:00.000Z' WHERE id = $1", [old]);
    // A retired machine and a CI machine.
    const retired = await call("POST", `${ORG}/${org}/identities`, { name: `${slug}-retired`, kind: "service" });
    await call("POST", `${ORG}/${org}/identities/${retired.id}/retire`);
    await call("POST", `${ORG}/${org}/identities`, { name: `${slug}-ci`, kind: "ci" });
  };
  for (const slug of ["acc", "rep", "enf"]) await structure(slug);
  // acc's own: Grants the table revokes and replaces.
  // other: a machine, a group, a Project and a Grant.
  const osvc = await call("POST", `${ORG}/other/identities`, { name: "other-svc", kind: "service" });
  await call("POST", `${ORG}/other/projects`, { name: "API", slug: "api", contractAuthority: "managed" });
  await call("POST", `${ORG}/other/groups`, { name: "odevs" });
  await call("POST", `${ORG}/other/grants`, { subjectIdentityId: osvc.id, scope: { kind: "organization" }, actions: ["fx.othergrant"] });
  // frozen and deleting: a machine and a Grant each, then the freeze and the deletion.
  for (const slug of ["frozen", "deleting"]) {
    const m = await call("POST", `${ORG}/${slug}/identities`, { name: `${slug}-svc`, kind: "service" });
    await call("POST", `${ORG}/${slug}/grants`, { subjectIdentityId: m.id, scope: { kind: "organization" }, actions: [`fx.${slug}grant`] });
  }
  await db.query(
    "INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', 'incident drill')",
    [newId("organizationFreeze"), orgs.frozen, alice],
  );
  await db.query(
    "INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', '2099-03-01T00:00:00.000Z', false)",
    [newId("organizationDeletion"), orgs.deleting, alice],
  );
  // enf: an admin machine (a Grant of policy.manage), to ask as a machine.
  const adminSvc = await call("POST", `${ORG}/enf/identities`, { name: "enf-admin-svc", kind: "service" });
  tokens["enf-admin-svc"] = adminSvc.credential;
  await call("POST", `${ORG}/enf/grants`, { subjectIdentityId: adminSvc.id, scope: { kind: "organization" }, actions: ["policy.manage", "organization.read"] });

  // The controls: rep at report, enf at enforce.
  const set = (org: string, body: unknown) => call("PATCH", `${ORG}/${org}/security/controls/admin-step-up`, body);
  await set("rep", { mode: "report", expectedVersion: 0 });
  await set("enf", { mode: "report", expectedVersion: 0 });
  await set("enf", { mode: "enforce", expectedVersion: 1 });

  // Approval intents of alice's second CLI credential in enf, each binding
  // one request of the table exactly as the operation binds it.
  const enf = { id: orgs.enf! };
  const id = async (table: string, name: string) =>
    (await db.query(`SELECT id FROM ${table} WHERE organization_id = $1 AND name = $2 AND revoked_at IS NULL`, [enf.id, name])).rows[0]!.id as string;
  const grantOf = async (action: string) =>
    (await db.query("SELECT id FROM grants WHERE organization_id = $1 AND $2 = ANY(actions)", [enf.id, action])).rows[0]!.id as string;
  const project = async (slug: string) => (await db.query("SELECT id FROM projects WHERE organization_id = $1 AND slug = $2", [enf.id, slug])).rows[0]!.id as string;
  const enfSvc = (await db.query("SELECT id FROM identities WHERE name = 'enf-svc'")).rows[0]!.id as string;
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
  const orgScope = { kind: "organization" } as const;
  await intent(APPROVALS.grantCreate, await grantCreateBinding(db, enf, { subjectIdentityId: enfSvc, scope: orgScope, actions: ["fx.approved"] }), true);
  await intent(APPROVALS.otherBody, await grantCreateBinding(db, enf, { subjectIdentityId: enfSvc, scope: orgScope, actions: ["fx.something-else"] }), true);
  await intent(APPROVALS.pending, await grantCreateBinding(db, enf, { subjectIdentityId: enfSvc, scope: orgScope, actions: ["fx.pending"] }), false);
  const toReplace = (await readGrant(db, enf.id, await grantOf("fx.approvedreplace")))!;
  await intent(APPROVALS.grantReplace, await grantReplaceBinding(db, enf, toReplace, { subjectIdentityId: enfSvc, scope: orgScope, roleId: await id("roles", "reader") }), true);
  await intent(APPROVALS.grantRevoke, await grantRevokeBinding(db, enf, (await readGrant(db, enf.id, await grantOf("fx.approvedrevoke")))!), true);
  await intent(APPROVALS.roleCreate, roleCreateBinding(enf, { name: "approved", actions: ["audit.read", "organization.read"] }), true);
  const updating = (await readRole(db, enf.id, await id("roles", "approvedupdate")))!;
  await intent(APPROVALS.roleUpdate, await roleUpdateBinding(db, enf, updating, { name: updating.name, actions: ["project.read", "config.value.read"] }, 1), true);
  await intent(APPROVALS.roleDelete, roleDeleteBinding(enf, (await readRole(db, enf.id, await id("roles", "approveddelete")))!), true);
  await intent(APPROVALS.groupCreate, groupCreateBinding(enf, { name: "approved", kind: "group" }), true);
  await intent(APPROVALS.groupUpdate, groupUpdateBinding(enf, (await readGroup(db, enf.id, await id("groups", "approvedrename")))!, "approved-renamed", 1), true);
  await intent(APPROVALS.teamDelete, await groupDeleteBinding(db, enf, (await readGroup(db, enf.id, await id("groups", "approveddelete")))!), true);
  const devs = (await readGroup(db, enf.id, await id("groups", "devs")))!;
  const backend = (await readGroup(db, enf.id, await id("groups", "backend")))!;
  await intent(APPROVALS.memberAdd, memberAddBinding(enf, devs, await readPerson(db, enfSvc)), true);
  await intent(APPROVALS.memberRemove, memberRemoveBinding(enf, devs, await readPerson(db, bob)), true);
  await intent(APPROVALS.projectAdd, teamProjectAddBinding(enf, backend, (await readLiveProject(db, enf.id, await project("web")))!), true);
  await intent(APPROVALS.projectRemove, teamProjectRemoveBinding(enf, backend, (await readLiveProject(db, enf.id, await project("api")))!), true);
  void dave;

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
        comment: "Written by services/varlatchd/test/go-access-fixture.test.ts from the TypeScript server's own answers; do not edit.",
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

describe("the access fixture is this server's answers", () => {
  it("access-v0.22.0.json", async () => {
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
