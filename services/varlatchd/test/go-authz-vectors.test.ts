// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Shared vectors for the Go authorization evaluator (ADR-0059 step 3.3):
 * this server's own code, run on fixed inputs, gives the decisions and
 * reasons go/server/authz must give for the same inputs
 * (go/server/authz/testdata/ts-vectors.json, read by vectors_test.go).
 *
 * - evaluate: the pure evaluator and auditAuthz, on inputs covering the
 *   built-in role bundles, every Grant scope, Requirement matching and the
 *   denial classes.
 * - world: a database fixture (Organizations, people and machines,
 *   memberships live and removed, Roles live, revoked and empty, Groups and
 *   Teams live and revoked, Grants of every shape, Requirements, an open
 *   incident freeze), the Grants loadGrants loads from it per subject, the
 *   Requirements loadTailnetRequirements loads, and for every principal,
 *   action and resource what decide answers (with and without existence
 *   hiding), and the incident freeze's answers at Organization entry and in
 *   refuseIfIncidentFrozen, and the two together in a request's order.
 * - destination: authz/destination.ts, and Node's domainToASCII and isIP
 *   under it.
 *
 * - nodeidna: go/server/whatwg's table of what Node's URL host parser
 *   knows about each code point, and Node's answers for every code point
 *   (go/server/whatwg/testdata/nodeidna.mjs), which destination.ts reaches
 *   through domainToASCII. Regenerate those two files with
 *   `node go/server/whatwg/testdata/nodeidna.mjs` after a Node.js update.
 *
 * The file is checked here: it must equal what this code produces now.
 * After a change to the evaluator, loadGrants, decide, the freeze checks or
 * this fixture, regenerate it and commit the result:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-authz-vectors.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";
import type { Context } from "hono";
import { expect, it } from "vitest";
import {
  auditAuthz,
  evaluate,
  type Action,
  type EvaluateInput,
  type GrantRecord,
  type ResourceContext,
  type TailnetContext,
  type TailnetRequirementRecord,
} from "../src/authz/evaluate.js";
import { canonicalizeHost, destinationMatches, formatSelector, parseDestinationSelector } from "../src/authz/destination.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { DomainError } from "../src/domain/errors.js";
import { refuseIfIncidentFrozen, type FreezeException } from "../src/domain/liveness.js";
import { getOrganization } from "../src/domain/orgs.js";
import { organizationEntryChecks } from "../src/http/organization.js";
import { decide, loadGrants, loadTailnetRequirements, type Principal } from "../src/http/support.js";
import { migratedTestDb } from "./helpers/pglite.js";

const OUT = new URL("../../../go/server/authz/testdata/ts-vectors.json", import.meta.url);

const ACTIONS: string[] = [
  "organization.read", "organization.manage", "project.read", "project.manage", "environment.read",
  "environment.manage", "config.metadata.read", "config.value.read", "config.value.write", "secret.reveal",
  "secret.use", "contract.read", "contract.submit", "contract.activate", "identity.read", "identity.manage",
  "policy.read", "policy.manage", "audit.read", "config.sync.manage", "unknown.action",
];
const CONSTRAINED = ["config.value.read", "secret.reveal", "secret.use"];

// ---------------------------------------------------------------- evaluate

const env = (id: string, tier: string, rootId = id) => ({ id, rootId, tier }) as NonNullable<ResourceContext["environment"]>;
const RESOURCES: Record<string, ResourceContext> = {
  org: { organizationId: "org_1" },
  project: { organizationId: "org_1", projectId: "prj_1" },
  otherProject: { organizationId: "org_1", projectId: "prj_2" },
  dev: { organizationId: "org_1", projectId: "prj_1", environment: env("env_dev", "development") },
  stg: { organizationId: "org_1", projectId: "prj_1", environment: env("env_stg", "staging") },
  prd: { organizationId: "org_1", projectId: "prj_1", environment: env("env_prd", "production") },
  prdChild: { organizationId: "org_1", projectId: "prj_1", environment: env("env_prv", "production", "env_prd") },
  otherPrd: { organizationId: "org_1", projectId: "prj_2", environment: env("env_x", "production") },
  noTier: { organizationId: "org_1", projectId: "prj_1", environment: { id: "env_odd", rootId: "env_odd", tier: "" as never } },
  // A tier the code does not know (the database's CHECK refuses one; the
  // evaluator does not): the member bundle gives nothing there, a tier
  // selector or Requirement naming it matches.
  unknownTier: { organizationId: "org_1", projectId: "prj_1", environment: { id: "env_qa", rootId: "env_qa", tier: "qa" as never } },
};

const g = (id: string, scope: GrantRecord["scope"], actions: (string | null)[], extra: Partial<GrantRecord> = {}): GrantRecord =>
  ({ id, subjectIdentityId: "idn_s", scope, actions: actions as Action[], ...extra });

const GRANTS: GrantRecord[] = [
  g("grt_org", { kind: "organization" }, ["project.manage", "secret.use"]),
  g("grt_prj", { kind: "project", projectId: "prj_1" }, ["config.value.write", "secret.reveal"], { viaGroupId: "grp_1" }),
  g("grt_ids", { kind: "environments", projectId: "prj_1", selector: { kind: "environments", environmentIds: ["env_prd"] } }, ["secret.reveal", "config.value.read"], { roleId: "rol_1", roleVersion: 4 }),
  g("grt_tier", { kind: "environments", projectId: "prj_1", selector: { kind: "tier", tier: "staging" } }, ["secret.use", "environment.manage"], { viaGroupId: "grp_1", roleId: "rol_1", roleVersion: 4 }),
  g("grt_team", { kind: "team", teamId: "tem_1" }, ["project.read", "secret.reveal"]),
  g("grt_null", { kind: "project", projectId: "prj_1" }, [null, "audit.read"], { roleId: "rol_2" }),
  g("grt_other", { kind: "environments", projectId: "prj_2", selector: { kind: "tier", tier: "production" } }, ["secret.reveal"], { viaGroupId: "grp_2" }),
  g("grt_weird", { kind: "weird" } as never, ["project.read"]),
  // A second and third Role contributing to the same actions as grt_ids.
  g("grt_role3", { kind: "project", projectId: "prj_1" }, ["secret.reveal", "config.value.read"], { viaGroupId: "grp_3", roleId: "rol_3", roleVersion: 1 }),
  g("grt_role4", { kind: "environments", projectId: "prj_1", selector: { kind: "tier", tier: "qa" as never } }, ["secret.reveal", "environment.manage"], { roleId: "rol_4", roleVersion: 9 }),
];

const REQUIREMENTS: TailnetRequirementRecord[] = [
  { id: "req_prd", version: 2, target: { kind: "tier", tier: "production" }, selector: { tailnet: "corp.ts.net", tags: ["tag:prod", "tag:ci"], users: ["alice@corp"], nodes: ["n1"] } },
  { id: "req_stg", target: { kind: "environments", environmentIds: ["env_stg"] }, selector: { tailnet: "corp.ts.net", tags: ["", "tag:stg"] } },
  { id: "req_root", version: 1, target: { kind: "environments", environmentIds: ["env_prd"] }, selector: { tailnet: "corp.ts.net", users: ["bob@corp", ""] } },
  { id: "req_qa", version: 3, target: { kind: "tier", tier: "qa" as never }, selector: { tailnet: "corp.ts.net", nodes: ["n9"] } },
];

const CONTEXTS: Record<string, TailnetContext | null> = {
  none: null,
  otherTailnet: { tailnet: "other.ts.net", nodeId: "n1", tags: ["tag:prod"] },
  node: { tailnet: "corp.ts.net", nodeId: "n1", nodeName: "build-1", tags: [] },
  tag: { tailnet: "corp.ts.net", nodeId: "n9", tags: ["tag:ci", "tag:prod"] },
  emptyTag: { tailnet: "corp.ts.net", nodeId: "n9", tags: ["", "tag:stg"] },
  user: { tailnet: "corp.ts.net", nodeId: "n9", tags: [], userLogin: "alice@corp" },
  bob: { tailnet: "corp.ts.net", nodeId: "n9", tags: ["tag:stg"], userLogin: "bob@corp" },
  emptyUser: { tailnet: "corp.ts.net", nodeId: "n9", tags: [], userLogin: "" },
  nobody: { tailnet: "corp.ts.net", nodeId: "n9", tags: ["tag:dev"], userLogin: "eve@corp" },
};

/**
 * Inputs name their parts in the tables above (exported once in the file):
 * a resource, the Grants (all or none), the Requirements (all or none) and
 * a Tailnet Context.
 */
function evaluateVectors() {
  const out: unknown[] = [];
  const add = (input: { action: string; resource: string; orgRole: "admin" | "member" | null; grants: boolean; requirements: boolean; tailnet: string }) => {
    const evaluation = evaluate({
      action: input.action as Action,
      resource: RESOURCES[input.resource]!,
      orgRole: input.orgRole,
      grants: input.grants ? GRANTS : [],
      requirements: input.requirements ? REQUIREMENTS : [],
      tailnetContext: CONTEXTS[input.tailnet]!,
    });
    out.push({ ...input, evaluation, auditAuthz: auditAuthz(evaluation) });
  };
  // The built-in bundles, without Grants.
  for (const orgRole of ["admin", "member", null] as const) {
    for (const resource of Object.keys(RESOURCES)) {
      for (const action of ACTIONS) add({ action, resource, orgRole, grants: false, requirements: false, tailnet: "none" });
    }
  }
  // Every Grant shape, together, without a role.
  for (const resource of Object.keys(RESOURCES)) {
    for (const action of ACTIONS) add({ action, resource, orgRole: null, grants: true, requirements: false, tailnet: "none" });
  }
  // Requirements: every context, for the roles and the Grants.
  for (const [resource, r] of Object.entries(RESOURCES)) {
    if (!r.environment) continue;
    for (const action of [...CONSTRAINED, "environment.read"]) {
      for (const tailnet of Object.keys(CONTEXTS)) {
        for (const orgRole of ["admin", "member", null] as const) {
          add({ action, resource, orgRole, grants: orgRole === null, requirements: true, tailnet });
        }
      }
    }
  }
  return out;
}

// ------------------------------------------------------------------- world

type Value = string | number | null | string[] | (string | null)[] | Record<string, unknown> | { $ts: string };
type Row = Record<string, Value>;
const ts = (iso: string) => ({ $ts: iso });

const ORG = { "1": "org_acme", "2": "org_other", "3": "org_gone" };
const kek = { v: 1 };

/** The fixture, in insertion order: [table, row]. */
function world(): [string, Row][] {
  const rows: [string, Row][] = [];
  const add = (table: string, row: Row) => rows.push([table, row]);
  add("organizations", { id: ORG["1"], slug: "acme", name: "Acme", wrapped_org_kek: kek });
  add("organizations", { id: ORG["2"], slug: "other", name: "Other", wrapped_org_kek: kek });
  add("organizations", { id: ORG["3"], slug: "gone", name: "Gone", wrapped_org_kek: kek, deleted_at: ts("2026-10-01T00:00:00Z") });
  const human = (id: string) => add("identities", { id, kind: "human", name: id });
  for (const id of ["idn_admin", "idn_member", "idn_grants", "idn_group", "idn_team", "idn_removed", "idn_elsewhere", "idn_nobody"]) human(id);
  add("identities", { id: "idn_svc", kind: "service", name: "svc", organization_id: ORG["1"] });
  add("identities", { id: "idn_agent", kind: "agent", name: "agent", organization_id: ORG["1"] });
  add("identities", { id: "idn_ci_other", kind: "ci", name: "ci", organization_id: ORG["2"] });
  add("identities", { id: "idn_svc_bare", kind: "service", name: "bare", organization_id: ORG["1"] });
  const member = (identity: string, org: string, role: string, removed?: string) =>
    add("org_memberships", { organization_id: org, identity_id: identity, role, ...(removed ? { removed_at: ts(removed) } : {}) });
  member("idn_admin", ORG["1"], "admin");
  member("idn_member", ORG["1"], "member");
  member("idn_grants", ORG["1"], "member");
  member("idn_group", ORG["1"], "member");
  member("idn_team", ORG["1"], "member");
  member("idn_removed", ORG["1"], "admin", "2026-10-02T00:00:00Z");
  member("idn_elsewhere", ORG["2"], "admin");
  member("idn_grants", ORG["2"], "member");
  for (const [id, org] of [["prj_web", ORG["1"]], ["prj_api", ORG["1"]], ["prj_ops", ORG["1"]], ["prj_far", ORG["2"]]] as const) {
    add("projects", { id, organization_id: org, slug: id, name: id, contract_authority: "managed" });
  }
  add("environments", { id: "env_dev", project_id: "prj_web", name: "dev", kind: "shared", tier: "development" });
  add("environments", { id: "env_stg", project_id: "prj_web", name: "stg", kind: "shared", tier: "staging" });
  add("environments", { id: "env_prd", project_id: "prj_web", name: "prd", kind: "shared", tier: "production" });
  add("environments", { id: "env_dev_me", project_id: "prj_web", name: "dev-me", kind: "personal", tier: "development", parent_environment_id: "env_dev", owner_identity_id: "idn_member" });
  add("environments", { id: "env_prd_pr", project_id: "prj_web", name: "prd-pr", kind: "preview", tier: "production", parent_environment_id: "env_prd" });
  add("environments", { id: "env_api_prd", project_id: "prj_api", name: "prd", kind: "shared", tier: "production" });
  add("roles", { id: "rol_reader", organization_id: ORG["1"], name: "reader", actions: ["config.value.read", "secret.reveal"], version: 3 });
  add("roles", { id: "rol_revoked", organization_id: ORG["1"], name: "old", actions: ["secret.use"], revoked_at: ts("2026-10-03T00:00:00Z") });
  add("roles", { id: "rol_empty", organization_id: ORG["1"], name: "empty", actions: [] });
  // No NULL array elements here: PGlite reads one back as the string "NULL"
  // (node-postgres reads null). The evaluate vectors cover them.
  add("roles", { id: "rol_audit", organization_id: ORG["1"], name: "audit", actions: ["audit.read"], version: 7 });
  add("roles", { id: "rol_ops", organization_id: ORG["1"], name: "ops", actions: ["secret.reveal", "environment.manage"], version: 2 });
  add("groups", { id: "grp_ops", organization_id: ORG["1"], name: "ops", kind: "group" });
  add("groups", { id: "grp_old", organization_id: ORG["1"], name: "old", kind: "group", revoked_at: ts("2026-10-04T00:00:00Z") });
  add("groups", { id: "tem_web", organization_id: ORG["1"], name: "web", kind: "team" });
  add("groups", { id: "tem_empty", organization_id: ORG["1"], name: "empty", kind: "team" });
  add("groups", { id: "tem_gone", organization_id: ORG["1"], name: "gone", kind: "team", revoked_at: ts("2026-10-05T00:00:00Z") });
  for (const [group, identity] of [["grp_ops", "idn_group"], ["grp_old", "idn_group"], ["tem_web", "idn_team"], ["grp_ops", "idn_svc"], ["grp_ops", "idn_removed"], ["tem_web", "idn_group"]]) {
    add("group_members", { group_id: group!, identity_id: identity! });
  }
  add("team_projects", { team_id: "tem_web", project_id: "prj_web" });
  add("team_projects", { team_id: "tem_web", project_id: "prj_api" });
  add("team_projects", { team_id: "tem_gone", project_id: "prj_ops" });
  const grant = (id: string, org: string, subject: { identity?: string; group?: string }, scope: Record<string, unknown>, permission: { actions?: (string | null)[]; role?: string }, revoked?: string) =>
    add("grants", {
      id,
      organization_id: org,
      ...(subject.identity ? { subject_identity_id: subject.identity } : {}),
      ...(subject.group ? { subject_group_id: subject.group } : {}),
      scope,
      ...(permission.actions ? { actions: permission.actions } : {}),
      ...(permission.role ? { role_id: permission.role } : {}),
      ...(revoked ? { revoked_at: ts(revoked) } : {}),
    });
  const O = ORG["1"];
  const web = "prj_web";
  grant("grt_a_org", O, { identity: "idn_grants" }, { kind: "organization" }, { actions: ["project.manage", "policy.read"] });
  grant("grt_b_project", O, { identity: "idn_grants" }, { kind: "project", projectId: web }, { actions: ["config.value.write", "environment.read"] });
  grant("grt_c_ids", O, { identity: "idn_grants" }, { kind: "environments", projectId: web, selector: { kind: "environments", environmentIds: ["env_dev"] } }, { actions: ["secret.reveal", "config.value.read"] });
  grant("grt_d_tier", O, { identity: "idn_grants" }, { kind: "environments", projectId: web, selector: { kind: "tier", tier: "production" } }, { actions: ["secret.use"] });
  grant("grt_e_role", O, { identity: "idn_grants" }, { kind: "environments", projectId: web, selector: { kind: "environments", environmentIds: ["env_prd"] } }, { role: "rol_reader" });
  grant("grt_f_revoked_role", O, { identity: "idn_grants" }, { kind: "project", projectId: web }, { role: "rol_revoked" });
  grant("grt_g_empty_role", O, { identity: "idn_grants" }, { kind: "project", projectId: web }, { role: "rol_empty" });
  grant("grt_h_no_actions", O, { identity: "idn_grants" }, { kind: "project", projectId: web }, { actions: [] });
  grant("grt_i_revoked", O, { identity: "idn_grants" }, { kind: "project", projectId: web }, { actions: ["project.read", "secret.use"] }, "2026-10-06T00:00:00Z");
  grant("grt_j_group", O, { group: "grp_ops" }, { kind: "project", projectId: web }, { actions: ["audit.read", "config.value.read"] });
  grant("grt_k_old_group", O, { group: "grp_old" }, { kind: "organization" }, { actions: ["policy.manage"] });
  grant("grt_l_team", O, { identity: "idn_team" }, { kind: "team", teamId: "tem_web" }, { actions: ["config.metadata.read", "environment.manage", "secret.reveal"] });
  grant("grt_m_team_group", O, { group: "grp_ops" }, { kind: "team", teamId: "tem_web" }, { actions: ["contract.submit"] });
  grant("grt_n_empty_team", O, { identity: "idn_team" }, { kind: "team", teamId: "tem_empty" }, { actions: ["identity.read"] });
  grant("grt_o_removed", O, { identity: "idn_removed" }, { kind: "organization" }, { actions: ["audit.read"] });
  grant("grt_p_machine", O, { identity: "idn_svc" }, { kind: "organization" }, { actions: ["config.value.read", "secret.use"] });
  grant("grt_q_machine_tier", O, { identity: "idn_svc" }, { kind: "environments", projectId: web, selector: { kind: "tier", tier: "development" } }, { actions: ["secret.reveal"] });
  grant("grt_r_group_role", O, { group: "grp_ops" }, { kind: "environments", projectId: web, selector: { kind: "tier", tier: "staging" } }, { role: "rol_reader" });
  grant("grt_s_api", O, { identity: "idn_grants" }, { kind: "project", projectId: "prj_api" }, { actions: ["secret.use"] });
  grant("grt_t_not_member", O, { identity: "idn_elsewhere" }, { kind: "organization" }, { actions: ["project.read"] });
  grant("grt_u_agent", O, { identity: "idn_agent" }, { kind: "environments", projectId: web, selector: { kind: "environments", environmentIds: ["env_dev"] } }, { role: "rol_reader" });
  grant("grt_v_other_org", ORG["2"], { identity: "idn_grants" }, { kind: "organization" }, { actions: ["secret.use", "project.manage"] });
  grant("grt_w_direct_dup", O, { identity: "idn_group" }, { kind: "project", projectId: web }, { actions: ["audit.read"] });
  grant("grt_x_weird", O, { identity: "idn_grants" }, { kind: "weird" }, { actions: ["project.read"] });
  grant("grt_y_audit_role", O, { identity: "idn_grants" }, { kind: "project", projectId: web }, { role: "rol_audit" });
  grant("grt_z_gone_team", O, { identity: "idn_team" }, { kind: "team", teamId: "tem_gone" }, { actions: ["contract.activate"] });
  // A second Role contributing to secret.reveal in production, with grt_e_role.
  grant("grt_zb_second_role", O, { identity: "idn_grants" }, { kind: "environments", projectId: web, selector: { kind: "tier", tier: "production" } }, { role: "rol_ops" });
  grant("grt_za_group_dup_role", O, { group: "tem_web" }, { kind: "environments", projectId: web, selector: { kind: "environments", environmentIds: ["env_prd", "env_stg"] } }, { role: "rol_reader" });
  const requirement = (id: string, org: string, target: Record<string, unknown>, config: Record<string, unknown>, version: number, revoked?: string) =>
    add("requirements", { id, organization_id: org, kind: "tailnet", target, config, version, ...(revoked ? { revoked_at: ts(revoked) } : {}) });
  requirement("req_prd", O, { kind: "tier", tier: "production" }, { tailnet: "corp.ts.net", tags: ["tag:prod", "tag:ci"], users: ["alice@corp"], nodes: ["n1"] }, 2);
  requirement("req_stg", O, { kind: "environments", environmentIds: ["env_stg"] }, { tailnet: "corp.ts.net", tags: ["tag:stg"] }, 5);
  requirement("req_revoked", O, { kind: "tier", tier: "development" }, { tailnet: "corp.ts.net" }, 1, "2026-10-07T00:00:00Z");
  requirement("req_other", ORG["2"], { kind: "tier", tier: "development" }, { tailnet: "corp.ts.net" }, 1);
  add("organization_freezes", { id: "ofz_open", organization_id: ORG["2"], frozen_by: "idn_elsewhere", frozen_at: ts("2026-11-01T10:20:30.123456Z"), reason: "incident" });
  add("organization_freezes", { id: "ofz_lifted", organization_id: O, frozen_by: "idn_admin", frozen_at: ts("2026-10-01T00:00:00Z"), reason: "drill", lifted_at: ts("2026-10-01T01:00:00Z"), lifted_by: "idn_admin", lift_method: "approval" });
  return rows;
}

async function insert(db: AppCtx["db"], table: string, row: Row) {
  const cols = Object.keys(row);
  const values = cols.map((c) => {
    const v = row[c];
    if (v !== null && typeof v === "object" && !Array.isArray(v)) return "$ts" in v ? v.$ts : JSON.stringify(v);
    return v;
  });
  await db.query(`INSERT INTO ${table} (${cols.join(", ")}) VALUES (${cols.map((_, i) => `$${i + 1}`).join(", ")})`, values);
}

interface PrincipalSpec { identity: { id: string; kind: string; organization_id: string | null }; credentialId: string }
const PRINCIPALS: PrincipalSpec[] = [
  ["idn_admin", "human", null], ["idn_member", "human", null], ["idn_grants", "human", null], ["idn_group", "human", null],
  ["idn_team", "human", null], ["idn_removed", "human", null], ["idn_elsewhere", "human", null], ["idn_nobody", "human", null],
  ["idn_svc", "service", ORG["1"]], ["idn_agent", "agent", ORG["1"]], ["idn_ci_other", "ci", ORG["2"]], ["idn_svc_bare", "service", ORG["1"]],
].map(([id, kind, org]) => ({ identity: { id: id!, kind: kind!, organization_id: org ?? null }, credentialId: `crd_${id!.slice(4)}` }));

const W = (projectId?: string, e?: [string, string, string]): ResourceContext => ({
  organizationId: ORG["1"],
  ...(projectId ? { projectId } : {}),
  ...(e ? { environment: { id: e[0], rootId: e[1], tier: e[2] as never } } : {}),
});
const WORLD_RESOURCES: Record<string, ResourceContext> = {
  org: W(),
  web: W("prj_web"),
  api: W("prj_api"),
  dev: W("prj_web", ["env_dev", "env_dev", "development"]),
  devChild: W("prj_web", ["env_dev_me", "env_dev", "development"]),
  stg: W("prj_web", ["env_stg", "env_stg", "staging"]),
  prd: W("prj_web", ["env_prd", "env_prd", "production"]),
  prdPreview: W("prj_web", ["env_prd_pr", "env_prd", "production"]),
  apiPrd: W("prj_api", ["env_api_prd", "env_api_prd", "production"]),
  otherOrg: { organizationId: ORG["2"], projectId: "prj_far" },
};
const WORLD_CONTEXTS: Record<string, TailnetContext | null> = {
  none: null,
  node: { tailnet: "corp.ts.net", nodeId: "n1", tags: [] },
  tag: { tailnet: "corp.ts.net", nodeId: "n7", tags: ["tag:stg", "tag:ci"] },
  wrongTailnet: { tailnet: "home.ts.net", nodeId: "n1", tags: ["tag:prod"] },
  user: { tailnet: "corp.ts.net", nodeId: "n7", tags: [], userLogin: "alice@corp" },
  mismatch: { tailnet: "corp.ts.net", nodeId: "n7", tags: ["tag:dev"] },
};

function fakeContext(requestId: string, tailnetContext: TailnetContext | null): Context {
  const vars = new Map<string, unknown>([["requestId", requestId], ...(tailnetContext ? [["tailnetContext", tailnetContext] as [string, unknown]] : [])]);
  return { get: (k: string) => vars.get(k), set: (k: string, v: unknown) => void vars.set(k, v) } as unknown as Context;
}

function errorOf(e: unknown) {
  if (!(e instanceof DomainError)) throw e;
  return { code: e.code, message: e.message, ...(e.details ? { details: e.details } : {}) };
}

async function worldVectors() {
  const rows = world();
  const db = await migratedTestDb({ lockOrder: "off" });
  try {
    for (const [table, row] of rows) await insert(db, table, row);
    const ctx = { db, rootKek: Buffer.alloc(32) } as AppCtx;
    const principal = (p: PrincipalSpec) => ({ identity: p.identity, credentialId: p.credentialId, credentialKind: "cli" }) as unknown as Principal;

    const grants: Record<string, Record<string, GrantRecord[]>> = {};
    for (const org of [ORG["1"], ORG["2"]]) {
      grants[org] = {};
      for (const p of PRINCIPALS) grants[org]![p.identity.id] = await loadGrants(ctx, org, p.identity.id);
    }
    const requirements: Record<string, TailnetRequirementRecord[]> = {};
    for (const org of [ORG["1"], ORG["2"]]) requirements[org] = await loadTailnetRequirements(ctx, org);

    const decisions: unknown[] = [];
    const decideOnce = async (p: PrincipalSpec, action: string, r: string, c: string, hideExistence: boolean) => {
      const d = await decide(ctx, fakeContext("req_vector", WORLD_CONTEXTS[c]!), principal(p), action as Action, WORLD_RESOURCES[r]!, { hideExistence });
      return d.allowed
        ? { allowed: true, evaluation: d.evaluation }
        : { allowed: false, error: errorOf(d.error), denialEvent: d.denialEvent };
    };
    // Every action on the Organization, its Projects and the three tiers;
    // on a derived Environment and a second Project's, the actions whose
    // answer depends on the Environment. Principals with no standing in
    // the Organization get a representative set.
    const outsiders = ["idn_removed", "idn_elsewhere", "idn_nobody", "idn_ci_other"];
    const someActions = ["organization.read", "project.read", "environment.read", "config.value.read", "secret.reveal", "audit.read", "unknown.action"];
    const envActions = [...CONSTRAINED, "environment.read", "environment.manage", "config.value.write", "config.metadata.read"];
    for (const p of PRINCIPALS) {
      for (const r of Object.keys(WORLD_RESOURCES)) {
        const actions = outsiders.includes(p.identity.id) ? someActions : ["devChild", "prdPreview", "apiPrd"].includes(r) ? envActions : ACTIONS;
        for (const action of actions) {
          // Every Tailnet Context for a value read in an Environment, by
          // the principals that can reach one.
          const reaches = ["idn_admin", "idn_member", "idn_grants", "idn_group", "idn_team", "idn_svc", "idn_agent"].includes(p.identity.id);
          const contexts = reaches && CONSTRAINED.includes(action) && WORLD_RESOURCES[r]!.environment ? Object.keys(WORLD_CONTEXTS) : ["none"];
          for (const c of contexts) {
            const shown = await decideOnce(p, action, r, c, false);
            const hidden = await decideOnce(p, action, r, c, true);
            decisions.push({
              principal: p.identity.id, action, resource: r, tailnet: c, ...shown,
              ...(JSON.stringify(hidden) !== JSON.stringify(shown) ? { hidden } : {}),
            });
          }
        }
      }
    }

    // The incident freeze: at Organization entry, in refuseIfIncidentFrozen,
    // and before authorization in a request.
    const refs = ["acme", ORG["1"], "other", ORG["2"], "gone", ORG["3"], "missing"];
    const exceptions: (FreezeException | undefined)[] = [undefined, "audit", "freeze"];
    const entries: unknown[] = [];
    for (const p of [...PRINCIPALS, null]) {
      for (const ref of refs) {
        for (const exception of exceptions) {
          let outcome: unknown;
          try {
            const org = await getOrganization(ctx, ref);
            await organizationEntryChecks(ctx, fakeContext("req_vector", null), p ? principal(p) : undefined, org, { duringIncidentFreeze: exception });
            outcome = { organizationId: org.id };
          } catch (e) {
            outcome = { error: errorOf(e) };
          }
          entries.push({ principal: p?.identity.id ?? null, ref, exception: exception ?? null, ...(outcome as object) });
        }
      }
    }
    const scopeChecks: unknown[] = [];
    for (const org of Object.values(ORG)) {
      for (const exception of exceptions) {
        let outcome: unknown = { refused: false };
        try {
          await refuseIfIncidentFrozen(db, org, exception);
        } catch (e) {
          outcome = { error: errorOf(e) };
        }
        scopeChecks.push({ organizationId: org, exception: exception ?? null, ...(outcome as object) });
      }
    }
    const requests: unknown[] = [];
    for (const p of PRINCIPALS) {
      for (const ref of ["other", "acme"]) {
        for (const exception of [undefined, "audit"] as const) {
          for (const action of ["organization.read", "audit.read", "secret.reveal"]) {
            const c = fakeContext("req_vector", null);
            let outcome: unknown;
            try {
              const org = await getOrganization(ctx, ref);
              await organizationEntryChecks(ctx, c, principal(p), org, { duringIncidentFreeze: exception });
              const d = await decide(ctx, c, principal(p), action as Action, { organizationId: org.id }, { hideExistence: true });
              outcome = d.allowed ? { stage: "decide", allowed: true } : { stage: "decide", error: errorOf(d.error) };
            } catch (e) {
              outcome = { stage: "entry", error: errorOf(e) };
            }
            requests.push({ principal: p.identity.id, ref, exception: exception ?? null, action, hideExistence: true, ...(outcome as object) });
          }
        }
      }
    }
    return {
      rows: rows.map(([table, row]) => ({ table, row })),
      principals: PRINCIPALS,
      resources: WORLD_RESOURCES,
      contexts: WORLD_CONTEXTS,
      grants,
      requirements,
      decisions,
      entries,
      scopeChecks,
      requests,
    };
  } finally {
    await db.close();
  }
}

// ------------------------------------------------------------- destination

const HOSTS = [
  "example.com", "Example.COM", " example.com ", "example.com.", "example.com..", "a..b", ".", "", "  ",
  "b\u00fccher.de", "B\u00dcCHER.de", "xn--bcher-kva.de", "xn--abc", "xn--", "\u2603.net", "\uff21\uff22\uff23.com", "a\u200db.com", "\u0130stanbul.tr",
  "\u03a3\u0391\u03a3.gr", "a_b.com", "-a.com", "a-.com", "user@example.com", "example.com/path", "example.com?q", "example.com#f",
  "exa mple.com", "exa\tmple.com", "example.com:443", "[::1]", "::1", "1.2.3.4", "01.2.3.4", "1.2.3", "0x7f.1",
  "256.1.1.1", "999.1.1.1", "a.0x10", "fe80::1%eth0", "FE80::A", "a%41.com", "%", "a%2e.com", "*.example.com",
  "a\u3000b.com", "a\ufeffb.com", "\u00a0example.com", "example\u2028.com", "a\\b", "a[b", "a]b", "example.com\u3002org",
  "xn--zz", "xn--ls8h", "xn---", "XN--abc", "xn--abc.xn--def", "xn--\u00e9", "xn--abc.b\u00fccher.de", "a..b\u00fccher.de", "b\u00fccher.de.",
  "-b\u00fccher.de", "a_\u00fc.de", "\u00fc.xn--zz", "\u0663.\u0661", "a\u0663b.de", "\u00fc\uff0ede", "\u00df.de", "\u03c2.gr", "\u200c\u00fc.de", "\u00fc\u00ad.de",
  "[::1]/x", "[::1]:80", "a:", ":x", "host\\path", "[0:0::1]", "[::ffff:1.2.3.4]", "[1:2:3:4:5:6:7:8:9]", "0", "0x", "1.2.3.4.5",
  "1.2.3.4.", "4294967295", "4294967296", "0377.0.0.1", "09.1.1.1", "a.1", "1.a", "exam%70le.com", "%C3%BC.de", "%FF.de",
  // IDNA as Node handles it: bidi, joiners, marks, mapping, ACE labels.
  "a\u0870.example", "\u0870.example", "\u0870a.example", "\u0627b.example", "\u05d0\u05d1.example",
  "\u05d0\u05d11.example", "1\u05d0.example", "abc.\u05d0\u05d1", "\u05d0.abc", "\u05d0a.example",
  "a\u05f3.example", "\u0627\u0661\u06f1.example", "\u0627\u0661.example", "\u06271.example",
  "\u0661\u0627.example", "\u05d0\u0300.example", "\u05d01\u0300.example", "\u00a1.\u05d0", "a\u00b7.\u05d0",
  "\u05d0\u0020\u05d1.example", "\u08b5a.example", "\u05d0\u08b5.example", "a\u200db.example",
  "a\u200cb.example", "\u0915\u094d\u200c\u0937.example", "\u0915\u094d\u200d\u0937.example", "\u200c.example",
  "\u0628\u200c\u0627.example", "\u0627\u200c\u0628.example", "\u0628\u200c.example",
  "\u0915\u094d\u200c\u05d0.example", "\u0628\u200c\u200d\u0627.example", "\ua872\u200c\u0627.example",
  "\u0301a.example", "\u0c3c.example", "\u1ac1.example", "\u1dfa.example", "a\u0c3c.example",
  "\uff41\uff42.example", "\u1e9e.de", "\u2488.com", "a\u3002b\u00fc.de", "a\uff0e\u00fc.de", "\u00fc\u00ad.de",
  "\u00fc\u034f.de", "e\u0301.example", "\u{1f600}.example", "\u2615.example", "\ue000.example",
  "\u0378.example", "\ufdd0.example", "\u{e0001}.example", "x\u0130.tr", "\u03a3\u0391\u03a3.gr", "a\u03c2.gr",
  "\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc\u00fc.de",
  "xn--tda.\u00fc", "xn--abc.\u00fc", "xn--a-ecp.\u00fc", "Xn--TDA.\u00fc", "xn--.\u00fc", "xn--tda\u00fc",
  "xn--ls8h.\u00fc", "xn--zz.\u00fc", "xn--55.\u00fc", "\u00fc.xn--a-fld", "\u00fc.xn--4db", "\u00fc.xn--cxb",
  "\u00fc.\u05d0\u0627", "\u00fc_x.de", "\u00fc!.de", "\u00fc%41.de", "%C3%BC.\u05d0", "\u00fc..de",
];
const SELECTORS = [
  "example.com", "example.com:8443", "*.example.com", "*.example.com:444", "*.1.2.3.4", "1.2.3.4", "1.2.3.4:80",
  "[::1]", "[::1]:8443", "[FE80::A]", "[::1]x", "[::1", "[1.2.3.4]", "::1", "fe80::1:443", "a*.example.com", "*example.com",
  "*.*.example.com", "*.", "*", "example.com:0", "example.com:65535", "example.com:65536", "example.com:", "example.com:abc",
  "example.com:123456", "B\u00fccher.DE:443", " example.com ", "", "  ", "user@example.com", "example.com/x", "*.xn--bcher-kva.de",
  "example.com.:443", "a..b", "0x7f.1", "[fe80::1%eth0]", "[::ffff:1.2.3.4]:1",
  "a\u0870.example", "*.a\u0870.example:8443", "\u05d0\u05d1.example", "\u0627b.example",
  "*.\u0628\u200c\u0627.example", "xn--a-fld.example",
];
const DESTINATIONS = [
  "example.com", "EXAMPLE.com.", "api.example.com", "a.b.example.com", "badexample.com", "1.2.3.4", "::1", "fe80::a",
  "b\u00fccher.de", "www.xn--bcher-kva.de", "www.b\u00fccher.de", "a..b", "", "user@x", "0x7f.1", "127.0.0.1", "::ffff:1.2.3.4",
  "a\u0870.example", "xn--a-fld.example", "www.a\u0870.example", "www.xn--a-fld.example", "\u05d0\u05d1.example",
  "x.\u05d0\u05d1.example", "\u0628\u200c\u0627.example",
];

function destinationVectors() {
  const hosts = HOSTS.map((h) => ({ input: h, canonical: canonicalizeHost(h), domainToASCII: domainToASCII(h), isIP: isIP(h) }));
  const selectors = SELECTORS.map((s) => {
    const sel = parseDestinationSelector(s);
    return { input: s, selector: sel, formatted: sel ? formatSelector(sel) : null };
  });
  const matches: unknown[] = [];
  for (const s of SELECTORS) {
    const sel = parseDestinationSelector(s);
    if (!sel) continue;
    for (const host of DESTINATIONS) {
      for (const port of [443, sel.port === 443 ? 8443 : sel.port]) {
        matches.push({ selector: s, host, port, matches: destinationMatches(sel, { host, port }) });
      }
    }
  }
  return { destinationHosts: hosts, destinationSelectors: selectors, destinationMatches: matches };
}

// ---------------------------------------------------------------- the file

/** One member per line, so a change shows as the vectors it touches. */
function format(vectors: Record<string, unknown>): string {
  const lines = ["{"];
  const keys = Object.keys(vectors);
  keys.forEach((k, i) => {
    const v = vectors[k];
    const tail = i < keys.length - 1 ? "," : "";
    if (Array.isArray(v)) {
      lines.push(`  ${JSON.stringify(k)}: [`);
      v.forEach((e, j) => lines.push(`    ${JSON.stringify(e)}${j < v.length - 1 ? "," : ""}`));
      lines.push(`  ]${tail}`);
    } else if (v && typeof v === "object") {
      lines.push(`  ${JSON.stringify(k)}: {`);
      const inner = Object.keys(v);
      inner.forEach((ik, j) => lines.push(`    ${JSON.stringify(ik)}: ${JSON.stringify((v as Record<string, unknown>)[ik])}${j < inner.length - 1 ? "," : ""}`));
      lines.push(`  }${tail}`);
    } else {
      lines.push(`  ${JSON.stringify(k)}: ${JSON.stringify(v)}${tail}`);
    }
  });
  lines.push("}");
  return `${lines.join("\n")}\n`;
}

it("the Go authorization vectors are current", { timeout: 300_000 }, async () => {
  const w = await worldVectors();
  const text = format({
    generator: "services/varlatchd/test/go-authz-vectors.test.ts",
    actions: ACTIONS,
    evaluateResources: RESOURCES,
    evaluateGrants: GRANTS,
    evaluateRequirements: REQUIREMENTS,
    evaluateContexts: CONTEXTS,
    evaluate: evaluateVectors(),
    ...w,
    ...destinationVectors(),
  });
  if (process.env.VARLATCH_WRITE_GO_VECTORS === "1") {
    writeFileSync(OUT, text);
    return;
  }
  const committed = readFileSync(OUT, "utf8");
  expect(committed === text, "go/server/authz/testdata/ts-vectors.json is stale: regenerate it (see the header of this file)").toBe(true);
});

it("go/server/whatwg's table of Node's host parser is current", { timeout: 300_000 }, async () => {
  // @ts-expect-error: a plain ES module without types
  const idna = (await import("../../../go/server/whatwg/testdata/nodeidna.mjs")) as {
    build: () => { go: string; json: string };
    TABLE: string;
    VECTORS: string;
  };
  const { go, json } = idna.build();
  const stale = [[idna.TABLE, go], [idna.VECTORS, json]].filter(([file, want]) => readFileSync(file!, "utf8") !== want);
  expect(stale.map(([file]) => file), "regenerate them: node go/server/whatwg/testdata/nodeidna.mjs").toEqual([]);
});
