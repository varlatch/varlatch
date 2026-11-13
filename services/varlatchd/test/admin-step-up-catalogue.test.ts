// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import ts from "typescript";
import { parse as parseYaml } from "yaml";
import { CAPABILITIES } from "@varlatch/protocol";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { APPROVAL_OPERATIONS, CONTROL_APPROVAL_OPERATIONS, OPERATIONS_DURING_FREEZE } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from "../src/domain/bootstrap.js";
import { getOrgRole } from "../src/domain/orgs.js";
import { ADMIN_STEP_UP_OPERATIONS, type AdminStepUpOperation } from "../src/domain/securityreport.js";
import { ENFORCEABLE_CONTROLS, enforceCapability, resetControls, type SecurityControlName } from "../src/domain/securitycontrols.js";
import { buildApp } from "../src/http/app.js";
import { PUBLIC_URL, RP } from "./helpers/device-sign-in.js";
import { fakeGitHubApps } from "./helpers/fake-github-app.js";
import { migratedTestDb } from "./helpers/pglite.js";
import { ROUTE_ACCESS } from "./helpers/route-access.js";
import { registerSoftPasskey, type SoftAuthenticator } from "./helpers/soft-authenticator.js";

/**
 * The check across all 40 admin-step-up operations (ADR-0054 step 4.9,
 * item 9 of the step-4 plan), before the control is unlocked. Each part
 * walks the binding catalogue (internal docs/design/adr-0054-binding-
 * catalogue.md), written down once here as CATALOGUE:
 *
 * - the lists: the operations the server asks approvals for, report mode's
 *   counted operations, the database's two CHECK constraints (migration
 *   0051) and the OpenAPI Approval.operation enum all name exactly the
 *   catalogue's 40;
 * - alternate callers: every write route under /v1/organizations/:org is
 *   either the route of a catalogue operation or listed as unprotected with
 *   a reason (UNPROTECTED_WRITES), every write in src/ to what the
 *   operations change is classified (WRITERS), and every caller of a
 *   protected domain function is known (CALLERS); at runtime, every route of
 *   every operation, alternate routes and request shapes included, asks for
 *   an approval of exactly that operation;
 * - machine refusal: a machine credential holding the actions is refused on
 *   every route, without an intent;
 * - the operator reset: it closes the open intents of every operation, and
 *   only for the controls it names;
 * - freeze: each operation either is in OPERATIONS_DURING_FREEZE (an intent
 *   is created) or is refused while frozen (none is);
 * - combinations of controls, and the order of refusals;
 * - follow-up (a): a denial found by a protected operation's recheck in its
 *   transaction is audited once, after the rollback, as main audits an
 *   ordinary denial; with every control off nothing changes.
 *
 * admin-step-up is enforced through the API here (it is unlocked); the
 * older per-group suites set it in the database and still may.
 */

vi.mock("../src/domain/orgs.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/domain/orgs.js")>();
  return { ...actual, getOrgRole: vi.fn(actual.getOrgRole) };
});
const orgRole = vi.mocked(getOrgRole);

const ORG = "/v1/organizations/:org";
const ACME = "/v1/organizations/acme";
const BETA = "/v1/organizations/beta";
const HOOK = "https://sink.example/services/T000/hook-secret-token-1";
const HOOK_2 = "https://sink.example/services/T000/hook-secret-token-2";
const CREDENTIAL = "ghp_secretcredential000000000000000001";
const CREDENTIAL_2 = "ghp_secretcredential000000000000000002";
const OWNER = { login: "acme-gh", id: 1009, type: "Organization" as const };
const PERMISSIONS = { secrets: "write", environments: "write", metadata: "read" };
const ISSUER = "https://ci.example";

/**
 * The binding catalogue's 40 admin-step-up operations, in its order, with
 * every route that performs each one and whether an intent may be created
 * for it while the Organization is frozen (ADR-0055 Decision 6).
 */
const CATALOGUE: { operation: AdminStepUpOperation; routes: string[]; duringFreeze: boolean }[] = [
  // 4.5: identities, credentials, OIDC bindings.
  { operation: "identity.create", routes: [`POST ${ORG}/identities`], duringFreeze: false },
  { operation: "credential.issue", routes: [`POST ${ORG}/identities/:identity/credentials`], duringFreeze: false },
  { operation: "identity.reactivate", routes: [`POST ${ORG}/identities/:identity/reactivate`], duringFreeze: false },
  { operation: "oidc_binding.create", routes: [`POST ${ORG}/identities/:identity/oidc-bindings`], duringFreeze: false },
  { operation: "oidc_binding.delete", routes: [`DELETE ${ORG}/identities/:identity/oidc-bindings/:binding`], duringFreeze: true },
  // 4.6: access structure.
  { operation: "grant.create", routes: [`POST ${ORG}/grants`], duringFreeze: false },
  { operation: "grant.replace", routes: [`POST ${ORG}/grants/:grant/replace`], duringFreeze: false },
  { operation: "grant.revoke", routes: [`DELETE ${ORG}/grants/:grant`], duringFreeze: true },
  { operation: "role.create", routes: [`POST ${ORG}/roles`], duringFreeze: false },
  { operation: "role.update", routes: [`PATCH ${ORG}/roles/:role`], duringFreeze: false },
  { operation: "role.delete", routes: [`DELETE ${ORG}/roles/:role`], duringFreeze: false },
  { operation: "group.create", routes: [`POST ${ORG}/groups`], duringFreeze: false },
  { operation: "group.update", routes: [`PATCH ${ORG}/groups/:group`], duringFreeze: false },
  { operation: "group.delete", routes: [`DELETE ${ORG}/groups/:group`], duringFreeze: false },
  { operation: "group.member_add", routes: [`POST ${ORG}/groups/:group/members`], duringFreeze: false },
  { operation: "group.member_remove", routes: [`DELETE ${ORG}/groups/:group/members/:identity`], duringFreeze: false },
  { operation: "team.create", routes: [`POST ${ORG}/teams`], duringFreeze: false },
  { operation: "team.update", routes: [`PATCH ${ORG}/teams/:team`], duringFreeze: false },
  // A team reached through a /groups/ route is still team.* (amendment A): the stored kind decides.
  { operation: "team.delete", routes: [`DELETE ${ORG}/teams/:team`, `DELETE ${ORG}/groups/:group`], duringFreeze: false },
  { operation: "team.member_add", routes: [`POST ${ORG}/teams/:team/members`, `POST ${ORG}/groups/:group/members`], duringFreeze: false },
  { operation: "team.member_remove", routes: [`DELETE ${ORG}/teams/:team/members/:identity`, `DELETE ${ORG}/groups/:group/members/:identity`], duringFreeze: false },
  { operation: "team.project_add", routes: [`POST ${ORG}/teams/:team/projects`], duringFreeze: false },
  { operation: "team.project_remove", routes: [`DELETE ${ORG}/teams/:team/projects/:project`], duringFreeze: false },
  // 4.7: people.
  { operation: "member.invite_admin", routes: [`POST ${ORG}/invitations`], duringFreeze: false },
  { operation: "member.promote", routes: [`PATCH ${ORG}/members/:member`], duringFreeze: false },
  { operation: "member.demote", routes: [`PATCH ${ORG}/members/:member`], duringFreeze: true },
  { operation: "member.remove", routes: [`DELETE ${ORG}/members/:member`], duringFreeze: true },
  // 4.8: integrations.
  { operation: "webhook.create", routes: [`POST ${ORG}/webhooks`], duringFreeze: false },
  { operation: "webhook.update", routes: [`PATCH ${ORG}/webhooks/:webhook`], duringFreeze: false },
  { operation: "webhook.delete", routes: [`DELETE ${ORG}/webhooks/:webhook`], duringFreeze: false },
  { operation: "connection.create", routes: [`POST ${ORG}/platform-connections`], duringFreeze: false },
  { operation: "connection.replace_credential", routes: [`POST ${ORG}/platform-connections/:connection/credential`], duringFreeze: false },
  { operation: "connection.delete", routes: [`DELETE ${ORG}/platform-connections/:connection`], duringFreeze: true },
  // Staged (amendment D): the callback converts and attaches; the attachment is repeated on its own route.
  { operation: "github_app.register", routes: [`POST ${ORG}/github-app/registrations/complete`, `POST ${ORG}/github-app/registrations/:registration/attach`], duringFreeze: false },
  { operation: "github_app.import", routes: [`POST ${ORG}/github-app/import`], duringFreeze: false },
  { operation: "github_app.replace_key", routes: [`POST ${ORG}/github-app/key`], duringFreeze: false },
  { operation: "github_app.remove", routes: [`DELETE ${ORG}/github-app`], duringFreeze: false },
  // 4.9: deletion and export.
  { operation: "project.delete", routes: [`DELETE ${ORG}/projects/:project`], duringFreeze: false },
  { operation: "organization.delete", routes: [`POST ${ORG}/deletion`], duringFreeze: false },
  { operation: "secret.export", routes: [`POST ${ORG}/projects/:project/environments/:environment/disclosures`], duringFreeze: false },
];

/** Protected by another control or by step 3: never admin-step-up's. */
const OTHER_PROTECTED: Record<string, string> = {
  [`PATCH ${ORG}/requirements/:requirement`]: "requirement-protection: requirement.update",
  [`DELETE ${ORG}/requirements/:requirement`]: "requirement-protection: requirement.revoke",
  [`PATCH ${ORG}/security/controls/:control`]: "security_control.change, when it loosens (step 3)",
  [`POST ${ORG}/incident-freeze/:freeze/lift`]: "organization.unfreeze (ADR-0055)",
};

/**
 * Every other write route under /v1/organizations/:org, and why
 * admin-step-up leaves it alone (ADR-0054 Decision 5's exemptions and the
 * catalogue's "Requests near the list that stay unprotected"). A new write
 * route fails until it is listed here or in the catalogue.
 */
const UNPROTECTED_WRITES: Record<string, string> = {
  [`PATCH ${ORG}`]: "renaming the Organization changes no authority",
  [`POST ${ORG}/deletion/:deletion/approve`]: "the second admin's approval of a scheduled deletion (amendment B): ADR-0051's own check",
  [`POST ${ORG}/deletion/:deletion/cancel`]: "cancelling a scheduled deletion only restricts",
  [`POST ${ORG}/incident-freeze`]: "freezing only restricts (ADR-0055)",
  [`POST ${ORG}/projects`]: "creating a Project grants nothing to anyone",
  [`PATCH ${ORG}/projects/:project`]: "renaming a Project",
  [`POST ${ORG}/projects/:project/environments`]: "creating an environment",
  [`DELETE ${ORG}/projects/:project/environments/:environment`]: "deleting an environment tombstones it (ADR-0025); on the catalogue's unprotected list",
  [`POST ${ORG}/projects/:project/environments/:environment/validate`]: "a validation: a read",
  [`PUT ${ORG}/projects/:project/environments/:environment/values/:item`]: "a value write",
  [`DELETE ${ORG}/projects/:project/environments/:environment/values/:item`]: "a value write",
  [`POST ${ORG}/projects/:project/environments/:environment/values/:item/rotations`]: "a value write",
  [`POST ${ORG}/projects/:project/environments/:environment/values/:item/rotations/complete`]: "a value write",
  [`GET ${ORG}/projects/:project/environments/:environment/effective-configuration`]: "a value read, export's non-sensitive values included (Codex, 2026-11-11)",
  [`POST ${ORG}/projects/:project/environments/:environment/retrievals`]: "a value read (varlatch run): exempt by Decision 5",
  [`POST ${ORG}/projects/:project/environments/:environment/capabilities`]: "a Capability: exercised authority is the creator's own, checked at exercise",
  [`DELETE ${ORG}/projects/:project/environments/:environment/capabilities/:capability`]: "revoking a Capability only restricts",
  [`POST ${ORG}/projects/:project/environments/:environment/capabilities/:capability/exercises`]: "Capability exercise: exempt by Decision 5",
  [`POST ${ORG}/projects/:project/environments/:environment/changes`]: "a value change set",
  [`POST ${ORG}/projects/:project/contract/revisions`]: "a Contract Revision",
  [`POST ${ORG}/projects/:project/contract/revisions/:revision/activate`]: "a Contract Revision",
  [`DELETE ${ORG}/identities/:identity/credentials/:credential`]: "revoking a credential only restricts; on the catalogue's unprotected list",
  [`POST ${ORG}/identities/:identity/retire`]: "retiring an identity only restricts; on the catalogue's unprotected list",
  [`PATCH ${ORG}/identities/:identity`]: "renaming an identity; on the catalogue's unprotected list",
  [`POST ${ORG}/members/:member/exposure/confirmations`]: "an operator's record that an exposed version was revoked (ADR-0052)",
  [`DELETE ${ORG}/invitations/:invitation`]: "revoking an invitation only restricts; on the catalogue's unprotected list",
  [`POST ${ORG}/requirements`]: "creating a Tailnet Requirement only restricts (Decision 5)",
  [`POST ${ORG}/platform-connections/check`]: "the credential checks: exempt, with their full behaviour (catalogue, Codex 2026-11-11)",
  [`POST ${ORG}/platform-connections/destinations`]: "the credential checks: exempt, with their full behaviour (catalogue, Codex 2026-11-11)",
  [`POST ${ORG}/github-app/registrations`]: "starting a registration (amendment D): only the attachment is protected",
  [`DELETE ${ORG}/github-app/registrations/:registration`]: "discarding a pending registration only restricts",
  [`GET ${ORG}/github-app/installations`]: "listing the App's installations: a read that mints a narrowed token, like the credential checks",
  [`POST ${ORG}/projects/:project/environments/:environment/sync-targets`]: "a Sync Target: ADR-0031's write-time disclosure gate applies; on the catalogue's unprotected list",
  [`PATCH ${ORG}/projects/:project/environments/:environment/sync-targets/:target`]: "a Sync Target: ADR-0031's write-time gate",
  [`POST ${ORG}/projects/:project/environments/:environment/sync-targets/:target/push`]: "sync: exempt by Decision 5",
  [`POST ${ORG}/projects/:project/environments/:environment/sync-targets/:target/pause`]: "pausing sync only restricts",
  [`POST ${ORG}/projects/:project/environments/:environment/sync-targets/:target/resume`]: "sync: exempt by Decision 5",
  [`DELETE ${ORG}/projects/:project/environments/:environment/sync-targets/:target`]: "deleting a Sync Target only restricts",
};

/**
 * Every function in src/ that writes the rows the 40 operations change
 * (identities, credentials, OIDC bindings, Grants, roles, groups, their
 * members and Team-Project links, memberships, invitations, webhooks,
 * Connections, GitHub Apps and their registrations, Projects,
 * Organization deletions), attributed by the syntax tree (attribute): by
 * file and route or function, a helper that is not exported resolved to
 * its callers ("caller via helper"). Each is protected by the named
 * operations or exempt for a reason. A new writer fails until it is
 * classified.
 */
const WRITERS: Record<string, string> = {
  "auth/credentials.ts authenticateBearer": "exempt: a credential's use count and last use",
  "auth/credentials.ts issueCredential": "the credential primitive: its callers are in CALLERS",
  "auth/credentials.ts revokeCredential": "exempt: revoking a credential only restricts",
  "domain/bootstrap.ts completePublicUrlChange": "exempt: host command, revokes browser credentials",
  "domain/bootstrap.ts consumeSetupGrant": "exempt: enrollment through a setup grant (an invitation, bootstrap or recovery)",
  "domain/bootstrap.ts issueBootstrapGrant": "exempt: host command",
  "domain/bootstrap.ts issueInviteGrant": "protected: member.invite_admin (a member invitation is exempt)",
  "domain/bootstrap.ts issueRecoveryGrant": "exempt: host command (admin recover)",
  "domain/bootstrap.ts issueReenrollmentGrants": "exempt: host command (admin reenroll)",
  "domain/contracts.ts activateRevision": "exempt: a Contract Revision",
  "domain/githubapps.ts attachRegistration via attachInTx": "protected: github_app.register",
  "domain/githubapps.ts attachRegistration via endRefused > endRefusedIn > endPending": "exempt: ends a pending registration refused for good (amendment D)",
  "domain/githubapps.ts completeRegistration": "protected: github_app.register (its conversion is not, amendment D)",
  "domain/githubapps.ts completeRegistration via attachInTx": "protected: github_app.register",
  "domain/githubapps.ts completeRegistration via endPending": "exempt: ends a pending registration (amendment D)",
  "domain/githubapps.ts completeRegistration via endRefusedIn > endPending": "exempt: ends a pending registration refused for good (amendment D)",
  "domain/githubapps.ts discardRegistration via endPending": "exempt: discarding a pending registration only restricts",
  "domain/githubapps.ts importGitHubApp": "protected: github_app.import",
  "domain/githubapps.ts startRegistration": "exempt: starting a registration (amendment D)",
  "domain/githubapps.ts sweepExpiredRegistrations": "exempt: background sweep of expired pending registrations",
  "domain/identities.ts createMachineIdentity": "protected: identity.create",
  "domain/identities.ts reactivateIdentity": "protected: identity.reactivate",
  "domain/identities.ts renameIdentity": "exempt: renaming",
  "domain/identities.ts retireIdentity": "exempt: retiring only restricts",
  "domain/invitations.ts revokeInvitation": "exempt: revoking an invitation only restricts",
  "domain/members.ts changeMemberRole": "protected: member.promote, member.demote",
  "domain/members.ts endMembership": "protected through its callers: member.remove (removeMember); leaving and the deletion's finalization are exempt",
  "domain/oidc.ts createOidcBinding": "protected: oidc_binding.create",
  "domain/oidc.ts revokeOidcBinding": "protected: oidc_binding.delete",
  "domain/orgdeletion.ts approveDeletion": "exempt: the second admin's approval (amendment B)",
  "domain/orgdeletion.ts cancelDeletion": "exempt: cancelling only restricts",
  "domain/orgdeletion.ts finalizeDeletion": "exempt: the deletion worker, after the approved scheduling and its waiting period",
  "domain/orgdeletion.ts scheduleDeletion": "protected: organization.delete",
  "domain/orgs.ts createOrganization": "exempt: a new Organization's first admin",
  "domain/orgs.ts pinLiveMembership": "exempt: a membership's version for a concurrent writer (amendment E)",
  "domain/policy.ts addGroupMember": "protected: group.member_add, team.member_add",
  "domain/policy.ts addTeamProject": "protected: team.project_add",
  "domain/policy.ts createGroup": "protected: group.create, team.create",
  "domain/policy.ts createRole": "protected: role.create",
  "domain/policy.ts deleteGroup": "protected: group.delete, team.delete",
  "domain/policy.ts deleteRole": "protected: role.delete",
  "domain/policy.ts removeGroupMember": "protected: group.member_remove, team.member_remove",
  "domain/policy.ts removeTeamProject": "protected: team.project_remove",
  "domain/policy.ts updateGroup": "protected: group.update, team.update",
  "domain/policy.ts updateRole": "protected: role.update",
  "domain/projects.ts createProject": "exempt: creating a Project",
  "domain/projects.ts deleteProject": "protected: project.delete",
  "domain/projects.ts renameProject": "exempt: renaming",
  "domain/sync.ts createAppConnection": "protected: connection.create (App shape)",
  "domain/sync.ts createConnection": "protected: connection.create (token shape)",
  "domain/sync.ts recordCredentialExpiry": "exempt: the expiry a credential check reports (catalogue, credential checks)",
  "domain/sync.ts removeGitHubApp": "protected: github_app.remove",
  "domain/sync.ts replaceConnectionCredential": "protected: connection.replace_credential",
  "domain/sync.ts revokeConnection": "protected: connection.delete",
  "domain/sync.ts rotateGitHubAppKey": "protected: github_app.replace_key",
  "domain/webhooks.ts createWebhook": "protected: webhook.create",
  "domain/webhooks.ts deliverWebhooksOnce via deliverOne": "exempt: the delivery worker's state",
  "domain/webhooks.ts revokeWebhook": "protected: webhook.delete",
  "domain/webhooks.ts updateWebhook": "protected: webhook.update",
  [`http/app.ts DELETE ${ORG}/grants/:grant`]: "protected: grant.revoke",
  "http/app.ts PATCH /v1/me/profile": "exempt: a person's own display name",
  "http/app.ts POST /v1/me/credentials/cli": "exempt: a person's own CLI credential (CLI handoff)",
  [`http/app.ts POST ${ORG}/grants/:grant/replace`]: "protected: grant.replace",
  [`http/app.ts POST ${ORG}/grants`]: "protected: grant.create",
};

/**
 * Every use in src/ of the protected domain functions and of the
 * credential primitive, each attributed by the syntax tree (attribute) to
 * its file and enclosing route ("METHOD /path") or function, a helper that
 * is not exported resolved to the routes or functions that use it
 * ("ROUTE via helper"). Never by file alone: a call added to any other
 * route, helper or function, an exempt one included, however it is
 * formatted, is a new entry and fails until it is classified
 * (and the runtime sweep below exercises the protected routes). A host
 * command reaching a protected function would pass noApprovalGate, which
 * throws ApprovalNeeded under enforce and so cannot bypass it.
 */
const inApp = (route: string) => `http/app.ts ${route}`;
const CALLERS: Record<string, string[]> = {
  createMachineIdentity: [inApp(`POST ${ORG}/identities`)],
  // Through the non-broker branch of the credentials route (the broker's mints an agent-run credential: exempt).
  issueMachineCredential: [inApp(`POST ${ORG}/identities/:identity/credentials via issueServiceCredential`)],
  reactivateIdentity: [inApp(`POST ${ORG}/identities/:identity/reactivate`)],
  createOidcBinding: [inApp(`POST ${ORG}/identities/:identity/oidc-bindings`)],
  revokeOidcBinding: [inApp(`DELETE ${ORG}/identities/:identity/oidc-bindings/:binding`)],
  createRole: [inApp(`POST ${ORG}/roles`)],
  updateRole: [inApp(`PATCH ${ORG}/roles/:role`)],
  deleteRole: [inApp(`DELETE ${ORG}/roles/:role`)],
  // Groups and teams share their writers through one helper per operation.
  createGroup: [inApp(`POST ${ORG}/groups via createGroupRoute`), inApp(`POST ${ORG}/teams via createGroupRoute`)],
  updateGroup: [inApp(`PATCH ${ORG}/groups/:group via updateGroupRoute`), inApp(`PATCH ${ORG}/teams/:team via updateGroupRoute`)],
  deleteGroup: [inApp(`DELETE ${ORG}/groups/:group via deleteGroupRoute`), inApp(`DELETE ${ORG}/teams/:team via deleteGroupRoute`)],
  addGroupMember: [inApp(`POST ${ORG}/groups/:group/members via addMemberRoute`), inApp(`POST ${ORG}/teams/:team/members via addMemberRoute`)],
  removeGroupMember: [
    inApp(`DELETE ${ORG}/groups/:group/members/:identity via removeMemberRoute`),
    inApp(`DELETE ${ORG}/teams/:team/members/:identity via removeMemberRoute`),
  ],
  addTeamProject: [inApp(`POST ${ORG}/teams/:team/projects`)],
  removeTeamProject: [inApp(`DELETE ${ORG}/teams/:team/projects/:project`)],
  issueInviteGrant: [inApp(`POST ${ORG}/invitations`)],
  changeMemberRole: [inApp(`PATCH ${ORG}/members/:member`)],
  removeMember: [inApp(`DELETE ${ORG}/members/:member`)],
  // Leaving (removeMember's exempt branch) and the deletion worker's finalization.
  endMembership: ["domain/members.ts removeMember", "domain/orgdeletion.ts finalizeDeletion"],
  createWebhook: [inApp(`POST ${ORG}/webhooks`)],
  updateWebhook: [inApp(`PATCH ${ORG}/webhooks/:webhook`)],
  revokeWebhook: [inApp(`DELETE ${ORG}/webhooks/:webhook`)],
  // net/outbound.ts's createConnection is node:net's, in its HTTP agent: another function.
  createConnection: [inApp(`POST ${ORG}/platform-connections`), "net/outbound.ts PolicyAgent.createConnection"],
  createAppConnection: [inApp(`POST ${ORG}/platform-connections`)],
  replaceConnectionCredential: [inApp(`POST ${ORG}/platform-connections/:connection/credential`)],
  revokeConnection: [inApp(`DELETE ${ORG}/platform-connections/:connection`)],
  attachInTx: ["domain/githubapps.ts attachRegistration", "domain/githubapps.ts completeRegistration"],
  attachRegistration: [inApp(`POST ${ORG}/github-app/registrations/:registration/attach`)],
  completeRegistration: [inApp(`POST ${ORG}/github-app/registrations/complete`)],
  importGitHubApp: [inApp(`POST ${ORG}/github-app/import`)],
  rotateGitHubAppKey: [inApp(`POST ${ORG}/github-app/key`)],
  removeGitHubApp: [inApp(`DELETE ${ORG}/github-app`)],
  deleteProject: [inApp(`DELETE ${ORG}/projects/:project`)],
  scheduleDeletion: [inApp(`POST ${ORG}/deletion`)],
  exportGuard: [inApp(`POST ${ORG}/projects/:project/environments/:environment/disclosures`)],
  // A service credential is issued only through createMachineIdentity and
  // issueMachineCredential (protected). The others issue a person's
  // credential (host commands, device sign-in, the CLI handoff, the
  // dashboard bearer), an OIDC-exchanged one, or an agent-run one: the
  // broker's branch of the credentials route (exempt by Decision 5).
  issueCredential: [
    "cli.ts (top level) via main > adminCommand",
    "domain/device-sign-in.ts pollDeviceSignIn via pollOnce",
    "domain/identities.ts createMachineIdentity",
    "domain/identities.ts issueMachineCredential",
    "domain/oidc.ts exchangeOidcToken",
    inApp("POST /auth/varlatch-token"),
    inApp("POST /v1/me/credentials/cli"),
    inApp(`POST ${ORG}/identities/:identity/credentials`),
  ],
};

const SRC = fileURLToPath(new URL("../src/", import.meta.url));

/** A source file under src/: its path there and its text. */
interface Source {
  file: string;
  text: string;
}

/** Every .ts file under src/, migrations aside. */
function srcFiles(): Source[] {
  const out: Source[] = [];
  const walk = (dir: string) => {
    for (const e of readdirSync(`${SRC}${dir}`, { withFileTypes: true })) {
      const rel = dir ? `${dir}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (rel !== "db/migrations") walk(rel);
      } else if (rel.endsWith(".ts")) {
        out.push({ file: rel, text: readFileSync(`${SRC}${rel}`, "utf8") });
      }
    }
  };
  walk("");
  return out;
}

/**
 * Attribution by the TypeScript compiler API (Codex's review of #135: a
 * line-based scanner let a multiline helper declaration fall into the
 * route above it). Each use of a name resolves to what encloses it in the
 * syntax tree: the nearest route registration (`app.get/post/put/patch/
 * delete/all/use(...)`, as "METHOD /path"), or else the nearest named
 * function: a function declaration, a method, or a function or arrow
 * function bound to a variable; at the module's own top level, "(top
 * level)". A helper that is not exported is resolved
 * through its own uses in its file, the same way, up to a depth bound and
 * with a cycle guard, and is shown as "ROUTE via outer > inner". Fail
 * closed: a registration whose path is not a string literal ("??"), a
 * cycle, the depth bound and a helper nobody uses each produce an entry
 * no expected list contains.
 */
interface Parsed {
  file: string;
  sf: ts.SourceFile;
}
type Scope =
  | { kind: "route"; label: string }
  | { kind: "function"; name: string; exported: boolean; decl: ts.Node }
  | { kind: "module" }
  | { kind: "error"; reason: string };

const REGISTRATION_METHODS = new Set(["get", "post", "put", "patch", "delete", "all", "use", "on"]);
const MAX_HELPER_DEPTH = 8;

const parseSource = (src: Source): Parsed => ({ file: src.file, sf: ts.createSourceFile(src.file, src.text, ts.ScriptTarget.Latest, true) });

/** `app.<method>(...)`: a route or middleware registration. */
function isRegistration(n: ts.Node): n is ts.CallExpression & { expression: ts.PropertyAccessExpression } {
  return ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && ts.isIdentifier(n.expression.expression) &&
    n.expression.expression.text === "app" && REGISTRATION_METHODS.has(n.expression.name.text);
}

/** "POST /v1/..." for a registration, or null when its path is not a string literal. */
function registrationLabel(call: ts.CallExpression & { expression: ts.PropertyAccessExpression }): string | null {
  const [path] = call.arguments;
  if (!path || !(ts.isStringLiteral(path) || ts.isNoSubstitutionTemplateLiteral(path))) return null;
  return `${call.expression.name.text.toUpperCase()} ${path.text}`;
}

const hasExport = (n: ts.Node) => ts.canHaveModifiers(n) && (ts.getModifiers(n) ?? []).some((m) => m.kind === ts.SyntaxKind.ExportKeyword);

/** What encloses `node`: the nearest registration or named function, walking up the tree. */
function scopeOf(node: ts.Node): Scope {
  let child: ts.Node = node;
  for (let n: ts.Node | undefined = node.parent; n; child = n, n = n.parent) {
    if (isRegistration(n) && child !== n.expression) {
      const label = registrationLabel(n);
      return label ? { kind: "route", label } : { kind: "error", reason: "a route registration whose path is not a string literal" };
    }
    if (ts.isFunctionDeclaration(n) && n.name) {
      return { kind: "function", name: n.name.text, exported: hasExport(n) && ts.isSourceFile(n.parent), decl: n };
    }
    if (ts.isMethodDeclaration(n) && ts.isIdentifier(n.name)) {
      const owner = ts.isClassLike(n.parent) && n.parent.name ? `${n.parent.name.text}.` : "";
      return { kind: "function", name: `${owner}${n.name.text}`, exported: true, decl: n };
    }
    if ((ts.isArrowFunction(n) || ts.isFunctionExpression(n)) && ts.isVariableDeclaration(n.parent) && ts.isIdentifier(n.parent.name)) {
      const statement = n.parent.parent.parent;
      const exported = ts.isVariableStatement(statement) && hasExport(statement) && ts.isSourceFile(statement.parent);
      return { kind: "function", name: n.parent.name.text, exported, decl: n.parent };
    }
    if (ts.isFunctionExpression(n) && n.name) return { kind: "function", name: n.name.text, exported: false, decl: n };
  }
  // A statement of the module itself, such as an entry point's main().
  return { kind: "module" };
}

/** Whether an identifier is a use of its name: not a declaration, an import or export, a property key or a type query. */
function isUse(id: ts.Identifier): boolean {
  const p = id.parent;
  if (ts.isImportSpecifier(p) || ts.isImportClause(p) || ts.isNamespaceImport(p) || ts.isExportSpecifier(p) || ts.isTypeQueryNode(p)) return false;
  if ((ts.isFunctionDeclaration(p) || ts.isVariableDeclaration(p) || ts.isParameter(p) || ts.isMethodDeclaration(p) ||
    ts.isPropertyAssignment(p) || ts.isPropertyDeclaration(p) || ts.isPropertySignature(p) || ts.isMethodSignature(p) ||
    ts.isBindingElement(p) || ts.isFunctionExpression(p) || ts.isClassDeclaration(p) || ts.isInterfaceDeclaration(p) ||
    ts.isTypeAliasDeclaration(p) || ts.isEnumMember(p)) && (p as { name?: ts.Node }).name === id) return false;
  if (ts.isBindingElement(p) && p.propertyName === id) return false;
  return true;
}

/** Every use of any of `names` in a parsed file (a call, or the name passed as a value). */
function usesOf(parsed: Parsed, names: ReadonlySet<string>): ts.Identifier[] {
  const out: ts.Identifier[] = [];
  const visit = (n: ts.Node) => {
    if (ts.isIdentifier(n) && names.has(n.text) && isUse(n)) out.push(n);
    ts.forEachChild(n, visit);
  };
  visit(parsed.sf);
  return out;
}

const isWithin = (n: ts.Node, outer: ts.Node) => n.pos >= outer.pos && n.end <= outer.end;

/** Who `node` runs for: "file ROUTE", "file function", "file ROUTE via helper", or a fail-closed entry. */
function attribute(parsed: Parsed, node: ts.Node, chain: readonly string[] = []): string[] {
  const scope = scopeOf(node);
  const via = chain.length > 0 ? ` via ${[...chain].reverse().join(" > ")}` : "";
  if (scope.kind === "error") return [`${parsed.file} ?? ${scope.reason}${via}`];
  if (scope.kind === "route") return [`${parsed.file} ${scope.label}${via}`];
  if (scope.kind === "module") return [`${parsed.file} (top level)${via}`];
  if (scope.exported) return [`${parsed.file} ${scope.name}${via}`];
  if (chain.includes(scope.name)) return [`${parsed.file} ${scope.name} (cycle)${via}`];
  if (chain.length >= MAX_HELPER_DEPTH) return [`${parsed.file} ${scope.name} (too deep)${via}`];
  // A helper: resolved through its uses in its file, outside its own body.
  const uses = usesOf(parsed, new Set([scope.name])).filter((u) => !isWithin(u, scope.decl));
  if (uses.length === 0) return [`${parsed.file} ${scope.name} (no caller)${via}`];
  return uses.flatMap((u) => attribute(parsed, u, [...chain, scope.name]));
}

/** Every use of each named function across `sources`, attributed (attribute), sorted. */
function callersIn(sources: readonly Source[], fns: readonly string[]): Record<string, string[]> {
  const found: Record<string, Set<string>> = Object.fromEntries(fns.map((f) => [f, new Set<string>()]));
  const names = new Set(fns);
  for (const parsed of sources.map(parseSource)) {
    for (const use of usesOf(parsed, names)) for (const entry of attribute(parsed, use)) found[use.text]!.add(entry);
  }
  return Object.fromEntries(Object.entries(found).map(([fn, set]) => [fn, [...set].sort()]));
}

/** Every string or template literal that writes one of the tables, attributed as above. */
function writersIn(sources: readonly Source[], write: RegExp): string[] {
  const found = new Set<string>();
  for (const parsed of sources.map(parseSource)) {
    const visit = (n: ts.Node) => {
      if ((ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n) || ts.isTemplateExpression(n)) && write.test(n.getText(parsed.sf))) {
        for (const entry of attribute(parsed, n)) found.add(entry);
        return;
      }
      ts.forEachChild(n, visit);
    };
    visit(parsed.sf);
  }
  return [...found].sort();
}

/** Every registration in a route file whose path is not a string literal. */
function unlabelledRegistrations(sources: readonly Source[]): string[] {
  const out: string[] = [];
  for (const parsed of sources.filter((s) => s.file.startsWith("http/")).map(parseSource)) {
    const visit = (n: ts.Node) => {
      if (isRegistration(n) && registrationLabel(n) === null) out.push(`${parsed.file}:${parsed.sf.getLineAndCharacterOfPosition(n.getStart(parsed.sf)).line + 1}`);
      ts.forEachChild(n, visit);
    };
    visit(parsed.sf);
  }
  return out;
}

const WRITTEN_TABLES =
  "identities|credentials|oidc_bindings|grants|roles|groups|group_members|team_projects|org_memberships|setup_grants|" +
  "webhooks|platform_connections|github_apps|github_app_registrations|projects|organization_deletions";

// ---------------------------------------------------------------------------

interface Person {
  id: string;
  web: string;
  key: SoftAuthenticator;
  /** A new CLI credential: an intent per request stays under the 5 open per credential. */
  cli: () => Promise<string>;
}

type Answer = { status: number; body: any };

interface World {
  acme: string;
  beta: string;
  project: string;
  web: string;
  svc: string;
  ci: string;
  binding: string;
  old: string;
  bob: Person;
  carol: Person;
  role: string;
  group: string;
  team: string;
  grant: string;
  webhook: { id: string; version: number };
  connection: { id: string; version: number };
  app: { id: string; githubAppId: number; version: number };
  installation: number;
  /** A pending registration of beta, converted and waiting for its attachment. */
  registration: string;
  importable: { id: number; pem: string };
  requirement: { id: string; version: number };
}

/** One request that performs an operation, by one of its routes. */
interface Request {
  operation: AdminStepUpOperation;
  label: string;
  route: string;
  org: "acme" | "beta";
  send: (token: string, approval?: string) => Promise<Answer>;
}

let ctx: AppCtx & { close: () => Promise<void> };
let app: ReturnType<typeof buildApp>;
let admin: Person;
let github: ReturnType<typeof fakeGitHubApps>;
let nextAppId: number;

async function call(method: string, path: string, token: string, body?: unknown, headers: Record<string, string> = {}): Promise<Answer> {
  const res = await app.request(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

async function ok(method: string, path: string, token: string, body?: unknown, headers: Record<string, string> = {}): Promise<any> {
  const res = await call(method, path, token, body, headers);
  expect(res.status, `${method} ${path}: ${JSON.stringify(res.body)}`).toBeLessThan(300);
  return res.body;
}

const rows = async (sql: string, params: unknown[] = []) => (await ctx.db.query(sql, params)).rows as any[];
const count = async (sql: string, params: unknown[] = []) => ((await rows(sql, params))[0] as { n: number }).n;
const intents = () => count("SELECT count(*)::int AS n FROM approval_intents");
const header = (approval?: string) => (approval ? { "Varlatch-Approval": approval } : {});
const parse = (v: unknown) => (typeof v === "string" ? JSON.parse(v) : v) as Record<string, any> | null;

async function person(identityId: string): Promise<Person> {
  const key = await registerSoftPasskey(ctx.db, identityId, { ...RP, trust: "trusted" });
  const sessionId = `session-${identityId}`;
  await ctx.db.query(
    `INSERT INTO "session" (id, "expiresAt", token, "userId")
     SELECT $1, now() + interval '1 day', $1, better_auth_user_id FROM auth_user_links WHERE identity_id = $2`,
    [sessionId, identityId],
  );
  const web = await issueCredential(ctx.db, {
    identityId,
    kind: "browser",
    expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
    authSessionId: sessionId,
  });
  return {
    id: identityId,
    web: web.token,
    key,
    cli: async () => (await issueCredential(ctx.db, { identityId, kind: "cli", name: "test cli" })).token,
  };
}

/** A dashboard bearer of a new sign-in whose evidence passkey-verification accepts (or not). */
async function signIn(identityId: string, userVerified: boolean): Promise<string> {
  const key = await registerSoftPasskey(ctx.db, identityId, { ...RP, trust: "trusted" });
  const sessionId = `session-${identityId}-${Math.random().toString(36).slice(2)}`;
  await ctx.db.query(
    `INSERT INTO "session" (id, "expiresAt", token, "userId")
     SELECT $1, now() + interval '1 day', $1, better_auth_user_id FROM auth_user_links WHERE identity_id = $2`,
    [sessionId, identityId],
  );
  await ctx.db.query(
    "INSERT INTO auth_session_evidence (session_id, ceremony, user_verified, passkey_id) VALUES ($1, 'sign-in', $2, $3)",
    [sessionId, userVerified, key.passkeyId],
  );
  return (await issueCredential(ctx.db, {
    identityId,
    kind: "browser",
    expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
    authSessionId: sessionId,
  })).token;
}

/** A person of the Organization, made an admin in the database when asked (an admin invitation is itself protected). */
async function invite(organizationId: string, name: string, role: "admin" | "member"): Promise<Person> {
  const grant = await issueInviteGrant(ctx, { organizationId, role: "member", name }, admin.id);
  const { identityId } = await consumeSetupGrant(ctx, grant.token, {});
  if (role === "admin") {
    await ctx.db.query("UPDATE org_memberships SET role = 'admin' WHERE organization_id = $1 AND identity_id = $2", [organizationId, identityId]);
  }
  return person(identityId);
}

const controlsPath = (org: "acme" | "beta") => `/v1/organizations/${org}/security/controls`;
async function controlOf(org: "acme" | "beta", control: SecurityControlName, token = admin.web) {
  return (await ok("GET", controlsPath(org), token)).items.find((i: { control: string }) => i.control === control);
}
/** Tighten a control through the API (tightening needs no approval). */
async function tighten(org: "acme" | "beta", control: SecurityControlName, mode: "report" | "enforce", config?: unknown, token = admin.web) {
  const res = await call("PATCH", `${controlsPath(org)}/${control}`, token, {
    mode,
    ...(config === undefined ? {} : { config }),
    expectedVersion: (await controlOf(org, control, token)).version,
  });
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  return res.body;
}

function stepUp(res: Answer) {
  expect(res.status, JSON.stringify(res.body)).toBe(403);
  expect(res.body.error.code, JSON.stringify(res.body)).toBe("STEP_UP_REQUIRED");
  return res.body.error.details.approval as { id: string; operation: string; organization: { id: string } | null; summary: { title: string } };
}

async function approve(p: Person, approvalId: string) {
  const started = await call("POST", `/v1/me/approvals/${approvalId}/options`, p.web);
  expect(started.status, JSON.stringify(started.body)).toBe(200);
  const approvedRes = await call("POST", `/v1/me/approvals/${approvalId}/approve`, p.web, {
    assertion: p.key.assert(started.body.publicKey.challenge, { userVerified: true }),
  });
  expect(approvedRes.status, JSON.stringify(approvedRes.body)).toBe(200);
}

/** Made while every control is off, in two Organizations: beta holds what needs an Organization without a live GitHub App. */
async function world(): Promise<World> {
  const acme = (await ok("POST", "/v1/organizations", admin.web, { name: "Acme", slug: "acme" })).id as string;
  const beta = (await ok("POST", "/v1/organizations", admin.web, { name: "Beta", slug: "beta" })).id as string;
  const project = (await ok("POST", `${ACME}/projects`, admin.web, { name: "API", slug: "api", contractAuthority: "managed" })).id as string;
  const web = (await ok("POST", `${ACME}/projects`, admin.web, { name: "Web", slug: "web", contractAuthority: "managed" })).id as string;
  await ok("POST", `${ACME}/projects/api/environments`, admin.web, { name: "production", tier: "production" });
  const revision = await ok("POST", `${ACME}/projects/api/contract/revisions`, admin.web, {
    contract: { schemaVersion: 1, items: [{ name: "DB_PASS", required: { kind: "never" }, sensitive: true, type: "string" }] },
  });
  await ok("POST", `${ACME}/projects/api/contract/revisions/${revision.id}/activate`, admin.web, {});
  await ok("PUT", `${ACME}/projects/api/environments/production/values/DB_PASS`, admin.web, { value: "hunter2" });

  const svc = (await ok("POST", `${ACME}/identities`, admin.web, { name: "api-svc", kind: "service" })).id as string;
  const ci = (await ok("POST", `${ACME}/identities`, admin.web, { name: "deploy", kind: "ci" })).id as string;
  const binding = (await ok("POST", `${ACME}/identities/${ci}/oidc-bindings`, admin.web, { issuer: ISSUER, audience: "varlatch", subject: "repo:acme/api:ref:refs/heads/main" })).id as string;
  const old = (await ok("POST", `${ACME}/identities`, admin.web, { name: "old-worker", kind: "workload" })).id as string;
  await ok("POST", `${ACME}/identities/${old}/retire`, admin.web);
  const bob = await invite(acme, "Bob", "member");
  const carol = await invite(acme, "Carol", "admin");

  const role = (await ok("POST", `${ACME}/roles`, admin.web, { name: "reader", actions: ["config.value.read", "project.read"] })).id as string;
  const group = (await ok("POST", `${ACME}/groups`, admin.web, { name: "oncall" })).id as string;
  await ok("POST", `${ACME}/groups/${group}/members`, admin.web, { identityId: svc });
  const team = (await ok("POST", `${ACME}/teams`, admin.web, { name: "platform" })).id as string;
  await ok("POST", `${ACME}/teams/${team}/members`, admin.web, { identityId: bob.id });
  await ok("POST", `${ACME}/teams/${team}/projects`, admin.web, { projectId: project });
  const grant = (await ok("POST", `${ACME}/grants`, admin.web, { subjectIdentityId: svc, scope: { kind: "project", projectId: project }, actions: ["project.read"] })).id as string;

  const hook = await ok("POST", `${ACME}/webhooks`, admin.web, { url: HOOK });
  const connection = await ok("POST", `${ACME}/platform-connections`, admin.web, { platform: "github-actions", baseIdentity: "Acme", name: "GitHub", credential: CREDENTIAL });
  const started = await ok("POST", `${ACME}/github-app/registrations`, admin.web, { account: { login: OWNER.login, type: "organization" } });
  const registered = (await ok("POST", `${ACME}/github-app/registrations/complete`, admin.web, { state: started.state, code: `code-${started.id}` })).app;
  const installation = github.install(registered.githubAppId, OWNER);
  const requirement = await ok("POST", `${ACME}/requirements`, admin.web, {
    kind: "tailnet", target: { kind: "tier", tier: "staging" }, selector: { tailnet: "example.ts.net", tags: ["tag:prod"] },
  });

  // beta: a registration GitHub converted and whose attachment waits for an
  // approval. Only an enforcing admin-step-up leaves one pending.
  await tighten("beta", "admin-step-up", "enforce");
  const pending = await ok("POST", `${BETA}/github-app/registrations`, admin.web, { account: { login: OWNER.login, type: "organization" } });
  const asked = await call("POST", `${BETA}/github-app/registrations/complete`, admin.web, { state: pending.state, code: `code-${pending.id}` });
  expect(stepUp(asked).operation).toBe("github_app.register");
  await ok("POST", `/v1/me/approvals/${asked.body.error.details.approval.id}/cancel`, admin.web);
  await ctx.db.query("UPDATE security_controls SET mode = 'off' WHERE organization_id = $1", [beta]);
  const importId = 7_000_001;
  const importPem = github.addApp({ id: importId, slug: `imported-${importId}`, clientId: `Iv1.imported${importId}`, owner: OWNER, permissions: PERMISSIONS });

  return {
    acme,
    beta,
    project,
    web,
    svc,
    ci,
    binding,
    old,
    bob,
    carol,
    role,
    group,
    team,
    grant,
    webhook: { id: hook.id, version: hook.version },
    connection: { id: connection.id, version: connection.version },
    app: { id: registered.id, githubAppId: registered.githubAppId, version: registered.version },
    installation,
    registration: asked.body.error.details.registrationId,
    importable: { id: importId, pem: importPem },
    requirement: { id: requirement.id, version: requirement.version },
  };
}

/** Every route of every operation, alternate routes and request shapes included, in catalogue order. */
function requests(w: World): Request[] {
  const r = (operation: AdminStepUpOperation, label: string, route: string, method: string, path: string, body?: unknown, org: "acme" | "beta" = "acme"): Request => ({
    operation,
    label,
    route: `${route.split(" ")[0]} ${ORG}${route.slice(route.indexOf(" ") + 1)}`,
    org,
    send: (token, approval) => call(method, `/v1/organizations/${org}${path}`, token, body, header(approval)),
  });
  const replacementKey = github.addKey(w.app.githubAppId);
  return [
    r("identity.create", "service with a credential", "POST /identities", "POST", "/identities", { name: "billing", kind: "service", credentialTtlSeconds: 3600 }),
    r("identity.create", "ci, without a credential", "POST /identities", "POST", "/identities", { name: "runner", kind: "ci" }),
    r("credential.issue", "service credential", "POST /identities/:identity/credentials", "POST", `/identities/${w.svc}/credentials`, { name: "job", ttlSeconds: 3600 }),
    r("identity.reactivate", "retired workload", "POST /identities/:identity/reactivate", "POST", `/identities/${w.old}/reactivate`),
    r("oidc_binding.create", "binding", "POST /identities/:identity/oidc-bindings", "POST", `/identities/${w.ci}/oidc-bindings`, { issuer: ISSUER, audience: "varlatch", subject: "repo:acme/web:*" }),
    r("oidc_binding.delete", "binding", "DELETE /identities/:identity/oidc-bindings/:binding", "DELETE", `/identities/${w.ci}/oidc-bindings/${w.binding}`),
    r("grant.create", "to an identity", "POST /grants", "POST", "/grants", { subjectIdentityId: w.svc, scope: { kind: "project", projectId: w.web }, actions: ["project.read"] }),
    r("grant.replace", "wider", "POST /grants/:grant/replace", "POST", `/grants/${w.grant}/replace`, { subjectIdentityId: w.svc, scope: { kind: "project", projectId: w.project }, actions: ["config.value.read", "project.read"] }),
    r("grant.revoke", "grant", "DELETE /grants/:grant", "DELETE", `/grants/${w.grant}`),
    r("role.create", "role", "POST /roles", "POST", "/roles", { name: "writer", actions: ["project.read"] }),
    r("role.update", "role", "PATCH /roles/:role", "PATCH", `/roles/${w.role}`, { expectedVersion: 1, actions: ["config.value.read", "config.value.write", "project.read"] }),
    r("role.delete", "role", "DELETE /roles/:role", "DELETE", `/roles/${w.role}`),
    r("group.create", "group", "POST /groups", "POST", "/groups", { name: "auditors" }),
    r("group.update", "group", "PATCH /groups/:group", "PATCH", `/groups/${w.group}`, { expectedVersion: 1, name: "oncall-2" }),
    r("group.delete", "group", "DELETE /groups/:group", "DELETE", `/groups/${w.group}`),
    r("group.member_add", "a person", "POST /groups/:group/members", "POST", `/groups/${w.group}/members`, { identityId: w.bob.id }),
    r("group.member_remove", "the service", "DELETE /groups/:group/members/:identity", "DELETE", `/groups/${w.group}/members/${w.svc}`),
    r("team.create", "team", "POST /teams", "POST", "/teams", { name: "billing" }),
    r("team.update", "team", "PATCH /teams/:team", "PATCH", `/teams/${w.team}`, { expectedVersion: 1, name: "platform-2" }),
    r("team.delete", "through /teams/", "DELETE /teams/:team", "DELETE", `/teams/${w.team}`),
    r("team.delete", "through /groups/", "DELETE /groups/:group", "DELETE", `/groups/${w.team}`),
    r("team.member_add", "through /teams/", "POST /teams/:team/members", "POST", `/teams/${w.team}/members`, { identityId: w.carol.id }),
    r("team.member_add", "through /groups/", "POST /groups/:group/members", "POST", `/groups/${w.team}/members`, { identityId: w.carol.id }),
    r("team.member_remove", "through /teams/", "DELETE /teams/:team/members/:identity", "DELETE", `/teams/${w.team}/members/${w.bob.id}`),
    r("team.member_remove", "through /groups/", "DELETE /groups/:group/members/:identity", "DELETE", `/groups/${w.team}/members/${w.bob.id}`),
    r("team.project_add", "project", "POST /teams/:team/projects", "POST", `/teams/${w.team}/projects`, { projectId: w.web }),
    r("team.project_remove", "project", "DELETE /teams/:team/projects/:project", "DELETE", `/teams/${w.team}/projects/${w.project}`),
    r("member.invite_admin", "admin invitation", "POST /invitations", "POST", "/invitations", { name: "Dana", role: "admin" }),
    r("member.promote", "Bob", "PATCH /members/:member", "PATCH", `/members/${w.bob.id}`, { role: "admin" }),
    r("member.demote", "Carol", "PATCH /members/:member", "PATCH", `/members/${w.carol.id}`, { role: "member" }),
    r("member.remove", "Bob", "DELETE /members/:member", "DELETE", `/members/${w.bob.id}`),
    r("webhook.create", "webhook", "POST /webhooks", "POST", "/webhooks", { url: HOOK_2 }),
    r("webhook.update", "webhook", "PATCH /webhooks/:webhook", "PATCH", `/webhooks/${w.webhook.id}`, { expectedVersion: w.webhook.version, url: HOOK_2 }),
    r("webhook.delete", "webhook", "DELETE /webhooks/:webhook", "DELETE", `/webhooks/${w.webhook.id}`),
    r("connection.create", "token shape", "POST /platform-connections", "POST", "/platform-connections", { platform: "github-actions", baseIdentity: "Acme-2", name: "GitHub 2", credential: CREDENTIAL_2 }),
    r("connection.create", "App shape", "POST /platform-connections", "POST", "/platform-connections", { credentialKind: "github-app", installationId: w.installation, name: "App" }),
    r("connection.replace_credential", "connection", "POST /platform-connections/:connection/credential", "POST", `/platform-connections/${w.connection.id}/credential`, { credential: CREDENTIAL_2, expectedVersion: w.connection.version }),
    r("connection.delete", "connection", "DELETE /platform-connections/:connection", "DELETE", `/platform-connections/${w.connection.id}`),
    r("github_app.register", "the attachment", "POST /github-app/registrations/:registration/attach", "POST", `/github-app/registrations/${w.registration}/attach`, undefined, "beta"),
    r("github_app.import", "App and key", "POST /github-app/import", "POST", "/github-app/import", { appId: w.importable.id, privateKey: w.importable.pem }, "beta"),
    r("github_app.replace_key", "new key", "POST /github-app/key", "POST", "/github-app/key", { privateKey: replacementKey, expectedVersion: w.app.version }),
    r("github_app.remove", "App", "DELETE /github-app", "DELETE", `/github-app?appId=${encodeURIComponent(w.app.id)}`),
    r("project.delete", "project", "DELETE /projects/:project", "DELETE", "/projects/web"),
    r("organization.delete", "scheduling", "POST /deletion", "POST", "/deletion", { afterDays: 7 }),
    r("secret.export", "one Secret", "POST /projects/:project/environments/:environment/disclosures", "POST", "/projects/api/environments/production/disclosures", { purpose: "export", items: ["DB_PASS"] }),
  ];
}

/** The rows the operations change, counted, to show a refused request changed nothing. */
async function state(): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  // A person's CLI credentials are left out: each request here gets a new one.
  for (const t of WRITTEN_TABLES.split("|")) {
    out[t] = await count(t === "credentials" ? "SELECT count(*)::int AS n FROM credentials WHERE kind <> 'cli'" : `SELECT count(*)::int AS n FROM ${t}`);
  }
  for (const [k, sql] of Object.entries({
    liveGrants: "SELECT count(*)::int AS n FROM grants WHERE revoked_at IS NULL",
    admins: "SELECT count(*)::int AS n FROM org_memberships WHERE role = 'admin' AND removed_at IS NULL",
    liveWebhooks: "SELECT count(*)::int AS n FROM webhooks WHERE revoked_at IS NULL",
    liveConnections: "SELECT count(*)::int AS n FROM platform_connections WHERE revoked_at IS NULL",
    liveApps: "SELECT count(*)::int AS n FROM github_apps WHERE removed_at IS NULL",
    liveProjects: "SELECT count(*)::int AS n FROM projects WHERE deleted_at IS NULL",
    disabled: "SELECT count(*)::int AS n FROM identities WHERE disabled",
    disclosures: "SELECT count(*)::int AS n FROM audit_events WHERE event_type LIKE 'secret.%'",
  })) out[k] = await count(sql);
  return out;
}

/** A machine identity of the Organization holding every action the operations need, made while its controls are off. */
async function robot(org: "acme" | "beta", organizationId: string): Promise<string> {
  const modes = await rows("SELECT control, mode FROM security_controls WHERE organization_id = $1", [organizationId]);
  await ctx.db.query("UPDATE security_controls SET mode = 'off' WHERE organization_id = $1", [organizationId]);
  try {
    const base = `/v1/organizations/${org}`;
    const created = await ok("POST", `${base}/identities`, admin.web, { name: "robot", kind: "service" });
    await ok("POST", `${base}/grants`, admin.web, {
      subjectIdentityId: created.id,
      scope: { kind: "organization" },
      actions: ["organization.manage", "identity.manage", "policy.manage", "project.manage", "config.sync.manage", "secret.reveal", "config.value.read"],
    });
    return created.credential as string;
  } finally {
    for (const m of modes) await ctx.db.query("UPDATE security_controls SET mode = $3 WHERE organization_id = $1 AND control = $2", [organizationId, m.control, m.mode]);
  }
}

beforeEach(async () => {
  const db = await migratedTestDb();
  ctx = { db, rootKek: generateKey(), close: db.close };
  await ensureInstallation(ctx);
  const { identityId } = await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, { adminName: "Admin" });
  github = fakeGitHubApps();
  nextAppId = 5_254_113;
  const syncFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const m = url.pathname.match(/^\/app-manifests\/([^/]+)\/conversions$/);
    if (m && init?.method === "POST") {
      github.calls.push({ method: "POST", path: url.pathname });
      const id = nextAppId++;
      const pem = github.addApp({ id, slug: `varlatch-${id}`, clientId: `Iv23li${id}`, owner: OWNER, permissions: PERMISSIONS });
      return Response.json({ id, slug: `varlatch-${id}`, client_id: `Iv23li${id}`, client_secret: "not-kept", pem, owner: OWNER, permissions: PERMISSIONS }, { status: 201 });
    }
    return github.fetchImpl(input, init);
  }) as typeof fetch;
  app = buildApp(ctx, { publicUrl: PUBLIC_URL, clientAddress: () => "203.0.113.7", syncFetch });
  admin = await person(identityId);
  orgRole.mockClear();
});
afterEach(async () => {
  orgRole.mockImplementation(async (...args) => (await vi.importActual<typeof import("../src/domain/orgs.js")>("../src/domain/orgs.js")).getOrgRole(...args));
  await ctx.close();
});

// ---------------------------------------------------------------------------

describe("the catalogue's 40 operations", () => {
  const operations = CATALOGUE.map((c) => c.operation);

  it("are what the server asks approvals for, what report mode counts, and nothing else", () => {
    expect(operations).toHaveLength(40);
    expect(new Set(operations).size).toBe(40);
    expect(CONTROL_APPROVAL_OPERATIONS["admin-step-up"]).toEqual(operations);
    expect([...ADMIN_STEP_UP_OPERATIONS]).toEqual(operations);
    const others = ["security_control.change", "passkey.remove", "organization.unfreeze", ...CONTROL_APPROVAL_OPERATIONS["requirement-protection"]!];
    expect(APPROVAL_OPERATIONS.filter((op) => !others.includes(op))).toEqual(operations);
    expect(CATALOGUE.filter((c) => c.duringFreeze).map((c) => c.operation)).toEqual(
      operations.filter((op) => OPERATIONS_DURING_FREEZE.has(op)),
    );
  });

  it("are the database's: migration 0051's two constraints name exactly them", async () => {
    const db = await migratedTestDb();
    try {
      const defs = (await db.query(
        `SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
         WHERE conrelid = 'approval_intents'::regclass AND conname IN ('approval_intents_operation_check', 'approval_intents_admin_step_up_organization')`,
      )).rows as { conname: string; def: string }[];
      const named = (conname: string) => [...defs.find((d) => d.conname === conname)!.def.matchAll(/'([a-z_.]+)'/g)].map((m) => m[1]!).sort();
      expect(named("approval_intents_operation_check")).toEqual([...APPROVAL_OPERATIONS].sort());
      expect(named("approval_intents_admin_step_up_organization")).toEqual([...operations].sort());
    } finally {
      await db.close();
    }
  });

  it("are the protocol's: the OpenAPI Approval.operation enum, and every route declares the approval header and STEP_UP_REQUIRED", () => {
    const spec = parseYaml(readFileSync(fileURLToPath(new URL("../../../packages/protocol/openapi.yaml", import.meta.url)), "utf8")) as any;
    expect([...spec.components.schemas.Approval.properties.operation.enum].sort()).toEqual([...APPROVAL_OPERATIONS].sort());
    expect(spec.components.responses.StepUpRequired.description).toContain("Varlatch-Approval");
    const missing: string[] = [];
    const routes = [...new Set([...CATALOGUE.flatMap((c) => c.routes), ...Object.keys(OTHER_PROTECTED)])];
    for (const route of routes) {
      const [method, path] = route.split(" ") as [string, string];
      const op = spec.paths[path.replace(/^\/v1/, "").replace(/:(\w+)/g, "{$1}")]?.[method.toLowerCase()];
      if (!op) {
        missing.push(`${route}: not in the spec`);
        continue;
      }
      const refs = (op.parameters ?? []).map((p: { $ref?: string }) => p.$ref);
      // The callback is never repeated: it answers STEP_UP_REQUIRED for the attachment, which is.
      const callback = path.endsWith("/registrations/complete");
      if (!callback && !refs.includes("#/components/parameters/approvalHeader")) missing.push(`${route}: no approvalHeader`);
      const forbidden = op.responses?.["403"];
      if (!forbidden || (callback ? !/STEP_UP_REQUIRED/.test(forbidden.description) : forbidden.$ref !== "#/components/responses/StepUpRequired")) {
        missing.push(`${route}: no STEP_UP_REQUIRED response`);
      }
    }
    expect(missing).toEqual([]);
    // The passkey removal is the one account operation.
    expect(spec.paths["/me/passkeys/{passkey}"].delete.responses["403"].$ref).toBe("#/components/responses/StepUpRequired");
  });
});

describe("alternate callers", () => {
  it("every write route under /v1/organizations/:org is a catalogue operation's, another control's, or unprotected with a reason", () => {
    const writes = Object.entries(ROUTE_ACCESS).filter(([, how]) => how !== "read" && how !== "stream").map(([route]) => route);
    const protectedRoutes = [...new Set(CATALOGUE.flatMap((c) => c.routes))];
    const classified = [...protectedRoutes, ...Object.keys(OTHER_PROTECTED), ...Object.keys(UNPROTECTED_WRITES)];
    expect(new Set(classified).size, "a route classified twice").toBe(classified.length);
    expect([...writes].sort()).toEqual([...classified].sort());
  });

  it("every writer in src/ of what the operations change is classified", () => {
    const write = new RegExp(`\\b(?:INSERT INTO|UPDATE|DELETE FROM) (?:${WRITTEN_TABLES})\\b`);
    expect(writersIn(srcFiles(), write)).toEqual(Object.keys(WRITERS).sort());
  });

  it("every caller of a protected domain function is known, by its route or function (helpers resolved to their routes)", () => {
    const sources = srcFiles();
    expect(unlabelledRegistrations(sources)).toEqual([]);
    const expected = Object.fromEntries(Object.entries(CALLERS).map(([fn, list]) => [fn, [...list].sort()]));
    expect(callersIn(sources, Object.keys(CALLERS))).toEqual(expected);
  });

  describe("would fail on an added caller (in-memory copies of app.ts)", () => {
    const RENAME = 'app.patch("/v1/organizations/:org/identities/:identity", async (c) => {';
    const rename = `http/app.ts PATCH ${ORG}/identities/:identity`;
    const fns = Object.keys(CALLERS);
    /** The inventory of the real sources, and of a copy of app.ts edited by `edit`. */
    function tamper(edit: (text: string) => string) {
      const sources = srcFiles();
      const appTs = sources.find((s) => s.file === "http/app.ts")!;
      const edited = edit(appTs.text);
      expect(edited, "the edit applies").not.toBe(appTs.text);
      return { before: callersIn(sources, fns), after: callersIn(sources.map((s) => (s === appTs ? { ...s, text: edited } : s)), fns) };
    }
    const intoRename = (code: string) => (text: string) => {
      expect(text).toContain(RENAME);
      return text.replace(RENAME, `${RENAME}\n${code}`);
    };

    it("a direct call to the credential primitive and to a protected function in an exempt route; a file-level view would not see it", () => {
      const { before, after } = tamper(intoRename('    await issueCredential(ctx.db, { identityId: "x", kind: "service" });\n    await createRole(ctx, gate, org.id, body, {});'));
      expect(before.issueCredential).not.toContain(rename);
      expect(after.issueCredential).toContain(rename);
      expect(after.createRole).toContain(rename);
      const byFile = (m: Record<string, string[]>) =>
        Object.fromEntries(Object.entries(m).map(([fn, list]) => [fn, [...new Set(list.map((c) => (c.startsWith("http/app.ts ") ? "http/app.ts" : c)))].sort()]));
      expect(byFile(after)).toEqual(byFile(before));
    });

    it("a multiline helper declared just before another route's helper, then called from an exempt route", () => {
      const anchor = "  const passkeyOwner = (c: Context) => {";
      const { before, after } = tamper((text) => {
        expect(text).toContain(anchor);
        const helper = '  const mintForIdentity =\n    async (identityId: string) => {\n      return issueCredential(ctx.db, { identityId, kind: "service" });\n    };\n';
        return intoRename("    await mintForIdentity(\"x\");")(text.replace(anchor, `${helper}${anchor}`));
      });
      expect(after.issueCredential).toContain(`${rename} via mintForIdentity`);
      expect(after.issueCredential.filter((e) => !before.issueCredential.includes(e))).toEqual([`${rename} via mintForIdentity`]);
    });

    it("a helper declared inside buildApp between two routes, then called from an exempt route", () => {
      const anchor = '  app.post("/v1/organizations/:org/identities/:identity/retire", async (c) => {';
      const { after } = tamper((text) => {
        expect(text).toContain(anchor);
        const helper = "  function quietRole(c: Context) {\n    return createRole(ctx, c.get(\"gate\"), \"org\", { name: \"x\", actions: [] }, {});\n  }\n";
        return intoRename("    await quietRole(c);")(text.replace(anchor, `${helper}${anchor}`));
      });
      expect(after.createRole).toContain(`${rename} via quietRole`);
    });

    it("a call split over several lines", () => {
      const { after } = tamper(intoRename('    await issueCredential\n      (\n        ctx.db,\n        { identityId: "x", kind: "service" },\n      );'));
      expect(after.issueCredential).toContain(rename);
    });

    it("fails closed: a helper nobody calls, and a registration whose path is not a literal", () => {
      const anchor = "  const passkeyOwner = (c: Context) => {";
      const { after } = tamper((text) =>
        text.replace(anchor, `  const unused = async () => issueCredential(ctx.db, { identityId: "x", kind: "service" });\n  app.post(somePath, async (c) => createRole(ctx, gate, "o", {}, {}));\n${anchor}`));
      expect(after.issueCredential).toContain("http/app.ts unused (no caller)");
      expect(after.createRole).toContain("http/app.ts ?? a route registration whose path is not a string literal");
    });
  });
});

describe("admin-step-up through the API", () => {
  it("is unlocked: advertised in /v1/meta, offered with enforce, tightening to enforce needs no approval, loosening needs one", async () => {
    await ok("POST", "/v1/organizations", admin.web, { name: "Acme", slug: "acme" });
    const meta = (await call("GET", "/v1/meta", admin.web)).body.capabilities as string[];
    expect(meta).toContain("security.enforce.admin-step-up");
    expect(ENFORCEABLE_CONTROLS.has("admin-step-up")).toBe(true);
    expect(CAPABILITIES.filter((c) => c.startsWith("security.enforce."))).toEqual([...ENFORCEABLE_CONTROLS].map(enforceCapability));
    // A new installation and a new Organization: every control off.
    const list = await ok("GET", controlsPath("acme"), admin.web);
    expect(list.items.map((i: { control: string; mode: string; version: number }) => [i.control, i.mode, i.version])).toEqual([
      ["requirement-protection", "off", 0], ["admin-step-up", "off", 0], ["passkey-verification", "off", 0], ["credential-lifetime", "off", 0],
    ]);
    expect(list.items.find((i: { control: string }) => i.control === "admin-step-up").availableModes).toEqual(["off", "report", "enforce"]);
    expect(list.availableModes).toEqual(["off", "report"]);

    // off -> report -> enforce: tightening, no approval; a machine never.
    const changed = await tighten("acme", "admin-step-up", "report");
    expect(changed).toMatchObject({ changed: true, loosened: false, control: { mode: "report", version: 1 } });
    const robotToken = await robot("acme", (await rows("SELECT id FROM organizations WHERE slug = 'acme'"))[0].id);
    const byMachine = await call("PATCH", `${controlsPath("acme")}/admin-step-up`, robotToken, { mode: "enforce", expectedVersion: 1 });
    expect(byMachine.status).toBe(403);
    expect((await tighten("acme", "admin-step-up", "enforce")).control).toMatchObject({ mode: "enforce", version: 2 });
    const [event] = (await rows("SELECT metadata FROM audit_events WHERE event_type = 'security_control.changed' ORDER BY event_order DESC LIMIT 1")).map((r) => parse(r.metadata)!);
    expect(event).toMatchObject({ control: "admin-step-up", fromMode: "report", toMode: "enforce", loosened: false, approvalId: null });

    // enforce -> off loosens: the requester's approval of exactly that change.
    const back = await call("PATCH", `${controlsPath("acme")}/admin-step-up`, admin.web, { mode: "off", expectedVersion: 2 });
    const asked = stepUp(back);
    expect(asked.operation).toBe("security_control.change");
    await approve(admin, asked.id);
    const done = await call("PATCH", `${controlsPath("acme")}/admin-step-up`, admin.web, { mode: "off", expectedVersion: 2 }, header(asked.id));
    expect(done.status, JSON.stringify(done.body)).toBe(200);
    expect(done.body).toMatchObject({ loosened: true, control: { mode: "off", version: 3 } });
  });
});

// ---------------------------------------------------------------------------

describe("under enforce, across all 40 operations", () => {
  let w: World;
  beforeEach(async () => {
    w = await world();
    await tighten("acme", "admin-step-up", "enforce");
    await tighten("beta", "admin-step-up", "enforce");
  });

  it("every route of every operation asks the requester for an approval of exactly that operation, and changes nothing", async () => {
    const all = requests(w);
    expect(new Set(all.map((q) => q.operation))).toEqual(new Set(CATALOGUE.map((c) => c.operation)));
    // Every catalogue route is exercised (the callback's request: world() and the machine test).
    const sent = new Set(all.map((q) => `${q.operation} ${q.route}`));
    for (const c of CATALOGUE) for (const route of c.routes) if (!route.endsWith("/complete")) expect(sent, `${c.operation} ${route}`).toContain(`${c.operation} ${route}`);

    const before = await state();
    const asked: { id: string; operation: string }[] = [];
    for (const [i, q] of all.entries()) {
      // Two admins share the 30 intents a person may create per 10 minutes.
      const by = q.org === "beta" || i % 2 === 0 ? admin : w.carol;
      const n = await intents();
      const approval = stepUp(await q.send(await by.cli()));
      expect(approval.operation, q.label).toBe(q.operation);
      expect(approval.organization?.id, q.label).toBe(q.org === "acme" ? w.acme : w.beta);
      expect(await intents(), q.label).toBe(n + 1);
      asked.push({ id: approval.id, operation: q.operation });
    }
    expect(await state()).toEqual(before);

    // The operator reset closes them, and only for the controls it names.
    const others = await resetControls(ctx, { organization: "acme", controls: ["requirement-protection", "passkey-verification", "credential-lifetime"] });
    expect(others.approvalsClosed).toBe(0);
    const acme = await resetControls(ctx, { organization: "acme", controls: ["admin-step-up"] });
    const beta = await resetControls(ctx, { organization: "beta", controls: "all" });
    expect(acme.approvalsClosed + beta.approvalsClosed).toBe(asked.length);
    expect(beta.approvalsClosed).toBe(all.filter((q) => q.org === "beta").length);
    const closed = await rows("SELECT operation, close_reason FROM approval_intents WHERE id = ANY($1)", [asked.map((a) => a.id)]);
    expect(closed.every((r) => r.close_reason === "reset")).toBe(true);
    expect(new Set(closed.map((r) => r.operation))).toEqual(new Set(CATALOGUE.map((c) => c.operation)));
    expect(await state()).toEqual(before);
  }, 180_000);

  it("a machine credential holding the actions is refused on every route, without an intent", async () => {
    const machines = { acme: await robot("acme", w.acme), beta: await robot("beta", w.beta) };
    const started = await ok("POST", `${BETA}/github-app/registrations`, admin.web, { account: { login: OWNER.login, type: "organization" } });
    const before = await state();
    const n = await intents();
    const answers: string[] = [];
    for (const q of requests(w)) {
      const res = await q.send(machines[q.org]);
      answers.push(`${q.operation} (${q.label}): ${res.status} ${res.body?.error?.code} ${res.body?.error?.details?.reason ?? ""}`.trim());
    }
    // The callback too: refused before GitHub's one-use code is spent.
    const conversions = github.calls.filter((c) => c.path.startsWith("/app-manifests/")).length;
    const callback = await call("POST", `${BETA}/github-app/registrations/complete`, machines.beta, { state: started.state, code: "code-machine" });
    answers.push(`github_app.register (the callback): ${callback.status} ${callback.body?.error?.code} ${callback.body?.error?.details?.reason ?? ""}`.trim());
    expect(github.calls.filter((c) => c.path.startsWith("/app-manifests/")).length).toBe(conversions);

    expect(await intents()).toBe(n);
    expect(await state()).toEqual(before);
    // Each one: PERMISSION_DENIED for the machine credential (Decision 5),
    // except where the operation is an Organization Admin's alone and its
    // own check refuses any machine first, as it did before the control.
    const ADMIN_ONLY: Partial<Record<AdminStepUpOperation, string>> = {
      "member.promote": "403 PERMISSION_DENIED",
      "member.demote": "403 PERMISSION_DENIED",
      "member.remove": "403 PERMISSION_DENIED",
      "organization.delete": "403 PERMISSION_DENIED",
    };
    // A pending registration is its starter's alone (another's is not
    // found), and a machine's own is never converted under enforce: the
    // callback refuses it first (below).
    const OTHERS: Partial<Record<string, string>> = { "github_app.register (the attachment)": "404 RESOURCE_NOT_FOUND" };
    const expected = [...requests(w).map((q) => `${q.operation} (${q.label}): ${OTHERS[`${q.operation} (${q.label})`] ?? ADMIN_ONLY[q.operation] ?? "403 PERMISSION_DENIED machine-credential"}`),
      "github_app.register (the callback): 403 PERMISSION_DENIED machine-credential"];
    expect(answers).toEqual(expected);
  }, 180_000);

  it("while the Organization is frozen, an intent is created only for an operation in OPERATIONS_DURING_FREEZE", async () => {
    for (const org of ["acme", "beta"] as const) expect((await call("POST", `/v1/organizations/${org}/incident-freeze`, admin.web, { reason: "A CI token leaked" })).status).toBe(201);
    const before = await state();
    const wrong: string[] = [];
    for (const q of requests(w)) {
      const n = await intents();
      const res = await q.send(await admin.cli());
      const during = CATALOGUE.find((c) => c.operation === q.operation)!.duringFreeze;
      const answer = `${res.status} ${res.body?.error?.code}`;
      if (during ? answer !== "403 STEP_UP_REQUIRED" : answer !== "409 ORGANIZATION_FROZEN") wrong.push(`${q.operation} (${q.label}): ${answer}`);
      if ((await intents()) !== n + (during ? 1 : 0)) wrong.push(`${q.operation} (${q.label}): intents`);
    }
    expect(wrong).toEqual([]);
    expect(await state()).toEqual(before);
  }, 180_000);
});

// ---------------------------------------------------------------------------

/**
 * Combinations of controls. The four controls meet in one place,
 * prepareProtectedOperation's decision (domain/protected.ts), each at its
 * own step: credential-lifetime's refusal, the existence preflight, the
 * passkey-verification checkpoint, then the approval (admin-step-up and
 * requirement-protection, whose operations are disjoint). So the set is:
 * admin-step-up at enforce with each other control at off, report and
 * enforce, plus everything at enforce together; a control acting on all 40
 * operations (passkey-verification) is walked across all 40, the others on
 * the operations they act on. The order of refusals, documented in
 * docs/reference/security-controls.md:
 *
 *   1. the route's authentication, authorization and existence checks
 *      (with the incident freeze at the Organization's entry);
 *   2. validation of the request;
 *   3. a deleting or frozen Organization (step 1 of the lock order);
 *   4. credential-lifetime's maximum, for identity.create and credential.issue;
 *   5. the operation's not-found (its preflight);
 *   6. passkey-verification;
 *   7. the operation's refusals that do not depend on an approval
 *      (amendment A), such as the last-admin rule;
 *   8. a machine credential, refused (PERMISSION_DENIED, machine-credential);
 *   9. STEP_UP_REQUIRED, with the intent, or the approval consumed.
 *
 * A request refused at any step before 9 gets no intent.
 */
describe("combinations of controls", () => {
  let w: World;
  beforeEach(async () => {
    w = await world();
    await tighten("acme", "admin-step-up", "enforce");
    await tighten("beta", "admin-step-up", "enforce");
  });

  const pvDenials = () => count("SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'authorization.denied' AND metadata::jsonb->>'reason' = 'passkey_verification_required'");

  it("passkey-verification at enforce: a sign-in it refuses is refused on all 40 operations before any intent, once audited each; one it accepts is asked for approvals", async () => {
    const verified = await signIn(admin.id, true);
    for (const org of ["acme", "beta"] as const) await tighten(org, "passkey-verification", "enforce", undefined, verified);
    const before = await state();
    const n = await intents();
    const denials = await pvDenials();
    const wrong: string[] = [];
    const all = requests(w);
    for (const q of all) {
      const res = await q.send(await admin.cli());
      if (res.body?.error?.code !== "PASSKEY_VERIFICATION_REQUIRED") wrong.push(`${q.operation} (${q.label}): ${res.status} ${res.body?.error?.code}`);
    }
    expect(wrong).toEqual([]);
    expect(await intents()).toBe(n);
    expect(await pvDenials()).toBe(denials + all.length);
    expect(await state()).toEqual(before);
    // An accepted sign-in: one operation of each group asks.
    for (const q of all.filter((q) => ["identity.create", "grant.create", "member.invite_admin", "webhook.create", "github_app.import", "secret.export"].includes(q.operation))) {
      expect(stepUp(await q.send(await signIn(admin.id, true))).operation).toBe(q.operation);
    }
    // A machine is not affected by passkey-verification: refused by admin-step-up.
    const machine = await robot("acme", w.acme);
    expect((await all[0]!.send(machine)).body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "machine-credential" } });
  }, 180_000);

  it("passkey-verification at report: nothing changes for admin-step-up, and a refused request counts nothing", async () => {
    const verified = await signIn(admin.id, true);
    await tighten("acme", "passkey-verification", "report", undefined, verified);
    const grant = requests(w).find((q) => q.operation === "grant.create")!;
    const asked = stepUp(await grant.send(await admin.cli()));
    expect(asked.operation).toBe("grant.create");
    expect(await count("SELECT count(*)::int AS n FROM security_control_counters WHERE control = 'passkey-verification'")).toBe(0);
  });

  it("credential-lifetime at off, report and enforce: what the approval binds, and its refusal first", async () => {
    const issue = requests(w).find((q) => q.operation === "credential.issue")!;
    const noTtl = (token: string, approval?: string) => call("POST", `${ACME}/identities/${w.svc}/credentials`, token, { name: "job" }, header(approval));
    const tooLong = (token: string) => call("POST", `${ACME}/identities/${w.svc}/credentials`, token, { name: "job", ttlSeconds: 86_401 });
    // off: the requested TTL, or none.
    expect(stepUp(await noTtl(await admin.cli())).summary.title).toContain("never expiring (none was requested)");
    // report: changes nothing.
    await tighten("acme", "credential-lifetime", "report", { defaultTtlSeconds: 3600, maxTtlSeconds: 86_400 });
    expect(stepUp(await noTtl(await admin.cli())).summary.title).toContain("never expiring (none was requested)");
    expect(stepUp(await tooLong(await admin.cli())).summary.title).toContain("(as requested)");
    // enforce: an over-long TTL is refused before any intent, for a person and a machine alike; none gets the default.
    await tighten("acme", "credential-lifetime", "enforce", { defaultTtlSeconds: 3600, maxTtlSeconds: 86_400 });
    const machine = await robot("acme", w.acme);
    const n = await intents();
    expect((await tooLong(await admin.cli())).body.error.code).toBe("CREDENTIAL_LIFETIME_EXCEEDED");
    expect((await tooLong(machine)).body.error.code).toBe("CREDENTIAL_LIFETIME_EXCEEDED");
    expect(await intents()).toBe(n);
    expect((await noTtl(machine)).body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "machine-credential" } });
    const asked = stepUp(await noTtl(await admin.cli()));
    expect(asked.summary.title).toContain("expiring after 1 hour (the organization's default, since none was requested)");
    expect(stepUp(await issue.send(await admin.cli())).summary.title).toContain("expiring after 1 hour (as requested)");
    // One approval covers both controls.
    const cli = await admin.cli();
    const again = stepUp(await noTtl(cli));
    await approve(admin, again.id);
    const issued = await noTtl(cli, again.id);
    expect(issued.status, JSON.stringify(issued.body)).toBe(201);
    expect(Date.parse(issued.body.expiresAt) - Date.now()).toBeLessThanOrEqual(3600_000);
  }, 60_000);

  it("requirement-protection at enforce: its operations and admin-step-up's are disjoint, and a reset closes only its own", async () => {
    await tighten("acme", "requirement-protection", "enforce");
    const revoke = (token: string) => call("DELETE", `${ACME}/requirements/${w.requirement.id}`, token);
    const grant = requests(w).find((q) => q.operation === "grant.create")!;
    const r = stepUp(await revoke(await admin.cli()));
    const g = stepUp(await grant.send(await admin.cli()));
    expect([r.operation, g.operation]).toEqual(["requirement.revoke", "grant.create"]);
    const machine = await robot("acme", w.acme);
    expect((await revoke(machine)).body.error).toMatchObject({ code: "PERMISSION_DENIED", details: { reason: "machine-credential" } });
    const reason = async (id: string) => (await rows("SELECT close_reason FROM approval_intents WHERE id = $1", [id]))[0].close_reason;
    expect((await resetControls(ctx, { organization: "acme", controls: ["admin-step-up"] })).approvalsClosed).toBe(1);
    expect([await reason(r.id), await reason(g.id)]).toEqual([null, "reset"]);
    expect((await resetControls(ctx, { organization: "acme", controls: ["requirement-protection"] })).approvalsClosed).toBe(1);
    expect(await reason(r.id)).toBe("reset");
  });

  it("admin-step-up at report with requirement-protection at enforce: the first counts, the second asks", async () => {
    await ctx.db.query("UPDATE security_controls SET mode = 'report' WHERE organization_id = $1 AND control = 'admin-step-up'", [w.acme]);
    await tighten("acme", "requirement-protection", "enforce");
    const grant = requests(w).find((q) => q.operation === "grant.create")!;
    expect((await grant.send(await admin.cli())).status).toBe(201);
    expect(await count("SELECT count(*)::int AS n FROM security_control_counters WHERE control = 'admin-step-up' AND operation = 'grant.create'")).toBe(1);
    expect(stepUp(await call("DELETE", `${ACME}/requirements/${w.requirement.id}`, await admin.cli())).operation).toBe("requirement.revoke");
  });

  it("every control at enforce: the refusals come in the documented order, and only the last step creates an intent", async () => {
    const verified = await signIn(admin.id, true);
    await tighten("acme", "requirement-protection", "enforce", undefined, verified);
    await tighten("acme", "credential-lifetime", "enforce", { defaultTtlSeconds: 3600, maxTtlSeconds: 86_400 }, verified);
    await tighten("acme", "passkey-verification", "enforce", undefined, verified);
    const machine = await robot("acme", w.acme);
    const create = (token: string, body: Record<string, unknown>, approval?: string) => call("POST", `${ACME}/identities`, token, body, header(approval));
    const n = await intents();
    const answers: string[] = [];
    const record = (label: string, res: Answer) => answers.push(`${label}: ${res.body?.error?.code ?? res.status}${res.body?.error?.details?.reason ? ` ${res.body.error.details.reason}` : ""}`);
    // 1. A member without identity.manage: authorization first, whatever the sign-in.
    record("member, unverified", await create(await w.bob.cli(), { name: "x", kind: "service", credentialTtlSeconds: 86_401 }));
    // 2. Validation.
    record("admin, unverified, invalid", await create(await admin.cli(), { name: "", kind: "service", credentialTtlSeconds: 86_401 }));
    // 4. credential-lifetime's maximum, before passkey-verification.
    record("admin, unverified, too long", await create(await admin.cli(), { name: "x", kind: "service", credentialTtlSeconds: 86_401 }));
    // 6. passkey-verification.
    record("admin, unverified", await create(await admin.cli(), { name: "x", kind: "service" }));
    // 8. A machine: not affected by passkey-verification, refused by admin-step-up.
    record("machine, too long", await create(machine, { name: "x", kind: "service", credentialTtlSeconds: 86_401 }));
    record("machine", await create(machine, { name: "x", kind: "service" }));
    expect(await intents()).toBe(n);
    // 9. An accepted sign-in: the approval, binding the default lifetime.
    const asked = stepUp(await create(verified, { name: "x", kind: "service" }));
    record("admin, verified", { status: 403, body: { error: { code: "STEP_UP_REQUIRED" } } });
    expect(asked.summary.title).toContain("(the organization's default, since none was requested)");
    expect(answers).toEqual([
      "member, unverified: PERMISSION_DENIED",
      "admin, unverified, invalid: VALIDATION_FAILED",
      "admin, unverified, too long: CREDENTIAL_LIFETIME_EXCEEDED",
      "admin, unverified: PASSKEY_VERIFICATION_REQUIRED no-evidence",
      "machine, too long: CREDENTIAL_LIFETIME_EXCEEDED",
      "machine: PERMISSION_DENIED machine-credential",
      "admin, verified: STEP_UP_REQUIRED",
    ]);
    await approve(admin, asked.id);
    const made = await create(verified, { name: "x", kind: "service" }, asked.id);
    expect(made.status, JSON.stringify(made.body)).toBe(201);
    // 3. A frozen Organization refuses before everything after it.
    expect((await call("POST", `${ACME}/incident-freeze`, verified, { reason: "drill" })).status).toBe(201);
    const frozen = await create(await admin.cli(), { name: "y", kind: "service", credentialTtlSeconds: 86_401 });
    expect(frozen.body.error.code).toBe("ORGANIZATION_FROZEN");
  }, 60_000);
});

/**
 * admin-step-up's mode flipping between an export's snapshot (phase 1) and
 * its phase 2 (amendment C), in both directions. The snapshot decides
 * which path the export takes; phase 2, when there is one, decides what the
 * mode it reads under the Organization lock asks for.
 */
describe("an export while admin-step-up's mode changes after its snapshot", () => {
  let w: World;
  beforeEach(async () => {
    w = await world();
  });

  const exportOne = (approval?: string) =>
    call("POST", `${ACME}/projects/api/environments/production/disclosures`, admin.web, { purpose: "export", items: ["DB_PASS"] }, header(approval));

  /**
   * Runs `request`, pausing it right after the COMMIT of its retrieval
   * snapshot while `change` commits (PGlite has one connection: the paused
   * request holds no transaction then). Returns the answer and every
   * statement the request ran after its snapshot.
   */
  async function flipAfterSnapshot(request: () => Promise<Answer>, change: () => Promise<unknown>) {
    const original = ctx.db.query.bind(ctx.db);
    let reached!: () => void;
    const reachedP = new Promise<void>((r) => (reached = r));
    let release!: () => void;
    const releaseP = new Promise<void>((r) => (release = r));
    let phase: "before" | "snapshot" | "paused" | "after" = "before";
    const after: string[] = [];
    const tap = (async (text: string, params?: unknown[]) => {
      if (phase === "before" && text.startsWith("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")) phase = "snapshot";
      else if (phase === "after") after.push(text.replace(/\s+/g, " ").trim());
      const res = await original(text, params);
      if (phase === "snapshot" && text.trim() === "COMMIT") {
        phase = "paused";
        ctx.db.query = original;
        reached();
        await releaseP;
        ctx.db.query = tap;
        phase = "after";
      }
      return res;
    }) as typeof ctx.db.query;
    ctx.db.query = tap;
    const running = request();
    try {
      await Promise.race([reachedP, running]);
      expect(phase, "the request reached its snapshot's end").toBe("paused");
      await change();
    } finally {
      release();
    }
    const res = await running;
    ctx.db.query = original;
    return { res, after };
  }

  const disclosed = async () =>
    (await rows("SELECT decision, actor_identity_id, organization_id, action, resource, authz, metadata FROM audit_events WHERE event_type = 'secret.disclosed' ORDER BY event_order"))
      .map((r) => ({ ...r, resource: parse(r.resource), authz: parse(r.authz), metadata: parse(r.metadata) }));
  // Phase 2's own statements (exportGuard, prepareProtectedOperation): the
  // Organization with its deletion check (lockLiveScope's step 1), the
  // controls read under it, then the requester (step 2). The off path's
  // audit transaction locks the Organization and the person too, for the
  // exposure record, but never these two first statements.
  const PHASE2_ORG_LOCK = /^SELECT deleted_at FROM organizations WHERE id = \$1 FOR KEY SHARE/;
  const PHASE2_CONTROLS = /^SELECT control, mode, version, config FROM security_controls/;
  const PERSON_LOCK = /^SELECT id FROM identities WHERE id = ANY\(\$1\) ORDER BY id FOR (KEY SHARE|UPDATE)/;
  const exportCounts = () => count("SELECT coalesce(sum(count), 0)::int AS n FROM security_control_counters WHERE control = 'admin-step-up' AND operation = 'secret.export'");

  it("off at the snapshot, enforce committed before phase 2: completes on the off path, with no approval, no extra lock and main's audit", async () => {
    // The off path as it is with nothing changing: its statements and audit.
    const plain = await flipAfterSnapshot(() => exportOne(), async () => undefined);
    expect(plain.res.status, JSON.stringify(plain.res.body)).toBe(200);
    const flipped = await flipAfterSnapshot(() => exportOne(), () => tighten("acme", "admin-step-up", "enforce"));
    expect(flipped.res.status, JSON.stringify(flipped.res.body)).toBe(200);
    expect((await controlOf("acme", "admin-step-up")).mode).toBe("enforce");
    expect(await intents()).toBe(1); // world()'s beta registration only
    expect(await exportCounts()).toBe(0);
    // The same statements after the snapshot: no phase 2, no lock it would take.
    expect(flipped.after.length).toBeGreaterThan(0);
    expect(flipped.after).toEqual(plain.after);
    expect(flipped.after.filter((t) => PHASE2_ORG_LOCK.test(t) || PHASE2_CONTROLS.test(t))).toEqual([]);
    // The same audit, without an approval.
    const [first, second] = await disclosed();
    expect(second).toEqual(first);
    expect(second!.metadata).not.toHaveProperty("approvalId");
    // The next export reads enforce at its snapshot and asks.
    expect(stepUp(await exportOne()).operation).toBe("secret.export");
  });

  for (const to of ["off", "report"] as const) {
    it(`enforce at the snapshot, ${to} before phase 2: phase 2 does what ${to} does, needs no approval, and still holds the Organization and the requester`, async () => {
      await tighten("acme", "admin-step-up", "enforce");
      const baseline = await flipAfterSnapshot(() => exportOne(), async () => undefined);
      // At enforce throughout: asked for an approval.
      expect(stepUp(baseline.res).operation).toBe("secret.export");
      const n = await intents();
      const flipped = await flipAfterSnapshot(() => exportOne(), async () => {
        if (to === "off") {
          await resetControls(ctx, { organization: "acme", controls: ["admin-step-up"] });
        } else {
          const path = `${controlsPath("acme")}/admin-step-up`;
          const body = { mode: "report", expectedVersion: (await controlOf("acme", "admin-step-up")).version };
          const asked = stepUp(await call("PATCH", path, admin.web, body));
          await approve(admin, asked.id);
          expect((await call("PATCH", path, admin.web, body, header(asked.id))).status).toBe(200);
        }
      });
      expect(flipped.res.status, JSON.stringify(flipped.res.body)).toBe(200);
      expect((await controlOf("acme", "admin-step-up")).mode).toBe(to);
      // No approval asked for or used: the loosening's own intent aside.
      expect(await intents()).toBe(n + (to === "report" ? 1 : 0));
      const [event] = (await disclosed()).slice(-1);
      expect(event!.metadata).not.toHaveProperty("approvalId");
      // report counts the export once; off counts nothing.
      expect(await exportCounts()).toBe(to === "report" ? 1 : 0);
      // Phase 2 ran: the Organization, the mode read under it, then the
      // requester, before anything is written (counter, exposure, audit).
      const at = (re: RegExp) => flipped.after.findIndex((t) => re.test(t));
      const firstWrite = at(/^INSERT /);
      const order = [at(PHASE2_ORG_LOCK), at(PHASE2_CONTROLS), at(PERSON_LOCK), firstWrite];
      expect(order.every((i) => i >= 0), flipped.after.join("\n")).toBe(true);
      expect([...order].sort((x, y) => x - y), flipped.after.join("\n")).toEqual(order);
      // No approval consumed: the requester is held FOR KEY SHARE, not FOR UPDATE.
      expect(flipped.after[at(PERSON_LOCK)]).toMatch(/FOR KEY SHARE/);
    });
  }
});

// ---------------------------------------------------------------------------

/**
 * Follow-up (a): a protected operation rechecks its requester's action in
 * its transaction once it consumed an approval. A denial there rolls the
 * transaction back; it is audited after the rollback, once, as an ordinary
 * denial is. The race: the person loses the action after the route's own
 * authorization and before the recheck (getOrgRole answers "member" inside
 * the operation's transaction).
 */
describe("a denial found by the recheck in the transaction", () => {
  let w: World;
  beforeEach(async () => {
    w = await world();
  });

  /** Runs `send` with Carol an admin outside the operation's transaction and a member inside it. */
  async function demotedInTransaction(send: () => Promise<Answer>) {
    const actual = await vi.importActual<typeof import("../src/domain/orgs.js")>("../src/domain/orgs.js");
    const original = ctx.db.query.bind(ctx.db);
    let inside = false;
    let consumed = false;
    ctx.db.query = (async (text: string, params?: unknown[]) => {
      if (text.trim() === "BEGIN") inside = true;
      if (/UPDATE approval_intents SET consumed_at/.test(text)) consumed = true;
      const res = await original(text, params);
      if (text.trim() === "ROLLBACK" || text.trim() === "COMMIT") inside = false;
      return res;
    }) as typeof ctx.db.query;
    orgRole.mockImplementation(async (c, organizationId, identityId) =>
      inside && identityId === w.carol.id ? "member" : actual.getOrgRole(c, organizationId, identityId));
    try {
      return { res: await send(), consumed };
    } finally {
      ctx.db.query = original;
      orgRole.mockImplementation(actual.getOrgRole);
    }
  }

  const denials = async (actor: string) =>
    (await rows(
      `SELECT event_type, decision, actor_identity_id, credential_id, organization_id, action, resource, authz, metadata
       FROM audit_events WHERE event_type = 'authorization.denied' AND actor_identity_id = $1 ORDER BY event_order`,
      [actor],
    )).map((r) => ({ ...r, resource: parse(r.resource), authz: parse(r.authz), metadata: parse(r.metadata), credential_id: typeof r.credential_id }));

  const CASES: { operation: AdminStepUpOperation; action: string; control?: "requirement-protection" }[] = [
    { operation: "identity.create", action: "identity.manage" },
    { operation: "grant.create", action: "policy.manage" },
    { operation: "webhook.create", action: "organization.manage" },
    { operation: "project.delete", action: "project.manage" },
    { operation: "secret.export", action: "secret.reveal" },
  ];

  it("is audited once after the rollback, exactly as main audits an ordinary denial; the approval stays usable", async () => {
    await tighten("acme", "admin-step-up", "enforce");
    for (const { operation, action } of CASES) {
      const q = requests(w).find((r) => r.operation === operation)!;
      const cli = await w.carol.cli();
      const asked = stepUp(await q.send(cli));
      await approve(w.carol, asked.id);
      const before = (await denials(w.carol.id)).length;
      const { res, consumed } = await demotedInTransaction(() => q.send(cli, asked.id));
      expect(consumed, operation).toBe(true);
      expect(res.status, `${operation}: ${JSON.stringify(res.body)}`).toBe(403);
      expect(res.body.error.code, operation).toBe("PERMISSION_DENIED");
      const after = await denials(w.carol.id);
      expect(after.length, operation).toBe(before + 1);
      const deferred = after.at(-1)!;
      expect(deferred, operation).toMatchObject({ decision: "deny", organization_id: w.acme, action });
      // The approval rolled back with the transaction: still usable.
      expect((await rows("SELECT consumed_at FROM approval_intents WHERE id = $1", [asked.id]))[0].consumed_at, operation).toBeNull();

      // The ordinary denial of the same request, by the route's own check, for comparison.
      await ctx.db.query("UPDATE org_memberships SET role = 'member' WHERE organization_id = $1 AND identity_id = $2", [w.acme, w.carol.id]);
      const ordinary = await q.send(cli, asked.id);
      await ctx.db.query("UPDATE org_memberships SET role = 'admin' WHERE organization_id = $1 AND identity_id = $2", [w.acme, w.carol.id]);
      expect(ordinary.body.error.code, operation).toBe("PERMISSION_DENIED");
      const plain = (await denials(w.carol.id)).at(-1)!;
      expect(deferred, operation).toEqual(plain);
    }
  }, 120_000);

  it("with every control off, the same race changes nothing: the request succeeds as on main, with no denial", async () => {
    const before = (await denials(w.carol.id)).length;
    for (const { operation } of CASES) {
      const q = requests(w).find((r) => r.operation === operation)!;
      const { res, consumed } = await demotedInTransaction(async () => q.send(await w.carol.cli()));
      expect(consumed, operation).toBe(false);
      expect(res.status, `${operation}: ${JSON.stringify(res.body)}`).toBeLessThan(300);
    }
    expect((await denials(w.carol.id)).length).toBe(before);
    expect(await intents()).toBe(1);
  }, 120_000);
});
