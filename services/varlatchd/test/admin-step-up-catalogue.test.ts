// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
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
import { buildGraph, declaredSymbol, functionLabels, reach, srcPath, unlabelledRegistrations, writers, type Graph, type RootClass } from "./helpers/caller-graph.js";
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
 * The roots of the caller graph (test/helpers/caller-graph.ts) besides
 * the route registrations ("route"), each named "file function" and
 * classified. A chain that ends anywhere else (a module's top level, a
 * function passed on as a value, a function nothing references) fails.
 */
const ROOTS = new Map<string, RootClass>([
  // varlatchd's host commands (cli.ts main dispatches to them).
  ["cli.ts adminCommand", "host-command"],
  ["cli.ts migrateCommand", "host-command"],
  // Server startup.
  ["cli.ts serveCommand", "startup"],
  // Background workers: each loop's tick, which its timer calls.
  ["domain/webhooks.ts tick", "worker"],
  ["domain/orgdeletion.ts tick", "worker"],
  ["domain/githubapps.ts tick", "worker"],
  ["domain/syncdelivery.ts tick", "worker"],
  // Better Auth calls it during an enrollment ceremony: a request to /auth/* or /enroll.
  ["auth/humanauth.ts {}.afterVerification", "route"],
]);

type Writer = { why: string; roots: RootClass[] };
const protectedBy = (why: string): Writer => ({ why: `protected: ${why}`, roots: ["route"] });
const exempt = (why: string, ...roots: RootClass[]): Writer => ({ why: `exempt: ${why}`, roots: roots.length > 0 ? roots : ["route"] });

/**
 * Every function in src/ that writes the rows the 40 operations change
 * (identities, credentials, OIDC bindings, Grants, roles, groups, their
 * members and Team-Project links, memberships, invitations, webhooks,
 * Connections, GitHub Apps and their registrations, Projects,
 * Organization deletions), by file and function (app.ts: by route), each
 * protected by the named operations or exempt for a reason, with the
 * classes of every root that reaches it in the caller graph. A writer
 * exempt as a host command holds only while host commands alone reach it:
 * a new route caller fails. A new writer fails until it is classified.
 */
const WRITERS: Record<string, Writer> = {
  "auth/credentials.ts authenticateBearer": exempt("a credential's use count and last use"),
  "auth/credentials.ts issueCredential": exempt("the credential primitive: its callers are in CALLERS", "host-command", "route"),
  "auth/credentials.ts revokeCredential": exempt("revoking a credential only restricts"),
  "domain/bootstrap.ts completePublicUrlChange": exempt("host command: revokes browser credentials on a public URL change", "host-command"),
  "domain/bootstrap.ts consumeSetupGrant": exempt("enrollment through a setup grant (an invitation, bootstrap or recovery)", "host-command", "route"),
  "domain/bootstrap.ts issueBootstrapGrant": exempt("host command (admin bootstrap)", "host-command"),
  "domain/bootstrap.ts issueInviteGrant": protectedBy("member.invite_admin (a member invitation is exempt)"),
  "domain/bootstrap.ts issueRecoveryGrant": exempt("host command (admin recover)", "host-command"),
  "domain/bootstrap.ts issueReenrollmentGrants": exempt("host command (admin reenroll)", "host-command"),
  "domain/contracts.ts activateRevision": exempt("a Contract Revision"),
  "domain/githubapps.ts attachInTx": protectedBy("github_app.register"),
  "domain/githubapps.ts completeRegistration": protectedBy("github_app.register (its conversion is not, amendment D)"),
  "domain/githubapps.ts endPending": exempt("ends a pending registration: discard, terminal refusal (amendment D)"),
  "domain/githubapps.ts importGitHubApp": protectedBy("github_app.import"),
  "domain/githubapps.ts startRegistration": exempt("starting a registration (amendment D)"),
  "domain/githubapps.ts sweepExpiredRegistrations": exempt("the sweep of expired pending registrations", "worker"),
  "domain/identities.ts createMachineIdentity": protectedBy("identity.create"),
  "domain/identities.ts reactivateIdentity": protectedBy("identity.reactivate"),
  "domain/identities.ts renameIdentity": exempt("renaming"),
  "domain/identities.ts retireIdentity": exempt("retiring only restricts"),
  "domain/invitations.ts revokeInvitation": exempt("revoking an invitation only restricts"),
  "domain/members.ts changeMemberRole": protectedBy("member.promote, member.demote"),
  "domain/members.ts endMembership": exempt("reached through member.remove (protected), leaving, and the deletion worker's finalization", "route", "worker"),
  "domain/oidc.ts createOidcBinding": protectedBy("oidc_binding.create"),
  "domain/oidc.ts revokeOidcBinding": protectedBy("oidc_binding.delete"),
  "domain/orgdeletion.ts approveDeletion": exempt("the second admin's approval (amendment B)"),
  "domain/orgdeletion.ts cancelDeletion": exempt("cancelling only restricts"),
  "domain/orgdeletion.ts finalizeDeletion": exempt("the deletion worker, after the approved scheduling and its waiting period", "worker"),
  "domain/orgdeletion.ts scheduleDeletion": protectedBy("organization.delete"),
  "domain/orgs.ts createOrganization": exempt("a new Organization's first admin"),
  "domain/orgs.ts pinLiveMembership": exempt("a membership's version for a concurrent writer (amendment E)"),
  "domain/policy.ts addGroupMember": protectedBy("group.member_add, team.member_add"),
  "domain/policy.ts addTeamProject": protectedBy("team.project_add"),
  "domain/policy.ts createGroup": protectedBy("group.create, team.create"),
  "domain/policy.ts createRole": protectedBy("role.create"),
  "domain/policy.ts deleteGroup": protectedBy("group.delete, team.delete"),
  "domain/policy.ts deleteRole": protectedBy("role.delete"),
  "domain/policy.ts removeGroupMember": protectedBy("group.member_remove, team.member_remove"),
  "domain/policy.ts removeTeamProject": protectedBy("team.project_remove"),
  "domain/policy.ts updateGroup": protectedBy("group.update, team.update"),
  "domain/policy.ts updateRole": protectedBy("role.update"),
  "domain/projects.ts createProject": exempt("creating a Project"),
  "domain/projects.ts deleteProject": protectedBy("project.delete"),
  "domain/projects.ts renameProject": exempt("renaming"),
  "domain/sync.ts createAppConnection": protectedBy("connection.create (App shape)"),
  "domain/sync.ts createConnection": protectedBy("connection.create (token shape)"),
  "domain/sync.ts recordCredentialExpiry": exempt("the expiry a credential check or a push reports (catalogue, credential checks)", "route", "worker"),
  "domain/sync.ts removeGitHubApp": protectedBy("github_app.remove"),
  "domain/sync.ts replaceConnectionCredential": protectedBy("connection.replace_credential"),
  "domain/sync.ts revokeConnection": protectedBy("connection.delete"),
  "domain/sync.ts rotateGitHubAppKey": protectedBy("github_app.replace_key"),
  "domain/webhooks.ts createWebhook": protectedBy("webhook.create"),
  "domain/webhooks.ts deliverOne": exempt("the delivery worker's state", "worker"),
  "domain/webhooks.ts revokeWebhook": protectedBy("webhook.delete"),
  "domain/webhooks.ts updateWebhook": protectedBy("webhook.update"),
  [`http/app.ts DELETE ${ORG}/grants/:grant`]: protectedBy("grant.revoke"),
  "http/app.ts PATCH /v1/me/profile": exempt("a person's own display name"),
  "http/app.ts POST /v1/me/credentials/cli": exempt("a person's own CLI credential (CLI handoff)"),
  [`http/app.ts POST ${ORG}/grants/:grant/replace`]: protectedBy("grant.replace"),
  [`http/app.ts POST ${ORG}/grants`]: protectedBy("grant.create"),
};

/**
 * Every root that reaches each protected domain function and the
 * credential primitive, through the caller graph (by symbol: renamed
 * imports, re-exports, aliases, destructuring and object methods
 * followed), as "ROOT via outer > ... > inner". A new caller anywhere, an
 * exempt route included, adds an entry and fails until it is classified;
 * the runtime sweep below exercises the protected routes. A host command
 * reaching a protected function would pass noApprovalGate, which throws
 * ApprovalNeeded under enforce and so cannot bypass it.
 */
const inApp = (route: string) => `http/app.ts ${route}`;
const CALLERS: Record<string, string[]> = {
  "domain/identities.ts createMachineIdentity": [inApp(`POST ${ORG}/identities`)],
  // The non-broker branch of the credentials route (the broker's mints an agent-run credential: exempt).
  "domain/identities.ts issueMachineCredential": [inApp(`POST ${ORG}/identities/:identity/credentials via issueServiceCredential`)],
  "domain/identities.ts reactivateIdentity": [inApp(`POST ${ORG}/identities/:identity/reactivate`)],
  "domain/oidc.ts createOidcBinding": [inApp(`POST ${ORG}/identities/:identity/oidc-bindings`)],
  "domain/oidc.ts revokeOidcBinding": [inApp(`DELETE ${ORG}/identities/:identity/oidc-bindings/:binding`)],
  "domain/policy.ts createRole": [inApp(`POST ${ORG}/roles`)],
  "domain/policy.ts updateRole": [inApp(`PATCH ${ORG}/roles/:role`)],
  "domain/policy.ts deleteRole": [inApp(`DELETE ${ORG}/roles/:role`)],
  // Groups and teams share their writers through one helper per operation.
  "domain/policy.ts createGroup": [inApp(`POST ${ORG}/groups via createGroupRoute`), inApp(`POST ${ORG}/teams via createGroupRoute`)],
  "domain/policy.ts updateGroup": [inApp(`PATCH ${ORG}/groups/:group via updateGroupRoute`), inApp(`PATCH ${ORG}/teams/:team via updateGroupRoute`)],
  "domain/policy.ts deleteGroup": [inApp(`DELETE ${ORG}/groups/:group via deleteGroupRoute`), inApp(`DELETE ${ORG}/teams/:team via deleteGroupRoute`)],
  "domain/policy.ts addGroupMember": [inApp(`POST ${ORG}/groups/:group/members via addMemberRoute`), inApp(`POST ${ORG}/teams/:team/members via addMemberRoute`)],
  "domain/policy.ts removeGroupMember": [
    inApp(`DELETE ${ORG}/groups/:group/members/:identity via removeMemberRoute`),
    inApp(`DELETE ${ORG}/teams/:team/members/:identity via removeMemberRoute`),
  ],
  "domain/policy.ts addTeamProject": [inApp(`POST ${ORG}/teams/:team/projects`)],
  "domain/policy.ts removeTeamProject": [inApp(`DELETE ${ORG}/teams/:team/projects/:project`)],
  "domain/bootstrap.ts issueInviteGrant": [inApp(`POST ${ORG}/invitations`)],
  "domain/members.ts changeMemberRole": [inApp(`PATCH ${ORG}/members/:member`)],
  "domain/members.ts removeMember": [inApp(`DELETE ${ORG}/members/:member`)],
  // member.remove (protected) and leaving through removeMember; the deletion worker's finalization.
  "domain/members.ts endMembership": ["domain/orgdeletion.ts tick via runDueDeletions > finalizeDeletion", inApp(`DELETE ${ORG}/members/:member via removeMember`)],
  "domain/webhooks.ts createWebhook": [inApp(`POST ${ORG}/webhooks`)],
  "domain/webhooks.ts updateWebhook": [inApp(`PATCH ${ORG}/webhooks/:webhook`)],
  "domain/webhooks.ts revokeWebhook": [inApp(`DELETE ${ORG}/webhooks/:webhook`)],
  "domain/sync.ts createConnection": [inApp(`POST ${ORG}/platform-connections`)],
  "domain/sync.ts createAppConnection": [inApp(`POST ${ORG}/platform-connections`)],
  "domain/sync.ts replaceConnectionCredential": [inApp(`POST ${ORG}/platform-connections/:connection/credential`)],
  "domain/sync.ts revokeConnection": [inApp(`DELETE ${ORG}/platform-connections/:connection`)],
  "domain/sync.ts rotateGitHubAppKey": [inApp(`POST ${ORG}/github-app/key`)],
  "domain/sync.ts removeGitHubApp": [inApp(`DELETE ${ORG}/github-app`)],
  "domain/githubapps.ts attachInTx": [
    inApp(`POST ${ORG}/github-app/registrations/:registration/attach via attachRegistration`),
    inApp(`POST ${ORG}/github-app/registrations/complete via completeRegistration`),
  ],
  "domain/githubapps.ts attachRegistration": [inApp(`POST ${ORG}/github-app/registrations/:registration/attach`)],
  "domain/githubapps.ts completeRegistration": [inApp(`POST ${ORG}/github-app/registrations/complete`)],
  "domain/githubapps.ts importGitHubApp": [inApp(`POST ${ORG}/github-app/import`)],
  "domain/projects.ts deleteProject": [inApp(`DELETE ${ORG}/projects/:project`)],
  "domain/orgdeletion.ts scheduleDeletion": [inApp(`POST ${ORG}/deletion`)],
  "domain/exportstepup.ts exportGuard": [inApp(`POST ${ORG}/projects/:project/environments/:environment/disclosures`)],
  // A service credential is issued only through createMachineIdentity and
  // issueMachineCredential (protected). The others issue a person's
  // credential (host commands, device sign-in, the CLI handoff, the
  // dashboard bearer), an OIDC-exchanged one, or an agent-run one: the
  // broker's branch of the credentials route (exempt by Decision 5).
  "auth/credentials.ts issueCredential": [
    "cli.ts adminCommand",
    inApp("POST /auth/varlatch-token"),
    inApp("POST /v1/auth/device/token via pollDeviceSignIn > pollOnce"),
    inApp("POST /v1/me/credentials/cli"),
    inApp("POST /v1/oidc/token via exchangeOidcToken"),
    inApp(`POST ${ORG}/identities via createMachineIdentity`),
    inApp(`POST ${ORG}/identities/:identity/credentials`),
    inApp(`POST ${ORG}/identities/:identity/credentials via issueServiceCredential > issueMachineCredential`),
  ],
};

const PACKAGE_DIR = fileURLToPath(new URL("..", import.meta.url));

/** The callers of every CALLERS target in a graph. */
function callersOf(g: Graph): Record<string, string[]> {
  return Object.fromEntries(Object.keys(CALLERS).map((key) => {
    const [file, name] = key.split(" ") as [string, string];
    return [key, reach(g, declaredSymbol(g, file, name), ROOTS).entries];
  }));
}

/** Every writer of a protected table in a graph, with the classes of the roots reaching it ("route" for a route's own body). */
function writersOf(g: Graph): Record<string, RootClass[] | string[]> {
  return Object.fromEntries(writers(g, new RegExp(`\\b(?:INSERT INTO|UPDATE|DELETE FROM) (?:${WRITTEN_TABLES})\\b`)).map((w) => {
    if (!w.symbol) return [w.label, ["route"]];
    const r = reach(g, w.symbol, ROOTS);
    const failed = r.entries.filter((e) => e.startsWith("??"));
    return [w.label, failed.length > 0 ? failed : r.classes];
  }));
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

  describe("by the caller graph (the TypeScript type checker over src/)", () => {
    // Built once for these tests: about 5 s and 700 MB on the test machine
    // (createProgram over src/ and a symbol lookup for each of its
    // identifiers). Each self-test builds an edited copy from it, reusing its
    // unchanged files (6 to 9 s; about 1.2 GB with both alive). The
    // timeouts leave room for a machine busy with other suites.
    const GRAPH_TIMEOUT = 300_000;
    let graph: Graph;
    beforeAll(() => {
      graph = buildGraph(PACKAGE_DIR);
    }, GRAPH_TIMEOUT);

    it("names only roots that exist, and every registration has a literal path", () => {
      const labels = functionLabels(graph);
      expect([...ROOTS.keys()].filter((root) => !labels.has(root))).toEqual([]);
      expect(unlabelledRegistrations(graph)).toEqual([]);
    }, GRAPH_TIMEOUT);

    it("every writer in src/ of what the operations change is classified, and reached only by the roots its classification allows", () => {
      const expected = Object.fromEntries(Object.entries(WRITERS).map(([label, w]) => [label, [...w.roots].sort()]));
      expect(writersOf(graph)).toEqual(expected);
    }, GRAPH_TIMEOUT);

    it("every root reaching a protected domain function, or the credential primitive, is known", () => {
      const expected = Object.fromEntries(Object.entries(CALLERS).map(([key, list]) => [key, [...list].sort()]));
      expect(callersOf(graph)).toEqual(expected);
    }, GRAPH_TIMEOUT);

    describe("would fail on an added caller (in-memory sources through a CompilerHost)", () => {
      const RENAME = 'app.patch("/v1/organizations/:org/identities/:identity", async (c) => {';
      const rename = `http/app.ts PATCH ${ORG}/identities/:identity`;
      const PASSKEY_OWNER = "  const passkeyOwner = (c: Context) => {";
      // The text the base graph was built from, not the file on disk now: an
      // edit to the file while the suite runs cannot make the comparison
      // with the base graph see unrelated differences.
      const appText = () => graph.program.getSourceFile(srcPath(graph, "http/app.ts"))!.text;
      /** A graph of src/ with http/app.ts edited by `edit`, and `more` files added (relative to src/). */
      function tampered(edit: (text: string) => string, more: Record<string, string> = {}) {
        const original = appText();
        const edited = edit(original);
        expect(edited, "the edit applies").not.toBe(original);
        const edits: Record<string, string> = { [srcPath(graph, "http/app.ts")]: edited };
        for (const [file, text] of Object.entries(more)) edits[srcPath(graph, file)] = text;
        return buildGraph(PACKAGE_DIR, edits, graph.program);
      }
      const intoRename = (code: string) => (text: string) => {
        expect(text).toContain(RENAME);
        return text.replace(RENAME, `${RENAME}\n${code}`);
      };
      const before = () => callersOf(graph);
      /** The entries `after` has that the real graph has not, per target. */
      const added = (after: Record<string, string[]>) => {
        const base = before();
        const out: Record<string, string[]> = {};
        for (const [k, list] of Object.entries(after)) {
          const fresh = list.filter((e) => !(base[k] ?? []).includes(e));
          if (fresh.length > 0) out[k] = fresh;
        }
        return out;
      };

      it("a direct call to the credential primitive and to a protected function in an exempt route", () => {
        const g = tampered(intoRename('    await issueCredential(ctx.db, { identityId: "x", kind: "service" });\n    await createRole(ctx, gate, org.id, body, {});'));
        expect(added(callersOf(g))).toEqual({ "auth/credentials.ts issueCredential": [rename], "domain/policy.ts createRole": [rename] });
      }, GRAPH_TIMEOUT);

      it("a multiline helper declared just before another route's helper, then called from an exempt route", () => {
        const g = tampered((text) => {
          expect(text).toContain(PASSKEY_OWNER);
          const helper = '  const mintForIdentity =\n    async (identityId: string) => {\n      return issueCredential(ctx.db, { identityId, kind: "service" });\n    };\n';
          return intoRename('    await mintForIdentity("x");')(text.replace(PASSKEY_OWNER, `${helper}${PASSKEY_OWNER}`));
        });
        expect(added(callersOf(g))).toEqual({ "auth/credentials.ts issueCredential": [`${rename} via mintForIdentity`] });
      }, GRAPH_TIMEOUT);

      it("a helper declared inside buildApp between two routes, then called from an exempt route", () => {
        const anchor = '  app.post("/v1/organizations/:org/identities/:identity/retire", async (c) => {';
        const g = tampered((text) => {
          expect(text).toContain(anchor);
          const helper = '  function quietRole(c: Context) {\n    return createRole(ctx, c.get("gate"), "org", { name: "x", actions: [] }, {});\n  }\n';
          return intoRename("    await quietRole(c);")(text.replace(anchor, `${helper}${anchor}`));
        });
        expect(added(callersOf(g))).toEqual({ "domain/policy.ts createRole": [`${rename} via quietRole`] });
      }, GRAPH_TIMEOUT);

      it("a call split over several lines", () => {
        const g = tampered(intoRename('    await issueCredential\n      (\n        ctx.db,\n        { identityId: "x", kind: "service" },\n      );'));
        expect(added(callersOf(g))).toEqual({ "auth/credentials.ts issueCredential": [rename] });
      }, GRAPH_TIMEOUT);

      it("fails closed: a helper nobody calls, a registration whose path is not a literal, a function passed on as a value", () => {
        const g = tampered((text) =>
          text.replace(PASSKEY_OWNER, [
            '  const unused = async () => issueCredential(ctx.db, { identityId: "x", kind: "service" });',
            '  app.post(String("/v1/x"), async (c) => createRole(ctx, gate, "o", {}, {}));',
            "  const later: unknown[] = [deleteRole];",
            PASSKEY_OWNER,
          ].join("\n")));
        const after = added(callersOf(g));
        expect(after["auth/credentials.ts issueCredential"]).toEqual(["?? unused: nothing references it via unused"]);
        expect(after["domain/policy.ts createRole"]![0]).toMatch(/^\?\? http\/app\.ts:\d+ a registration whose path is not a string literal$/);
        expect(after["domain/policy.ts deleteRole"]![0]).toMatch(/^\?\? http\/app\.ts:\d+ deleteRole: a value passed on \(ArrayLiteralExpression\)$/);
        expect(unlabelledRegistrations(g)).toHaveLength(1);
      }, GRAPH_TIMEOUT);

      it("a renamed import", () => {
        const g = tampered((text) =>
          intoRename('    await mint(ctx.db, { identityId: "x", kind: "service" });')(
            `import { issueCredential as mint } from "../auth/credentials.js";\n${text}`));
        expect(added(callersOf(g))).toEqual({ "auth/credentials.ts issueCredential": [rename] });
      }, GRAPH_TIMEOUT);

      it("an exported host-command helper called from an exempt route: its host-command exemption no longer holds", () => {
        const g = tampered((text) =>
          intoRename('    await issueReenrollmentGrants(ctx, { identities: [] } as never);')(
            `import { issueReenrollmentGrants } from "../domain/bootstrap.js";\n${text}`));
        expect(writersOf(graph)["domain/bootstrap.ts issueReenrollmentGrants"]).toEqual(["host-command"]);
        expect(writersOf(g)["domain/bootstrap.ts issueReenrollmentGrants"]).toEqual(["host-command", "route"]);
      }, GRAPH_TIMEOUT);

      it("an object method reused from an exempt route", () => {
        const g = tampered((text) => {
          const helper = '  const tools = {\n    mint(identityId: string) {\n      return issueCredential(ctx.db, { identityId, kind: "service" });\n    },\n  };\n';
          return intoRename('    await tools.mint("x");')(text.replace(PASSKEY_OWNER, `${helper}${PASSKEY_OWNER}`));
        });
        expect(added(callersOf(g))).toEqual({ "auth/credentials.ts issueCredential": [`${rename} via tools.mint`] });
      }, GRAPH_TIMEOUT);

      it("an element access with a literal key on a module namespace", () => {
        const g = tampered((text) =>
          intoRename('    await credentialsProbe["issueCredential"](ctx.db, { identityId: "x", kind: "service" });')(
            `import * as credentialsProbe from "../auth/credentials.js";\n${text}`));
        expect(added(callersOf(g))).toEqual({ "auth/credentials.ts issueCredential": [rename] });
      }, GRAPH_TIMEOUT);

      it("an element access with a literal key on a module namespace, to a host-command helper: its exemption no longer holds", () => {
        const g = tampered((text) =>
          intoRename('    await bootstrapProbe["issueReenrollmentGrants"](ctx, { identities: [] } as never);')(
            `import * as bootstrapProbe from "../domain/bootstrap.js";\n${text}`));
        expect(writersOf(g)["domain/bootstrap.ts issueReenrollmentGrants"]).toEqual(["host-command", "route"]);
      }, GRAPH_TIMEOUT);

      const HANDLERS = '  const handlers = {\n    mint() {\n      return issueCredential(ctx.db, { identityId: "x", kind: "service" });\n    },\n  };\n';
      const RETIRE = '  app.post("/v1/organizations/:org/identities/:identity/retire", async (c) => {';
      const retire = `http/app.ts POST ${ORG}/identities/:identity/retire`;

      it("a handler map's method called with a literal key, next to a caller by name", () => {
        const g = tampered((text) => {
          expect(text).toContain(RETIRE);
          const withMap = text.replace(PASSKEY_OWNER, `${HANDLERS}${PASSKEY_OWNER}`).replace(RETIRE, `${RETIRE}\n    await handlers.mint();`);
          return intoRename('    await handlers["mint"]();')(withMap);
        });
        expect(added(callersOf(g))).toEqual({ "auth/credentials.ts issueCredential": [`${rename} via handlers.mint`, `${retire} via handlers.mint`] });
      }, GRAPH_TIMEOUT);

      it("fails closed: a handler map's method called with a computed key", () => {
        const g = tampered((text) => {
          const withMap = text.replace(PASSKEY_OWNER, `${HANDLERS}${PASSKEY_OWNER}`).replace(RETIRE, `${RETIRE}\n    await handlers.mint();`);
          return intoRename('    const which = c.req.param("identity") as "mint";\n    await handlers[which]();')(withMap);
        });
        const after = added(callersOf(g))["auth/credentials.ts issueCredential"] ?? [];
        expect(after).toContain(`${retire} via handlers.mint`);
        expect(after.filter((e) => e.startsWith("??"))).toEqual([
          expect.stringMatching(/^\?\? http\/app\.ts:\d+ a computed access handlers\[which\] may reach mint via handlers\.mint$/),
        ]);
      }, GRAPH_TIMEOUT);

      /** The handler map, called by name from the retire route, then `code` in the rename route; with a helper declared first. */
      const withHandlers = (code: string, helper = "") => (text: string) =>
        intoRename(code)(text.replace(PASSKEY_OWNER, `${helper}${HANDLERS}${PASSKEY_OWNER}`).replace(RETIRE, `${RETIRE}\n    await handlers.mint();`));
      /** The one fail-closed entry a handler map passed on records, and the caller by name still listed. */
      const handlersEscaped = (g: Graph, kind: string) => {
        const after = added(callersOf(g))["auth/credentials.ts issueCredential"] ?? [];
        expect(after).toContain(`${retire} via handlers.mint`);
        expect(after.filter((e) => e.startsWith("??"))).toEqual([
          expect.stringMatching(new RegExp(`^\\?\\? http/app\\.ts:\\d+ handlers passed on \\(${kind}\\) may reach mint via handlers\\.mint$`)),
        ]);
      };

      it("fails closed: a handler map enumerated through Object[\"values\"]", () => {
        handlersEscaped(tampered(withHandlers('    await Object["values"](handlers)[0]!();')), "CallExpression");
      }, GRAPH_TIMEOUT);

      it("fails closed: a handler map enumerated through an alias of Object.values", () => {
        handlersEscaped(tampered(withHandlers("    const values = Object.values;\n    await values(handlers)[0]!();")), "CallExpression");
      }, GRAPH_TIMEOUT);

      it("fails closed: a handler map passed to a user-defined function", () => {
        const invokeAll = "  function invokeAll(h: Record<string, () => unknown>) {\n    for (const f of Object.values(h)) f();\n  }\n";
        handlersEscaped(tampered(withHandlers("    invokeAll(handlers);", invokeAll)), "CallExpression");
      }, GRAPH_TIMEOUT);

      // ---- The last broadening round (Sonnet's review at 40fc6f2; its probes B, N, A/D/E and C).
      const MINT = 'issueCredential(ctx.db, { identityId: "x", kind: "service" })';
      /** The fail-closed entries a tampered graph adds for the credential primitive. */
      const failClosed = (g: Graph) => (added(callersOf(g))["auth/credentials.ts issueCredential"] ?? []).filter((e) => e.startsWith("??"));
      /** `helper` declared before passkeyOwner, `named` in the retire route (the chain), `code` in the rename route. */
      const probe = (helper: string, code: string, named: string, head = "") => (text: string) =>
        head + intoRename(code)(text.replace(PASSKEY_OWNER, `${helper}${PASSKEY_OWNER}`).replace(RETIRE, `${RETIRE}\n${named}`));
      const MINTER = "  interface Minter { mint(): unknown }\n";

      it("fails closed: a call through an interface the handler map is cast to (item 1, probe B1)", () => {
        const g = tampered(probe(MINTER + HANDLERS, "    await (handlers as Minter).mint();", "    await handlers.mint();"));
        expect(failClosed(g)).toEqual([expect.stringMatching(/^\?\? http\/app\.ts:\d+ Minter\.mint: a use of a member without a body may dispatch to mint via handlers\.mint$/)]);
      }, GRAPH_TIMEOUT);

      it("fails closed: a call through an interface-typed alias of the handler map (item 1, probe B2)", () => {
        const g = tampered(probe(MINTER + HANDLERS, "    const t: Minter = handlers;\n    await t.mint();", "    await handlers.mint();"));
        expect(failClosed(g)).toEqual([expect.stringMatching(/^\?\? http\/app\.ts:\d+ Minter\.mint: a use of a member without a body may dispatch to mint via handlers\.mint$/)]);
      }, GRAPH_TIMEOUT);

      it("fails closed: a call through an abstract base (item 1, probe B5)", () => {
        const classes = `  abstract class Base { abstract mint(): unknown }\n  class M extends Base { mint() { return ${MINT}; } }\n`;
        const g = tampered(probe(classes, "    const m: Base = new M();\n    await m.mint();", "    await new M().mint();"));
        expect(failClosed(g)).toEqual([expect.stringMatching(/^\?\? http\/app\.ts:\d+ Base\.mint: a use of a member without a body may dispatch to mint via M\.mint$/)]);
      }, GRAPH_TIMEOUT);

      const NS = 'import * as credProbe from "../auth/credentials.js";\n';
      const NS_NAMED = `    await credProbe.${MINT};`;

      it("fails closed: a module namespace enumerated (item 2, probe N2)", () => {
        const g = tampered(probe("", "    await (Object.values(credProbe)[0] as any)(ctx.db, {});", NS_NAMED, NS));
        expect(failClosed(g)).toEqual([expect.stringMatching(/^\?\? http\/app\.ts:\d+ credProbe passed on \(CallExpression\) may reach issueCredential$/)]);
      }, GRAPH_TIMEOUT);

      it("fails closed: a dynamically imported module with a computed key (item 2, probe N4)", () => {
        const g = tampered(probe("", "    const m = await import('../auth/credentials.js');\n    await (m as any)[c.req.param('identity')](ctx.db, {});", NS_NAMED, NS));
        expect(failClosed(g)).toEqual([expect.stringMatching(/^\?\? http\/app\.ts:\d+ a computed access \(m as any\)\[c\.req\.param\('identity'\)\] may reach issueCredential$/)]);
      }, GRAPH_TIMEOUT);

      const MAKE = `  function makeH() { return { mint() { return ${MINT}; } }; }\n`;

      it("fails closed: a factory's result enumerated, and the factory returning it (item 3, probe A1)", () => {
        const g = tampered(probe(MAKE, "    await Object.values(makeH())[0]!();", "    await makeH().mint();"));
        expect(failClosed(g)).toEqual([
          expect.stringMatching(/^\?\? http\/app\.ts:\d+ \{ mint\(\) \{ .* \} \} passed on \(ReturnStatement\) may reach mint via \{\}\.mint$/),
          expect.stringMatching(/^\?\? http\/app\.ts:\d+ makeH\(\) passed on \(CallExpression\) may reach mint via \{\}\.mint$/),
        ]);
      }, GRAPH_TIMEOUT);

      it("fails closed: a new instance with a computed key (item 3, probe D3)", () => {
        const g = tampered(probe(`  class X { mint() { return ${MINT}; } }\n`, "    const k = 'mint' as const;\n    await new X()[k]();", "    await new X().mint();"));
        expect(failClosed(g)).toEqual([expect.stringMatching(/^\?\? http\/app\.ts:\d+ a computed access new X\(\)\[k\] may reach mint via X\.mint$/)]);
      }, GRAPH_TIMEOUT);

      it("fails closed: an awaited holder enumerated (item 3, probe E16)", () => {
        const g = tampered(probe(`  const mk = async () => ({ mint() { return ${MINT}; } });\n`, "    await Object.values(await mk())[0]!();", "    await (await mk()).mint();"));
        expect(failClosed(g)).toContainEqual(expect.stringMatching(/^\?\? http\/app\.ts:\d+ mk\(\) passed on \(CallExpression\) may reach mint via \{\}\.mint$/));
      }, GRAPH_TIMEOUT);

      it("fails closed: a holder typed as a union with undefined (item 3, heldKeys through unions)", () => {
        // `maybe` is `typeof handlers | undefined`: only a union-aware heldKeys sees it hold mint.
        const g = tampered(withHandlers("    const maybe = c.req.param('identity') ? handlers : undefined;\n    await Object.values(maybe!)[0]!();"));
        expect(failClosed(g)).toEqual([
          expect.stringMatching(/^\?\? http\/app\.ts:\d+ handlers passed on \(ConditionalExpression\) may reach mint via handlers\.mint$/),
          expect.stringMatching(/^\?\? http\/app\.ts:\d+ maybe passed on \(CallExpression\) may reach mint via handlers\.mint$/),
        ]);
      }, GRAPH_TIMEOUT);

      it("fails closed: a destructuring with a computed key (item 4, probe C1)", () => {
        const g = tampered(withHandlers("    const k = c.req.param('identity') as 'mint';\n    const { [k]: f } = handlers;\n    await f();"));
        expect(failClosed(g)).toEqual([expect.stringMatching(/^\?\? http\/app\.ts:\d+ a computed destructuring \{ \[k\]: f \} may reach mint via handlers\.mint$/)]);
      }, GRAPH_TIMEOUT);

      it("fails closed: the handler map spread into another object", () => {
        handlersEscaped(tampered(withHandlers("    const copy = { ...handlers };\n    await copy.mint();")), "SpreadAssignment");
      }, GRAPH_TIMEOUT);

      it("fails closed: the handler map returned", () => {
        handlersEscaped(tampered(withHandlers("    const get = () => {\n      return handlers;\n    };\n    await get().mint();")), "ReturnStatement");
      }, GRAPH_TIMEOUT);

      it("fails closed: the handler map stored into a property", () => {
        handlersEscaped(tampered(withHandlers("    const box: { h?: unknown } = {};\n    box.h = handlers;")), "BinaryExpression");
      }, GRAPH_TIMEOUT);

      it("a re-export through another module", () => {
        const g = tampered(
          (text) => intoRename('    await issue(ctx.db, { identityId: "x", kind: "service" });')(`import { issue } from "../domain/reexport-probe.js";\n${text}`),
          { "domain/reexport-probe.ts": 'export { issueCredential as issue } from "../auth/credentials.js";\n' },
        );
        expect(added(callersOf(g))).toEqual({ "auth/credentials.ts issueCredential": [rename] });
      }, GRAPH_TIMEOUT);
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
