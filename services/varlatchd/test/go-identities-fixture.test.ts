// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.4a's parity fixture (ADR-0059 step 4, feature-parity decision 3),
 * on the parity kit (go-fixture-kit.ts): machine identities and their
 * credentials, built through this server's own /v1 API, and a table of
 * requests with this server's answers: listIdentities,
 * createServiceIdentity, renameIdentity, retireIdentity,
 * reactivateIdentity, listIdentityCredentials, issueIdentityCredential
 * (a Broker's agent-run credentials too) and revokeIdentityCredential.
 * go/server/identities' parity test replays it against varlatchd.
 *
 * The database: alice (the bootstrap Installation Admin) and Organizations
 * made through /v1: ids (every control off), rep (admin-step-up and
 * credential-lifetime at report), enf (both at enforce), frozen (an
 * incident freeze), deleting (a deletion scheduled, one identity suspended
 * by it) and other. In ids: a machine identity of every kind, one retired,
 * an Agent retired; svc holds a credential of every state (no expiry, a
 * TTL, a use limit, used, expired, revoked) and an OIDC one; the Broker
 * minted an agent-run credential. People: bob (a member), dave (an admin
 * with a profile), erin (a former member), carol (in none). Approval
 * intents of alice's second CLI credential in enf, bound to exact requests
 * of the table. Responses that show a new token mask it.
 *
 * Every run checks the committed file: its requests must be the table's,
 * and this server, on the file's rows, must give the recorded answers.
 * After a change, regenerate it and commit the result:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-identities-fixture.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { issueCredential } from "../src/auth/credentials.js";
import { generateKey } from "../src/crypto/aead.js";
import { newId } from "../src/db/ids.js";
import { approvalHash, canonicalJson, type ApprovalBinding } from "../src/domain/approvals.js";
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant } from "../src/domain/bootstrap.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { credentialIssueBinding, identityCreateBinding, identityReactivateBinding } from "../src/domain/identitystepup.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { migratedTestDb } from "./helpers/pglite.js";
import {
  expectCurrentTable, expectSameAnswers, expectSameRows, exportRows, loadRows, record, withIds,
  type Fixture, type RequestCase, type Row, type SideTable, type Table,
} from "./go-fixture-kit.js";

// The unwrapped app: some requests are outside the OpenAPI document on
// purpose (bodies that are not JSON, extra members).
const { buildApp, SERVER_VERSION } = await vi.importActual<typeof import("../src/http/app.js")>("../src/http/app.js");

const FILE = new URL("../../../go/server/paritytest/testdata/identities-v0.22.0.json", import.meta.url);

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
  { name: "security_controls", orderBy: "organization_id, control" },
  { name: "security_control_counters", orderBy: "organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour" },
  // The intents' hashes are keyed by the build's random Root KEK.
  { name: "approval_intents", orderBy: "id", random: ["body_hash", "query_hash"] },
  { name: "organization_freezes", orderBy: "id" },
  { name: "organization_deletions", orderBy: "id" },
];

const SIDE: SideTable[] = [
  { name: "identities", key: ["id"], sortBy: ["organization_id", "name"], volatile: ["created_at"] },
  {
    name: "credentials", key: ["id"], sortBy: ["identity_id", "kind", "name"],
    volatile: ["token_hash", "created_at", "expires_at", "revoked_at", "last_used_at"],
  },
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
  create: aprId("create"),
  issue: aprId("issue"),
  reactivate: aprId("reactivate"),
  otherBody: aprId("otherbody"),
  pending: aprId("pending"),
} as const;

const LIFETIME_REP = { defaultTtlSeconds: 3600, maxTtlSeconds: 86_400 };
const LIFETIME_ENF = { defaultTtlSeconds: 600, maxTtlSeconds: 7200 };

/** The table of requests. */
function requestTable(): RequestCase[] {
  const approval = (id?: string) => (id !== undefined ? { headers: { "Varlatch-Approval": id } } : {});
  const list = (name: string, org: string, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "GET", path: `${ORG}/${org}/identities`, credential });
  const create = (name: string, org: string, body: unknown, credential = "alice", approvalId?: string): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/identities`, credential, body, masked: ["credential"], ...approval(approvalId) });
  const createRaw = (name: string, org: string, rawBody: string): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/identities`, credential: "alice", rawBody });
  const issue = (name: string, org: string, identity: string, body: unknown, credential = "alice", approvalId?: string): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/identities/${identity}/credentials`, credential, body, masked: ["token"], ...approval(approvalId) });
  const issueRaw = (name: string, org: string, identity: string, rawBody: string, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/identities/${identity}/credentials`, credential, rawBody });
  const revoke = (name: string, org: string, identity: string, cred: string, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "DELETE", path: `${ORG}/${org}/identities/${identity}/credentials/${cred}`, credential });
  const creds = (name: string, org: string, identity: string, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "GET", path: `${ORG}/${org}/identities/${identity}/credentials`, credential });
  const retire = (name: string, org: string, identity: string, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/identities/${identity}/retire`, credential });
  const reactivate = (name: string, org: string, identity: string, credential = "alice", approvalId?: string): Omit<RequestCase, "id"> =>
    ({ name, method: "POST", path: `${ORG}/${org}/identities/${identity}/reactivate`, credential, ...approval(approvalId) });
  const rename = (name: string, org: string, identity: string, body: unknown, credential = "alice"): Omit<RequestCase, "id"> =>
    ({ name, method: "PATCH", path: `${ORG}/${org}/identities/${identity}`, credential, body });
  const renameRaw = (name: string, org: string, identity: string, rawBody: string): Omit<RequestCase, "id"> =>
    ({ name, method: "PATCH", path: `${ORG}/${org}/identities/${identity}`, credential: "alice", rawBody });
  const emoji = (n: number) => "\u{1F511}".repeat(n);
  return withIds([
    // listIdentities.
    list("list", "ids"),
    list("list by id", "{idsId}"),
    list("list as a member", "ids", "bob"),
    list("list as an outsider", "ids", "carol"),
    list("list as a machine", "ids", "svc"),
    list("list a frozen Organization", "frozen"),
    list("list an Organization being deleted", "deleting"),
    list("list an unknown Organization", "nope"),
    list("list another Organization", "other"),

    // createServiceIdentity, every kind, controls off.
    create("create a service identity", "ids", { name: "c-svc", kind: "service" }),
    create("create a workload with limits", "ids", { name: "c-wl", kind: "workload", credentialTtlSeconds: 3600, credentialMaxUses: 2 }),
    create("create a ci identity", "ids", { name: "c-ci", kind: "ci" }),
    create("create a broker", "ids", { name: "c-broker", kind: "broker" }),
    create("create an agent", "ids", { name: "c-agent", kind: "agent" }),
    create("create with a TTL only", "ids", { name: "c-ttl", kind: "service", credentialTtlSeconds: 1 }),
    create("create a one-shot credential", "ids", { name: "c-one", kind: "service", credentialMaxUses: 1 }),
    create("create, a TTL written as a float", "ids", { name: "c-float", kind: "service", credentialTtlSeconds: 6e1 }),
    create("create, ci ignores the limits", "ids", { name: "c-ci-limits", kind: "ci", credentialTtlSeconds: 60, credentialMaxUses: 3 }),
    create("create with extra members", "ids", { name: "c-extra", kind: "service", extra: true }),
    create("create, a name of 200 characters", "ids", { name: "n".repeat(200), kind: "ci" }),
    create("create, a name of 100 emoji", "ids", { name: emoji(100), kind: "ci" }),
    create("create, a name of 101 emoji", "ids", { name: emoji(101), kind: "ci" }),
    create("create, a name of 201 characters", "ids", { name: "n".repeat(201), kind: "ci" }),
    create("create, an empty name", "ids", { name: "", kind: "ci" }),
    create("create, no name", "ids", { kind: "ci" }),
    create("create, a null name", "ids", { name: null, kind: "ci" }),
    create("create, a person", "ids", { name: "c-human", kind: "human" }),
    create("create, no kind", "ids", { name: "c-nokind" }),
    create("create, a TTL of 0", "ids", { name: "c-ttl0", kind: "service", credentialTtlSeconds: 0 }),
    create("create, a TTL above ten years", "ids", { name: "c-ttlbig", kind: "service", credentialTtlSeconds: 315_360_001 }),
    create("create, a fractional TTL", "ids", { name: "c-ttlfrac", kind: "service", credentialTtlSeconds: 1.5 }),
    create("create, a TTL as a string", "ids", { name: "c-ttlstr", kind: "service", credentialTtlSeconds: "60" }),
    create("create, a null TTL", "ids", { name: "c-ttlnull", kind: "service", credentialTtlSeconds: null }),
    create("create, no uses", "ids", { name: "c-uses0", kind: "service", credentialMaxUses: 0 }),
    create("create, too many uses", "ids", { name: "c-usesbig", kind: "service", credentialMaxUses: 1_000_001 }),
    create("create, every member wrong", "ids", { name: "", kind: "robot", credentialTtlSeconds: 0, credentialMaxUses: -1 }),
    create("create, an array", "ids", []),
    create("create, a string", "ids", "c-svc"),
    createRaw("create, a body that is not JSON", "ids", "{name:"),
    createRaw("create, an empty body", "ids", ""),
    create("create, a name with NUL", "ids", { name: "a\u0000b", kind: "ci" }),
    create("create as a member", "ids", { name: "c-bob", kind: "ci" }, "bob"),
    create("create as an outsider", "ids", { name: "c-carol", kind: "ci" }, "carol"),
    create("create as a machine", "ids", { name: "c-machine", kind: "ci" }, "svc"),
    create("create in a frozen Organization", "frozen", { name: "c-frozen", kind: "ci" }),
    create("create in an Organization being deleted", "deleting", { name: "c-deleting", kind: "ci" }),
    create("create in an unknown Organization", "nope", { name: "c-nope", kind: "ci" }),

    // At report: counted, created anyway.
    create("create at report, the default lifetime", "rep", { name: "r-default", kind: "service" }),
    create("create at report, above the maximum", "rep", { name: "r-long", kind: "service", credentialTtlSeconds: 100_000 }),
    create("create at report, a ci identity", "rep", { name: "r-ci", kind: "ci" }),

    // At enforce.
    create("create at enforce, no approval", "enf", { name: "e-ask", kind: "service" }),
    create("create at enforce, a ci identity and no approval", "enf", { name: "e-ci", kind: "ci" }),
    create("create at enforce, above the maximum", "enf", { name: "e-long", kind: "service", credentialTtlSeconds: 7201 }),
    create("create at enforce, its approval", "enf", { name: "approved", kind: "service" }, "alice2", APPROVALS.create),
    create("create at enforce, its approval again", "enf", { name: "approved", kind: "service" }, "alice2", APPROVALS.create),
    create("create at enforce, another request's approval", "enf", { name: "e-other", kind: "service" }, "alice2", APPROVALS.otherBody),
    create("create at enforce, an approval not given yet", "enf", { name: "pending", kind: "service" }, "alice2", APPROVALS.pending),
    create("create at enforce, a malformed approval", "enf", { name: "e-bad", kind: "service" }, "alice2", "not-an-approval"),
    create("create at enforce, an empty approval", "enf", { name: "e-empty", kind: "service" }, "alice2", ""),
    create("create, controls off, a malformed approval", "ids", { name: "c-ignored", kind: "ci" }, "alice", "not-an-approval"),

    // issueIdentityCredential, identity.manage.
    issue("issue a credential", "ids", "{svcId}", { name: "i-plain" }),
    issue("issue with a TTL", "ids", "{svcId}", { name: "i-ttl", ttlSeconds: 120 }),
    issue("issue with a use limit", "ids", "{svcId}", { name: "i-limited", maxUses: 3 }),
    issue("issue with both and extra members", "ids", "{svcId}", { name: "i-both", ttlSeconds: 60, maxUses: 1, extra: 1 }),
    issue("issue for a workload", "ids", "{wlId}", { name: "i-wl" }),
    issue("issue for a broker", "ids", "{brokerId}", { name: "i-broker" }),
    issue("issue for a ci identity", "ids", "{ciId}", { name: "i-ci" }),
    issue("issue for an agent", "ids", "{agentId}", { name: "i-agent" }),
    issue("issue for a person", "ids", "{bobId}", { name: "i-bob" }),
    issue("issue for a retired identity", "ids", "{oldId}", { name: "i-old" }),
    issue("issue for an unknown identity", "ids", "idn_unknownaaaaaaaaaaaaaaaaaa", { name: "i-unknown" }),
    issue("issue for another Organization's identity", "ids", "{osvcId}", { name: "i-other" }),
    issue("issue, no name", "ids", "{svcId}", { ttlSeconds: 60 }),
    issue("issue, a name of 201 characters", "ids", "{svcId}", { name: "n".repeat(201) }),
    issue("issue, a name of 101 emoji", "ids", "{svcId}", { name: emoji(101) }),
    issue("issue, a TTL of 0", "ids", "{svcId}", { name: "i-0", ttlSeconds: 0 }),
    issue("issue, no uses", "ids", "{svcId}", { name: "i-u0", maxUses: 0 }),
    issue("issue, a null use limit", "ids", "{svcId}", { name: "i-unull", maxUses: null }),
    issueRaw("issue, a body that is not JSON", "ids", "{svcId}", "nope"),
    issueRaw("issue for a ci identity, a body that is not JSON", "ids", "{ciId}", "nope"),
    issue("issue as a member", "ids", "{svcId}", { name: "i-bob" }, "bob"),
    issue("issue as the identity itself", "ids", "{svcId}", { name: "i-self" }, "svc"),
    issue("issue in a frozen Organization", "frozen", "{fsvcId}", { name: "i-frozen" }),
    issue("issue for an identity suspended by a deletion", "deleting", "{suspId}", { name: "i-susp" }),
    issue("issue at report, the default lifetime", "rep", "{rsvcId}", { name: "i-rep" }),
    issue("issue at report, above the maximum", "rep", "{rsvcId}", { name: "i-replong", ttlSeconds: 90_000 }),
    issue("issue at enforce, no approval", "enf", "{esvcId}", { name: "i-ask" }),
    issue("issue at enforce, above the maximum", "enf", "{esvcId}", { name: "i-enflong", ttlSeconds: 7201 }),
    issue("issue at enforce, its approval", "enf", "{esvcId}", { name: "approved-cred" }, "alice2", APPROVALS.issue),

    // issueIdentityCredential, a Broker's agent-run credentials.
    issue("agent-run credential", "ids", "{agentId}", { ttlSeconds: 600, runId: "run-1" }, "broker"),
    issue("agent-run credential, no run id", "ids", "{agentId}", { ttlSeconds: 3600 }, "broker"),
    issue("agent-run credential, an empty run id", "ids", "{agentId}", { ttlSeconds: 1, runId: "" }, "broker"),
    issue("agent-run credential, extra members", "ids", "{agentId}", { ttlSeconds: 60, name: "ignored" }, "broker"),
    issue("agent-run credential, a run id of 201 characters", "ids", "{agentId}", { ttlSeconds: 60, runId: "r".repeat(201) }, "broker"),
    issue("agent-run credential, an hour and a second", "ids", "{agentId}", { ttlSeconds: 3601 }, "broker"),
    issue("agent-run credential, no TTL", "ids", "{agentId}", { runId: "r" }, "broker"),
    issue("agent-run credential, a TTL of 0", "ids", "{agentId}", { ttlSeconds: 0 }, "broker"),
    issueRaw("agent-run credential, a body that is not JSON", "ids", "{agentId}", "[", "broker"),
    issue("agent-run credential for a retired agent", "ids", "{agentOffId}", { ttlSeconds: 60 }, "broker"),
    issue("agent-run credential for a service identity", "ids", "{svcId}", { ttlSeconds: 60 }, "broker"),
    issue("agent-run credential for a person", "ids", "{bobId}", { ttlSeconds: 60 }, "broker"),
    issue("agent-run credential for an unknown identity", "ids", "idn_unknownaaaaaaaaaaaaaaaaaa", { ttlSeconds: 60 }, "broker"),
    issue("agent-run credential from another Organization's Broker", "ids", "{agentId}", { ttlSeconds: 60 }, "obroker"),
    issue("agent-run credential in a frozen Organization", "frozen", "{fagentId}", { ttlSeconds: 60 }, "fbroker"),

    // listIdentityCredentials.
    creds("credentials of every state", "ids", "{svcId}"),
    creds("credentials of an agent", "ids", "{agentId}"),
    creds("credentials of a person", "ids", "{bobId}"),
    creds("credentials of an unknown identity", "ids", "idn_unknownaaaaaaaaaaaaaaaaaa"),
    creds("credentials as a member", "ids", "{svcId}", "bob"),
    creds("credentials in a frozen Organization", "frozen", "{fsvcId}"),

    // revokeIdentityCredential.
    revoke("revoke a service credential", "ids", "{svcId}", "{svcLimitedCred}"),
    revoke("revoke it again", "ids", "{svcId}", "{svcLimitedCred}"),
    revoke("revoke an OIDC credential", "ids", "{svcId}", "{svcOidcCred}"),
    revoke("revoke an agent-run credential as an admin", "ids", "{agentId}", "{setupRunCred}"),
    revoke("revoke a person's credential", "ids", "{bobId}", "{bobCliCred}"),
    revoke("revoke another identity's credential", "ids", "{svcId}", "{wlCred}"),
    revoke("revoke an unknown credential", "ids", "{svcId}", "crd_unknownaaaaaaaaaaaaaaaaaa"),
    revoke("revoke as a member", "ids", "{svcId}", "{svcTtlCred}", "bob"),
    revoke("revoke the caller's own credential", "ids", "{svcId}", "{svcCred}", "svc"),
    revoke("revoke an agent-run credential as its Broker", "ids", "{agentId}", "{setupRunCred}", "broker"),
    revoke("revoke a service credential as a Broker", "ids", "{svcId}", "{svcTtlCred}", "broker"),
    revoke("revoke a retired agent's credential as a Broker", "ids", "{agentOffId}", "{offRunCred}", "broker"),
    revoke("revoke in a frozen Organization", "frozen", "{fsvcId}", "{fsvcCred}"),
    revoke("revoke as a Broker in a frozen Organization", "frozen", "{fagentId}", "{fRunCred}", "fbroker"),
    creds("credentials after the revocations", "ids", "{svcId}"),

    // retireIdentity.
    retire("retire a workload", "ids", "{wlId}"),
    retire("retire it again", "ids", "{wlId}"),
    retire("retire a person", "ids", "{bobId}"),
    retire("retire an unknown identity", "ids", "idn_unknownaaaaaaaaaaaaaaaaaa"),
    retire("retire as a member", "ids", "{svcId}", "bob"),
    retire("retire in a frozen Organization", "frozen", "{fsvc2Id}"),
    retire("retire in an Organization being deleted", "deleting", "{dsvcId}"),
    creds("a retired identity's credentials", "ids", "{wlId}"),

    // reactivateIdentity.
    reactivate("reactivate a retired identity", "ids", "{oldId}"),
    reactivate("reactivate an enabled identity", "ids", "{svcId}"),
    reactivate("reactivate a person", "ids", "{bobId}"),
    reactivate("reactivate as a member", "ids", "{wlId}", "bob"),
    reactivate("reactivate an identity suspended by a deletion", "deleting", "{suspId}"),
    reactivate("reactivate in a frozen Organization", "frozen", "{fsvc2Id}"),
    reactivate("reactivate at report", "rep", "{roldId}"),
    reactivate("reactivate at enforce, no approval", "enf", "{eoldId}"),
    reactivate("reactivate at enforce, an enabled identity", "enf", "{esvcId}"),
    reactivate("reactivate at enforce, its approval", "enf", "{eoldId}", "alice2", APPROVALS.reactivate),
    issue("issue for the reactivated identity", "ids", "{oldId}", { name: "i-again" }),

    // renameIdentity.
    rename("rename", "ids", "{ciId}", { name: "ci-renamed" }),
    rename("rename to the same name", "ids", "{ciId}", { name: "ci-renamed" }),
    rename("rename with extra members", "ids", "{ciId}", { name: "ci-again", kind: "service" }),
    rename("rename, a name of 101 emoji", "ids", "{ciId}", { name: emoji(101) }),
    rename("rename, a name of 201 characters", "ids", "{ciId}", { name: "n".repeat(201) }),
    rename("rename, an empty name", "ids", "{ciId}", { name: "" }),
    rename("rename, no name", "ids", "{ciId}", {}),
    rename("rename, a name with NUL", "ids", "{ciId}", { name: "a\u0000b" }),
    renameRaw("rename, a body that is not JSON", "ids", "{ciId}", "x"),
    rename("rename a person", "ids", "{bobId}", { name: "robert" }),
    rename("rename a retired identity", "ids", "{wlId}", { name: "wl-retired" }),
    rename("rename as a member", "ids", "{ciId}", { name: "ci-bob" }, "bob"),
    rename("rename in a frozen Organization", "frozen", "{fsvcId}", { name: "f-renamed" }),
    list("list after the changes", "ids"),
  ]);
}

/** The table's placeholders, from the file's rows. */
function fillPath(rows: Record<string, Row[]>): (p: string) => string {
  const orgId = (slug: string) => rows.organizations!.find((o) => o.slug === slug)!.id as string;
  const identity = (name: string, org?: string) =>
    rows.identities!.find((i) => i.name === name && (org === undefined || i.organization_id === orgId(org)))!.id as string;
  const credential = (owner: string, name: string) => rows.credentials!.find((c) => c.identity_id === owner && c.name === name)!.id as string;
  const svc = identity("svc", "ids");
  const pairs: [string, string][] = [
    ["{idsId}", orgId("ids")],
    ["{svcId}", svc],
    ["{wlId}", identity("wl", "ids")],
    ["{ciId}", identity("ci", "ids")],
    ["{brokerId}", identity("broker", "ids")],
    ["{agentId}", identity("agent", "ids")],
    ["{agentOffId}", identity("agent-off", "ids")],
    ["{oldId}", identity("old", "ids")],
    ["{bobId}", identity("bob")],
    ["{osvcId}", identity("osvc", "other")],
    ["{fsvcId}", identity("fsvc", "frozen")],
    ["{fsvc2Id}", identity("fsvc2", "frozen")],
    ["{fagentId}", identity("fagent", "frozen")],
    ["{suspId}", identity("susp", "deleting")],
    ["{dsvcId}", identity("dsvc", "deleting")],
    ["{rsvcId}", identity("rsvc", "rep")],
    ["{roldId}", identity("rold", "rep")],
    ["{esvcId}", identity("esvc", "enf")],
    ["{eoldId}", identity("eold", "enf")],
    ["{svcCred}", credential(svc, "svc credential")],
    ["{svcTtlCred}", credential(svc, "svc-expiring")],
    ["{svcLimitedCred}", credential(svc, "svc-limited")],
    ["{svcOidcCred}", credential(svc, "gh-actions")],
    ["{wlCred}", credential(identity("wl", "ids"), "wl credential")],
    ["{setupRunCred}", credential(identity("agent", "ids"), "setup-run")],
    ["{offRunCred}", credential(identity("agent-off", "ids"), "off-run")],
    ["{bobCliCred}", rows.credentials!.find((c) => c.identity_id === identity("bob") && c.kind === "cli")!.id as string],
    ["{fsvcCred}", credential(identity("fsvc", "frozen"), "fsvc credential")],
    ["{fRunCred}", credential(identity("fagent", "frozen"), "f-run")],
  ];
  return (p) => pairs.reduce((out, [k, v]) => out.replaceAll(k, v), p);
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
  for (const slug of ["ids", "rep", "enf", "frozen", "deleting", "other"]) {
    orgs[slug] = (await call("POST", ORG, { name: slug[0]!.toUpperCase() + slug.slice(1), slug })).id;
  }
  const machine = async (org: string, name: string, kind: string, extra: Record<string, unknown> = {}) =>
    call("POST", `${ORG}/${org}/identities`, { name, kind, ...extra });

  // ids: a machine identity of every kind.
  const svc = await machine("ids", "svc", "service");
  tokens.svc = svc.credential;
  const wl = await machine("ids", "wl", "workload", { credentialTtlSeconds: 86_400, credentialMaxUses: 5 });
  await machine("ids", "ci", "ci");
  const broker = await machine("ids", "broker", "broker");
  tokens.broker = broker.credential;
  const agent = await machine("ids", "agent", "agent");
  const agentOff = await machine("ids", "agent-off", "agent");
  const old = await machine("ids", "old", "service");
  // svc's credentials: a TTL, a use limit, revoked, used, expired, OIDC.
  await call("POST", `${ORG}/ids/identities/${svc.id}/credentials`, { name: "svc-expiring", ttlSeconds: 86_400 * 3650 });
  await call("POST", `${ORG}/ids/identities/${svc.id}/credentials`, { name: "svc-limited", maxUses: 10 });
  const revoked = await call("POST", `${ORG}/ids/identities/${svc.id}/credentials`, { name: "svc-revoked" });
  await call("DELETE", `${ORG}/ids/identities/${svc.id}/credentials/${revoked.id}`);
  await issueCredential(ctx.db, { identityId: svc.id, kind: "service", name: "svc-expired", expiresAt: "2026-01-01T00:00:00.000Z", actorIdentityId: alice, organizationId: orgs.ids });
  await issueCredential(ctx.db, { identityId: svc.id, kind: "oidc", name: "gh-actions", expiresAt: "2099-01-01T00:00:00.000Z" });
  await db.query(
    "UPDATE credentials SET last_used_at = '2026-02-01T10:00:00.000Z', use_count = 4, client = 'varlatch-cli/0.22.0' WHERE identity_id = $1 AND name = 'svc-limited'",
    [svc.id],
  );
  // The Broker's agent-run credentials, then the second Agent and old retired.
  await call("POST", `${ORG}/ids/identities/${agent.id}/credentials`, { ttlSeconds: 600, runId: "setup-run" }, tokens.broker);
  await call("POST", `${ORG}/ids/identities/${agentOff.id}/credentials`, { ttlSeconds: 600, runId: "off-run" }, tokens.broker);
  await call("POST", `${ORG}/ids/identities/${agentOff.id}/retire`);
  await call("POST", `${ORG}/ids/identities/${old.id}/retire`);
  void wl;

  // People: bob a member, dave an admin with a profile, erin a former member, carol in none.
  const person = async (name: string, role?: "member" | "admin", removed = false) => {
    const id = newId("identity");
    await db.query("INSERT INTO identities (id, kind, name, created_at) VALUES ($1, 'human', $2, '2026-01-01T00:00:00.000Z')", [id, name]);
    if (role) {
      await db.query(
        "INSERT INTO org_memberships (organization_id, identity_id, role, removed_at) VALUES ($1, $2, $3, $4)",
        [orgs.ids, id, role, removed ? "2026-02-01T00:00:00.000Z" : null],
      );
    }
    tokens[name] = (await issueCredential(ctx.db, { identityId: id, kind: "cli" })).token;
    return id;
  };
  await person("bob", "member");
  await person("carol");
  const dave = await person("dave", "admin");
  await person("erin", "member", true);
  await db.query(`INSERT INTO "user" (id, name, email, image, "createdAt", "updatedAt") VALUES ('UserDave00001', 'dave', 'dave@varlatch.placeholder.invalid', 'https://avatars.invalid/dave.png', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`);
  await db.query("INSERT INTO auth_user_links (better_auth_user_id, identity_id, created_at) VALUES ('UserDave00001', $1, '2026-01-01T00:00:00.000Z')", [dave]);
  await db.query("UPDATE identities SET last_seen_at = '2026-02-02T00:00:00.000Z' WHERE id = $1", [svc.id]);

  // other: a Broker and a service identity of its own.
  tokens.obroker = (await machine("other", "obroker", "broker")).credential;
  await machine("other", "osvc", "service");

  // frozen: identities, a Broker's agent-run credential, then the freeze.
  await machine("frozen", "fsvc", "service");
  await machine("frozen", "fsvc2", "service");
  const fbroker = await machine("frozen", "fbroker", "broker");
  tokens.fbroker = fbroker.credential;
  const fagent = await machine("frozen", "fagent", "agent");
  await call("POST", `${ORG}/frozen/identities/${fagent.id}/credentials`, { ttlSeconds: 600, runId: "f-run" }, tokens.fbroker);
  await db.query(
    "INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', 'incident drill')",
    [newId("organizationFreeze"), orgs.frozen, alice],
  );

  // deleting: a deletion scheduled, one identity suspended by it.
  const susp = await machine("deleting", "susp", "service");
  await machine("deleting", "dsvc", "service");
  const deletion = newId("organizationDeletion");
  await db.query(
    "INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required) VALUES ($1, $2, $3, '2026-03-01T00:00:00.000Z', '2099-03-01T00:00:00.000Z', false)",
    [deletion, orgs.deleting, alice],
  );
  await db.query("UPDATE identities SET disabled = true, suspended_by_deletion = $1 WHERE id = $2", [deletion, susp.id]);

  // rep and enf: identities before their controls, one retired in each.
  await machine("rep", "rsvc", "service");
  const rold = await machine("rep", "rold", "service");
  await call("POST", `${ORG}/rep/identities/${rold.id}/retire`);
  const esvc = await machine("enf", "esvc", "service");
  const eold = await machine("enf", "eold", "service");
  await call("POST", `${ORG}/enf/identities/${eold.id}/retire`);
  const set = (org: string, control: string, body: unknown) => call("PATCH", `${ORG}/${org}/security/controls/${control}`, body);
  await set("rep", "admin-step-up", { mode: "report", expectedVersion: 0 });
  await set("rep", "credential-lifetime", { mode: "report", config: LIFETIME_REP, expectedVersion: 0 });
  await set("enf", "admin-step-up", { mode: "report", expectedVersion: 0 });
  await set("enf", "admin-step-up", { mode: "enforce", expectedVersion: 1 });
  await set("enf", "credential-lifetime", { mode: "enforce", config: LIFETIME_ENF, expectedVersion: 0 });

  // Approval intents of alice's second CLI credential in enf, each binding
  // one request of the table exactly as the operation binds it.
  const intent = async (id: string, binding: ApprovalBinding, approved: boolean) =>
    db.query(
      `INSERT INTO approval_intents
         (id, credential_id, identity_id, organization_id, operation, target, body_hash, query_hash, expected_version, summary, origin,
          created_at, expires_at, poll_interval, approved_at, approved_with_passkey_id, approval_user_verified)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, NULL, $9::jsonb, 'cli',
               '2026-01-10T00:00:00.000Z', '2099-01-01T00:00:00.000Z', 5, $10, $11, $12)`,
      [
        id, alice2.credentialId, alice, orgs.enf, binding.operation, canonicalJson(binding.target),
        approvalHash(ctx.rootKek, "body", binding.body), approvalHash(ctx.rootKek, "query", binding.query),
        JSON.stringify(binding.summary),
        approved ? "2026-01-10T00:01:00.000Z" : null, approved ? "PasskeyConf001" : null, approved ? true : null,
      ],
    );
  const enf = { id: orgs.enf! };
  const def = LIFETIME_ENF.defaultTtlSeconds;
  await intent(APPROVALS.create, identityCreateBinding(enf, { name: "approved", kind: "service" }, true, def), true);
  await intent(APPROVALS.otherBody, identityCreateBinding(enf, { name: "something else", kind: "service" }, true, def), true);
  await intent(APPROVALS.pending, identityCreateBinding(enf, { name: "pending", kind: "service" }, true, def), false);
  await intent(APPROVALS.issue, credentialIssueBinding(enf, { id: esvc.id, name: "esvc", kind: "service", disabled: false, suspendedByDeletion: false }, { name: "approved-cred" }, def), true);
  await intent(APPROVALS.reactivate, identityReactivateBinding(enf, { id: eold.id, name: "eold", kind: "service", disabled: true, suspendedByDeletion: false }), true);
  await accessCountsSettled();
  // The setup's own sign-ins leave last-seen and last-used times a minute
  // apart at most from a replay that runs at once, which would then leave
  // them as they are, and a later one would not: an old time instead, which
  // every replay's first use moves on.
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
        comment: "Written by services/varlatchd/test/go-identities-fixture.test.ts from the TypeScript server's own answers; do not edit.",
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

describe("the identities fixture is this server's answers", () => {
  it("identities-v0.22.0.json", async () => {
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
