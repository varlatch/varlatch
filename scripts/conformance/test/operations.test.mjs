// SPDX-License-Identifier: Apache-2.0
// Operations and declared gaps (lib/operations.mjs): the OpenAPI table, the
// inventory's needs, target-lacks as a runner-only result, the gate.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { lacksFor, validateExpectations } from "../lib/expect.mjs";
import { judgeGate } from "../lib/gate.mjs";
import { evaluate } from "../lib/inventory.mjs";
import { lackingChecks, lacksProblems, NOT_IMPLEMENTED_YET, openapiOperations, operationProblems, operationsOf, placeholderPath, probeFor, setupLacks, skippedGroupProblems, skippedGroups, staleBecause } from "../lib/operations.mjs";
import { parseSuiteOutput, resultLine } from "../lib/results.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..", "..");
const inventory = JSON.parse(readFileSync(join(here, "..", "inventory.json"), "utf8"));
const openapi = openapiOperations(readFileSync(join(repoRoot, "packages/protocol/openapi.yaml"), "utf8"));
const goExpect = JSON.parse(readFileSync(join(here, "..", "expect", "go-binary.json"), "utf8"));

test("the OpenAPI table is the routes the Go server is generated with", () => {
  // /v1 (go/server/api, served under /v1) and the browser session's paths
  // (go/server/api/browser, served at the root).
  const routesOf = (file, base) =>
    [...readFileSync(join(repoRoot, file), "utf8").matchAll(/^\tm\.HandleFunc\(http\.Method(\w+)\+" "\+options\.BaseURL\+"([^"]+)", wrapper\.(\w+)\)/gm)].map(
      ([, method, path, wrapper]) => ({ method, path: `${base}${path}`, wrapper }),
    );
  const v1 = routesOf("go/server/api/api.gen.go", "/v1");
  const browser = routesOf("go/server/api/browser/browser.gen.go", "");
  assert.ok(v1.length > 150);
  assert.ok(browser.length >= 7 && browser.every((r) => r.path.startsWith("/auth/")));
  assert.equal(openapi.size, v1.length + browser.length);
  for (const { method, path, wrapper } of [...v1, ...browser]) {
    const id = wrapper[0].toLowerCase() + wrapper.slice(1);
    assert.deepEqual(openapi.get(id), { method: method.toUpperCase(), path }, id);
  }
  assert.equal(placeholderPath("/v1/organizations/{org}/projects/{project}"), "/v1/organizations/placeholder/projects/placeholder");
});

test("operations: every name known; named operations well formed", () => {
  assert.deepEqual(operationProblems(inventory, openapi), []);
  const bad = {
    ...inventory,
    operations: {
      ...inventory.operations,
      getMeta: { title: "clash", method: "GET", path: "/x" },
      "no-kind": { title: "x" },
      "two-kinds": { title: "x", target: "bootstrap", uses: ["getMeta"] },
      "v1-path": { title: "x", method: "GET", path: "/v1/meta" },
      "bad-target": { title: "x", target: "migrate" },
      "nested-seed": { title: "x", uses: ["seed"] },
    },
    suites: { ...inventory.suites, mcp: { ...inventory.suites.mcp, operations: ["getMeta", "getMeta", "noSuchOperation"] } },
  };
  const problems = operationProblems(bad, openapi).join("\n");
  for (const want of [
    /operation getMeta: is also an OpenAPI operationId/,
    /operation no-kind: names exactly one/,
    /operation two-kinds: names exactly one/,
    /operation v1-path: path must be a route outside \/v1/,
    /operation bad-target: target must be one of/,
    /operation nested-seed: uses seed, which uses others/,
    /suite mcp: getMeta is listed twice/,
    /suite mcp: noSuchOperation is neither/,
  ]) assert.match(problems, want);
});

test("a group is skipped only when every one of its checks lacks an operation", () => {
  const audit = Object.entries(inventory.checks).filter(([, c]) => c.suite === "client-runtime" && c.group === "audit-export").map(([id]) => id);
  assert.deepEqual([...skippedGroups(inventory, "client-runtime", audit)], ["audit-export"]);
  assert.deepEqual([...skippedGroups(inventory, "client-runtime", audit.slice(1))], []);
  assert.deepEqual([...skippedGroups(inventory, "client-runtime", [])], []);
  // From the target's lacks, as the runner reads them.
  assert.ok(skippedGroups(inventory, "client-runtime", lackingChecks(inventory, ["exportAuditEvents"]).keys()).has("audit-export"));
  assert.ok(!skippedGroups(inventory, "client-runtime", lackingChecks(inventory, ["exportAuditEvents"]).keys()).has("service-identities"));
});

// The runner's guard (run.mjs calls skippedGroupProblems with the CLI's
// verified version): a result for a check of a skipped group fails the
// run; PREDATES-CLI passes only when the CLI really predates the feature.
test("a skipped group's check may report only a PREDATES-CLI the CLI's version confirms", () => {
  const lacked = lackingChecks(inventory, ["exportAuditEvents"]).keys();
  const scan = "client-runtime.scan-nothing-read-nothing-disclosed"; // feature scan, introduced in 0.11.0
  const plain = "client-runtime.audit-export-holds-no-value"; // no feature
  const run = (results, cliVersion) => skippedGroupProblems(inventory, "client-runtime", [...lackingChecks(inventory, ["exportAuditEvents"]).keys()], results, cliVersion);
  assert.equal(inventory.features.scan.introducedIn, "0.11.0");
  assert.ok([...lacked].includes(scan));
  // A legitimate old-CLI skip.
  assert.deepEqual(run([{ id: scan, status: "PREDATES-CLI" }], "0.10.0"), []);
  // A bogus one: a CLI built from source, or one not older, or a check
  // with no feature.
  for (const [results, version] of [
    [[{ id: scan, status: "PREDATES-CLI" }], null],
    [[{ id: scan, status: "PREDATES-CLI" }], "0.11.0"],
    [[{ id: scan, status: "PREDATES-CLI" }], "0.22.0"],
    [[{ id: plain, status: "PREDATES-CLI" }], "0.10.0"],
  ]) {
    assert.match(run(results, version).join(), /operation group audit-export is skipped on this target/, `${results[0].id} at ${version}`);
  }
  for (const status of ["PASS", "FAIL", "N/A"]) assert.equal(run([{ id: scan, status }], "0.10.0").length, 1, status);
  // A check of a group that runs is none of the guard's business.
  assert.deepEqual(run([{ id: "client-runtime.redact-run-exits-child-status", status: "PASS" }], null), []);
});

test("a check in an operation group needs its suite's, its group's and its own operations", () => {
  const id = "client-runtime.export-context-run-cannot-export-context";
  const ops = operationsOf(inventory, id);
  for (const op of ["createProject", "createServiceIdentity", "createGrant", "exportAuditEvents"]) assert.ok(ops.includes(op), op);
  // A check outside the group does not need the group's operations.
  assert.ok(!operationsOf(inventory, "client-runtime.redact-run-exits-child-status").includes("createServiceIdentity"));
  const lacking = lackingChecks(inventory, ["exportAuditEvents"]);
  assert.deepEqual(lacking.get(id), ["exportAuditEvents"]);
  assert.ok(lacking.has("client-runtime.audit-export-holds-no-value") && !lacking.has("client-runtime.export-context-identity-without-secret-reveal"));
});

test("a check needs its suite's operations and its own; the seed lacks when an operation it uses does", () => {
  const inv = structuredClone(inventory);
  inv.checks["mcp.lists-read-tools-only"] = { ...inv.checks["mcp.lists-read-tools-only"], operations: ["strictRetrieval"] };
  assert.ok(operationsOf(inv, "mcp.lists-read-tools-only").includes("strictRetrieval"));
  assert.ok(!operationsOf(inv, "mcp.reads-effective-configuration").includes("strictRetrieval"));
  // Only strictRetrieval lacking: the one check that adds it.
  assert.deepEqual([...lackingChecks(inv, ["strictRetrieval"]).keys()].filter((id) => id.startsWith("mcp.")), ["mcp.lists-read-tools-only"]);
  // An operation only the seed uses: every check whose suite needs the seed lacks it, by name.
  const bySeed = lackingChecks(inventory, ["pushContractRevision"]);
  assert.deepEqual(bySeed.get("mcp.lists-read-tools-only"), ["seed"]);
  // cli-core: its env list group needs the seed; its token sign-in does not.
  assert.ok(bySeed.has("cli-core.env-list-json") && !bySeed.has("cli-core.login-token-stores-credential"));
  assert.ok(!bySeed.has("cli-download-off.install-sh-404"));
  assert.ok(setupLacks(inventory, "seed", ["admin-recover"]));
  assert.ok(!setupLacks(inventory, "seed", ["getMeta"]));
  assert.ok(setupLacks(inventory, "admin-bootstrap", ["admin-bootstrap"]));
  // The runner holds the gaps as a Map (operation → entry).
  assert.ok(setupLacks(inventory, "seed", new Map([["setValue", {}]])));
  assert.ok(lackingChecks(inventory, new Map([["whoami", {}]])).has("cli-core.whoami-human-format"));
});

test("lacks entries: a known operation (never the seed itself), a reason and the step that adds it", () => {
  assert.deepEqual(lacksProblems("x", { whoami: { reason: "r", step: "s" }, "admin-recover": { reason: "r", step: "s" } }, { inventory, openapi }), []);
  const problems = lacksProblems("x", { noSuch: { reason: "r", step: "s" }, seed: { reason: "r", step: "s" }, whoami: { reason: "r" }, getMeta: { reason: "", step: "s" } }, { inventory, openapi }).join("\n");
  assert.match(problems, /noSuch is neither/);
  assert.match(problems, /seed is never listed/);
  assert.match(problems, /whoami must be \{ "reason"/);
  assert.match(problems, /getMeta must be \{ "reason"/);
  const file = { schema: 1, expected: {}, lacks: { "ts-source": { whoami: { reason: "r", step: "s" } } } };
  assert.match(validateExpectations(file, { targetName: "go-binary", inventory, cliVersions: [], openapi }).join("\n"), /ts-source is not a go-binary target/);
});

test("expect/go-binary.json lacks every operation but the ones the Go server has, each with a step of ADR-0059 step 4 (serving the CLI: step 6)", () => {
  assert.deepEqual(validateExpectations(goExpect, { targetName: "go-binary", inventory, cliVersions: ["0.21.0", "0.22.0"], openapi }), []);
  const lacks = lacksFor(goExpect, "go-binary");
  // ADR-0059 step 3.4: the browser session's paths, and the /v1 operations
  // sessions, passkeys (with the step-up approval a trusted passkey's
  // removal can need), credentials and device sign-in need.
  const built = [
    "getMeta",
    "whoami", "getMyProfile", "listMyCredentials", "exchangeCliCredential", "revokeMyCredential",
    "listMyPasskeys", "removeMyPasskey", "startPasskeyConfirmation", "confirmMyPasskey",
    "getApproval", "startApproval", "approveApproval", "cancelApproval",
    "startDeviceSignIn", "collectDeviceSignIn", "lookupDeviceSignIn", "decideDeviceSignIn", "listOrganizations",
    "getBrowserSession", "startPasskeySignIn", "finishPasskeySignIn", "startPasskeyRegistration", "finishPasskeyRegistration",
    "signOut", "mintBrowserBearer",
    // Step 3.5: the dashboard's live updates.
    "streamBrowserEvents",
    // Step 3.6: the read path of values.
    "getEffectiveConfiguration", "discloseSecrets",
    // Step 4.1a: Organizations.
    "createOrganization", "getOrganization", "renameOrganization",
    // Step 4.1b: Contracts.
    "getActiveContract", "pushContractRevision", "getContractRevision", "activateContractRevision",
    // Step 4.1c: Projects and environments, and the two installation reads.
    "listProjects", "createProject", "getProject", "renameProject",
    "listEnvironments", "createEnvironment", "getEnvironment", "deleteEnvironment",
    "getInstallationRelease", "getInstallationBackups",
    // Step 4.1d: the writes of values.
    "setValue", "deleteValue", "applyChangeSet",
    "validateEnvironment", "strictRetrieval", "searchConfigItems",
    // Step 4.3a: Security Controls.
    "listSecurityControls", "changeSecurityControl", "securityControlReport", "securityApprovalKeys",
  ];
  for (const id of openapi.keys()) assert.equal(lacks.has(id), !built.includes(id), id);
  // Of the named operations only serving the CLI is lacking (the seed is
  // lacking through the writes it uses, never listed).
  for (const [name, op] of Object.entries(inventory.operations)) assert.equal(lacks.has(name), !op.uses && name === "serve-cli", name);
  // Serving the CLI waits for the Go CLI and installers (feature-parity
  // decision 13); every other gap is step 4's.
  for (const [op, e] of lacks) assert.equal(e.step, op === "serve-cli" ? "ADR-0059 step 6" : "ADR-0059 step 4", op);
  // The conformance checks the Go server runs (step 3.4): the passkey
  // bootstrap, the CLI's token sign-in and whoami, the CLI browser login,
  // device sign-in with the dashboard's sign-in and the proxy probe's
  // pending cap, and the CLI-download-off checks, which need only /v1/meta;
  // and (step 3.5) degraded live updates; (step 3.6) the read path of
  // values, varlatch mcp's reads and the server logs check; (step 4.1c)
  // cli-core's env list checks, on the Projects and environments reads;
  // (step 4.1d) the sdk suite, on the value writes. Each seeds through
  // /v1. And (4.1e, feature-parity decision 2) every check of the suites
  // split into operation groups whose group and own operations are built:
  // the dashboard, values, p4, onboarding, client-runtime and strict-run,
  // but for their groups on audit, webhooks, rotation, Requirements,
  // service identities and agent-safe runs, and the three checks that read
  // the audit log or identities themselves. (4.3a) The security suite, on
  // the Security Controls. Every other one lacks something.
  const lacking = lackingChecks(inventory, lacks.keys());
  const runs = Object.entries(inventory.checks).filter(([id, c]) => c.kind === "conformance" && !lacking.has(id) && inventory.suites[c.suite].runner !== true).map(([id]) => id);
  // G11's go-server checks (step 3.5) lack nothing either.
  assert.deepEqual(
    Object.entries(inventory.checks).filter(([id, c]) => c.kind === "go-server" && !lacking.has(id)).map(([id]) => id).sort(),
    Object.keys(inventory.checks).filter((id) => id.startsWith("realtime-events.")).sort(),
  );
  const notYet = {
    dashboard: ["audit-feed"], values: ["rotation", "tailnet"], p4: ["audit", "webhooks"], onboarding: [],
    "client-runtime": ["service-identities", "audit-export"], "strict-run": ["service-identities", "agent-safe"],
  };
  const ownLacking = ["values.row-says-value-last-changed-filtered", "values.item-history-lists-item-changes-filtered", "onboarding.workload-invite-recommended-not-required"];
  const expected = Object.entries(inventory.checks).filter(([id, c]) =>
    /^(passkey|cli-login|device|proxy-probe|cli-download-off|realtime-degraded|mcp|server-logs|sdk|security)\./.test(id) ||
    ["cli-core.login-token-stores-credential", "cli-core.whoami-names-signed-in-identity", "cli-core.whoami-human-format",
      "cli-core.env-list-json", "cli-core.env-list-frozen-format"].includes(id) ||
    (c.suite in notYet && c.kind === "conformance" && !notYet[c.suite].includes(c.group) && !ownLacking.includes(id))).map(([id]) => id);
  assert.deepEqual(runs.sort(), expected.sort());
  assert.equal(runs.length, 247);
  // The groups still lacking lack exactly their own operations.
  for (const [suite, groups] of Object.entries(notYet)) {
    for (const g of groups) {
      const ids = Object.entries(inventory.checks).filter(([, c]) => c.suite === suite && c.group === g).map(([id]) => id);
      assert.ok(ids.length > 0 && ids.every((id) => lacking.has(id)), `${suite} ${g}`);
      for (const id of ids) assert.ok(lacking.get(id).every((op) => inventory.suites[suite].groups[g].operations.includes(op) || (inventory.checks[id].operations ?? []).includes(op)), id);
    }
  }
});

test("probes: a /v1 or named HTTP operation is asked by its route; a target operation through the adapter; the seed never", () => {
  assert.deepEqual(probeFor(inventory, openapi, "getOrganization"), { kind: "http", method: "GET", path: "/v1/organizations/placeholder" });
  assert.deepEqual(probeFor(inventory, openapi, "enroll-page"), { kind: "http", method: "GET", path: "/enroll" });
  assert.deepEqual(probeFor(inventory, openapi, "admin-recover"), { kind: "target", operation: "recover" });
  assert.equal(probeFor(inventory, openapi, "seed"), null);
  const stub = JSON.stringify({ error: { code: NOT_IMPLEMENTED_YET, message: "x", requestId: "req_1" } });
  assert.equal(staleBecause(501, stub), null);
  assert.match(staleBecause(200, "{}"), /answered 200, not 501/);
  assert.match(staleBecause(501, "not json"), /answered 501, not 501 NOT_IMPLEMENTED_YET/);
  assert.match(staleBecause(401, JSON.stringify({ error: { code: "AUTHENTICATION_REQUIRED" } })), /answered 401 AUTHENTICATION_REQUIRED/);
  assert.match(staleBecause(404, "404 Not Found"), /answered 404/);
});

test("target-lacks: only the runner reports it, only for a check that needs a lacking operation", () => {
  const id = "mcp.lists-read-tools-only";
  const lacking = new Map([[id, ["seed"]]]);
  const judge = (reports) => evaluate({ inventory: { ...inventory, checks: { [id]: inventory.checks[id] } }, reports, lacking: reports.lacking ?? lacking });
  let j = judge([{ suite: "mcp", id, status: "TARGET-LACKS", text: "", runner: true }]);
  assert.equal(j.ok, true);
  assert.equal(j.checks[0].outcome, "target-lacks");
  assert.match(j.checks[0].why, /the target lacks seed/);
  j = judge([{ suite: "mcp", id, status: "TARGET-LACKS", text: "" }]);
  assert.equal(j.ok, false);
  assert.match(j.checks[0].why, /only the runner can/);
  j = evaluate({ inventory: { ...inventory, checks: { [id]: inventory.checks[id] } }, reports: [{ suite: "mcp", id, status: "TARGET-LACKS", text: "", runner: true }], lacking: new Map() });
  assert.equal(j.ok, false);
  assert.match(j.checks[0].why, /needs no operation the target lacks/);
  // A suite that prints it has made an error.
  const parsed = parseSuiteOutput(`TARGET-LACKS  [${id}] the suite says so\nPASS  [mcp.x] y`);
  assert.equal(parsed.results.length, 1);
  assert.match(parsed.errors[0], /only the runner reports target-lacks/);
  assert.equal(resultLine("TARGET-LACKS", id, "z"), `TARGET-LACKS  [${id}] z`);
});

test("--gate refuses target-lacks and any lacking operation in force", () => {
  const run = { target: "go-binary:/x", partial: false, ok: true, checks: [{ id: "mcp.lists-read-tools-only", outcome: "target-lacks" }], expectedInForce: [], lacksInForce: ["whoami"], implementation: { sha256: "x" } };
  const gate = judgeGate({ inventory, run, walkthrough: { path: "docs/evidence/w.md", exists: true, size: 1, sha256: "x" } });
  assert.equal(gate.passed, false);
  assert.ok(gate.problems.some((p) => /no lacking operation is allowed, and go-binary:\/x declares 1: whoami/.test(p)));
  assert.ok(gate.problems.some((p) => /no check may report target-lacks, and 1 do: mcp\.lists-read-tools-only/.test(p)));
});
