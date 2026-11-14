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
import {
  lackingChecks,
  lacksProblems,
  NOT_IMPLEMENTED_YET,
  openapiOperations,
  operationProblems,
  operationsOf,
  placeholderPath,
  probeFor,
  setupLacks,
  staleBecause,
} from "../lib/operations.mjs";
import { parseSuiteOutput, resultLine } from "../lib/results.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..", "..");
const inventory = JSON.parse(readFileSync(join(here, "..", "inventory.json"), "utf8"));
const openapi = openapiOperations(readFileSync(join(repoRoot, "packages/protocol/openapi.yaml"), "utf8"));
const goExpect = JSON.parse(readFileSync(join(here, "..", "expect", "go-binary.json"), "utf8"));

test("the OpenAPI table is the routes the Go server is generated with", () => {
  const gen = readFileSync(join(repoRoot, "go/server/api/api.gen.go"), "utf8");
  const routes = [...gen.matchAll(/^\tm\.HandleFunc\(http\.Method(\w+)\+" "\+options\.BaseURL\+"([^"]+)", wrapper\.(\w+)\)/gm)];
  assert.ok(routes.length > 150);
  assert.equal(openapi.size, routes.length);
  for (const [, method, path, wrapper] of routes) {
    const id = wrapper[0].toLowerCase() + wrapper.slice(1);
    assert.deepEqual(openapi.get(id), { method: method.toUpperCase(), path: `/v1${path}` }, id);
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
  assert.ok(bySeed.has("cli-core.login-token-stores-credential"));
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

test("expect/go-binary.json lacks every operation but the ones the Go server has, each with a step of ADR-0059 step 3 or 4", () => {
  assert.deepEqual(validateExpectations(goExpect, { targetName: "go-binary", inventory, cliVersions: ["0.21.0", "0.22.0"], openapi }), []);
  const lacks = lacksFor(goExpect, "go-binary");
  const built = ["getMeta"];
  for (const id of openapi.keys()) assert.equal(lacks.has(id), !built.includes(id), id);
  for (const [name, op] of Object.entries(inventory.operations)) assert.equal(lacks.has(name), !op.uses, name);
  for (const [op, e] of lacks) assert.match(e.step, /^ADR-0059 step (3\.[3-6]|4)$/, op);
  // Every conformance check that needs the target lacks something on it, but
  // the CLI-download-off checks, which need only /v1/meta.
  const lacking = lackingChecks(inventory, lacks.keys());
  const runs = Object.entries(inventory.checks).filter(([id, c]) => c.kind === "conformance" && !lacking.has(id) && inventory.suites[c.suite].runner !== true).map(([id]) => id);
  assert.deepEqual(runs.sort(), Object.keys(inventory.checks).filter((id) => id.startsWith("cli-download-off.")).sort());
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
