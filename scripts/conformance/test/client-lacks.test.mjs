// SPDX-License-Identifier: Apache-2.0
/**
 * The Go CLI's declared gaps (lib/client-lacks.mjs) and how a run judges
 * client-lacks (lib/inventory.mjs evaluate): only the runner reports it,
 * only for a check that needs a lacking feature, and the real
 * client-go.json is valid against the real inventory.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { clientLackingChecks, featuresNeeded, loadClientLacks, validateClientLacks, withoutLacking } from "../lib/client-lacks.mjs";
import { evaluate } from "../lib/inventory.mjs";

const inventory = {
  features: { "login-token": { core: true }, scan: { introducedIn: "0.11.0" }, run: { core: true } },
  suites: { a: { cliNeeds: ["login-token"] }, b: {} },
  checks: {
    "a.scan": { suite: "a", kind: "conformance", feature: "scan" },
    "a.plain": { suite: "a", kind: "conformance", cliNeeds: ["run"] },
    "a.scan-run": { suite: "a", kind: "conformance", feature: "scan", cliNeeds: ["run"] },
    "b.free": { suite: "b", kind: "conformance" },
  },
};

test("a check needs its suite's setup features, its own, and its cliNeeds", () => {
  assert.deepEqual(featuresNeeded(inventory, "a.scan"), ["login-token", "scan"]);
  assert.deepEqual(featuresNeeded(inventory, "a.plain"), ["login-token", "run"]);
  assert.deepEqual(featuresNeeded(inventory, "a.scan-run"), ["login-token", "run", "scan"]);
  assert.deepEqual(featuresNeeded(inventory, "b.free"), []);
});

test("the lacking checks are those that need a lacking feature, and none without lacks", () => {
  assert.deepEqual([...clientLackingChecks(inventory, new Map([["scan", {}]]))], [["a.scan", ["scan"]], ["a.scan-run", ["scan"]]]);
  // A check with a feature of its own still lacks what its cliNeeds lists.
  assert.deepEqual([...clientLackingChecks(inventory, new Map([["run", {}]]))], [["a.plain", ["run"]], ["a.scan-run", ["run"]]]);
  assert.deepEqual([...clientLackingChecks(inventory, new Map([["login-token", {}]])).keys()], ["a.scan", "a.plain", "a.scan-run"]);
  assert.equal(clientLackingChecks(inventory, new Map()).size, 0);
});

test("a lacking check's result is dropped, and a PASS among them is stale", () => {
  const lacking = new Map([["a.scan", ["scan"]]]);
  const results = [
    { id: "a.scan", status: "PASS" },
    { id: "a.plain", status: "FAIL" },
  ];
  const { kept, stale } = withoutLacking(results, new Set(["a.scan"]), lacking);
  assert.deepEqual(kept, [{ id: "a.plain", status: "FAIL" }]);
  assert.deepEqual(stale, [{ id: "a.scan", features: ["scan"] }]);
  assert.deepEqual(withoutLacking([{ id: "a.scan", status: "FAIL" }], new Set(["a.scan"]), lacking).stale, []);
});

test("client-lacks counts only from the runner, and only for a check that needs a lacking feature", () => {
  const clientLacking = new Map([["a.scan", ["scan"]]]);
  const judge = (reports) => evaluate({ inventory, reports, clientLacking }).checks.find((c) => c.id === reports[0].id);
  assert.equal(judge([{ suite: "a", id: "a.scan", status: "CLIENT-LACKS", runner: true }]).outcome, "client-lacks");
  const bySuite = judge([{ suite: "a", id: "a.scan", status: "CLIENT-LACKS" }]);
  assert.equal(bySuite.outcome, "fail");
  assert.match(bySuite.why, /only the runner can/);
  const unneeded = judge([{ suite: "b", id: "b.free", status: "CLIENT-LACKS", runner: true }]);
  assert.equal(unneeded.outcome, "fail");
  assert.match(unneeded.why, /needs no feature the client lacks/);
});

test("client-go.json's shape: known features, a reason and the slice that builds it", () => {
  assert.deepEqual(validateClientLacks({ schema: 1, lacksFeatures: { scan: { reason: "r", slice: "5.4d" } } }, inventory), []);
  assert.match(validateClientLacks({ schema: 1, lacksFeatures: { nope: { reason: "r", slice: "5.4d" } } }, inventory)[0], /not a feature/);
  assert.match(validateClientLacks({ schema: 1, lacksFeatures: { scan: { reason: "r", slice: "soon" } } }, inventory)[0], /must be/);
  assert.match(validateClientLacks({ schema: 2 }, inventory)[0], /schema/);
});

test("the real client-go.json is valid against the real inventory", () => {
  const real = JSON.parse(readFileSync(new URL("../inventory.json", import.meta.url), "utf8"));
  const file = JSON.parse(readFileSync(new URL("../client-go.json", import.meta.url), "utf8"));
  assert.deepEqual(validateClientLacks(file, real), []);
  assert.ok(loadClientLacks().size > 0);
});
