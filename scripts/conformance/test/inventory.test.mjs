// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import { compareVersions, evaluate, validateInventory } from "../lib/inventory.mjs";

const base = () => ({
  schema: 1,
  suites: {
    web: { title: "web", script: "apps/web/scripts/e2e-web.mjs" },
    stack: { title: "stack", script: "s.mjs", needs: ["ts-stack"] },
    stub: { title: "stub", script: "t.mjs" },
  },
  checks: {
    "web.csp-strict": { suite: "web", kind: "conformance", title: "strict CSP" },
    "web.types-python": { suite: "web", kind: "conformance", title: "Python module", introducedIn: "0.12.0" },
    "web.whoami": { suite: "web", kind: "conformance", title: "whoami", core: true },
    "stack.convex": { suite: "stack", kind: "ts-stack", title: "Convex", replacement: "web.csp-strict" },
    "stack.reconcile": { suite: "stack", kind: "ts-stack", title: "reconcile", replacement: { none: "no Convex" } },
    "stack.doctor": { suite: "stack", kind: "ts-stack", title: "doctor", replacement: { open: "step 6" } },
    "stub.page": { suite: "stub", kind: "component", title: "page" },
  },
});

test("a well-formed inventory has no problems", () => {
  assert.deepEqual(validateInventory(base()), []);
});

test("each ts-stack check names a conformance replacement, none with a reason, or an open step", () => {
  const cases = [
    [undefined, /names its replacement/],
    ["web.missing", /not in the inventory/],
    ["stack.reconcile", /not a conformance check/],
    [{ none: "" }, /replacement must be/],
    [{ none: "x", open: "y" }, /replacement must be/],
    [{ later: "x" }, /replacement must be/],
  ];
  for (const [replacement, problem] of cases) {
    const inv = base();
    inv.checks["stack.convex"].replacement = replacement;
    if (replacement === undefined) delete inv.checks["stack.convex"].replacement;
    assert.match(validateInventory(inv).join("\n"), problem, JSON.stringify(replacement));
  }
  const inv = base();
  inv.checks["web.csp-strict"].replacement = "stack.convex";
  assert.match(validateInventory(inv).join("\n"), /only a ts-stack check has a replacement/);
});

test("IDs, suites, kinds, capabilities and versions are checked", () => {
  const inv = base();
  inv.checks["Web.Bad"] = { suite: "web", kind: "conformance", title: "x" };
  inv.checks["other.thing"] = { suite: "web", kind: "conformance", title: "x" };
  inv.checks["web.kind"] = { suite: "web", kind: "smoke", title: "x" };
  inv.checks["web.nosuite"] = { suite: "nope", kind: "conformance", title: "x" };
  inv.checks["web.version"] = { suite: "web", kind: "conformance", title: "x", introducedIn: "0.12" };
  inv.checks["web.core-gated"] = { suite: "web", kind: "conformance", title: "x", core: true, introducedIn: "0.12.0" };
  inv.checks["web.untitled"] = { suite: "web", kind: "conformance" };
  inv.suites.stack.needs.push("psql");
  inv.suites.empty = { title: "empty", script: "e.mjs" };
  const problems = validateInventory(inv).join("\n");
  for (const expected of [
    /Web\.Bad: not a check ID/,
    /other\.thing: its ID must start with its suite, web\./,
    /web\.kind: kind must be one of/,
    /web\.nosuite: unknown suite nope/,
    /web\.version: introducedIn must be x\.y\.z/,
    /web\.core-gated: a compatibility-core check is never version-gated/,
    /web\.untitled: no title/,
    /suite stack: unknown capability psql/,
    /suite empty: no checks/,
  ]) {
    assert.match(problems, expected);
  }
  assert.deepEqual(validateInventory({ schema: 2 }), ["schema: expected 1"]);
});

const pass = (suite, id) => ({ suite, id, status: "PASS", text: "" });
const all = () => [pass("web", "web.csp-strict"), pass("web", "web.types-python"), pass("web", "web.whoami"), pass("stack", "stack.convex"), pass("stack", "stack.reconcile"), pass("stack", "stack.doctor"), pass("stub", "stub.page")];
const outcome = (run, id) => run.checks.find((c) => c.id === id);

test("a run where every check passed is ok", () => {
  const run = evaluate({ inventory: base(), reports: all() });
  assert.equal(run.ok, true);
  assert.deepEqual(run.problems, []);
});

test("a check in the inventory that did not report fails the run", () => {
  const run = evaluate({ inventory: base(), reports: all().filter((r) => r.id !== "stub.page") });
  assert.equal(run.ok, false);
  assert.deepEqual(outcome(run, "stub.page"), { id: "stub.page", suite: "stub", kind: "component", outcome: "fail", why: "did not report", reports: 0 });
});

test("a reported check that is not in the inventory, or comes from another suite, fails the run", () => {
  let run = evaluate({ inventory: base(), reports: [...all(), pass("web", "web.extra")] });
  assert.equal(run.ok, false);
  assert.match(run.problems.join(), /web\.extra, which is not in the inventory/);
  run = evaluate({ inventory: base(), reports: [...all(), pass("stub", "web.csp-strict")] });
  assert.equal(run.ok, false);
  assert.match(run.problems.join(), /reported web\.csp-strict, which belongs to web/);
});

test("not applicable: allowed for ts-stack checks only", () => {
  const na = (suite, id) => ({ suite, id, status: "N/A", text: "the target lacks ts-stack" });
  let run = evaluate({ inventory: base(), reports: [...all().filter((r) => r.suite !== "stack"), na("stack", "stack.convex"), na("stack", "stack.reconcile"), na("stack", "stack.doctor")] });
  assert.equal(run.ok, true);
  assert.equal(outcome(run, "stack.convex").outcome, "not-applicable");
  for (const [suite, id] of [["web", "web.csp-strict"], ["stub", "stub.page"]]) {
    run = evaluate({ inventory: base(), reports: [...all().filter((r) => r.id !== id), na(suite, id)] });
    assert.equal(run.ok, false, id);
    assert.match(outcome(run, id).why, /reported not applicable/);
  }
});

test("a check reported more than once passes only if every report passed and they agree", () => {
  let run = evaluate({ inventory: base(), reports: [...all(), { ...pass("web", "web.csp-strict"), status: "FAIL", text: "second case" }] });
  assert.equal(outcome(run, "web.csp-strict").outcome, "fail");
  assert.equal(outcome(run, "web.csp-strict").why, "second case");
  run = evaluate({ inventory: base(), reports: [...all(), { suite: "stack", id: "stack.convex", status: "N/A", text: "" }] });
  assert.match(outcome(run, "stack.convex").why, /inconsistently/);
  run = evaluate({ inventory: base(), reports: [...all(), pass("web", "web.csp-strict")] });
  assert.equal(run.ok, true);
});

test("an error outside a check fails the run, even when every check passed", () => {
  const run = evaluate({ inventory: base(), reports: all(), errors: [{ suite: "web", message: "exited 1 without reporting a failed check" }] });
  assert.equal(run.ok, false);
  assert.deepEqual(run.problems, ["web: exited 1 without reporting a failed check"]);
});

test("predates-cli is accepted only when the runner confirms the CLI is older than the feature", () => {
  const predates = (id) => ({ suite: "web", id, status: "PREDATES-CLI", text: "" });
  const reports = (id) => [...all().filter((r) => r.id !== id), predates(id)];
  let run = evaluate({ inventory: base(), reports: reports("web.types-python"), cliVersion: "0.11.0" });
  assert.equal(run.ok, true);
  assert.equal(outcome(run, "web.types-python").outcome, "predates-cli");
  for (const [cliVersion, why] of [
    ["0.12.0", /not older than 0\.12\.0/],
    ["0.13.1", /not older than/],
    [null, /built from source/],
  ]) {
    run = evaluate({ inventory: base(), reports: reports("web.types-python"), cliVersion });
    assert.equal(run.ok, false, String(cliVersion));
    assert.match(outcome(run, "web.types-python").why, why);
  }
  run = evaluate({ inventory: base(), reports: reports("web.csp-strict"), cliVersion: "0.1.0" });
  assert.match(outcome(run, "web.csp-strict").why, /names no version/);
  run = evaluate({ inventory: base(), reports: reports("web.whoami"), cliVersion: "0.1.0" });
  assert.match(outcome(run, "web.whoami").why, /compatibility-core/);
});

test("compareVersions orders x.y.z numerically", () => {
  assert.equal(compareVersions("0.9.0", "0.10.0"), -1);
  assert.equal(compareVersions("0.22.0", "0.22.0"), 0);
  assert.equal(compareVersions("1.0.0", "0.99.99"), 1);
});
