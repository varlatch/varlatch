// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import { CORE_FEATURES, compareVersions, evaluate, gating, predates, validateInventory } from "../lib/inventory.mjs";

const cite = (release) => ({ release, quote: "the entry" });
/** Every compatibility-core feature, each with one conformance check in suite `core`. */
const coreFeatures = () => Object.fromEntries(CORE_FEATURES.map((f) => [f, { title: f, core: true, changelog: cite("0.1.0") }]));
const coreChecks = () => Object.fromEntries(CORE_FEATURES.map((f) => [`core.${f}`, { suite: "core", kind: "conformance", feature: f, title: f }]));

const base = () => ({
  schema: 1,
  features: {
    ...coreFeatures(),
    scan: { title: "varlatch scan", introducedIn: "0.12.0", changelog: cite("0.12.0") },
  },
  suites: {
    web: { title: "web", script: "apps/web/scripts/e2e-web.mjs" },
    stack: { title: "stack", script: "s.mjs", needs: ["ts-stack"] },
    stub: { title: "stub", script: "t.mjs" },
    core: { title: "core", script: "c.mjs" },
  },
  checks: {
    "web.csp-strict": { suite: "web", kind: "conformance", title: "strict CSP" },
    "web.scan-staged": { suite: "web", kind: "conformance", feature: "scan", title: "scan --staged" },
    "web.whoami": { suite: "web", kind: "conformance", feature: "whoami", title: "whoami" },
    "stack.convex": { suite: "stack", kind: "ts-stack", title: "Convex", replacement: "web.csp-strict" },
    "stack.reconcile": { suite: "stack", kind: "ts-stack", title: "reconcile", replacement: { none: "no Convex" } },
    "stack.doctor": { suite: "stack", kind: "ts-stack", title: "doctor", replacement: { open: "step 6" } },
    "stub.page": { suite: "stub", kind: "component", title: "page" },
    ...coreChecks(),
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
  inv.checks["web.version"] = { suite: "web", kind: "conformance", title: "x", introducedIn: "0.12.0" };
  inv.checks["web.core-flag"] = { suite: "web", kind: "conformance", title: "x", core: true };
  inv.checks["web.no-feature"] = { suite: "web", kind: "conformance", title: "x", feature: "nope" };
  inv.checks["stub.featured"] = { suite: "stub", kind: "component", title: "x", feature: "scan" };
  inv.checks["web.untitled"] = { suite: "web", kind: "conformance" };
  inv.suites.stack.needs.push("psql");
  inv.suites.empty = { title: "empty", script: "e.mjs" };
  const problems = validateInventory(inv).join("\n");
  for (const expected of [
    /Web\.Bad: not a check ID/,
    /other\.thing: its ID must start with its suite, web\./,
    /web\.kind: kind must be one of/,
    /web\.nosuite: unknown suite nope/,
    /web\.version: introducedIn belongs on the check's feature/,
    /web\.core-flag: core belongs on the check's feature/,
    /web\.no-feature: unknown feature nope/,
    /stub\.featured: a component check tests this checkout/,
    /web\.untitled: no title/,
    /suite stack: unknown capability psql/,
    /suite empty: no checks/,
  ]) {
    assert.match(problems, expected);
  }
  assert.deepEqual(validateInventory({ schema: 2 }), ["schema: expected 1"]);
});

test("features: a valid changelog citation, introducedIn or core, and the whole compatibility core", () => {
  const problems = (change) => {
    const inv = base();
    change(inv);
    return validateInventory(inv).join("\n");
  };
  assert.match(problems((i) => delete i.features.scan.changelog), /feature scan: changelog must be/);
  assert.match(problems((i) => (i.features.scan.changelog = { release: "latest", quote: "x" })), /feature scan: changelog must be/);
  assert.match(problems((i) => (i.features.scan.changelog.quote = " ")), /feature scan: changelog must be/);
  assert.match(problems((i) => delete i.features.scan.introducedIn), /feature scan: introducedIn must be x\.y\.z/);
  assert.match(problems((i) => (i.features.scan.introducedIn = "0.11.0")), /introducedIn 0\.11\.0 differs from the release its changelog entry cites \(0\.12\.0\)/);
  assert.match(problems((i) => (i.features.scan.core = true)), /feature scan: only .* are in the compatibility core/);
  assert.match(problems((i) => delete i.features.whoami.core), /feature whoami: is in the compatibility core/);
  assert.match(problems((i) => (i.features.whoami.introducedIn = "0.17.0")), /feature whoami: a compatibility-core feature is never version-gated/);
  assert.match(problems((i) => delete i.features["types-python"]), /feature types-python: the compatibility core needs it/);
  assert.match(problems((i) => (i.checks["core.types-python"].kind = "ts-stack", i.checks["core.types-python"].replacement = { none: "x" })), /feature types-python: the compatibility core needs at least one conformance check/);
  assert.match(problems((i) => (i.features.unused = { title: "u", introducedIn: "0.1.0", changelog: cite("0.1.0") })), /feature unused: no checks/);
  assert.match(problems((i) => (i.features.Bad = { title: "b", introducedIn: "0.1.0", changelog: cite("0.1.0") })), /feature Bad: not a feature name/);
});

test("gating and predates follow the check's feature", () => {
  const inv = base();
  assert.deepEqual(gating(inv, "web.scan-staged"), { feature: "scan", core: false, introducedIn: "0.12.0" });
  assert.deepEqual(gating(inv, "web.whoami"), { feature: "whoami", core: true, introducedIn: null });
  assert.deepEqual(gating(inv, "web.csp-strict"), { feature: null, core: false, introducedIn: null });
  assert.equal(predates(inv, "scan", "0.11.9"), true);
  assert.equal(predates(inv, "scan", "0.12.0"), false);
  assert.equal(predates(inv, "scan", "0.22.0"), false);
  assert.equal(predates(inv, "scan", null), false, "a CLI built from source predates nothing");
  assert.equal(predates(inv, "scan", ""), false);
  assert.equal(predates(inv, "whoami", "0.1.0"), false, "the core is never version-gated");
  assert.throws(() => predates(inv, "nope", "0.1.0"), /unknown feature nope/);
});

const pass = (suite, id) => ({ suite, id, status: "PASS", text: "" });
const all = () => [
  pass("web", "web.csp-strict"),
  pass("web", "web.scan-staged"),
  pass("web", "web.whoami"),
  pass("stack", "stack.convex"),
  pass("stack", "stack.reconcile"),
  pass("stack", "stack.doctor"),
  pass("stub", "stub.page"),
  ...CORE_FEATURES.map((f) => pass("core", `core.${f}`)),
];
const outcome = (run, id) => run.checks.find((c) => c.id === id);

test("a run where every check passed is ok", () => {
  const run = evaluate({ inventory: base(), reports: all() });
  assert.equal(run.ok, true);
  assert.deepEqual(run.problems, []);
});

test("a check in the inventory that did not report fails the run", () => {
  const run = evaluate({ inventory: base(), reports: all().filter((r) => r.id !== "stub.page") });
  assert.equal(run.ok, false);
  assert.deepEqual(outcome(run, "stub.page"), { id: "stub.page", suite: "stub", kind: "component", feature: null, outcome: "fail", why: "did not report", reports: 0 });
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
  const claim = (suite, id) => ({ suite, id, status: "PREDATES-CLI", text: "" });
  const reports = (id, suite = "web") => [...all().filter((r) => r.id !== id), claim(suite, id)];
  let run = evaluate({ inventory: base(), reports: reports("web.scan-staged"), cliVersion: "0.11.0" });
  assert.equal(run.ok, true);
  assert.equal(outcome(run, "web.scan-staged").outcome, "predates-cli");
  assert.match(outcome(run, "web.scan-staged").why, /predates scan, introduced in 0\.12\.0/);
  for (const [cliVersion, why] of [
    ["0.12.0", /not older than 0\.12\.0/],
    ["0.13.1", /not older than/],
    [null, /built from source/],
  ]) {
    run = evaluate({ inventory: base(), reports: reports("web.scan-staged"), cliVersion });
    assert.equal(run.ok, false, String(cliVersion));
    assert.match(outcome(run, "web.scan-staged").why, why);
  }
  // A check with no feature cannot take it, nor can any compatibility-core check, at any version.
  run = evaluate({ inventory: base(), reports: reports("web.csp-strict"), cliVersion: "0.1.0" });
  assert.match(outcome(run, "web.csp-strict").why, /names no version/);
  for (const f of CORE_FEATURES) {
    run = evaluate({ inventory: base(), reports: reports(`core.${f}`, "core"), cliVersion: "0.0.1" });
    assert.equal(run.ok, false, f);
    assert.match(outcome(run, `core.${f}`).why, /compatibility-core/);
  }
  // A partial claim: one report predates, another passes; inconsistent, so it fails.
  run = evaluate({ inventory: base(), reports: [...reports("web.scan-staged"), pass("web", "web.scan-staged")], cliVersion: "0.11.0" });
  assert.match(outcome(run, "web.scan-staged").why, /inconsistently/);
});

test("compareVersions orders x.y.z numerically, and refuses anything else", () => {
  assert.equal(compareVersions("0.9.0", "0.10.0"), -1);
  assert.equal(compareVersions("0.22.0", "0.22.0"), 0);
  assert.equal(compareVersions("1.0.0", "0.99.99"), 1);
  assert.equal(compareVersions("0.21.0", "0.22.0"), -1);
  assert.equal(compareVersions("0.22.1", "0.22.0"), 1);
  for (const bad of ["latest", "0.22", "v0.22.0", "0.22.0-rc.1", ""]) {
    assert.throws(() => compareVersions(bad, "0.22.0"), /not an x\.y\.z version/, bad);
  }
});

test("an external suite is a scripts/test-*.mjs suite the runner does not run, with a replacement", () => {
  const withExternal = (suite) => ({ ...base(), externalSuites: { setup: { title: "setup", script: "scripts/test-setup.mjs", kind: "ts-stack", replacement: { open: "step 6" }, ...suite } } });
  assert.deepEqual(validateInventory(withExternal({})), []);
  assert.deepEqual(validateInventory(withExternal({ replacement: "web.csp-strict" })), []);
  assert.deepEqual(validateInventory(withExternal({ replacement: { none: "nothing to replace" } })), []);
  const problems = (suite) => validateInventory(withExternal(suite)).join("\n");
  assert.match(problems({ script: "apps/web/scripts/e2e-web.mjs" }), /script must be scripts\/test-<name>\.mjs/);
  assert.match(problems({ kind: "conformance" }), /kind must be ts-stack/);
  assert.match(problems({ replacement: undefined }), /names its replacement/);
  assert.match(problems({ replacement: "stack.convex" }), /is not a conformance check/);
  assert.match(problems({ replacement: { open: "" } }), /replacement must be/);
  assert.match(problems({ title: "" }), /no title/);
  const clash = base();
  clash.externalSuites = { web: { title: "web", script: "scripts/test-web.mjs", kind: "ts-stack", replacement: { open: "step 6" } } };
  assert.match(validateInventory(clash).join(), /is also a suite the runner runs/);
});
