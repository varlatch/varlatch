// SPDX-License-Identifier: Apache-2.0
/**
 * Gate mode (lib/gate.mjs): each rule on its own, and why no target can
 * pass the gate today: replacements that later ADR-0059 steps write are
 * still open.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { canonical, judgeGate, predatedFeatures, recentCliProblems, replacements } from "../lib/gate.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const inventory = JSON.parse(readFileSync(join(here, "..", "inventory.json"), "utf8"));

/** A small inventory whose replacements are all satisfiable. */
const small = {
  features: { scan: { title: "scan", introducedIn: "0.20.0", changelog: { release: "0.20.0", quote: "q" } } },
  checks: {
    "a.new": { suite: "a", kind: "conformance" },
    "a.old": { suite: "a", kind: "ts-stack", replacement: "a.new" },
    "a.gone": { suite: "a", kind: "ts-stack", replacement: { none: "no Convex" } },
  },
  externalSuites: { setup: { script: "scripts/test-setup.mjs", replacement: "a.new" } },
};
const walkthrough = { path: "docs/evidence/walkthrough-2026-12.md", exists: true, size: 120, sha256: "w".repeat(64) };
const implementation = { target: "go-binary", sha256: "b".repeat(64) };
const run = (outcomes, extra = {}) => ({
  target: "go-binary:/usr/bin/varlatchd",
  partial: false,
  ok: true,
  checks: Object.entries(outcomes).map(([id, outcome]) => ({ id, outcome })),
  expectedInForce: [],
  implementation,
  ...extra,
});
const passing = { "a.new": "pass", "a.old": "not-applicable", "a.gone": "not-applicable" };

test("a gate run passes when every rule holds", () => {
  const verdict = judgeGate({ inventory: small, run: run(passing), walkthrough });
  assert.deepEqual(verdict, { passed: true, problems: [], open: [] });
});

test("no expected failure is allowed, and the run itself must pass", () => {
  let v = judgeGate({ inventory: small, run: run(passing, { expectedInForce: ["a.new"] }), walkthrough });
  assert.equal(v.passed, false);
  assert.match(v.problems.join(), /no expected failure is allowed, and 1 are in force for go-binary:\/usr\/bin\/varlatchd: a\.new/);
  v = judgeGate({ inventory: small, run: run(passing, { ok: false }), walkthrough });
  assert.match(v.problems.join(), /the run itself did not pass/);
  v = judgeGate({ inventory: small, run: run(passing, { partial: ["a"] }), walkthrough });
  assert.match(v.problems.join(), /covers every suite/);
});

test("each replacement must be present and passing; an open one fails the gate", () => {
  let v = judgeGate({ inventory: small, run: run({ ...passing, "a.new": "expected-fail" }), walkthrough });
  assert.match(v.problems.join("\n"), /a\.old: its replacement a\.new must pass in this run \(expected-fail\)/);
  assert.match(v.problems.join("\n"), /setup \(scripts\/test-setup\.mjs\): its replacement a\.new must pass/);
  v = judgeGate({ inventory: small, run: run({ "a.old": "pass", "a.gone": "pass" }), walkthrough });
  assert.match(v.problems.join("\n"), /its replacement a\.new must pass in this run \(not in the run\)/);
  const withOpen = structuredClone(small);
  withOpen.externalSuites.setup.replacement = { open: "ADR-0059 step 6" };
  v = judgeGate({ inventory: withOpen, run: run(passing), walkthrough });
  assert.equal(v.passed, false);
  assert.deepEqual(v.open, ["setup (scripts/test-setup.mjs): ADR-0059 step 6"]);
});

test("the browser-walkthrough evidence must be named, under docs/evidence/, present and not empty", () => {
  const problem = (w) => judgeGate({ inventory: small, run: run(passing), walkthrough: w }).problems.join();
  assert.match(problem(null), /names no browser-walkthrough evidence file/);
  assert.match(problem({ ...walkthrough, path: "notes.md" }), /is not under docs\/evidence\//);
  assert.match(problem({ ...walkthrough, path: "docs/evidence/../../x.md" }), /is not under docs\/evidence\//);
  assert.match(problem({ ...walkthrough, exists: false }), /does not exist/);
  assert.match(problem({ ...walkthrough, size: 0 }), /is empty/);
});

/** A complete report of a gate run with a source CLI, as run.mjs writes it. */
const recentReport = (change = () => {}) => {
  const report = {
    target: "go-binary:/usr/bin/varlatchd",
    partial: false,
    implementation: structuredClone(implementation),
    cli: { spec: "source", version: null, sha256: "c".repeat(64) },
    checks: [
      { id: "a.new", outcome: "pass" },
      { id: "a.old", outcome: "not-applicable" },
      { id: "a.gone", outcome: "not-applicable" },
    ],
    problems: [],
    ok: true,
    gate: { passed: true, walkthrough: { ...walkthrough } },
  };
  change(report);
  return report;
};
const old = run({ "a.new": "pass", "a.old": "not-applicable", "a.gone": "predates-cli" });
const why = (report) => recentCliProblems(report, { inventory: small, target: old.target, implementation, walkthrough }).join("\n");

test("a run whose CLI predates checks needs the complete, passing report of the same implementation with a recent CLI", () => {
  assert.match(judgeGate({ inventory: small, run: old, walkthrough }).problems.join(), /1 checks predate this run's CLI, .*--recent-cli-report.*: none named/);
  const verdict = judgeGate({ inventory: small, run: old, walkthrough, recentCli: recentReport() });
  assert.equal(verdict.passed, true, verdict.problems.join());
  assert.equal(why(recentReport((r) => (r.cli = { spec: "0.22.0", version: "0.22.0" }))), "");
});

test("the recent-CLI report is judged again, not trusted: a bare or failing report with ok and gate.passed set is refused", () => {
  // Sol's case: only the fields a forger would set.
  const bare = why({ target: old.target, ok: true, gate: { passed: true } });
  assert.match(bare, /not a complete run/);
  assert.match(bare, /ran another implementation/);
  assert.match(bare, /names no verified CLI/);
  assert.match(bare, /reports problems outside its checks/);
  assert.match(bare, /3 inventory checks are missing/);
  // A failed check, with ok and gate.passed still claimed.
  assert.match(why(recentReport((r) => (r.checks[0].outcome = "fail"))), /1 of its checks did not pass \(a\.new: fail\)/);
  assert.match(why(recentReport((r) => (r.checks[0].outcome = "expected-fail"))), /did not pass/);
  assert.match(why(recentReport((r) => (r.checks[1].outcome = "predates-cli"))), /did not pass \(a\.old: predates-cli\)/);
  // Not applicable is accepted for a ts-stack check only.
  assert.match(why(recentReport((r) => (r.checks[0].outcome = "not-applicable"))), /a\.new: not-applicable/);
  assert.match(why(recentReport((r) => r.checks.pop())), /1 inventory checks are missing from it \(a\.gone\)/);
  assert.match(why(recentReport((r) => r.checks.push({ id: "a.extra", outcome: "pass" }))), /checks the inventory does not \(a\.extra\)/);
  assert.match(why(recentReport((r) => r.checks.push({ id: "a.new", outcome: "pass" }))), /more than once \(a\.new\)/);
  assert.match(why(recentReport((r) => (r.problems = ["runner: the run stopped"]))), /problems outside its checks/);
  assert.match(why(recentReport((r) => (r.partial = ["a"]))), /not a complete run/);
  assert.match(why(recentReport((r) => (r.checks[0].expected = { reason: "x" }))), /its own gate: no expected failure is allowed/);
});

test("the recent-CLI report must come from the same implementation, a CLI that predates nothing, and the same walkthrough", () => {
  assert.match(why(recentReport((r) => (r.target = "go-binary:/other/varlatchd"))), /a run of "go-binary:\/other\/varlatchd"/);
  // Same path, another binary.
  assert.match(why(recentReport((r) => (r.implementation.sha256 = "d".repeat(64)))), /ran another implementation/);
  assert.match(why(recentReport((r) => delete r.implementation)), /ran another implementation/);
  assert.match(recentCliProblems(recentReport(), { inventory: small, target: old.target, implementation: null }).join(), /this run recorded no implementation fingerprint/);
  // Its CLI must predate nothing in the current inventory.
  assert.match(why(recentReport((r) => (r.cli = { spec: "0.19.0", version: "0.19.0" }))), /its CLI 0\.19\.0 predates scan/);
  assert.match(why(recentReport((r) => (r.gate.walkthrough.sha256 = "x".repeat(64)))), /other browser-walkthrough evidence/);
  // Fingerprints compare by content, not key order.
  assert.equal(canonical({ b: 1, a: [1, { d: 2, c: 3 }] }), canonical({ a: [1, { c: 3, d: 2 }], b: 1 }));
  assert.deepEqual(predatedFeatures(small, null), []);
  assert.deepEqual(predatedFeatures(small, "0.19.9"), ["scan"]);
  assert.deepEqual(predatedFeatures(small, "0.20.0"), []);
});

test("a gate run needs its own implementation fingerprint", () => {
  const verdict = judgeGate({ inventory: small, run: run(passing, { implementation: null }), walkthrough });
  assert.match(verdict.problems.join(), /recorded no implementation fingerprint/);
});

test("today no target can pass the gate: the realtime (G11), doctor and lifecycle replacements are open", () => {
  const open = replacements(inventory).filter((r) => r.replacement && typeof r.replacement === "object" && "open" in r.replacement);
  // G11's realtime checks are written in step 3, doctor in step 6, and each
  // lifecycle and installer suite in the step its Go counterpart lands.
  assert.ok(open.some((r) => r.of.startsWith("realtime.") && /step 3: the G11 realtime checks/.test(r.replacement.open)));
  assert.ok(open.some((r) => r.of.startsWith("doctor.") && /step 6/.test(r.replacement.open)));
  for (const name of Object.keys(inventory.externalSuites)) assert.ok(open.some((r) => r.of.startsWith(`${name} (`)), name);

  // The best a run can do on each target: every check passes (a ts-stack
  // check does not apply where the target has no TypeScript stack), with a
  // recent CLI, no expected failure and the walkthrough named.
  for (const [target, tsStack] of [["ts-source", "pass"], ["ts-release:0.22.0", "pass"], ["go-binary:/opt/varlatchd", "not-applicable"]]) {
    const outcomes = Object.fromEntries(Object.entries(inventory.checks).map(([id, c]) => [id, c.kind === "ts-stack" ? tsStack : "pass"]));
    const verdict = judgeGate({ inventory, run: run(outcomes, { target }), walkthrough });
    assert.equal(verdict.passed, false, target);
    assert.equal(verdict.problems.length, 1, `${target}: only the open replacements stop it: ${verdict.problems.join("\n")}`);
    assert.match(verdict.problems[0], /replacements are still open/);
    assert.equal(verdict.open.length, open.length);
  }
});
