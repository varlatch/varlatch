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
import { judgeGate, recentCliProblem, replacements } from "../lib/gate.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const inventory = JSON.parse(readFileSync(join(here, "..", "inventory.json"), "utf8"));

/** A small inventory whose replacements are all satisfiable. */
const small = {
  checks: {
    "a.new": { suite: "a", kind: "conformance" },
    "a.old": { suite: "a", kind: "ts-stack", replacement: "a.new" },
    "a.gone": { suite: "a", kind: "ts-stack", replacement: { none: "no Convex" } },
  },
  externalSuites: { setup: { script: "scripts/test-setup.mjs", replacement: "a.new" } },
};
const walkthrough = { path: "docs/evidence/walkthrough-2026-12.md", exists: true, size: 120 };
const run = (outcomes, extra = {}) => ({
  target: "go-binary:/usr/bin/varlatchd",
  partial: false,
  ok: true,
  checks: Object.entries(outcomes).map(([id, outcome]) => ({ id, outcome })),
  expectedInForce: [],
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

test("a run whose CLI predates checks needs the passing gate report of a run with a recent CLI", () => {
  const old = run({ ...passing, "a.new": "pass", "a.x": "predates-cli" });
  let v = judgeGate({ inventory: small, run: old, walkthrough });
  assert.match(v.problems.join(), /1 checks predate this run's CLI, .*--recent-cli-report.*: none named/);
  const recent = { target: old.target, partial: false, ok: true, gate: { passed: true }, checks: [{ id: "a.new", outcome: "pass" }] };
  v = judgeGate({ inventory: small, run: old, walkthrough, recentCli: recent });
  assert.equal(v.passed, true, v.problems.join());
  assert.match(recentCliProblem({ ...recent, target: "ts-source" }, old.target), /a run of ts-source/);
  assert.match(recentCliProblem({ ...recent, gate: { passed: false } }, old.target), /did not pass in gate mode/);
  assert.match(recentCliProblem({ ...recent, ok: false }, old.target), /did not pass in gate mode/);
  assert.match(recentCliProblem({ ...recent, partial: ["a"] }, old.target), /partial/);
  assert.match(recentCliProblem({ ...recent, checks: [{ id: "a.x", outcome: "predates-cli" }] }, old.target), /predated its CLI too/);
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
