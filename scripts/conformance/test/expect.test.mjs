// SPDX-License-Identifier: Apache-2.0
/**
 * Expected failures: the file's rules, which entries are in force for a
 * run, the unexpected-pass rule, and the merge-base comparison (pure, and
 * expect-check.mjs on a throwaway git repository).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { addedEntries, applyExpectations, entryKeys, expectationsFor, validateExpectations } from "../lib/expect.mjs";
import { evaluate } from "../lib/inventory.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const inventory = JSON.parse(readFileSync(join(here, "..", "inventory.json"), "utf8"));
const cliVersions = ["0.21.0", "0.22.0"];
const entry = (reason = "a reason", removedBy = "ADR-0059 step 3") => ({ reason, removedBy });
const file = (expected) => ({ schema: 1, expected });

test("an expectations file: its own target's keys, known clients and checks, a reason and the step that removes it", () => {
  const ok = file({ "ts-release:0.22.0": { "*": { "values.grid-masks-secret": entry() }, "0.21.0": { "dashboard.csp-strict": entry() } } });
  assert.deepEqual(validateExpectations(ok, { targetName: "ts-release", inventory, cliVersions }), []);
  const problems = (expected, targetName = "ts-release") => validateExpectations(file(expected), { targetName, inventory, cliVersions }).join("\n");
  assert.match(problems({ "ts-source": { "*": {} } }), /ts-source is not a ts-release target/);
  assert.match(problems({ "ts-release:0.22.0": { latest: {} } }), /the client must be source, \*, or a CLI clients\.json pins/);
  assert.match(problems({ "ts-release:0.22.0": { "0.20.0": {} } }), /the client must be/);
  assert.match(problems({ "ts-release:0.22.0": { source: { "values.no-such-check": entry() } } }), /not in the inventory/);
  assert.match(problems({ "ts-release:0.22.0": { source: { "values.grid-masks-secret": { reason: "x" } } } }), /must be \{ "reason"/);
  assert.match(problems({ "ts-release:0.22.0": { source: { "values.grid-masks-secret": entry("", "step 3") } } }), /must be \{ "reason"/);
  assert.match(problems({ "ts-release:0.22.0": { source: { "values.grid-masks-secret": { ...entry(), extra: 1 } } } }), /must be \{ "reason"/);
  assert.match(
    problems({ "ts-release:0.22.0": { "*": { "values.grid-masks-secret": entry() }, source: { "values.grid-masks-secret": entry() } } }),
    /also expected for every client/,
  );
  assert.match(validateExpectations({ schema: 2 }, { targetName: "ts-source", inventory, cliVersions }).join(), /schema: expected 1/);
  assert.deepEqual(validateExpectations(file({ "go-binary": { "*": { "values.grid-masks-secret": entry() } } }), { targetName: "go-binary", inventory, cliVersions }), []);
});

test("the entries in force: those of the run's target key, for its client and for every client", () => {
  const f = file({
    "ts-release:0.22.0": { "*": { a: entry("any") }, "0.21.0": { b: entry("old") }, source: { c: entry("src") } },
    "ts-release:0.21.0": { "*": { d: entry() } },
  });
  assert.deepEqual([...expectationsFor(f, "ts-release:0.22.0", "0.21.0").keys()].sort(), ["a", "b"]);
  assert.deepEqual([...expectationsFor(f, "ts-release:0.22.0", "source").keys()].sort(), ["a", "c"]);
  assert.equal(expectationsFor(f, "ts-release:0.22.0", "source").get("a").client, "*");
  assert.deepEqual([...expectationsFor(f, "ts-source", "source").keys()], []);
  assert.deepEqual([...expectationsFor({ schema: 1, expected: {} }, "ts-source", "source").keys()], []);
});

/** A judged run whose failures are all the checks' own FAIL lines. */
const judged = (outcomes, problems = []) => ({
  checks: Object.entries(outcomes).map(([id, outcome]) => ({
    id,
    suite: id.split(".")[0],
    kind: "conformance",
    outcome,
    why: outcome === "fail" ? "it failed" : "",
    ...(outcome === "fail" ? { failure: "assertion" } : {}),
  })),
  problems,
  ok: false,
});

test("an expected failure is reported as one, never hidden, and the run passes", () => {
  const expected = new Map([["s.a", { ...entry("known"), client: "*" }]]);
  const out = applyExpectations(judged({ "s.a": "fail", "s.b": "pass" }), expected);
  assert.equal(out.ok, true);
  const a = out.checks.find((c) => c.id === "s.a");
  assert.equal(a.outcome, "expected-fail");
  assert.equal(a.why, "it failed");
  assert.deepEqual(a.expected, { reason: "known", removedBy: "ADR-0059 step 3", client: "*" });
  assert.deepEqual(out.expectations, { inForce: 1, failedAsExpected: ["s.a"], failedOtherwise: [], passedUnexpectedly: [], notExercised: [] });
});

test("an expected failure that passes fails the run", () => {
  const out = applyExpectations(judged({ "s.a": "pass" }), new Map([["s.a", { ...entry("known"), client: "source" }]]));
  assert.equal(out.ok, false);
  assert.equal(out.checks[0].outcome, "fail");
  assert.match(out.checks[0].why, /expected to fail \(known; removed by ADR-0059 step 3\), but it passed: remove its entry/);
  assert.deepEqual(out.expectations.passedUnexpectedly, ["s.a"]);
});

test("expectations cover failed checks only: other failures and problems still fail the run", () => {
  const expected = new Map([["s.a", { ...entry(), client: "*" }]]);
  assert.equal(applyExpectations(judged({ "s.a": "fail", "s.b": "fail" }), expected).ok, false);
  assert.equal(applyExpectations(judged({ "s.a": "fail" }, ["runner: the run stopped"]), expected).ok, false);
  // A check that did not apply or predates the CLI is left as it is, and listed.
  const na = applyExpectations(judged({ "s.a": "predates-cli" }), expected);
  assert.equal(na.ok, true);
  assert.equal(na.checks[0].outcome, "predates-cli");
  assert.deepEqual(na.expectations.notExercised, ["s.a"]);
  // An entry for a check the run does not have is a problem.
  assert.match(applyExpectations(judged({ "s.b": "pass" }), expected).problems.join(), /s\.a is expected to fail, but the run has no such check/);
});

/** A tiny inventory, judged by the real evaluate(), then the expectation for s.a applied. */
function judgeWithExpectation(reports, { errors = [], cliVersion = null, kind = "conformance" } = {}) {
  const inv = {
    features: { gated: { title: "gated", introducedIn: "0.20.0", changelog: { release: "0.20.0", quote: "q" } } },
    suites: { s: { title: "s", script: "s.mjs" } },
    checks: {
      "s.a": { suite: "s", kind, title: "a", feature: "gated", ...(kind === "ts-stack" ? { replacement: { none: "x" } } : {}) },
      "s.b": { suite: "s", kind: "conformance", title: "b" },
    },
  };
  const all = [{ suite: "s", id: "s.b", status: "PASS", text: "" }, ...reports];
  return applyExpectations(evaluate({ inventory: inv, reports: all, errors, cliVersion }), new Map([["s.a", { ...entry("known"), client: "*" }]]));
}

test("only a check's own FAIL line can be expected; a reporting failure always fails the run", () => {
  // The reported failure the entry is for: expected.
  const asserted = judgeWithExpectation([{ suite: "s", id: "s.a", status: "FAIL", text: "s.a failed" }]);
  assert.equal(asserted.ok, true);
  assert.equal(asserted.checks.find((c) => c.id === "s.a").outcome, "expected-fail");

  const fails = (out, why) => {
    const a = out.checks.find((c) => c.id === "s.a");
    assert.equal(out.ok, false, why.source);
    assert.equal(a.outcome, "fail");
    assert.equal(a.failure, "reporting");
    assert.match(a.why, why);
    assert.match(a.why, /an expectation never covers it/);
    assert.deepEqual(out.expectations.failedOtherwise, ["s.a"]);
    assert.deepEqual(out.expectations.failedAsExpected, []);
  };
  // A check that never reported.
  const missing = judgeWithExpectation([]);
  fails(missing, /did not report/);
  assert.equal(missing.checks.find((c) => c.id === "s.a").reports, 0);
  // A conformance check reported not applicable.
  fails(judgeWithExpectation([{ suite: "s", id: "s.a", status: "N/A", text: "no capability" }]), /reported not applicable/);
  // PREDATES-CLI the runner cannot confirm: a source CLI, or one not older.
  fails(judgeWithExpectation([{ suite: "s", id: "s.a", status: "PREDATES-CLI", text: "" }]), /built from source/);
  fails(judgeWithExpectation([{ suite: "s", id: "s.a", status: "PREDATES-CLI", text: "" }], { cliVersion: "0.22.0" }), /is not older than 0\.20\.0/);
  // Inconsistent reports.
  fails(judgeWithExpectation([{ suite: "s", id: "s.a", status: "PASS", text: "" }, { suite: "s", id: "s.a", status: "N/A", text: "" }]), /reported inconsistently/);
  // An infrastructure error fails the run even when the expected check failed as expected.
  const infra = judgeWithExpectation([{ suite: "s", id: "s.a", status: "FAIL", text: "" }], { errors: [{ suite: "runner", message: "the run stopped: docker compose up failed" }] });
  assert.equal(infra.ok, false);
  assert.match(infra.problems.join(), /the run stopped/);
});

test("merge-base comparison: an added entry, or one moved to another client or target, counts as added; removing does not", () => {
  const base = { "ts-release": file({ "ts-release:0.22.0": { "*": { a: entry() }, source: { b: entry() } } }) };
  assert.deepEqual(addedEntries(base, base), []);
  assert.deepEqual(addedEntries(base, { "ts-release": file({ "ts-release:0.22.0": { "*": { a: entry("reworded") } } }) }), []);
  assert.deepEqual(addedEntries(base, { "ts-release": file({ "ts-release:0.22.0": { "*": { a: entry(), c: entry() }, source: { b: entry() } } }) }), ["ts-release|ts-release:0.22.0|*|c"]);
  assert.deepEqual(addedEntries(base, { "ts-release": file({ "ts-release:0.22.0": { "*": { a: entry(), b: entry() } } }) }), ["ts-release|ts-release:0.22.0|*|b"]);
  assert.deepEqual(addedEntries(base, { ...base, "ts-source": file({ "ts-source": { source: { a: entry() } } }) }), ["ts-source|ts-source|source|a"]);
  assert.deepEqual(addedEntries({}, {}), []);
  assert.equal(entryKeys(base).size, 2);
});

function git(dir, ...args) {
  const r = spawnSync("git", ["-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", ...args], { cwd: dir, encoding: "utf8" });
  assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
  return r.stdout.trim();
}

test("expect-check.mjs: fails a branch that adds an entry, unless labeled; compares with the merge base, not the base's tip", () => {
  const repo = mkdtempSync(join(tmpdir(), "conformance-expect-test-"));
  const script = join(here, "..", "expect-check.mjs");
  const check = (...args) => spawnSync(process.execPath, [script, "--repo", repo, ...args], { encoding: "utf8" });
  const write = (expected) => writeFileSync(join(repo, "scripts/conformance/expect/ts-source.json"), JSON.stringify(file(expected)));
  try {
    git(repo, "init", "-q", "-b", "main");
    mkdirSync(join(repo, "scripts/conformance/expect"), { recursive: true });
    for (const name of ["inventory.json", "clients.json"]) writeFileSync(join(repo, "scripts/conformance", name), readFileSync(join(here, "..", name)));
    write({ "ts-source": { "*": { "values.grid-masks-secret": entry() } } });
    git(repo, "add", ".");
    git(repo, "commit", "-q", "-m", "base");
    const mergeBase = git(repo, "rev-parse", "HEAD");

    // The base branch moves on: it removes the entry after the branch point.
    write({});
    git(repo, "commit", "-q", "-am", "main fixes it");
    const mainTip = git(repo, "rev-parse", "HEAD");

    // A branch from the merge base that keeps the entry adds nothing.
    git(repo, "checkout", "-q", "-b", "keeps", mergeBase);
    writeFileSync(join(repo, "README"), "x");
    git(repo, "add", "README");
    git(repo, "commit", "-q", "-m", "unrelated");
    let r = check("--base", mainTip, "--head", "HEAD");
    assert.equal(r.status, 0, r.stdout + r.stderr);

    // A branch that adds an entry fails, unless labeled.
    git(repo, "checkout", "-q", "-b", "adds", mergeBase);
    write({ "ts-source": { "*": { "values.grid-masks-secret": entry() }, source: { "dashboard.csp-strict": entry() } } });
    git(repo, "commit", "-q", "-am", "adds");
    r = check("--base", mainTip, "--head", "HEAD");
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /ADDED {4}ts-source\|ts-source\|source\|dashboard\.csp-strict/);
    assert.match(r.stdout, /label the pull request conformance-regression/);
    r = check("--base", mainTip, "--head", "HEAD", "--labeled");
    assert.equal(r.status, 0, r.stdout + r.stderr);

    // A branch that removes an entry passes.
    git(repo, "checkout", "-q", "-b", "removes", mergeBase);
    write({});
    git(repo, "commit", "-q", "-am", "removes");
    r = check("--base", mainTip, "--head", "HEAD");
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /REMOVED {2}ts-source\|ts-source\|\*\|values\.grid-masks-secret/);

    // An invalid file fails even with the label.
    git(repo, "checkout", "-q", "-b", "invalid", mergeBase);
    write({ "ts-source": { "*": { "values.no-such-check": entry() } } });
    git(repo, "commit", "-q", "-am", "invalid");
    r = check("--base", mainTip, "--head", "HEAD", "--labeled");
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /INVALID .*not in the inventory/);
    r = check("--validate-only", "--head", "HEAD");
    assert.equal(r.status, 1, r.stdout + r.stderr);

    // A file not named after a target is refused, whatever its keys say.
    git(repo, "checkout", "-q", "-b", "stray", mergeBase);
    writeFileSync(join(repo, "scripts/conformance/expect/mine.json"), JSON.stringify(file({ mine: { "*": { "values.grid-masks-secret": entry() } } })));
    git(repo, "add", ".");
    git(repo, "commit", "-q", "-m", "stray");
    r = check("--base", mainTip, "--head", "HEAD", "--labeled");
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /INVALID +expect\/mine\.json: not named after a target/);

    // A push to main validates what it lands, without a base.
    r = check("--validate-only", "--head", mainTip);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /0 entries, valid/);
    assert.equal(check("--validate-only", "--head", mainTip, "--labeled").status, 64);
    assert.equal(check("--head", mainTip).status, 64);

    // The checker reads the head only as data: a head that changes the
    // checker itself changes nothing, since CI runs the base's checker.
    git(repo, "checkout", "-q", "-b", "sneaky", mergeBase);
    mkdirSync(join(repo, "scripts/conformance/lib"), { recursive: true });
    writeFileSync(join(repo, "scripts/conformance/expect-check.mjs"), "process.exit(0);\n");
    write({ "ts-source": { "*": { "values.grid-masks-secret": entry() }, source: { "dashboard.csp-strict": entry() } } });
    git(repo, "add", ".");
    git(repo, "commit", "-q", "-m", "sneaky");
    r = check("--base", mainTip, "--head", "HEAD");
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /ADDED/);
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});
