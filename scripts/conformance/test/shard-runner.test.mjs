// SPDX-License-Identifier: Apache-2.0
/**
 * The runner (run.mjs) with --shard, end to end, on a stub target, against
 * stub suites: what a shard judges. Hermetic, as test/runner.test.mjs: the
 * conformance directory is copied into a temporary root, where the copy
 * gains three stub suites (alpha, beta, gamma) and the runner's
 * request-budget check in its inventory and plan, weights that put alpha in
 * shard 1 of 2 and beta and gamma in shard 2, a stub target (a local HTTP
 * server answering 501 NOT_IMPLEMENTED_YET, or 200 with STUB_PROVIDES=1)
 * that lacks exportAuditEvents, and a CLI resolver that names a CLI built
 * from source. Every other file is this checkout's.
 *
 * The target's expectations: alpha.flaky is expected to fail (the stub
 * suite fails it, or passes it with STUB_MODE=alpha-passes), and the target
 * lacks exportAuditEvents, which gamma's group "audit" (gamma.audit) needs.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
let root;
let allChecks;

before(() => {
  root = mkdtempSync(join(tmpdir(), "conformance-shard-runner-test-"));
  const dst = join(root, "scripts/conformance");
  cpSync(join(repoRoot, "scripts/conformance"), dst, { recursive: true, filter: (p) => !p.includes(`${"/"}node_modules`) });
  cpSync(join(repoRoot, "scripts/redact-tokens.mjs"), join(root, "scripts/redact-tokens.mjs"));
  mkdirSync(join(root, "packages/protocol"), { recursive: true });
  cpSync(join(repoRoot, "packages/protocol/openapi.yaml"), join(root, "packages/protocol/openapi.yaml"));
  symlinkSync(join(repoRoot, "node_modules"), join(root, "node_modules"));

  // The compatibility core's features each need a check: alpha reports them.
  const real = JSON.parse(readFileSync(join(dst, "inventory.json"), "utf8"));
  const features = Object.fromEntries(Object.entries(real.features).filter(([, f]) => f.core === true));
  const suite = (title) => ({ title, script: "scripts/conformance/stub-suite.mjs", operations: [] });
  const check = (s, title, extra = {}) => ({ suite: s, kind: "conformance", title, ...extra });
  const inventory = {
    schema: 1, description: "the shard runner test's", features, operations: real.operations, goServerChecks: {}, externalSuites: {},
    suites: {
      alpha: suite("the alpha stub"),
      beta: suite("the beta stub"),
      gamma: { ...suite("the gamma stub"), groups: { audit: { title: "the audit log", operations: ["exportAuditEvents"] } } },
      "request-budget": real.suites["request-budget"],
    },
    checks: {
      "alpha.base": check("alpha", "alpha's base check"),
      "alpha.flaky": check("alpha", "alpha's check the target is expected to fail"),
      ...Object.fromEntries(Object.keys(features).map((f) => [`alpha.core-${f}`, check("alpha", f, { feature: f })])),
      "beta.base": check("beta", "beta's base check"),
      "gamma.base": check("gamma", "gamma's base check"),
      "gamma.audit": check("gamma", "gamma's check in the group the target lacks", { group: "audit" }),
      "request-budget.no-unexpected-429": real.checks["request-budget.no-unexpected-429"],
    },
  };
  allChecks = Object.keys(inventory.checks).sort();
  writeFileSync(join(dst, "inventory.json"), JSON.stringify(inventory, null, 2));
  writeFileSync(join(dst, "plan.mjs"), `export const PLAN = [
  { suite: "alpha", args: () => [] },
  { suite: "beta", args: () => [] },
  { suite: "gamma", args: () => [] },
  { suite: "request-budget", runner: true },
];\n`);
  // Greedy, longest first, over two shards: alpha (100) to 1; beta (60) and gamma (50) to 2.
  writeFileSync(join(dst, "shard-weights.json"), JSON.stringify({ description: "the test's", seconds: { alpha: 100, beta: 60, gamma: 50 } }));

  // Each suite reports its checks outside the skipped group; alpha fails
  // alpha.flaky unless STUB_MODE=alpha-passes.
  const reported = {
    alpha: ["alpha.base", ...Object.keys(features).map((f) => `alpha.core-${f}`)],
    beta: ["beta.base"],
    gamma: ["gamma.base"],
  };
  writeFileSync(join(dst, "stub-suite.mjs"), `
const suite = process.env.CONFORMANCE_SUITE;
const line = (status, id) => console.log(\`\${status}  [\${id}] \${id}\`);
for (const id of ${JSON.stringify(reported)}[suite]) line("PASS", id);
if (suite === "alpha") line(process.env.STUB_MODE === "alpha-passes" ? "PASS" : "FAIL", "alpha.flaky");
// The end, as every suite ends: suite-kit's finish().
const { reporter } = await import("./suite-kit.mjs");
reporter().finish();
`);

  writeFileSync(join(dst, "targets/stub.mjs"), `
import http from "node:http";
export async function up() {
  const provides = process.env.STUB_PROVIDES === "1";
  const server = http.createServer((req, res) => {
    req.resume();
    res.writeHead(provides ? 200 : 501, { "Content-Type": "application/json" });
    res.end(provides ? "{}" : JSON.stringify({ error: { code: "NOT_IMPLEMENTED_YET", message: "stub", requestId: "req_stub" } }));
  });
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  return { server, origin: \`http://127.0.0.1:\${server.address().port}\` };
}
export async function down(state) { await new Promise((ok) => state.server.close(ok)); }
export function origin(state) { return state.origin; }
export async function bootstrap() { throw new Error("the stub has no bootstrap"); }
export async function recover() { throw new Error("the stub has no recover"); }
export async function restart() {}
export async function logs() { return ""; }
export async function requestLog() { return []; }
`);
  const index = join(dst, "targets/index.mjs");
  writeFileSync(index, readFileSync(index, "utf8").replace(
    `"go-binary": { load: () => import("./go-binary.mjs"), argument: "required" },`,
    `"go-binary": { load: () => import("./go-binary.mjs"), argument: "required" },\n  stub: { load: () => import("./stub.mjs"), argument: "none" },`,
  ));
  const caps = JSON.parse(readFileSync(join(dst, "targets/capabilities.json"), "utf8"));
  caps.stub = [];
  writeFileSync(join(dst, "targets/capabilities.json"), JSON.stringify(caps));
  writeFileSync(join(dst, "expect/stub.json"), JSON.stringify({
    schema: 1, description: "the stub target",
    expected: { stub: { "*": { "alpha.flaky": { reason: "the stub fails it", removedBy: "never" } } } },
    lacks: { stub: { exportAuditEvents: { reason: "the stub has no audit log", step: "never" } } },
  }));

  // The CLI: built from source, and no sdk to build (a full run builds one).
  const clients = join(dst, "clients.mjs");
  writeFileSync(clients, readFileSync(clients, "utf8")
    .replace("export async function resolveCli(spec, {", `export async function resolveCli(spec, { workDir }) {
  const path = (await import("node:path")).join(workDir, "stub-cli.cjs");
  (await import("node:fs")).writeFileSync(path, "");
  return { spec, path, version: null, commit: null, sha256: "0".repeat(64), verified: null };
}
export async function resolveCliReal(spec, {`)
    .replace("export async function buildSdk(cli, {", `export async function buildSdk(cli, { workDir }) {
  const path = (await import("node:path")).join(workDir, "stub-sdk.mjs");
  (await import("node:fs")).writeFileSync(path, "");
  return { path, commit: null, sha256: "0".repeat(64) };
}
export async function buildSdkReal(cli, {`));
});

after(() => rmSync(root, { recursive: true, force: true }));

let runs = 0;
/** Runs the copied runner with these arguments: its exit status, output and report. */
function run(args, env = {}) {
  const report = join(root, `report-${++runs}.json`);
  const r = spawnSync(process.execPath, [join(root, "scripts/conformance/run.mjs"), "--target", "stub", "--cli", "source", "--report", report, ...args], {
    encoding: "utf8",
    timeout: 120_000,
    env: { ...process.env, STUB_MODE: "", STUB_PROVIDES: "", ...env },
  });
  let parsed = null;
  try {
    parsed = JSON.parse(readFileSync(report, "utf8"));
  } catch {}
  return { status: r.status, out: r.stdout + r.stderr, report: parsed };
}

const outcomes = (report) => Object.fromEntries(report.checks.map((c) => [c.id, c.outcome]));
const ids = (report) => report.checks.map((c) => c.id).sort();

test("--shard: each shard judges only its own suites' checks, plus its own request budget; together, every check once", () => {
  const one = run(["--shard", "1/2"]);
  const two = run(["--shard", "2/2"]);
  assert.equal(one.status, 0, one.out);
  assert.equal(two.status, 0, two.out);
  assert.equal(one.report.shard, "1/2");
  assert.deepEqual(one.report.partial, ["alpha", "request-budget"]);
  assert.deepEqual(two.report.partial, ["beta", "gamma", "request-budget"]);
  assert.match(one.out, /SHARD 1\/2 PASSED \(only alpha, request-budget;/);
  assert.match(two.out, /SHARD 2\/2 PASSED \(only beta, gamma, request-budget;/);
  // The suites outside a shard do not run in it.
  assert.deepEqual(one.report.suites.map((s) => s.suite), ["alpha"]);
  assert.deepEqual(two.report.suites.map((s) => s.suite), ["beta", "gamma"]);
  // Every shard proves its own server refused nothing.
  assert.equal(outcomes(one.report)["request-budget.no-unexpected-429"], "pass");
  assert.equal(outcomes(two.report)["request-budget.no-unexpected-429"], "pass");
  // Every other check is judged in exactly one shard, and none is missing.
  const owned = (r) => ids(r).filter((id) => !id.startsWith("request-budget."));
  assert.deepEqual(owned(one.report).filter((id) => owned(two.report).includes(id)), []);
  assert.deepEqual([...owned(one.report), ...owned(two.report), "request-budget.no-unexpected-429"].sort(), allChecks);
});

test("--shard: an expected failure is judged in the shard that owns its suite, and ignored (not flagged) in the others", () => {
  const one = run(["--shard", "1/2"]);
  assert.equal(one.status, 0, one.out);
  assert.equal(outcomes(one.report)["alpha.flaky"], "expected-fail");
  assert.deepEqual(one.report.expectations.failedAsExpected, ["alpha.flaky"]);
  assert.match(one.out, /EXPECTED-FAIL {2}alpha\.flaky: the stub fails it/);

  const two = run(["--shard", "2/2"]);
  assert.equal(two.status, 0, two.out);
  assert.equal(outcomes(two.report)["alpha.flaky"], undefined);
  assert.equal(two.report.expectations.inForce, 0);
  assert.deepEqual(two.report.expectations.notExercised, []);
  assert.deepEqual(two.report.problems, []);
  assert.doesNotMatch(two.out, /alpha\.flaky/);
});

test("--shard: an expected failure that passes fails the shard that owns it, and only that one", () => {
  const one = run(["--shard", "1/2"], { STUB_MODE: "alpha-passes" });
  assert.equal(one.status, 1, one.out);
  assert.match(one.out, /alpha\.flaky.*expected to fail \(the stub fails it; removed by never\), but it passed/);
  const two = run(["--shard", "2/2"], { STUB_MODE: "alpha-passes" });
  assert.equal(two.status, 0, two.out);
});

test("--shard: the lacks probe runs in every shard; a lacking check is reported by the shard that owns it", () => {
  const one = run(["--shard", "1/2"]);
  const two = run(["--shard", "2/2"]);
  for (const r of [one, two]) assert.match(r.out, /the target declares 1 lacking operations; asking it about each\n--- every one answered NOT_IMPLEMENTED_YET/);
  assert.equal(outcomes(two.report)["gamma.audit"], "target-lacks");
  assert.equal(outcomes(one.report)["gamma.audit"], undefined);
  // A stale entry is the target's, not a suite's: every shard fails on it,
  // including the one whose suites need no lacking operation.
  for (const shard of ["1/2", "2/2"]) {
    const r = run(["--shard", shard], { STUB_PROVIDES: "1" });
    assert.equal(r.status, 1, `${shard}: ${r.out}`);
    assert.match(r.out, /STALE-LACKS {2}exportAuditEvents/, shard);
    assert.match(r.out, /expect\/stub\.json lacks exportAuditEvents, but/, shard);
  }
});

test("--shard 1/1 is a full run", () => {
  const r = run(["--shard", "1/1"]);
  const full = run([]);
  assert.equal(r.status, 0, r.out);
  assert.equal(r.report.partial, false);
  assert.equal(r.report.shard, null);
  assert.match(r.out, /ALL E2E SUITES PASSED/);
  assert.deepEqual(ids(r.report), allChecks);
  assert.deepEqual(r.report.checks.map((c) => [c.id, c.outcome]), full.report.checks.map((c) => [c.id, c.outcome]));
  assert.deepEqual(r.report.suites.map((s) => s.suite), full.report.suites.map((s) => s.suite));
});

test("--shard is a usage error with --suite or --gate, or when it is not k/n with 1 <= k <= n", () => {
  for (const args of [
    ["--shard", "1/2", "--suite", "alpha"],
    ["--suite", "alpha", "--shard", "1/2"],
    ["--shard", "1/2", "--gate", "--walkthrough", "README.md"],
    ["--shard", "3/2"],
    ["--shard", "0/2"],
    ["--shard", "two"],
  ]) {
    const r = run(args);
    assert.equal(r.status, 64, `${args.join(" ")}: ${r.out}`);
  }
});
