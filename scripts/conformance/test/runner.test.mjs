// SPDX-License-Identifier: Apache-2.0
/**
 * The runner itself (run.mjs), end to end, on a stub target, against stub
 * suites: the skipped-group guard as the runner applies it. Hermetic: the
 * conformance directory is copied into a temporary root (with the token
 * redaction it imports, the OpenAPI document and a link to node_modules), where the copy gains a stub suite
 * in the inventory, a plan of that suite alone, a stub target (a local
 * HTTP server that answers every route 501 NOT_IMPLEMENTED_YET, so the
 * lacks probe passes) lacking exportAuditEvents, and a CLI resolver that
 * names the CLI version a case asks for (a released CLI is otherwise
 * downloaded and verified). Every other file is this checkout's.
 *
 * The stub suite's checks: stub.base (no group), stub.scanned (feature
 * scan, no group), and in group "audit" (exportAuditEvents, which the target
 * lacks, so the group is skipped) stub.featured (feature scan, introduced in
 * 0.11.0) and stub.plain (no feature).
 *
 * The Go CLI (`--cli go:<path>`, lib/client-lacks.mjs): the copy's
 * client-go.json says it lacks scan, so stub.scanned reports client-lacks.
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

before(() => {
  root = mkdtempSync(join(tmpdir(), "conformance-runner-test-"));
  const dst = join(root, "scripts/conformance");
  cpSync(join(repoRoot, "scripts/conformance"), dst, { recursive: true, filter: (p) => !p.includes(`${"/"}node_modules`) });
  cpSync(join(repoRoot, "scripts/redact-tokens.mjs"), join(root, "scripts/redact-tokens.mjs"));
  mkdirSync(join(root, "packages/protocol"), { recursive: true });
  cpSync(join(repoRoot, "packages/protocol/openapi.yaml"), join(root, "packages/protocol/openapi.yaml"));
  symlinkSync(join(repoRoot, "node_modules"), join(root, "node_modules"));

  // An inventory of the stub suite alone: the compatibility core's features
  // (each needs a check: the stub reports them, outside the group) and scan.
  const real = JSON.parse(readFileSync(join(dst, "inventory.json"), "utf8"));
  const features = Object.fromEntries(Object.entries(real.features).filter(([name, f]) => f.core === true || name === "scan"));
  const inventory = {
    schema: 1, description: "the runner test's", features, operations: real.operations, goServerChecks: {}, externalSuites: {},
    suites: {
      stub: {
        title: "a stub suite", script: "scripts/conformance/stub-suite.mjs", operations: [],
        groups: { audit: { title: "the audit log", operations: ["exportAuditEvents"] } },
      },
    },
    checks: {
      "stub.base": { suite: "stub", kind: "conformance", title: "the base check" },
      "stub.scanned": { suite: "stub", kind: "conformance", feature: "scan", title: "a scan check outside the group" },
      "stub.featured": { suite: "stub", kind: "conformance", group: "audit", feature: "scan", title: "a scan check in the group" },
      "stub.plain": { suite: "stub", kind: "conformance", group: "audit", title: "a plain check in the group" },
      ...Object.fromEntries(Object.keys(features).filter((f) => f !== "scan").map((f) => [`stub.core-${f}`, { suite: "stub", kind: "conformance", feature: f, title: f }])),
    },
  };
  writeFileSync(join(dst, "inventory.json"), JSON.stringify(inventory, null, 2));
  const coreChecks = Object.keys(inventory.checks).filter((id) => id.startsWith("stub.core-"));
  writeFileSync(join(dst, "plan.mjs"), 'export const PLAN = [{ suite: "stub", args: () => [] }];\n');

  // The suite: what it prints and how it ends, by STUB_MODE.
  writeFileSync(join(dst, "stub-suite.mjs"), `
const mode = process.env.STUB_MODE;
const line = (status, id) => console.log(\`\${status}  [\${id}] \${id}\`);
if (mode === "crash") throw new Error("the stub suite crashed");
if (mode === "exit-early") process.exit(3);
for (const id of ${JSON.stringify(coreChecks)}) line("PASS", id);
line(mode === "base-fails" ? "FAIL" : "PASS", "stub.base");
line(mode === "scan-fails" ? "FAIL" : "PASS", "stub.scanned");
if (mode === "predates") { line("PREDATES-CLI", "stub.featured"); }
if (mode === "predates-plain") { line("PREDATES-CLI", "stub.plain"); }
if (mode === "pass-skipped") { line("PASS", "stub.plain"); }
`);

  // The target: a local server answering 501 to everything.
  writeFileSync(join(dst, "targets/stub.mjs"), `
import http from "node:http";
export async function up() {
  const server = http.createServer((req, res) => {
    req.resume();
    res.writeHead(501, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: { code: "NOT_IMPLEMENTED_YET", message: "stub", requestId: "req_stub" } }));
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
    schema: 1, description: "the stub target", expected: {},
    lacks: { stub: { exportAuditEvents: { reason: "the stub has no audit log", step: "never" } } },
  }));

  // The CLI: the version the case names (STUB_CLI_VERSION; empty is a CLI
  // built from source).
  const clients = join(dst, "clients.mjs");
  writeFileSync(clients, readFileSync(clients, "utf8").replace(
    "export async function resolveCli(spec, {",
    `export async function resolveCli(spec, { workDir }) {
  const path = (await import("node:path")).join(workDir, "stub-cli.cjs");
  (await import("node:fs")).writeFileSync(path, "");
  const go = spec.startsWith("go:");
  return { spec: go ? "go" : spec, path, version: process.env.STUB_CLI_VERSION || null, commit: null, sha256: "0".repeat(64), verified: null, native: go };
}
export async function resolveCliReal(spec, {`,
  ));

  // The Go CLI lacks scan.
  writeFileSync(join(dst, "client-go.json"), JSON.stringify({ schema: 1, lacksFeatures: { scan: { reason: "not ported yet", slice: "5.4d" } } }));
});

after(() => rmSync(root, { recursive: true, force: true }));

/** Runs the copied runner on the stub suite: its exit status, output and report. */
function run(mode, cliVersion = "", cli = "source") {
  const report = join(root, `report-${mode}-${cliVersion || "source"}-${cli === "source" ? "ts" : "go"}.json`);
  const r = spawnSync(process.execPath, [join(root, "scripts/conformance/run.mjs"), "--target", "stub", "--cli", cli, "--suite", "stub", "--report", report], {
    encoding: "utf8",
    timeout: 120_000,
    env: { ...process.env, STUB_MODE: mode, STUB_CLI_VERSION: cliVersion },
  });
  let parsed = null;
  try {
    parsed = JSON.parse(readFileSync(report, "utf8"));
  } catch {}
  return { status: r.status, out: r.stdout + r.stderr, report: parsed };
}

const outcomeOf = (report, id) => report.checks.find((c) => c.id === id)?.outcome;

test("the runner: a skipped group's checks report nothing, and the run passes", () => {
  const r = run("plain");
  assert.equal(r.status, 0, r.out);
  assert.equal(outcomeOf(r.report, "stub.base"), "pass");
  assert.equal(outcomeOf(r.report, "stub.featured"), "target-lacks");
  assert.equal(outcomeOf(r.report, "stub.plain"), "target-lacks");
});

test("the runner: a PREDATES-CLI the CLI's version confirms passes; a bogus one fails the run", () => {
  const genuine = run("predates", "0.10.0");
  assert.equal(genuine.status, 0, genuine.out);
  assert.equal(outcomeOf(genuine.report, "stub.base"), "pass");
  for (const [mode, version] of [["predates", ""], ["predates", "0.11.0"], ["predates-plain", "0.10.0"]]) {
    const r = run(mode, version);
    assert.equal(r.status, 1, `${mode} with CLI ${version || "source"}: ${r.out}`);
    assert.match(r.out, /operation group audit is skipped on this target/, `${mode} with CLI ${version || "source"}`);
  }
});

test("the runner: a skipped group's PASS fails the run", () => {
  const r = run("pass-skipped");
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /stub\.plain reported PASS, but its operation group audit is skipped on this target/);
});

test("the runner: a suite that exits early, or crashes, fails the run", () => {
  for (const [mode, why] of [["exit-early", /exited 3 without reporting a failed check/], ["crash", /the stub suite crashed|exited 1 without reporting a failed check/]]) {
    const r = run(mode);
    assert.equal(r.status, 1, `${mode}: ${r.out}`);
    assert.match(r.out, why, mode);
    assert.match(r.out, /stub\.base/, `${mode}: the missing check is named`);
  }
});

// The Go CLI's gaps (lib/client-lacks.mjs): client-go.json says it lacks scan.

test("the runner: a check of a feature the Go CLI lacks reports client-lacks, whatever the suite printed", () => {
  const r = run("scan-fails", "", "go:/stub/varlatch");
  assert.equal(r.status, 0, r.out);
  assert.equal(outcomeOf(r.report, "stub.scanned"), "client-lacks");
  assert.equal(outcomeOf(r.report, "stub.base"), "pass");
  assert.deepEqual(r.report.clientLacks.stale, []);
});

test("the runner: a lacking check that passes is a stale entry, and fails the run", () => {
  const r = run("plain", "", "go:/stub/varlatch");
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /stub\.scanned passed, but client-go\.json says the CLI lacks scan: remove the entry/);
  assert.deepEqual(r.report.clientLacks.stale, [{ id: "stub.scanned", features: ["scan"] }]);
});

test("the runner: client-lacks never hides a check of a feature the Go CLI has", () => {
  const r = run("base-fails", "", "go:/stub/varlatch");
  assert.equal(r.status, 1, r.out);
  assert.equal(outcomeOf(r.report, "stub.base"), "fail");
});

test("the runner: a TypeScript CLI lacks nothing, whatever client-go.json says", () => {
  const r = run("scan-fails");
  assert.equal(r.status, 1, r.out);
  assert.equal(outcomeOf(r.report, "stub.scanned"), "fail");
});
