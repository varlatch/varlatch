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
 *
 * The CLI under test is a fake: it prints STUB_CLI_OUT on stderr and exits
 * STUB_CLI_EXIT, run with Node (a TypeScript CLI) or directly (the Go CLI).
 * The stub suite's step-* modes use suite-kit as a real suite does: they run
 * one CLI step and judge checks that depend on it (`check(..., { after })`).
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
      handover: { title: "a stub hand-over suite", script: "scripts/conformance/stub-handover.mjs", client: "go", operations: [] },
    },
    checks: {
      "stub.base": { suite: "stub", kind: "conformance", title: "the base check" },
      "stub.scanned": { suite: "stub", kind: "conformance", feature: "scan", title: "a scan check outside the group" },
      "stub.featured": { suite: "stub", kind: "conformance", group: "audit", feature: "scan", title: "a scan check in the group" },
      "stub.plain": { suite: "stub", kind: "conformance", group: "audit", title: "a plain check in the group" },
      "handover.both": { suite: "handover", kind: "go-client", title: "the Go CLI and the TypeScript CLI hand over" },
      ...Object.fromEntries(Object.keys(features).filter((f) => f !== "scan").map((f) => [`stub.core-${f}`, { suite: "stub", kind: "conformance", feature: f, title: f }])),
    },
  };
  writeFileSync(join(dst, "inventory.json"), JSON.stringify(inventory, null, 2));
  const coreChecks = Object.keys(inventory.checks).filter((id) => id.startsWith("stub.core-"));
  writeFileSync(join(dst, "plan.mjs"), 'export const PLAN = [{ suite: "stub", args: () => [] }, { suite: "handover", args: () => [] }];\n');

  // The hand-over suite: PASS when the runner named the TypeScript CLI beside
  // the Go CLI, else a failure; N/A on its own in mode handover-na.
  writeFileSync(join(dst, "stub-handover.mjs"), `
const ok = Boolean(process.env.VARLATCH_HANDOVER_CLI) && process.env.VARLATCH_CLI_NATIVE === "1";
console.log(\`\${process.env.STUB_MODE === "handover-na" ? "N/A" : ok ? "PASS" : "FAIL"}  [handover.both] handover.both\`);
// The end, as every suite ends: suite-kit's finish().
const { reporter } = await import("./suite-kit.mjs");
reporter().finish();
`);

  // The suite: what it prints and how it ends, by STUB_MODE.
  writeFileSync(join(dst, "stub-suite.mjs"), `
const mode = process.env.STUB_MODE;
const line = (status, id) => console.log(\`\${status}  [\${id}] \${id}\`);
// A CLI step and the checks that depend on it, judged through suite-kit.
// A refused agent-safe run, as in the broker suite: the claim "the refused
// run issued nothing" holds only once the refusal itself was observed.
const kitMode = mode.startsWith("step-") || mode.startsWith("raw-") || mode.startsWith("end-");
if (mode.startsWith("end-")) {
  // The end-of-suite channel's cases: every check but the lacking one
  // reported, then each mode ends its own way.
  const earlyNonce = process.env.CONFORMANCE_END_NONCE;
  const { reporter } = await import("./suite-kit.mjs");
  const { spawnSync } = await import("node:child_process");
  const { writeSync } = await import("node:fs");
  const kit = reporter();
  for (const id of ${JSON.stringify(coreChecks)}) kit.check(id, id, true);
  kit.check("stub.base", "stub.base", true);
  if (mode === "end-finish") {
    kit.finish();
  } else if (mode === "end-natural") {
    // No finish(): the script runs to its natural end.
  } else if (mode === "end-stalled") {
    // A stalled top-level await, with a beforeExit that prints a marker-looking line.
    process.once("beforeExit", () => console.log("END  [stub]"));
    await new Promise(() => {});
  } else if (mode === "end-fake-marker") {
    // A child prints marker-looking lines on stdout and stderr; the suite never finishes.
    spawnSync("sh", ["-c", 'echo "END stub $CONFORMANCE_END_NONCE 0"; echo "END  [stub]"; echo "END stub $CONFORMANCE_END_NONCE 0" >&2'], { stdio: ["ignore", "inherit", "inherit"] });
    process.exit(0);
  } else if (mode === "end-leaked-fd3") {
    // A child given fd 3 on purpose writes a marker there; then the suite finishes.
    spawnSync("sh", ["-c", 'echo "END stub \${CONFORMANCE_END_NONCE:-} 0" >&3'], { stdio: ["ignore", "inherit", "inherit", "inherit"] });
    kit.finish();
  } else if (mode === "end-default-child") {
    // A child started as the kit's helpers start them (default stdio) gets neither fd 3 nor the nonce.
    spawnSync("sh", ["-c", '{ echo "END stub x 0" >&3; } 2>/dev/null && echo fd3-leaked || echo fd3-not-inherited; echo "nonce=\${CONFORMANCE_END_NONCE:-absent}"'], { stdio: ["ignore", "inherit", "inherit"] });
    kit.finish();
  } else if (mode === "end-exit-mismatch") {
    // A well-formed marker saying 0, then exit 1.
    writeSync(3, \`END stub \${earlyNonce} 0\\n\`);
    process.exit(1);
  } else if (mode === "end-signal") {
    // A well-formed marker, then killed.
    writeSync(3, \`END stub \${earlyNonce} 0\\n\`);
    process.kill(process.pid, "SIGKILL");
  }
} else if (kitMode) {
  const { reporter, cliCommand } = await import("./suite-kit.mjs");
  const { spawnSync } = await import("node:child_process");
  const kit = reporter();
  for (const id of ${JSON.stringify(coreChecks)}) kit.check(id, id, true);
  if (mode === "step-kit-fail-then-crash") {
    // An expected FAIL, then a crash before the lacking check.
    kit.check("stub.base", "stub.base", false);
    throw new Error("the stub suite crashed after a failure");
  }
  if (mode === "raw-not-built") {
    // A suite that prints NOT-BUILT itself, whatever the CLI did.
    console.log(\`NOT-BUILT  [stub.base] \${process.env.STUB_RAW_LINE}\`);
    kit.check("stub.scanned", "stub.scanned", false);
    kit.finish();
  }
  const [cmd, args] = cliCommand(["run", "--agent-safe", "--", "node", "-e", "0"]);
  const r = spawnSync(cmd, args, { encoding: "utf8" });
  const step = { code: r.status, out: (r.stdout ?? "") + (r.stderr ?? "") };
  const refused = step.code !== 0 && step.out.includes("DATABASE_URL has no substitution target");
  const issuedNothing = true; // what a step that never ran leaves behind too
  if (mode === "step-observed") {
    kit.check("stub.base", "the refused run issued nothing", refused && issuedNothing, step.out, { after: step });
    kit.check("stub.scanned", "the run refused, naming the item", refused, step.out, { after: step });
  } else if (mode === "step-vacuous") {
    // The shape that passed vacuously: the absence alone, no dependency.
    kit.check("stub.base", "stub.base", true);
    kit.check("stub.scanned", "the refused run issued nothing", issuedNothing, step.out);
  } else if (mode === "step-vacuous-after") {
    kit.check("stub.base", "stub.base", true);
    kit.check("stub.scanned", "the refused run issued nothing", issuedNothing, step.out, { after: step });
  } else if (mode === "step-scanned-only") {
    // One check of the lacking feature, depending on the step.
    kit.check("stub.base", "stub.base", true);
    kit.check("stub.scanned", "the run refused, naming the item", refused, step.out, { after: step });
  } else if (mode === "step-group") {
    // The rest of a feature's checks, after a step refused as not built.
    if (!kit.notBuilt(["stub.scanned"], step)) kit.check("stub.scanned", "the run refused, naming the item", refused, step.out);
    kit.check("stub.base", "stub.base", true);
  }
  kit.finish();
}
if (!kitMode) {
  if (mode === "crash") throw new Error("the stub suite crashed");
  if (mode === "exit-early") process.exit(3);
  for (const id of ${JSON.stringify(coreChecks)}) line("PASS", id);
  line(mode === "base-fails" || mode === "fail-then-crash" ? "FAIL" : "PASS", "stub.base");
  if (mode === "fail-then-crash") throw new Error("the stub suite crashed after a failure");
  if (!mode.startsWith("scan-silent")) line(mode === "scan-fails" ? "FAIL" : "PASS", "stub.scanned");
  if (mode === "predates") { line("PREDATES-CLI", "stub.featured"); }
  if (mode === "predates-plain") { line("PREDATES-CLI", "stub.plain"); }
  if (mode === "pass-skipped") { line("PASS", "stub.plain"); }
  // The end-of-suite marker, as suite-kit's reporter prints it; never in the
  // modes that end without it.
  // The end, as every suite ends: suite-kit's finish(), never in the modes
  // that end without it.
  if (!mode.endsWith("no-end")) {
    const { reporter } = await import("./suite-kit.mjs");
    reporter().finish();
  }
}
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
  (await import("node:fs")).writeFileSync(path, "#!/usr/bin/env node\\nprocess.stderr.write((process.env.STUB_CLI_OUT ?? \\"\\") + \\"\\\\n\\");\\nprocess.exit(Number(process.env.STUB_CLI_EXIT ?? 0));\\n", { mode: 0o755 });
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
function run(mode, cliVersion = "", cli = "source", extra = ["--suite", "stub"], env = {}) {
  const report = join(root, `report-${mode}-${cliVersion || "source"}-${cli === "source" ? "ts" : "go"}-${extra.join("_").replace(/\W/g, "")}.json`);
  const r = spawnSync(process.execPath, [join(root, "scripts/conformance/run.mjs"), "--target", "stub", "--cli", cli, ...extra, "--report", report], {
    encoding: "utf8",
    timeout: 120_000,
    env: { ...process.env, STUB_MODE: mode, STUB_CLI_VERSION: cliVersion, ...env },
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

test("the runner: a check of a feature the Go CLI lacks that gave no verdict reports client-lacks", () => {
  const r = run("scan-silent", "", "go:/stub/varlatch");
  assert.equal(r.status, 0, r.out);
  assert.equal(outcomeOf(r.report, "stub.scanned"), "client-lacks");
  assert.equal(outcomeOf(r.report, "stub.base"), "pass");
  assert.deepEqual(r.report.clientLacks.stale, []);
});

test("the runner: a FAIL of a feature the Go CLI lacks stays a failure, whatever client-go.json lists", () => {
  const r = run("scan-fails", "", "go:/stub/varlatch");
  assert.equal(r.status, 1, r.out);
  assert.equal(outcomeOf(r.report, "stub.scanned"), "fail");
  assert.equal(outcomeOf(r.report, "stub.base"), "pass");
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

// The hand-over (kind go-client): the Go CLI under test with a TypeScript CLI beside it.

test("the runner: a hand-over suite is not applicable with a TypeScript CLI under test, and is not started", () => {
  const r = run("handover-na", "", "source", ["--suite", "handover"]);
  assert.equal(r.status, 0, r.out);
  assert.equal(outcomeOf(r.report, "handover.both"), "not-applicable");
  assert.match(r.out, /not run, the CLI under test is not the Go CLI/);
  assert.equal(r.report.handoverCli, null);
});

test("the runner: with the Go CLI, a hand-over suite runs with the TypeScript CLI named beside it", () => {
  const r = run("plain", "", "go:/stub/varlatch", ["--suite", "handover"]);
  assert.equal(r.status, 0, r.out);
  assert.equal(outcomeOf(r.report, "handover.both"), "pass");
  assert.equal(r.report.handoverCli.spec, "0.22.0");
  const chosen = run("plain", "", "go:/stub/varlatch", ["--suite", "handover", "--handover-cli", "source"]);
  assert.equal(chosen.status, 0, chosen.out);
  assert.equal(chosen.report.handoverCli.spec, "source");
});

test("the runner: with the Go CLI, a hand-over check that says not applicable fails the run", () => {
  const r = run("handover-na", "", "go:/stub/varlatch", ["--suite", "handover"]);
  assert.equal(r.status, 1, r.out);
  assert.equal(outcomeOf(r.report, "handover.both"), "fail");
});

test("the runner: --handover-cli pairs the Go CLI with a TypeScript CLI only", () => {
  for (const [cli, extra, why] of [
    ["source", ["--handover-cli", "0.22.0"], /--handover-cli pairs the Go CLI/],
    ["go:/stub/varlatch", ["--handover-cli", "go:/x"], /--handover-cli names a TypeScript CLI/],
  ]) {
    const r = run("plain", "", cli, ["--suite", "handover", ...extra]);
    assert.equal(r.status, 64, r.out);
    assert.match(r.out, why);
  }
});

// A step the CLI refused as not built yet (suite-kit's NOT_BUILT, the Go
// CLI's exact refusal on a usage exit): its checks observed nothing.

const NOT_BUILT_LINE = "varlatch run: not in this build of the Go CLI yet (slice 5.4b); use the TypeScript CLI for it until then";
const refusedAsNotBuilt = { STUB_CLI_OUT: NOT_BUILT_LINE, STUB_CLI_EXIT: "64" };
const refusedForTarget = { STUB_CLI_OUT: "varlatch run: DATABASE_URL has no substitution target: add --target DATABASE_URL=header:authorization", STUB_CLI_EXIT: "1" };
const failedOtherwise = { STUB_CLI_OUT: "varlatch run: could not reach the server", STUB_CLI_EXIT: "1" };

test("the runner: a check of what a refused step left behind passes only after observing the refusal", () => {
  for (const cli of ["source", "go:/stub/varlatch"]) {
    // The refusal the checks are about, observed: both pass (scan is lacking for Go).
    const honest = run("step-observed", "", cli, undefined, refusedForTarget);
    assert.equal(outcomeOf(honest.report, "stub.base"), "pass", `${cli}: ${honest.out}`);
    // Any other outcome of the step: "nothing was issued" holds too, and
    // proves nothing, so the check fails on any client.
    const vacuous = run("step-observed", "", cli, undefined, failedOtherwise);
    assert.equal(vacuous.status, 1, `${cli}: ${vacuous.out}`);
    assert.equal(outcomeOf(vacuous.report, "stub.base"), "fail", cli);
  }
});

test("the runner: the Go CLI's not-built refusal makes a lacking feature's checks client-lacks, never stale", () => {
  // A check after the refusal whose verdict would have been a vacuous pass
  // reports NOT-BUILT, so the stale-entry probe never sees a pass ...
  const after = run("step-vacuous-after", "", "go:/stub/varlatch", undefined, refusedAsNotBuilt);
  assert.equal(after.status, 0, after.out);
  assert.equal(outcomeOf(after.report, "stub.scanned"), "client-lacks");
  assert.deepEqual(after.report.clientLacks.notBuilt, [{ id: "stub.scanned", refusal: NOT_BUILT_LINE }]);
  assert.deepEqual(after.report.clientLacks.stale, []);
  // ... where the same check without its dependency passed, and failed the run as stale.
  const vacuous = run("step-vacuous", "", "go:/stub/varlatch", undefined, refusedAsNotBuilt);
  assert.equal(vacuous.status, 1, vacuous.out);
  assert.deepEqual(vacuous.report.clientLacks.stale, [{ id: "stub.scanned", features: ["scan"] }]);
  // A feature's remaining checks, after the refusal (kit.notBuilt).
  const group = run("step-group", "", "go:/stub/varlatch", undefined, refusedAsNotBuilt);
  assert.equal(group.status, 0, group.out);
  assert.equal(outcomeOf(group.report, "stub.scanned"), "client-lacks");
  assert.equal(outcomeOf(group.report, "stub.base"), "pass");
});

test("the runner: a check refused as not built that needs no listed feature fails, naming the fix", () => {
  // stub.base needs no feature client-go.json lists: the refusal shows
  // the inventory or client-go.json is wrong, and client-lacks never covers
  // a check the Go CLI claims to have.
  const r = run("step-observed", "", "go:/stub/varlatch", undefined, refusedAsNotBuilt);
  assert.equal(r.status, 1, r.out);
  assert.equal(outcomeOf(r.report, "stub.base"), "fail");
  assert.match(r.report.checks.find((c) => c.id === "stub.base").why, /^client-go\.json lists no feature this check needs, but the Go CLI refused a step it needs as not built: .*\(varlatch run: not in this build/);
  assert.equal(outcomeOf(r.report, "stub.scanned"), "client-lacks");
});

test("the runner: another Go CLI error on exit 64, on a lacking feature's step, fails the run", () => {
  // Sol's case: the step fails for a reason that is not the not-built
  // refusal; the check of a feature client-go.json lists fails, and the
  // failure is never turned into client-lacks.
  const r = run("step-scanned-only", "", "go:/stub/varlatch", undefined, { STUB_CLI_OUT: "varlatch run: could not load configuration", STUB_CLI_EXIT: "64" });
  assert.equal(r.status, 1, r.out);
  assert.equal(outcomeOf(r.report, "stub.scanned"), "fail");
  assert.equal(outcomeOf(r.report, "stub.base"), "pass");
  assert.deepEqual(r.report.clientLacks.notBuilt, []);
  // The refusal itself, on the same step: client-lacks, and the run passes.
  const refused = run("step-scanned-only", "", "go:/stub/varlatch", undefined, refusedAsNotBuilt);
  assert.equal(refused.status, 0, refused.out);
  assert.equal(outcomeOf(refused.report, "stub.scanned"), "client-lacks");
});

test("the runner: only the Go CLI's exact refusal, on a usage exit, counts as not built", () => {
  for (const [why, env] of [
    ["another message on exit 64", { STUB_CLI_OUT: "varlatch run: not in this build yet; use the TypeScript CLI", STUB_CLI_EXIT: "64" }],
    ["the refusal on another exit", { STUB_CLI_OUT: NOT_BUILT_LINE, STUB_CLI_EXIT: "1" }],
    ["the refusal inside a longer line", { STUB_CLI_OUT: `error: ${NOT_BUILT_LINE}`, STUB_CLI_EXIT: "64" }],
  ]) {
    const r = run("step-observed", "", "go:/stub/varlatch", undefined, env);
    assert.equal(r.status, 1, `${why}: ${r.out}`);
    assert.equal(outcomeOf(r.report, "stub.base"), "fail", why);
    assert.deepEqual(r.report.clientLacks.notBuilt, [], why);
  }
  // A NOT-BUILT line the suite printed with anything but the refusal fails the run.
  const raw = run("raw-not-built", "", "go:/stub/varlatch", undefined, { STUB_RAW_LINE: "varlatch run: not built" });
  assert.equal(raw.status, 1, raw.out);
  assert.match(raw.out, /stub\.base reported NOT-BUILT with "varlatch run: not built", which is not the Go CLI's not-built refusal/);
});

test("the runner: a TypeScript CLI never takes the not-built path, whatever it prints", () => {
  // The very refusal, from a TypeScript CLI: the checks judge it as any
  // other output, and fail.
  const r = run("step-observed", "", "source", undefined, refusedAsNotBuilt);
  assert.equal(r.status, 1, r.out);
  assert.equal(outcomeOf(r.report, "stub.base"), "fail");
  assert.deepEqual(r.report.clientLacks.notBuilt, []);
  // A suite that prints NOT-BUILT under a TypeScript CLI fails the run.
  const raw = run("raw-not-built", "", "source", undefined, { STUB_RAW_LINE: NOT_BUILT_LINE });
  assert.equal(raw.status, 1, raw.out);
  assert.match(raw.out, /stub\.base reported NOT-BUILT, which only the Go CLI's refusal gives; the CLI under test is source/);
});

// The end of a suite: only suite-kit's finish(), on fd 3 with the runner's
// nonce, then an exit with the code it names. A suite that did not end so
// never counts its unreported checks as lacking.

test("the runner: a crash after an expected FAIL fails the run, and the unreported lacking check is no client-lacks", () => {
  for (const mode of ["fail-then-crash", "step-kit-fail-then-crash"]) {
    const r = run(mode, "", "go:/stub/varlatch");
    assert.equal(r.status, 1, `${mode}: ${r.out}`);
    assert.match(r.out, /stub: did not finish: it never called finish\(\)/, mode);
    assert.equal(outcomeOf(r.report, "stub.scanned"), "fail", mode);
  }
});

test("the runner: a suite that finishes gets client-lacks for its unreported lacking checks, and passes without any", () => {
  for (const mode of ["scan-silent", "end-finish"]) {
    const r = run(mode, "", "go:/stub/varlatch");
    assert.equal(r.status, 0, `${mode}: ${r.out}`);
    assert.equal(outcomeOf(r.report, "stub.scanned"), "client-lacks", mode);
    assert.equal(outcomeOf(r.report, "stub.base"), "pass", mode);
  }
  const ts = run("plain");
  assert.equal(ts.status, 0, ts.out);
});

test("the runner: a suite that never calls finish() fails the run: no crash, a natural end, or a stalled await", () => {
  for (const [mode, cli] of [["plain-no-end", "source"], ["scan-silent-no-end", "go:/stub/varlatch"], ["end-natural", "go:/stub/varlatch"], ["end-stalled", "go:/stub/varlatch"]]) {
    const r = run(mode, "", cli);
    assert.equal(r.status, 1, `${mode}: ${r.out}`);
    assert.match(r.out, /stub: did not finish: it never called finish\(\)/, mode);
    if (cli !== "source") assert.equal(outcomeOf(r.report, "stub.scanned"), "fail", mode);
  }
});

test("the runner: marker-looking output on stdout or stderr is no end", () => {
  const r = run("end-fake-marker", "", "go:/stub/varlatch");
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /END {2}\[stub\]/, "the child's lines reached the output");
  assert.match(r.out, /stub: did not finish: it never called finish\(\)/);
  assert.equal(outcomeOf(r.report, "stub.scanned"), "fail");
});

test("the runner: fd 3 and the nonce reach no child the kit's way; a child given fd 3 on purpose spoils the end", () => {
  const plain = run("end-default-child", "", "go:/stub/varlatch");
  assert.equal(plain.status, 0, plain.out);
  assert.match(plain.out, /fd3-not-inherited/);
  assert.match(plain.out, /nonce=absent/);
  const leaked = run("end-leaked-fd3", "", "go:/stub/varlatch");
  assert.equal(leaked.status, 1, leaked.out);
  assert.match(leaked.out, /stub: did not finish: its end-of-suite channel carried 2 lines, not one marker/);
  assert.equal(outcomeOf(leaked.report, "stub.scanned"), "fail");
});

test("the runner: an exit that does not match the marker fails the run: another code, or a signal", () => {
  const code = run("end-exit-mismatch", "", "go:/stub/varlatch");
  assert.equal(code.status, 1, code.out);
  assert.match(code.out, /stub: did not finish: it exited 1, but its end-of-suite marker says 0/);
  assert.equal(outcomeOf(code.report, "stub.scanned"), "fail");
  const signal = run("end-signal", "", "go:/stub/varlatch");
  assert.equal(signal.status, 1, signal.out);
  assert.match(signal.out, /stub: did not finish: it was killed by SIGKILL after its end-of-suite marker/);
});
