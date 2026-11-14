#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { redactTokens } from "../redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * The conformance runner (ADR-0059 step 2; scripts/conformance/README.md).
 * It starts a target, runs the suites of plan.mjs against it in order, each
 * as its own process, collects one result per check ID, and judges the run
 * against inventory.json.
 *
 *   node scripts/conformance/run.mjs --target <target> --cli source|<version>
 *        [--report <file.json>] [--suite <name>]...
 *        [--gate --walkthrough <docs/evidence/file> [--recent-cli-report <file.json>]]
 *
 *   --target   the server under test (targets/index.mjs): ts-source,
 *              ts-release:<version> (a signed release, verified and pulled
 *              by digest), go-binary:<path> (a stub until ADR-0059 step 3)
 *   --cli      the CLI under test: `source` is apps/cli/dist/varlatch.cjs; a
 *              version is a released CLI pinned in clients.json, downloaded
 *              and verified before anything starts (clients.mjs). The sdk
 *              suite drives packages/sdk from the same source: this
 *              checkout, or the pinned release's commit.
 *   --report   also write the report as JSON to this file
 *   --suite    run only these suites (and the setup they need); the report
 *              then covers only their checks
 *   --gate     judge the run as ADR-0059's gates G1 and G2 are judged
 *              (lib/gate.mjs): no expected failure, every replacement present
 *              and passing, the browser-walkthrough evidence named with
 *              --walkthrough, and, when a check predates the CLI, the passing
 *              gate report of a run with a recent CLI (--recent-cli-report)
 *
 * The target's expected failures (expect/<target name>.json, lib/expect.mjs)
 * are applied to the result: an expected failure is reported as one, and an
 * expected failure that passes fails the run.
 *
 * Exit status 0 only when every check in scope accounted for itself as the
 * inventory and the expectations require (and, with --gate, the gate
 * passed); 1 otherwise; 64 on a usage error.
 */
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSdk, loadClients, resolveCli, sha256 } from "./clients.mjs";
import { applyExpectations, expectationsFor, validateExpectations } from "./lib/expect.mjs";
import { judgeGate } from "./lib/gate.mjs";
import { evaluate, validateInventory } from "./lib/inventory.mjs";
import { assess, BUDGET, waitMs, WINDOW_MS } from "./lib/request-log.mjs";
import { parseSuiteOutput, resultLine } from "./lib/results.mjs";
import { PLAN } from "./plan.mjs";
import { loadTarget } from "./targets/index.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");
const SUITE_TIMEOUT_MS = 30 * 60_000;
const SEEDED_SECRET = "postgres://dev-db";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function usage(message) {
  console.error(
    `${message}\nUsage: run.mjs --target ts-source|ts-release:<version>|go-binary:<path> --cli source|<version> [--report <file.json>] [--suite <name>]...` +
      " [--gate --walkthrough <docs/evidence/file> [--recent-cli-report <file.json>]]",
  );
  process.exit(64);
}

function parseArgs(argv) {
  const options = { suites: [] };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const value = () => argv[++i] ?? usage(`${flag} needs a value`);
    if (flag === "--target") options.target = value();
    else if (flag === "--cli") options.cli = value();
    else if (flag === "--report") options.report = value();
    else if (flag === "--suite") options.suites.push(value());
    else if (flag === "--gate") options.gate = true;
    else if (flag === "--walkthrough") options.walkthrough = value();
    else if (flag === "--recent-cli-report") options.recentCliReport = value();
    else usage(`unknown argument ${flag}`);
  }
  if (!options.target) usage("--target is required");
  if (!options.cli) usage("--cli is required");
  if (!options.gate && (options.walkthrough || options.recentCliReport)) usage("--walkthrough and --recent-cli-report belong to --gate");
  if (options.gate && options.suites.length > 0) usage("--gate judges a whole run: --suite is not allowed");
  if (options.gate && !options.walkthrough) usage("--gate needs the browser-walkthrough evidence file: --walkthrough docs/evidence/<file>");
  return options;
}

/** The browser-walkthrough evidence as the gate judges it: its path in the checkout, and whether it is there. */
function walkthroughEvidence(file) {
  const absolute = resolve(file);
  const path = relative(REPO_ROOT, absolute).split(sep).join("/");
  const exists = existsSync(absolute) && statSync(absolute).isFile();
  return { path, exists, size: exists ? statSync(absolute).size : 0, sha256: exists ? sha256(readFileSync(absolute)) : null };
}

/** The target's expected failures file (expect/<name>.json), validated; an empty one when there is none. */
function loadExpectations(targetName, inventory) {
  const file = join(HERE, "expect", `${targetName}.json`);
  if (!existsSync(file)) return { schema: 1, expected: {} };
  const parsed = JSON.parse(readFileSync(file, "utf8"));
  const problems = validateExpectations(parsed, { targetName, inventory, cliVersions: Object.keys(loadClients().cli) });
  if (problems.length > 0) throw new Error(`expect/${targetName}.json is not valid:\n  ${problems.join("\n  ")}`);
  return parsed;
}

/** Runs one suite as its own process group; streams its output and returns it. */
function runSuite(script, args, env, cwd) {
  return new Promise((resolvePromise) => {
    const child = spawn(process.execPath, [script, ...args], { cwd, env, stdio: ["ignore", "pipe", "pipe"], detached: true });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => {
      stdout += d;
      process.stdout.write(d);
    });
    child.stderr.on("data", (d) => {
      stderr += d;
      process.stderr.write(d);
    });
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      killGroup(child.pid);
    }, SUITE_TIMEOUT_MS);
    running.add(child.pid);
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      running.delete(child.pid);
      // Browsers and CLIs a suite started go with it.
      killGroup(child.pid);
      resolvePromise({ code, signal, timedOut, stdout, stderr });
    });
    child.on("error", (err) => {
      stderr += String(err);
    });
  });
}

const running = new Set();
function killGroup(pid) {
  try {
    process.kill(-pid, "SIGKILL");
  } catch {
    // Already gone.
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const inventory = JSON.parse(readFileSync(join(HERE, "inventory.json"), "utf8"));
  const shape = validateInventory(inventory);
  if (shape.length > 0) throw new Error(`inventory.json is not valid:\n  ${shape.join("\n  ")}`);
  const planned = PLAN.filter((e) => e.setup || inventory.suites[e.suite]);
  const unknown = PLAN.filter((e) => !e.setup && !inventory.suites[e.suite]).map((e) => e.suite);
  const unplanned = Object.keys(inventory.suites).filter((s) => !PLAN.some((e) => e.suite === s));
  if (unknown.length || unplanned.length) throw new Error(`plan.mjs and inventory.json disagree: not in the inventory: ${unknown.join(", ") || "none"}; not in the plan: ${unplanned.join(", ") || "none"}`);
  for (const s of options.suites) if (!inventory.suites[s]) usage(`--suite ${s}: no such suite`);
  const inScope = (suite) => options.suites.length === 0 || options.suites.includes(suite);

  let loaded;
  try {
    loaded = await loadTarget(options.target);
  } catch (err) {
    usage(err.message);
  }
  const { name: targetName, argument: targetArgument, target, capabilities, expectKey } = loaded;
  const expectations = loadExpectations(targetName, inventory);
  // Gate evidence is checked before anything starts: a gate run without it
  // cannot pass, so it does not spend an hour finding that out.
  const walkthrough = options.walkthrough ? walkthroughEvidence(options.walkthrough) : null;
  if (walkthrough && !walkthrough.exists) usage(`--walkthrough ${options.walkthrough}: no such file`);
  let recentCli = null;
  if (options.recentCliReport) {
    try {
      recentCli = JSON.parse(readFileSync(options.recentCliReport, "utf8"));
    } catch (err) {
      usage(`--recent-cli-report ${options.recentCliReport}: ${err.message}`);
    }
  }
  const scratch = mkdtempSync(join(tmpdir(), "conformance-run-"));
  const stateFile = join(scratch, "target.json");
  // The clients, verified before the target starts: a CLI that fails
  // verification or reports another version stops the run here.
  let cli;
  let sdk;
  try {
    cli = await resolveCli(options.cli, { repoRoot: REPO_ROOT, workDir: scratch });
    if (!options.suites.length || options.suites.some((s) => s === "sdk")) {
      sdk = await buildSdk(cli, { repoRoot: REPO_ROOT, workDir: scratch });
    }
  } catch (err) {
    rmSync(scratch, { recursive: true, force: true });
    if (err.usage) usage(err.message);
    console.error(`--- the clients could not be prepared: ${err.message}`);
    console.log("CONFORMANCE RUN FAILED");
    process.exit(1);
  }
  const expected = expectationsFor(expectations, expectKey, cli.spec);
  const report = {
    target: options.target,
    expectKey,
    cli: { spec: cli.spec, version: cli.version, commit: cli.commit, sha256: cli.sha256, verified: cli.verified },
    sdk: sdk ? { from: cli.commit ? `release ${cli.version} (${cli.commit})` : "this checkout", commit: sdk.commit, sha256: sdk.sha256 } : null,
    partial: options.suites.length > 0 ? options.suites : false,
    startedAt: new Date().toISOString(),
    suites: [],
  };
  const reports = [];
  const errors = [];
  const windows = {};
  let state = null;
  let stopped = null;

  const cleanup = async () => {
    for (const pid of running) killGroup(pid);
    if (state) {
      const s = state;
      state = null;
      await target.down(s).catch((err) => console.error(`down failed: ${err.message}`));
    }
    rmSync(scratch, { recursive: true, force: true });
  };
  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.once(signal, async () => {
      console.error(`--- ${signal}: removing the target`);
      await cleanup();
      process.exit(130);
    });
  }

  try {
    console.log(`--- target ${options.target}, CLI ${cli.spec} (${cli.path}, sha256 ${cli.sha256})`);
    if (sdk) console.log(`--- sdk from ${report.sdk.from}: ${sdk.path}, sha256 ${sdk.sha256}`);
    try {
      // `onState` hands over the state before up creates anything, so a
      // signal during startup still removes what up has created so far.
      state = await target.up({ repoRoot: REPO_ROOT, argument: targetArgument, onState: (s) => (state = s) });
    } catch (err) {
      state = err.state ?? null;
      throw err;
    }
    writeFileSync(stateFile, JSON.stringify(state));
    if (target.describe) report.targetDetails = target.describe(state);
    // VARLATCH_CLI_VERSION is the verified version (empty for source): the
    // suites gate feature groups on it, and the runner checks every
    // predates-cli result against it again.
    const suiteEnv = {
      ...process.env,
      VARLATCH_CLI: cli.path,
      VARLATCH_CLI_VERSION: cli.version ?? "",
      VARLATCH_SDK: sdk?.path ?? "",
      CONFORMANCE_TARGET_STATE: stateFile,
    };
    const ctx = { origin: target.origin(state) };
    const admin = (args) => target.recover(state, ctx.adminId, args);
    ctx.grant = async () => {
      const url = (await admin({})).match(/http:\/\/\S*enroll#\S*/)?.[0];
      if (!url) throw new Error("recover printed no enrollment URL");
      return url;
    };
    ctx.cliCredential = async () => (await admin({ cliCredential: true })).trim().split("\n").pop().trim();
    ctx.seededSecret = SEEDED_SECRET;

    const pace = async (suite) => {
      const ms = waitMs(await target.requestLog(state), Date.now());
      if (ms > 0) {
        console.log(`--- request budget: waiting ${Math.ceil(ms / 1000)} s before ${suite} for the server's request window to have room`);
        await sleep(ms);
      }
    };

    for (const entry of planned) {
      if (entry.setup === "bootstrap") {
        console.log("--- bootstrap: the first enrollment URL");
        ctx.bootstrapUrl = (await target.bootstrap(state)).match(/http:\/\/\S*enroll#\S*/)?.[0];
        if (!ctx.bootstrapUrl) throw new Error("bootstrap printed no enrollment URL");
        continue;
      }
      if (entry.setup === "seed") {
        if (!ctx.adminId) throw new Error("the passkey suite named no identity: nothing after it can run");
        console.log(`--- seed data as ${ctx.adminId}`);
        ctx.token = await ctx.cliCredential();
        await seed(ctx.origin, ctx.token);
        await target.settle?.(state);
        continue;
      }
      const suite = inventory.suites[entry.suite];
      // Suites whose work later steps need run even when not chosen (plan.mjs `always`).
      if (!inScope(entry.suite) && !entry.always) continue;
      if (entry.runner) {
        if (entry.suite === "request-budget") await requestBudget();
        continue;
      }
      const missing = (suite.needs ?? []).filter((c) => !capabilities.includes(c));
      if (missing.length > 0) {
        console.log(`--- ${suite.title}: not run, the target lacks ${missing.join(", ")}`);
        for (const [id, check] of Object.entries(inventory.checks)) {
          if (check.suite === entry.suite) reports.push({ suite: entry.suite, id, status: "N/A", text: `the target lacks ${missing.join(", ")}` });
        }
        continue;
      }
      console.log(`--- ${suite.title}`);
      const args = await entry.args(ctx);
      await pace(entry.suite);
      const around = entry.around === "convex-down" ? await convexDown(entry.suite) : null;
      const start = Date.now();
      const out = await runSuite(join(REPO_ROOT, suite.script), args, { ...suiteEnv, CONFORMANCE_SUITE: entry.suite }, scratch);
      const end = Date.now();
      (windows[entry.suite] ??= []).push({ start, end });
      if (around) await around.finish();
      const parsed = parseSuiteOutput(`${out.stdout}\n${out.stderr}`);
      for (const r of parsed.results) reports.push({ suite: entry.suite, ...r });
      for (const message of parsed.errors) errors.push({ suite: entry.suite, message });
      const failedResults = parsed.results.some((r) => r.status === "FAIL");
      if (out.timedOut) errors.push({ suite: entry.suite, message: `did not finish within ${SUITE_TIMEOUT_MS / 60_000} minutes` });
      else if (out.code !== 0 && !failedResults && parsed.errors.length === 0) {
        errors.push({ suite: entry.suite, message: `exited ${out.code ?? out.signal} without reporting a failed check` });
      }
      report.suites.push({ suite: entry.suite, start: new Date(start).toISOString(), end: new Date(end).toISOString(), exit: out.code ?? out.signal, results: parsed.results.length });
      if (entry.suite === "passkey") ctx.adminId = out.stdout.match(/idn_[a-z0-9]*/)?.[0];
    }
  } catch (err) {
    stopped = err.message;
    errors.push({ suite: "runner", message: `the run stopped: ${err.message}` });
    if (state && target.describe && !report.targetDetails) report.targetDetails = target.describe(state);
    // What the server refused so far still helps explain the failure.
    if (state && !report.requestBudget && inScope("request-budget")) {
      await requestBudget().catch((e) => errors.push({ suite: "runner", message: `request-log: ${e.message}` }));
    }
  }

  // Holds Convex down around a suite on the TypeScript stack, and reports
  // broker.convex-down-throughout; elsewhere that check does not apply.
  async function convexDown(suite) {
    const id = `${suite}.convex-down-throughout`;
    if (!capabilities.includes("ts-stack")) {
      reports.push({ suite, id, status: "N/A", text: "the target has no Convex backend" });
      return null;
    }
    const compose = (...args) => target.tsStack(state, "compose", ...args);
    const stoppedOk = (await compose("stop", "convex-backend")).status === 0;
    console.log(`--- Convex stopped for ${suite}: ${stoppedOk}`);
    return {
      finish: async () => {
        const stillDown = (await compose("ps", "-q", "--status", "running", "convex-backend")).stdout.trim() === "";
        const startedOk = (await compose("start", "convex-backend")).status === 0;
        let back = false;
        for (let i = 0; i < 60 && !back; i++) {
          back = await fetch(`${target.origin(state)}/convex/version`).then((r) => r.status === 200, () => false);
          if (!back) await sleep(2000);
        }
        const ok = stoppedOk && stillDown && startedOk && back;
        const line = resultLine(ok ? "PASS" : "FAIL", id, `the ${suite} suite ran with Convex stopped throughout, and Convex came back after it (stopped ${stoppedOk}, still down at the end ${stillDown}, back ${back})`);
        console.log(line);
        reports.push({ suite, id, status: ok ? "PASS" : "FAIL", text: line });
      },
    };
  }

  async function requestBudget() {
    const id = "request-budget.no-unexpected-429";
    console.log(`--- ${inventory.suites["request-budget"].title}`);
    const records = await target.requestLog(state);
    const { refusals, busiest } = assess(records, { windows });
    console.log(
      `--- request budget: ${records.length} requests answered by the server; it refused ${refusals.length} unexpectedly (429). ` +
        `Context only: at most ${busiest.count} logged in one window` +
        (busiest.client ? ` (from ${busiest.client} from ${new Date(busiest.start).toISOString()})` : "") +
        `, against the server's budget of ${BUDGET} per ${WINDOW_MS / 1000} s.`,
    );
    for (const r of refusals.slice(0, 10)) {
      console.log(`  429 to ${r.method} ${r.path} from ${r.client} (logged ${new Date(r.completedAt).toISOString()}): a limit was exceeded`);
    }
    if (refusals.length > 10) console.log(`  ... and ${refusals.length - 10} more 429s`);
    const line = resultLine(refusals.length === 0 ? "PASS" : "FAIL", id, `the server answered no 429 other than the proxy probe's pending cap (${refusals.length} unexpected)`);
    console.log(line);
    reports.push({ suite: "request-budget", id, status: refusals.length === 0 ? "PASS" : "FAIL", text: line });
    report.requestBudget = { requests: records.length, unexpected429: refusals.length, busiest };
  }

  // Everything after the target came up stays inside this block, so a
  // failure while judging or writing the report still removes the stack.
  let judged = { ok: false };
  try {
    // Judge the run; on a partial run, only the checks of the chosen suites.
    const scoped = options.suites.length === 0 ? inventory : {
      ...inventory,
      checks: Object.fromEntries(Object.entries(inventory.checks).filter(([, c]) => inScope(c.suite))),
    };
    judged = evaluate({ inventory: scoped, reports: reports.filter((r) => inScope(r.suite)), errors: errors.filter((e) => e.suite === "runner" || inScope(e.suite)), cliVersion: cli.version });
    // The expected failures of this target and client, for the checks in scope.
    const inForce = new Map([...expected].filter(([id]) => id in scoped.checks));
    judged = applyExpectations(judged, inForce);
    report.finishedAt = new Date().toISOString();
    report.checks = judged.checks;
    report.problems = judged.problems;
    report.expectations = judged.expectations;
    report.ok = judged.ok;
    if (options.gate) {
      report.gate = judgeGate({
        inventory,
        run: { target: options.target, partial: report.partial, ok: judged.ok, checks: judged.checks, expectedInForce: [...inForce.keys()] },
        walkthrough,
        recentCli,
      });
      report.gate.walkthrough = walkthrough;
      report.gate.recentCliReport = options.recentCliReport ? { file: options.recentCliReport, sha256: sha256(readFileSync(options.recentCliReport)) } : null;
    }

    console.log(`\n--- conformance report: target ${options.target}, CLI ${cli.spec}${report.partial ? ` (only ${report.partial.join(", ")})` : ""}`);
    for (const c of judged.checks) {
      console.log(`${c.outcome.toUpperCase().padEnd(15)}${c.kind.padEnd(13)}${c.id}${c.outcome === "fail" ? `  (${c.why.slice(0, 200)})` : ""}`);
    }
    const count = (o) => judged.checks.filter((c) => c.outcome === o).length;
    console.log(
      `--- ${judged.checks.length} checks: ${count("pass")} passed, ${count("fail")} failed, ${count("expected-fail")} failed as expected, ` +
        `${count("not-applicable")} not applicable, ${count("predates-cli")} predate the CLI`,
    );
    for (const c of judged.checks.filter((c) => c.outcome === "predates-cli")) console.log(`PREDATES-CLI   ${c.id}: ${c.why}`);
    // Expected failures are listed with their reason, never hidden.
    for (const c of judged.checks.filter((c) => c.outcome === "expected-fail")) {
      console.log(`EXPECTED-FAIL  ${c.id}: ${c.expected.reason} (removed by ${c.expected.removedBy}; failed with: ${c.why.slice(0, 200)})`);
    }
    for (const id of judged.expectations.notExercised) console.log(`EXPECTED-FAIL  ${id}: expected to fail, but not exercised in this run`);
    for (const p of judged.problems) console.log(`PROBLEM  ${p}`);
    if (report.gate) {
      console.log(`--- gate (ADR-0059 G1, G2): ${report.gate.passed ? "passed" : "FAILED"}`);
      for (const p of report.gate.problems) console.log(`GATE  ${p}`);
    }
    // The report is published as a CI artifact: masked like the logs.
    if (options.report) writeFileSync(options.report, redactTokens(`${JSON.stringify(report, null, 2)}\n`));

    if (!judged.ok && state && target.diagnostics) {
      console.log("--- the target's recent logs");
      console.log(await target.diagnostics(state).catch((err) => `diagnostics failed: ${err.message}`));
    }
  } catch (err) {
    judged = { ...judged, ok: false };
    console.log(`--- judging or reporting the run failed: ${err.message}`);
  } finally {
    await cleanup();
  }
  if (stopped) console.log(`--- the run stopped early: ${stopped}`);
  const gateFailed = options.gate && report.gate?.passed !== true;
  if (!judged.ok) console.log("CONFORMANCE RUN FAILED");
  else if (gateFailed) console.log(`CONFORMANCE GATE FAILED (the run passed; target ${targetName}, CLI ${cli.spec})`);
  else if (report.partial) console.log(`PARTIAL RUN PASSED (only ${report.partial.join(", ")}; target ${targetName}, CLI ${cli.spec})`);
  else console.log(`ALL E2E SUITES PASSED (target ${targetName}, CLI ${cli.spec})${options.gate ? "; GATE PASSED" : ""}`);
  process.exit(judged.ok && !gateFailed ? 0 : 1);
}

/** The data the suites expect: organization acme, project api with two environments and a Contract, and two values. */
async function seed(origin, token) {
  const call = async (method, path, body) => {
    const res = await fetch(`${origin}${path}`, {
      method,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`seed: ${method} ${path} answered ${res.status}: ${text.slice(0, 300)}`);
    return text ? JSON.parse(text) : null;
  };
  const P = "/v1/organizations/acme/projects/api";
  await call("POST", "/v1/organizations", { name: "Acme", slug: "acme" });
  await call("POST", "/v1/organizations/acme/projects", { name: "API", slug: "api", contractAuthority: "git" });
  await call("POST", `${P}/environments`, { name: "development", tier: "development" });
  await call("POST", `${P}/environments`, { name: "production", tier: "production" });
  const revision = await call("POST", `${P}/contract/revisions`, {
    contract: {
      schemaVersion: 1,
      items: [
        { name: "DATABASE_URL", required: { kind: "always" }, sensitive: true, type: "url" },
        { name: "PORT", required: { kind: "always" }, sensitive: false, type: "number", defaultValue: "3000" },
        { name: "API_KEY", required: { kind: "selector", selector: { kind: "tier", tier: "production" } }, sensitive: true, type: "string" },
        { name: "PUBLIC_URL", required: { kind: "never" }, sensitive: false, type: "string" },
      ],
    },
  });
  await call("POST", `${P}/contract/revisions/${revision.id}/activate`, {});
  await call("PUT", `${P}/environments/development/values/DATABASE_URL`, { value: SEEDED_SECRET });
  await call("PUT", `${P}/environments/development/values/PORT`, { value: "3000" });
}

await main();
