#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { redactTokens } from "../redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * The conformance runner (ADR-0059 step 2; scripts/conformance/README.md).
 * It starts a target, runs the suites of plan.mjs against it in order, each
 * as its own process, collects one result per check ID, and judges the run
 * against inventory.json.
 *
 *   node scripts/conformance/run.mjs --target <target> --cli source|<version>|go:<path>
 *        [--handover-cli source|<version>] [--report <file.json>] [--suite <name>]... [--shard <k>/<n>]
 *        [--gate --walkthrough <docs/evidence/file> [--recent-cli-report <file.json>]]
 *
 *   --target   the server under test (targets/index.mjs): ts-source,
 *              ts-release:<version> (a signed release, verified and pulled
 *              by digest), go-binary:<path> (the Go varlatchd at <path>)
 *   --cli      the CLI under test: `source` is apps/cli/dist/varlatch.cjs; a
 *              version is a released CLI pinned in clients.json, downloaded
 *              and verified before anything starts (clients.mjs). The sdk
 *              suite drives packages/sdk from the same source: this
 *              checkout, or the pinned release's commit. `go:<path>` is
 *              the Go CLI (ADR-0059 step 5) at <path>, run as a native
 *              binary; the features it lacks yet (client-go.json,
 *              lib/client-lacks.mjs) report client-lacks.
 *   --handover-cli  with --cli go:<path>, the TypeScript CLI the hand-over
 *              suite pairs it with (internal docs/design/go-cli.md, decision
 *              11): `source` or a pinned version, verified as --cli is;
 *              0.22.0 when not given. Its checks (kind go-client) are not
 *              applicable when the CLI under test is not the Go CLI.
 *   --report   also write the report as JSON to this file
 *   --suite    run only these suites (and the setup they need); the report
 *              then covers only their checks
 *   --shard    run shard k of n (1-based): the suites shard.mjs assigns to
 *              it, as a --suite selection, so the report covers only their
 *              checks; every suite is in exactly one shard, and every shard
 *              also checks its own server's request budget and logs
 *              (shard.mjs PER_SHARD). --shard 1/1 is a full run. Not with
 *              --suite or --gate
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
 * The target's declared gaps (the same file's `lacks`, lib/operations.mjs):
 * before the suites, the runner asks the target, once per lacking
 * operation, and requires the stub's answer (501 NOT_IMPLEMENTED_YET); any
 * other answer fails the run, naming the stale entry. A check that needs a
 * lacking operation is reported target-lacks by the runner, and its suite
 * is not started when every one of its checks lacks something; a setup step
 * (the first enrollment, the seed) that needs one is skipped.
 *
 * Exit status 0 only when every check in scope accounted for itself as the
 * inventory and the expectations require (and, with --gate, the gate
 * passed); 1 otherwise; 64 on a usage error.
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSdk, loadClients, resolveCli, sha256 } from "./clients.mjs";
import { applyExpectations, expectationsFor, lacksFor, validateExpectations } from "./lib/expect.mjs";
import { judgeGate } from "./lib/gate.mjs";
import { evaluate, TARGET_SPECIFIC, validateInventory } from "./lib/inventory.mjs";
import { clientLackingChecks, loadClientLacks, validateClientLacks, withoutLacking } from "./lib/client-lacks.mjs";
import { lackingChecks, NOT_IMPLEMENTED_YET, openapiOperations, operationProblems, setupLacks, skippedGroupProblems } from "./lib/operations.mjs";
import { probeLacks } from "./lacks-probe.mjs";
import { assess, BUDGET, waitMs, WINDOW_MS } from "./lib/request-log.mjs";
import { endProblem, parseSuiteOutput, resultLine } from "./lib/results.mjs";
import { NOT_BUILT } from "./suite-kit.mjs";
import { PLAN } from "./plan.mjs";
import { loadWeights, parseShard, shardSuites } from "./shard.mjs";
import { loadTarget } from "./targets/index.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");
const SUITE_TIMEOUT_MS = 30 * 60_000;
const SEEDED_SECRET = "postgres://dev-db";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function usage(message) {
  console.error(
    `${message}\nUsage: run.mjs --target ts-source|ts-release:<version>|go-binary:<path> --cli source|<version>|go:<path> [--handover-cli source|<version>] [--report <file.json>] [--suite <name>]... [--shard <k>/<n>]` +
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
    else if (flag === "--handover-cli") options.handoverCli = value();
    else if (flag === "--report") options.report = value();
    else if (flag === "--suite") options.suites.push(value());
    else if (flag === "--shard") {
      const text = value();
      options.shard = parseShard(text) ?? usage(`--shard ${text}: expected <k>/<n> with 1 <= k <= n`);
    }
    else if (flag === "--gate") options.gate = true;
    else if (flag === "--walkthrough") options.walkthrough = value();
    else if (flag === "--recent-cli-report") options.recentCliReport = value();
    else usage(`unknown argument ${flag}`);
  }
  if (!options.target) usage("--target is required");
  if (!options.cli) usage("--cli is required");
  if (options.handoverCli !== undefined && !options.cli.startsWith("go:")) usage("--handover-cli pairs the Go CLI (--cli go:<path>) with a TypeScript CLI");
  if (options.handoverCli !== undefined && options.handoverCli.startsWith("go:")) usage("--handover-cli names a TypeScript CLI: source or a pinned version");
  if (!options.gate && (options.walkthrough || options.recentCliReport)) usage("--walkthrough and --recent-cli-report belong to --gate");
  if (options.gate && options.suites.length > 0) usage("--gate judges a whole run: --suite is not allowed");
  if (options.shard && options.suites.length > 0) usage("--shard selects the suites itself: --suite is not allowed");
  if (options.shard && options.gate) usage("--gate judges a whole run: --shard is not allowed");
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
function loadExpectations(targetName, inventory, openapi) {
  const file = join(HERE, "expect", `${targetName}.json`);
  if (!existsSync(file)) return { schema: 1, expected: {} };
  const parsed = JSON.parse(readFileSync(file, "utf8"));
  const problems = validateExpectations(parsed, { targetName, inventory, cliVersions: Object.keys(loadClients().cli), openapi });
  if (problems.length > 0) throw new Error(`expect/${targetName}.json is not valid:\n  ${problems.join("\n  ")}`);
  return parsed;
}

/** Runs one suite as its own process group; streams its output and returns it. */
const END_PRELOAD = pathToFileURL(join(dirname(fileURLToPath(import.meta.url)), "lib", "end-preload.mjs")).href;

function runSuite(script, args, env, cwd) {
  return new Promise((resolvePromise) => {
    // The end-of-suite channel: fd 3, a pipe of this suite's alone, and a
    // nonce made for this suite (suite-kit's finish() writes both). The
    // nonce goes on fd 4, never in the environment: the preload reads it
    // and closes fd 4 before any module of the suite runs.
    const nonce = randomBytes(16).toString("hex");
    const child = spawn(process.execPath, ["--import", END_PRELOAD, script, ...args], {
      cwd,
      // Not a secret: tells the preload that fd 4 is the runner's.
      env: { ...env, CONFORMANCE_NONCE_FD: "4" },
      stdio: ["ignore", "pipe", "pipe", "pipe", "pipe"],
      detached: true,
    });
    child.stdio[4].on("error", () => {
      // The suite exited before reading it; its end is judged without it.
    });
    child.stdio[4].end(nonce);
    let stdout = "";
    let stderr = "";
    let endChannel = "";
    child.stdio[3].on("data", (d) => {
      endChannel += d;
    });
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
      resolvePromise({ code, signal, timedOut, stdout, stderr, endChannel, nonce });
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
  const openapi = openapiOperations(readFileSync(join(REPO_ROOT, "packages", "protocol", "openapi.yaml"), "utf8"));
  const opShape = operationProblems(inventory, openapi);
  if (opShape.length > 0) throw new Error(`inventory.json names operations that do not exist:\n  ${opShape.join("\n  ")}`);
  const planned = PLAN.filter((e) => e.setup || inventory.suites[e.suite]);
  const unknown = PLAN.filter((e) => !e.setup && !inventory.suites[e.suite]).map((e) => e.suite);
  const unplanned = Object.keys(inventory.suites).filter((s) => !PLAN.some((e) => e.suite === s));
  if (unknown.length || unplanned.length) throw new Error(`plan.mjs and inventory.json disagree: not in the inventory: ${unknown.join(", ") || "none"}; not in the plan: ${unplanned.join(", ") || "none"}`);
  for (const s of options.suites) if (!inventory.suites[s]) usage(`--suite ${s}: no such suite`);
  // A shard is a --suite selection (shard.mjs), so everything below treats
  // it as one: the always suites and the setup still run, and the report,
  // the errors and the expected failures cover only the selected suites'
  // checks. One shard of one is the whole plan: a full run.
  if (options.shard && options.shard.count > 1) options.suites = shardSuites(PLAN, loadWeights(), options.shard.index, options.shard.count);
  const inScope = (suite) => options.suites.length === 0 || options.suites.includes(suite);

  let loaded;
  try {
    loaded = await loadTarget(options.target);
  } catch (err) {
    usage(err.message);
  }
  const { name: targetName, argument: targetArgument, target, capabilities, expectKey } = loaded;
  const expectations = loadExpectations(targetName, inventory, openapi);
  // The target's declared gaps, and the checks that need one.
  const lacks = lacksFor(expectations, expectKey);
  const lacking = lackingChecks(inventory, lacks.keys());
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
  let handover = null;
  try {
    cli = await resolveCli(options.cli, { repoRoot: REPO_ROOT, workDir: scratch });
    // The hand-over suites (client "go") pair the Go CLI with a TypeScript one.
    const handoverSuites = Object.entries(inventory.suites).filter(([name, suite]) => suite.client === "go" && inScope(name));
    if (cli.spec === "go" && handoverSuites.length > 0) {
      handover = await resolveCli(options.handoverCli ?? "0.22.0", { repoRoot: REPO_ROOT, workDir: scratch });
    }
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
  // What the Go CLI does not do yet; nothing for a TypeScript CLI.
  const clientLacks = cli.spec === "go" ? loadClientLacks() : new Map();
  if (cli.spec === "go") {
    const problems = validateClientLacks({ schema: 1, lacksFeatures: Object.fromEntries(clientLacks) }, inventory);
    if (problems.length > 0) usage(problems.join("\n"));
  }
  const clientLacking = clientLackingChecks(inventory, clientLacks);
  const report = {
    target: options.target,
    expectKey,
    cli: { spec: cli.spec, version: cli.version, commit: cli.commit, sha256: cli.sha256, verified: cli.verified },
    handoverCli: handover ? { spec: handover.spec, version: handover.version, commit: handover.commit, sha256: handover.sha256, verified: handover.verified } : null,
    sdk: sdk ? { from: cli.commit ? `release ${cli.version} (${cli.commit})` : "this checkout", commit: sdk.commit, sha256: sdk.sha256 } : null,
    partial: options.suites.length > 0 ? options.suites : false,
    // Which shard this is; a shard of one is a full run, recorded as one.
    shard: options.shard?.count > 1 ? `${options.shard.index}/${options.shard.count}` : null,
    lacks: { declared: Object.fromEntries(lacks), stale: [] },
    clientLacks: { declared: Object.fromEntries(clientLacks), stale: [], notBuilt: [] },
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
    if (report.shard) console.log(`--- shard ${report.shard}: ${report.partial ? report.partial.join(", ") : "every suite"}`);
    if (sdk) console.log(`--- sdk from ${report.sdk.from}: ${sdk.path}, sha256 ${sdk.sha256}`);
    if (handover) console.log(`--- hand-over with the TypeScript CLI ${handover.spec} (${handover.path}, sha256 ${handover.sha256})`);
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
    // What ran, for gate mode to compare runs by (targets' `fingerprint`).
    report.implementation = target.fingerprint ? await target.fingerprint(state) : null;
    // VARLATCH_CLI_VERSION is the verified version (empty for source): the
    // suites gate feature groups on it, and the runner checks every
    // predates-cli result against it again.
    const suiteEnv = {
      ...process.env,
      VARLATCH_CLI: cli.path,
      VARLATCH_CLI_VERSION: cli.version ?? "",
      // A native binary (the Go CLI) runs directly, a TypeScript one with Node (suite-kit cliCommand).
      VARLATCH_CLI_NATIVE: cli.native ? "1" : "",
      // The hand-over's TypeScript CLI (suite-kit handoverCliCommand), with --cli go only.
      VARLATCH_HANDOVER_CLI: handover?.path ?? "",
      VARLATCH_SDK: sdk?.path ?? "",
      CONFORMANCE_TARGET_STATE: stateFile,
    };
    const ctx = { origin: target.origin(state) };
    if (lacks.size > 0) await checkLacks(ctx.origin);
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
        if (setupLacks(inventory, "admin-bootstrap", lacks)) {
          console.log("--- bootstrap: not run, the target lacks admin-bootstrap");
          continue;
        }
        console.log("--- bootstrap: the first enrollment URL");
        ctx.bootstrapUrl = (await target.bootstrap(state)).match(/http:\/\/\S*enroll#\S*/)?.[0];
        if (!ctx.bootstrapUrl) throw new Error("bootstrap printed no enrollment URL");
        continue;
      }
      if (entry.setup === "seed") {
        // The admin identity's CLI credential, which later suites use: issued
        // whenever the target can recover, seed or not (a target that lacks
        // the seed's writes still signs in with it; cli-core's token sign-in).
        if (!setupLacks(inventory, "admin-recover", lacks)) {
          if (!ctx.adminId) throw new Error("the passkey suite named no identity: nothing after it can run");
          ctx.token = await ctx.cliCredential();
        }
        if (setupLacks(inventory, "seed", lacks)) {
          const missing = inventory.operations.seed.uses.filter((op) => lacks.has(op));
          console.log(`--- seed: not run, the target lacks ${missing.join(", ")}`);
          continue;
        }
        console.log(`--- seed data as ${ctx.adminId}`);
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
      // A hand-over suite (client "go") with a TypeScript CLI under test: not applicable.
      if (suite.client === "go" && cli.spec !== "go") {
        console.log(`--- ${suite.title}: not run, the CLI under test is not the Go CLI`);
        for (const [id, check] of Object.entries(inventory.checks)) {
          if (check.suite === entry.suite) reports.push({ suite: entry.suite, id, status: "N/A", text: "the CLI under test is not the Go CLI" });
        }
        continue;
      }
      const missing = (suite.needs ?? []).filter((c) => !capabilities.includes(c));
      const ids = Object.entries(inventory.checks).filter(([, c]) => c.suite === entry.suite).map(([id]) => id);
      // A check needing an operation the target lacks: target-lacks, from
      // the runner; a ts-stack (or go-server) check on a target without
      // the stack (or the Go server) stays not applicable.
      const lacked = new Set(ids.filter((id) => lacking.has(id) && !(missing.length > 0 && inventory.checks[id].kind in TARGET_SPECIFIC)));
      // A check needing a CLI feature the client lacks: client-lacks, from
      // the runner, unless the target already lacks what it needs.
      const clientLacked = new Set(ids.filter((id) => clientLacking.has(id) && !lacked.has(id) && !(missing.length > 0 && inventory.checks[id].kind in TARGET_SPECIFIC)));
      // A lacking check that ran and failed keeps its FAIL (`failed`): only
      // a check that gave no verdict reports client-lacks. A check the suite
      // never reported counts as lacking only when the runner did not start
      // the suite or the suite ended (its end-of-suite marker); after a
      // crash it is not reported here, and fails as unreported
      // (`unreported`, the checks that gave no verdict of their own).
      const reportLacks = (failed = new Set(), unreported = new Set()) => {
        for (const id of lacked) reports.push({ suite: entry.suite, id, status: "TARGET-LACKS", text: `the target lacks ${lacking.get(id).join(", ")}`, runner: true });
        for (const id of clientLacked) {
          if (!failed.has(id) && !unreported.has(id)) reports.push({ suite: entry.suite, id, status: "CLIENT-LACKS", text: `the CLI lacks ${clientLacking.get(id).join(", ")}`, runner: true });
        }
      };
      if (missing.length > 0) {
        console.log(`--- ${suite.title}: not run, the target lacks ${missing.join(", ")}`);
        reportLacks();
        for (const id of ids) {
          if (!lacked.has(id)) reports.push({ suite: entry.suite, id, status: "N/A", text: `the target lacks ${missing.join(", ")}` });
        }
        continue;
      }
      if (lacked.size === ids.length) {
        const ops = [...new Set([...lacked].flatMap((id) => lacking.get(id)))].sort();
        console.log(`--- ${suite.title}: not run, the target lacks ${ops.length === 1 ? "an operation" : `${ops.length} operations`} it needs (${ops.slice(0, 8).join(", ")}${ops.length > 8 ? ", ..." : ""})`);
        reportLacks();
        continue;
      }
      if (lacked.size + clientLacked.size === ids.length) {
        const features = [...new Set([...clientLacked].flatMap((id) => clientLacking.get(id)))].sort();
        console.log(`--- ${suite.title}: not run, the CLI lacks ${features.join(", ")}`);
        reportLacks();
        continue;
      }
      console.log(`--- ${suite.title}`);
      const args = await entry.args(ctx);
      await pace(entry.suite);
      const around = entry.around === "convex-down" ? await convexDown(entry.suite) : null;
      const start = Date.now();
      // The suite skips each operation group all of whose checks lack an
      // operation (suite-kit's group()), so its setup never meets one.
      const out = await runSuite(join(REPO_ROOT, suite.script), args, { ...suiteEnv, CONFORMANCE_SUITE: entry.suite, CONFORMANCE_LACKING: JSON.stringify([...lacked].sort()) }, scratch);
      const end = Date.now();
      (windows[entry.suite] ??= []).push({ start, end });
      if (around) await around.finish();
      const parsed = parseSuiteOutput(`${out.stdout}\n${out.stderr}`);
      // A check whose step the Go CLI refused as not built yet (suite-kit's
      // NOT-BUILT, with the CLI's exact refusal) observed nothing: it
      // reports client-lacks, from the runner, like every check of a
      // feature client-go.json lists. Never a pass, so never a stale entry.
      // Only for --cli go: a TypeScript CLI never gives that refusal, and a
      // NOT-BUILT under one fails the run. A refused check that needs no
      // listed feature fails: client-lacks never covers a check whose
      // features the Go CLI claims to have (decision 3), so its feature
      // goes in its cliNeeds and client-go.json, or gets built.
      const notBuiltRefused = [];
      const observedNotBuilt = new Set();
      for (const r of parsed.results.filter((r) => r.status === "NOT-BUILT")) {
        if (cli.spec !== "go") {
          errors.push({ suite: entry.suite, message: `${r.id} reported NOT-BUILT, which only the Go CLI's refusal gives; the CLI under test is ${cli.spec}` });
        } else if (!NOT_BUILT.test(r.text)) {
          errors.push({ suite: entry.suite, message: `${r.id} reported NOT-BUILT with ${JSON.stringify(r.text.slice(0, 200))}, which is not the Go CLI's not-built refusal` });
        } else if (lacked.has(r.id) || clientLacked.has(r.id)) {
          observedNotBuilt.add(r.id);
          report.clientLacks.notBuilt.push({ id: r.id, refusal: r.text });
        } else {
          notBuiltRefused.push({
            status: "FAIL",
            id: r.id,
            text: `client-go.json lists no feature this check needs, but the Go CLI refused a step it needs as not built: name the feature in its cliNeeds and list it, or build it (${r.text})`,
          });
        }
      }
      parsed.results = [...parsed.results.filter((r) => r.status !== "NOT-BUILT"), ...notBuiltRefused];
      // A lacking check that gave no verdict reports the runner's
      // client-lacks; one that passed shows a stale entry in client-go.json;
      // one that failed stays a failure, whatever client-go.json lists.
      const anyFailed = parsed.results.some((r) => r.status === "FAIL");
      const { kept, stale, failed } = withoutLacking(parsed.results, clientLacked, clientLacking);
      parsed.results = kept;
      for (const { id, features } of stale) {
        report.clientLacks.stale.push({ id, features });
        errors.push({ suite: entry.suite, message: `${id} passed, but client-go.json says the CLI lacks ${features.join(", ")}: remove the entry` });
      }
      // What the suite printed for a check that lacks an operation is
      // replaced by the runner's target-lacks, and for a ts-stack (or
      // go-server) check on a target without that capability, by not
      // applicable: a suite that runs everywhere can hold one
      // (dashboard.csp-connect-src-convex).
      // A result for a check of a group the target skips: the suite ran
      // that group's work on a target that lacks it. The run fails; the
      // gate convention's static check is only a lint aid for this.
      for (const message of skippedGroupProblems(inventory, entry.suite, lacked, parsed.results, cli.version)) {
        errors.push({ suite: entry.suite, message });
      }
      for (const r of parsed.results) {
        if (lacked.has(r.id)) continue;
        const capability = TARGET_SPECIFIC[inventory.checks[r.id]?.kind];
        if (capability && !capabilities.includes(capability)) {
          reports.push({ suite: entry.suite, id: r.id, status: "N/A", text: `the target lacks ${capability}` });
          continue;
        }
        reports.push({ suite: entry.suite, ...r });
      }
      // The suite finished only when its own end-of-suite channel (fd 3)
      // carried one marker with its name and this run's nonce, and it then
      // exited normally with the code the marker names (suite-kit's
      // finish()). Anything else, whatever it reported before: the run
      // fails, and the lacking checks it did not report are not counted as
      // lacking.
      const unfinished = out.timedOut ? "timed out" : endProblem(out.endChannel, { suite: entry.suite, nonce: out.nonce, code: out.code, signal: out.signal });
      const ended = unfinished === null;
      if (!ended && !out.timedOut) {
        errors.push({ suite: entry.suite, message: `did not finish: ${unfinished}; the checks it did not report fail` });
      }
      const reportedIds = new Set(parsed.results.map((r) => r.id));
      const unreported = ended ? new Set() : new Set([...clientLacked].filter((id) => !reportedIds.has(id) && !observedNotBuilt.has(id)));
      reportLacks(failed, unreported);
      for (const message of parsed.errors) errors.push({ suite: entry.suite, message });
      // A failed check explains a non-zero exit.
      const failedResults = anyFailed;
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

  // Asks the target about every operation it declares it lacks
  // (lacks-probe.mjs); a stale entry fails the run, named.
  async function checkLacks(origin) {
    console.log(`--- the target declares ${lacks.size} lacking operations; asking it about each`);
    report.lacks.stale = await probeLacks({ inventory, openapi, lacks: [...lacks.keys()], origin, target, state });
    for (const { operation, why } of report.lacks.stale) {
      console.log(`STALE-LACKS  ${operation}: ${why}`);
      errors.push({ suite: "runner", message: `expect/${targetName}.json lacks ${operation}, but ${why}` });
    }
    if (report.lacks.stale.length === 0) console.log(`--- every one answered ${NOT_IMPLEMENTED_YET}`);
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
    judged = evaluate({
      inventory: scoped,
      reports: reports.filter((r) => inScope(r.suite)),
      errors: errors.filter((e) => e.suite === "runner" || inScope(e.suite)),
      cliVersion: cli.version,
      cliSpec: cli.spec,
      lacking,
      clientLacking,
    });
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
        run: {
          target: options.target,
          cli: cli.spec,
          partial: report.partial,
          ok: judged.ok,
          checks: judged.checks,
          expectedInForce: [...inForce.keys()],
          lacksInForce: [...lacks.keys()],
          implementation: report.implementation ?? null,
        },
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
        `${count("not-applicable")} not applicable, ${count("predates-cli")} predate the CLI, ${count("target-lacks")} need an operation the target lacks, ${count("client-lacks")} need a feature the CLI lacks`,
    );
    if (count("target-lacks") > 0) {
      // The parity tracker: which lacking operations hold back how many checks.
      const holding = new Map();
      for (const c of judged.checks.filter((c) => c.outcome === "target-lacks")) {
        for (const op of lacking.get(c.id) ?? []) holding.set(op, (holding.get(op) ?? 0) + 1);
      }
      const ranked = [...holding].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
      console.log(`--- the lacking operations checks need (${lacks.size} declared): ${ranked.map(([op, n]) => `${op} ${n}`).join(", ")}`);
    }
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
  else if (report.shard && report.partial) console.log(`SHARD ${report.shard} PASSED (only ${report.partial.join(", ")}; target ${targetName}, CLI ${cli.spec})`);
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
