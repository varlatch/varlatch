// SPDX-License-Identifier: Apache-2.0
/**
 * What a conformance suite needs from the harness (scripts/conformance/README.md):
 * one result line per check, the CLI under test, and the target's operations.
 *
 * A suite runs as its own process, started by scripts/conformance/run.mjs.
 * It reports each check with a stable ID from scripts/conformance/inventory.json:
 *
 *   PASS  [dashboard.csp-strict] the dashboard is served with a strict ... - detail
 *   FAIL  [dashboard.csp-strict] ...
 *
 * and a problem that is not one check's verdict (a crash, a step that could
 * not run) as `ERROR  <message>`, which fails the run. The runner, not the
 * suite, decides what a missing or unexpected ID means.
 */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const TARGET_OP = fileURLToPath(new URL("./target-op.mjs", import.meta.url));
const ID = /^[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9.-]*$/;

/**
 * A reporter for one suite. `check(id, name, ok, detail)` prints one result
 * line; `error(message)` reports a problem outside any check; `finish()`
 * ends the process with a status that says whether anything failed.
 *
 * `detail` is printed with every result, or with failures only when
 * `detailOnFailure` is set (for suites whose details are whole command
 * outputs). `separator` keeps each suite's existing look.
 */
export function reporter({ detailOnFailure = false, separator = " - " } = {}) {
  let failures = 0;
  const check = (id, name, ok, detail = "") => {
    if (!ID.test(id)) throw new Error(`not a check ID: ${id}`);
    const shown = detail && (!detailOnFailure || !ok) ? `${separator}${detail}` : "";
    console.log(`${ok ? "PASS" : "FAIL"}  [${id}] ${name}${shown}`);
    if (!ok) failures += 1;
    return ok;
  };
  const error = (message) => {
    console.log(`ERROR  ${String(message).split("\n").join("\n       ")}`);
    failures += 1;
  };
  return {
    check,
    error,
    get failures() {
      return failures;
    },
    finish(summary) {
      if (failures > 0) {
        if (summary) console.error(`${failures} ${summary} failed`);
        process.exit(1);
      }
      process.exit(0);
    },
  };
}

/**
 * The CLI under test: a script run with Node, named by VARLATCH_CLI. The
 * runner sets it for every suite (`--cli source` is apps/cli/dist/varlatch.cjs);
 * a suite never picks a CLI of its own.
 */
export function cliPath() {
  const path = process.env.VARLATCH_CLI;
  if (!path) {
    throw new Error("VARLATCH_CLI is not set: run the suite through scripts/conformance/run.mjs, or set it to the CLI under test");
  }
  return path;
}

/**
 * Runs one operation of the target under test (scripts/conformance/target-op.mjs)
 * and returns its standard output; throws when the operation fails.
 * `input` is passed on standard input, `env` is added to the environment.
 */
export function targetOp(operation, args = [], { input, env } = {}) {
  const r = spawnSync(process.execPath, [TARGET_OP, operation, ...args], {
    encoding: "utf8",
    input: input ?? "",
    env: { ...process.env, ...env },
    maxBuffer: 256 * 1024 * 1024,
  });
  if (r.status !== 0) {
    throw new Error(`target operation ${[operation, ...args].join(" ")} failed (exit ${r.status}): ${(r.stderr || r.stdout).trim().slice(-500)}`);
  }
  return r.stdout;
}

/** Like targetOp, for operations whose result the suite judges itself: never throws. */
export function tryTargetOp(operation, args = [], { input, env } = {}) {
  const r = spawnSync(process.execPath, [TARGET_OP, operation, ...args], {
    encoding: "utf8",
    input: input ?? "",
    env: { ...process.env, ...env },
    maxBuffer: 256 * 1024 * 1024,
  });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}
