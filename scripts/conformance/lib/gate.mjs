// SPDX-License-Identifier: Apache-2.0
/**
 * Gate mode (`run.mjs --gate`): what ADR-0059's G1 (parity) and G2 (old
 * clients) are judged with. A gate run passes only when, besides the run
 * itself passing:
 *
 *   - no expected failure is in force for its target and client;
 *   - every ts-stack check's replacement, and every outside suite's
 *     (inventory.externalSuites: the lifecycle and installer suites the
 *     runner does not run), is present and passing: a replacement check that
 *     passed in this run, or `none` with its reason. An `open` replacement
 *     fails the gate;
 *   - it names the browser-walkthrough evidence file (G1's full browser
 *     walkthrough, done by hand and kept under docs/evidence/);
 *   - it covers every suite (no --suite);
 *   - either no check reported predates-cli, or the run names the passing
 *     gate report of the same target with a CLI recent enough that none did.
 */

export const EVIDENCE_DIR = "docs/evidence/";

/** Every replacement the gate needs: the ts-stack checks' and the outside suites'. */
export function replacements(inventory) {
  const out = [];
  for (const [id, check] of Object.entries(inventory.checks)) {
    if (check.kind === "ts-stack") out.push({ of: id, replacement: check.replacement });
  }
  for (const [name, suite] of Object.entries(inventory.externalSuites ?? {})) {
    out.push({ of: `${name} (${suite.script})`, replacement: suite.replacement });
  }
  return out;
}

/**
 * Judges a run in gate mode.
 *
 *   run         { target, partial, ok, checks: [{ id, outcome }], expectedInForce: [check ids] }
 *   walkthrough null, or { path (relative to the checkout), exists, size }
 *   recentCli   null, or the parsed report (conformance-report.json) of a
 *               gate run with a recent CLI
 *
 * Returns `{ passed, problems, open }`; `open` lists the open replacements.
 */
export function judgeGate({ inventory, run, walkthrough = null, recentCli = null }) {
  const problems = [];
  if (run.partial) problems.push("a gate run covers every suite: --suite is not allowed");
  if (!run.ok) problems.push("the run itself did not pass");
  if (run.expectedInForce.length > 0) {
    problems.push(`no expected failure is allowed, and ${run.expectedInForce.length} are in force for ${run.target}: ${run.expectedInForce.join(", ")}`);
  }

  const outcome = new Map(run.checks.map((c) => [c.id, c.outcome]));
  const open = [];
  for (const { of, replacement } of replacements(inventory)) {
    if (typeof replacement === "string") {
      const got = outcome.get(replacement);
      if (got !== "pass") problems.push(`${of}: its replacement ${replacement} must pass in this run (${got ?? "not in the run"})`);
    } else if (replacement && "open" in replacement) {
      open.push(`${of}: ${replacement.open}`);
    } else if (!(replacement && typeof replacement.none === "string" && replacement.none.trim())) {
      problems.push(`${of}: names no replacement`);
    }
  }
  if (open.length > 0) problems.push(`${open.length} replacements are still open:\n    ${open.join("\n    ")}`);

  if (!walkthrough) problems.push(`the run names no browser-walkthrough evidence file (--walkthrough ${EVIDENCE_DIR}<file>)`);
  else if (!walkthrough.path.startsWith(EVIDENCE_DIR) || walkthrough.path.split("/").includes("..")) {
    problems.push(`the browser-walkthrough evidence ${walkthrough.path} is not under ${EVIDENCE_DIR} of this checkout`);
  } else if (!walkthrough.exists) problems.push(`the browser-walkthrough evidence ${walkthrough.path} does not exist`);
  else if (!(walkthrough.size > 0)) problems.push(`the browser-walkthrough evidence ${walkthrough.path} is empty`);

  const predating = run.checks.filter((c) => c.outcome === "predates-cli").map((c) => c.id);
  if (predating.length > 0) {
    const why = recentCliProblem(recentCli, run.target);
    if (why) problems.push(`${predating.length} checks predate this run's CLI, so the gate also needs a passing gate run of ${run.target} with a CLI that predates nothing (--recent-cli-report <report.json>): ${why}`);
  }
  return { passed: problems.length === 0, problems, open };
}

/** Why `report` is not a passing gate run of `target` in which nothing predated the CLI; null when it is. */
export function recentCliProblem(report, target) {
  if (!report) return "none named";
  if (report.target !== target) return `it is a run of ${report.target}, not ${target}`;
  if (report.partial) return "it is a partial run";
  if (report.ok !== true || report.gate?.passed !== true) return "it did not pass in gate mode";
  if ((report.checks ?? []).some((c) => c.outcome === "predates-cli")) return "checks predated its CLI too";
  return null;
}
