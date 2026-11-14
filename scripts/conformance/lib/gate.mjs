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
 *   - the target recorded what it ran (its implementation fingerprint:
 *     targets/*.mjs `fingerprint`);
 *   - either no check reported predates-cli, or the run names the report of
 *     a run of the same implementation, with a CLI recent enough that
 *     nothing predates it, that passes these rules itself. That report is
 *     judged again here from its checks and the current inventory; its own
 *     `ok` and `gate` fields are not trusted.
 *
 * The companion report is a file: whoever can write it can forge it. Gate
 * evidence is taken from the CI artifacts of one workflow run
 * (scripts/conformance/README.md, Gate mode), never from a local file.
 */
import { compareVersions, VERSION } from "./inventory.mjs";

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

/** JSON with sorted object keys, so two fingerprints compare by content. */
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value ?? null);
}

/** The features a CLI of `version` predates (none for a CLI built from source: null or ""). */
export function predatedFeatures(inventory, version) {
  if (version === null || version === undefined || version === "") return [];
  return Object.entries(inventory.features ?? {})
    .filter(([, f]) => f.core !== true && VERSION.test(String(f.introducedIn)) && compareVersions(version, f.introducedIn) < 0)
    .map(([name]) => name);
}

/** The rules a run's own checks must meet: no expected failure, every replacement passing. */
function runRules(inventory, run) {
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
  return { problems, open };
}

/**
 * Judges a run in gate mode.
 *
 *   run         { target, partial, ok, checks: [{ id, outcome }], expectedInForce: [check ids],
 *                 implementation (the target's fingerprint, or null) }
 *   walkthrough null, or { path (relative to the checkout), exists, size, sha256 }
 *   recentCli   null, or the parsed report (conformance-report.json) of a
 *               run with a recent CLI
 *
 * Returns `{ passed, problems, open }`; `open` lists the open replacements.
 */
export function judgeGate({ inventory, run, walkthrough = null, recentCli = null }) {
  const { problems, open } = runRules(inventory, run);
  if (!run.implementation) problems.push(`target ${run.target} recorded no implementation fingerprint: the gate cannot name what passed`);

  if (!walkthrough) problems.push(`the run names no browser-walkthrough evidence file (--walkthrough ${EVIDENCE_DIR}<file>)`);
  else if (!walkthrough.path.startsWith(EVIDENCE_DIR) || walkthrough.path.split("/").includes("..")) {
    problems.push(`the browser-walkthrough evidence ${walkthrough.path} is not under ${EVIDENCE_DIR} of this checkout`);
  } else if (!walkthrough.exists) problems.push(`the browser-walkthrough evidence ${walkthrough.path} does not exist`);
  else if (!(walkthrough.size > 0)) problems.push(`the browser-walkthrough evidence ${walkthrough.path} is empty`);

  const predating = run.checks.filter((c) => c.outcome === "predates-cli").map((c) => c.id);
  if (predating.length > 0) {
    const why = recentCliProblems(recentCli, { inventory, target: run.target, implementation: run.implementation, walkthrough });
    if (why.length > 0) {
      problems.push(
        `${predating.length} checks predate this run's CLI, so the gate also needs the report of a gate run of the same implementation ` +
          `with a CLI that predates nothing (--recent-cli-report <report.json>): ${why.join("; ")}`,
      );
    }
  }
  return { passed: problems.length === 0, problems, open };
}

/**
 * Why `report` cannot stand in as the recent-CLI gate run for this one;
 * empty when it can. It is judged again from scratch: a complete report of
 * the same target and the same implementation, every inventory check present
 * once and passing (or not applicable, for a ts-stack check), no problem,
 * a CLI that predates no feature, the same walkthrough evidence, and the
 * gate's own rules on its checks.
 */
export function recentCliProblems(report, { inventory, target, implementation, walkthrough = null }) {
  if (!report || typeof report !== "object") return ["none named"];
  const problems = [];
  if (report.target !== target) problems.push(`it is a run of ${JSON.stringify(report.target)}, not ${target}`);
  if (report.partial !== false) problems.push("it is not a complete run");
  if (!implementation) problems.push("this run recorded no implementation fingerprint to compare it with");
  else if (!report.implementation || canonical(report.implementation) !== canonical(implementation)) {
    problems.push(`it ran another implementation (${canonical(report.implementation ?? null).slice(0, 200)}, not ${canonical(implementation).slice(0, 200)})`);
  }
  const cli = report.cli;
  if (!cli || typeof cli !== "object" || typeof cli.spec !== "string" || !(cli.version === null || VERSION.test(String(cli.version)))) {
    problems.push("it names no verified CLI (cli.spec, cli.version)");
  } else {
    const predated = predatedFeatures(inventory, cli.version);
    if (predated.length > 0) problems.push(`its CLI ${cli.version} predates ${predated.join(", ")}`);
  }
  if (!Array.isArray(report.problems) || report.problems.length > 0) problems.push("it reports problems outside its checks");
  if (walkthrough?.sha256 && report.gate?.walkthrough?.sha256 !== walkthrough.sha256) problems.push("it names other browser-walkthrough evidence");

  const checks = Array.isArray(report.checks) ? report.checks : [];
  const seen = new Map();
  for (const c of checks) seen.set(c?.id, (seen.get(c?.id) ?? 0) + 1);
  const missing = Object.keys(inventory.checks).filter((id) => !seen.has(id));
  const extra = [...seen.keys()].filter((id) => !(id in inventory.checks));
  const twice = [...seen].filter(([, n]) => n > 1).map(([id]) => id);
  if (missing.length > 0) problems.push(`${missing.length} inventory checks are missing from it (${missing.slice(0, 5).join(", ")})`);
  if (extra.length > 0) problems.push(`it has checks the inventory does not (${extra.slice(0, 5).join(", ")})`);
  if (twice.length > 0) problems.push(`it lists checks more than once (${twice.slice(0, 5).join(", ")})`);
  const bad = checks.filter((c) => !(c?.outcome === "pass" || (c?.outcome === "not-applicable" && inventory.checks[c.id]?.kind === "ts-stack")));
  if (bad.length > 0) problems.push(`${bad.length} of its checks did not pass (${bad.slice(0, 5).map((c) => `${c?.id}: ${c?.outcome}`).join(", ")})`);

  // The gate's rules on its own checks, recomputed: its ok is ours, not its.
  const rules = runRules(inventory, {
    target,
    partial: report.partial !== false,
    ok: bad.length === 0 && missing.length === 0 && problems.length === 0,
    checks: checks.map((c) => ({ id: c?.id, outcome: c?.outcome })),
    expectedInForce: checks.filter((c) => c?.expected).map((c) => c.id),
  }).problems.filter((p) => p !== "the run itself did not pass" && !p.startsWith("a gate run covers every suite"));
  problems.push(...rules.map((p) => `its own gate: ${p.split("\n")[0]}`));
  return problems;
}
