// SPDX-License-Identifier: Apache-2.0
/**
 * The inventory (scripts/conformance/inventory.json) is the gate: every
 * check a run must account for, with its suite, its kind and, for a check
 * about the TypeScript deployment itself, what replaces it on the Go server.
 *
 * Kinds:
 *   conformance  must run and pass on every target;
 *   ts-stack     about the TypeScript deployment (Convex, nginx, compose):
 *                not applicable where the target lacks the ts-stack
 *                capability; names its `replacement`: a conformance check
 *                in the inventory, { "none": "<why>" }, or
 *                { "open": "<the step that writes it>" };
 *   component    tests this checkout's code, not the target; kept in the
 *                run, never counted as conformance.
 *
 * A run fails on: a check in the inventory that did not report; a reported
 * check that is not in the inventory (or reported by another suite); a
 * failure; a conformance or component check reported not applicable; a
 * `predates-cli` result the runner cannot confirm; and any error a suite
 * or the runner reports outside a check. An error is never a skip.
 */

export const KINDS = ["conformance", "ts-stack", "component"];

/**
 * The optional capabilities a suite may need. The required operations (up,
 * down, origin, bootstrap, recover, restart, logs, request-log) are not
 * listed: a target without them cannot run at all.
 */
export const CAPABILITIES = [
  "probe:audit-event-count",
  "probe:device-sign-in-addresses",
  "probe:expire-pending-device-sign-ins",
  "probe:proxy-addresses",
  "maintenance",
  "serve-cli",
  "ts-stack",
];

const ID = /^[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9.-]*$/;
const SUITE = /^[a-z0-9][a-z0-9-]*$/;
const VERSION = /^\d+\.\d+\.\d+$/;

/** -1, 0 or 1 as version `a` is older than, the same as, or newer than `b` (x.y.z). */
export function compareVersions(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  }
  return 0;
}

/** Problems with the inventory's own shape; empty when it is valid. */
export function validateInventory(inventory) {
  const problems = [];
  if (inventory?.schema !== 1) return ["schema: expected 1"];
  const suites = inventory.suites ?? {};
  const checks = inventory.checks ?? {};
  const counts = new Map(Object.keys(suites).map((s) => [s, 0]));
  for (const [name, suite] of Object.entries(suites)) {
    if (!SUITE.test(name)) problems.push(`suite ${name}: not a suite name`);
    if (typeof suite.title !== "string" || suite.title === "") problems.push(`suite ${name}: no title`);
    if (suite.runner !== true && (typeof suite.script !== "string" || suite.script === "")) problems.push(`suite ${name}: no script (or "runner": true)`);
    for (const need of suite.needs ?? []) {
      if (!CAPABILITIES.includes(need)) problems.push(`suite ${name}: unknown capability ${need}`);
    }
  }
  for (const [id, check] of Object.entries(checks)) {
    const where = `check ${id}`;
    if (!ID.test(id)) problems.push(`${where}: not a check ID`);
    if (!(check.suite in suites)) problems.push(`${where}: unknown suite ${check.suite}`);
    else {
      counts.set(check.suite, counts.get(check.suite) + 1);
      if (!id.startsWith(`${check.suite}.`)) problems.push(`${where}: its ID must start with its suite, ${check.suite}.`);
    }
    if (typeof check.title !== "string" || check.title === "") problems.push(`${where}: no title`);
    if (!KINDS.includes(check.kind)) {
      problems.push(`${where}: kind must be one of ${KINDS.join(", ")}`);
      continue;
    }
    if (check.kind === "ts-stack") {
      const r = check.replacement;
      if (typeof r === "string") {
        if (!(r in checks)) problems.push(`${where}: replacement ${r} is not in the inventory`);
        else if (checks[r].kind !== "conformance") problems.push(`${where}: replacement ${r} is not a conformance check`);
      } else if (r && typeof r === "object") {
        const keys = Object.keys(r);
        if (keys.length !== 1 || !["none", "open"].includes(keys[0]) || typeof r[keys[0]] !== "string" || r[keys[0]].trim() === "") {
          problems.push(`${where}: replacement must be a check ID, { "none": "<why>" } or { "open": "<the step that writes it>" }`);
        }
      } else {
        problems.push(`${where}: a ts-stack check names its replacement`);
      }
    } else if ("replacement" in check) {
      problems.push(`${where}: only a ts-stack check has a replacement`);
    }
    if ("reportedBy" in check && check.reportedBy !== "runner") problems.push(`${where}: reportedBy can only be "runner"`);
    if ("introducedIn" in check && !VERSION.test(String(check.introducedIn))) problems.push(`${where}: introducedIn must be x.y.z`);
    if (check.core === true && "introducedIn" in check) problems.push(`${where}: a compatibility-core check is never version-gated`);
  }
  for (const [suite, count] of counts) if (count === 0) problems.push(`suite ${suite}: no checks`);
  return problems;
}

/**
 * Judges one run against the inventory.
 *
 * `reports`: every result line, { suite, id, status, text }, status one of
 * PASS, FAIL, N/A, PREDATES-CLI (the runner adds N/A lines for a suite it
 * did not start because the target lacks what the suite needs).
 * `errors`: { suite, message } for anything outside a check.
 * `cliVersion`: the CLI's verified version, or null for a CLI built from
 * source (no `predates-cli` result is accepted then).
 */
export function evaluate({ inventory, reports, errors = [], cliVersion = null }) {
  const problems = errors.map((e) => `${e.suite}: ${e.message}`);
  const byId = new Map();
  for (const r of reports) {
    const entry = inventory.checks[r.id];
    if (!entry) {
      problems.push(`${r.suite}: reported ${r.id}, which is not in the inventory`);
      continue;
    }
    if (entry.suite !== r.suite) {
      problems.push(`${r.suite}: reported ${r.id}, which belongs to ${entry.suite}`);
      continue;
    }
    byId.set(r.id, [...(byId.get(r.id) ?? []), r]);
  }
  const checks = [];
  for (const [id, entry] of Object.entries(inventory.checks)) {
    const got = byId.get(id) ?? [];
    const statuses = new Set(got.map((r) => r.status));
    const judged = (outcome, why = "") => checks.push({ id, suite: entry.suite, kind: entry.kind, outcome, why, reports: got.length });
    if (got.length === 0) judged("fail", "did not report");
    else if (statuses.has("FAIL")) judged("fail", got.find((r) => r.status === "FAIL").text);
    else if (statuses.size > 1) judged("fail", `reported inconsistently: ${[...statuses].join(", ")}`);
    else if (statuses.has("PASS")) judged("pass");
    else if (statuses.has("N/A")) {
      if (entry.kind === "ts-stack") judged("not-applicable", got[0].text);
      else judged("fail", `a ${entry.kind} check reported not applicable: ${got[0].text}`);
    } else {
      // PREDATES-CLI: accepted only when the runner itself confirms it.
      if (entry.core === true) judged("fail", "a compatibility-core check cannot predate the CLI");
      else if (!entry.introducedIn) judged("fail", "reported predates-cli, but the inventory names no version that introduced it");
      else if (cliVersion === null) judged("fail", "reported predates-cli, but the CLI under test is built from source");
      else if (compareVersions(cliVersion, entry.introducedIn) >= 0) judged("fail", `reported predates-cli, but CLI ${cliVersion} is not older than ${entry.introducedIn}`);
      else judged("predates-cli", `CLI ${cliVersion} predates ${entry.introducedIn}`);
    }
  }
  const failed = checks.filter((c) => c.outcome === "fail");
  return { checks, problems, ok: failed.length === 0 && problems.length === 0 };
}
