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
 * External suites (`externalSuites`): the suites the runner does not run,
 * the TypeScript installation's lifecycle and installer suites
 * (scripts/test-*.mjs). Each names its replacement the way a ts-stack check
 * does; gate mode (lib/gate.mjs) needs every replacement present and passing,
 * so an `open` one keeps the gate shut until the step that writes it.
 *
 * Features: a check that exercises a CLI feature names it (`feature`). A
 * feature cites the CHANGELOG entry that introduced it and is either part of
 * the compatibility core (`core: true`, never version-gated: every pinned
 * CLI must pass it) or names the version that introduced it
 * (`introducedIn`). A suite runs each version-gated feature's checks as one
 * group, and reports them `predates-cli` when the CLI under test is older.
 *
 * A run fails on: a check in the inventory that did not report; a reported
 * check that is not in the inventory (or reported by another suite); a
 * failure; a conformance or component check reported not applicable; a
 * `predates-cli` result the runner cannot confirm; and any error a suite
 * or the runner reports outside a check. An error is never a skip.
 */

import { STATUSES } from "./results.mjs";

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

/**
 * The compatibility core (ADR-0059 step 2): what every pinned CLI must run
 * and pass, never version-gated. Exactly these features carry `core: true`.
 */
export const CORE_FEATURES = [
  "login-token",
  "whoami",
  "env-list",
  "run",
  "run-export-context",
  "types-typescript",
  "types-python",
  "login-browser",
  "login-device",
];

const ID = /^[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9.-]*$/;
const SUITE = /^[a-z0-9][a-z0-9-]*$/;
const FEATURE = /^[a-z0-9][a-z0-9-]*$/;
export const VERSION = /^\d+\.\d+\.\d+$/;

/** -1, 0 or 1 as version `a` is older than, the same as, or newer than `b` (x.y.z). */
export function compareVersions(a, b) {
  if (!VERSION.test(a) || !VERSION.test(b)) throw new Error(`not an x.y.z version: ${VERSION.test(a) ? b : a}`);
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
  const features = inventory.features ?? {};
  const counts = new Map(Object.keys(suites).map((s) => [s, 0]));
  const featureChecks = new Map(Object.keys(features).map((f) => [f, 0]));
  for (const [name, feature] of Object.entries(features)) {
    const where = `feature ${name}`;
    if (!FEATURE.test(name)) problems.push(`${where}: not a feature name`);
    if (typeof feature.title !== "string" || feature.title === "") problems.push(`${where}: no title`);
    const cite = feature.changelog;
    if (!cite || typeof cite !== "object" || !VERSION.test(String(cite.release)) || typeof cite.quote !== "string" || cite.quote.trim() === "") {
      problems.push(`${where}: changelog must be { "release": "x.y.z", "quote": "<the entry's words>" }`);
    }
    const core = CORE_FEATURES.includes(name);
    if (core && feature.core !== true) problems.push(`${where}: is in the compatibility core, so it must say "core": true`);
    if (!core && feature.core === true) problems.push(`${where}: only ${CORE_FEATURES.join(", ")} are in the compatibility core`);
    if (feature.core === true) {
      if ("introducedIn" in feature) problems.push(`${where}: a compatibility-core feature is never version-gated (no introducedIn)`);
    } else if (!VERSION.test(String(feature.introducedIn))) {
      problems.push(`${where}: introducedIn must be x.y.z`);
    } else if (cite && cite.release !== feature.introducedIn) {
      problems.push(`${where}: introducedIn ${feature.introducedIn} differs from the release its changelog entry cites (${cite.release})`);
    }
  }
  for (const name of CORE_FEATURES) if (!(name in features)) problems.push(`feature ${name}: the compatibility core needs it in the inventory`);
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
      problems.push(...replacementProblems(where, check.replacement, checks));
    } else if ("replacement" in check) {
      problems.push(`${where}: only a ts-stack check has a replacement`);
    }
    if ("reportedBy" in check && check.reportedBy !== "runner") problems.push(`${where}: reportedBy can only be "runner"`);
    for (const key of ["introducedIn", "core"]) {
      if (key in check) problems.push(`${where}: ${key} belongs on the check's feature, not the check`);
    }
    if ("feature" in check) {
      if (!(check.feature in features)) problems.push(`${where}: unknown feature ${check.feature}`);
      else {
        featureChecks.set(check.feature, featureChecks.get(check.feature) + 1);
        if (check.kind === "component") problems.push(`${where}: a component check tests this checkout, not a CLI feature`);
        if (check.reportedBy === "runner") problems.push(`${where}: a check the runner reports exercises no CLI feature`);
      }
    }
  }
  for (const [name, suite] of Object.entries(inventory.externalSuites ?? {})) {
    const where = `external suite ${name}`;
    if (!SUITE.test(name)) problems.push(`${where}: not a suite name`);
    if (name in suites) problems.push(`${where}: is also a suite the runner runs`);
    if (typeof suite.title !== "string" || suite.title === "") problems.push(`${where}: no title`);
    if (typeof suite.script !== "string" || !/^scripts\/test-[a-z0-9-]+\.mjs$/.test(suite.script)) problems.push(`${where}: script must be scripts/test-<name>.mjs`);
    if (suite.kind !== "ts-stack") problems.push(`${where}: kind must be ts-stack (it tests the TypeScript installation)`);
    problems.push(...replacementProblems(where, suite.replacement, checks));
  }
  for (const [suite, count] of counts) if (count === 0) problems.push(`suite ${suite}: no checks`);
  for (const [feature, count] of featureChecks) if (count === 0) problems.push(`feature ${feature}: no checks`);
  for (const name of CORE_FEATURES) {
    if (name in features && !Object.values(checks).some((c) => c.feature === name && c.kind === "conformance")) {
      problems.push(`feature ${name}: the compatibility core needs at least one conformance check`);
    }
  }
  return problems;
}

/**
 * Problems with a replacement: a conformance check ID in the inventory,
 * { "none": "<why>" } or { "open": "<the step that writes it>" }.
 */
function replacementProblems(where, r, checks) {
  if (typeof r === "string") {
    if (!(r in checks)) return [`${where}: replacement ${r} is not in the inventory`];
    if (checks[r].kind !== "conformance") return [`${where}: replacement ${r} is not a conformance check`];
    return [];
  }
  if (r && typeof r === "object") {
    const keys = Object.keys(r);
    if (keys.length !== 1 || !["none", "open"].includes(keys[0]) || typeof r[keys[0]] !== "string" || r[keys[0]].trim() === "") {
      return [`${where}: replacement must be a check ID, { "none": "<why>" } or { "open": "<the step that writes it>" }`];
    }
    return [];
  }
  return [`${where}: a ts-stack check or external suite names its replacement`];
}

/**
 * What a check's feature says about version gating: `{ feature, core,
 * introducedIn }`, all null for a check that exercises no CLI feature.
 */
export function gating(inventory, id) {
  const check = inventory.checks?.[id];
  const feature = check?.feature ? inventory.features?.[check.feature] : undefined;
  if (!feature) return { feature: null, core: false, introducedIn: null };
  return { feature: check.feature, core: feature.core === true, introducedIn: feature.core === true ? null : feature.introducedIn ?? null };
}

/**
 * Whether a CLI of version `cliVersion` predates `feature` (a name in
 * inventory.features). A CLI built from source (null) predates nothing, and
 * nothing predates a compatibility-core feature.
 */
export function predates(inventory, feature, cliVersion) {
  const f = inventory.features?.[feature];
  if (!f) throw new Error(`unknown feature ${feature}`);
  if (cliVersion === null || cliVersion === undefined || cliVersion === "" || f.core === true) return false;
  return compareVersions(cliVersion, f.introducedIn) < 0;
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
    // `failure` says why a check failed: "assertion" only when the check
    // itself reported a FAIL line; every other failure (no report, a
    // forbidden N/A, an unconfirmed PREDATES-CLI, inconsistent reports) is
    // "reporting", which no expected failure can cover (lib/expect.mjs).
    const judged = (outcome, why = "", failure = null) =>
      checks.push({ id, suite: entry.suite, kind: entry.kind, feature: entry.feature ?? null, outcome, why, reports: got.length, ...(failure ? { failure } : {}) });
    const reporting = (why) => judged("fail", why, "reporting");
    // Inconsistency first: only a single, valid status is judged by its
    // kind, so a FAIL mixed with any other result (PASS, a forbidden N/A, an
    // unconfirmed PREDATES-CLI) is a reporting failure, never an assertion
    // an expectation could excuse.
    const invalid = [...statuses].filter((st) => !STATUSES.includes(st));
    if (got.length === 0) reporting("did not report");
    else if (invalid.length > 0) reporting(`reported an invalid status: ${invalid.join(", ")}`);
    else if (statuses.size > 1) {
      const failed = got.find((r) => r.status === "FAIL");
      reporting(`reported inconsistently: ${[...statuses].join(", ")} (${got.length} results)${failed ? `; a FAIL said: ${failed.text}` : ""}`);
    }
    else if (statuses.has("FAIL")) judged("fail", got.find((r) => r.status === "FAIL").text, "assertion");
    else if (statuses.has("PASS")) judged("pass");
    else if (statuses.has("N/A")) {
      if (entry.kind === "ts-stack") judged("not-applicable", got[0].text);
      else reporting(`a ${entry.kind} check reported not applicable: ${got[0].text}`);
    } else {
      // PREDATES-CLI: accepted only when the runner itself confirms it,
      // from the inventory and the CLI's verified version.
      const gate = gating(inventory, id);
      if (gate.core) reporting(`a compatibility-core check (${gate.feature}) cannot predate the CLI`);
      else if (!gate.introducedIn) reporting("reported predates-cli, but the inventory names no version that introduced its feature");
      else if (cliVersion === null) reporting("reported predates-cli, but the CLI under test is built from source");
      else if (compareVersions(cliVersion, gate.introducedIn) >= 0) reporting(`reported predates-cli, but CLI ${cliVersion} is not older than ${gate.introducedIn} (${gate.feature})`);
      else judged("predates-cli", `CLI ${cliVersion} predates ${gate.feature}, introduced in ${gate.introducedIn}`);
    }
  }
  const failed = checks.filter((c) => c.outcome === "fail");
  return { checks, problems, ok: failed.length === 0 && problems.length === 0 };
}
