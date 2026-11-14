// SPDX-License-Identifier: Apache-2.0
/**
 * Expected failures (scripts/conformance/README.md): the checks a target is
 * known to fail, kept in scripts/conformance/expect/<target name>.json:
 *
 *   {
 *     "schema": 1,
 *     "expected": {
 *       "<target key>": {                       ts-source, ts-release:<version>, go-binary
 *         "<client>": {                         source, a pinned CLI version, or * for every CLI
 *           "<check id>": { "reason": "<why it fails>", "removedBy": "<the step that removes it>" }
 *         }
 *       }
 *     },
 *     "lacks": {
 *       "<target key>": {                       the operations the target does not have yet
 *         "<operation>": { "reason": "<why the target lacks it>", "step": "<the step that adds it>" }
 *       }
 *     }
 *   }
 *
 * `lacks` (lib/operations.mjs) declares the target's gaps: a check that
 * needs a lacking operation reports target-lacks, and the runner asks the
 * target that each entry is really missing before the suites run.
 *
 * A check expected to fail that fails is reported as an expected failure,
 * never hidden; one that passes fails the run (remove its entry). The list
 * only shrinks by default: CI compares the files with the pull request's
 * merge base, and an added entry fails unless the pull request carries the
 * `conformance-regression` label (expect-check.mjs).
 */
import { readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { VERSION } from "./inventory.mjs";
import { lackingChecks, lacksProblems } from "./operations.mjs";

export const ANY_CLIENT = "*";
export const REGRESSION_LABEL = "conformance-regression";

/**
 * Problems with one expectations file's shape; empty when it is valid.
 * `openapi` (lib/operations.mjs openapiOperations) checks that each lacking
 * operation exists; without it, only named operations are known.
 */
export function validateExpectations(file, { targetName, inventory, cliVersions, openapi = new Map() }) {
  const where = `expect/${targetName}.json`;
  if (file?.schema !== 1) return [`${where}: schema: expected 1`];
  if (!file.expected || typeof file.expected !== "object" || Array.isArray(file.expected)) return [`${where}: expected must be an object`];
  const problems = [];
  if ("lacks" in file) {
    if (!file.lacks || typeof file.lacks !== "object" || Array.isArray(file.lacks)) problems.push(`${where}: lacks must be an object`);
    else {
      for (const [key, entries] of Object.entries(file.lacks)) {
        if (key !== targetName && !key.startsWith(`${targetName}:`)) problems.push(`${where}: lacks: ${key} is not a ${targetName} target`);
        problems.push(...lacksProblems(`${where}: lacks / ${key}`, entries, { inventory, openapi }));
      }
    }
  }
  for (const [key, clients] of Object.entries(file.expected)) {
    if (key !== targetName && !key.startsWith(`${targetName}:`)) problems.push(`${where}: ${key} is not a ${targetName} target`);
    if (!clients || typeof clients !== "object") {
      problems.push(`${where}: ${key} must map clients to checks`);
      continue;
    }
    const anyClient = new Set(Object.keys(clients[ANY_CLIENT] ?? {}));
    for (const [client, checks] of Object.entries(clients)) {
      const at = `${where}: ${key} / ${client}`;
      if (client !== ANY_CLIENT && client !== "source" && !(VERSION.test(client) && cliVersions.includes(client))) {
        problems.push(`${at}: the client must be source, ${ANY_CLIENT}, or a CLI clients.json pins (${cliVersions.join(", ")})`);
      }
      for (const [id, entry] of Object.entries(checks ?? {})) {
        if (!(id in inventory.checks)) problems.push(`${at}: ${id} is not in the inventory`);
        if (client !== ANY_CLIENT && anyClient.has(id)) problems.push(`${at}: ${id} is also expected for every client (${ANY_CLIENT})`);
        const keys = Object.keys(entry ?? {}).sort().join(",");
        if (keys !== "reason,removedBy" || !String(entry.reason).trim() || !String(entry.removedBy).trim()) {
          problems.push(`${at}: ${id} must be { "reason": "<why it fails>", "removedBy": "<the step that removes it>" }`);
        }
      }
    }
  }
  return problems;
}

/** The operations a target lacks: Map(operation → { reason, step }). */
export function lacksFor(file, key) {
  return new Map(Object.entries(file?.lacks?.[key] ?? {}));
}

/**
 * Every check that reports target-lacks under a set of expectations files,
 * judged with one inventory: `<file>|<target key>|<check id>`.
 */
export function lackingCheckKeys(files, inventory) {
  const keys = new Set();
  for (const [fileName, file] of Object.entries(files)) {
    for (const [key, entries] of Object.entries(file?.lacks ?? {})) {
      for (const id of lackingChecks(inventory, Object.keys(entries ?? {})).keys()) keys.add(`${fileName}|${key}|${id}`);
    }
  }
  return keys;
}

/** Every `lacks` entry of a set of expectations files: `<file>|<target key>|<operation>`. */
export function lacksKeys(files) {
  const keys = new Set();
  for (const [fileName, file] of Object.entries(files)) {
    for (const [key, entries] of Object.entries(file?.lacks ?? {})) {
      for (const op of Object.keys(entries ?? {})) keys.add(`${fileName}|${key}|${op}`);
    }
  }
  return keys;
}

/** The expected failures in force for one run: Map(check id → { reason, removedBy, client }). */
export function expectationsFor(file, key, cliSpec) {
  const clients = file?.expected?.[key] ?? {};
  const out = new Map();
  for (const client of [ANY_CLIENT, cliSpec]) {
    for (const [id, entry] of Object.entries(clients[client] ?? {})) out.set(id, { ...entry, client });
  }
  return out;
}

/**
 * Applies the expected failures to a judged run (lib/inventory.mjs
 * evaluate): an expected check that failed by its own FAIL line
 * (`failure: "assertion"`) becomes `expected-fail`, still listed with why
 * it failed and its entry; an expected check that passed becomes a
 * failure. A reporting failure (no result, a forbidden N/A, an unconfirmed
 * PREDATES-CLI, inconsistent results) stays a failure whatever is
 * expected. Other outcomes (not applicable, predates the CLI) stay as they
 * are and are listed as not exercised. Problems outside checks are never
 * expected.
 */
export function applyExpectations(judged, expected) {
  const summary = { inForce: expected.size, failedAsExpected: [], failedOtherwise: [], passedUnexpectedly: [], notExercised: [] };
  const checks = judged.checks.map((c) => {
    const entry = expected.get(c.id);
    if (!entry) return c;
    const expectation = { reason: entry.reason, removedBy: entry.removedBy, client: entry.client };
    // Only a failure the check itself reported (a FAIL line) can be
    // expected. A check that did not report, reported a forbidden N/A or an
    // unconfirmed PREDATES-CLI, or reported inconsistently always fails.
    if (c.outcome === "fail" && c.failure === "assertion") {
      summary.failedAsExpected.push(c.id);
      return { ...c, outcome: "expected-fail", expected: expectation };
    }
    if (c.outcome === "fail") {
      summary.failedOtherwise.push(c.id);
      return { ...c, why: `${c.why} (expected to fail by assertion, but this failure is not one: an expectation never covers it)`, expected: expectation };
    }
    if (c.outcome === "pass") {
      summary.passedUnexpectedly.push(c.id);
      return { ...c, outcome: "fail", why: `expected to fail (${entry.reason}; removed by ${entry.removedBy}), but it passed: remove its entry from the expectations`, expected: expectation };
    }
    summary.notExercised.push(c.id);
    return { ...c, expected: expectation };
  });
  const listed = new Set(judged.checks.map((c) => c.id));
  const problems = [...judged.problems];
  for (const id of expected.keys()) if (!listed.has(id)) problems.push(`expectations: ${id} is expected to fail, but the run has no such check`);
  const ok = problems.length === 0 && !checks.some((c) => c.outcome === "fail");
  return { checks, problems, ok, expectations: summary };
}

/** Every entry of a set of expectations files, as `<file>|<target key>|<client>|<check id>`. */
export function entryKeys(files) {
  const keys = new Set();
  for (const [fileName, file] of Object.entries(files)) {
    for (const [key, clients] of Object.entries(file?.expected ?? {})) {
      for (const [client, checks] of Object.entries(clients ?? {})) {
        for (const id of Object.keys(checks ?? {})) keys.add(`${fileName}|${key}|${client}|${id}`);
      }
    }
  }
  return keys;
}

/**
 * The entries `head` has that `base` (the merge base) does not: what a pull
 * request adds to the expected failures. Moving an entry to another client
 * or target counts as adding one.
 */
export function addedEntries(base, head) {
  const before = entryKeys(base);
  return [...entryKeys(head)].filter((k) => !before.has(k)).sort();
}

/**
 * A module and every module it reaches through static relative imports
 * (`... from "<relative path>"` and bare `import "<relative path>"`), as
 * paths relative to `root` with forward slashes: what the expectations
 * checker needs to run. Comments are ignored. Dynamic imports are not
 * followed: the checker loads no module that way (it reads only target
 * names from targets/index.mjs).
 */
export function importClosure(entry, root) {
  const seen = new Set();
  const visit = (file) => {
    const path = relative(root, file).split("\\").join("/");
    if (seen.has(path)) return;
    seen.add(path);
    const code = readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
    for (const m of code.matchAll(/(?:\bfrom\s*|^\s*import\s+)["'](\.{1,2}\/[^"']+)["']/gm)) visit(join(dirname(file), m[1]));
  };
  visit(entry);
  return [...seen].sort();
}
