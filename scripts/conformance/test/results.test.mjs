// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import { endProblem, lastError, parseSuiteOutput, resultLine } from "../lib/results.mjs";

test("reads one result per line, with its status, ID and text", () => {
  const { results, errors } = parseSuiteOutput(
    [
      "--- something the suite prints",
      "PASS  [dashboard.csp-strict] the dashboard is served with a strict Content-Security-Policy - default-src 'none'",
      "FAIL  [values.grid-masks-secret] the grid masks a Secret",
      "N/A  [realtime.live-signals-drive-updates-again] live signals drive updates again",
      "PREDATES-CLI  [client-runtime.types-python] the Python module",
      "  [browser] PASS  [not.a-result] indented lines are the suite's own output",
    ].join("\n"),
  );
  assert.deepEqual(errors, []);
  assert.deepEqual(
    results.map((r) => [r.status, r.id]),
    [
      ["PASS", "dashboard.csp-strict"],
      ["FAIL", "values.grid-masks-secret"],
      ["N/A", "realtime.live-signals-drive-updates-again"],
      ["PREDATES-CLI", "client-runtime.types-python"],
    ],
  );
  assert.match(results[0].text, /^the dashboard is served/);
});

test("an ERROR line and a failure that names no check are errors", () => {
  const { results, errors } = parseSuiteOutput("ERROR  maintenance E2E: timeout\nFAIL  cli login: refused\nFAILED to parse\nPASS  no id here\n");
  assert.equal(results.length, 0);
  // "FAILED to parse" is the suite's own words, not a FAIL line.
  assert.deepEqual(errors, ["maintenance E2E: timeout", "a failure that names no check: FAIL  cli login: refused"]);
});

test("Windows line endings and a result with no text", () => {
  const { results } = parseSuiteOutput("PASS  [a.b]\r\nFAIL  [a.c] x\r\n");
  assert.deepEqual(results, [
    { status: "PASS", id: "a.b", text: "" },
    { status: "FAIL", id: "a.c", text: "x" },
  ]);
});

test("resultLine writes what parseSuiteOutput reads, and only known statuses", () => {
  const line = resultLine("PASS", "request-budget.no-unexpected-429", "no 429");
  assert.deepEqual(parseSuiteOutput(line).results, [{ status: "PASS", id: "request-budget.no-unexpected-429", text: "no 429" }]);
  assert.throws(() => resultLine("SKIP", "a.b", "x"));
});

test("a suite ends only with one marker on its channel, its name and nonce, and the exit code it names", () => {
  const nonce = "0123456789abcdef0123456789abcdef";
  const ok = { suite: "a", nonce, code: 0, signal: null };
  assert.equal(endProblem(`END a ${nonce} 0\n`, ok), null);
  assert.equal(endProblem(`END a ${nonce} 1\n`, { ...ok, code: 1 }), null);
  assert.match(endProblem("", ok), /never called finish\(\)/);
  assert.match(endProblem(`END a ${nonce} 0\nEND a ${nonce} 0\n`, ok), /carried 2 lines/);
  assert.match(endProblem(`END b ${nonce} 0\n`, ok), /names b, not a/);
  assert.match(endProblem(`END a ${"f".repeat(32)} 0\n`, ok), /another nonce/);
  assert.match(endProblem(`END a ${nonce} 0\n`, { ...ok, code: 1 }), /exited 1, but its end-of-suite marker says 0/);
  assert.match(endProblem(`END a ${nonce} 0\n`, { ...ok, code: null, signal: "SIGKILL" }), /killed by SIGKILL/);
  assert.match(endProblem("END  [a]\n", ok), /not a marker/);
  // Output on stdout or stderr is never the channel.
  assert.deepEqual(parseSuiteOutput(`END a ${nonce} 0\nEND  [a]\n`), { results: [], errors: [] });
});

test("a suite that did not finish is named by the error it last wrote", () => {
  // The access suite's crash on a merge-queue run, as Node printed it.
  const playwright = [
    "  [browser] Failed to load resource: the server responded with a status of 404 (Not Found)",
    "node:internal/modules/run_main:111",
    "    triggerUncaughtException(",
    "    ^",
    "",
    "page.waitForFunction: Timeout 10000ms exceeded.",
    "    at /home/runner/work/varlatch/varlatch/apps/web/scripts/e2e-access.mjs:392:14 {",
    "  log: [],",
    "  name: 'TimeoutError'",
    "}",
    "",
    "Node.js v26.13.1",
    "",
  ].join("\n");
  assert.equal(
    lastError(playwright),
    "TimeoutError: page.waitForFunction: Timeout 10000ms exceeded. (at /home/runner/work/varlatch/varlatch/apps/web/scripts/e2e-access.mjs:392:14)",
  );
  // A plain Error: its message already carries its name; the last trace wins.
  const two = [
    "Error: an earlier, caught one",
    "    at first (/x/a.mjs:1:1)",
    "TypeError: Cannot read properties of undefined (reading 'id')",
    "    at step (/x/e2e-values.mjs:85:12)",
    "    at async main (/x/e2e-values.mjs:20:3)",
  ].join("\n");
  assert.equal(lastError(two), "TypeError: Cannot read properties of undefined (reading 'id') (at step (/x/e2e-values.mjs:85:12))");
  // No trace: the last line; nothing: null.
  assert.equal(lastError("starting\nthe server went away\n\n"), "the server went away");
  assert.equal(lastError(""), null);
  assert.equal(lastError(undefined), null);
});
