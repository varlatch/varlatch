// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSuiteOutput, resultLine } from "../lib/results.mjs";

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
