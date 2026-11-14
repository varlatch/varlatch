// SPDX-License-Identifier: Apache-2.0
/**
 * Reading a suite's output (scripts/conformance/suite-kit.mjs writes it):
 *
 *   PASS  [<check id>] <name>[ - <detail>]
 *   FAIL  [<check id>] ...
 *   N/A  [<check id>] ...            the check does not apply to this target
 *   PREDATES-CLI  [<check id>] ...   the CLI under test is older than the feature
 *   ERROR  <message>                 a problem outside any one check
 *
 * Any other line is the suite's own output. A line that starts with FAIL but
 * names no check is a failure nobody can attribute, so it counts as an error.
 */

export const STATUSES = ["PASS", "FAIL", "N/A", "PREDATES-CLI"];
const RESULT = /^(PASS|FAIL|N\/A|PREDATES-CLI) {2}\[([^\]\s]+)\](?: (.*))?$/;
const ERROR = /^ERROR {2}(.*)$/;
const UNNAMED_FAILURE = /^FAIL\b/;

/** Parses one suite's whole output. */
export function parseSuiteOutput(text) {
  const results = [];
  const errors = [];
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\r$/, "");
    const result = RESULT.exec(line);
    if (result) {
      results.push({ status: result[1], id: result[2], text: result[3] ?? "" });
      continue;
    }
    const error = ERROR.exec(line);
    if (error) errors.push(error[1]);
    else if (UNNAMED_FAILURE.test(line)) errors.push(`a failure that names no check: ${line.slice(0, 300)}`);
  }
  return { results, errors };
}

/** A result line, as a suite prints it; the runner uses it for the checks it reports itself. */
export function resultLine(status, id, text) {
  if (!STATUSES.includes(status)) throw new Error(`not a result status: ${status}`);
  return `${status}  [${id}] ${text}`;
}
