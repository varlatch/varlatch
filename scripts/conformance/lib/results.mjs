// SPDX-License-Identifier: Apache-2.0
/**
 * Reading a suite's output (scripts/conformance/suite-kit.mjs writes it):
 *
 *   PASS  [<check id>] <name>[ - <detail>]
 *   FAIL  [<check id>] ...
 *   N/A  [<check id>] ...            the check does not apply to this target
 *   PREDATES-CLI  [<check id>] ...   the CLI under test is older than the feature
 *   NOT-BUILT  [<check id>] <line>   the Go CLI refused a step the check depends
 *                                    on as not built yet (suite-kit's NOT_BUILT);
 *                                    the runner turns it into client-lacks for
 *                                    --cli go, and fails the run for any other
 *                                    CLI, so it never reaches a verdict
 *   ERROR  <message>                 a problem outside any one check
 *
 * Any other line is the suite's own output. A line that starts with FAIL but
 * names no check is a failure nobody can attribute, so it counts as an error.
 *
 * TARGET-LACKS and CLIENT-LACKS are results only the runner gives
 * (lib/operations.mjs, lib/client-lacks.mjs), from the inventory and the
 * target's or the client's declared gaps: a suite that prints one has made
 * an error.
 */

export const STATUSES = ["PASS", "FAIL", "N/A", "PREDATES-CLI"];
/** The results only the runner reports. */
export const RUNNER_STATUSES = ["TARGET-LACKS", "CLIENT-LACKS"];
const RUNNER_ONLY = /^(?:TARGET|CLIENT)-LACKS\b/;
const RESULT = /^(PASS|FAIL|N\/A|PREDATES-CLI|NOT-BUILT) {2}\[([^\]\s]+)\](?: (.*))?$/;
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
    else if (RUNNER_ONLY.test(line)) errors.push(`only the runner reports target-lacks and client-lacks: ${line.slice(0, 300)}`);
    else if (UNNAMED_FAILURE.test(line)) errors.push(`a failure that names no check: ${line.slice(0, 300)}`);
  }
  return { results, errors };
}

const END_MARKER = /^END ([a-z0-9][a-z0-9-]*) ([0-9a-f]{32}) ([0-9]{1,3})$/;

/**
 * Whether a suite ended as finished: its end-of-suite channel (fd 3,
 * suite-kit's finish()) carried exactly one well-formed marker naming this
 * suite and the runner's nonce for it, and the process then exited
 * normally (no signal) with the code the marker names. Returns null when
 * it did, else why not. Nothing a suite or its children print on stdout or
 * stderr counts.
 */
export function endProblem(channel, { suite, nonce, code, signal }) {
  const lines = String(channel ?? "").split("\n").filter((l) => l !== "");
  if (lines.length === 0) return "it never called finish(): no end-of-suite marker on its channel (it crashed, stalled, or exited before its end)";
  if (lines.length > 1) return `its end-of-suite channel carried ${lines.length} lines, not one marker`;
  const m = END_MARKER.exec(lines[0]);
  if (!m) return `its end-of-suite channel carried ${JSON.stringify(lines[0].slice(0, 120))}, not a marker`;
  if (m[1] !== suite) return `its end-of-suite marker names ${m[1]}, not ${suite}`;
  if (m[2] !== nonce) return "its end-of-suite marker carries another nonce than the runner's";
  if (signal) return `it was killed by ${signal} after its end-of-suite marker`;
  if (code !== Number(m[3])) return `it exited ${code}, but its end-of-suite marker says ${m[3]}`;
  return null;
}

/**
 * The error a suite that did not finish last wrote on stderr, in one line:
 * the message of its last stack trace and the trace's first frame (a
 * Playwright timeout: "TimeoutError: page.waitForFunction: Timeout 10000ms
 * exceeded. (at …/e2e-access.mjs:392:14)"), or, with no trace, its last
 * line. null when it wrote nothing. So a crash names its cause instead of
 * showing only as checks that did not report.
 */
export function lastError(stderr) {
  const lines = String(stderr ?? "")
    .split("\n")
    .map((l) => l.replace(/\s+$/, ""));
  const frame = (l) => /^\s+at\s/.test(l);
  for (let i = lines.length - 1; i > 0; i--) {
    if (!frame(lines[i]) || frame(lines[i - 1])) continue;
    let message = lines[i - 1].trim();
    // Node prints a thrown object's extra fields after the frames, its name
    // among them ("  name: 'TimeoutError'"), when the message lacks it.
    const name = lines
      .slice(i + 1, i + 12)
      .map((l) => /^\s+name: '([A-Za-z]+)',?$/.exec(l)?.[1])
      .find(Boolean);
    if (name && !message.startsWith(name)) message = `${name}: ${message}`;
    const at = lines[i].trim().replace(/\s*\{$/, "");
    return `${message} (${at})`.slice(0, 400);
  }
  const last = lines.filter((l) => l.trim() !== "").at(-1);
  return last === undefined ? null : last.trim().slice(0, 400);
}

/** A result line, as a suite prints it; the runner uses it for the checks it reports itself. */
export function resultLine(status, id, text) {
  if (!STATUSES.includes(status) && !RUNNER_STATUSES.includes(status)) throw new Error(`not a result status: ${status}`);
  return `${status}  [${id}] ${text}`;
}
