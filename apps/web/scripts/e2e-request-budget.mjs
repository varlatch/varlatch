#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The end-to-end suites against varlatchd's real request budget.
 *
 * varlatchd allows each client 600 requests per 60-second window (a fixed
 * window that opens at the client's first request after the previous one
 * ended), and this production limit stays as it is. In ci-e2e.sh every
 * suite's browser and scripts reach varlatchd through the dashboard's nginx
 * from the same host address, so they share one budget. Run back to back,
 * busy suites overran it, and a suite failed on whichever request met the
 * 429.
 *
 * So the harness schedules: before each suite it waits until the host's
 * requests in the trailing window are few enough that whatever window
 * varlatchd has open has room for the next suite. At the end it checks the
 * one thing that proves the budget held: varlatchd refused nothing. The
 * window refuses the request that would exceed it with 429, and nginx logs
 * every response's status, so a 429 from varlatchd in the access log, other
 * than the proxy probe's expected pending-cap answers, fails the run (the
 * suite involved must slow down or split: the limit is not the thing to
 * change). nginx logs whole seconds, at completion rather than arrival, so
 * request counts per window from its log are estimates and certify nothing;
 * the report shows the busiest 61-second span only as context.
 *
 *   docker compose logs --no-log-prefix varlatch-web | e2e-request-budget.mjs wait <suite>
 *   docker compose logs --no-log-prefix varlatch-web | e2e-request-budget.mjs report
 */
import { fileURLToPath } from "node:url";

export const BUDGET = 600;
export const WINDOW_MS = 60_000;
/** nginx logs whole seconds: a request logged at second s happened in [s, s+1). */
const LOG_RESOLUTION_MS = 1_000;
/** Requests that may still count in varlatchd's open window when a suite starts. */
export const START_ALLOWANCE = 100;

const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
// nginx's default "main" format: $remote_addr - $remote_user [$time_local]
// "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for"
const LINE = /^(\S+) - \S+ \[(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})\] "(\S+) (\S+)[^"]*" (\d{3}) .*"([^"]*)"\s*$/;
/** The proxy probe (e2e-proxy-probe.mjs) forges these client addresses; its own check verifies its 429s are the pending cap. */
const PROBE_FORGED = /^198\.18\.0\.\d+$/;
// What nginx forwards to varlatchd, minus the paths its request window exempts.
const PROXIED = /^\/(auth|v1|enroll|\.well-known)(?:[/?]|$)/;

/**
 * The requests nginx forwarded to varlatchd's request window: client
 * address, logged time (ms; whole seconds, at completion), method, path,
 * status, and the X-Forwarded-For the client sent.
 */
export function requestsIn(log) {
  const requests = [];
  for (const line of log.split("\n")) {
    const m = LINE.exec(line);
    if (!m || !PROXIED.test(m[10])) continue;
    const [, client, day, mon, year, h, min, sec, zone, method, path, status, forwardedFor] = m;
    const offset = (zone.startsWith("-") ? -1 : 1) * (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(3))) * 60_000;
    const at = Date.UTC(Number(year), MONTHS[mon], Number(day), Number(h), Number(min), Number(sec)) - offset;
    requests.push({ client, at, method, path, status: Number(status), forwardedFor });
  }
  return requests.sort((a, b) => a.at - b.at);
}

/** The proxy probe's own requests, whose 429s its check verifies are the per-client pending cap. */
function fromProbe(r) {
  return r.method === "POST" && r.path === "/v1/auth/device" && PROBE_FORGED.test(r.forwardedFor);
}

/**
 * What the access log establishes about varlatchd's request budget:
 * `refusals`, every 429 varlatchd answered outside the proxy probe (any
 * refusal means a window, or another limit, was exceeded: the run fails);
 * and, as context only, the most requests per client whose logged times
 * fall in one 61-second span (a window holds at most 60 s of arrivals, and
 * nginx logs whole seconds at completion, so this is neither exact nor a
 * bound for long requests).
 */
export function assess(requests) {
  const refusals = requests.filter((r) => r.status === 429 && !fromProbe(r));
  const span = WINDOW_MS + LOG_RESOLUTION_MS;
  let busiest = { client: null, start: null, count: 0 };
  const byClient = new Map();
  for (const r of requests) byClient.set(r.client, [...(byClient.get(r.client) ?? []), r.at]);
  for (const [client, times] of byClient) {
    for (let first = 0, last = 0; last < times.length; last++) {
      while (times[last] - times[first] >= span) first++;
      if (last - first + 1 > busiest.count) busiest = { client, start: times[first], count: last - first + 1 };
    }
  }
  return { refusals, busiest };
}

/**
 * How long to wait, from `now`, until every client has at most `allowance`
 * requests logged in the trailing window plus the log's resolution.
 * Whatever window varlatchd has open started less than a window ago, and a
 * request is logged when it completes, never before it arrives, so every
 * request counted in that window is in the trailing span: after the wait
 * the window has room for at least BUDGET - allowance more. (Between suites
 * no request is in flight.)
 */
export function waitMs(requests, now, allowance = START_ALLOWANCE) {
  const span = WINDOW_MS + LOG_RESOLUTION_MS;
  const byClient = new Map();
  for (const r of requests) {
    if (r.at + span <= now) continue;
    byClient.set(r.client, [...(byClient.get(r.client) ?? []), r.at]);
  }
  let wait = 0;
  for (const times of byClient.values()) {
    if (times.length <= allowance) continue;
    // The (n - allowance)th oldest request must age out of the span.
    const ages = times.length - allowance;
    wait = Math.max(wait, times[ages - 1] + span - now);
  }
  return Math.max(0, wait);
}

async function readStdin() {
  let text = "";
  for await (const chunk of process.stdin) text += chunk;
  return text;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [mode, suite] = process.argv.slice(2);
  const requests = requestsIn(await readStdin());
  if (mode === "wait") {
    const ms = waitMs(requests, Date.now());
    if (ms > 0) {
      console.log(`--- request budget: waiting ${Math.ceil(ms / 1000)} s before ${suite ?? "the next suite"} for varlatchd's request window to have room`);
      await new Promise((r) => setTimeout(r, ms));
    }
  } else if (mode === "report") {
    const { refusals, busiest } = assess(requests);
    console.log(
      `--- request budget: ${requests.length} requests through nginx; varlatchd refused ${refusals.length} (429, outside the proxy probe). ` +
        `Context only: at most ${busiest.count} logged in one 61-second span` +
        (busiest.client ? ` (from ${busiest.client} from ${new Date(busiest.start).toISOString()}; whole seconds, at completion)` : "") +
        `, against varlatchd's budget of ${BUDGET} per ${WINDOW_MS / 1000} s.`,
    );
    for (const r of refusals.slice(0, 10)) {
      console.log(`FAIL  varlatchd answered 429 to ${r.method} ${r.path} from ${r.client} (logged ${new Date(r.at).toISOString()}): a limit was exceeded`);
    }
    if (refusals.length > 10) console.log(`FAIL  ... and ${refusals.length - 10} more 429s`);
    if (refusals.length > 0) process.exit(1);
  } else {
    console.error("Usage: ... | e2e-request-budget.mjs wait <suite> | report");
    process.exit(64);
  }
}
