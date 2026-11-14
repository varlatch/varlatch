// SPDX-License-Identifier: Apache-2.0
/**
 * The run against the server's real request budget, from the target's
 * `request-log` operation (one record per request the server answered).
 *
 * The server allows each client 600 requests per 60-second window, and that
 * production limit stays as it is. Every suite reaches the server from the
 * same host address, so they share one budget. The runner therefore paces:
 * before each suite it waits until the host's requests in the trailing
 * window are few enough that whatever window the server has open has room
 * for the next suite (`waitMs`). At the end it checks the one thing that
 * proves the budget held: the server refused nothing (`assess`). A 429 is
 * how the window refuses, so any 429 fails the run, except the proxy
 * probe's expected pending-cap answers, and only from that suite, on that
 * path. A suite that needs more than one window is split; the limit is never
 * raised.
 *
 * A record: { client, method, path, status, completedAt, arrivedAt?,
 * resolutionMs?, forwardedFor? }. Times are milliseconds since the epoch.
 * `resolutionMs` is how coarse the target's clock is (nginx logs whole
 * seconds: 1000); `arrivedAt` may be missing when the target logs only
 * completion (nginx does). Counts per window from such a log are estimates,
 * so the busiest span is reported as context only.
 */

export const BUDGET = 600;
export const WINDOW_MS = 60_000;
/** Requests that may still count in the server's open window when a suite starts. */
export const START_ALLOWANCE = 100;

/**
 * The 429s a run may see. The proxy probe forges client addresses in
 * X-Forwarded-For and meets the per-client pending cap on purpose; its own
 * checks verify those answers are the cap. Where a target records the
 * forwarded header, it must be one of the probe's forged addresses.
 */
export const EXPECTED_429 = [
  { suite: "proxy-probe", method: "POST", path: "/v1/auth/device", forwardedFor: /^198\.18\.0\.\d+$/ },
];

const resolutionOf = (r) => Math.max(r.resolutionMs ?? 0, 0);

/** Whether a record falls in a time window ({ start, end }), allowing for its clock's resolution. */
export function within(record, window) {
  const resolution = Math.max(resolutionOf(record), 1);
  return record.completedAt + resolution > window.start && record.completedAt <= window.end;
}

/**
 * Whether a 429 is one a rule expects: the rule's method and exact path,
 * logged while the rule's suite ran (`windows[suite]` lists when it ran),
 * and, when the rule names a forwarded header, a record that carries one
 * matching it. A record without the header never matches such a rule: missing
 * evidence fails closed.
 */
export function expectedRefusal(record, windows, rules = EXPECTED_429) {
  return rules.some(
    (rule) =>
      record.method === rule.method &&
      record.path === rule.path &&
      (windows[rule.suite] ?? []).some((w) => within(record, w)) &&
      (!rule.forwardedFor || (typeof record.forwardedFor === "string" && rule.forwardedFor.test(record.forwardedFor))),
  );
}

/**
 * What the request log establishes: `refusals`, every 429 no rule expects
 * (any one fails the run); and, as context only, the most requests from one
 * client whose completion times fall in one window plus the clock's
 * resolution.
 */
export function assess(records, { windows = {}, rules = EXPECTED_429 } = {}) {
  const refusals = records.filter((r) => r.status === 429 && !expectedRefusal(r, windows, rules));
  const resolution = records.reduce((m, r) => Math.max(m, resolutionOf(r)), 0);
  const span = WINDOW_MS + resolution;
  let busiest = { client: null, start: null, count: 0 };
  for (const [client, times] of timesByClient(records)) {
    for (let first = 0, last = 0; last < times.length; last++) {
      while (times[last] - times[first] >= span) first++;
      if (last - first + 1 > busiest.count) busiest = { client, start: times[first], count: last - first + 1 };
    }
  }
  return { refusals, busiest };
}

/**
 * How long to wait, from `now`, until every client has at most `allowance`
 * requests completed in the trailing window plus the clock's resolution.
 * Whatever window the server has open started less than a window ago, and a
 * request completes after it arrives, so every request counted in that
 * window is in the trailing span: after the wait the window has room for at
 * least BUDGET - allowance more. (Between suites no request is in flight.)
 */
export function waitMs(records, now, allowance = START_ALLOWANCE) {
  const resolution = records.reduce((m, r) => Math.max(m, resolutionOf(r)), 0);
  const span = WINDOW_MS + resolution;
  let wait = 0;
  for (const times of timesByClient(records.filter((r) => r.completedAt + span > now)).values()) {
    if (times.length <= allowance) continue;
    // The (n - allowance)th oldest request must age out of the span.
    wait = Math.max(wait, times[times.length - allowance - 1] + span - now);
  }
  return Math.max(0, wait);
}

function timesByClient(records) {
  const byClient = new Map();
  for (const r of records) {
    const times = byClient.get(r.client) ?? [];
    times.push(r.completedAt);
    byClient.set(r.client, times);
  }
  for (const times of byClient.values()) times.sort((a, b) => a - b);
  return byClient;
}
