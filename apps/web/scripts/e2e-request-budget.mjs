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
 * varlatchd has open has room for the next suite, and at the end it replays
 * varlatchd's windows from nginx's access log to show the busiest window,
 * failing when one went over the budget (the suite in it must slow down or
 * split: the limit is not the thing to change).
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
// nginx's default "main" format: $remote_addr - $remote_user [$time_local] "$request" $status ...
const LINE = /^(\S+) - \S+ \[(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})\] "(\S+) (\S+)[^"]*" (\d{3}) /;
// What nginx forwards to varlatchd, minus the paths its request window exempts.
const PROXIED = /^\/(auth|v1|enroll|\.well-known)(?:[/?]|$)/;

/** The requests nginx forwarded to varlatchd's request window: client address and time (ms). */
export function requestsIn(log) {
  const requests = [];
  for (const line of log.split("\n")) {
    const m = LINE.exec(line);
    if (!m || !PROXIED.test(m[10])) continue;
    const [, client, day, mon, year, h, min, sec, zone] = m;
    const offset = (zone.startsWith("-") ? -1 : 1) * (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(3))) * 60_000;
    const at = Date.UTC(Number(year), MONTHS[mon], Number(day), Number(h), Number(min), Number(sec)) - offset;
    requests.push({ client, at });
  }
  return requests.sort((a, b) => a.at - b.at);
}

/** varlatchd's fixed windows, replayed per client: each window's start and request count. */
export function windowsOf(requests) {
  const open = new Map();
  const windows = [];
  for (const { client, at } of requests) {
    let window = open.get(client);
    if (!window || at >= window.start + WINDOW_MS) {
      window = { client, start: at, count: 0 };
      open.set(client, window);
      windows.push(window);
    }
    window.count++;
  }
  return windows;
}

/**
 * How long to wait, from `now`, until every client has at most `allowance`
 * requests in the trailing window plus the log's resolution. Whatever
 * window varlatchd has open started less than a window ago, so it holds no
 * more requests than that trailing span: after the wait it has room for
 * BUDGET - allowance more.
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
    const windows = windowsOf(requests);
    const busiest = windows.reduce((a, w) => (w.count > (a?.count ?? -1) ? w : a), null);
    const over = windows.filter((w) => w.count > BUDGET);
    console.log(
      `--- request budget: ${requests.length} requests through nginx; busiest window ` +
        (busiest ? `${busiest.count} requests from ${busiest.client} at ${new Date(busiest.start).toISOString()}` : "none") +
        ` (budget ${BUDGET} per ${WINDOW_MS / 1000} s)`,
    );
    for (const w of over) console.log(`FAIL  ${w.count} requests from ${w.client} in the window opened at ${new Date(w.start).toISOString()}: over varlatchd's budget`);
    if (over.length > 0) process.exit(1);
  } else {
    console.error("Usage: ... | e2e-request-budget.mjs wait <suite> | report");
    process.exit(64);
  }
}
