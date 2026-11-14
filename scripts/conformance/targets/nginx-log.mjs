// SPDX-License-Identifier: Apache-2.0
/**
 * The TypeScript stack's request log: the dashboard's nginx access log,
 * reduced to the requests nginx passed to varlatchd's request window.
 *
 * nginx's default "main" format is
 *   $remote_addr - $remote_user [$time_local] "$request" $status
 *   $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for"
 * and $time_local is written when the response completes, in whole seconds.
 * So each record has `completedAt` (the start of its logged second),
 * `resolutionMs` 1000, and no arrival time.
 */

const MONTH = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
const ACCESS =
  /^(\S+) - \S+ \[(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})\] "(\S+) (\S+)[^"]*" (\d{3}) .*"([^"]*)"\s*$/;
// What nginx forwards to varlatchd, minus the paths varlatchd's request
// window leaves out (/healthz, /readyz). Static files and /convex never
// reach varlatchd.
const TO_VARLATCHD = /^\/(auth|v1|enroll|\.well-known)(?:[/?]|$)/;

/** Request-log records from nginx's log text; other lines (errors, other paths) are left out. */
export function requestsFromNginxLog(text) {
  const records = [];
  for (const line of text.split("\n")) {
    const m = ACCESS.exec(line);
    if (!m) continue;
    const [, client, day, month, year, hour, minute, second, sign, zoneHours, zoneMinutes, method, path, status, forwardedFor] = m;
    if (!(month in MONTH) || !TO_VARLATCHD.test(path)) continue;
    const zone = (sign === "-" ? -1 : 1) * (Number(zoneHours) * 60 + Number(zoneMinutes)) * 60_000;
    const completedAt = Date.UTC(Number(year), MONTH[month], Number(day), Number(hour), Number(minute), Number(second)) - zone;
    records.push({ client, method, path, status: Number(status), completedAt, resolutionMs: 1000, forwardedFor });
  }
  return records.sort((a, b) => a.completedAt - b.completedAt);
}
