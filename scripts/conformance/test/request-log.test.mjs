// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import { START_ALLOWANCE, WINDOW_MS, assess, declared429, expectedRefusal, waitMs } from "../lib/request-log.mjs";
import { requestsFromNginxLog } from "../targets/nginx-log.mjs";

const line = (client, time, path, status = 200, method = "GET", forwardedFor = "-") =>
  `${client} - - [${time} +0000] "${method} ${path} HTTP/1.1" ${status} 12 "-" "node" "${forwardedFor}"`;
const T0 = Date.UTC(2026, 9, 2, 19, 15, 0);

test("nginx: the requests varlatchd's window saw, with client, completion second, method, path, status, forwarded-for", () => {
  const log = [
    line("172.27.0.1", "02/Oct/2026:19:15:00", "/v1/organizations"),
    line("172.27.0.1", "02/Oct/2026:19:15:01", "/auth/varlatch-token", 401, "POST"),
    line("172.27.0.1", "02/Oct/2026:19:15:02", "/enroll"),
    line("172.27.0.1", "02/Oct/2026:19:15:03", "/.well-known/jwks.json"),
    line("172.27.0.1", "02/Oct/2026:19:15:04", "/healthz"), // left out of the window
    line("172.27.0.1", "02/Oct/2026:19:15:05", "/readyz"),
    line("127.0.0.1", "02/Oct/2026:19:15:06", "/varlatch-config.js"), // static, never reaches varlatchd
    line("172.27.0.1", "02/Oct/2026:19:15:07", "/convex/version"), // Convex, not varlatchd
    line("172.27.0.1", "02/Oct/2026:19:15:08", "/authorize"), // not under /auth/
    "2026/10/02 19:15:09 [error] 29#29: *1 connect() failed",
  ].join("\n");
  const records = requestsFromNginxLog(log);
  assert.deepEqual(records.map((r) => r.completedAt), [T0, T0 + 1000, T0 + 2000, T0 + 3000]);
  assert.deepEqual(records[1], { client: "172.27.0.1", method: "POST", path: "/auth/varlatch-token", status: 401, completedAt: T0 + 1000, resolutionMs: 1000, forwardedFor: "-" });
});

test("nginx: the log's time zone applies", () => {
  const [r] = requestsFromNginxLog(`172.27.0.1 - - [02/Oct/2026:21:15:00 +0200] "GET /v1/meta HTTP/1.1" 200 1 "-" "node" "-"`);
  assert.equal(r.completedAt, T0);
  const [w] = requestsFromNginxLog(`172.27.0.1 - - [02/Oct/2026:14:45:00 -0430] "GET /v1/meta HTTP/1.1" 200 1 "-" "node" "-"`);
  assert.equal(w.completedAt, T0);
});

const PROBE = { start: T0 - 500, end: T0 + 5_000 };
const record = (fields) => ({ client: "172.27.0.1", method: "GET", path: "/v1/meta", status: 200, completedAt: T0, resolutionMs: 1000, forwardedFor: "-", ...fields });
const probe429 = record({ method: "POST", path: "/v1/auth/device", status: 429, forwardedFor: "198.18.0.11" });

test("any 429 fails the run, wherever it fell", () => {
  const records = [record({}), record({ completedAt: T0 + 60_000, status: 429 })];
  assert.equal(assess(records, { windows: { "proxy-probe": [PROBE] } }).refusals.length, 1);
});

test("the proxy probe's pending-cap answers are expected, only from that suite and on that path", () => {
  assert.equal(assess([probe429], { windows: { "proxy-probe": [PROBE] } }).refusals.length, 0);
  // Not the probe: another path, another method, an unforged or other forwarded-for.
  for (const other of [
    { ...probe429, path: "/v1/auth/device/token" },
    { ...probe429, method: "GET" },
    { ...probe429, forwardedFor: "-" },
    { ...probe429, forwardedFor: "10.0.0.1" },
  ]) {
    assert.equal(assess([other], { windows: { "proxy-probe": [PROBE] } }).refusals.length, 1, JSON.stringify(other));
  }
  // The same request outside the probe's run, or with no probe run at all.
  assert.equal(assess([{ ...probe429, completedAt: T0 + 10_000 }], { windows: { "proxy-probe": [PROBE] } }).refusals.length, 1);
  assert.equal(assess([{ ...probe429, completedAt: T0 - 2_000 }], { windows: { "proxy-probe": [PROBE] } }).refusals.length, 1);
  assert.equal(assess([probe429], { windows: { device: [PROBE] } }).refusals.length, 1);
  assert.equal(assess([probe429]).refusals.length, 1);
});

test("a whole-second log time counts in a window that starts inside that second", () => {
  // Logged at T0 (completed somewhere in [T0, T0 + 1 s)); the probe started at T0 + 400 ms.
  assert.equal(expectedRefusal(probe429, { "proxy-probe": [{ start: T0 + 400, end: T0 + 3_000 }] }), true);
  assert.equal(expectedRefusal(probe429, { "proxy-probe": [{ start: T0 + 1_000, end: T0 + 3_000 }] }), false);
});

test("a target that does not record the forwarded header: the probe's 429 is not excused", () => {
  const { forwardedFor, ...bare } = probe429;
  void forwardedFor;
  assert.equal(assess([bare], { windows: { "proxy-probe": [PROBE] } }).refusals.length, 1);
  assert.equal(assess([{ ...bare, path: "/v1/meta" }], { windows: { "proxy-probe": [PROBE] } }).refusals.length, 1);
});

test("the busiest window of logged times is reported as context", () => {
  const records = Array.from({ length: 70 }, (_, i) => record({ completedAt: T0 + (i % 60) * 1000 }));
  assert.deepEqual(assess(records).busiest, { client: "172.27.0.1", start: T0, count: 70 });
});

test("pacing: no wait while the trailing window holds no more than the start allowance", () => {
  const now = T0 + 120_000;
  assert.equal(waitMs(Array.from({ length: START_ALLOWANCE }, (_, i) => record({ completedAt: now - 1000 - i })), now), 0);
  assert.equal(waitMs([record({ completedAt: now - 70_000 })], now), 0);
  assert.equal(waitMs([], now), 0);
});

test("pacing: waits until enough trailing requests have aged out, per client", () => {
  const now = T0 + 120_000;
  // 300 requests, one every 100 ms, ending 1 s ago: 200 must age out of the 61 s span.
  const records = Array.from({ length: 300 }, (_, i) => record({ client: "a", completedAt: now - 31_000 + i * 100 }));
  const wait = waitMs(records, now);
  const span = WINDOW_MS + 1000;
  assert.ok(records.filter((r) => r.completedAt + span > now + wait).length <= START_ALLOWANCE);
  assert.ok(records.filter((r) => r.completedAt + span > now + wait - 100).length > START_ALLOWANCE);
  // Another client's quiet history does not shorten it.
  assert.equal(waitMs([...records, record({ client: "b", completedAt: now - 500 })], now), wait);
});

test("a declared 429 excuses exactly one refusal of its request, in its window, for the suite allowed to declare it", () => {
  const token429 = (completedAt) => record({ method: "POST", path: "/v1/auth/device/token", status: 429, completedAt, resolutionMs: 0 });
  const { declarations, errors } = declared429(
    "cli-handover",
    `PASS  [x] y\nEXPECTED-429  [cli-handover.device-ts-slow-down-go-keeps] POST /v1/auth/device/token ${T0} ${T0 + 3_000}\n`,
  );
  assert.deepEqual(errors, []);
  assert.equal(declarations.length, 1);
  // The one poll it declared.
  assert.equal(assess([token429(T0 + 1_000)], { declared: declarations }).refusals.length, 0);
  // A second 429 in the same window is a refusal: one each.
  assert.equal(assess([token429(T0 + 1_000), token429(T0 + 2_000)], { declared: declarations }).refusals.length, 1);
  // Outside its window, or another request, or none declared: a refusal.
  assert.equal(assess([token429(T0 + 10_000)], { declared: declarations }).refusals.length, 1);
  assert.equal(assess([record({ method: "POST", path: "/v1/auth/device", status: 429, completedAt: T0 + 1_000, resolutionMs: 0 })], { declared: declarations }).refusals.length, 1);
  assert.equal(assess([token429(T0 + 1_000)]).refusals.length, 1);
  // Only cli-handover may declare, and only that request; a malformed line fails.
  assert.match(declared429("device", `EXPECTED-429  [device.x] POST /v1/auth/device/token ${T0} ${T0 + 1}`).errors[0], /device may not declare/);
  assert.match(declared429("cli-handover", `EXPECTED-429  [cli-handover.x] POST /v1/auth/device ${T0} ${T0 + 1}`).errors[0], /may not declare a 429 for POST \/v1\/auth\/device$/);
  assert.match(declared429("cli-handover", "EXPECTED-429 somewhere").errors[0], /malformed/);
});
