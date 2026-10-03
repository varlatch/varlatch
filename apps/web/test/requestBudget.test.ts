// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { START_ALLOWANCE, WINDOW_MS, assess, requestsIn, waitMs } from "../scripts/e2e-request-budget.mjs";

/**
 * The e2e harness's scheduling against varlatchd's request window (600 per
 * 60 s per client). The regression against the production limiter itself is
 * in services/varlatchd/test/e2e-request-budget.test.ts.
 */

const line = (client: string, time: string, path: string, status = 200, method = "GET", forwardedFor = "-") =>
  `${client} - - [${time} +0000] "${method} ${path} HTTP/1.1" ${status} 12 "-" "node" "${forwardedFor}"`;
const T0 = Date.UTC(2026, 9, 2, 19, 15, 0);

describe("requestsIn", () => {
  it("reads what nginx forwards to varlatchd's request window: client, logged time, method, path, status, forwarded-for", () => {
    const log = [
      line("172.27.0.1", "02/Oct/2026:19:15:00", "/v1/organizations"),
      line("172.27.0.1", "02/Oct/2026:19:15:01", "/auth/varlatch-token", 401, "POST"),
      line("172.27.0.1", "02/Oct/2026:19:15:02", "/enroll"),
      line("172.27.0.1", "02/Oct/2026:19:15:03", "/.well-known/jwks.json"),
      line("172.27.0.1", "02/Oct/2026:19:15:04", "/healthz"), // exempt from the window
      line("172.27.0.1", "02/Oct/2026:19:15:05", "/readyz"), // exempt
      line("127.0.0.1", "02/Oct/2026:19:15:06", "/varlatch-config.js"), // static, never reaches varlatchd
      line("172.27.0.1", "02/Oct/2026:19:15:07", "/convex/version"), // Convex, not varlatchd
      line("172.27.0.1", "02/Oct/2026:19:15:08", "/authorize"), // not under /auth/
      "2026/10/02 19:15:09 [error] 29#29: *1 connect() failed",
    ].join("\n");
    const requests = requestsIn(log);
    expect(requests.map((r: { at: number }) => r.at)).toEqual([T0, T0 + 1000, T0 + 2000, T0 + 3000]);
    expect(requests[1]).toMatchObject({ client: "172.27.0.1", method: "POST", path: "/auth/varlatch-token", status: 401, forwardedFor: "-" });
  });

  it("applies the log's time zone", () => {
    const [r] = requestsIn(`172.27.0.1 - - [02/Oct/2026:21:15:00 +0200] "GET /v1/meta HTTP/1.1" 200 1 "-" "node" "-"`);
    expect(r!.at).toBe(T0);
  });
});

describe("assess", () => {
  it("fails on any 429 varlatchd answered, wherever it fell", () => {
    const log = [line("172.27.0.1", "02/Oct/2026:19:15:00", "/v1/meta"), line("172.27.0.1", "02/Oct/2026:19:16:00", "/v1/meta", 429)].join("\n");
    expect(assess(requestsIn(log)).refusals).toHaveLength(1);
  });

  it("leaves the proxy probe's pending-cap answers to the probe's own check, and only those", () => {
    const probe = line("172.27.0.1", "02/Oct/2026:19:15:00", "/v1/auth/device", 429, "POST", "198.18.0.11");
    expect(assess(requestsIn(probe)).refusals).toHaveLength(0);
    // Not the probe: another path, another method, an unforged or other forwarded-for.
    for (const other of [
      line("172.27.0.1", "02/Oct/2026:19:15:00", "/v1/auth/device/token", 429, "POST", "198.18.0.11"),
      line("172.27.0.1", "02/Oct/2026:19:15:00", "/v1/auth/device", 429, "GET", "198.18.0.11"),
      line("172.27.0.1", "02/Oct/2026:19:15:00", "/v1/auth/device", 429, "POST"),
      line("172.27.0.1", "02/Oct/2026:19:15:00", "/v1/auth/device", 429, "POST", "10.0.0.1"),
    ]) {
      expect(assess(requestsIn(other)).refusals, other).toHaveLength(1);
    }
  });

  it("reports the busiest 61-second span of logged times as context", () => {
    const log = Array.from({ length: 70 }, (_, i) => line("172.27.0.1", `02/Oct/2026:19:15:${String(i % 60).padStart(2, "0")}`, "/v1/meta")).join("\n");
    expect(assess(requestsIn(log)).busiest).toMatchObject({ client: "172.27.0.1", count: 70 });
  });
});

describe("waitMs", () => {
  it("does not wait when the trailing window holds no more than the start allowance", () => {
    const now = T0 + 120_000;
    expect(waitMs(Array.from({ length: START_ALLOWANCE }, (_, i) => ({ client: "a", at: now - 1000 - i })), now)).toBe(0);
    expect(waitMs([{ client: "a", at: now - 70_000 }], now)).toBe(0);
  });

  it("waits until enough of the trailing requests have aged out, per client", () => {
    const now = T0 + 120_000;
    // 300 requests, one every 100 ms, ending 1 s ago: 200 must age out of the 61 s span.
    const requests = Array.from({ length: 300 }, (_, i) => ({ client: "a", at: now - 31_000 + i * 100 }));
    const wait = waitMs(requests, now);
    const after = requests.filter((r) => r.at + WINDOW_MS + 1000 > now + wait);
    expect(after.length).toBeLessThanOrEqual(START_ALLOWANCE);
    expect(requests.filter((r) => r.at + WINDOW_MS + 1000 > now + wait - 100).length).toBeGreaterThan(START_ALLOWANCE);
    // Another client's quiet history does not shorten it.
    expect(waitMs([...requests, { client: "b", at: now - 500 }], now)).toBe(wait);
  });
});
