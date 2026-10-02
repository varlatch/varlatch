// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { BUDGET, START_ALLOWANCE, WINDOW_MS, requestsIn, waitMs, windowsOf } from "../scripts/e2e-request-budget.mjs";

/** The e2e harness's scheduling against varlatchd's request window (600 per 60 s per client). */

const line = (client: string, time: string, path: string, status = 200) =>
  `${client} - - [${time} +0000] "GET ${path} HTTP/1.1" ${status} 12 "-" "node" "-"`;
const T0 = Date.UTC(2026, 9, 2, 19, 15, 0);

describe("requestsIn", () => {
  it("counts what nginx forwards to varlatchd's request window, with its time", () => {
    const log = [
      line("172.27.0.1", "02/Oct/2026:19:15:00", "/v1/organizations"),
      line("172.27.0.1", "02/Oct/2026:19:15:01", "/auth/varlatch-token", 401),
      line("172.27.0.1", "02/Oct/2026:19:15:02", "/enroll"),
      line("172.27.0.1", "02/Oct/2026:19:15:03", "/.well-known/jwks.json"),
      line("172.27.0.1", "02/Oct/2026:19:15:04", "/healthz"), // exempt from the window
      line("172.27.0.1", "02/Oct/2026:19:15:05", "/readyz"), // exempt
      line("127.0.0.1", "02/Oct/2026:19:15:06", "/varlatch-config.js"), // static, never reaches varlatchd
      line("172.27.0.1", "02/Oct/2026:19:15:07", "/convex/version"), // Convex, not varlatchd
      line("172.27.0.1", "02/Oct/2026:19:15:08", "/authorize"), // not under /auth/
      "2026/10/02 19:15:09 [error] 29#29: *1 connect() failed",
    ].join("\n");
    expect(requestsIn(log)).toEqual([
      { client: "172.27.0.1", at: T0 },
      { client: "172.27.0.1", at: T0 + 1000 },
      { client: "172.27.0.1", at: T0 + 2000 },
      { client: "172.27.0.1", at: T0 + 3000 },
    ]);
  });

  it("applies the log's time zone", () => {
    const [r] = requestsIn(`172.27.0.1 - - [02/Oct/2026:21:15:00 +0200] "GET /v1/meta HTTP/1.1" 200 1 "-" "node" "-"`);
    expect(r!.at).toBe(T0);
  });
});

describe("windowsOf", () => {
  it("replays varlatchd's fixed windows per client: a new one opens at the first request after the last ended", () => {
    const requests = [
      ...Array.from({ length: BUDGET + 1 }, (_, i) => ({ client: "a", at: T0 + i * 50 })), // 601 in about 30 s
      { client: "a", at: T0 + WINDOW_MS }, // exactly one window later: a new window
      { client: "b", at: T0 + 10 },
    ].sort((x, y) => x.at - y.at); // as requestsIn returns them
    expect(windowsOf(requests).map((w) => [w.client, w.count])).toEqual([["a", BUDGET + 1], ["b", 1], ["a", 1]]);
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
