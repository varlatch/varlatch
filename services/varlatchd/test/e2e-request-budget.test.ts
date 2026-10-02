// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AppCtx } from "../src/domain/ctx.js";
import { buildApp } from "../src/http/app.js";
import { assess, requestsIn } from "../../../apps/web/scripts/e2e-request-budget.mjs";

/**
 * The e2e harness's budget report (apps/web/scripts/e2e-request-budget.mjs)
 * against varlatchd's production request window, unchanged: 600 requests
 * per client per 60 s, the window opening at the first request's
 * millisecond. nginx logs whole seconds, so the report must rest on what
 * varlatchd answered, not on windows reconstructed from the log.
 */

const ctx = { db: { query: async () => ({ rows: [] }) }, rootKek: Buffer.alloc(32, 1) } as unknown as AppCtx;
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const pad = (n: number) => String(n).padStart(2, "0");

/** nginx's access-log line for a request at `at` (logged in whole seconds). */
function logged(at: number, status: number): string {
  const d = new Date(at);
  const time = `${pad(d.getUTCDate())}/${MONTHS[d.getUTCMonth()]}/${d.getUTCFullYear()}:${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
  return `172.27.0.1 - - [${time} +0000] "GET /v1/meta HTTP/1.1" ${status} 12 "-" "node" "-"`;
}

/** Send /v1/meta at each time through the production app; the access log nginx would write. */
async function replay(times: number[]): Promise<{ statuses: number[]; log: string }> {
  const app = buildApp(ctx);
  const statuses: number[] = [];
  const lines: string[] = [];
  for (const at of times) {
    vi.setSystemTime(at);
    const res = await app.request("/v1/meta");
    statuses.push(res.status);
    lines.push(logged(at, res.status));
  }
  return { statuses, log: lines.join("\n") };
}

const at = (h: number, m: number, s: number, ms: number) => Date.UTC(2026, 9, 2, h, m, s, ms);

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
});
afterEach(() => {
  vi.useRealTimers();
});

describe("the e2e budget report against the production request window", () => {
  it("fails a run in which one real window took 601 requests, though whole-second log times would split it in two", async () => {
    // Window opens at 19:15:00.900; 599 more at 19:15:59.900; one at 19:16:00.100, 59.2 s after the window opened.
    const times = [at(19, 15, 0, 900), ...Array.from({ length: 599 }, () => at(19, 15, 59, 900)), at(19, 16, 0, 100)];
    const { statuses, log } = await replay(times);
    expect(statuses.filter((s) => s === 200)).toHaveLength(600);
    expect(statuses.at(-1)).toBe(429); // the production limiter refused the 601st
    // The log shows 19:15:00, 19:15:59, 19:16:00: windows replayed from it would read [600, 1].
    expect(log.split("\n").at(-1)).toContain("[02/Oct/2026:19:16:00 +0000]");
    const { refusals } = assess(requestsIn(log));
    expect(refusals).toHaveLength(1);
    expect(refusals[0]).toMatchObject({ path: "/v1/meta", status: 429 });
  });

  it("passes clearly separated windows in which varlatchd refused nothing (control)", async () => {
    const times = [
      ...Array.from({ length: 600 }, (_, i) => at(19, 15, 0, 100 + i * 50)), // 600 within 30 s
      ...Array.from({ length: 600 }, (_, i) => at(19, 16, 30, i * 50)), // a new window, 90 s after the first opened
    ];
    const { statuses, log } = await replay(times);
    expect(statuses.every((s) => s === 200)).toBe(true);
    expect(assess(requestsIn(log)).refusals).toEqual([]);
  });
});
