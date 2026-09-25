// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { onlyLoopback, startNetnsWatchdog } from "../src/netns-watchdog.js";

const lo = { address: "127.0.0.1", netmask: "255.0.0.0", family: "IPv4" as const, mac: "00:00:00:00:00:00", internal: true, cidr: "127.0.0.1/8" };
const eth = { ...lo, address: "172.18.0.5", internal: false, cidr: "172.18.0.5/16" };

describe("network namespace watchdog", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("recognises a namespace with only loopback left", () => {
    expect(onlyLoopback({ lo: [lo] })).toBe(true);
    expect(onlyLoopback({ lo: [lo], eth0: [eth] })).toBe(false);
  });

  it("exits after consecutive loopback-only checks, not on a blip", () => {
    const exit = vi.fn();
    let stranded = true;
    const stop = startNetnsWatchdog({ intervalMs: 1000, strikes: 3, check: () => stranded, exit, log: () => {} });
    vi.advanceTimersByTime(2000);
    stranded = false; // recovered: the count starts over
    vi.advanceTimersByTime(1000);
    stranded = true;
    vi.advanceTimersByTime(2000);
    expect(exit).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1000);
    expect(exit).toHaveBeenCalledExactlyOnceWith(1);
    stop();
  });
});
