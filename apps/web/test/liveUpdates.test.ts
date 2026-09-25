// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GRACE_MS, LiveUpdatesController, POLL_MAX_MS, POLL_START_MS, pollBase, pollDelay, type LiveStatus } from "../src/lib/liveUpdates";

describe("poll schedule (ADR-0035 D10)", () => {
  it("starts at 15 s and backs off to 60 s", () => {
    expect([0, 1, 2, 3, 10].map(pollBase)).toEqual([POLL_START_MS, 30_000, POLL_MAX_MS, POLL_MAX_MS, POLL_MAX_MS]);
  });
  it("jitters within ±20%", () => {
    expect(pollDelay(0, () => 0)).toBe(12_000);
    expect(pollDelay(0, () => 1)).toBe(18_000);
    expect(pollDelay(5, () => 0.5)).toBe(POLL_MAX_MS);
  });
});

describe("LiveUpdatesController", () => {
  let refresh: ReturnType<typeof vi.fn>;
  let statuses: [LiveStatus, number | null][];
  let hidden: boolean;
  let controller: LiveUpdatesController;
  beforeEach(() => {
    vi.useFakeTimers();
    refresh = vi.fn();
    statuses = [];
    hidden = false;
    controller = new LiveUpdatesController({
      refresh,
      isHidden: () => hidden,
      now: () => Date.now(),
      setTimer: (fn, ms) => setTimeout(fn, ms),
      clearTimer: (h) => clearTimeout(h as ReturnType<typeof setTimeout>),
      onStatus: (s, every) => statuses.push([s, every]),
      random: () => 0.5, // no jitter
    });
  });
  afterEach(() => {
    controller.dispose();
    vi.useRealTimers();
  });
  const last = () => statuses[statuses.length - 1];

  it("says nothing and polls nothing while connected", () => {
    controller.connection(false);
    controller.connection(true);
    vi.advanceTimersByTime(10 * POLL_MAX_MS);
    expect(last()).toEqual(["live", null]);
    expect(refresh).not.toHaveBeenCalled();
  });

  it("shows the outage only after the grace period, then polls with backoff", () => {
    controller.connection(true);
    controller.connection(false);
    vi.advanceTimersByTime(GRACE_MS - 1);
    expect(last()![0]).toBe("live");
    vi.advanceTimersByTime(1);
    expect(last()).toEqual(["reconnecting", POLL_START_MS]);
    vi.advanceTimersByTime(POLL_START_MS);
    expect(refresh).toHaveBeenLastCalledWith("active");
    expect(last()).toEqual(["reconnecting", 30_000]);
    vi.advanceTimersByTime(30_000);
    vi.advanceTimersByTime(POLL_MAX_MS);
    vi.advanceTimersByTime(POLL_MAX_MS);
    expect(refresh).toHaveBeenCalledTimes(4);
    expect(last()).toEqual(["reconnecting", POLL_MAX_MS]);
  });

  it("refreshes everything once on reconnect and stops polling", () => {
    controller.connection(true);
    controller.connection(false);
    vi.advanceTimersByTime(GRACE_MS + POLL_START_MS);
    refresh.mockClear();
    controller.connection(true);
    expect(refresh).toHaveBeenCalledExactlyOnceWith("all");
    expect(last()).toEqual(["live", null]);
    vi.advanceTimersByTime(10 * POLL_MAX_MS);
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it("catches up after a short drop within the grace period too", () => {
    controller.connection(true);
    controller.connection(false);
    vi.advanceTimersByTime(1_000);
    controller.connection(true);
    expect(refresh).toHaveBeenCalledExactlyOnceWith("all");
    expect(statuses.map((s) => s[0])).not.toContain("reconnecting");
  });

  it("does not refresh on the first connection", () => {
    controller.connection(false);
    controller.connection(true);
    expect(refresh).not.toHaveBeenCalled();
  });

  it("does not poll a hidden tab, and catches up when it is shown", () => {
    controller.connection(true);
    controller.connection(false);
    hidden = true;
    vi.advanceTimersByTime(GRACE_MS + POLL_START_MS + 30_000);
    expect(refresh).not.toHaveBeenCalled();
    hidden = false;
    controller.visibility();
    expect(refresh).toHaveBeenCalledExactlyOnceWith("active");
    controller.visibility(); // flapping visibility does not multiply requests
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it("reports an Application Plane that never connected as unavailable", () => {
    controller.connection(false);
    vi.advanceTimersByTime(GRACE_MS);
    expect(last()).toEqual(["unavailable", POLL_START_MS]);
    vi.advanceTimersByTime(POLL_START_MS);
    expect(refresh).toHaveBeenCalledWith("active");
  });
});
