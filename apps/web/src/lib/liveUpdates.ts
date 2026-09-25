// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Degraded realtime (ADR-0035 D10). Convex is only an invalidation signal
 * over authoritative /v1 queries (realtime.ts). While its connection is down
 * those signals are lost, so the dashboard:
 *
 * - says so, after a short grace period (a normal page load connects well
 *   within it);
 * - polls the queries on screen instead, starting at 15 s and backing off to
 *   60 s with jitter, and not at all in a hidden tab — a Convex outage must
 *   never multiply load on varlatchd;
 * - refreshes every query once when the connection returns, because missed
 *   signals cannot be replayed. That includes short drops within the grace
 *   period.
 *
 * The controller is plain logic over injected timers so it can be tested
 * without a browser; LiveUpdatesStatus wires it to Convex and React Query.
 */

export const GRACE_MS = 4_000;
export const POLL_START_MS = 15_000;
export const POLL_MAX_MS = 60_000;
export const JITTER = 0.2;

/** connecting: not yet connected, within grace. unavailable: never connected. */
export type LiveStatus = "connecting" | "live" | "reconnecting" | "unavailable";

/** Base poll interval for the n-th poll (0-based), before jitter. */
export function pollBase(attempt: number): number {
  return Math.min(POLL_START_MS * 2 ** attempt, POLL_MAX_MS);
}

export function pollDelay(attempt: number, random: () => number = Math.random): number {
  return Math.round(pollBase(attempt) * (1 - JITTER + 2 * JITTER * random()));
}

export interface LiveUpdatesDeps {
  /** "active": refetch the queries on screen. "all": invalidate everything. */
  refresh(scope: "active" | "all"): void;
  isHidden(): boolean;
  now(): number;
  setTimer(fn: () => void, ms: number): unknown;
  clearTimer(handle: unknown): void;
  /** pollEveryMs: the current base interval while degraded, else null. */
  onStatus(status: LiveStatus, pollEveryMs: number | null): void;
  random?: () => number;
}

export class LiveUpdatesController {
  private connected = false;
  private everConnected = false;
  private degraded = false;
  private grace: unknown = null;
  private poll: unknown = null;
  private attempt = 0;
  private lastRefresh = 0;

  constructor(private readonly deps: LiveUpdatesDeps) {
    deps.onStatus("connecting", null);
  }

  /** Feed every connection state change (Convex's isWebSocketConnected). */
  connection(connected: boolean): void {
    const wasConnected = this.connected;
    this.connected = connected;
    if (connected) {
      this.clearGrace();
      if (this.degraded) {
        this.degraded = false;
        this.stopPolling();
        this.refresh("all");
      } else if (!wasConnected && this.everConnected) {
        // A drop within the grace period still loses signals.
        this.refresh("all");
      }
      this.everConnected = true;
      this.deps.onStatus("live", null);
      return;
    }
    if (this.degraded || this.grace !== null) return;
    this.grace = this.deps.setTimer(() => {
      this.grace = null;
      if (this.connected) return;
      this.degraded = true;
      this.attempt = 0;
      this.schedulePoll();
    }, GRACE_MS);
  }

  /** Call on visibilitychange: a tab coming back catches up at once. */
  visibility(): void {
    if (!this.degraded || this.deps.isHidden()) return;
    if (this.deps.now() - this.lastRefresh >= POLL_START_MS) this.refresh("active");
  }

  dispose(): void {
    this.clearGrace();
    this.stopPolling();
  }

  private schedulePoll(): void {
    this.deps.onStatus(this.everConnected ? "reconnecting" : "unavailable", pollBase(this.attempt));
    this.poll = this.deps.setTimer(() => {
      this.poll = null;
      if (!this.degraded) return;
      if (!this.deps.isHidden()) this.refresh("active");
      this.attempt += 1;
      this.schedulePoll();
    }, pollDelay(this.attempt, this.deps.random));
  }

  private refresh(scope: "active" | "all"): void {
    this.lastRefresh = this.deps.now();
    this.deps.refresh(scope);
  }

  private clearGrace(): void {
    if (this.grace !== null) this.deps.clearTimer(this.grace);
    this.grace = null;
  }

  private stopPolling(): void {
    if (this.poll !== null) this.deps.clearTimer(this.poll);
    this.poll = null;
  }
}
