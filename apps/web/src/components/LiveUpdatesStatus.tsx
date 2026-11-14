// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from "react";
import { useConvex } from "convex/react";
import { useQueryClient } from "@tanstack/react-query";
import { LiveUpdatesController, type LiveStatus } from "../lib/liveUpdates";

/**
 * Mounted once under the Convex and React Query providers: drives degraded
 * realtime (ADR-0035 D10) and shows a quiet indicator while live updates are
 * down. Nothing is shown while they work.
 */
export function LiveUpdatesStatus() {
  const convex = useConvex();
  return <Status connected={() => convex.connectionState().isWebSocketConnected} subscribe={(on) => convex.subscribeToConnectionState((s) => on(s.isWebSocketConnected))} />;
}

const NEVER_CONNECTED = { connected: () => false, subscribe: () => () => {} };

/**
 * The same indicator on a server without live updates yet (lib/backend.ts:
 * the Go server until it serves events): never connected, so it says live
 * updates are unavailable and keeps what is on screen fresh by polling.
 */
export function RealtimeUnavailable() {
  return <Status {...NEVER_CONNECTED} />;
}

function Status({ connected, subscribe }: { connected: () => boolean; subscribe: (on: (connected: boolean) => void) => () => void }) {
  const qc = useQueryClient();
  const [state, setState] = useState<{ status: LiveStatus; pollEveryMs: number | null }>({ status: "connecting", pollEveryMs: null });

  useEffect(() => {
    const controller = new LiveUpdatesController({
      // Polling touches only the queries on screen; the reconnect catch-up
      // also marks the rest stale so they refetch when next shown.
      refresh: (scope) => void (scope === "all" ? qc.invalidateQueries() : qc.refetchQueries({ type: "active" })),
      isHidden: () => document.visibilityState === "hidden",
      now: () => Date.now(),
      setTimer: (fn, ms) => window.setTimeout(fn, ms),
      clearTimer: (handle) => window.clearTimeout(handle as number),
      onStatus: (status, pollEveryMs) => setState({ status, pollEveryMs }),
    });
    controller.connection(connected());
    const unsubscribe = subscribe((c) => controller.connection(c));
    const onVisibility = () => controller.visibility();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      unsubscribe();
      document.removeEventListener("visibilitychange", onVisibility);
      controller.dispose();
    };
    // The source is fixed for the page's lifetime (lib/backend.ts).
  }, [qc]);

  if (state.status !== "reconnecting" && state.status !== "unavailable") return null;
  const every = state.pollEveryMs ? ` · refreshing every ${Math.round(state.pollEveryMs / 1000)} s` : "";
  return (
    <div
      role="status"
      aria-live="polite"
      data-testid="live-updates-status"
      data-status={state.status}
      className="fixed right-5 top-3 z-50 flex items-center gap-2 rounded-full border border-bd bg-raised px-3.5 py-1.5 text-xs text-muted shadow-pop"
      title="The dashboard stays correct: it reloads what is on screen from the server until live updates return."
    >
      <span className="size-2 animate-pulse rounded-full bg-warn" aria-hidden="true" />
      {state.status === "reconnecting" ? "Live updates reconnecting" : "Live updates unavailable"}
      {every}
    </div>
  );
}
