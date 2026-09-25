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
    controller.connection(convex.connectionState().isWebSocketConnected);
    const unsubscribe = convex.subscribeToConnectionState((s) => controller.connection(s.isWebSocketConnected));
    const onVisibility = () => controller.visibility();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      unsubscribe();
      document.removeEventListener("visibilitychange", onVisibility);
      controller.dispose();
    };
  }, [convex, qc]);

  if (state.status !== "reconnecting" && state.status !== "unavailable") return null;
  const every = state.pollEveryMs ? ` · refreshing every ${Math.round(state.pollEveryMs / 1000)} s` : "";
  return (
    <div
      role="status"
      aria-live="polite"
      data-testid="live-updates-status"
      data-status={state.status}
      className="fixed top-3 right-4 z-50 flex items-center gap-2 rounded-full border border-bd bg-raised px-3 py-1.5 text-xs text-muted shadow-sm"
      title="The dashboard stays correct: it reloads what is on screen from the server until live updates return."
    >
      <span className="size-2 rounded-full bg-muted animate-pulse" aria-hidden="true" />
      {state.status === "reconnecting" ? "Live updates reconnecting" : "Live updates unavailable"}
      {every}
    </div>
  );
}
