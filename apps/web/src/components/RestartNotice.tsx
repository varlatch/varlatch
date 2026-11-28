// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { useSseInstallationNotice } from "../lib/sseProvider";

/**
 * Every signed-in dashboard's notice that the host restarts Varlatch for an
 * upgrade (ADR-0065 Decision 8): sent over the live updates before the stop,
 * gone once the server is back (or the upgrade ended without the restart).
 * Mounted under SseProvider.
 */
export function RestartNotice() {
  const notice = useSseInstallationNotice();
  if (!notice) return null;
  return (
    <div
      role="status"
      aria-live="polite"
      data-testid="restart-notice"
      className="fixed inset-x-0 top-0 z-50 flex justify-center px-4 pt-3"
    >
      <div className="flex max-w-xl items-center gap-2 rounded-lg border border-warn/40 bg-raised px-4 py-2 text-[13px] shadow-pop">
        <span className="size-2 shrink-0 animate-pulse rounded-full bg-warn" aria-hidden="true" />
        <span>
          <span className="font-medium">Varlatch is restarting for an upgrade{notice.version ? ` to ${notice.version}` : ""}.</span>{" "}
          It is unavailable for about a minute; this page reconnects by itself. CLI commands, Brokers and syncs that run meanwhile fail or wait.
        </span>
      </div>
    </div>
  );
}
