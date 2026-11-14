// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { StatusDot } from "../components/ui";
import { BrandMark } from "./BrandMark";

/*
 * Screens main.tsx can show before the app loads (lib/backend.ts): they
 * import nothing of the session, the router or realtime.
 */

/** Centered card on the dot-grid backdrop: every signed-out screen. */
export function CenteredCard({ children, testId }: { children: React.ReactNode; testId?: string }) {
  return (
    <main className="relative grid min-h-screen place-items-center overflow-hidden p-6" data-testid={testId}>
      <div className="dot-grid pointer-events-none absolute inset-0" aria-hidden="true" />
      <div className="relative w-full max-w-[420px]">{children}</div>
    </main>
  );
}

export function MaintenanceScreen() {
  return (
    <CenteredCard testId="maintenance-screen">
      <div className="rounded-2xl border border-bd bg-raised px-8 py-8 shadow-pop">
        <div className="flex items-center gap-3">
          <BrandMark size={36} />
          <div>
            <h1 className="font-semibold">Varlatch is under maintenance</h1>
            <p className="mt-0.5 flex items-center gap-2 text-[13px] text-muted">
              <StatusDot tone="muted" className="animate-pulse" /> Reconnecting by itself
            </p>
          </div>
        </div>
        <p className="mt-5 text-[13px] leading-relaxed text-muted">
          A restore or an upgrade is in progress. This page continues on its own when it finishes; there is no
          need to sign in again.
        </p>
      </div>
    </CenteredCard>
  );
}

/** While /v1/meta has not answered: the dashboard is still reaching the server. */
export function ConnectingScreen() {
  return (
    <CenteredCard testId="connecting-screen">
      <div className="rounded-2xl border border-bd bg-raised px-8 py-8 shadow-pop">
        <div className="flex items-center gap-3">
          <BrandMark size={36} />
          <div>
            <h1 className="font-semibold">Connecting to Varlatch</h1>
            <p className="mt-0.5 flex items-center gap-2 text-[13px] text-muted">
              <StatusDot tone="muted" className="animate-pulse" /> Trying again by itself
            </p>
          </div>
        </div>
      </div>
    </CenteredCard>
  );
}
