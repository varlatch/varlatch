// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { useQuery } from "@tanstack/react-query";
import { useSession } from "../../lib/session";
import { useCapability } from "../projects/hooks";
import { cn } from "../../components/ui";

/** Where a newer-release dot leads (ADR-0049). */
export const RELEASE_TAB_PATH = "/installation/settings?tab=release";

/**
 * The host's last release check, for Installation Admins. `admin` gates the
 * request: the dashboard asks only once another admin-only read succeeded,
 * so members never see a refusal for something they cannot act on.
 */
export function useInstallationRelease(admin: boolean) {
  const { api } = useSession();
  const supported = useCapability("installation.release");
  return useQuery({
    queryKey: ["installation-release"],
    queryFn: () => api.getInstallationRelease(),
    enabled: admin && supported,
    retry: false,
    refetchInterval: 5 * 60_000,
  });
}

/** The newer-release dot: colour plus text for screen readers, never colour alone. */
export function NewerReleaseDot({ className }: { className?: string }) {
  return (
    <span className={cn("inline-flex items-center", className)} data-testid="newer-release-dot">
      <span aria-hidden="true" className="inline-block size-2 shrink-0 rounded-full bg-warn" />
      <span className="sr-only">A newer release is available</span>
    </span>
  );
}
