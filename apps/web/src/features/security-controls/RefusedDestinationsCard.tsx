// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { useQuery } from "@tanstack/react-query";
import { ArrowUpRight, Ban, CircleCheck, CircleHelp } from "lucide-react";
import { OUTBOUND_HOST_NOTE, OUTBOUND_POLICY_DOCS, OUTBOUND_REFUSAL_LABELS, OUTBOUND_REFUSAL_MESSAGES } from "@varlatch/protocol";
import type { RefusedDestination, RefusedDestinations } from "@varlatch/sdk";
import { useSession } from "../../lib/session";
import { formatDateTime, timeAgo, useNow } from "../../lib/time";
import { useCapability } from "../projects/hooks";
import { myPermissionsKey, refusedDestinationsKey } from "./keys";
import { Badge, Mono, SectionCard } from "../../components/ui";

export { refusedDestinationsKey };

/** How often an open page asks again: longer than the server's 30-second reuse of a check. */
export const REFUSED_REFETCH_MS = 60_000;

/**
 * The refused destinations, for pages other than Security (the Connections
 * page): asked only where the server has them and the caller holds
 * organization.manage, so nobody collects a refusal for it. Pages invalidate
 * it on the same changes as their own data; it is also asked again every
 * minute while the page is visible (the server reuses a check for up to 30
 * seconds), so a destination the host operator allowed stops showing as
 * refused without a reload.
 */
export function useRefusedDestinations(org: string) {
  const { api } = useSession();
  const supported = useCapability("security.refused-destinations");
  const reportsPermissions = useCapability("organizations.permissions");
  const permissions = useQuery({
    queryKey: myPermissionsKey(org),
    queryFn: () => api.myOrganizationPermissions(org),
    enabled: supported && reportsPermissions,
  });
  const canManage = permissions.data?.actions.includes("organization.manage") ?? false;
  return useQuery({
    queryKey: refusedDestinationsKey(org),
    queryFn: () => api.refusedDestinations(org),
    enabled: supported && canManage,
    retry: false,
    refetchInterval: REFUSED_REFETCH_MS,
    refetchIntervalInBackground: false,
  });
}

/**
 * What the empty or partial result means: an all-clear only when every
 * configured destination was checked. Older servers send no counts.
 */
export function refusedSummary(refused: RefusedDestinations): { kind: "all-allowed" | "nothing-configured" | "unchecked" | "refused"; unchecked: string | null } {
  const checked = refused.checked as number | undefined;
  const unresolved = (refused.unresolved as number | undefined) ?? 0;
  const unchecked =
    unresolved > 0
      ? `${unresolved}${checked === undefined ? "" : ` of ${checked}`} destination${unresolved === 1 && checked === undefined ? "" : "s"} could not be checked: ${unresolved === 1 ? "its name did" : "their names did"} not resolve. They are checked again when they connect.`
      : null;
  if (refused.items.length > 0) return { kind: "refused", unchecked };
  if (unchecked) return { kind: "unchecked", unchecked };
  return { kind: checked === 0 ? "nothing-configured" : "all-allowed", unchecked: null };
}
export const DESTINATION_KIND: Record<RefusedDestination["kind"], string> = {
  webhook: "Webhook",
  coolify: "Coolify",
  convex: "Convex",
  "oidc-issuer": "OIDC issuer",
};

/**
 * The organization's destinations this installation's outbound policy
 * refuses (ADR-0057 Decision 8): webhooks, Connections and OIDC issuers,
 * with why and since when. Private destinations are the host operator's to
 * allow, never something to change here; nothing waiting is lost meanwhile.
 */
export function RefusedDestinationsCard({ refused }: { refused: RefusedDestinations }) {
  const now = useNow();
  const summary = refusedSummary(refused);
  return (
    <SectionCard
      id="security-refused-destinations"
      title="Refused destinations"
      description="Destinations this organization configured that this installation does not connect to. Deliveries to them wait."
      className="scroll-mt-6"
      data-testid="security-refused-destinations"
      data-count={refused.items.length}
    >
      {summary.kind === "all-allowed" || summary.kind === "nothing-configured" ? (
        <p className="flex items-center gap-2 px-5 py-4 text-[13px] text-muted" data-testid="refused-destinations-none" data-kind={summary.kind}>
          <CircleCheck size={15} className="text-accent" aria-hidden="true" />
          {summary.kind === "all-allowed"
            ? "None. This installation connects to every destination this organization configured."
            : "None. This organization has no webhooks, Coolify or Convex connections, or OIDC issuers."}
        </p>
      ) : summary.kind === "unchecked" ? (
        <p className="px-5 py-4 text-[13px] text-muted" data-testid="refused-destinations-none" data-kind="unchecked">
          None of those checked.
        </p>
      ) : (
        <ul>
          {refused.items.map((d) => (
            <li
              key={`${d.kind}-${d.id}`}
              className="flex flex-wrap items-start justify-between gap-x-6 gap-y-2 border-b border-bd px-5 py-3.5 last:border-b-0"
              data-testid={`refused-destination-${d.id}`}
              data-reason={d.reason}
            >
              <div className="min-w-0">
                <p className="flex flex-wrap items-center gap-2 text-[14px] font-medium">
                  <Badge>{DESTINATION_KIND[d.kind]}</Badge>
                  {d.name ?? <span className="text-muted">{d.id}</span>}
                </p>
                <p className="mt-1">
                  <Mono className="break-all text-[13px]">
                    {d.scheme}://{d.host}:{d.port}
                  </Mono>
                </p>
                <p className="mt-1 text-xs text-muted">{OUTBOUND_REFUSAL_MESSAGES[d.reason]}</p>
              </div>
              <div className="text-right text-[13px]">
                <span className="inline-flex items-center gap-1.5 text-warn">
                  <Ban size={13} aria-hidden="true" />
                  {OUTBOUND_REFUSAL_LABELS[d.reason]}
                </span>
                <span className="block text-xs text-muted" title={d.since ? formatDateTime(d.since) : undefined} data-testid={`refused-since-${d.id}`}>
                  {d.since
                    ? `first recorded within the last ${refused.sinceDays} days: ${timeAgo(d.since, now)}`
                    : `no refusal recorded in the last ${refused.sinceDays} days`}
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}
      {summary.unchecked && (
        <p className="flex items-center gap-2 border-t border-bd px-5 py-2.5 text-[13px] text-warn" data-testid="refused-destinations-unchecked">
          <CircleHelp size={14} aria-hidden="true" />
          {summary.unchecked}
        </p>
      )}
      <p className="border-t border-bd px-5 py-2.5 text-xs text-muted" data-testid="refused-destinations-note">
        {OUTBOUND_HOST_NOTE}{" "}
        <a href={OUTBOUND_POLICY_DOCS} target="_blank" rel="noreferrer" className="inline-flex items-center gap-0.5 text-accent hover:underline">
          Outbound policy
          <ArrowUpRight size={12} aria-hidden="true" />
        </a>
      </p>
    </SectionCard>
  );
}
