// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { ArrowUpRight, Ban, CircleCheck } from "lucide-react";
import { OUTBOUND_HOST_NOTE, OUTBOUND_POLICY_DOCS, OUTBOUND_REFUSAL_LABELS, OUTBOUND_REFUSAL_MESSAGES } from "@varlatch/protocol";
import type { RefusedDestination, RefusedDestinations } from "@varlatch/sdk";
import { formatDateTime, timeAgo, useNow } from "../../lib/time";
import { Badge, Mono, SectionCard } from "../../components/ui";

export const refusedDestinationsKey = (org: string) => ["security-refused-destinations", org] as const;

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
  return (
    <SectionCard
      id="security-refused-destinations"
      title="Refused destinations"
      description="Destinations this organization configured that this installation does not connect to. Deliveries to them wait."
      className="scroll-mt-6"
      data-testid="security-refused-destinations"
      data-count={refused.items.length}
    >
      {refused.items.length === 0 ? (
        <p className="flex items-center gap-2 px-5 py-4 text-[13px] text-muted" data-testid="refused-destinations-none">
          <CircleCheck size={15} className="text-accent" aria-hidden="true" />
          None. This installation connects to every destination this organization configured.
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
                  {d.since ? `first refused ${timeAgo(d.since, now)}` : `no refusal recorded in the last ${refused.sinceDays} days`}
                </span>
              </div>
            </li>
          ))}
        </ul>
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
