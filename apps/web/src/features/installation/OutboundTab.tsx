// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { useQuery } from "@tanstack/react-query";
import { ArrowUpRight, CircleCheck, CircleHelp, Info, TriangleAlert } from "lucide-react";
import { OUTBOUND_POLICY_DOCS, OUTBOUND_REFUSAL_LABELS } from "@varlatch/protocol";
import type { InstallationOutbound, InstallationRefusedDestination } from "@varlatch/sdk";
import { useSession } from "../../lib/session";
import { Badge, Callout, Mono, SectionCard, Skeleton, cn, table } from "../../components/ui";
import { CodeBlock } from "../../components/CodeBlock";
import { errorMessage } from "../../shell/Shell";
import { useCapability } from "../projects/hooks";

export const installationOutboundKey = ["installation-outbound"] as const;

const KIND: Record<InstallationRefusedDestination["kind"], string> = {
  webhook: "Webhook",
  coolify: "Coolify",
  convex: "Convex",
  "oidc-issuer": "OIDC issuer",
};

/**
 * The outbound policy, for Installation Admins (ADR-0057 Decision 8): the
 * host's allow list as varlatchd parsed it at startup, with doctor's
 * warnings, and every destination an Organization configured that it
 * refuses, with the line that would allow the refused names. Read-only by
 * design: the allow list is set on the host, never from the dashboard.
 */
export function OutboundTab({ admin, checking }: { admin: boolean; checking: boolean }) {
  const { api } = useSession();
  const supported = useCapability("installation.outbound");
  const outbound = useQuery({
    queryKey: installationOutboundKey,
    queryFn: () => api.getInstallationOutbound(),
    enabled: admin && supported,
    retry: false,
  });
  if (checking || outbound.isLoading) return <Skeleton className="h-48" />;
  if (!admin) {
    return (
      <Callout tone="danger" icon={<TriangleAlert size={17} />} title="Outbound policy is unavailable" data-testid="outbound-error">
        Installation Admin authority is required to see this installation's outbound policy.
      </Callout>
    );
  }
  if (!supported || outbound.isError || !outbound.data) {
    return (
      <Callout tone="danger" icon={<TriangleAlert size={17} />} title="Outbound policy is unavailable" data-testid="outbound-error">
        {outbound.error ? errorMessage(outbound.error) : "This server does not report its outbound policy."}
      </Callout>
    );
  }
  return <OutboundReport outbound={outbound.data} />;
}

/** Refused destinations grouped by Organization, in the server's order. */
function byOrganization(refused: InstallationRefusedDestination[]): { organization: InstallationRefusedDestination["organization"]; items: InstallationRefusedDestination[] }[] {
  const groups: { organization: InstallationRefusedDestination["organization"]; items: InstallationRefusedDestination[] }[] = [];
  for (const d of refused) {
    const group = groups.find((g) => g.organization.id === d.organization.id);
    if (group) group.items.push(d);
    else groups.push({ organization: d.organization, items: [d] });
  }
  return groups;
}

export function OutboundReport({ outbound }: { outbound: InstallationOutbound }) {
  const groups = byOrganization(outbound.refused);
  const checked = outbound.checked as number | undefined;
  const unchecked =
    outbound.unresolved > 0
      ? `${outbound.unresolved}${checked === undefined ? "" : ` of ${checked}`} configured destination${outbound.unresolved === 1 && checked === undefined ? "" : "s"} could not be checked: ${outbound.unresolved === 1 ? "its name did" : "their names did"} not resolve. They are checked again when they connect, and varlatch admin outbound check on the host names them.`
      : null;
  return (
    <div className="space-y-6">
      <SectionCard
        title="Allow list"
        description="Private destinations Organizations may reach. Set on the host as VARLATCH_OUTBOUND_ALLOW, read when varlatchd starts; it cannot be changed here."
        data-testid="outbound-allow"
      >
        <div className="px-5 py-4">
          {outbound.allow.length === 0 ? (
            <p className="text-[13px] text-muted" data-testid="outbound-allow-empty">
              Not set. Organizations reach what the internet reaches over https, and nothing on a private network.
            </p>
          ) : (
            <ul className="flex flex-wrap gap-1.5" data-testid="outbound-allow-entries">
              {outbound.allow.map((entry) => (
                <li key={entry}>
                  <Badge className="font-mono">{entry}</Badge>
                </li>
              ))}
            </ul>
          )}
        </div>
        {outbound.warnings.length > 0 && (
          <div className="space-y-2 px-5 pb-4">
            {outbound.warnings.map((w) => (
              <Callout key={w} tone="warn" icon={<TriangleAlert size={16} />} data-testid="outbound-warning">
                {w}
              </Callout>
            ))}
          </div>
        )}
      </SectionCard>

      <SectionCard
        title="Refused destinations"
        description="Webhooks, Connections and OIDC issuers that Organizations configured and this installation does not connect to. Their deliveries wait, and catch up once allowed."
        data-testid="outbound-refused"
        data-count={outbound.refused.length}
        bodyClassName={outbound.refused.length > 0 ? table.wrap : undefined}
      >
        {outbound.refused.length === 0 ? (
          <p className="flex items-center gap-2 px-5 py-4 text-[13px] text-muted" data-testid="outbound-refused-none">
            {unchecked ? (
              "None of those checked."
            ) : (
              <>
                <CircleCheck size={15} className="text-accent" aria-hidden="true" />
                {checked === 0 ? "None. No Organization has configured a webhook, Coolify or Convex connection, or OIDC issuer." : "None. Every configured destination is allowed."}
              </>
            )}
          </p>
        ) : (
          <table className={table.table}>
            <thead>
              <tr>
                <th className={table.th}>Organization</th>
                <th className={table.th}>Kind</th>
                <th className={table.th}>Name</th>
                <th className={table.th}>Host</th>
                <th className={table.th}>Reason</th>
              </tr>
            </thead>
            <tbody>
              {groups.flatMap((g) =>
                g.items.map((d, i) => (
                  <tr key={`${d.kind}-${d.id}`} className={table.tr} data-testid={`outbound-refused-${d.id}`} data-reason={d.reason}>
                    <td className={cn(table.td, "whitespace-nowrap")}>{i === 0 ? g.organization.name : ""}</td>
                    <td className={table.td}>
                      <Badge>{KIND[d.kind]}</Badge>
                    </td>
                    <td className={cn(table.td, "text-[13px]")}>{d.name ?? <span className="font-mono text-muted">{d.id}</span>}</td>
                    <td className={table.td}>
                      <Mono className="break-all text-[13px]">
                        {d.scheme}://{d.host}:{d.port}
                      </Mono>
                    </td>
                    <td className={cn(table.td, "text-[13px]")}>
                      {OUTBOUND_REFUSAL_LABELS[d.reason]}
                      {d.notSuggested && <span className="block text-xs text-muted">{d.notSuggested}</span>}
                    </td>
                  </tr>
                )),
              )}
            </tbody>
          </table>
        )}
        {unchecked && (
          <p className="flex items-center gap-2 border-t border-bd px-5 py-2.5 text-[13px] text-warn" data-testid="outbound-unchecked">
            <CircleHelp size={14} aria-hidden="true" />
            {unchecked}
          </p>
        )}
      </SectionCard>

      {outbound.suggested && (
        <SectionCard
          title="Allow them on the host"
          description="Add this line to the installation's .env, then restart varlatchd. Every Organization on this installation can then reach these destinations."
          data-testid="outbound-suggested"
        >
          <div className="space-y-3 px-5 py-4 text-[13px]">
            <CodeBlock lines={[`VARLATCH_OUTBOUND_ALLOW=${outbound.suggested}`]} data-testid="outbound-suggested-line" />
            <p className="text-muted">
              Check a value before restarting with <Mono>varlatch admin outbound check --allow &lt;value&gt;</Mono>.
            </p>
          </div>
        </SectionCard>
      )}

      <Callout tone="neutral" icon={<Info size={17} />}>
        Only the host operator allows private destinations. Nothing waiting is lost meanwhile.{" "}
        <a href={OUTBOUND_POLICY_DOCS} target="_blank" rel="noreferrer" className="inline-flex items-center gap-0.5 text-accent hover:underline">
          Outbound policy
          <ArrowUpRight size={13} aria-hidden="true" />
        </a>
      </Callout>
    </div>
  );
}
