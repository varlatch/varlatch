// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ExternalLink, Info, Network, TriangleAlert } from "lucide-react";
import type { TailnetListenerReport } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { formatDateTime, timeAgo, timeUntil, useNow } from "../../lib/time";
import { Callout, EmptyState, SectionCard, Segmented, Skeleton, Status, table, cn } from "../../components/ui";
import { CodeBlock } from "../../components/CodeBlock";
import { errorMessage } from "../../shell/Shell";
import {
  DOCS_ENDPOINT_URL,
  DOCS_TAILSCALE_URL,
  addTailscaleLines,
  checkRows,
  checkTone,
  enableEndpointLines,
  endpointRule,
  remedy,
  tailnetSummary,
  REASON_TEXT,
  type Deployment,
} from "./tailnetStatus";

/**
 * Tailscale on this installation, for Installation Admins: the tailnet
 * listeners as varlatchd configured and last checked them, and what the
 * operator runs on the host to change them. Read-only: setup happens on the
 * host (`varlatch setup`, or the deployment's own settings), never here.
 */
export function TailnetTab() {
  const { api } = useSession();
  const now = useNow();
  const listeners = useQuery({
    queryKey: ["installation-listeners"],
    queryFn: () => api.getInstallationListeners(),
    retry: false,
    // varlatchd checks every 60 seconds.
    refetchInterval: 60_000,
  });
  const [deployment, setDeployment] = useState<Deployment>("setup");

  if (listeners.isLoading) return <Skeleton className="h-48" />;
  if (listeners.isError || !listeners.data) {
    return (
      <Callout tone="danger" icon={<TriangleAlert size={17} />} title="Tailnet status is unavailable" data-testid="tailnet-error">
        {errorMessage(listeners.error)}
      </Callout>
    );
  }
  const report = listeners.data.tailnet;
  return (
    <div className="space-y-6">
      {/* The dashboard cannot tell how the operator deploys: the fixes and the guidance follow this choice. */}
      <div className="flex flex-wrap items-center gap-3 text-[13px]">
        <span className="text-muted">Deployed with</span>
        <Segmented
          size="sm"
          aria-label="How this installation is deployed"
          value={deployment}
          onChange={setDeployment}
          options={[
            { value: "setup", label: "varlatch setup", "data-testid": "tailnet-deployment-setup" },
            { value: "coolify", label: "Coolify", "data-testid": "tailnet-deployment-coolify" },
          ]}
        />
      </div>
      {report ? <Report report={report} now={now} deployment={deployment} /> : <NotConfigured />}
      <Guidance report={report} deployment={deployment} />
    </div>
  );
}

function NotConfigured() {
  return (
    <SectionCard title="Tailnet listener" data-testid="tailnet-not-configured">
      <EmptyState
        icon={<Network size={20} />}
        title="No tailnet listener configured in Varlatch"
        description="varlatchd serves no tailnet listener. This does not tell whether Tailscale is installed or joined elsewhere on the host."
        className="py-8"
      />
    </SectionCard>
  );
}

function Report({ report, now, deployment }: { report: TailnetListenerReport; now: number; deployment: Deployment }) {
  const { configured, observed } = report;
  const summary = tailnetSummary(report, now);
  return (
    <>
      <SectionCard title="Configured" description="From varlatchd's configuration. Not a sign that anything works." data-testid="tailnet-configured">
        <dl className="grid gap-x-8 gap-y-3 px-5 py-4 text-[14px] sm:grid-cols-[max-content_1fr]">
          <dt className="text-muted">Tailnet</dt>
          <dd className="font-mono text-[13px]">{configured.tailnet}</dd>
          <dt className="text-muted">Tailnet listener</dt>
          <dd>port {configured.listenerPort}</dd>
          <dt className="text-muted">Browser endpoint</dt>
          <dd data-testid="tailnet-endpoint">{configured.browserEndpoint ? <span className="font-mono text-[13px]">{configured.browserEndpoint}</span> : <span className="text-muted">Off</span>}</dd>
        </dl>
      </SectionCard>

      <SectionCard
        title="Server checks"
        description="What varlatchd checks itself, at start and every 60 seconds."
        bodyClassName={table.wrap}
        data-testid="tailnet-checks"
        actions={
          <span className="text-[13px] text-muted" data-testid="tailnet-checked-at" title={observed.checkedAt ? formatDateTime(observed.checkedAt) : undefined}>
            Last checked {observed.checkedAt ? timeAgo(observed.checkedAt, now) : "never"}
          </span>
        }
      >
        <div className="flex items-center gap-2 border-b border-bd px-5 py-3">
          <span data-testid="tailnet-summary" data-tone={summary.tone}>
            <Status tone={summary.tone}>{summary.headline}</Status>
          </span>
        </div>
        {summary.stale && (
          <Callout tone="warn" icon={<TriangleAlert size={17} />} className="mx-5 my-4" data-testid="tailnet-stale">
            varlatchd checks every 60 seconds, so a report this old may no longer hold. The results below are from that
            time.
          </Callout>
        )}
        <table className={table.table}>
          <thead>
            <tr>
              <th className={table.th}>Check</th>
              <th className={table.th}>Result</th>
              <th className={table.th}>Detail</th>
            </tr>
          </thead>
          <tbody>
            {checkRows(report).map((row) => {
              const { check } = row;
              const fix = check.status === "fail" ? remedy(check.reason, deployment, configured.browserEndpoint !== null) : null;
              return (
                <tr key={row.key} className={table.tr} data-check={row.key} data-status={check.status}>
                  <td className={cn(table.td, "whitespace-nowrap font-medium")}>{row.label}</td>
                  <td className={cn(table.td, "whitespace-nowrap")}>
                    <Status tone={checkTone(check.status)}>{check.status}</Status>
                  </td>
                  <td className={cn(table.td, "text-[13px]")}>
                    {check.reason ? <span className="block">{REASON_TEXT[check.reason]}</span> : <span className="block text-muted">{row.passes}</span>}
                    {check.certificateNotAfter && (
                      <span className="block text-muted">
                        {Date.parse(check.certificateNotAfter) > now
                          ? `Certificate valid until ${formatDateTime(check.certificateNotAfter)} (${timeUntil(check.certificateNotAfter, now)})`
                          : `Certificate expired ${formatDateTime(check.certificateNotAfter)}`}
                      </span>
                    )}
                    {fix && <span className="mt-1 block text-muted">{fix}</span>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </SectionCard>

      <Callout tone="info" icon={<Info size={17} />} data-testid="tailnet-server-side">
        These checks run on the server. Whether a device can reach the tailnet listener or the browser endpoint depends on
        your tailnet policy, and only that device can find out: in the dashboard, with Connect to tailnet on a tailnet-only
        environment.
      </Callout>
    </>
  );
}

function Guidance({ report, deployment }: { report: TailnetListenerReport | null; deployment: Deployment }) {
  const endpoint = report?.configured.browserEndpoint ?? null;
  const setup = deployment === "setup";
  return (
    <SectionCard
      title={report ? (endpoint ? "Access rule" : "Turn on the browser endpoint") : "Set up Tailscale"}
      description="For the operator: deployment changes on the host or in Coolify, access rules in the tailnet policy. The dashboard changes neither."
      data-testid="tailnet-guidance"
    >
      <div className="space-y-4 px-5 py-4 text-[13px]">
        {!report && (
          <>
            <p>
              {setup
                ? "Add the Tailscale sidecar and the browser endpoint to this installation. Its address stays what it is. The node joins your tailnet once, with an auth key that is neither expired nor used up, and the tailnet needs HTTPS certificates enabled:"
                : "Deploy the Compose file with the Tailscale sidecar and set these variables. Give the auth key as a host file, not as a Coolify variable: Coolify passes every variable to every service."}
            </p>
            <CodeBlock lines={addTailscaleLines(deployment)} data-testid="tailnet-add-lines" />
            {!setup && (
              <>
                <p>Once the node has joined, the browser endpoint takes these four, all together:</p>
                <CodeBlock lines={enableEndpointLines(deployment, null)} data-testid="tailnet-endpoint-lines" />
              </>
            )}
            {setup && (
              <p className="text-muted">
                A new installation reachable only on the tailnet uses <span className="font-mono">varlatch setup --ingress tailnet</span> instead.
                Switching an existing installation to the tailnet ingress is not supported: set up a new installation on the
                tailnet and restore an archive into it.
              </p>
            )}
          </>
        )}
        {report && !endpoint && (
          <>
            <p>
              The browser endpoint lets people on approved devices read tailnet-protected values in the dashboard. It needs HTTPS
              certificates enabled for the tailnet.
            </p>
            <CodeBlock lines={enableEndpointLines(deployment, report.configured.tailnet)} data-testid="tailnet-endpoint-lines" />
          </>
        )}
        <p>
          {endpoint ? "Browsers" : "Then browsers"} reach the endpoint only where your tailnet policy lets their device connect
          to it. Start from this grant, put in the node, and narrow the source to the people, groups or devices that may read
          tailnet-protected values. Network requirements still decide which of those devices may read which values.
        </p>
        <CodeBlock lines={endpointRule(endpoint).split("\n")} data-testid="tailnet-rule" />
        <p className="flex flex-wrap gap-x-4 gap-y-1">
          <DocLink href={DOCS_TAILSCALE_URL}>Tailscale settings</DocLink>
          <DocLink href={DOCS_ENDPOINT_URL}>Tailnet browser endpoint</DocLink>
        </p>
      </div>
    </SectionCard>
  );
}

function DocLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a className="link inline-flex items-center gap-1" href={href} target="_blank" rel="noreferrer">
      {children}
      <ExternalLink size={12} aria-hidden="true" />
    </a>
  );
}
