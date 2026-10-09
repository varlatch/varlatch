// SPDX-License-Identifier: AGPL-3.0-or-later
import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Wifi } from "lucide-react";
import type { Environment, Project, TailnetDevice } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { TAILNET_ONLY_GUIDANCE, TAILNET_ONLY_LABEL } from "../../lib/tailnet";
import { unrecognizedReason, useTailnetConnection, type TailnetConnection } from "../../lib/tailnetConnection";
import { Button, Callout, cn } from "../../components/ui";
import { requirementSentence } from "../access/requirements";
import type { Names } from "../access/model";

/**
 * Where a Tailnet Requirement keeps values out of the dashboard: a badge on
 * the environment and a notice where Reveal would be. The server sends the
 * covering Requirement IDs only to viewers holding policy.read; they get the
 * rules and a link to them, everyone else the generic guidance.
 */

/** The covering rules as sentences, or null for viewers without policy.read. */
function useCoveringRules(org: string, project: Project, env: Environment, environments: Environment[]): string[] | null {
  const { api } = useSession();
  const ids = env.tailnetRequirementIds;
  const reqs = useQuery({
    queryKey: ["requirements", org],
    queryFn: () => api.listRequirements(org),
    enabled: (ids?.length ?? 0) > 0,
    retry: false,
  });
  return useMemo(() => {
    if (!ids?.length) return null;
    // A rule covering this environment targets a tier, this environment or
    // its root: all within this project.
    const names: Names = {
      project: (id) => (id === project.id ? project : undefined),
      environment: (id) => environments.find((e) => e.id === id),
      team: () => undefined,
    };
    const byId = new Map((reqs.data?.items ?? []).map((r) => [r.id, r]));
    return ids.map((id) => {
      const req = byId.get(id);
      return req ? requirementSentence(req, names) : `Requirement ${id}`;
    });
  }, [ids, reqs.data, project, environments]);
}

function rulesHref(org: string) {
  return `/o/${org}/access?tab=advanced`;
}

/** "Values: tailnet only", with what that means on hover or focus. */
export function TailnetOnlyBadge({
  org,
  project,
  env,
  environments,
  compact,
  className,
}: {
  org: string;
  project: Project;
  env: Environment;
  environments: Environment[];
  compact?: boolean;
  className?: string;
}) {
  const rules = useCoveringRules(org, project, env, environments);
  const chip = (
    <span
      className={cn(
        "inline-flex items-center gap-1 whitespace-nowrap rounded-md border border-info/40 bg-info/[0.08] px-1.5 py-px text-[11px] font-medium leading-4 text-info",
        rules && "hover:border-info/70",
      )}
    >
      <Wifi size={11} aria-hidden="true" />
      {compact ? "tailnet only" : TAILNET_ONLY_LABEL}
    </span>
  );
  return (
    <span className={cn("group relative inline-flex align-middle", className)} data-testid={`tailnet-only-${env.name}`}>
      {rules ? (
        <Link to={rulesHref(org)} aria-label={`${TAILNET_ONLY_LABEL}. ${rules.join(". ")}`} className="rounded-md outline-none focus-visible:outline-2 focus-visible:outline-accent">
          {chip}
        </Link>
      ) : (
        <span tabIndex={0} aria-label={`${TAILNET_ONLY_LABEL}. ${TAILNET_ONLY_GUIDANCE}`} className="rounded-md outline-none focus-visible:outline-2 focus-visible:outline-accent">
          {chip}
        </span>
      )}
      <span
        role="tooltip"
        className="pointer-events-none absolute left-0 top-full z-40 mt-1.5 w-80 rounded-lg border border-bd bg-raised px-3 py-2 text-xs font-normal normal-case leading-relaxed text-fg opacity-0 shadow-pop transition-opacity group-focus-within:opacity-100 group-hover:opacity-100"
      >
        {rules ? (
          <>
            <span className="block">Values here can only be read from approved devices on the tailnet:</span>
            {rules.map((r) => (
              <span key={r} className="mt-1 block text-muted">
                {r}
              </span>
            ))}
            <span className="mt-1 block text-muted">Select to see the network requirements.</span>
          </>
        ) : (
          TAILNET_ONLY_GUIDANCE
        )}
      </span>
    </span>
  );
}

const deviceName = (device: TailnetDevice) => device.nodeName ?? device.nodeId ?? "this device";

/**
 * Where this tab stands with the tailnet browser endpoint (ADR-0046
 * Decision 5), with the Connect action. Labels say who observed what: the
 * endpoint is configured, the device is checked by Varlatch, reachability
 * is known only from this browser. Nothing is sent to the endpoint before
 * the person chooses Connect.
 */
export function TailnetConnectStatus({ connection, connect, deviceRefused }: { connection: TailnetConnection; connect: () => void; deviceRefused?: boolean | undefined }) {
  if (connection.status === "unavailable") return null;
  const action = (label: string) => (
    <Button size="sm" icon={<Wifi size={13} />} loading={connection.status === "connecting"} onClick={connect} data-testid="tailnet-connect">
      {label}
    </Button>
  );
  switch (connection.status) {
    case "idle":
    case "connecting":
      return (
        <span className="mt-2 block" data-testid="tailnet-connect-status" data-status={connection.status}>
          <span className="block">
            This installation has a tailnet endpoint (configured). Connect to read these values from this browser:
            Varlatch then checks this device on every request. Your browser may ask to allow access to devices on your
            local network.
          </span>
          <span className="mt-2 block">{action(connection.status === "connecting" ? "Connecting" : "Connect to tailnet")}</span>
        </span>
      );
    case "unreachable":
      return (
        <span className="mt-2 block" data-testid="tailnet-connect-status" data-status="unreachable">
          <span className="block">
            {connection.blockedByPolicy
              ? "This dashboard's security policy does not allow the tailnet endpoint, so this browser could not reach it. Ask the operator to run setup again."
              : "The tailnet endpoint did not answer from this browser. This device may not be on the tailnet, or the tailnet's access rules may not let it reach the endpoint."}
          </span>
          <span className="mt-2 block">{action("Try again")}</span>
        </span>
      );
    case "unrecognized":
      return (
        <span className="mt-2 block" data-testid="tailnet-connect-status" data-status="unrecognized">
          <span className="block">
            The endpoint answered, but Varlatch did not recognize this device: {unrecognizedReason(connection.reason)}.
          </span>
          <span className="mt-2 block">{action("Try again")}</span>
        </span>
      );
    case "connected":
      return (
        <span className="mt-2 block" data-testid="tailnet-connect-status" data-status={deviceRefused ? "refused" : "connected"}>
          {deviceRefused
            ? `Connected from this browser as ${deviceName(connection.device)}, but this device does not meet the requirements here (checked by Varlatch).`
            : `Connected from this browser as ${deviceName(connection.device)} (checked by Varlatch). Reading values through the tailnet.`}
        </span>
      );
  }
}

/** In place of Reveal: why values here cannot be read in the dashboard, and how this browser can, where it can. */
export function TailnetOnlyNotice({
  org,
  project,
  env,
  environments,
  deviceRefused,
}: {
  org: string;
  project: Project;
  env: Environment;
  environments: Environment[];
  deviceRefused?: boolean | undefined;
}) {
  const rules = useCoveringRules(org, project, env, environments);
  const { connection, connect } = useTailnetConnection();
  const offered = connection.status !== "unavailable";
  return (
    <Callout
      tone="info"
      icon={<Wifi size={15} />}
      data-testid="tailnet-only-notice"
      title="Values here require an approved device on the tailnet"
    >
      {rules ? (
        <>
          {rules.map((r) => (
            <span key={r} className="block">
              {r}.
            </span>
          ))}
          <span className="mt-1 block">
            {offered
              ? "The dashboard reads them only through the tailnet, from an approved device."
              : "The dashboard cannot read them: it never connects through the tailnet. Use the CLI configured for the Tailscale endpoint on an approved device."}{" "}
            <Link to={rulesHref(org)} className="text-accent hover:underline">
              Network requirements
            </Link>
          </span>
        </>
      ) : offered ? (
        "Values here require an approved device on the tailnet."
      ) : (
        TAILNET_ONLY_GUIDANCE
      )}
      <TailnetConnectStatus connection={connection} connect={connect} deviceRefused={deviceRefused} />
    </Callout>
  );
}

/** Where values were read through the tailnet: from this browser, as this device. */
export function TailnetReadNote({ device }: { device: TailnetDevice }) {
  return (
    <p className="flex items-center gap-1.5 text-xs text-muted" data-testid="tailnet-read-note">
      <Wifi size={12} className="text-info" aria-hidden="true" />
      Values here were read through the tailnet from this browser, as {deviceName(device)}. Varlatch checks this device on
      every request.
    </p>
  );
}

/** Above a grid with protected columns: the same Connect action, for all of them. */
export function TailnetConnectPrompt({ envs }: { envs: string[] }) {
  const { connection, connect } = useTailnetConnection();
  if (envs.length === 0 || connection.status === "unavailable" || connection.status === "connected") return null;
  return (
    <Callout tone="info" icon={<Wifi size={15} />} data-testid="tailnet-connect-prompt" title={`Values in ${envs.join(", ")} need this device's tailnet identity`}>
      <TailnetConnectStatus connection={connection} connect={connect} />
    </Callout>
  );
}
