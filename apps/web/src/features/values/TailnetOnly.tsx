// SPDX-License-Identifier: AGPL-3.0-or-later
import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Wifi } from "lucide-react";
import type { Environment, Project } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { TAILNET_ONLY_GUIDANCE, TAILNET_ONLY_LABEL } from "../../lib/tailnet";
import { Callout, cn } from "../../components/ui";
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

/** In place of Reveal: why values here cannot be read in the dashboard. */
export function TailnetOnlyNotice({
  org,
  project,
  env,
  environments,
}: {
  org: string;
  project: Project;
  env: Environment;
  environments: Environment[];
}) {
  const rules = useCoveringRules(org, project, env, environments);
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
            The dashboard cannot read them: it never connects through the tailnet. Use the CLI configured for the
            Tailscale endpoint on an approved device.{" "}
            <Link to={rulesHref(org)} className="text-accent hover:underline">
              Network requirements
            </Link>
          </span>
        </>
      ) : (
        TAILNET_ONLY_GUIDANCE
      )}
    </Callout>
  );
}
