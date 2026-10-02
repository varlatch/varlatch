// SPDX-License-Identifier: AGPL-3.0-or-later
import { Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, Upload } from "lucide-react";
import type { Tier } from "@varlatch/protocol";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { EmptyState, Skeleton, TierDot } from "../../components/ui";
import { connectionsKey } from "../sync/keys";
import { TargetCard } from "../sync/TargetCard";
import { keys, useProjectContext } from "./hooks";

/**
 * Project Integrations: every sync target of the project, grouped by
 * environment. Adding one happens on an environment's Integrations tab,
 * where the review names that environment's values.
 */
export function ProjectIntegrations() {
  const { org, project, environments } = useProjectContext();
  const { api } = useSession();
  const qc = useQueryClient();
  useOrgRealtime(org, ["sync"], [keys.orgSyncTargets(org), connectionsKey(org)]);
  const targets = useQuery({ queryKey: keys.orgSyncTargets(org), queryFn: () => api.listOrgSyncTargets(org) });
  const connections = useQuery({ queryKey: connectionsKey(org), queryFn: () => api.listPlatformConnections(org) });
  const byConnection = new Map((connections.data?.items ?? []).map((c) => [c.id, c]));
  const mine = (targets.data?.items ?? []).filter((t) => t.projectId === project.id);
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: keys.orgSyncTargets(org) });
    void qc.invalidateQueries({ queryKey: ["sync-targets", org, project.slug] });
  };
  const base = `/o/${org}/p/${project.slug}/e`;

  if (targets.isLoading) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-5 w-40" />
        <Skeleton className="h-20 w-full rounded-xl" />
        <Skeleton className="h-20 w-full rounded-xl" />
      </div>
    );
  }

  if (mine.length === 0) {
    const first = environments.find((e) => e.tier === "production") ?? environments[0];
    return (
      <div className="rounded-xl border border-dashed border-bd" data-testid="project-integrations-empty">
        <EmptyState
          icon={<Upload size={20} />}
          title="No integrations in this project"
          description="Integrations push one environment's values to GitHub Actions, Coolify or Convex. Add one from that environment's Integrations tab."
          actions={
            first ? (
              <Link
                to={`${base}/${encodeURIComponent(first.name)}/integrations`}
                className="inline-flex h-8 items-center gap-2 rounded-md border border-bd bg-raised px-3 text-sm text-fg hover:border-bd-strong hover:bg-hover"
              >
                Open <span className="font-mono">{first.name}</span> integrations <ArrowRight size={14} />
              </Link>
            ) : undefined
          }
        />
      </div>
    );
  }

  return (
    <div className="space-y-7" data-testid="project-integrations">
      {environments
        .filter((env) => mine.some((t) => t.environmentId === env.id))
        .map((env) => (
          <section key={env.id} aria-label={env.name}>
            <header className="mb-2.5 flex items-center gap-2.5">
              <TierDot tier={env.tier as Tier} />
              <Link
                to={`${base}/${encodeURIComponent(env.name)}/integrations`}
                className="font-mono text-sm font-semibold text-fg hover:text-accent"
              >
                {env.name}
              </Link>
              <span className="text-xs text-muted">
                {mine.filter((t) => t.environmentId === env.id).length} integration
                {mine.filter((t) => t.environmentId === env.id).length === 1 ? "" : "s"}
              </span>
            </header>
            <div className="space-y-2.5">
              {mine
                .filter((t) => t.environmentId === env.id)
                .map((t) => (
                  <TargetCard
                    key={t.id}
                    compact
                    org={org}
                    project={project.slug}
                    envName={env.name}
                    target={t}
                    connection={byConnection.get(t.connectionId)}
                    onChanged={refresh}
                  />
                ))}
            </div>
          </section>
        ))}
    </div>
  );
}
