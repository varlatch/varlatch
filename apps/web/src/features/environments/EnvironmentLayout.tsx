// SPDX-License-Identifier: AGPL-3.0-or-later
import { Outlet, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import type { Tier } from "@varlatch/protocol";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { EmptyState, TierChip, TierDot } from "../../components/ui";
import { PageHeader, Tabs } from "../../components/PageHeader";
import { FullPageLoading } from "../../shell/AuthScreens";
import {
  keys,
  sortEnvironments,
  useEnvironments,
  useOrgName,
  useProject,
  type EnvironmentContext,
} from "../projects/hooks";

/**
 * One environment: header (breadcrumbs, tier, kind) and the tabs Values /
 * Integrations / Activity. Child routes render content only and read the
 * environment from `useEnvironmentContext()`.
 */
export function EnvironmentLayout() {
  const { org, project: slug, env } = useParams() as { org: string; project: string; env: string };
  const envName = decodeURIComponent(env);
  useOrgRealtime(org, ["environment", "sync"], [keys.environments(org, slug), keys.syncTargets(org, slug, envName)]);
  const orgName = useOrgName(org);
  const { api } = useSession();
  const { project, isLoading } = useProject(org, slug);
  const envs = useEnvironments(org, slug);
  const targets = useQuery({
    queryKey: keys.syncTargets(org, slug, envName),
    queryFn: () => api.listSyncTargets(org, slug, envName),
    retry: false,
  });

  if (isLoading || envs.isLoading) return <FullPageLoading />;
  const environment = envs.data?.items.find((e) => e.name === envName);
  if (!project || !environment) {
    return (
      <EmptyState
        title="Environment not found"
        description={`There is no environment “${envName}” in ${slug}, or you cannot see it.`}
      />
    );
  }
  const tier = environment.tier as Tier;
  const parent = environment.parentEnvironmentId
    ? envs.data?.items.find((e) => e.id === environment.parentEnvironmentId)
    : undefined;
  const base = `/o/${org}/p/${slug}/e/${encodeURIComponent(envName)}`;
  const targetCount = targets.data?.items.length ?? 0;
  const context: EnvironmentContext = {
    org,
    project,
    environments: sortEnvironments(envs.data?.items ?? []),
    environment,
  };

  return (
    <>
      <PageHeader
        breadcrumbs={[
          { label: orgName, to: `/o/${org}/projects` },
          { label: "Projects", to: `/o/${org}/projects` },
          { label: project.slug, to: `/o/${org}/p/${slug}` },
          { label: environment.name },
        ]}
        title={
          <span className="inline-flex items-center gap-3">
            <TierDot tier={tier} className="size-3" />
            <span className="font-mono" data-testid="environment-name">
              {environment.name}
            </span>
          </span>
        }
        badges={<TierChip tier={tier} />}
        subtitle={
          <span>
            {environment.kind}
            {parent && (
              <>
                {" "}
                · derived from <span className="font-mono text-fg">{parent.name}</span>
              </>
            )}
          </span>
        }
        tabs={
          <Tabs
            aria-label="Environment sections"
            items={[
              { key: "values", label: "Values", to: base, end: true, "data-testid": "env-tab-values" },
              {
                key: "integrations",
                label: "Integrations",
                to: `${base}/integrations`,
                ...(targetCount > 0 ? { count: targetCount } : {}),
                "data-testid": "integrations-link",
              },
              { key: "activity", label: "Activity", to: `${base}/activity`, "data-testid": "env-tab-activity" },
            ]}
          />
        }
      />
      <Outlet context={context} />
    </>
  );
}
