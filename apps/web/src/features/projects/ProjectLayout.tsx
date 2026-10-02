// SPDX-License-Identifier: AGPL-3.0-or-later
import { Outlet, useParams } from "react-router-dom";
import { GitBranch, Pencil } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { Badge, EmptyState } from "../../components/ui";
import { PageHeader, Tabs } from "../../components/PageHeader";
import { FullPageLoading } from "../../shell/AuthScreens";
import { keys, sortEnvironments, useEnvironments, useOrgName, useProject, type ProjectContext } from "./hooks";

/**
 * Project workspace: one header (breadcrumbs, slug, contract authority) and
 * the tabs Values / Contract / Integrations / Activity. Child routes render
 * content only and read the project from `useProjectContext()`.
 */
export function ProjectLayout() {
  const { org, project: slug } = useParams() as { org: string; project: string };
  useOrgRealtime(org, ["project", "environment", "contract", "sync"], [
    keys.projects(org),
    keys.environments(org, slug),
    keys.contract(org, slug),
  ]);
  const orgName = useOrgName(org);
  const { project, isLoading } = useProject(org, slug);
  const envs = useEnvironments(org, slug);
  const { api } = useSession();
  const targets = useQuery({ queryKey: keys.orgSyncTargets(org), queryFn: () => api.listOrgSyncTargets(org), retry: false });

  if (isLoading || envs.isLoading) return <FullPageLoading />;
  if (!project) {
    return (
      <EmptyState
        title="Project not found"
        description={`There is no project “${slug}” in this organization, or you cannot see it.`}
      />
    );
  }
  const environments = sortEnvironments(envs.data?.items ?? []);
  const targetCount = (targets.data?.items ?? []).filter((t) => t.projectId === project.id).length;
  const base = `/o/${org}/p/${slug}`;
  const context: ProjectContext = { org, project, environments };

  return (
    <>
      <PageHeader
        breadcrumbs={[
          { label: orgName, to: `/o/${org}/projects` },
          { label: "Projects", to: `/o/${org}/projects` },
          { label: project.slug },
        ]}
        title={<span className="font-mono">{project.slug}</span>}
        badges={
          <>
            {project.name !== project.slug && <span className="text-lg text-muted">{project.name}</span>}
            <Badge className="h-6 gap-1.5 px-2 text-xs" data-testid="contract-authority-badge">
              {project.contractAuthority === "git" ? <GitBranch size={13} /> : <Pencil size={12} />}
              {project.contractAuthority === "git" ? "git contract" : "managed contract"}
            </Badge>
          </>
        }
        tabs={
          <Tabs
            aria-label="Project sections"
            items={[
              { key: "values", label: "Values", to: base, end: true, "data-testid": "project-tab-values" },
              { key: "contract", label: "Contract", to: `${base}/contract`, "data-testid": "project-tab-contract" },
              {
                key: "integrations",
                label: "Integrations",
                to: `${base}/integrations`,
                ...(targetCount > 0 ? { count: targetCount } : {}),
                "data-testid": "project-tab-integrations",
              },
              { key: "activity", label: "Activity", to: `${base}/activity`, "data-testid": "project-tab-activity" },
            ]}
          />
        }
      />
      <Outlet context={context} />
    </>
  );
}
