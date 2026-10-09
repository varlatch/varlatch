// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import { Outlet, useNavigate, useParams } from "react-router-dom";
import { Ellipsis, GitBranch, Layers, Pencil, Type } from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { Badge, EmptyState } from "../../components/ui";
import { Menu, type MenuItem } from "../../components/Select";
import { usePrompt } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { PageHeader, Tabs } from "../../components/PageHeader";
import { FullPageLoading } from "../../shell/AuthScreens";
import { errorMessage } from "../../shell/Shell";
import { NewEnvironmentDialog } from "./NewEnvironmentDialog";
import {
  keys,
  sortEnvironments,
  useCapability,
  useEnvironments,
  useOrgName,
  useProject,
  type ProjectContext,
} from "./hooks";

/**
 * Project workspace: one header (breadcrumbs, slug, contract authority) and
 * the tabs Values / Contract / Integrations / Activity. Child routes render
 * content only and read the project from `useProjectContext()`.
 */
export function ProjectLayout() {
  const { org, project: slug } = useParams() as { org: string; project: string };
  useOrgRealtime(org, ["project", "environment", "contract", "sync", "requirement"], [
    keys.projects(org),
    keys.environments(org, slug),
    keys.contract(org, slug),
    ["requirements", org],
  ]);
  const orgName = useOrgName(org);
  const { project, isLoading } = useProject(org, slug);
  const envs = useEnvironments(org, slug);
  const { api } = useSession();
  const targets = useQuery({ queryKey: keys.orgSyncTargets(org), queryFn: () => api.listOrgSyncTargets(org), retry: false });
  const canRename = useCapability("projects.rename");
  const prompt = usePrompt();
  const toast = useToast();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [newEnvOpen, setNewEnvOpen] = useState(false);

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

  const rename = async () => {
    const name = await prompt({
      title: "Rename project",
      description: `Changes the display name. The slug ${project.slug} stays, so CLI commands and links keep working.`,
      label: "Display name",
      initialValue: project.name,
      confirmLabel: "Rename",
      validate: (v) => (v.length > 100 ? "Use at most 100 characters." : null),
    });
    if (!name || name === project.name) return;
    try {
      await api.renameProject(org, project.slug, name);
      await qc.invalidateQueries({ queryKey: keys.projects(org) });
      toast.success(`Renamed to ${name}`, { description: project.slug });
    } catch (err) {
      toast.error("Could not rename the project", { description: errorMessage(err) });
    }
  };
  const menu: MenuItem[] = [
    {
      label: "New environment…",
      icon: <Layers size={14} />,
      onSelect: () => setNewEnvOpen(true),
      "data-testid": "header-new-environment",
    },
    ...(canRename
      ? [{ label: "Rename…", icon: <Type size={14} />, onSelect: () => void rename(), "data-testid": "header-rename-project" }]
      : []),
  ];

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
        actions={
          <Menu
            label={`${project.slug} actions`}
            data-testid="project-header-menu"
            items={menu}
            buttonClassName="size-8 justify-center border border-bd bg-raised hover:border-bd-strong"
          >
            <Ellipsis size={16} />
          </Menu>
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
      <NewEnvironmentDialog
        org={org}
        project={project.slug}
        environments={environments}
        open={newEnvOpen}
        onClose={() => setNewEnvOpen(false)}
        onCreated={(env) => env.parentEnvironmentId && navigate(`/o/${org}/p/${project.slug}/e/${encodeURIComponent(env.name)}`)}
      />
    </>
  );
}
