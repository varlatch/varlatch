// SPDX-License-Identifier: AGPL-3.0-or-later
import { useQuery } from "@tanstack/react-query";
import { useOutletContext } from "react-router-dom";
import type { Environment, Project } from "@varlatch/protocol";
import { useSession } from "../../lib/session";

/** Shared query keys: every screen uses the same ones so caches line up. */
export const keys = {
  orgs: () => ["orgs"] as const,
  projects: (org: string) => ["projects", org] as const,
  environments: (org: string, project: string) => ["environments", org, project] as const,
  contract: (org: string, project: string) => ["contract", org, project] as const,
  effectiveMeta: (org: string, project: string, env: string) => ["effective-meta", org, project, env] as const,
  effectiveValues: (org: string, project: string, env: string) => ["effective-values", org, project, env] as const,
  syncTargets: (org: string, project: string, env: string) => ["sync-targets", org, project, env] as const,
  orgSyncTargets: (org: string) => ["org-sync-targets", org] as const,
  meta: () => ["meta"] as const,
};

export function useOrgName(org: string | undefined): string | undefined {
  const { api } = useSession();
  const orgs = useQuery({ queryKey: keys.orgs(), queryFn: () => api.listOrganizations() });
  return orgs.data?.items.find((o) => o.slug === org)?.name ?? org;
}

export function useMeta() {
  const { api } = useSession();
  return useQuery({ queryKey: keys.meta(), queryFn: () => api.meta(), staleTime: 5 * 60_000 });
}

/** True when the server advertises `capability` in /v1/meta. */
export function useCapability(capability: string): boolean {
  const meta = useMeta();
  return (meta.data?.capabilities ?? []).includes(capability);
}

export function useProjects(org: string) {
  const { api } = useSession();
  return useQuery({ queryKey: keys.projects(org), queryFn: () => api.listProjects(org) });
}

export function useProject(org: string, slug: string): { project: Project | undefined; isLoading: boolean } {
  const projects = useProjects(org);
  return { project: projects.data?.items.find((p) => p.slug === slug), isLoading: projects.isLoading };
}

export function useEnvironments(org: string, project: string) {
  const { api } = useSession();
  return useQuery({ queryKey: keys.environments(org, project), queryFn: () => api.listEnvironments(org, project) });
}

/** Root environments first in tier order (development, staging, production), then by name. */
export function sortEnvironments(envs: Environment[]): Environment[] {
  const order: Record<string, number> = { development: 0, staging: 1, production: 2 };
  return [...envs].sort(
    (a, b) => (order[a.tier] ?? 9) - (order[b.tier] ?? 9) || a.name.localeCompare(b.name),
  );
}

export type ProjectContext = { org: string; project: Project; environments: Environment[] };
export type EnvironmentContext = ProjectContext & { environment: Environment };

/** Inside ProjectLayout: the loaded project and its environments. */
export function useProjectContext(): ProjectContext {
  return useOutletContext<ProjectContext>();
}

/** Inside EnvironmentLayout: the loaded project, environment and siblings. */
export function useEnvironmentContext(): EnvironmentContext {
  return useOutletContext<EnvironmentContext>();
}
