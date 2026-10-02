// SPDX-License-Identifier: AGPL-3.0-or-later
import { useMemo } from "react";
import { useQueries } from "@tanstack/react-query";
import type { Environment, Project } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { keys, useProjects } from "../projects/hooks";

export type EnvironmentRef = { environment: Environment; project: Project };

/**
 * Every environment of every project in the organization, by ID: sync
 * targets and audit events carry environment IDs, people read names.
 */
export function useOrgEnvironments(org: string): { byId: Map<string, EnvironmentRef>; loading: boolean } {
  const { api } = useSession();
  const projects = useProjects(org);
  const list = projects.data?.items ?? [];
  const queries = useQueries({
    queries: list.map((p) => ({
      queryKey: keys.environments(org, p.slug),
      queryFn: () => api.listEnvironments(org, p.slug),
      staleTime: 60_000,
    })),
  });
  const stamp = queries.map((q) => q.dataUpdatedAt).join(",");
  const byId = useMemo(() => {
    const map = new Map<string, EnvironmentRef>();
    list.forEach((project, i) => {
      for (const environment of queries[i]?.data?.items ?? []) map.set(environment.id, { environment, project });
    });
    return map;
    // `queries` is a fresh array each render; `stamp` says when its data changed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projects.data, stamp]);
  return { byId, loading: projects.isLoading || queries.some((q) => q.isLoading) };
}
