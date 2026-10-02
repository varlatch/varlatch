// SPDX-License-Identifier: AGPL-3.0-or-later
import { useMemo } from "react";
import { useQueries, useQuery } from "@tanstack/react-query";
import type { Environment, Project } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { shortId } from "../../lib/identity";
import { useIdentities } from "./shared";
import type { Names } from "./model";

/**
 * Resolves ids in grants and audit records to names: identities, groups,
 * teams, roles, projects and their environments. Never shows a raw id when a
 * name is known.
 */
export function useAccessNames(org: string) {
  const { api } = useSession();
  const identities = useIdentities(org);
  const groups = useQuery({ queryKey: ["groups", org], queryFn: () => api.listGroups(org) });
  const teams = useQuery({ queryKey: ["teams", org], queryFn: () => api.listTeams(org) });
  const roles = useQuery({ queryKey: ["roles", org], queryFn: () => api.listRoles(org) });
  const projects = useQuery({ queryKey: ["projects", org], queryFn: () => api.listProjects(org) });
  const envQueries = useQueries({
    queries: (projects.data?.items ?? []).map((p) => ({
      queryKey: ["environments", org, p.slug],
      queryFn: () => api.listEnvironments(org, p.slug),
    })),
  });
  const envList = envQueries.flatMap((q) => q.data?.items ?? []);
  const envKey = envList.map((e) => e.id).join(",");

  return useMemo(() => {
    const projectById = new Map<string, Project>((projects.data?.items ?? []).map((p) => [p.id, p]));
    const envById = new Map<string, Environment>(envList.map((e) => [e.id, e]));
    const teamName = (id: string) => teams.data?.items.find((t) => t.id === id)?.name;
    const names: Names = {
      project: (id) => projectById.get(id),
      environment: (id) => envById.get(id),
      team: teamName,
    };
    const nameOf = (id: string | null | undefined): string => {
      if (!id) return "unknown";
      return (
        identities.data?.items.find((i) => i.id === id)?.name ??
        groups.data?.items.find((g) => g.id === id)?.name ??
        teamName(id) ??
        shortId(id)
      );
    };
    const roleName = (id: string | null | undefined) => (id ? (roles.data?.items.find((r) => r.id === id)?.name ?? "a role") : null);
    return { names, nameOf, roleName, projects: projects.data?.items ?? [], environments: envList };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projects.data, envKey, identities.data, groups.data, teams.data, roles.data]);
}
