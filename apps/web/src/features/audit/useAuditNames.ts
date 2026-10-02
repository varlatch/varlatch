// SPDX-License-Identifier: AGPL-3.0-or-later
import { useMemo } from "react";
import { useQueries, useQuery } from "@tanstack/react-query";
import type { Environment, PlatformConnection } from "@varlatch/protocol";
import type { OrgIdentity } from "@varlatch/sdk";
import { useSession } from "../../lib/session";
import { keys, useProjects } from "../projects/hooks";
import { connectionsKey } from "../sync/keys";
import { targetLabel } from "../sync/status";
import type { NameResolver } from "./describe";

/**
 * Names for the IDs audit events carry: identities, projects, environments,
 * connections, integrations, roles and groups. Every list is optional: a
 * caller who cannot read one simply sees the neutral noun instead.
 */
export function useAuditNames(org: string): {
  names: NameResolver;
  identities: OrgIdentity[];
  identityById: Map<string, OrgIdentity>;
  environments: Environment[];
} {
  const { api } = useSession();
  const quiet = { retry: false, staleTime: 60_000 } as const;
  const identities = useQuery({ queryKey: ["identities", org], queryFn: () => api.listIdentities(org), ...quiet });
  const projects = useProjects(org);
  const envQueries = useQueries({
    queries: (projects.data?.items ?? []).map((p) => ({
      queryKey: keys.environments(org, p.slug),
      queryFn: () => api.listEnvironments(org, p.slug),
      ...quiet,
    })),
  });
  const connections = useQuery({ queryKey: connectionsKey(org), queryFn: () => api.listPlatformConnections(org), ...quiet });
  const targets = useQuery({ queryKey: keys.orgSyncTargets(org), queryFn: () => api.listOrgSyncTargets(org), ...quiet });
  const roles = useQuery({ queryKey: ["roles", org], queryFn: () => api.listRoles(org), ...quiet });
  const groups = useQuery({ queryKey: ["groups", org], queryFn: () => api.listGroups(org), ...quiet });
  const teams = useQuery({ queryKey: ["teams", org], queryFn: () => api.listTeams(org), ...quiet });

  const envData = envQueries.map((q) => q.data);
  // One string dependency: the number of projects (and so of queries) varies.
  const envStamp = envQueries.map((q) => q.dataUpdatedAt).join(",");
  return useMemo(() => {
    const identityById = new Map((identities.data?.items ?? []).map((i) => [i.id, i]));
    const projectById = new Map((projects.data?.items ?? []).map((p) => [p.id, p.slug]));
    const environments = envData.flatMap((d) => d?.items ?? []);
    const envById = new Map(environments.map((e) => [e.id, e]));
    const connById = new Map<string, PlatformConnection>((connections.data?.items ?? []).map((c) => [c.id, c]));
    const targetById = new Map((targets.data?.items ?? []).map((t) => [t.id, t]));
    const roleById = new Map((roles.data?.items ?? []).map((r) => [r.id, r.name]));
    const groupById = new Map([...(groups.data?.items ?? []), ...(teams.data?.items ?? [])].map((g) => [g.id, g.name]));
    const names: NameResolver = {
      identity: (id) => (id ? identityById.get(id)?.name : undefined),
      project: (id) => (id ? projectById.get(id) : undefined),
      environment: (id) => {
        const e = id ? envById.get(id) : undefined;
        return e ? { name: e.name, projectId: e.projectId } : undefined;
      },
      connection: (id) => (id ? connById.get(id)?.name : undefined),
      target: (id) => {
        const t = id ? targetById.get(id) : undefined;
        return t ? targetLabel(t, connById.get(t.connectionId)) : undefined;
      },
      role: (id) => (id ? roleById.get(id) : undefined),
      group: (id) => (id ? groupById.get(id) : undefined),
    };
    return { names, identities: identities.data?.items ?? [], identityById, environments };
    // envData is a fresh array each render; envStamp says when it changed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [identities.data, projects.data, connections.data, targets.data, roles.data, groups.data, teams.data, envStamp]);
}
