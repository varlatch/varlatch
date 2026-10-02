// SPDX-License-Identifier: AGPL-3.0-or-later
import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import type { Project } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { useCapability } from "./hooks";

/**
 * "Updated 4m ago by …" for a project, from its newest audit event. Only
 * servers advertising `audit.filters` can filter the audit list by project;
 * everywhere else this stays off and the column is not shown.
 */

/** The audit list options on servers with `audit.filters`. */
type FilteredAuditList = (
  org: string,
  opts: { limit?: number; cursor?: string; projectId?: string },
) => Promise<{ items: Record<string, unknown>[] }>;

export type ProjectLastChange = { at: string; actorIdentityId: string | null };

export function useAuditFilters(): boolean {
  return useCapability("audit.filters");
}

export function useProjectLastChange(org: string, project: Project, enabled: boolean) {
  const { api } = useSession();
  const supported = useAuditFilters();
  return useQuery({
    queryKey: ["project-last-change", org, project.id],
    enabled: supported && enabled,
    retry: false,
    staleTime: 60_000,
    queryFn: async (): Promise<ProjectLastChange | null> => {
      const list = api.listAuditEvents.bind(api) as FilteredAuditList;
      const page = await list(org, { projectId: project.id, limit: 1 });
      const event = page.items[0];
      // Trust only an event about this project: a client that drops the
      // filter would otherwise attribute another project's change.
      const resource = event?.resource as { projectId?: unknown } | null | undefined;
      if (!event || resource?.projectId !== project.id || typeof event.occurredAt !== "string") return null;
      const actor = event.actorIdentityId;
      return { at: event.occurredAt, actorIdentityId: typeof actor === "string" ? actor : null };
    },
  });
}

/** Display names for actors; null when the caller may not list identities. */
export function useIdentityNames(org: string, enabled: boolean): Map<string, string> | null {
  const { api } = useSession();
  const identities = useQuery({
    queryKey: ["identities", org],
    queryFn: () => api.listIdentities(org),
    enabled,
    retry: false,
  });
  const data = identities.data;
  return useMemo(() => (data ? new Map(data.items.map((i) => [i.id, i.name])) : null), [data]);
}
