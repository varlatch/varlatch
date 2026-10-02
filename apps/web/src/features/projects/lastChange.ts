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

/** Event types that change a project; reads, reveals and denials do not count. */
const CHANGE = /^(value\.(written|deleted|rotation)|contract\.(revision_pushed|activated)|environment\.(created|deleted)|project\.(created|renamed)|sync\.target_)/;

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
      const page = await api.listAuditEvents(org, { projectId: project.id, limit: 25 });
      const event = page.items.find(
        (e) => typeof e.eventType === "string" && CHANGE.test(e.eventType) && e.decision !== "deny",
      );
      if (!event || typeof event.occurredAt !== "string") return null;
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
