// SPDX-License-Identifier: AGPL-3.0-or-later
import { useMemo } from "react";
import { useQueries, useQuery } from "@tanstack/react-query";
import type { EffectiveConfiguration, Environment, SyncTarget } from "@varlatch/protocol";
import type { VarlatchClient } from "@varlatch/sdk";
import { useSession } from "../../lib/session";
import { isTailnetDenial, isTailnetOnly } from "../../lib/tailnet";
import { keys, useCapability } from "../projects/hooks";
import { contractItemsOf, type ContractItemMeta, type ServerItem } from "./model";

/**
 * Queries behind the values screens. Only metadata and non-sensitive
 * plaintext enter the React Query cache; Secrets come from the explicit
 * disclosure call and stay in component memory (`useDisclosure`).
 */

/** The active contract's items by name; a project without one has none. */
export function useContractItems(org: string, project: string) {
  const { api } = useSession();
  // Same key and query function as the Contract tab, so the caches agree.
  const query = useQuery({
    queryKey: keys.contract(org, project),
    queryFn: () => api.getActiveContract(org, project),
    retry: false,
  });
  const items = useMemo(() => contractItemsOf(query.data), [query.data]);
  const byName = useMemo(() => new Map(items.map((i) => [i.name, i])), [items]);
  return { items, byName, isLoading: query.isLoading, revision: query.data };
}

export type EnvValues = {
  items: ServerItem[];
  byName: Map<string, ServerItem>;
  /** Non-sensitive values this caller may not read: show state only. */
  withheld: Set<string>;
  /**
   * A Tailnet Requirement covers the environment: every value read needs
   * Tailnet Context the dashboard never has, so names and states only.
   */
  tailnetOnly: boolean;
};

function toEnvValues(result: EffectiveConfiguration): EnvValues {
  const items = result.items ?? [];
  const withheld = new Set((result.callerView?.withheld ?? []).map((w) => w.name));
  // Older servers: a non-sensitive item with a null value was withheld.
  for (const i of items) if (!i.sensitive && i.value === null) withheld.add(i.name);
  return { items, byName: new Map(items.map((i) => [i.name, i])), withheld, tailnetOnly: false };
}

function tailnetOnlyValues(result: EffectiveConfiguration): EnvValues {
  const items = result.items ?? [];
  const withheld = new Set(items.filter((i) => !i.sensitive).map((i) => i.name));
  return { items, byName: new Map(items.map((i) => [i.name, i])), withheld, tailnetOnly: true };
}

/**
 * A tailnet-only environment loads metadata only: asking for values there
 * fails and records a denial on every load. A Requirement added since the
 * environment list loaded is caught the same way, from the denial.
 */
export async function loadEnvValues(api: VarlatchClient, org: string, project: string, env: Environment): Promise<EnvValues> {
  if (isTailnetOnly(env)) return tailnetOnlyValues(await api.effectiveConfiguration(org, project, env.name));
  try {
    return toEnvValues(await api.effectiveConfiguration(org, project, env.name, { includeValues: true }));
  } catch (err) {
    if (!isTailnetDenial(err)) throw err;
    return tailnetOnlyValues(await api.effectiveConfiguration(org, project, env.name));
  }
}

const valuesKey = (org: string, project: string, env: Environment) =>
  [...keys.effectiveValues(org, project, env.name), isTailnetOnly(env)] as const;

/** Effective configuration with non-sensitive values, for one environment. */
export function useEnvValues(org: string, project: string, env: Environment) {
  const { api } = useSession();
  return useQuery({
    queryKey: valuesKey(org, project, env),
    queryFn: () => loadEnvValues(api, org, project, env),
  });
}

/** The same, for several environments at once (the grid's columns). */
export function useManyEnvValues(org: string, project: string, envs: Environment[]) {
  const { api } = useSession();
  return useQueries({
    queries: envs.map((env) => ({
      queryKey: valuesKey(org, project, env),
      queryFn: () => loadEnvValues(api, org, project, env),
    })),
  });
}

export function usePlatformConnections(org: string) {
  const { api } = useSession();
  return useQuery({
    queryKey: ["platform-connections", org],
    queryFn: () => api.listPlatformConnections(org),
    retry: false,
  });
}

/** Sync targets of a project's environments, keyed by environment id. */
export function useProjectSyncTargets(org: string, projectId: string): Map<string, SyncTarget[]> {
  const { api } = useSession();
  const targets = useQuery({
    queryKey: keys.orgSyncTargets(org),
    queryFn: () => api.listOrgSyncTargets(org),
    retry: false,
  });
  return useMemo(() => {
    const map = new Map<string, SyncTarget[]>();
    for (const t of targets.data?.items ?? []) {
      if (t.projectId !== projectId) continue;
      map.set(t.environmentId, [...(map.get(t.environmentId) ?? []), t]);
    }
    return map;
  }, [targets.data, projectId]);
}

/** One environment's sync targets (shares the layout's query). */
export function useEnvSyncTargets(org: string, project: string, env: string) {
  const { api } = useSession();
  return useQuery({
    queryKey: keys.syncTargets(org, project, env),
    queryFn: () => api.listSyncTargets(org, project, env),
    retry: false,
  });
}

/** Event types that change a value here; reads, reveals and denials are not changes. */
const VALUE_CHANGES = ["value.written", "value.rotation_started"] as const;

/**
 * When each item last changed in this environment, from filtered audit
 * queries by exact event type (servers with audit.filters, callers who may
 * read the audit log), so frequent reads never crowd changes out. Items
 * whose last change is older than the newest 200 of a type have no entry:
 * the screen shows nothing rather than a guess.
 */
export function useItemChanges(org: string, environmentId: string) {
  const { api } = useSession();
  const supported = useCapability("audit.filters");
  return useQuery({
    queryKey: ["item-changes", org, environmentId],
    enabled: supported,
    retry: false,
    staleTime: 30_000,
    queryFn: async () => {
      const pages = await Promise.all(
        VALUE_CHANGES.map((eventType) => api.listAuditEvents(org, { environmentId, eventType, limit: 200 })),
      );
      const changed: Record<string, string> = {};
      for (const e of pages.flatMap((p) => p.items)) {
        const item = (e.resource as { itemName?: unknown } | undefined)?.itemName;
        if (e.decision === "deny" || typeof item !== "string" || typeof e.occurredAt !== "string") continue;
        if (!changed[item] || e.occurredAt > changed[item]) changed[item] = e.occurredAt;
      }
      return changed;
    },
  });
}

export type { ContractItemMeta };
