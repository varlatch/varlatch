// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useMemo } from "react";
import { useQueries, useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";
import type { EffectiveConfiguration, Environment, SyncTarget, TailnetDevice } from "@varlatch/protocol";
import type { Page, VarlatchClient } from "@varlatch/sdk";
import { useSession } from "../../lib/session";
import { isTailnetDenial, isTailnetOnly } from "../../lib/tailnet";
import { TailnetUnreachableError, tailnetReadKey, useTailnetConnection, type TailnetConnection } from "../../lib/tailnetConnection";
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
   * A Tailnet Requirement covers the environment and this tab cannot read
   * its values: names and states only.
   */
  tailnetOnly: boolean;
  /** Values read through the tailnet browser endpoint, as this device (ADR-0046). */
  viaTailnet?: TailnetDevice | undefined;
  /** Through the endpoint, this device did not meet the environment's Requirements. */
  deviceRefused?: boolean | undefined;
};

/** The endpoint client and the device it was checked as, while this tab is connected. */
export type TailnetReader = { client: VarlatchClient; device: TailnetDevice } | null;

export function tailnetReader(connection: TailnetConnection, client: VarlatchClient | null): TailnetReader {
  return connection.status === "connected" && client ? { client, device: connection.device } : null;
}

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
 * A protected environment's values never come from the dashboard's own
 * origin, where they can only be refused: through the tailnet endpoint
 * when this tab is connected, otherwise metadata only (ADR-0046 Decision 5).
 */
async function loadProtected(api: VarlatchClient, tailnet: TailnetReader, org: string, project: string, env: Environment): Promise<EnvValues> {
  if (tailnet) {
    try {
      return { ...toEnvValues(await tailnet.client.effectiveConfiguration(org, project, env.name, { includeValues: true })), viaTailnet: tailnet.device };
    } catch (err) {
      if (isTailnetDenial(err)) return { ...tailnetOnlyValues(await api.effectiveConfiguration(org, project, env.name)), deviceRefused: true };
      // No answer: the connection is being checked again; show what the dashboard may.
      if (!(err instanceof TailnetUnreachableError)) throw err;
    }
  }
  return tailnetOnlyValues(await api.effectiveConfiguration(org, project, env.name));
}

/**
 * A Requirement the page did not know about, found by a denial on the
 * dashboard's origin: the cached environment list says so at once, so
 * every later read follows the protected path, and the list is refetched.
 */
export function markTailnetOnly(qc: QueryClient, org: string, project: string, envName: string) {
  qc.setQueryData<Page<Environment>>(keys.environments(org, project), (page) =>
    page ? { ...page, items: page.items.map((e) => (e.name === envName ? { ...e, tailnetRequired: true } : e)) } : page,
  );
  void qc.invalidateQueries({ queryKey: keys.environments(org, project) });
}

/**
 * A tailnet-only environment loads metadata only, or its values through the
 * endpoint: asking the dashboard's origin for them fails and records a
 * denial on every load. A Requirement added since the environment list
 * loaded is caught the same way, from the denial.
 */
export async function loadEnvValues(
  api: VarlatchClient,
  org: string,
  project: string,
  env: Environment,
  tailnet: TailnetReader = null,
  onTailnetOnly: (env: string) => void = () => {},
): Promise<EnvValues> {
  if (isTailnetOnly(env)) return loadProtected(api, tailnet, org, project, env);
  try {
    return toEnvValues(await api.effectiveConfiguration(org, project, env.name, { includeValues: true }));
  } catch (err) {
    if (!isTailnetDenial(err)) throw err;
    onTailnetOnly(env.name);
    return loadProtected(api, tailnet, org, project, env);
  }
}

/** Values read through the endpoint are cached apart, per device, and only for protected environments. */
const valuesKey = (org: string, project: string, env: Environment, readKey: string) =>
  [...keys.effectiveValues(org, project, env.name), isTailnetOnly(env), isTailnetOnly(env) ? readKey : "ordinary"] as const;

/**
 * Once an environment turns tailnet-only, drop what was cached before: its
 * non-sensitive plaintext, under the key without the restriction.
 */
function useForgetUnrestricted(org: string, project: string, envs: Environment[]) {
  const qc = useQueryClient();
  const tailnetOnly = envs.filter(isTailnetOnly).map((e) => e.name).join("\u0000");
  useEffect(() => {
    for (const env of tailnetOnly ? tailnetOnly.split("\u0000") : []) {
      qc.removeQueries({ queryKey: [...keys.effectiveValues(org, project, env), false] });
    }
  }, [qc, org, project, tailnetOnly]);
}

function useValuesLoader(org: string, project: string) {
  const { api } = useSession();
  const qc = useQueryClient();
  const { connection, client } = useTailnetConnection();
  const tailnet = tailnetReader(connection, client);
  return {
    readKey: tailnetReadKey(connection),
    load: (env: Environment) => loadEnvValues(api, org, project, env, tailnet, (name) => markTailnetOnly(qc, org, project, name)),
  };
}

/** Effective configuration with non-sensitive values, for one environment. */
export function useEnvValues(org: string, project: string, env: Environment) {
  const { readKey, load } = useValuesLoader(org, project);
  useForgetUnrestricted(org, project, [env]);
  return useQuery({
    queryKey: valuesKey(org, project, env, readKey),
    queryFn: () => load(env),
  });
}

/** The same, for several environments at once (the grid's columns). */
export function useManyEnvValues(org: string, project: string, envs: Environment[]) {
  const { readKey, load } = useValuesLoader(org, project);
  useForgetUnrestricted(org, project, envs);
  return useQueries({
    queries: envs.map((env) => ({
      queryKey: valuesKey(org, project, env, readKey),
      queryFn: () => load(env),
    })),
  });
}

/**
 * How an environment's values stand in this tab: protected by a Tailnet
 * Requirement or not, and if protected, whether they were read through the
 * endpoint (`readable`) or are held back (`blocked`).
 */
export function tailnetAccess(env: Environment | undefined, values: EnvValues | undefined) {
  const isProtected = isTailnetOnly(env) || values?.tailnetOnly === true || values?.viaTailnet !== undefined;
  const readable = isProtected && values?.viaTailnet !== undefined && !values.tailnetOnly;
  return { isProtected, readable, blocked: isProtected && !readable, device: values?.viaTailnet, deviceRefused: values?.deviceRefused === true };
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
