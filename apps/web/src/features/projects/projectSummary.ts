// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useRef, useState, type RefCallback } from "react";
import { useQueries, useQuery } from "@tanstack/react-query";
import { VarlatchApiError } from "@varlatch/sdk";
import type { Environment, Project } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { contractItems, environmentHealth, itemCount, type ContractItemMeta, type EnvHealth } from "./health";
import { keys, sortEnvironments } from "./hooks";

/**
 * Metadata a project row needs: environments, the active contract and which
 * items each root environment has. Names and presence only, never values.
 * Every query uses the shared keys, so the values grid and this list share
 * one cache, and `enabled` lets rows load lazily as they scroll into view.
 */
export function useProjectSummary(org: string, project: Project, enabled: boolean) {
  const { api } = useSession();
  const envs = useQuery({
    queryKey: keys.environments(org, project.slug),
    queryFn: () => api.listEnvironments(org, project.slug),
    enabled,
  });
  // A project without an active revision has nothing to fetch.
  const hasContract = project.activeContractRevisionId !== null;
  const contract = useQuery({
    queryKey: keys.contract(org, project.slug),
    queryFn: () => api.getActiveContract(org, project.slug),
    enabled: enabled && hasContract,
    retry: false,
  });
  const all = sortEnvironments(envs.data?.items ?? []);
  const roots = all.filter((e) => !e.parentEnvironmentId);
  const presence = useQueries({
    queries: roots.map((env) => ({
      queryKey: keys.effectiveMeta(org, project.slug, env.name),
      queryFn: () => api.effectiveConfiguration(org, project.slug, env.name),
      enabled,
      retry: false,
    })),
  });

  const contractState: "loading" | "none" | "unreadable" | ContractItemMeta[] = !hasContract
    ? "none"
    : contract.isPending
      ? "loading"
      : contract.data
        ? contractItems(contract.data.contract)
        : // No revision although the project names one: the caller may not read it.
          project.activeContractRevisionId === undefined && isNotFound(contract.error)
          ? "none"
          : "unreadable";

  const presenceSets = presence.map((q) =>
    q.isPending ? ("loading" as const) : q.data ? new Set(q.data.items.map((i) => i.name)) : ("unreadable" as const),
  );
  const health: { env: Environment; health: EnvHealth }[] = roots.map((env, i) => ({
    env,
    health: environmentHealth({ contract: contractState, presence: presenceSets[i] ?? "loading", env }),
  }));
  const readable = presenceSets.filter((p): p is Set<string> => p instanceof Set);
  const settled = presenceSets.every((p) => p !== "loading");
  const items =
    envs.isSuccess && settled && (Array.isArray(contractState) || contractState === "none")
      ? itemCount(Array.isArray(contractState) ? contractState : [], readable)
      : undefined;

  return {
    environments: all,
    roots,
    derived: all.length - roots.length,
    envsLoading: envs.isPending,
    envsError: envs.isError,
    contract: contractState,
    health,
    items,
  };
}

function isNotFound(err: unknown): boolean {
  return err instanceof VarlatchApiError && err.status === 404;
}

/** True once the element has come near the viewport; stays true. */
export function useSeen<T extends Element>(margin = "200px"): [RefCallback<T>, boolean] {
  const [seen, setSeen] = useState(false);
  const observer = useRef<IntersectionObserver | null>(null);
  useEffect(() => () => observer.current?.disconnect(), []);
  const ref = useCallback((el: T | null) => {
    observer.current?.disconnect();
    if (!el || seen) return;
    if (typeof IntersectionObserver === "undefined") {
      setSeen(true);
      return;
    }
    observer.current = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setSeen(true);
          observer.current?.disconnect();
        }
      },
      { rootMargin: margin },
    );
    observer.current.observe(el);
  }, [seen, margin]);
  return [ref, seen];
}
