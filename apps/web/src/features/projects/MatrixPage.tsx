// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQueries, useQuery } from "@tanstack/react-query";
import { Check, CircleDashed, CircleDot, TriangleAlert } from "lucide-react";
import type { Environment, Tier } from "@varlatch/protocol";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { Card, Mono, TierChip, cn } from "../../components/ui";

/**
 * The project landing matrix (design R1 §Q4 / R2 §Q1): rows = Config Items,
 * columns = root Environments, cells = configuration state from authoritative
 * metadata only — never plaintext, never invented permission states.
 */

type CellState = "set" | "unset_optional" | "missing_required" | "covered_by_default";

interface ContractItemMeta {
  name: string;
  sensitive: boolean;
  required: { kind: string; selector?: { kind: string; tier?: Tier; environmentIds?: string[] } };
  defaultValue?: string;
}

function requiredHere(item: ContractItemMeta, env: Environment): boolean {
  const r = item.required;
  if (r.kind === "always") return true;
  if (r.kind === "never") return false;
  if (r.selector?.kind === "tier") return r.selector.tier === env.tier;
  if (r.selector?.kind === "environments") {
    return r.selector.environmentIds?.includes(env.id) ?? false;
  }
  return false;
}

const CELL: Record<CellState, { icon: React.ReactNode; label: string; className: string }> = {
  set: { icon: <CircleDot size={14} />, label: "set", className: "text-allow" },
  covered_by_default: { icon: <Check size={14} />, label: "default", className: "text-muted" },
  unset_optional: { icon: <CircleDashed size={14} />, label: "—", className: "text-muted/50" },
  missing_required: { icon: <TriangleAlert size={14} />, label: "missing", className: "text-deny" },
};

export function MatrixPage() {
  const { org, project } = useParams() as { org: string; project: string };
  const { api } = useSession();
  useOrgRealtime(
    org,
    ["environment", "contract", "value"],
    [
      ["environments", org, project],
      ["contract", org, project],
      ["effective-meta", org, project],
    ],
  );
  const [expandedRoot, setExpandedRoot] = useState<string | null>(null);

  const envsQuery = useQuery({
    queryKey: ["environments", org, project],
    queryFn: () => api.listEnvironments(org, project),
  });
  const contractQuery = useQuery({
    queryKey: ["contract", org, project],
    queryFn: () => api.getActiveContract(org, project).catch(() => null),
  });

  const environments = envsQuery.data?.items ?? [];
  const roots = environments.filter((e) => !e.parentEnvironmentId);
  const derivedByRoot = useMemo(() => {
    const map = new Map<string, Environment[]>();
    for (const env of environments) {
      if (env.parentEnvironmentId) {
        map.set(env.parentEnvironmentId, [...(map.get(env.parentEnvironmentId) ?? []), env]);
      }
    }
    return map;
  }, [environments]);

  // Presence metadata per root environment (authorized metadata only).
  const presence = useQueries({
    queries: roots.map((env) => ({
      queryKey: ["effective-meta", org, project, env.name],
      queryFn: () => api.effectiveConfiguration(org, project, env.name),
    })),
  });

  const contractItems: ContractItemMeta[] =
    ((contractQuery.data?.contract as { items?: ContractItemMeta[] } | undefined)?.items ?? []);

  const rowNames = useMemo(() => {
    const names = new Set<string>(contractItems.map((i) => i.name));
    for (const q of presence) for (const item of q.data?.items ?? []) names.add(item.name);
    return [...names].sort();
  }, [contractItems, presence]);

  const cellState = (name: string, envIndex: number): CellState => {
    const env = roots[envIndex] as Environment;
    const present = presence[envIndex]?.data?.items?.some((i) => i.name === name) ?? false;
    if (present) return "set";
    const contractItem = contractItems.find((i) => i.name === name);
    if (contractItem && requiredHere(contractItem, env)) {
      return contractItem.defaultValue !== undefined ? "covered_by_default" : "missing_required";
    }
    return "unset_optional";
  };

  if (envsQuery.isLoading) return <p className="text-muted">Loading…</p>;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <h1 className="text-lg font-semibold">{project}</h1>
        <Link className="text-sm text-muted hover:text-fg" to={`/o/${org}/p/${project}/contract`}>
          Contract
        </Link>
      </div>
      {roots.length === 0 && (
        <Card>
          <p className="text-muted text-sm">No environments yet — create them from the Projects page.</p>
        </Card>
      )}
      {roots.length > 0 && (
        <Card className="p-0 overflow-x-auto" data-testid="matrix">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-bd">
                <th className="px-3 py-2 text-left text-muted font-medium">Config Item</th>
                {roots.map((env) => {
                  const derived = derivedByRoot.get(env.id) ?? [];
                  return (
                    <th key={env.id} className="px-3 py-2 text-left font-medium">
                      <Link
                        to={`/o/${org}/p/${project}/e/${encodeURIComponent(env.name)}`}
                        className="hover:text-accent"
                      >
                        <Mono>{env.name}</Mono>
                      </Link>{" "}
                      <TierChip tier={env.tier as Tier} />
                      {derived.length > 0 && (
                        <button
                          className="ml-1 text-xs text-muted hover:text-fg cursor-pointer"
                          onClick={() => setExpandedRoot(expandedRoot === env.id ? null : env.id)}
                        >
                          +{derived.length} derived
                        </button>
                      )}
                      {expandedRoot === env.id && (
                        <div className="mt-1 space-y-0.5 font-normal">
                          {derived.map((d) => (
                            <Link
                              key={d.id}
                              className="block text-xs text-muted hover:text-accent"
                              to={`/o/${org}/p/${project}/e/${encodeURIComponent(d.name)}`}
                            >
                              {d.name} <span className="opacity-60">({d.kind})</span>
                            </Link>
                          ))}
                        </div>
                      )}
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody>
              {rowNames.map((name) => (
                <tr key={name} className="border-b border-bd/40">
                  <td className="px-3 py-1.5">
                    <Mono>{name}</Mono>
                    {contractItems.find((i) => i.name === name)?.sensitive && (
                      <span className="ml-2 text-[10px] uppercase tracking-wide text-muted">secret</span>
                    )}
                  </td>
                  {roots.map((env, idx) => {
                    const state = cellState(name, idx);
                    const cell = CELL[state];
                    return (
                      <td key={env.id} className="px-3 py-1.5" data-cell={`${name}:${env.name}:${state}`}>
                        <span
                          className={cn("inline-flex items-center gap-1.5 text-xs", cell.className)}
                          title={state.replace(/_/g, " ")}
                        >
                          {cell.icon}
                          {cell.label}
                        </span>
                      </td>
                    );
                  })}
                </tr>
              ))}
              {rowNames.length === 0 && (
                <tr>
                  <td colSpan={roots.length + 1} className="px-3 py-4 text-muted text-sm">
                    No configuration yet — open an environment to add values.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
