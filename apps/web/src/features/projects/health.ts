// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Environment, Tier } from "@varlatch/protocol";

/**
 * Environment health from metadata only (the same rules as the project
 * values matrix): a required Config Item with no value and no default is
 * missing; a default covers it. Values are never read here.
 */

export interface ContractItemMeta {
  name: string;
  sensitive?: boolean;
  required: { kind: string; selector?: { kind: string; tier?: Tier; environmentIds?: string[] } };
  defaultValue?: string;
}

/** The items of a contract revision's body, tolerating an absent body. */
export function contractItems(contract: unknown): ContractItemMeta[] {
  const items = (contract as { items?: unknown } | null | undefined)?.items;
  return Array.isArray(items) ? (items as ContractItemMeta[]) : [];
}

export function requiredHere(item: ContractItemMeta, env: Pick<Environment, "id" | "tier">): boolean {
  const r = item.required;
  if (r.kind === "always") return true;
  if (r.kind === "never") return false;
  if (r.selector?.kind === "tier") return r.selector.tier === env.tier;
  if (r.selector?.kind === "environments") return r.selector.environmentIds?.includes(env.id) ?? false;
  return false;
}

/** Required items without a value or default in this environment. */
export function missingRequired(
  items: ContractItemMeta[],
  env: Pick<Environment, "id" | "tier">,
  present: ReadonlySet<string>,
): string[] {
  return items
    .filter((i) => requiredHere(i, env) && i.defaultValue === undefined && !present.has(i.name))
    .map((i) => i.name)
    .sort();
}

export type EnvHealth =
  | { state: "loading" }
  /** The caller cannot read the contract or the environment's metadata: say nothing. */
  | { state: "unknown" }
  /** No active contract: nothing is required yet. */
  | { state: "no-contract" }
  | { state: "ok" }
  | { state: "missing"; items: string[] };

export function environmentHealth(input: {
  contract: "loading" | "none" | "unreadable" | ContractItemMeta[];
  presence: "loading" | "unreadable" | ReadonlySet<string>;
  env: Pick<Environment, "id" | "tier">;
}): EnvHealth {
  const { contract, presence, env } = input;
  if (contract === "unreadable" || presence === "unreadable") return { state: "unknown" };
  if (contract === "loading" || presence === "loading") return { state: "loading" };
  if (contract === "none") return { state: "no-contract" };
  const missing = missingRequired(contract, env, presence);
  return missing.length > 0 ? { state: "missing", items: missing } : { state: "ok" };
}

/** Distinct Config Item names across the contract and every readable environment. */
export function itemCount(contract: ContractItemMeta[], presence: ReadonlySet<string>[]): number {
  const names = new Set(contract.map((i) => i.name));
  for (const set of presence) for (const n of set) names.add(n);
  return names.size;
}
