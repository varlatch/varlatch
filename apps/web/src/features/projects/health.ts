// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Environment } from "@varlatch/protocol";
import { requiredHere, type ContractItemMeta } from "../values/model";

/**
 * Environment health from metadata only, with the same rules as the values
 * grid (`requiredHere` is shared): a required Config Item with no value and no default is
 * missing; a default covers it. Values are never read here.
 */

export { requiredHere };
export type { ContractItemMeta };

/** The items of a contract revision's body, tolerating an absent body. */
export function contractItems(contract: unknown): ContractItemMeta[] {
  const items = (contract as { items?: unknown } | null | undefined)?.items;
  return Array.isArray(items) ? (items as ContractItemMeta[]) : [];
}

/** Required items without a value or default in this environment. */
export function missingRequired(
  items: ContractItemMeta[],
  env: Environment,
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
  env: Environment;
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
