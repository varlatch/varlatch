// SPDX-License-Identifier: Apache-2.0
import {
  normalizeContract,
  type ConfigurationContract,
  type ContractItem,
  type Requiredness,
} from "@varlatch/contract";
import type { ContractDraft, DraftItem } from "./parse.js";

/**
 * Resolve a Contract draft into the canonical Contract. `env(...)` names are
 * resolved against the project's live Environments at push time: each must
 * name a root Environment, and an unknown or derived name fails loudly
 * (ADR-0013 §12), never approximated, broadened, or dropped.
 *
 * The stored revision keeps the IDs resolved here. A later push resolves the
 * names again, so a renamed Environment's old name fails, and a name reused
 * by a different Environment selects that Environment.
 */

/** The fields of an Environment that name resolution needs. */
export interface EnvironmentRef {
  id: string;
  name: string;
  parentEnvironmentId: string | null;
}

export class UnknownEnvironmentNameError extends Error {
  override name = "UnknownEnvironmentNameError";
  readonly unknown: string[];
  readonly derived: string[];
  constructor(unknown: string[], derived: string[], roots: string[]) {
    const parts: string[] = [];
    if (unknown.length > 0) parts.push(`unknown environment name(s) in env(...): ${unknown.join(", ")}`);
    if (derived.length > 0) {
      parts.push(`derived environment(s) in env(...): ${derived.join(", ")}; env(...) names root environments`);
    }
    super(
      `${parts.join("; ")}. This project's root environments: ${roots.length > 0 ? roots.join(", ") : "(none)"}.`,
    );
    this.unknown = unknown;
    this.derived = derived;
  }
}

function resolveRequired(
  item: DraftItem,
  defaults: ContractDraft["defaults"],
  byName: Map<string, EnvironmentRef>,
  unknown: Set<string>,
  derived: Set<string>,
): Requiredness {
  const required = item.required ?? defaults.required;
  switch (required.kind) {
    case "always":
    case "never":
      return required;
    case "tier":
      return { kind: "selector", selector: { kind: "tier", tier: required.tier } };
    case "environments": {
      const ids: string[] = [];
      for (const name of required.names) {
        const env = byName.get(name);
        if (!env) unknown.add(name);
        else if (env.parentEnvironmentId !== null) derived.add(name);
        else ids.push(env.id);
      }
      return { kind: "selector", selector: { kind: "environments", environmentIds: ids } };
    }
  }
}

export function resolveDraft(
  draft: ContractDraft,
  environments: EnvironmentRef[],
): ConfigurationContract {
  const byName = new Map(environments.map((e) => [e.name, e]));
  const unknown = new Set<string>();
  const derived = new Set<string>();
  const items: ContractItem[] = draft.items.map((item) => {
    const resolved: ContractItem = {
      name: item.name,
      required: resolveRequired(item, draft.defaults, byName, unknown, derived),
      sensitive: item.sensitive ?? draft.defaults.sensitive,
      type: item.type,
    };
    if (item.enumValues) resolved.enumValues = item.enumValues;
    if (item.defaultValue !== undefined) resolved.defaultValue = item.defaultValue;
    if (item.description !== undefined) resolved.description = item.description;
    if (item.example !== undefined) resolved.example = item.example;
    return resolved;
  });
  if (unknown.size > 0 || derived.size > 0) {
    const roots = environments
      .filter((e) => e.parentEnvironmentId === null)
      .map((e) => e.name)
      .sort();
    throw new UnknownEnvironmentNameError([...unknown].sort(), [...derived].sort(), roots);
  }
  // The file names no semantics version: the push leaves it to the server
  // (the active revision's, or the newest for a first revision), so the
  // check that each type exists at that version waits for the decision.
  return normalizeContract({ schemaVersion: 1, items }, { versionUndecided: true });
}
