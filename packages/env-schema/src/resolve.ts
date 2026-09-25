// SPDX-License-Identifier: Apache-2.0
import {
  normalizeContract,
  type ConfigurationContract,
  type ContractItem,
  type Requiredness,
} from "@varlatch/contract";
import type { ContractDraft, DraftItem } from "./parse.js";

/**
 * Resolve a Contract draft into the canonical Contract using the Project's
 * Varlock Environment Mapping (varlock name -> root Environment ID, fetched
 * from varlatchd). Unmapped forEnv names fail loudly (ADR-0013 §12) — never
 * approximated, broadened, or dropped.
 */

export class UnmappedVarlockEnvironmentError extends Error {
  override name = "UnmappedVarlockEnvironmentError";
  readonly names: string[];
  constructor(names: string[]) {
    super(
      `Unmapped Varlock environment name(s): ${names.join(", ")}. ` +
        "Set the Project's Varlock Environment Mapping first " +
        "(varlatch varlock-mapping set <name> <environment>).",
    );
    this.names = names;
  }
}

function resolveRequired(
  item: DraftItem,
  defaults: ContractDraft["defaults"],
  mapping: Record<string, string>,
  unmapped: Set<string>,
): Requiredness {
  const required = item.required ?? defaults.required;
  if (required.kind === "always" || required.kind === "never") return required;
  if (required.kind === "forEnv") {
    const ids: string[] = [];
    for (const name of required.varlockNames) {
      const id = mapping[name];
      if (!id) unmapped.add(name);
      else ids.push(id);
    }
    return { kind: "selector", selector: { kind: "environments", environmentIds: ids } };
  }
  return required;
}

export function resolveDraft(
  draft: ContractDraft,
  mapping: Record<string, string>,
): ConfigurationContract {
  const unmapped = new Set<string>();
  const items: ContractItem[] = draft.items.map((item) => {
    const resolved: ContractItem = {
      name: item.name,
      required: resolveRequired(item, draft.defaults, mapping, unmapped),
      sensitive: item.sensitive ?? draft.defaults.sensitive,
      type: item.type,
    };
    if (item.enumValues) resolved.enumValues = item.enumValues;
    if (item.defaultValue !== undefined) resolved.defaultValue = item.defaultValue;
    if (item.description !== undefined) resolved.description = item.description;
    if (item.example !== undefined) resolved.example = item.example;
    return resolved;
  });
  if (unmapped.size > 0) {
    throw new UnmappedVarlockEnvironmentError([...unmapped].sort());
  }
  return normalizeContract({ schemaVersion: 1, items });
}
