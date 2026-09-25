// SPDX-License-Identifier: Apache-2.0
import { canonicalJson } from "./canonical.js";
import { semanticsVersionOf } from "./semantics.js";
import type {
  ConfigurationContract,
  ContractItem,
  ItemType,
  Requiredness,
} from "./types.js";

/**
 * Semantic diff between two canonical Contracts (ADR-0013 §14): sensitivity
 * flips, item additions/removals, requiredness/applicability changes must be
 * distinguishable from cosmetic edits in audit and UI.
 */
export interface ContractDiff {
  itemsAdded: string[];
  itemsRemoved: string[];
  sensitivityChanged: { name: string; from: boolean; to: boolean }[];
  requirednessChanged: { name: string; from: Requiredness; to: Requiredness }[];
  typeChanged: { name: string; from: ItemType; to: ItemType }[];
  /** description/default/example/enum value edits — cosmetic. */
  otherChanged: string[];
  /** Set when the revisions are evaluated with different Contract Semantics. */
  semanticsVersionChanged: { from: number; to: number } | null;
  /** True when the diff includes authorization-relevant changes. */
  securityRelevant: boolean;
}

function cosmeticFingerprint(item: ContractItem): string {
  return canonicalJson({
    defaultValue: item.defaultValue,
    description: item.description,
    enumValues: item.enumValues,
    example: item.example,
    rotationGraceSeconds: item.rotationGraceSeconds,
  });
}

export function diffContracts(
  from: ConfigurationContract,
  to: ConfigurationContract,
): ContractDiff {
  const fromByName = new Map(from.items.map((i) => [i.name, i]));
  const toByName = new Map(to.items.map((i) => [i.name, i]));

  const diff: ContractDiff = {
    itemsAdded: [],
    itemsRemoved: [],
    sensitivityChanged: [],
    requirednessChanged: [],
    typeChanged: [],
    otherChanged: [],
    semanticsVersionChanged: null,
    securityRelevant: false,
  };
  const fromVersion = semanticsVersionOf(from);
  const toVersion = semanticsVersionOf(to);
  if (fromVersion !== toVersion) diff.semanticsVersionChanged = { from: fromVersion, to: toVersion };

  for (const name of toByName.keys()) {
    if (!fromByName.has(name)) diff.itemsAdded.push(name);
  }
  for (const name of fromByName.keys()) {
    if (!toByName.has(name)) diff.itemsRemoved.push(name);
  }

  for (const [name, a] of fromByName) {
    const b = toByName.get(name);
    if (!b) continue;
    if (a.sensitive !== b.sensitive) {
      diff.sensitivityChanged.push({ name, from: a.sensitive, to: b.sensitive });
    }
    if (canonicalJson(a.required) !== canonicalJson(b.required)) {
      diff.requirednessChanged.push({ name, from: a.required, to: b.required });
    }
    if (a.type !== b.type) {
      diff.typeChanged.push({ name, from: a.type, to: b.type });
    }
    if (cosmeticFingerprint(a) !== cosmeticFingerprint(b)) {
      diff.otherChanged.push(name);
    }
  }

  diff.securityRelevant =
    diff.itemsAdded.length > 0 ||
    diff.itemsRemoved.length > 0 ||
    diff.sensitivityChanged.length > 0 ||
    diff.requirednessChanged.length > 0;

  return diff;
}
