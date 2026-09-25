// SPDX-License-Identifier: Apache-2.0
import type { ContractItem, Tier } from "./types.js";

/**
 * Contract Semantics: what a Contract item means for a value in an
 * Environment. Requiredness, validation, and (from a later version)
 * conversion are defined here once, so the server, the CLI, and generated
 * code apply the same rules.
 *
 * Rules are versioned. A version never changes once released: a different
 * result for any input is a new version. Golden vectors in
 * `test/vectors/` pin every version.
 */

export const SEMANTICS_VERSIONS = [1] as const;
export type SemanticsVersion = (typeof SEMANTICS_VERSIONS)[number];

/** The Environment facts requiredness depends on. */
export interface SemanticsEnvironment {
  /** The root Environment's ID: the Environment itself when it has no parent. */
  rootId: string;
  tier: Tier;
}

export interface ContractSemantics {
  readonly version: SemanticsVersion;
  /** Whether the item is required in this Environment. */
  requiredApplies(item: ContractItem, env: SemanticsEnvironment): boolean;
  /** Whether an item with no value in this Environment is reported missing. */
  missingWhenAbsent(item: ContractItem, env: SemanticsEnvironment): boolean;
  /**
   * Why `value` is invalid for the item, or null when it is valid. The
   * reason never contains the value or any part of it.
   */
  validate(item: ContractItem, value: string): string | null;
}

export class UnsupportedSemanticsVersionError extends Error {
  override name = "UnsupportedSemanticsVersionError";
  readonly version: unknown;
  constructor(version: unknown) {
    super(
      `Contract semantics version ${String(version)} is not supported (supported: ${SEMANTICS_VERSIONS.join(", ")})`,
    );
    this.version = version;
  }
}

function requiredApplies(item: ContractItem, env: SemanticsEnvironment): boolean {
  switch (item.required.kind) {
    case "always":
      return true;
    case "never":
      return false;
    case "selector": {
      const sel = item.required.selector;
      if (sel.kind === "tier") return sel.tier === env.tier;
      return sel.environmentIds.includes(env.rootId);
    }
  }
}

/**
 * Version 1: validation only, no conversion. An empty string is a present
 * value and is validated like any other; a Contract default satisfies
 * requiredness.
 */
const V1: ContractSemantics = {
  version: 1,
  requiredApplies,
  missingWhenAbsent: (item, env) => requiredApplies(item, env) && item.defaultValue === undefined,
  validate(item, value) {
    switch (item.type) {
      case "string":
        return null;
      case "number":
        return /^-?\d+(\.\d+)?$/.test(value) ? null : "must be a number";
      case "boolean":
        return /^(true|false|1|0)$/i.test(value) ? null : "must be a boolean";
      case "url":
        try {
          new URL(value);
          return null;
        } catch {
          return "must be a valid URL";
        }
      case "email":
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) ? null : "must be an email address";
      case "enum":
        return item.enumValues?.includes(value)
          ? null
          : `must be one of: ${item.enumValues?.join(", ")}`;
    }
  },
};

const BY_VERSION = new Map<unknown, ContractSemantics>([[1, V1]]);

/** The rules of one semantics version. Unknown versions fail closed. */
export function semanticsFor(version: number): ContractSemantics {
  const semantics = BY_VERSION.get(version);
  if (!semantics) throw new UnsupportedSemanticsVersionError(version);
  return semantics;
}
