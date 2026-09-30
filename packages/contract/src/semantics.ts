// SPDX-License-Identifier: Apache-2.0
import type { ConfigurationContract, ContractItem, Tier } from "./types.js";

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

export const SEMANTICS_VERSIONS = [1, 2, 3] as const;
export type SemanticsVersion = (typeof SEMANTICS_VERSIONS)[number];

/** The Environment facts requiredness depends on. */
export interface SemanticsEnvironment {
  /** The root Environment's ID: the Environment itself when it has no parent. */
  rootId: string;
  tier: Tier;
}

/** A converted value: `process.env` strings become these typed values. */
export type ConvertedValue = string | number | boolean;

export type ParseResult =
  | { ok: true; value: ConvertedValue }
  | { ok: false; reason: string };

export interface ContractSemantics {
  readonly version: SemanticsVersion;
  /**
   * Validation and conversion as one step, from version 2: every string
   * that validates converts, the same way everywhere. Undefined for a
   * version that defines no conversion.
   */
  readonly parse?: (item: ContractItem, value: string) => ParseResult;
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
      case "integer":
        // Normalization keeps integer items out of version 1 and 2
        // revisions; an evaluator that still meets one fails closed.
        return BEFORE_INTEGER;
    }
  },
};

const BEFORE_INTEGER = "has a type this Contract Semantics version does not define (integer needs version 3)";

/** The largest integer a JavaScript number represents exactly: 2^53 - 1. */
const MAX_EXACT = "9007199254740991";
const NUMBER_V2 = /^-?(\d+)(?:\.(\d+))?$/;

/**
 * Version 2 numbers: the version 1 lexical form, and an exact decimal
 * magnitude of at most 2^53 - 1, checked on the digits before any rounding.
 * Within that range a fraction converts to the nearest double.
 */
function parseNumberV2(value: string): ParseResult {
  const match = NUMBER_V2.exec(value);
  if (!match) return { ok: false, reason: "must be a number" };
  const integer = (match[1] as string).replace(/^0+(?=\d)/, "");
  const fractionNonZero = match[2] !== undefined && /[1-9]/.test(match[2]);
  const tooLarge =
    integer.length > MAX_EXACT.length ||
    (integer.length === MAX_EXACT.length &&
      (integer > MAX_EXACT || (integer === MAX_EXACT && fractionNonZero)));
  if (tooLarge) {
    return { ok: false, reason: "must be a number no larger in magnitude than 2^53 - 1" };
  }
  return { ok: true, value: Number(value) };
}

/**
 * Version 2: version 1's rules with conversion, and a magnitude bound on
 * numbers so that every valid number converts exactly or to the nearest
 * double, never to a different integer or to Infinity. Booleans convert
 * `true`/`1` to true and `false`/`0` to false; every other type converts to
 * the validated string.
 */
function parseV2(item: ContractItem, value: string): ParseResult {
  if (item.type === "number") return parseNumberV2(value);
  if (item.type === "integer") return { ok: false, reason: BEFORE_INTEGER };
  const reason = V1.validate(item, value);
  if (reason !== null) return { ok: false, reason };
  if (item.type === "boolean") return { ok: true, value: /^(true|1)$/i.test(value) };
  return { ok: true, value };
}

const V2: ContractSemantics = {
  version: 2,
  requiredApplies,
  missingWhenAbsent: V1.missingWhenAbsent,
  parse: parseV2,
  validate(item, value) {
    const result = parseV2(item, value);
    return result.ok ? null : result.reason;
  },
};

const INTEGER_V3 = /^-?([0-9]+)$/;

/**
 * Version 3 integers (ADR-0042): an optional `-` and ASCII digits only, so
 * no fraction (`3.0` too), exponent, sign `+`, separator, or whitespace; and
 * the same exact-digit bound as version 2 numbers. `-0` converts to 0.
 */
function parseIntegerV3(value: string): ParseResult {
  const match = INTEGER_V3.exec(value);
  if (!match) return { ok: false, reason: "must be a whole number" };
  const digits = (match[1] as string).replace(/^0+(?=\d)/, "");
  if (digits.length > MAX_EXACT.length || (digits.length === MAX_EXACT.length && digits > MAX_EXACT)) {
    return { ok: false, reason: "must be a whole number no larger in magnitude than 2^53 - 1" };
  }
  const converted = Number(value);
  return { ok: true, value: converted === 0 ? 0 : converted };
}

/** Version 3: version 2 plus the `integer` type. Every other rule is version 2's. */
function parseV3(item: ContractItem, value: string): ParseResult {
  if (item.type === "integer") return parseIntegerV3(value);
  return parseV2(item, value);
}

const V3: ContractSemantics = {
  version: 3,
  requiredApplies,
  missingWhenAbsent: V1.missingWhenAbsent,
  parse: parseV3,
  validate(item, value) {
    const result = parseV3(item, value);
    return result.ok ? null : result.reason;
  },
};

const BY_VERSION = new Map<unknown, ContractSemantics>([
  [1, V1],
  [2, V2],
  [3, V3],
]);

/** The newest version: what a project's first revision gets. */
export const LATEST_SEMANTICS_VERSION: SemanticsVersion = 3;

/** A Contract's semantics version: absent means 1. */
export function semanticsVersionOf(contract: Pick<ConfigurationContract, "semanticsVersion">): number {
  return contract.semanticsVersion ?? 1;
}

/** The rules of one semantics version. Unknown versions fail closed. */
export function semanticsFor(version: number): ContractSemantics {
  const semantics = BY_VERSION.get(version);
  if (!semantics) throw new UnsupportedSemanticsVersionError(version);
  return semantics;
}
