// SPDX-License-Identifier: Apache-2.0
/**
 * Canonical Varlatch Configuration Contract model (ADR-0002, ADR-0012, ADR-0013).
 *
 * This package is deliberately pure: no HTTP, no auth, no database access, no
 * policy evaluation, no secret Values. Both the CLI (drift detection, push) and
 * varlatchd (verification, storage) depend on it, and the same logical Contract
 * must canonicalize to exactly the same bytes and hash on both sides.
 */

export const CONTRACT_SCHEMA_VERSION = 1;

export const TIERS = ["development", "staging", "production"] as const;
export type Tier = (typeof TIERS)[number];

/**
 * The small internal construct a Contract condition resolves against (ADR-0013):
 * specific root Environment identities or a tier. Deliberately not an
 * expression language.
 */
export type EnvironmentSelector =
  | { kind: "environments"; environmentIds: string[] }
  | { kind: "tier"; tier: Tier };

export type Requiredness =
  | { kind: "always" }
  | { kind: "never" }
  | { kind: "selector"; selector: EnvironmentSelector };

export const ITEM_TYPES = [
  "string",
  "number",
  "integer",
  "boolean",
  "url",
  "email",
  "enum",
] as const;
export type ItemType = (typeof ITEM_TYPES)[number];

/**
 * The first Contract Semantics version that defines each item type
 * (ADR-0042). A revision at an older version may not use the type: its
 * evaluators do not know it.
 */
export const ITEM_TYPE_SINCE_SEMANTICS: Readonly<Record<ItemType, number>> = {
  string: 1,
  number: 1,
  integer: 3,
  boolean: 1,
  url: 1,
  email: 1,
  enum: 1,
};

export interface ContractItem {
  /** Config Item name, e.g. DATABASE_URL. */
  name: string;
  required: Requiredness;
  /** Marks the Config Item as a Secret (ADR-0012): affects policy, never storage. */
  sensitive: boolean;
  type: ItemType;
  /** Present iff type === "enum". Canonical form is sorted and de-duplicated. */
  enumValues?: string[];
  defaultValue?: string;
  description?: string;
  example?: string;
  /**
   * Advisory: default grace window (seconds) for dual-phase rotation of this
   * item (ADR-0027). Cosmetic — never gates whether the item may be rotated.
   */
  rotationGraceSeconds?: number;
  /**
   * Advisory: how to rotate this credential, in a sentence or two (ADR-0053).
   * Shown where rotation happens, never in generated code. Readable by every
   * Member, so never a secret.
   */
  rotationHint?: string;
}

/** The most code points a rotation hint may hold (ADR-0053). */
export const ROTATION_HINT_MAX = 1024;
/** Controls (tab and line breaks included), line separators and bidirectional formatting: a hint is one plain paragraph. */
const ROTATION_HINT_FORBIDDEN = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/;

/** Why a rotation hint is not acceptable, or null. Rejects rather than cleans, so what is shown is what was written. */
export function rotationHintProblem(hint: string): string | null {
  const length = [...hint].length;
  if (length === 0) return "a rotation hint cannot be empty; leave it out instead";
  if (length > ROTATION_HINT_MAX) return `a rotation hint holds at most ${ROTATION_HINT_MAX} characters`;
  if (ROTATION_HINT_FORBIDDEN.test(hint)) {
    return "a rotation hint is one paragraph: no tabs, line breaks, control or bidirectional formatting characters";
  }
  return null;
}

export interface ConfigurationContract {
  schemaVersion: typeof CONTRACT_SCHEMA_VERSION;
  /**
   * The Contract Semantics version this revision is evaluated with. Absent
   * means 1: canonical form omits it then, so every revision created before
   * versions existed keeps its content hash.
   */
  semanticsVersion?: number;
  /** Canonical form: sorted by name (code-point order), names unique. */
  items: ContractItem[];
}

/** `sha256:<lowercase hex>` over the canonical byte encoding. */
export type ContractHash = `sha256:${string}`;

export const CONFIG_ITEM_NAME_PATTERN = /^[A-Z][A-Z0-9_]*$/;

/**
 * Names reserved for launcher metadata. `VARLATCH_RUN_CONTEXT` is set by
 * `varlatch run` itself, so no Contract item or stored value may use it.
 */
export const RESERVED_ITEM_NAMES: readonly string[] = ["VARLATCH_RUN_CONTEXT"];

export function isReservedItemName(name: string): boolean {
  return RESERVED_ITEM_NAMES.includes(name);
}
