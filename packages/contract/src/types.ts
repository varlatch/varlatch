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
  "boolean",
  "url",
  "email",
  "enum",
] as const;
export type ItemType = (typeof ITEM_TYPES)[number];

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
