// SPDX-License-Identifier: Apache-2.0
import { z } from "zod";
import {
  CONFIG_ITEM_NAME_PATTERN,
  CONTRACT_SCHEMA_VERSION,
  ITEM_TYPES,
  ITEM_TYPE_SINCE_SEMANTICS,
  TIERS,
  isReservedItemName,
  type ConfigurationContract,
  type ContractItem,
} from "./types.js";
import { SEMANTICS_VERSIONS } from "./semantics.js";

const environmentSelectorSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("environments"),
    environmentIds: z.array(z.string().min(1)).min(1),
  }),
  z.strictObject({ kind: z.literal("tier"), tier: z.enum(TIERS) }),
]);

const requirednessSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("always") }),
  z.strictObject({ kind: z.literal("never") }),
  z.strictObject({
    kind: z.literal("selector"),
    selector: environmentSelectorSchema,
  }),
]);

const contractItemSchema = z.strictObject({
  name: z
    .string()
    .min(1)
    .max(256)
    .regex(
      CONFIG_ITEM_NAME_PATTERN,
      "Config Item names must match ^[A-Z][A-Z0-9_]*$",
    ),
  required: requirednessSchema,
  sensitive: z.boolean(),
  type: z.enum(ITEM_TYPES),
  enumValues: z.array(z.string().min(1)).min(1).optional(),
  defaultValue: z.string().optional(),
  description: z.string().max(4096).optional(),
  example: z.string().max(4096).optional(),
  rotationGraceSeconds: z.number().int().min(1).max(2_592_000).optional(),
});

const contractSchema = z.strictObject({
  schemaVersion: z.literal(CONTRACT_SCHEMA_VERSION),
  semanticsVersion: z.number().int().optional(),
  items: z.array(contractItemSchema),
});

export class ContractValidationError extends Error {
  readonly issues: string[];
  constructor(issues: string[]) {
    super(`Invalid Configuration Contract: ${issues.join("; ")}`);
    this.name = "ContractValidationError";
    this.issues = issues;
  }
}

function codePointCompare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export interface NormalizeOptions {
  /**
   * The semantics version is not decided yet: a Contract without
   * `semanticsVersion` is being pushed, and the server will give it the
   * active revision's version. The check that each item type exists at the
   * revision's version then waits for that decision; everything else is
   * checked as usual. A Contract that names its version is always checked.
   */
  versionUndecided?: boolean;
}

/**
 * Validate an untrusted input and produce the canonical Contract form:
 * items sorted by name, enum values and selector environment IDs sorted and
 * de-duplicated, optional fields omitted when absent. Idempotent.
 *
 * Throws {@link ContractValidationError} on structurally or semantically
 * invalid input (unknown fields, duplicate names, enum constraint violations).
 */
export function normalizeContract(input: unknown, options: NormalizeOptions = {}): ConfigurationContract {
  const parsed = contractSchema.safeParse(input);
  if (!parsed.success) {
    throw new ContractValidationError(
      parsed.error.issues.map(
        (i) => `${i.path.join(".") || "(root)"}: ${i.message}`,
      ),
    );
  }

  const issues: string[] = [];
  const version = parsed.data.semanticsVersion;
  if (version !== undefined && !(SEMANTICS_VERSIONS as readonly number[]).includes(version)) {
    issues.push(
      `semanticsVersion: version ${version} is not supported (supported: ${SEMANTICS_VERSIONS.join(", ")})`,
    );
  }
  const typesVersion = version ?? (options.versionUndecided ? undefined : 1);
  const seen = new Set<string>();
  for (const item of parsed.data.items) {
    const since = ITEM_TYPE_SINCE_SEMANTICS[item.type];
    if (typesVersion !== undefined && typesVersion < since) {
      issues.push(
        `${item.name}: type ${item.type} needs Contract Semantics version ${since} or later, and this Contract uses version ${typesVersion}; move it to the newest rules (varlatch contract push --semantics latest, or the dashboard's Contract page)`,
      );
    }
    if (isReservedItemName(item.name)) {
      issues.push(`${item.name} is reserved for launcher metadata and cannot be a Config Item`);
    }
    if (seen.has(item.name)) issues.push(`duplicate Config Item name ${item.name}`);
    seen.add(item.name);
    if (item.type === "enum" && !item.enumValues) {
      issues.push(`${item.name}: enum type requires enumValues`);
    }
    if (item.type !== "enum" && item.enumValues) {
      issues.push(`${item.name}: enumValues is only valid for enum type`);
    }
    if (
      item.type === "enum" &&
      item.enumValues &&
      item.defaultValue !== undefined &&
      !item.enumValues.includes(item.defaultValue)
    ) {
      issues.push(`${item.name}: defaultValue is not one of enumValues`);
    }
  }
  if (issues.length > 0) throw new ContractValidationError(issues);

  const items: ContractItem[] = parsed.data.items
    .map((item) => {
      const normalized: ContractItem = {
        name: item.name,
        required:
          item.required.kind === "selector" &&
          item.required.selector.kind === "environments"
            ? {
                kind: "selector",
                selector: {
                  kind: "environments",
                  environmentIds: [...new Set(item.required.selector.environmentIds)].sort(
                    codePointCompare,
                  ),
                },
              }
            : item.required,
        sensitive: item.sensitive,
        type: item.type,
      };
      if (item.enumValues) {
        normalized.enumValues = [...new Set(item.enumValues)].sort(codePointCompare);
      }
      if (item.defaultValue !== undefined) normalized.defaultValue = item.defaultValue;
      if (item.description !== undefined) normalized.description = item.description;
      if (item.example !== undefined) normalized.example = item.example;
      if (item.rotationGraceSeconds !== undefined) {
        normalized.rotationGraceSeconds = item.rotationGraceSeconds;
      }
      return normalized;
    })
    .sort((a, b) => codePointCompare(a.name, b.name));

  // Version 1 is encoded by omission, so pre-existing hashes never change.
  return version === undefined || version === 1
    ? { schemaVersion: CONTRACT_SCHEMA_VERSION, items }
    : { schemaVersion: CONTRACT_SCHEMA_VERSION, semanticsVersion: version, items };
}
