// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";
import type { ConfigurationContract, ContractHash } from "./types.js";

/**
 * Deterministic JSON encoding: recursively sorted object keys (code-point
 * order), arrays in given order, no insignificant whitespace, `undefined`
 * properties omitted, standard JSON string escaping. The output is stable
 * across runtimes for the value shapes this package produces (strings,
 * booleans, integers, plain objects, arrays).
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        throw new TypeError("Non-finite numbers are not canonicalizable");
      }
      if (!Number.isInteger(value)) {
        // The Contract model only carries integers (schemaVersion). Reject
        // floats outright rather than risking cross-runtime formatting drift.
        throw new TypeError("Non-integer numbers are not canonicalizable");
      }
      return String(value);
    case "object": {
      if (Array.isArray(value)) {
        return `[${value.map((v) => canonicalJson(v)).join(",")}]`;
      }
      const entries = Object.entries(value as Record<string, unknown>)
        .filter(([, v]) => v !== undefined)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
      return `{${entries
        .map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`)
        .join(",")}}`;
    }
    default:
      throw new TypeError(`Value of type ${typeof value} is not canonicalizable`);
  }
}

/** Canonical UTF-8 bytes of a (already normalized) Contract. */
export function canonicalContractBytes(contract: ConfigurationContract): Uint8Array {
  return new TextEncoder().encode(canonicalJson(contract));
}

/** Content hash of a (already normalized) Contract: `sha256:<hex>`. */
export function contractHash(contract: ConfigurationContract): ContractHash {
  const digest = createHash("sha256")
    .update(canonicalContractBytes(contract))
    .digest("hex");
  return `sha256:${digest}`;
}
