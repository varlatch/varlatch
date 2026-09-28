// SPDX-License-Identifier: Apache-2.0
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type * as Runtime from "../src/runtime.js";
import type { AccessorItem, AccessorSchema } from "../src/runtime.js";

export type BuiltRuntime = typeof Runtime;

/**
 * The runtime exactly as generated modules embed it: the bundle in
 * dist/embedded.js, evaluated on its own. Tests use this rather than the
 * sources, so they check what ships.
 */
export async function builtRuntime(): Promise<BuiltRuntime> {
  const embedded = new URL("../dist/embedded.js", import.meta.url);
  if (!existsSync(fileURLToPath(embedded))) {
    throw new Error("the accessor bundle is not built: run pnpm --filter @varlatch/accessor build");
  }
  const { ACCESSOR_RUNTIME_NAME, ACCESSOR_RUNTIME_SOURCE } = (await import(embedded.href)) as {
    ACCESSOR_RUNTIME_NAME: string;
    ACCESSOR_RUNTIME_SOURCE: string;
  };
  return new Function(`${ACCESSOR_RUNTIME_SOURCE}\nreturn ${ACCESSOR_RUNTIME_NAME}();`)() as BuiltRuntime;
}

export const HASH_A = `sha256:${"a".repeat(64)}`;
export const HASH_B = `sha256:${"b".repeat(64)}`;

export function item(name: string, fields: Partial<AccessorItem> = {}): AccessorItem {
  return { name, type: "string", required: { kind: "never" }, ...fields };
}

export function schema(items: AccessorItem[], fields: Partial<AccessorSchema> = {}): AccessorSchema {
  return {
    format: 1,
    revisionId: "crv_one",
    contentHash: HASH_A,
    semanticsVersion: 2,
    generator: "varlatch test",
    items,
    ...fields,
  };
}

type Server = "delivered" | "withheld" | "notStored";
type Delivery = "varlatch" | "inherited" | "default" | "absent";

/** A run context exactly as `varlatch run --strict` or `--export-context` emits it. */
export function runContext(
  items: Record<string, { server: Server; delivery: Delivery }>,
  fields: Partial<{
    mode: "strict" | "exported";
    contractRevisionId: string;
    contractHash: string;
    semanticsVersion: number;
    environment: { rootId: string; tier: "development" | "staging" | "production" };
  }> = {},
): string {
  return JSON.stringify({
    v: 1,
    mode: "strict",
    contractRevisionId: "crv_one",
    contractHash: HASH_A,
    semanticsVersion: 2,
    environment: { rootId: "env_dev", tier: "development" },
    items,
    ...fields,
  });
}

/** The ConfigError a call throws, or a failure if it returns. */
export function configError(call: () => unknown): { name: string; message: string; issues: { name: string; reason: string }[] } {
  try {
    call();
  } catch (err) {
    return err as { name: string; message: string; issues: { name: string; reason: string }[] };
  }
  throw new Error("expected a ConfigError");
}
