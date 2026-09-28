// SPDX-License-Identifier: Apache-2.0
import { contractHash, normalizeContract } from "@varlatch/contract";

/** A Contract Revision as the server returns it, with a correct content hash. */
export function revision(items: Record<string, unknown>[], opts: { id?: string; semanticsVersion?: number } = {}) {
  const semanticsVersion = opts.semanticsVersion ?? 2;
  const contract = normalizeContract({ schemaVersion: 1, ...(semanticsVersion !== 1 ? { semanticsVersion } : {}), items });
  return {
    id: opts.id ?? "crv_types1",
    projectId: "prj_1",
    contentHash: contractHash(contract),
    semanticsVersion,
    active: true,
    contract: contract as unknown as Record<string, unknown>,
    createdAt: "2026-09-28T00:00:00.000Z",
  };
}

export function contractItem(name: string, fields: Record<string, unknown> = {}) {
  return { name, required: { kind: "never" }, sensitive: false, type: "string", ...fields };
}

/** One Contract with every item type and requiredness kind. */
export const ITEMS = [
  contractItem("API_KEY", { sensitive: true, required: { kind: "always" }, description: "Key for the payments API." }),
  contractItem("DATABASE_URL", { sensitive: true, type: "url", required: { kind: "always" }, example: "postgres://localhost/app" }),
  contractItem("DEBUG", { type: "boolean" }),
  contractItem("FEATURE_X", { type: "boolean", required: { kind: "selector", selector: { kind: "environments", environmentIds: ["env_prod"] } } }),
  contractItem("LOG_LEVEL", { type: "enum", enumValues: ["debug", "info", "warn"], defaultValue: "info", required: { kind: "always" } }),
  contractItem("PORT", { type: "number", required: { kind: "always" }, description: "Port to listen on." }),
  contractItem("SENTRY_DSN", { type: "url", required: { kind: "selector", selector: { kind: "tier", tier: "production" } } }),
  contractItem("SUPPORT_EMAIL", { type: "email" }),
];
