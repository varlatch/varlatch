// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ContractRevision, EffectiveConfigurationItem, Environment, Tier } from "@varlatch/protocol";

/**
 * Pure model shared by the project values grid and the environment values
 * page: contract metadata, cell states, drafts and the change sets built
 * from them. No React, no network, no plaintext Secrets kept anywhere.
 */

export interface ContractItemMeta {
  name: string;
  sensitive: boolean;
  type?: string | undefined;
  enumValues?: string[] | undefined;
  required: { kind: string; selector?: { kind: string; tier?: Tier; environmentIds?: string[] } };
  defaultValue?: string | undefined;
  description?: string | undefined;
  rotationGraceSeconds?: number | undefined;
}

/** One effective item as the server returned it (metadata, plus non-sensitive plaintext when readable). */
export type ServerItem = EffectiveConfigurationItem;

/** A local, unsaved change. Drafts live in memory only: they may hold typed Secrets. */
export type Draft = { op: "set"; value: string } | { op: "delete" };

/** Cell states (design R2): `set`, `unset_optional`, `missing_required`, `covered_by_default`. */
export type CellState = "set" | "unset_optional" | "missing_required" | "covered_by_default";

export type Change =
  | { op: "set"; item: string; value: string; expectedVersionId?: string }
  | { op: "delete"; item: string; expectedVersionId?: string };

export const ITEM_NAME_PATTERN = /^[A-Z][A-Z0-9_]*$/;

export function contractItemsOf(revision: ContractRevision | undefined | null): ContractItemMeta[] {
  return ((revision?.contract as { items?: ContractItemMeta[] } | undefined)?.items ?? []) as ContractItemMeta[];
}

/** The root environment's id: contract selectors name root environments. */
export function rootIdOf(env: Environment): string {
  return env.parentEnvironmentId ?? env.id;
}

export function requiredHere(item: ContractItemMeta, env: Environment): boolean {
  const r = item.required;
  if (r.kind === "always") return true;
  if (r.kind === "never") return false;
  if (r.selector?.kind === "tier") return r.selector.tier === env.tier;
  if (r.selector?.kind === "environments") return r.selector.environmentIds?.includes(rootIdOf(env)) ?? false;
  return false;
}

/** Plain-language requiredness for the item panel. */
export function requirednessLabel(item: ContractItemMeta | undefined, env: Environment): string {
  if (!item) return "Not in the contract";
  const r = item.required;
  if (r.kind === "always") return "Required everywhere";
  if (r.kind === "never") return "Optional";
  const here = requiredHere(item, env) ? "required here" : "optional here";
  if (r.selector?.kind === "tier") return `Required in ${r.selector.tier} (${here})`;
  return `Required in selected environments (${here})`;
}

export function cellStateOf(
  server: ServerItem | undefined,
  contract: ContractItemMeta | undefined,
  env: Environment,
): CellState {
  if (server) return "set";
  if (contract && requiredHere(contract, env)) {
    return contract.defaultValue !== undefined ? "covered_by_default" : "missing_required";
  }
  return "unset_optional";
}

/**
 * Whether the item is a Secret. The server's answer wins; the contract
 * decides before a value exists; items outside the contract are Secrets
 * (the server treats them so).
 */
export function isSensitive(server: ServerItem | undefined, contract: ContractItemMeta | undefined): boolean {
  return server?.sensitive ?? contract?.sensitive ?? true;
}

/** The text an editor starts from: the stored text (references intact), never the expansion. */
export function storedText(server: ServerItem | undefined): string | null {
  if (!server) return null;
  return server.rawValue ?? server.value ?? null;
}

/** "edited", "new" or "deleted" for a drafted cell. */
export function draftKind(draft: Draft | undefined, server: ServerItem | undefined): "edited" | "new" | "deleted" | null {
  if (!draft) return null;
  if (draft.op === "delete") return "deleted";
  return server && server.source === "self" ? "edited" : "new";
}

/**
 * The change set for one environment. Expected versions come from the
 * reviewed snapshot, never the live data, and only for the environment's
 * own values: an inherited value's version belongs to the parent.
 */
export function buildChanges(drafts: Map<string, Draft>, reviewed: Map<string, ServerItem>): Change[] {
  return [...drafts.entries()].map(([item, draft]) => {
    const server = reviewed.get(item);
    const expected = server && server.source === "self" && server.versionId ? { expectedVersionId: server.versionId } : {};
    return draft.op === "delete" ? { op: "delete", item, ...expected } : { op: "set", item, value: draft.value, ...expected };
  });
}

/**
 * The `.env` paste format accepted as draft input: KEY=value lines, comments
 * and blank lines ignored, one level of matching quotes stripped. Anything
 * else makes the whole paste ambiguous: no silent partial import.
 */
export function parseDotenv(text: string): { name: string; value: string }[] | null {
  const lines = text.split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith("#"));
  const parsed: { name: string; value: string }[] = [];
  for (const line of lines) {
    const match = /^(?:export\s+)?([A-Z][A-Z0-9_]*)=(.*)$/.exec(line.trim());
    if (!match) return null;
    let value = match[2] as string;
    if (value.length >= 2 && ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")))) {
      const quote = value[0];
      value = value.slice(1, -1);
      if (quote === '"') value = value.replace(/\\(n|"|\\)/g, (_, c: string) => (c === "n" ? "\n" : c));
    }
    parsed.push({ name: match[1] as string, value });
  }
  return parsed;
}

/** One `.env` line; quotes only when the value needs them. */
export function dotenvLine(name: string, value: string): string {
  if (/^[A-Za-z0-9_./:@,+%=?&-]*$/.test(value)) return `${name}=${value}`;
  const escaped = value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
  return `${name}="${escaped}"`;
}

/** 32 random bytes, base64url: a fresh credential for rotations. */
export function generateSecret(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  let bin = "";
  for (const b of buf) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Editor flavour for an item: a select for enums and booleans, a blind input for Secrets. */
export function editorKind(
  sensitive: boolean,
  contract: ContractItemMeta | undefined,
): { kind: "secret" } | { kind: "options"; options: string[] } | { kind: "text" } {
  if (sensitive) return { kind: "secret" };
  if (contract?.type === "enum" && contract.enumValues?.length) return { kind: "options", options: contract.enumValues };
  if (contract?.type === "boolean") return { kind: "options", options: ["true", "false"] };
  return { kind: "text" };
}

/** Root environments in tier order, each with its derived environments. */
export function groupEnvironments(envs: Environment[]): { root: Environment; derived: Environment[] }[] {
  const roots = envs.filter((e) => !e.parentEnvironmentId);
  return roots.map((root) => ({ root, derived: envs.filter((e) => e.parentEnvironmentId === root.id) }));
}

export function envPath(org: string, project: string, env: string, item?: string): string {
  const base = `/o/${org}/p/${project}/e/${encodeURIComponent(env)}`;
  return item ? `${base}?item=${encodeURIComponent(item)}` : base;
}

export function plural(n: number, word: string, many = `${word}s`): string {
  return `${n} ${n === 1 ? word : many}`;
}

/** "development", "development and staging", "development, staging and production". */
export function listNames(names: string[]): string {
  if (names.length <= 1) return names[0] ?? "";
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}
