// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Tier } from "@varlatch/protocol";

/**
 * The managed contract editor's draft: rows that remember where they came
 * from, a semantic diff with security-relevant changes first, and the small
 * validations the editor shows inline before the server has its say. Pure,
 * so it is tested without rendering.
 */

export type Requiredness =
  | { kind: "always" }
  | { kind: "never" }
  | { kind: "selector"; selector: { kind: "tier"; tier: Tier } | { kind: "environments"; environmentIds: string[] } };

export type ContractItem = {
  name: string;
  required: Requiredness;
  sensitive: boolean;
  type: string;
  enumValues?: string[] | undefined;
  defaultValue?: string | undefined;
  description?: string | undefined;
  rotationGraceSeconds?: number | undefined;
  /** How to rotate this credential (ADR-0053). */
  rotationHint?: string | undefined;
  /** Fields the editor does not show travel through unchanged. */
  [key: string]: unknown;
};

export type DraftRow = {
  /** Stable React key; the item name can still change on new rows. */
  key: string;
  item: ContractItem;
  /** The active revision's item, or null for a row added in this draft. */
  origin: ContractItem | null;
  removed: boolean;
};

export type RowState = "new" | "edited" | "removed" | "unchanged";

export const ITEM_NAME = /^[A-Z][A-Z0-9_]*$/;
export const TIERS: Tier[] = ["production", "staging", "development"];

export function rowsFrom(items: ContractItem[]): DraftRow[] {
  return items.map((item) => ({ key: `item:${item.name}`, item, origin: item, removed: false }));
}

export function rowState(row: DraftRow): RowState {
  if (row.removed) return "removed";
  if (!row.origin) return "new";
  return sameItem(cleanItem(row.item), cleanItem(row.origin)) ? "unchanged" : "edited";
}

/** The item as it would be pushed: empty optional fields dropped. */
export function cleanItem(item: ContractItem): ContractItem {
  const { enumValues, defaultValue, description, rotationHint, rotationGraceSeconds, ...rest } = item;
  const out: ContractItem = { ...rest };
  // A hint is kept exactly as typed (rowProblem refuses what the server
  // would refuse); only an empty field means "no hint".
  if (rotationHint !== undefined && rotationHint !== "") out.rotationHint = rotationHint;
  if (rotationGraceSeconds !== undefined && Number.isFinite(rotationGraceSeconds)) out.rotationGraceSeconds = rotationGraceSeconds;
  if (item.type === "enum") {
    const values = [...new Set((enumValues ?? []).map((v) => v.trim()).filter(Boolean))].sort();
    out.enumValues = values;
  }
  if (defaultValue !== undefined && defaultValue !== "") out.defaultValue = defaultValue;
  if (description !== undefined && description.trim() !== "") out.description = description.trim();
  return out;
}

/** The contract items a publish pushes, sorted like the server stores them. */
export function draftItems(rows: DraftRow[]): ContractItem[] {
  return rows
    .filter((r) => !r.removed)
    .map((r) => cleanItem(r.item))
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

export function changeCount(rows: DraftRow[]): number {
  return rows.filter((r) => rowState(r) !== "unchanged").length;
}

// ---- requiredness

export function requiredKey(r: Requiredness): string {
  if (r.kind === "always") return "always";
  if (r.kind === "never") return "never";
  return r.selector.kind === "tier" ? `tier:${r.selector.tier}` : "environments";
}

export function requiredLabel(r: Requiredness): string {
  if (r.kind === "always") return "always";
  if (r.kind === "never") return "optional";
  return r.selector.kind === "tier" ? `${r.selector.tier} only` : "selected environments";
}

/** The requiredness for a select value; "environments" keeps the current selector. */
export function requiredFromKey(key: string, current: Requiredness): Requiredness {
  if (key === "always") return { kind: "always" };
  if (key === "never") return { kind: "never" };
  if (key.startsWith("tier:")) return { kind: "selector", selector: { kind: "tier", tier: key.slice(5) as Tier } };
  return current;
}

// ---- diff

export type ChangeKind = "added" | "removed" | "secret" | "required" | "type" | "enum" | "default" | "description" | "rotation" | "other";

export type Change = {
  name: string;
  kind: ChangeKind;
  from?: string | undefined;
  to?: string | undefined;
  /** Changes what is protected, required or accepted: secret, required, type, and items added or removed. */
  securityRelevant: boolean;
};

const ORDER: ChangeKind[] = ["removed", "added", "secret", "required", "type", "enum", "default", "description", "rotation", "other"];

/** Semantic diff, security-relevant changes first, then by item name. */
export function diffItems(before: ContractItem[], after: ContractItem[]): Change[] {
  const a = new Map(before.map((i) => [i.name, cleanItem(i)]));
  const b = new Map(after.map((i) => [i.name, cleanItem(i)]));
  const out: Change[] = [];
  for (const [name, item] of b) {
    if (!a.has(name)) {
      out.push({
        name,
        kind: "added",
        to: `${item.type}, ${requiredLabel(item.required)}${item.sensitive ? ", secret" : ""}`,
        securityRelevant: true,
      });
    }
  }
  for (const [name, prev] of a) {
    const next = b.get(name);
    if (!next) {
      out.push({ name, kind: "removed", securityRelevant: true });
      continue;
    }
    if (prev.sensitive !== next.sensitive) {
      out.push({ name, kind: "secret", from: prev.sensitive ? "secret" : "not secret", to: next.sensitive ? "secret" : "not secret", securityRelevant: true });
    }
    if (requiredKey(prev.required) !== requiredKey(next.required)) {
      out.push({ name, kind: "required", from: requiredLabel(prev.required), to: requiredLabel(next.required), securityRelevant: true });
    }
    if (prev.type !== next.type) out.push({ name, kind: "type", from: prev.type, to: next.type, securityRelevant: true });
    if (prev.type === next.type && next.type === "enum" && (prev.enumValues ?? []).join(",") !== (next.enumValues ?? []).join(",")) {
      out.push({ name, kind: "enum", from: (prev.enumValues ?? []).join(", "), to: (next.enumValues ?? []).join(", "), securityRelevant: true });
    }
    if ((prev.defaultValue ?? "") !== (next.defaultValue ?? "")) {
      out.push({ name, kind: "default", from: prev.defaultValue, to: next.defaultValue, securityRelevant: false });
    }
    if ((prev.description ?? "") !== (next.description ?? "")) {
      out.push({ name, kind: "description", from: prev.description, to: next.description, securityRelevant: false });
    }
    if ((prev.rotationHint ?? "") !== (next.rotationHint ?? "") || prev.rotationGraceSeconds !== next.rotationGraceSeconds) {
      out.push({ name, kind: "rotation", from: rotationLabel(prev), to: rotationLabel(next), securityRelevant: false });
    }
    const { name: _n, required: _r, sensitive: _s, type: _t, enumValues: _e, defaultValue: _d, description: _ds, rotationHint: _h, rotationGraceSeconds: _g, ...restA } = prev;
    const { name: _n2, required: _r2, sensitive: _s2, type: _t2, enumValues: _e2, defaultValue: _d2, description: _ds2, rotationHint: _h2, rotationGraceSeconds: _g2, ...restB } = next;
    if (stable(restA) !== stable(restB)) out.push({ name, kind: "other", securityRelevant: false });
  }
  return out.sort(
    (x, y) =>
      Number(y.securityRelevant) - Number(x.securityRelevant) ||
      ORDER.indexOf(x.kind) - ORDER.indexOf(y.kind) ||
      (x.name < y.name ? -1 : x.name > y.name ? 1 : 0),
  );
}

/** A rotation hint and grace window, as the diff shows them. */
function rotationLabel(item: ContractItem): string | undefined {
  const parts = [
    ...(item.rotationGraceSeconds !== undefined ? [`grace ${graceHours(item.rotationGraceSeconds)} h`] : []),
    ...(item.rotationHint ? [item.rotationHint] : []),
  ];
  return parts.length > 0 ? parts.join(" · ") : undefined;
}

/** Seconds as hours for the editor, exact to the second. */
export function graceHours(seconds: number): string {
  return String(Math.round((seconds / 3600) * 10_000) / 10_000);
}

// ---- validation

/** At most 1024 code points (ADR-0053); kept in step with @varlatch/contract, and the server decides. */
const ROTATION_HINT_MAX = 1024;
const ROTATION_HINT_FORBIDDEN = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/;

export function rotationProblem(item: ContractItem): string | null {
  const hint = item.rotationHint;
  if (hint !== undefined && hint !== "") {
    if ([...hint].length > ROTATION_HINT_MAX) return `A rotation hint holds at most ${ROTATION_HINT_MAX} characters`;
    if (ROTATION_HINT_FORBIDDEN.test(hint)) return "A rotation hint is one line, without tabs or control characters";
  }
  const grace = item.rotationGraceSeconds;
  if (grace !== undefined && (!Number.isInteger(grace) || grace < 1 || grace > 2_592_000)) {
    return "The rotation grace must be between 1 second and 30 days";
  }
  return null;
}

/** An inline problem with a row, or null. `names` counts every live row's name. */
export function rowProblem(item: ContractItem, names: Map<string, number>): string | null {
  if (!item.name) return "Name the item";
  if (!ITEM_NAME.test(item.name)) return "Use capitals, digits and underscores, starting with a letter";
  if ((names.get(item.name) ?? 0) > 1) return "Another item has this name";
  if (item.type === "enum") {
    const values = (item.enumValues ?? []).map((v) => v.trim()).filter(Boolean);
    if (values.length === 0) return "List the allowed values";
    if (item.defaultValue && !values.includes(item.defaultValue)) return "The default must be one of the allowed values";
  }
  return defaultProblem(item.type, item.defaultValue) ?? rotationProblem(item);
}

export function defaultProblem(type: string, value: string | undefined): string | null {
  if (value === undefined || value === "") return null;
  if (type === "integer" && !/^-?\d+$/.test(value)) return "The default must be a whole number";
  if (type === "number" && !/^-?\d+(\.\d+)?$/.test(value)) return "The default must be a number";
  if (type === "boolean" && !/^(true|false|1|0)$/i.test(value)) return "The default must be true or false";
  if (type === "url" && !/^[a-z][a-z0-9+.-]*:\/\/\S+$/i.test(value)) return "The default must be an absolute URL";
  if (type === "email" && !/^[^\s@]+@[^\s@]+$/.test(value)) return "The default must be an email address";
  return null;
}

function sameItem(a: ContractItem, b: ContractItem): boolean {
  return stable(a) === stable(b);
}

function stable(value: unknown): string {
  return (
    JSON.stringify(value, (_k, v: unknown) =>
      v && typeof v === "object" && !Array.isArray(v)
        ? Object.fromEntries(Object.entries(v as Record<string, unknown>).filter(([, x]) => x !== undefined).sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0)))
        : v,
    ) ?? "undefined"
  );
}
