// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Contract Semantics in the dashboard: which item types the editor may offer
 * at a revision's version, and the review shown before a Contract moves to
 * the newest rules. Pure, so it is tested without rendering.
 *
 * Moving changes the version and nothing else: the new revision is the
 * active revision's Contract with only `semanticsVersion` set, and the
 * review refuses activation when the server's stored revision differs in
 * anything else.
 */

/** The first semantics version that defines each item type (mirrors @varlatch/contract). */
export const ITEM_TYPE_SINCE: Readonly<Record<string, number>> = {
  string: 1,
  number: 1,
  integer: 3,
  boolean: 1,
  url: 1,
  email: 1,
  enum: 1,
};

/** What each version adds over the one before it. */
const STEP_CHANGES: Readonly<Record<number, string>> = {
  2: "Numbers are bounded at 2^53 - 1 in magnitude, and values convert to typed values for generated types.",
  3: "Adds the integer type.",
};

/** The newest version a server evaluates; servers that list none evaluate only version 1. */
export function newestSemanticsVersion(supported: readonly number[] | undefined): number {
  return supported && supported.length > 0 ? Math.max(...supported) : 1;
}

/** A revision's version; revisions from servers before versions existed are version 1. */
export function revisionSemanticsVersion(revision: { semanticsVersion?: number | null }): number {
  return revision.semanticsVersion ?? 1;
}

export type TypeOffer = { enabled: true } | { enabled: false; reason: string };

/**
 * Whether the editor offers an item type. `version` is the version the next
 * published revision gets (the active revision's, since edits keep it), or
 * undefined while that is not known yet.
 */
export function typeOffer(type: string, version: number | undefined, newest: number): TypeOffer {
  const since = ITEM_TYPE_SINCE[type] ?? 1;
  if (version !== undefined && version >= since) return { enabled: true };
  if (newest < since) {
    return { enabled: false, reason: `Needs semantics version ${since}, which this server does not support.` };
  }
  if (version === undefined) return { enabled: false, reason: `Needs semantics version ${since}.` };
  return {
    enabled: false,
    reason: `Needs semantics version ${since}. This Contract uses version ${version}: use "Move to the newest rules" above first. Edits keep the version.`,
  };
}

/** Whether to offer moving the active revision to the newest rules. */
export function canMoveRules(activeVersion: number, newest: number): boolean {
  return activeVersion < newest;
}

/** The Contract to push: the active one exactly as stored, with only the version set. */
export function movedContract(activeContract: unknown, target: number): Record<string, unknown> {
  return { ...(activeContract as Record<string, unknown>), semanticsVersion: target };
}

/** What the newer rules change, one entry per version step after `from` up to `to`. */
export function semanticsSteps(from: number, to: number): { version: number; change: string }[] {
  const steps: { version: number; change: string }[] = [];
  for (let v = from + 1; v <= to; v++) {
    steps.push({ version: v, change: STEP_CHANGES[v] ?? "See the Varlatch release notes for this version." });
  }
  return steps;
}

/**
 * The consequences of activating the moved revision. Text in backticks is a
 * command and renders as code.
 */
export function moveConsequences(from: number, to: number, authority: "git" | "managed"): string[] {
  const out = [
    from < 2
      ? "Version 1 defines no conversion, so `varlatch types` could not generate types for this project; from version 2 it can."
      : "Generated types from `varlatch types` become stale; regenerate them.",
    `A CLI that does not implement version ${to} refuses \`varlatch run --strict\` for this project; upgrade CLIs that run it.`,
    from < 2 && to >= 2
      ? "Existing values are re-validated with the newer rules (numbers larger than 2^53 - 1 in magnitude become invalid from version 2)."
      : "Existing values are re-validated with the newer rules.",
  ];
  if (authority === "git") {
    out.push(`Later pushes from your repository keep version ${to}; you do not need to change the file.`);
  }
  return out;
}

type RevisionLike = { id: string; semanticsVersion?: number | null; contract?: unknown };

export interface MoveReview {
  /** Set when the pushed revision's version differs from the base's. */
  versionChange: { from: number; to: number } | null;
  /** Anything else that differs, or why the pushed revision is not the expected one. */
  otherChanges: string[];
  /** True only when the version moved to `target` and nothing else changed. */
  activatable: boolean;
}

/** Compare the pushed revision with the revision it was built from. */
export function reviewMove(base: RevisionLike, pushed: RevisionLike, target: number): MoveReview {
  const from = revisionSemanticsVersion(base);
  const to = revisionSemanticsVersion(pushed);
  const otherChanges: string[] = [];
  if (pushed.id === base.id) otherChanges.push("The server returned the active revision instead of a new one.");
  if (to !== target) otherChanges.push(`The pushed revision uses semantics version ${to}, not ${target}.`);

  const a = asContract(base.contract);
  const b = asContract(pushed.contract);
  for (const key of new Set([...Object.keys(a.rest), ...Object.keys(b.rest)])) {
    if (stableJson(a.rest[key]) !== stableJson(b.rest[key])) otherChanges.push(`Contract field changed: ${key}`);
  }
  for (const name of b.items.keys()) if (!a.items.has(name)) otherChanges.push(`Item added: ${name}`);
  for (const [name, item] of a.items) {
    if (!b.items.has(name)) otherChanges.push(`Item removed: ${name}`);
    else if (stableJson(item) !== stableJson(b.items.get(name))) otherChanges.push(`Item changed: ${name}`);
  }

  const versionChange = from !== to ? { from, to } : null;
  return { versionChange, otherChanges, activatable: versionChange !== null && otherChanges.length === 0 };
}

function asContract(contract: unknown): { items: Map<string, unknown>; rest: Record<string, unknown> } {
  const { items, semanticsVersion: _version, ...rest } = (contract ?? {}) as Record<string, unknown>;
  const byName = new Map<string, unknown>();
  if (Array.isArray(items)) {
    for (const item of items) byName.set(String((item as { name?: unknown }).name), item);
  }
  return { items: byName, rest };
}

/** JSON with object keys sorted, so key order never counts as a change. */
function stableJson(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) =>
    v && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v as Record<string, unknown>).sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0)))
      : v,
  ) ?? "undefined";
}
