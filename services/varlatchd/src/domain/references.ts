// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Value references: a value may embed \${NAME} to reuse another Config
 * Item's value from the same Effective Configuration (same environment,
 * including parent inheritance). Expansion is strictly server-side and
 * never expands authority: a reference is only substituted when the caller
 * receives (or is authorized to read) the referenced value through the same
 * operation — otherwise the reference stays literal. $${NAME} escapes to a
 * literal ${NAME}.
 */

import { DomainError } from "./errors.js";

const TOKEN = /\$\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

/** Bounded so reference cycles terminate (leaving the cycle literal). */
export const MAX_REFERENCE_DEPTH = 8;

/** Names referenced (unescaped) in one raw value. */
export function referencedNames(raw: string): string[] {
  const names: string[] = [];
  for (const m of raw.matchAll(TOKEN)) {
    if (m[2]) names.push(m[2]);
  }
  return names;
}

/** Maximum expanded UTF-8 bytes per value, including literals. */
export const MAX_EXPANDED_BYTES = 1024 * 1024;

export class ReferenceExpansionError extends DomainError {
  /** True when a reference would stay literal; false for a size or work limit. */
  readonly unresolved: boolean;
  constructor(message: string, unresolved = false) {
    super("VALIDATION_FAILED", message);
    this.unresolved = unresolved;
  }
}

/** Resolve chains without ever reinterpreting escaped references. Strict
 * delivery rejects incomplete expansions; metadata may retain unreadable
 * references literally. Both modes bound work and output size. */
export function expandReferences(
  raw: string,
  lookup: (name: string) => string | undefined,
  strict = false,
  /** Called with the name of every reference left literal (lenient mode). */
  onUnexpanded?: (name: string) => void,
): string {
  let remaining = MAX_EXPANDED_BYTES;
  const chunks: string[] = [];
  let work = 0;
  const append = (text: string) => {
    remaining -= Buffer.byteLength(text, "utf8");
    if (remaining < 0) throw new ReferenceExpansionError("expanded value exceeds 1 MiB");
    chunks.push(text);
  };
  const visit = (text: string, path: Set<string>) => {
    let offset = 0;
    for (const match of text.matchAll(TOKEN)) {
      if (++work > 10_000) throw new ReferenceExpansionError("reference expansion exceeds work limit");
      append(text.slice(offset, match.index));
      offset = match.index + match[0].length;
      if (match[1]) { append("${" + match[1] + "}"); continue; }
      const name = match[2]!;
      const value = lookup(name);
      if (value === undefined || path.has(name) || path.size >= MAX_REFERENCE_DEPTH) {
        if (strict) throw new ReferenceExpansionError(value === undefined ? `references outside the disclosure set (${name})` : `cyclic or too-deep reference (${name})`, true);
        onUnexpanded?.(name);
        append(match[0]);
      } else {
        visit(value, new Set([...path, name]));
      }
    }
    append(text.slice(offset));
  };
  visit(raw, new Set());
  return chunks.join("");
}
