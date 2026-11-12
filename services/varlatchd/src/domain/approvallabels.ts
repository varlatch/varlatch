// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * How a step-up approval's summary names things (ADR-0054 Decision 3): the
 * approver must be able to tell, from the words alone, exactly which rows
 * an approval is for. Names are not unique and may contain anything a
 * request accepted: trailing whitespace, parentheses, text that looks like
 * an id, invisible characters. So a named item is always written as its
 * name in JSON quotes, with every character a reader cannot see escaped,
 * followed by the id the approval binds, whether or not another row shares
 * the name. A collision lookup could miss a case; this has none to miss.
 *
 * The rule, by construction: a summary holds no free text (from the
 * database or the request) that is not quoted. Names, action names, an
 * OIDC issuer, audience, subject and claims, Tailnet selector parts, tags,
 * URLs and slugs all go through quoted(); lists through quotedList() or
 * list(); maps through quotedMap(). Every existing item is named with
 * labelWithId(). Only the summary's own words, numbers, ids the server
 * resolved, and validated enum values (an identity kind, a tier) are
 * written bare: their sets are fixed and hold no delimiter.
 *
 * Shared by every summary of step 4: requirementprotection.ts (4.2),
 * identitystepup.ts (4.5), accessstepup.ts (4.6), and the people (4.7)
 * and integration (4.8) operations. Keep these names and this location.
 */

/**
 * Characters a reader cannot see: controls (Cc), format characters (Cf:
 * zero-width spaces and joiners, bidi overrides, U+FEFF), line and
 * paragraph separators (Zl, Zp), every whitespace but the plain ASCII
 * space (no-break and other spaces among them), and the other default
 * ignorable code points (variation selectors, U+180E, U+3164), and U+2800
 * (a blank braille pattern, which renders as a space). Each is
 * written as `\u{XXXX}`, so two names that differ only by one never read
 * the same.
 */
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\u2800]|[^\S ]/gu;
const escapeInvisible = (text: string) =>
  text.replace(INVISIBLE, (c) => `\\u{${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}}`);

/**
 * A name as a summary writes it: JSON-quoted (a backslash, a quote and the
 * C0 controls escaped as JSON does), then every invisible character JSON
 * leaves literal written as `\u{XXXX}`. The escapes cannot be faked: a
 * backslash typed in the name is already doubled.
 */
export function quoted(name: string): string {
  return escapeInvisible(JSON.stringify(name));
}

/**
 * A named item with its bound id: `"Bob" (idn_…)`, after an optional kind
 * (`role "reader" (rol_…)`). The quotes make the id suffix impossible to
 * fake from inside a name: a name's own quotes and parentheses stay inside
 * the escaped string.
 */
export function labelWithId(kind: string | null, name: string, id: string): string {
  return `${kind ? `${kind} ` : ""}${quoted(name)} (${id})`;
}

/**
 * An id the summary could not name: no row of this Organization has it, so
 * it came from the request and is free text. Written quoted, after words
 * that say so, so it never reads like a name or a known id.
 */
export function unnamed(kind: string | null, id: string): string {
  return `${kind ? `${kind} ` : ""}with unknown id ${quoted(id)}`;
}

/**
 * A list as a summary writes it: items already rendered (quoted values, or
 * labelWithId labels), in brackets, separated by ", ". Each item is
 * delimited by its own quotes, so a comma or bracket inside a value never
 * reads as a separator.
 */
export function list(items: readonly string[]): string {
  return `[${items.join(", ")}]`;
}

/** A list of free-text values: `["config.value.read", "project.read"]`. */
export function quotedList(values: readonly string[]): string {
  return list(values.map(quoted));
}

/** A map of free-text keys and values, keys in sorted order: `{"ref": "main", "repo": "acme/api"}`. */
export function quotedMap(map: Readonly<Record<string, string>>): string {
  const keys = Object.keys(map).sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
  return `{${keys.map((k) => `${quoted(k)}: ${quoted(map[k]!)}`).join(", ")}}`;
}
