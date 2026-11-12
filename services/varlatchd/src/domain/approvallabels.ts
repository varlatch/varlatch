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
 * Shared by every summary of step 4: identitystepup.ts (4.5),
 * accessstepup.ts (4.6), and the people (4.7) and integration (4.8)
 * operations. Keep this name and location.
 */

/**
 * Characters a reader cannot see: controls (Cc), format characters (Cf:
 * zero-width spaces and joiners, bidi overrides, U+FEFF), line and
 * paragraph separators (Zl, Zp), every whitespace but the plain ASCII
 * space (no-break and other spaces among them), and the other default
 * ignorable code points (variation selectors, U+180E, U+3164). Each is
 * written as `\u{XXXX}`, so two names that differ only by one never read
 * the same.
 */
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]|[^\S ]/gu;
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
 * Free text a summary writes unquoted (action names, an OIDC issuer,
 * audience, subject or claim): a backslash doubled, then every invisible
 * character written as `\u{XXXX}`, as in quoted().
 */
export function visible(text: string): string {
  return escapeInvisible(text.replace(/\\/g, "\\\\"));
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

/** An id the summary could not name (no row of this Organization has it): the id alone, which never looks like a quoted name. */
export function unnamed(kind: string | null, id: string): string {
  return `${kind ? `${kind} ` : ""}${id}`;
}
