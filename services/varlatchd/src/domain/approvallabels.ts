// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * How a step-up approval's summary names things (ADR-0054 Decision 3): the
 * approver must be able to tell, from the words alone, exactly which rows
 * an approval is for. Names are not unique and may contain anything a
 * request accepted: trailing whitespace, parentheses, text that looks like
 * an id. So a named item is always written as its name in JSON quotes
 * (whitespace, quotes and control characters stay visible and escaped),
 * followed by the id the approval binds, whether or not another row shares
 * the name. A collision lookup could miss a case; this has none to miss.
 *
 * Shared by every summary of step 4: identitystepup.ts (4.5),
 * accessstepup.ts (4.6), and the people (4.7) and integration (4.8)
 * operations. Keep this name and location.
 */

/** A name as a summary writes it: JSON-quoted. */
export function quoted(name: string): string {
  return JSON.stringify(name);
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
