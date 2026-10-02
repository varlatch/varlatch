// SPDX-License-Identifier: Apache-2.0
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

/**
 * File helpers for `varlatch agents install` (ADR-0043 Decisions 7 and 8):
 * exact additions that removing takes back byte for byte, and reads that
 * never turn a file the CLI must not rewrite into text.
 */

export function eolOf(text: string): string {
  return text.includes("\r\n") ? "\r\n" : "\n";
}

/**
 * The CLI's additions are exact, so that removing one gives the file back
 * byte for byte. A new file is the addition alone. An existing file, even
 * an empty one, keeps every byte and gains one line break (which ends its
 * last line, or leaves a blank line when it already ended one) and then the
 * addition, whose lines end with the file's line ending.
 */
export function appendOwned(current: string | null, owned: string): string {
  return current === null ? owned : current + eolOf(current) + owned;
}

/**
 * The line ending of an addition at [start, end): the one inside it, else
 * the one that ends it. install used the same one for the line break it put
 * before the addition, so this is what removing takes back, and what
 * installing again reuses. Judging from the whole file instead would be
 * fooled by the file's own bytes next to the addition: a file ending in a
 * bare CR, followed by the LF install added, reads as CRLF.
 */
export function ownedEol(text: string, start: number, end: number): string {
  const span = text.slice(start, end);
  if (span.includes("\r\n")) return "\r\n";
  if (span.includes("\n")) return "\n";
  return text.startsWith("\r\n", end) ? "\r\n" : "\n";
}

/**
 * The file without the addition at [start, end), and without the line break
 * that ends it. At the end of the file, the line break install put before
 * it goes too. Only those exact bytes go, so the file's own bytes around
 * them stay. Null: nothing precedes or follows the addition, so install
 * created the file and removing takes the file away.
 */
export function withoutOwned(text: string, start: number, end: number): string | null {
  const eol = ownedEol(text, start, end);
  const before = text.slice(0, start);
  const rest = text.slice(end);
  const after = rest.startsWith(eol) ? rest.slice(eol.length) : rest;
  if (after !== "") return before + after;
  if (before === "") return null;
  return before.endsWith(eol) ? before.slice(0, -eol.length) : before;
}

export function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * A file's text; null when there is no file; undefined when the path is not
 * a UTF-8 text file, which the CLI never edits (decoding and encoding again
 * would change its bytes). A byte order mark is kept.
 */
export function readText(path: string): string | null | undefined {
  const bytes = readBytes(path);
  if (bytes === undefined || bytes === null) return bytes;
  try {
    return UTF8.decode(bytes);
  } catch {
    return undefined;
  }
}

/** A file's bytes; null when nothing is there; undefined when something other than a file is. */
export function readBytes(path: string): Buffer | null | undefined {
  try {
    if (!statSync(path).isFile()) return undefined;
  } catch {
    return null;
  }
  return readFileSync(path);
}

export function filesUnder(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...filesUnder(path));
    else out.push(path);
  }
  return out;
}

export function isCanonicalJson(raw: string, parsed: unknown): boolean {
  const canonical = JSON.stringify(parsed, null, 2);
  return raw === canonical || raw === `${canonical}\n`;
}

/**
 * The edits one run plans, on top of each other: a later edit of a file
 * reads what an earlier one wrote (the Gemini CLI adapter and the MCP entry
 * both edit .gemini/settings.json, guardrails and the MCP entry both edit
 * .codex/config.toml). Nothing touches the disk until the run applies them.
 */
export class Staging {
  private readonly staged = new Map<string, string | null>();

  read(path: string): string | null | undefined {
    return this.staged.has(path) ? (this.staged.get(path) as string | null) : readText(path);
  }

  write(path: string, desired: string | null): void {
    this.staged.set(path, desired);
  }

  entries(): { path: string; desired: string | null }[] {
    return [...this.staged].map(([path, desired]) => ({ path, desired }));
  }
}
