// SPDX-License-Identifier: Apache-2.0

/**
 * The dotenv parser behind `varlatch import` (ADR-0043 Decision 2). It reads
 * the common dotenv format:
 *
 *   # comment
 *   NAME=value                 unquoted: trimmed; whitespace then `#` starts a comment
 *   export NAME=value          an `export ` prefix is ignored
 *   NAME = value               spaces or tabs around `=` are allowed
 *   NAME='literal'             single quotes and backticks: taken as written,
 *   NAME=`literal`             and may span lines
 *   NAME="text\n"              double quotes: \n \r \t \" \\ are escapes, and
 *                              may span lines
 *   NAME=                      an empty value
 *
 * Nothing is expanded: `$OTHER` and `${OTHER}` stay as written. Errors carry
 * a line number and a reason, never the line's text or any part of a value,
 * since the file holds secrets.
 */

export interface DotenvEntry {
  name: string;
  value: string;
  /** The 1-based line the entry starts on. */
  line: number;
}

export class DotenvParseError extends Error {
  override name = "DotenvParseError";
  readonly line: number;
  constructor(line: number, reason: string) {
    super(`line ${line}: ${reason}`);
    this.line = line;
  }
}

const NAME = /^[A-Za-z_][A-Za-z0-9_.-]*/;
const ESCAPES: Record<string, string> = { n: "\n", r: "\r", t: "\t", '"': '"', "\\": "\\" };

export function parseDotenv(source: string): DotenvEntry[] {
  const text = source.startsWith("﻿") ? source.slice(1) : source;
  const lines = text.split(/\r?\n/);
  const entries: DotenvEntry[] = [];
  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    let rest = (lines[i] as string).replace(/^[ \t]+/, "");
    if (rest === "" || rest.startsWith("#")) continue;
    if (/^export[ \t]+/.test(rest)) rest = rest.replace(/^export[ \t]+/, "");
    const name = NAME.exec(rest)?.[0];
    if (!name) throw new DotenvParseError(lineNo, "expected NAME=value");
    rest = rest.slice(name.length).replace(/^[ \t]+/, "");
    if (!rest.startsWith("=")) throw new DotenvParseError(lineNo, "expected NAME=value");
    rest = rest.slice(1).replace(/^[ \t]+/, "");

    const quote = rest[0];
    if (quote === "'" || quote === "`" || quote === '"') {
      // A quoted value may continue on the following lines.
      let body = rest.slice(1);
      let value = "";
      let end = -1;
      for (;;) {
        end = closingQuote(body, quote);
        if (end >= 0) {
          value += body.slice(0, end);
          break;
        }
        value += `${body}\n`;
        i++;
        if (i >= lines.length) throw new DotenvParseError(lineNo, "a quoted value is not closed");
        body = lines[i] as string;
      }
      const after = body.slice(end + 1).replace(/^[ \t]+/, "");
      if (after !== "" && !after.startsWith("#")) {
        throw new DotenvParseError(i + 1, "unexpected text after a closing quote");
      }
      entries.push({ name, value: quote === '"' ? unescape(value, lineNo) : value, line: lineNo });
      continue;
    }
    // Unquoted: up to a comment (whitespace, then #), trimmed.
    const comment = /[ \t]#/.exec(rest);
    const value = (comment ? rest.slice(0, comment.index) : rest).replace(/[ \t]+$/, "");
    entries.push({ name, value, line: lineNo });
  }
  return entries;
}

/** The index of the quote that closes a value, or -1; in double quotes a backslash escapes the next character. */
function closingQuote(body: string, quote: string): number {
  for (let j = 0; j < body.length; j++) {
    const ch = body[j];
    if (quote === '"' && ch === "\\") {
      j++;
      continue;
    }
    if (ch === quote) return j;
  }
  return -1;
}

function unescape(value: string, line: number): string {
  let out = "";
  for (let j = 0; j < value.length; j++) {
    const ch = value[j] as string;
    if (ch !== "\\") {
      out += ch;
      continue;
    }
    const next = value[j + 1];
    if (next === undefined) throw new DotenvParseError(line, "a double-quoted value ends in a backslash");
    // An unknown escape keeps its backslash, as common dotenv parsers do.
    out += ESCAPES[next] ?? `\\${next}`;
    j++;
  }
  return out;
}
