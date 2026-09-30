// SPDX-License-Identifier: Apache-2.0
import { parse as parseToml } from "smol-toml";
import { appendOwned, eolOf, ownedEol, withoutOwned } from "./files.js";

/**
 * The CLI's tables in a TOML file (ADR-0043 Decisions 8 and 9), kept in one
 * marked region at the end of the file. One region, however many tables:
 * two separately appended blocks could not both be taken back byte for
 * byte, since the line break before the first would end up in the middle
 * of the file. A change is kept only when the parser confirms the file says
 * what it said before plus exactly the change (TOML forbids defining a
 * table twice, and a file may end mid-structure). Removing the last table
 * removes the region with the line breaks install added, so the file is
 * byte for byte as before.
 */

export type Table = Record<string, unknown>;

export function isTable(value: unknown): value is Table {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Date);
}

/** A value's JSON with keys sorted: equal for equal data, whatever its objects' prototypes. */
export function canonicalData(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) =>
    isTable(v) ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) : v,
  );
}

export function parseTomlOrNull(text: string): Table | null {
  try {
    return parseToml(text) as Table;
  } catch {
    return null;
  }
}

export const REGION_BEGIN = "# varlatch:begin: added by varlatch agents install; varlatch agents install --remove takes it out";
export const REGION_END = "# varlatch:end";

/** The tables the CLI writes, by header, in the order it writes them. */
export const TOML_PARTS = ["[shell_environment_policy.set]", "[mcp_servers.varlatch]"] as const;
export type TomlPart = (typeof TOML_PARTS)[number];

interface Region {
  start: number;
  /** Just after the end marker. */
  end: number;
  parts: Map<string, string[]>;
}

/** The CLI's region, its tables by header; null when there is none; "damaged" when a marker is missing or it holds something else. */
function regionOf(text: string): Region | null | "damaged" {
  const begin = new RegExp(`(^|\\n)${REGION_BEGIN.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\r?\\n`).exec(text);
  const hasEnd = text.includes(REGION_END);
  if (!begin) return hasEnd ? "damaged" : null;
  const start = begin.index + begin[1]!.length;
  const innerStart = begin.index + begin[0].length;
  const endAt = text.indexOf(REGION_END, innerStart);
  if (endAt < 0 || (endAt > 0 && text[endAt - 1] !== "\n")) return "damaged";
  const parts = new Map<string, string[]>();
  let current: string[] | null = null;
  for (const line of text.slice(innerStart, endAt).split(/\r?\n/)) {
    if ((TOML_PARTS as readonly string[]).includes(line)) {
      current = [];
      parts.set(line, current);
    } else if (line !== "") {
      if (current === null) return "damaged";
      current.push(line);
    }
  }
  return { start, end: endAt + REGION_END.length, parts };
}

function regionText(parts: Map<string, string[]>, eol: string): string {
  const tables = TOML_PARTS.filter((h) => parts.has(h)).map((h) => [h, ...(parts.get(h) as string[])].join(eol));
  return [REGION_BEGIN, tables.join(eol + eol), REGION_END].join(eol);
}

/**
 * `current` with the CLI's table `header` set to `body` (its lines after
 * the header), or taken out when `body` is null; or null with the reason
 * the CLI leaves the file to the human. `expected` gives what the whole
 * file must parse to after setting the table.
 */
export function withTomlPart(
  current: string | null,
  header: TomlPart,
  body: readonly string[] | null,
  expected: (before: Table) => Table = (b) => b,
): { next: string | null; reason?: string } {
  const text = current ?? "";
  const region = regionOf(text);
  if (region === "damaged") return { next: null, reason: "its varlatch:begin/varlatch:end block is damaged" };
  if (body === null) {
    if (region === null || !region.parts.has(header)) return { next: current };
    region.parts.delete(header);
    if (region.parts.size === 0) return { next: withoutOwned(text, region.start, region.end) };
    const eol = ownedEol(text, region.start, region.end);
    return { next: text.slice(0, region.start) + regionText(region.parts, eol) + text.slice(region.end) };
  }
  const before = parseTomlOrNull(text);
  if (before === null) return { next: null, reason: "it does not parse as TOML" };
  if (region !== null && canonicalData(region.parts.get(header)) === canonicalData([...body])) return { next: current };
  const parts = new Map(region === null ? [] : region.parts);
  parts.set(header, [...body]);
  const next =
    region === null
      ? appendOwned(current, regionText(parts, eolOf(text)) + eolOf(text))
      : text.slice(0, region.start) + regionText(parts, ownedEol(text, region.start, region.end)) + text.slice(region.end);
  const after = parseTomlOrNull(next);
  if (after === null || canonicalData(after) !== canonicalData(expected(before))) {
    return { next: null, reason: "adding to it would change what it says" };
  }
  return { next };
}
