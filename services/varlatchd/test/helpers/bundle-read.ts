// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Decision, Digest } from "../../src/migration/bundle.js";

/**
 * A bundle's parts, read leniently (the tests' reader: varlatchd's is the
 * strict one). Rows stay the lines they are; numbers in the sections and
 * the header are read as JSON reads them.
 */
export interface BundleParts {
  header: { frozenPoint: { auditPosition: number; snapshot: string } } & Record<string, unknown>;
  /** Each table's row lines, by table, in the order they came. */
  tables: Map<string, string[]>;
  digests: Digest[];
  /** The digest lines as written. */
  digestLines: string[];
  at: bigint;
  decisions: Decision[];
  end: Record<string, unknown> | null;
}

export function readBundle(text: string): BundleParts {
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  const header = JSON.parse(lines[0]!) as BundleParts["header"];
  const parts: BundleParts = { header, tables: new Map(), digests: [], digestLines: [], at: 0n, decisions: [], end: null };
  let section: "tables" | "digests" | "decisions" = "tables";
  let current: string[] | null = null;
  for (const line of lines.slice(1)) {
    const table = /^\{"table":"([^"]+)","rows":\d+\}$/.exec(line);
    if (line.startsWith('{"end":')) {
      parts.end = (JSON.parse(line) as { end: Record<string, unknown> }).end;
    } else if (table) {
      current = [];
      parts.tables.set(table[1]!, current);
    } else if (/^\{"digests":\d+\}$/.test(line)) {
      section = "digests";
    } else if (line.startsWith('{"decisions":')) {
      section = "decisions";
      parts.at = BigInt(/"at":(-?\d+)/.exec(line)![1]!);
    } else if (section === "digests") {
      parts.digests.push(JSON.parse(line) as Digest);
      parts.digestLines.push(line);
    } else if (section === "decisions") {
      const d = JSON.parse(line) as Decision;
      parts.decisions.push({ ...d, tailnet: d.tailnet ? { ...d.tailnet, userLogin: d.tailnet.userLogin ?? null } : null });
    } else {
      current?.push(line);
    }
  }
  return parts;
}
