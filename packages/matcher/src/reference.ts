// SPDX-License-Identifier: Apache-2.0
import { formsOf } from "./forms.js";
import type { SecretEntry } from "./matcher.js";

/**
 * The whole-input reference for ADR-0039 Decision 18, deliberately written
 * differently from the streaming matcher (a naive search over the complete
 * input, no automaton, no hold-back) so the two can check each other. It is
 * for tests only: it needs the whole input in memory.
 */
export function scrubWhole(
  input: Uint8Array,
  entries: SecretEntry[],
  replacement: (item: string) => Uint8Array,
): Uint8Array {
  const matches: { start: number; end: number; item: string }[] = [];
  const haystack = Buffer.from(input);
  for (const { item, value } of entries) {
    for (const form of formsOf(value)) {
      const needle = Buffer.from(form);
      for (let at = haystack.indexOf(needle); at >= 0; at = haystack.indexOf(needle, at + 1)) {
        matches.push({ start: at, end: at + needle.length, item });
      }
    }
  }
  // Regions: unions of matches sharing at least one byte.
  matches.sort((a, b) => a.start - b.start || b.end - a.end);
  const regions: { start: number; end: number; members: typeof matches }[] = [];
  for (const match of matches) {
    const last = regions[regions.length - 1];
    if (last && match.start < last.end) {
      last.end = Math.max(last.end, match.end);
      last.members.push(match);
    } else {
      regions.push({ start: match.start, end: match.end, members: [match] });
    }
  }
  const out: number[] = [];
  let at = 0;
  for (const region of regions) {
    for (; at < region.start; at++) out.push(input[at]!);
    // Earliest start, then longest, then the item name that sorts first.
    const winner = [...region.members].sort(
      (a, b) =>
        a.start - b.start ||
        b.end - b.start - (a.end - a.start) ||
        Buffer.compare(Buffer.from(a.item), Buffer.from(b.item)),
    )[0]!;
    for (const b of replacement(winner.item)) out.push(b);
    at = region.end;
  }
  for (; at < input.length; at++) out.push(input[at]!);
  return Uint8Array.from(out);
}
