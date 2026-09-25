// SPDX-License-Identifier: Apache-2.0

/**
 * The forms of a secret value the matcher looks for (ADR-0039 Decision 17):
 * raw UTF-8 bytes; JSON string escaping, with and without `\/`;
 * percent-encoding, with upper- and lower-case hex; and base64 and base64url
 * at each of the three byte alignments a value can have inside a longer
 * encoded string (so `user:secret` in a Basic header is found).
 *
 * Other transformations are not covered: hex, arbitrary `\uXXXX` escaping,
 * other character sets, compression, values split across fields, and
 * anything derived from the value.
 */

/** Values, and derived forms, shorter than this are never registered. */
export const MIN_LENGTH = 8;

const encoder = new TextEncoder();

function base64Core(value: Uint8Array, alignment: number, url: boolean): string {
  // Encode the value after `alignment` filler bytes, then keep only the
  // characters whose six bits all come from the value: they are the same
  // whatever surrounds the value in a longer string.
  const bytes = new Uint8Array(alignment + value.length);
  bytes.set(value, alignment);
  let encoded = Buffer.from(bytes).toString("base64").replace(/=+$/, "");
  const first = Math.ceil((8 * alignment) / 6);
  const last = Math.floor((8 * (alignment + value.length)) / 6);
  encoded = encoded.slice(first, last);
  return url ? encoded.replace(/\+/g, "-").replace(/\//g, "_") : encoded;
}

/** Every registered form of `value`, deduplicated, each at least MIN_LENGTH bytes. */
export function formsOf(value: string): Uint8Array[] {
  const raw = encoder.encode(value);
  if (raw.length < MIN_LENGTH) return [];
  const json = JSON.stringify(value).slice(1, -1);
  const percent = encodeURIComponent(value);
  const candidates = [
    value,
    json,
    json.replace(/\//g, "\\/"),
    percent,
    percent.replace(/%[0-9A-F]{2}/g, (e) => e.toLowerCase()),
  ];
  for (const alignment of [0, 1, 2]) {
    candidates.push(base64Core(raw, alignment, false), base64Core(raw, alignment, true));
  }
  const seen = new Set<string>();
  const forms: Uint8Array[] = [];
  for (const candidate of candidates) {
    const bytes = encoder.encode(candidate);
    if (bytes.length < MIN_LENGTH || seen.has(candidate)) continue;
    seen.add(candidate);
    forms.push(bytes);
  }
  return forms;
}
