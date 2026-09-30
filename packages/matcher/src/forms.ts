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

const UNPAIRED_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

/**
 * A value as UTF-8 carries it. A stored value can hold an unpaired UTF-16
 * surrogate (JSON allows `"\ud83d"`), but UTF-8 cannot: an environment
 * variable, a header, percent-encoding, and a terminal all carry U+FFFD in
 * its place. The raw, percent, and base64 forms are computed from this
 * text, so they never throw (percent-encoding rejects an unpaired
 * surrogate) and match what a command can print.
 */
export function deliveredText(value: string): string {
  return value.replace(UNPAIRED_SURROGATE, "\uFFFD");
}

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

/**
 * The name of a form, as reported by scanning: `raw` (as written), `json`
 * (either JSON escaping), `percent` (either hex case), `base64`, or
 * `base64url`. When two forms have the same bytes, the earlier name in this
 * order is reported (a base64url form without `-` or `_` is `base64`).
 */
export type FormName = "raw" | "json" | "percent" | "base64" | "base64url";

export interface LabelledForm {
  form: FormName;
  bytes: Uint8Array;
}

/**
 * Every registered form of `value` with its name, deduplicated, each at
 * least MIN_LENGTH bytes, in the order `formsOf` returns them.
 */
export function labelledFormsOf(stored: string): LabelledForm[] {
  const value = deliveredText(stored);
  const raw = encoder.encode(value);
  if (raw.length < MIN_LENGTH) return [];
  // JSON keeps an unpaired surrogate as a `\udXXX` escape instead of
  // replacing it: a JSON body carrying the stored value (the Broker's JSON
  // targets write one) holds the stored value's escaping. Both are
  // registered; for a well-formed value they are the same form.
  const storedJson = JSON.stringify(stored).slice(1, -1);
  const json = JSON.stringify(value).slice(1, -1);
  const percent = encodeURIComponent(value);
  const candidates: [FormName, string][] = [
    ["raw", value],
    ["json", storedJson],
    ["json", storedJson.replace(/\//g, "\\/")],
    ["json", json],
    ["json", json.replace(/\//g, "\\/")],
    ["percent", percent],
    ["percent", percent.replace(/%[0-9A-F]{2}/g, (e) => e.toLowerCase())],
  ];
  for (const alignment of [0, 1, 2]) {
    candidates.push(["base64", base64Core(raw, alignment, false)], ["base64url", base64Core(raw, alignment, true)]);
  }
  const seen = new Set<string>();
  const forms: LabelledForm[] = [];
  for (const [form, candidate] of candidates) {
    const bytes = encoder.encode(candidate);
    if (bytes.length < MIN_LENGTH || seen.has(candidate)) continue;
    seen.add(candidate);
    forms.push({ form, bytes });
  }
  return forms;
}

/** Every registered form of `value`, deduplicated, each at least MIN_LENGTH bytes. */
export function formsOf(value: string): Uint8Array[] {
  return labelledFormsOf(value).map((f) => f.bytes);
}
