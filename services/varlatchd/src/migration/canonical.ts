// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The migration's canonical encoding, canonical-v1 (ADR-0059 Decision 9;
 * docs/design/go-step7.md decision 3). It says how the export writes a
 * value, a row and decision 7's digest input, byte for byte as varlatchd
 * writes them (go/server/migration/canonical, whose CANONICAL.md is the
 * specification). test/migration/canonical-vectors.json is varlatchd's
 * vectors file, the same bytes; both encoders reproduce it.
 */

/** A column's PostgreSQL type, as the manifest names it. */
export type ColumnType =
  | "text"
  | "timestamp with time zone"
  | "integer"
  | "bigint"
  | "boolean"
  | "jsonb"
  | "text[]"
  | "bytea";

export const COLUMN_TYPES: readonly ColumnType[] = [
  "text",
  "timestamp with time zone",
  "integer",
  "bigint",
  "boolean",
  "jsonb",
  "text[]",
  "bytea",
];

/**
 * A value as the export holds it:
 * - null for SQL NULL;
 * - text: a string;
 * - timestamps (microseconds since the epoch, UTC), integers and bigints:
 *   a bigint, never a double (a number is taken only when it is a safe
 *   integer);
 * - boolean: a boolean;
 * - jsonb: its JSON text (the column read as text);
 * - text[]: an array of strings and nulls;
 * - bytea: a Uint8Array (a Buffer is one).
 */
export type Value = null | string | bigint | number | boolean | Uint8Array | readonly (string | null)[];

export class CanonicalError extends Error {
  override name = "CanonicalError";
}

const INT4_MIN = -2147483648n;
const INT4_MAX = 2147483647n;

/** Writes a value of a column of the given type in canonical form. */
export function encodeValue(type: ColumnType, value: Value): string {
  if (!COLUMN_TYPES.includes(type)) throw new CanonicalError(`canonical: the encoding does not define type ${JSON.stringify(type)}`);
  if (value === null) return "null";
  switch (type) {
    case "text":
      if (typeof value !== "string") throw typeError(type, value);
      checkText(value);
      return quote(value);
    case "timestamp with time zone":
    case "integer":
    case "bigint": {
      const n = asBigInt(type, value);
      if (type === "integer" && (n < INT4_MIN || n > INT4_MAX)) {
        throw new CanonicalError(`canonical: ${n} is outside an integer's 32 bits`);
      }
      return n.toString();
    }
    case "boolean":
      if (typeof value !== "boolean") throw typeError(type, value);
      return value ? "1" : "0";
    case "jsonb":
      if (typeof value !== "string") throw typeError(type, value);
      return quote(jsonbText(value));
    case "text[]": {
      if (!Array.isArray(value)) throw typeError(type, value);
      const parts = value.map((e: unknown, i: number) => {
        if (e === null) return "null";
        if (typeof e !== "string") throw new CanonicalError(`canonical: text[] element ${i + 1} is not a string or null`);
        checkText(e);
        return quote(e);
      });
      return `[${parts.join(",")}]`;
    }
    case "bytea":
      if (!(value instanceof Uint8Array)) throw typeError(type, value);
      return quote(Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString("base64"));
  }
}

/** Writes a row: its values in the manifest's column order, as a JSON array with no space. */
export function encodeRow(types: readonly ColumnType[], values: readonly Value[]): string {
  if (types.length !== values.length) throw new CanonicalError(`canonical: ${types.length} types for ${values.length} values`);
  return `[${types
    .map((t, i) => {
      try {
        // Indexed as it is: a hole or undefined is refused, never read as NULL.
        return encodeValue(t, values[i] as Value);
      } catch (err) {
        throw new CanonicalError(`column ${i + 1}: ${(err as Error).message}`);
      }
    })
    .join(",")}]`;
}

/**
 * A jsonb value's canonical text: parsed as JSON.parse parses it, every
 * object's members in jsonb's order (shorter keys first, keys of one length
 * by their bytes, both in UTF-8), written as JSON.stringify writes it. Text
 * jsonb would refuse (a lone surrogate, U+0000) is refused, and so is a
 * number a double does not hold exactly (checkNumbers): a migration never
 * changes a value silently.
 */
export function jsonbText(text: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new CanonicalError(`canonical: jsonb: ${(err as Error).message}`);
  }
  checkNumbers(text);
  return writeJsonb(parsed);
}

/**
 * Refuses JSON text (already parsed, so well formed) holding a number whose
 * spelling is not the one ECMAScript writes for its double: parsing it and
 * writing it back must give the same text. "1.0", "0.10", "1e2", "-0",
 * "123456789012345678901" and "1e999" are refused; PostgreSQL's jsonb keeps
 * them as written (as numeric), and a double would change them.
 */
function checkNumbers(text: string): void {
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (inString) {
      if (c === "\\") i++; // the escaped character; a \u escape's hex digits hold no quote
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') {
      inString = true;
    } else if (c === "-" || (c >= "0" && c <= "9")) {
      let j = i;
      while (j < text.length && "+-0123456789.eE".includes(text[j]!)) j++;
      const token = text.slice(i, j);
      if (String(Number(token)) !== token) {
        throw new CanonicalError(`canonical: jsonb number ${token.slice(0, 40)} is not exactly a double; the migration would change it`);
      }
      i = j - 1;
    }
  }
}

/**
 * What decision 7's keyed digest is computed over for one decrypted item:
 * the canonical JSON of {class, ids, plaintext}, members in jsonb's order
 * (so ids, class, plaintext), the ids' members too, and the plaintext's
 * bytes in base64.
 */
export function digestInput(cls: string, ids: Readonly<Record<string, string>>, plaintext: Uint8Array): string {
  checkText(cls);
  for (const [k, v] of Object.entries(ids)) {
    checkText(k);
    checkText(v);
  }
  return writeJsonb({
    class: cls,
    ids,
    plaintext: Buffer.from(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength).toString("base64"),
  });
}

// writeJsonb writes a parsed JSON value with jsonb's member order. Objects
// are written member by member: a JavaScript object would put keys that are
// array indexes ("9", "10") first, whatever order they were given in.
function writeJsonb(v: unknown): string {
  if (v === null || typeof v === "boolean" || typeof v === "number") return JSON.stringify(v);
  if (typeof v === "string") {
    checkJsonbString(v);
    return quote(v);
  }
  if (Array.isArray(v)) return `[${v.map(writeJsonb).join(",")}]`;
  if (typeof v === "object") {
    const keys = Object.keys(v);
    for (const k of keys) checkJsonbString(k);
    keys.sort(jsonbKeyOrder);
    return `{${keys.map((k) => `${quote(k)}:${writeJsonb((v as Record<string, unknown>)[k])}`).join(",")}}`;
  }
  throw new CanonicalError(`canonical: jsonb cannot hold a ${typeof v}`);
}

/** jsonb's key order: shorter keys first, keys of one length by their bytes, in UTF-8. */
export function jsonbKeyOrder(a: string, b: string): number {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  return ab.length !== bb.length ? ab.length - bb.length : Buffer.compare(ab, bb);
}

// In a u-flag pattern a surrogate pair is one code point, so this matches
// only a surrogate that is not half of a pair.
const LONE_SURROGATE = /[\uD800-\uDFFF]/u;

function checkJsonbString(s: string): void {
  if (LONE_SURROGATE.test(s)) throw new CanonicalError("canonical: jsonb refuses a lone surrogate");
  if (s.includes("\u0000")) throw new CanonicalError("canonical: jsonb refuses \\u0000");
}

/** Refuses what PostgreSQL's text cannot hold: a lone surrogate (not UTF-8) and U+0000. */
function checkText(s: string): void {
  if (LONE_SURROGATE.test(s)) throw new CanonicalError("canonical: text that is not UTF-8");
  if (s.includes("\u0000")) throw new CanonicalError("canonical: text holding U+0000");
}

/** JSON.stringify's quoting: CANONICAL.md's, with no other escape. */
function quote(s: string): string {
  return JSON.stringify(s);
}

function asBigInt(type: ColumnType, v: Value): bigint {
  if (typeof v === "bigint") return v;
  if (typeof v === "number" && Number.isSafeInteger(v)) return BigInt(v);
  throw typeError(type, v);
}

function typeError(type: ColumnType, v: unknown): CanonicalError {
  const kind = v instanceof Uint8Array ? "Uint8Array" : Array.isArray(v) ? "array" : typeof v;
  return new CanonicalError(`canonical: a ${kind} for a ${type} column`);
}
