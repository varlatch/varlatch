// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { COLUMN_TYPES, digestInput, encodeRow, encodeValue, jsonbText, type ColumnType, type Value } from "../src/migration/canonical.js";

/**
 * canonical-v1 (go/server/migration/canonical/CANONICAL.md): this encoder
 * reproduces varlatchd's vectors byte for byte. The vectors file is
 * varlatchd's, the same bytes (its manifest_test checks the copy).
 */

interface Vectors {
  values: { name: string; type: ColumnType; input: unknown; output: string }[];
  refused: { name: string; type: ColumnType; input: unknown; why: string }[];
  rows: { name: string; types: ColumnType[]; inputs: unknown[]; output: string }[];
  digests: { name: string; class: string; ids: Record<string, string>; plaintext: string; output: string }[];
}

const vectors = JSON.parse(readFileSync(new URL("./migration/canonical-vectors.json", import.meta.url), "utf8")) as Vectors;

/** A vector's neutral input as the export holds it (the pg driver's forms, bigints for integers). */
function native(type: ColumnType, input: unknown): Value {
  if (input === null) return null;
  switch (type) {
    case "timestamp with time zone":
    case "integer":
    case "bigint":
      return BigInt(input as string);
    case "bytea":
      return Buffer.from(input as string, "hex");
    default:
      return input as Value;
  }
}

describe("canonical-v1 vectors", () => {
  it("covers every type", () => {
    expect(new Set(vectors.values.map((v) => v.type))).toEqual(new Set(COLUMN_TYPES));
  });

  for (const v of vectors.values) {
    it(`writes ${v.name}`, () => {
      expect(encodeValue(v.type, native(v.type, v.input))).toBe(v.output);
    });
  }

  for (const v of vectors.refused) {
    it(`refuses ${v.name}`, () => {
      expect(() => encodeValue(v.type, native(v.type, v.input))).toThrow();
    });
  }

  for (const r of vectors.rows) {
    it(`writes ${r.name}`, () => {
      expect(encodeRow(r.types, r.inputs.map((input, i) => native(r.types[i]!, input)))).toBe(r.output);
    });
  }

  for (const d of vectors.digests) {
    it(`writes the digest input of ${d.name}`, () => {
      expect(digestInput(d.class, d.ids, Buffer.from(d.plaintext, "hex"))).toBe(d.output);
    });
  }
});

describe("canonical-v1, what only JavaScript can hold", () => {
  it("refuses a lone surrogate in text, text[] and jsonb", () => {
    expect(() => encodeValue("text", "a\ud800")).toThrow();
    expect(() => encodeValue("text[]", ["\udc00"])).toThrow();
    expect(() => jsonbText('{"\\ud800": 1}')).toThrow();
    expect(() => digestInput("value", { id: "\ud800" }, new Uint8Array())).toThrow();
  });

  it("takes an integer only as a bigint or a safe integer, never a double", () => {
    expect(encodeValue("integer", 7)).toBe("7");
    expect(() => encodeValue("bigint", 2 ** 53)).toThrow();
    expect(() => encodeValue("bigint", 1.5)).toThrow();
    expect(() => encodeValue("timestamp with time zone", "1")).toThrow();
  });

  it("writes keys that are array indexes in jsonb's order, not JavaScript's", () => {
    expect(jsonbText('{"b": 1, "10": 2, "9": 3}')).toBe('{"9":3,"b":1,"10":2}');
  });

  it("writes a Buffer slice's own bytes", () => {
    const whole = Buffer.from("00ff10ab", "hex");
    expect(encodeValue("bytea", whole.subarray(1, 3))).toBe('"/xA="');
  });

  it("refuses a row with more values than types", () => {
    expect(() => encodeRow(["text"], ["a", "b"])).toThrow();
  });
});
