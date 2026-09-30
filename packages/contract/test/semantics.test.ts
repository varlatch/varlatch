// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  ITEM_TYPES,
  ITEM_TYPE_SINCE_SEMANTICS,
  SEMANTICS_VERSIONS,
  UnsupportedSemanticsVersionError,
  semanticsFor,
  type ContractItem,
  type Requiredness,
  type SemanticsEnvironment,
} from "../src/index.js";

interface ValidateVector {
  type: ContractItem["type"];
  enumValues?: string[];
  value: string;
  valid: boolean;
  reason?: string;
  /** Present from version 2. A number is written as a string: `-0` and exact digits survive JSON. */
  converted?: { string: string } | { number: string } | { boolean: boolean };
}

interface RequiredVector {
  required: Requiredness;
  defaultValue?: string;
  environment: SemanticsEnvironment;
  requiredApplies: boolean;
  missingWhenAbsent: boolean;
}

interface Vectors {
  semanticsVersion: number;
  validate: ValidateVector[];
  required: RequiredVector[];
}

function load(version: number): Vectors {
  const url = new URL(`./vectors/semantics-v${version}.json`, import.meta.url);
  return JSON.parse(readFileSync(url, "utf8")) as Vectors;
}

function item(fields: Partial<ContractItem> & Pick<ContractItem, "type">): ContractItem {
  return { name: "ITEM", required: { kind: "never" }, sensitive: false, ...fields };
}

describe.each(SEMANTICS_VERSIONS.map((v) => [v]))("semantics version %i golden vectors", (version) => {
  const vectors = load(version);
  const semantics = semanticsFor(version);

  it("names its own version", () => {
    expect(vectors.semanticsVersion).toBe(version);
    expect(semantics.version).toBe(version);
  });

  it.each(vectors.validate.map((v) => [`${v.type} ${JSON.stringify(v.value)}`, v] as const))(
    "validate %s",
    (_, v) => {
      const reason = semantics.validate(
        item({ type: v.type, ...(v.enumValues ? { enumValues: v.enumValues } : {}) }),
        v.value,
      );
      expect(reason).toBe(v.valid ? null : v.reason);
    },
  );

  it.each(vectors.validate.map((v) => [`${v.type} ${JSON.stringify(v.value)}`, v] as const))(
    "parse %s",
    (_, v) => {
      const subject = item({ type: v.type, ...(v.enumValues ? { enumValues: v.enumValues } : {}) });
      if (!semantics.parse) {
        expect(v.converted, "a version without conversion has no converted vectors").toBeUndefined();
        return;
      }
      const result = semantics.parse(subject, v.value);
      if (!v.valid) {
        expect(result).toEqual({ ok: false, reason: v.reason });
        return;
      }
      // Every string that validates converts.
      expect(result.ok).toBe(true);
      const value = result.ok ? result.value : undefined;
      const expected = v.converted;
      expect(expected, "every valid vector names its conversion").toBeDefined();
      if (expected && "number" in expected) {
        expect(typeof value).toBe("number");
        expect(Object.is(value, Number(expected.number)), `${String(value)} is ${expected.number}`).toBe(true);
      } else {
        expect(value).toStrictEqual(expected && ("boolean" in expected ? expected.boolean : expected.string));
      }
    },
  );

  it.each(vectors.required.map((v, i) => [i, v] as const))("requiredness vector %i", (_, v) => {
    const subject = item({
      type: "string",
      required: v.required,
      ...(v.defaultValue !== undefined ? { defaultValue: v.defaultValue } : {}),
    });
    expect(semantics.requiredApplies(subject, v.environment)).toBe(v.requiredApplies);
    expect(semantics.missingWhenAbsent(subject, v.environment)).toBe(v.missingWhenAbsent);
  });

  it("covers every item type the version defines with a valid and an invalid value", () => {
    for (const type of ITEM_TYPES.filter((t) => ITEM_TYPE_SINCE_SEMANTICS[t] <= version)) {
      const own = vectors.validate.filter((v) => v.type === type);
      expect(own.some((v) => v.valid), `${type} valid`).toBe(true);
      if (type !== "string") expect(own.some((v) => !v.valid), `${type} invalid`).toBe(true);
    }
  });

  it("covers every requiredness kind", () => {
    const kinds = new Set(
      vectors.required.map((v) =>
        v.required.kind === "selector" ? `selector:${v.required.selector.kind}` : v.required.kind,
      ),
    );
    expect([...kinds].sort()).toEqual(["always", "never", "selector:environments", "selector:tier"]);
  });

  it("never puts any fragment of the value in a reason", () => {
    for (const v of vectors.validate) {
      if (v.valid) continue;
      // An enum reason lists the Contract's values, never the rejected one.
      if (v.type === "enum") {
        expect(v.reason).toBe(`must be one of: ${v.enumValues?.join(", ")}`);
        continue;
      }
      for (let i = 0; i + 4 <= v.value.length; i++) {
        expect(v.reason, JSON.stringify(v.value)).not.toContain(v.value.slice(i, i + 4));
      }
    }
  });
});

describe("semanticsFor", () => {
  it("defines conversion from version 2", () => {
    expect(semanticsFor(1).parse).toBeUndefined();
    expect(semanticsFor(2).parse).toBeTypeOf("function");
    expect(semanticsFor(3).parse).toBeTypeOf("function");
  });

  it("fails closed on a version it does not implement, naming it", () => {
    for (const version of [0, 4, 1.5, Number.NaN]) {
      expect(() => semanticsFor(version)).toThrow(UnsupportedSemanticsVersionError);
    }
    expect(() => semanticsFor(7)).toThrow("Contract semantics version 7 is not supported (supported: 1, 2, 3)");
    expect(() => semanticsFor("__proto__" as unknown as number)).toThrow(UnsupportedSemanticsVersionError);
  });
});

describe.each([[2], [3]])("semantics version %i portability vectors", (version) => {
  // Inputs where other languages' regular expressions and parsers commonly
  // differ. The TypeScript semantics are the reference: these pin what they
  // already do, so every other implementation can be held to it.
  const url = new URL(`./vectors/semantics-v${version}-portability.json`, import.meta.url);
  const vectors = JSON.parse(readFileSync(url, "utf8")) as {
    semanticsVersion: number;
    validate: (ValidateVector & { internationalizedHost?: boolean })[];
  };
  const semantics = semanticsFor(version);

  it("names its version", () => {
    expect(vectors.semanticsVersion).toBe(version);
  });

  it.each(vectors.validate.map((v) => [`${v.type} ${JSON.stringify(v.value)}`, v] as const))("%s", (_, v) => {
    const subject = item({ type: v.type, ...(v.enumValues ? { enumValues: v.enumValues } : {}) });
    const result = semantics.parse?.(subject, v.value);
    if (!v.valid) {
      expect(result).toEqual({ ok: false, reason: v.reason });
      expect(v.converted).toBeUndefined();
      return;
    }
    expect(result?.ok).toBe(true);
    const value = result?.ok ? result.value : undefined;
    const expected = v.converted;
    expect(expected, "every valid vector names its conversion").toBeDefined();
    if (expected && "number" in expected) {
      expect(Object.is(value, Number(expected.number)), `${String(value)} is ${expected.number}`).toBe(true);
    } else {
      expect(value).toStrictEqual(expected && ("boolean" in expected ? expected.boolean : expected.string));
    }
  });

  it("marks internationalized hosts on URL vectors only", () => {
    for (const v of vectors.validate) {
      if (v.internationalizedHost !== undefined) {
        expect(v.type).toBe("url");
        expect(v.internationalizedHost).toBe(true);
      }
    }
    expect(vectors.validate.some((v) => v.internationalizedHost && v.valid)).toBe(true);
    expect(vectors.validate.some((v) => v.internationalizedHost && !v.valid)).toBe(true);
  });

  it("never puts any fragment of the value in a reason", () => {
    for (const v of vectors.validate) {
      if (v.valid || v.type === "enum") continue;
      for (let i = 0; i + 4 <= v.value.length; i++) {
        expect(v.reason, JSON.stringify(v.value)).not.toContain(v.value.slice(i, i + 4));
      }
    }
  });
});

describe("semantics version 3", () => {
  const load = (name: string) =>
    JSON.parse(readFileSync(new URL(`./vectors/${name}.json`, import.meta.url), "utf8")) as { validate: ValidateVector[] };

  it("repeats every version 2 vector with its version 2 result: nothing but integer changes", () => {
    const v3 = load("semantics-v3").validate;
    for (const v of load("semantics-v2").validate) {
      const again = v3.find((w) => w.type === v.type && w.value === v.value && JSON.stringify(w.enumValues) === JSON.stringify(v.enumValues));
      expect(again, `${v.type} ${JSON.stringify(v.value)}`).toBeDefined();
      expect({ ...again, note: undefined }).toEqual({ ...v, note: undefined });
    }
  });

  it("integer: an optional - and ASCII digits, within 2^53 - 1; never a fraction, even .0", () => {
    const parse = semanticsFor(3).parse!;
    const integer = { name: "PORT", type: "integer" as const, required: { kind: "never" as const }, sensitive: false };
    expect(parse(integer, "3000")).toEqual({ ok: true, value: 3000 });
    expect(Object.is((parse(integer, "-0") as { value: number }).value, 0)).toBe(true);
    for (const value of ["3.0", "3.5", "+1", "1e3", " 1", ""]) {
      expect(parse(integer, value), value).toEqual({ ok: false, reason: "must be a whole number" });
    }
    expect(parse(integer, "9007199254740992")).toEqual({
      ok: false,
      reason: "must be a whole number no larger in magnitude than 2^53 - 1",
    });
  });

  it("number keeps accepting fractions at every version", () => {
    const number = { name: "RATIO", type: "number" as const, required: { kind: "never" as const }, sensitive: false };
    for (const version of SEMANTICS_VERSIONS) expect(semanticsFor(version).validate(number, "3.5"), `v${version}`).toBeNull();
  });

  it("an evaluator before version 3 that meets an integer item fails closed", () => {
    const integer = { name: "PORT", type: "integer" as const, required: { kind: "never" as const }, sensitive: false };
    for (const version of [1, 2]) expect(semanticsFor(version).validate(integer, "1"), `v${version}`).toMatch(/integer needs version 3/);
  });
});
