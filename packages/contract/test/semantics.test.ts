// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  ITEM_TYPES,
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

  it("covers every item type with a valid and an invalid value", () => {
    for (const type of ITEM_TYPES) {
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
  });

  it("fails closed on a version it does not implement, naming it", () => {
    for (const version of [0, 3, 1.5, Number.NaN]) {
      expect(() => semanticsFor(version)).toThrow(UnsupportedSemanticsVersionError);
    }
    expect(() => semanticsFor(7)).toThrow("Contract semantics version 7 is not supported (supported: 1, 2)");
    expect(() => semanticsFor("__proto__" as unknown as number)).toThrow(UnsupportedSemanticsVersionError);
  });
});
