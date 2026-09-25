// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import {
  ContractValidationError,
  canonicalJson,
  contractHash,
  diffContracts,
  normalizeContract,
} from "../src/index.js";

const sample = {
  schemaVersion: 1,
  items: [
    {
      name: "STRIPE_SECRET_KEY",
      required: { kind: "selector", selector: { kind: "tier", tier: "production" } },
      sensitive: true,
      type: "string",
      example: "sk_test_000",
    },
    {
      name: "DATABASE_URL",
      required: { kind: "always" },
      sensitive: true,
      type: "url",
      description: "Primary database connection string",
    },
    {
      name: "LOG_LEVEL",
      required: { kind: "never" },
      sensitive: false,
      type: "enum",
      enumValues: ["warn", "debug", "info", "error"],
      defaultValue: "info",
    },
    {
      name: "PORT",
      required: { kind: "never" },
      sensitive: false,
      type: "number",
      defaultValue: "3000",
    },
  ],
};

describe("normalizeContract", () => {
  it("sorts items by name and enum values by code point", () => {
    const c = normalizeContract(sample);
    expect(c.items.map((i) => i.name)).toEqual([
      "DATABASE_URL",
      "LOG_LEVEL",
      "PORT",
      "STRIPE_SECRET_KEY",
    ]);
    expect(c.items[1]?.enumValues).toEqual(["debug", "error", "info", "warn"]);
  });

  it("is idempotent", () => {
    const once = normalizeContract(sample);
    const twice = normalizeContract(once);
    expect(canonicalJson(twice)).toBe(canonicalJson(once));
  });

  it("sorts and de-duplicates selector environment IDs", () => {
    const c = normalizeContract({
      schemaVersion: 1,
      items: [
        {
          name: "A",
          required: {
            kind: "selector",
            selector: {
              kind: "environments",
              environmentIds: ["env_b", "env_a", "env_b"],
            },
          },
          sensitive: false,
          type: "string",
        },
      ],
    });
    expect(c.items[0]?.required).toEqual({
      kind: "selector",
      selector: { kind: "environments", environmentIds: ["env_a", "env_b"] },
    });
  });

  it("rejects duplicate names", () => {
    expect(() =>
      normalizeContract({
        schemaVersion: 1,
        items: [
          { name: "A", required: { kind: "always" }, sensitive: false, type: "string" },
          { name: "A", required: { kind: "never" }, sensitive: false, type: "string" },
        ],
      }),
    ).toThrow(ContractValidationError);
  });

  it("rejects lowercase names, unknown fields, enum constraint violations", () => {
    const base = { required: { kind: "always" }, sensitive: false, type: "string" };
    expect(() =>
      normalizeContract({ schemaVersion: 1, items: [{ ...base, name: "lower" }] }),
    ).toThrow(ContractValidationError);
    expect(() =>
      normalizeContract({
        schemaVersion: 1,
        items: [{ ...base, name: "A", surprise: true }],
      }),
    ).toThrow(ContractValidationError);
    expect(() =>
      normalizeContract({
        schemaVersion: 1,
        items: [{ name: "A", required: { kind: "always" }, sensitive: false, type: "enum" }],
      }),
    ).toThrow(ContractValidationError);
    expect(() =>
      normalizeContract({
        schemaVersion: 1,
        items: [
          {
            name: "A",
            required: { kind: "always" },
            sensitive: false,
            type: "enum",
            enumValues: ["x"],
            defaultValue: "y",
          },
        ],
      }),
    ).toThrow(ContractValidationError);
  });
});

describe("canonicalJson", () => {
  it("sorts object keys recursively and omits undefined", () => {
    expect(canonicalJson({ b: 1, a: { d: undefined, c: [true, null] } })).toBe(
      '{"a":{"c":[true,null]},"b":1}',
    );
  });

  it("distinguishes array boundary cases", () => {
    expect(canonicalJson(["ab", "c"])).not.toBe(canonicalJson(["a", "bc"]));
  });

  it("rejects non-integers and non-finite numbers", () => {
    expect(() => canonicalJson(1.5)).toThrow(TypeError);
    expect(() => canonicalJson(Number.NaN)).toThrow(TypeError);
  });
});

describe("contractHash", () => {
  it("is stable regardless of input ordering (golden vector)", () => {
    const a = contractHash(normalizeContract(sample));
    const reordered = {
      schemaVersion: 1,
      items: [...sample.items].reverse().map((i) => ({ ...i })),
    };
    const b = contractHash(normalizeContract(reordered));
    expect(a).toBe(b);
    expect(a).toBe(GOLDEN_SAMPLE_HASH);
  });

  it("differs for a semantically different contract", () => {
    const flipped = normalizeContract({
      ...sample,
      items: sample.items.map((i) =>
        i.name === "PORT" ? { ...i, sensitive: true } : i,
      ),
    });
    expect(contractHash(flipped)).not.toBe(GOLDEN_SAMPLE_HASH);
  });

  it("empty contract golden vector", () => {
    expect(contractHash(normalizeContract({ schemaVersion: 1, items: [] }))).toBe(
      GOLDEN_EMPTY_HASH,
    );
  });
});

describe("diffContracts", () => {
  const from = normalizeContract(sample);

  it("reports no changes for identical contracts", () => {
    const d = diffContracts(from, normalizeContract(sample));
    expect(d.securityRelevant).toBe(false);
    expect(d.itemsAdded).toEqual([]);
    expect(d.otherChanged).toEqual([]);
  });

  it("flags sensitivity flips, additions, and removals as security-relevant", () => {
    const to = normalizeContract({
      schemaVersion: 1,
      items: [
        ...sample.items
          .filter((i) => i.name !== "PORT")
          .map((i) => (i.name === "LOG_LEVEL" ? { ...i, sensitive: true } : i)),
        {
          name: "NEW_FLAG",
          required: { kind: "never" },
          sensitive: false,
          type: "boolean",
        },
      ],
    });
    const d = diffContracts(from, to);
    expect(d.itemsAdded).toEqual(["NEW_FLAG"]);
    expect(d.itemsRemoved).toEqual(["PORT"]);
    expect(d.sensitivityChanged).toEqual([
      { name: "LOG_LEVEL", from: false, to: true },
    ]);
    expect(d.securityRelevant).toBe(true);
  });

  it("treats description edits as cosmetic", () => {
    const to = normalizeContract({
      ...sample,
      items: sample.items.map((i) =>
        i.name === "DATABASE_URL" ? { ...i, description: "reworded" } : i,
      ),
    });
    const d = diffContracts(from, to);
    expect(d.otherChanged).toEqual(["DATABASE_URL"]);
    expect(d.securityRelevant).toBe(false);
  });

  it("flags requiredness/applicability changes as security-relevant", () => {
    const to = normalizeContract({
      ...sample,
      items: sample.items.map((i) =>
        i.name === "STRIPE_SECRET_KEY" ? { ...i, required: { kind: "always" } } : i,
      ),
    });
    const d = diffContracts(from, to);
    expect(d.requirednessChanged.map((r) => r.name)).toEqual(["STRIPE_SECRET_KEY"]);
    expect(d.securityRelevant).toBe(true);
  });
});

// Golden vectors: any change to canonicalization or the model that alters these
// is a breaking change to the Contract hashing contract and must be deliberate
// (it invalidates stored revision hashes and drift detection).
const GOLDEN_SAMPLE_HASH =
  "sha256:ed1548fa21ba06ec251f40443cc8335ef93e79513c24c45c49f23408ac897070";
const GOLDEN_EMPTY_HASH =
  "sha256:8aec8887eb1a0f7eb74d40e98c4283c5801214cac1e8a2031473e6084d289db0";
