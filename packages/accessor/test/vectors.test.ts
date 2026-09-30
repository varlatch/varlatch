// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { SEMANTICS_VERSIONS } from "@varlatch/contract";
import type { AccessorItem } from "../src/runtime.js";
import { builtRuntime, configError, item, runContext, schema, type BuiltRuntime } from "./helpers.js";

/**
 * The Contract Semantics golden vectors, run against the built accessor
 * bundle through its public API: the accessor has no rules of its own, so
 * every vector the server and the CLI pass, it passes too.
 */

interface ValidateVector {
  type: AccessorItem["type"];
  enumValues?: string[];
  value: string;
  valid: boolean;
  reason?: string;
  converted?: { string: string } | { number: string } | { boolean: boolean };
}

interface RequiredVector {
  required: AccessorItem["required"];
  defaultValue?: string;
  environment: { rootId: string; tier: "development" | "staging" | "production" };
  requiredApplies: boolean;
  missingWhenAbsent: boolean;
}

function vectors(version: number): { semanticsVersion: number; validate: ValidateVector[]; required: RequiredVector[] } {
  const url = new URL(`../../contract/test/vectors/semantics-v${version}.json`, import.meta.url);
  return JSON.parse(readFileSync(url, "utf8"));
}

let rt: BuiltRuntime;
beforeAll(async () => {
  rt = await builtRuntime();
});

describe("the built accessor implements exactly the versions that define conversion", () => {
  it("implements version 2, and refuses version 1 naming the fix", () => {
    expect(rt.implementedSemanticsVersions()).toEqual([2, 3]);
    const err = configError(() => rt.loadConfig(schema([], { semanticsVersion: 1 }), { env: {} }));
    expect(err).toBeInstanceOf(rt.ConfigError);
    expect(err.message).toContain("Contract Semantics version 1, which defines no conversion");
    expect(err.message).toContain("activate a revision at version 2 or 3");
  });

  it("refuses a version it does not implement", () => {
    for (const version of [0, 4, 1.5]) {
      const err = configError(() => rt.loadConfig(schema([], { semanticsVersion: version }), { env: {} }));
      expect(err.message).toContain(`Contract Semantics version ${version}, which this accessor does not implement`);
    }
  });
});

describe.each(SEMANTICS_VERSIONS.filter((v) => v !== 1).map((v) => [v]))(
  "semantics version %i golden vectors against the built accessor",
  (version) => {
    const { validate, required, semanticsVersion } = vectors(version);

    it("names its version", () => {
      expect(semanticsVersion).toBe(version);
    });

    it.each(validate.map((v) => [`${v.type} ${JSON.stringify(v.value)}`, v] as const))("%s", (_, v) => {
      const s = schema([item("ITEM", { type: v.type, ...(v.enumValues ? { enumValues: v.enumValues } : {}) })], {
        semanticsVersion: version,
      });
      if (!v.valid) {
        const err = configError(() => rt.loadConfig(s, { env: { ITEM: v.value } }));
        expect(err).toBeInstanceOf(rt.ConfigError);
        expect(err.issues).toEqual([{ name: "ITEM", reason: v.reason }]);
        return;
      }
      const { config } = rt.loadConfig(s, { env: { ITEM: v.value } });
      const expected = v.converted;
      expect(expected, "every valid vector names its conversion").toBeDefined();
      if (expected && "number" in expected) {
        expect(typeof config.ITEM).toBe("number");
        expect(Object.is(config.ITEM, Number(expected.number)), `${String(config.ITEM)} is ${expected.number}`).toBe(true);
      } else {
        expect(config.ITEM).toStrictEqual(expected && ("boolean" in expected ? expected.boolean : expected.string));
      }
    });

    it.each(required.map((v, i) => [i, v] as const))("requiredness vector %i", (_, v) => {
      const s = schema(
        [item("ITEM", { required: v.required, ...(v.defaultValue !== undefined ? { defaultValue: v.defaultValue } : {}) })],
        { semanticsVersion: version },
      );
      const context = (mode: "strict" | "exported", server: "notStored" | "withheld") =>
        runContext({ ITEM: { server, delivery: "absent" } }, { mode, semanticsVersion: version, environment: v.environment });
      const fails = (env: Record<string, string>) => {
        try {
          rt.loadConfig(s, { env });
          return false;
        } catch (err) {
          expect(err).toBeInstanceOf(rt.ConfigError);
          return true;
        }
      };
      // After a strict run defaults are already applied: an absent item is
      // a problem exactly when it is required here.
      expect(fails({ VARLATCH_RUN_CONTEXT: context("strict", "notStored") })).toBe(v.requiredApplies);
      // Under an exported context a Contract default satisfies requiredness,
      // except for a value the server withheld.
      expect(fails({ VARLATCH_RUN_CONTEXT: context("exported", "notStored") })).toBe(v.missingWhenAbsent);
      expect(fails({ VARLATCH_RUN_CONTEXT: context("exported", "withheld") })).toBe(v.requiredApplies);
    });
  },
);

describe.each([[2], [3]])("semantics version %i portability vectors against the built accessor", (version) => {
  const url = new URL(`../../contract/test/vectors/semantics-v${version}-portability.json`, import.meta.url);
  const { validate } = JSON.parse(readFileSync(url, "utf8")) as { validate: ValidateVector[] };

  it.each(validate.map((v) => [`${v.type} ${JSON.stringify(v.value)}`, v] as const))("%s", (_, v) => {
    const s = schema([item("ITEM", { type: v.type, ...(v.enumValues ? { enumValues: v.enumValues } : {}) })], {
      semanticsVersion: version,
    });
    if (!v.valid) {
      const err = configError(() => rt.loadConfig(s, { env: { ITEM: v.value } }));
      expect(err.issues).toEqual([{ name: "ITEM", reason: v.reason }]);
      return;
    }
    const { config } = rt.loadConfig(s, { env: { ITEM: v.value } });
    const expected = v.converted;
    if (expected && "number" in expected) {
      expect(Object.is(config.ITEM, Number(expected.number)), `${String(config.ITEM)} is ${expected.number}`).toBe(true);
    } else {
      expect(config.ITEM).toStrictEqual(expected && ("boolean" in expected ? expected.boolean : expected.string));
    }
  });
});

interface RunContextVectors {
  v: number;
  valid: { note: string; raw: string; parsed: Record<string, unknown> & { items: Record<string, unknown> } }[];
  invalid: { note: string; raw: string; reason: string }[];
}

describe("run context version 1 vectors against the built accessor", () => {
  const url = new URL("./vectors/run-context-v1.json", import.meta.url);
  const vectors = JSON.parse(readFileSync(url, "utf8")) as RunContextVectors;

  it("names version 1, and covers every check", () => {
    expect(vectors.v).toBe(1);
    const reasons = new Set(vectors.invalid.map((v) => v.reason.replace(/ \(it reads.*$/, "")));
    for (const reason of [
      "is not valid JSON",
      "is not a JSON object",
      "has a version this accessor does not read",
      "is malformed: mode",
      "is malformed: contractRevisionId",
      "is malformed: contractHash",
      "is malformed: semanticsVersion",
      "is malformed: environment",
      "is malformed: items",
      "is malformed: an entry in items",
    ]) {
      expect(reasons, reason).toContain(reason);
    }
  });

  it.each(vectors.valid.map((v) => [v.note, v] as const))("valid: %s", (_, v) => {
    const context = rt.parseRunContext(v.raw);
    expect({ ...context, items: Object.fromEntries(context.items) }).toEqual(v.parsed);
  });

  it.each(vectors.invalid.map((v) => [v.note, v] as const))("invalid: %s", (_, v) => {
    const err = configError(() => rt.parseRunContext(v.raw));
    expect(err).toBeInstanceOf(rt.ConfigError);
    expect(err.issues).toEqual([{ name: "VARLATCH_RUN_CONTEXT", reason: v.reason }]);
    expect(err.message).not.toContain("leaked-secret-value");
  });

  it("reports the same issue when loading configuration", () => {
    for (const v of vectors.invalid) {
      const err = configError(() => rt.loadConfig(schema([]), { env: { VARLATCH_RUN_CONTEXT: v.raw } }));
      expect(err.issues, v.note).toEqual([{ name: "VARLATCH_RUN_CONTEXT", reason: v.reason }]);
    }
  });
});
