// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { PYTHON_RUNTIME_SOURCE } from "@varlatch/accessor-python/embedded";
import { TypesError } from "../src/typegen.js";
import { generatePythonModule, pyString } from "../src/typegenPython.js";
import { ITEMS, contractItem, revision } from "./fixtures.js";

const GENERATOR = "0.11.0-test";
const gen = (items: Record<string, unknown>[] = ITEMS, opts: Parameters<typeof revision>[1] = {}) =>
  generatePythonModule(revision(items, opts), { generatorVersion: GENERATOR });

/** Everything before the embedded runtime: the part generated from the Contract. */
const generatedPart = (text: string) => text.slice(0, text.indexOf("# Varlatch Typed Accessor for Python."));

describe("the generated Python module", () => {
  it("records the revision, content hash, semantics version, and generator version in its header", () => {
    const rev = revision(ITEMS);
    const header = gen().split("\n").slice(0, 9).join("\n");
    expect(header).toContain(`# Contract Revision:          ${rev.id}`);
    expect(header).toContain(`# Content hash:               ${rev.contentHash}`);
    expect(header).toContain("# Contract Semantics version: 2");
    expect(header).toContain(`# Generator:                  varlatch ${GENERATOR}`);
  });

  it("is deterministic, whatever order the items were pushed in", () => {
    expect(gen()).toBe(gen());
    expect(gen([...ITEMS].reverse())).toBe(gen());
    expect(gen().endsWith("\n")).toBe(true);
  });

  it("embeds the runtime once, after the generated part, with its license", () => {
    const text = gen();
    expect(text.split(PYTHON_RUNTIME_SOURCE.trimEnd())).toHaveLength(2);
    expect(text.indexOf("class Config:")).toBeLessThan(text.indexOf(PYTHON_RUNTIME_SOURCE.trimEnd()));
    expect(text).toContain("SPDX-License-Identifier: Apache-2.0");
    expect(PYTHON_RUNTIME_SOURCE).not.toContain("embed-drop");
    expect(PYTHON_RUNTIME_SOURCE).not.toMatch(/^from __future__/m);
  });

  it("annotates each item, optional unless required everywhere without a default", () => {
    const part = generatedPart(gen());
    expect(part).toContain("    API_KEY: str = _dataclasses.field(repr=False)\n");
    expect(part).toContain("    DATABASE_URL: str = _dataclasses.field(repr=False)\n");
    expect(part).toContain("    DEBUG: bool | None = None\n");
    expect(part).toContain('    LOG_LEVEL: _typing.Literal["debug", "info", "warn"] | None = None\n');
    expect(part).toContain("    PORT: float\n");
    expect(part).toContain("    SENTRY_DSN: str | None = None\n");
  });

  it("keeps sensitive items out of PublicConfig and out of repr()", () => {
    const part = generatedPart(gen());
    const pub = part.slice(part.indexOf("class PublicConfig:"), part.indexOf("class LoadResult:"));
    expect(pub).not.toContain("API_KEY");
    expect(pub).toContain("PORT: float");
    expect(part).toContain('_VARLATCH_PUBLIC = ("DEBUG", "FEATURE_X", "LOG_LEVEL", "PORT", "SENTRY_DSN", "SUPPORT_EMAIL",)');
  });

  it("no Contract text can end a docstring or a literal, or hide in the file", () => {
    const hostile = '"""\nimport os; os.system("x")\n"""\\ ‮ end \u0000 \r\n next';
    const text = gen([
      contractItem("A", { description: hostile, example: hostile, defaultValue: hostile, type: "string" }),
      contractItem("B", { type: "enum", enumValues: ['x"y', "a\\b", "‮"] }),
    ]);
    const part = generatedPart(text);
    expect(part).not.toContain('"""\nimport os');
    expect(part).not.toMatch(/^import os; os\.system/m);
    expect(part).not.toContain("‮");
    expect(part).not.toContain("\u0000");
    // Data literals are printable ASCII.
    const schema = part.slice(part.indexOf("_VARLATCH_SCHEMA = {"));
    expect(/^[\x20-\x7e\n]*$/.test(schema)).toBe(true);
    // normalizeContract sorts enum values.
    expect(schema).toContain('"enumValues": ["a\\\\b", "x\\"y", "\\u202e"]');
  });

  it("writes Python string literals in printable ASCII", () => {
    expect(pyString('a"b\\c')).toBe('"a\\"b\\\\c"');
    expect(pyString("é\n‮\u{1f600}")).toBe('"\\xe9\\x0a\\u202e\\U0001f600"');
  });

  it("an integer item is an int, documented as a whole number (semantics version 3)", () => {
    const part = generatedPart(
      gen([contractItem("WORKERS", { type: "integer", required: { kind: "always" } }), contractItem("RATIO", { type: "number" })], {
        semanticsVersion: 3,
      }),
    );
    expect(part).toContain("    WORKERS: int\n");
    expect(part).toContain("    RATIO: float | None = None\n");
    expect(part).toContain("A whole number.");
    expect(part).toContain('"semanticsVersion": 3,');
  });

  it("refuses version 1, naming the fix", () => {
    expect(() => gen(ITEMS, { semanticsVersion: 1 })).toThrow(TypesError);
    expect(() => gen(ITEMS, { semanticsVersion: 1 })).toThrow("defines no conversion");
  });

  it("generates an empty Contract", () => {
    const part = generatedPart(gen([]));
    expect(part).toContain("class Config:");
    expect(part).toContain("_VARLATCH_PUBLIC = ()");
  });
});
