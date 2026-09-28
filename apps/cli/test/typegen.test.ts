// SPDX-License-Identifier: Apache-2.0
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { ACCESSOR_RUNTIME_SOURCE } from "@varlatch/accessor/embedded";
import { TypesError, commentLines, generateTypesModule } from "../src/typegen.js";
import { ITEMS, contractItem, revision } from "./fixtures.js";

const GENERATOR = "0.11.0-test";
const gen = (items: Record<string, unknown>[] = ITEMS, opts: Parameters<typeof revision>[1] = {}) =>
  generateTypesModule(revision(items, opts), { generatorVersion: GENERATOR });

/** Everything before the embedded runtime: the part generated from the Contract. */
const generatedPart = (text: string) => text.slice(0, text.indexOf("/*! Varlatch Typed Accessor."));

function syntaxErrors(text: string): string[] {
  const out = ts.transpileModule(text, { reportDiagnostics: true, compilerOptions: { target: ts.ScriptTarget.ES2022 } });
  return (out.diagnostics ?? []).map((d) => ts.flattenDiagnosticMessageText(d.messageText, "\n"));
}

/** The members of `interface Config`, as the TypeScript parser sees them. */
function configMembers(text: string): { name: string; optional: boolean; type: string; doc: string }[] {
  const source = ts.createSourceFile("gen.ts", text, ts.ScriptTarget.Latest, true);
  const config = source.statements.find((s): s is ts.InterfaceDeclaration => ts.isInterfaceDeclaration(s) && s.name.text === "Config");
  if (!config) throw new Error("no Config interface");
  return config.members.map((m) => {
    const sig = m as ts.PropertySignature;
    const docs = ts.getJSDocCommentsAndTags(sig).map((d) => d.getText(source));
    return { name: sig.name.getText(source), optional: sig.questionToken !== undefined, type: sig.type?.getText(source) ?? "", doc: docs.join("\n") };
  });
}

describe("the generated module", () => {
  it("records the revision, content hash, semantics version, and generator version in its header", () => {
    const rev = revision(ITEMS);
    const text = generateTypesModule(rev, { generatorVersion: GENERATOR });
    const header = text.split("\n").slice(0, 12).join("\n");
    expect(text.startsWith("// @ts-nocheck\n")).toBe(true);
    expect(header).toContain(`// Contract Revision:          ${rev.id}`);
    expect(header).toContain(`// Content hash:               ${rev.contentHash}`);
    expect(header).toContain("// Contract Semantics version: 2");
    expect(header).toContain(`// Generator:                  varlatch ${GENERATOR}`);
    expect(text).toContain(`"revisionId": "${rev.id}"`);
  });

  it("is deterministic: the same revision gives the same bytes, whatever order its items were pushed in", () => {
    expect(gen()).toBe(gen());
    expect(gen([...ITEMS].reverse())).toBe(gen());
    expect(gen().endsWith("\n")).toBe(true);
  });

  it("parses as TypeScript without errors and embeds the bundled accessor once", () => {
    const text = gen();
    expect(syntaxErrors(text)).toEqual([]);
    expect(text.split(ACCESSOR_RUNTIME_SOURCE)).toHaveLength(2);
    expect(text).toContain("SPDX-License-Identifier: Apache-2.0");
  });

  it("types each item: numbers, booleans, enum unions, and strings for URLs and emails", () => {
    const types = Object.fromEntries(configMembers(gen()).map((m) => [m.name, m.type]));
    expect(types).toEqual({
      API_KEY: "string",
      DATABASE_URL: "string",
      DEBUG: "boolean",
      FEATURE_X: "boolean",
      LOG_LEVEL: '"debug" | "info" | "warn"',
      PORT: "number",
      SENTRY_DSN: "string",
      SUPPORT_EMAIL: "string",
    });
  });

  it("an item is non-optional only when required in every environment without a default", () => {
    const members = Object.fromEntries(configMembers(gen()).map((m) => [m.name, m]));
    expect(Object.entries(members).filter(([, m]) => !m.optional).map(([n]) => n)).toEqual(["API_KEY", "DATABASE_URL", "PORT"]);
    // Always required, but a default satisfies it: optional, and the default is named.
    expect(members.LOG_LEVEL?.optional).toBe(true);
    expect(members.LOG_LEVEL?.doc).toContain('@default "info"');
    expect(members.LOG_LEVEL?.doc).toContain("Required in every environment, or satisfied by the Contract default.");
    expect(members.DEBUG?.doc).toContain("Optional in every environment.");
  });

  it("keeps conditional requiredness as data: optional in the type, the Environment Selector in the schema (C-T3)", () => {
    const text = gen();
    const members = Object.fromEntries(configMembers(text).map((m) => [m.name, m]));
    expect(members.SENTRY_DSN?.optional).toBe(true);
    expect(members.SENTRY_DSN?.doc).toContain("Required only in environments of tier production");
    expect(members.FEATURE_X?.optional).toBe(true);
    expect(members.FEATURE_X?.doc).toContain("Required only in the environments with root ID env_prod");
    const schema = text.slice(text.indexOf("const varlatchSchema = ") + "const varlatchSchema = ".length, text.indexOf(";\n\nconst varlatchAccessor"));
    // Object-literal syntax that is also JSON once trailing commas go.
    const items = (JSON.parse(schema.replace(/,(\n\s*[\]}])/g, "$1")) as { items: { name: string; required: unknown }[] }).items;
    expect(items.find((i) => i.name === "SENTRY_DSN")?.required).toEqual({ kind: "selector", selector: { kind: "tier", tier: "production" } });
    expect(items.find((i) => i.name === "FEATURE_X")?.required).toEqual({
      kind: "selector",
      selector: { kind: "environments", environmentIds: ["env_prod"] },
    });
  });

  it("carries only what the accessor needs in its schema: no descriptions or examples, and no values", () => {
    const text = gen();
    const schema = text.slice(text.indexOf("const varlatchSchema = "), text.indexOf("const varlatchAccessor"));
    expect(schema).not.toContain("payments API");
    expect(schema).not.toContain("postgres://localhost/app");
    expect(schema).toContain('"defaultValue":"info"');
  });

  it("marks Secrets @sensitive and leaves them out of PublicConfig", () => {
    const text = gen();
    const members = Object.fromEntries(configMembers(text).map((m) => [m.name, m]));
    expect(members.API_KEY?.doc).toContain("@sensitive");
    expect(members.DATABASE_URL?.doc).toContain("@example postgres://localhost/app");
    expect(members.PORT?.doc).not.toContain("@sensitive");
    expect(text).toContain(
      'export type PublicConfig = Pick<Config, "DEBUG" | "FEATURE_X" | "LOG_LEVEL" | "PORT" | "SENTRY_DSN" | "SUPPORT_EMAIL">;',
    );
  });

  it("an all-sensitive Contract gives an empty public type, and an empty Contract an empty Config", () => {
    const secrets = gen([contractItem("TOKEN", { sensitive: true }), contractItem("KEY", { sensitive: true })]);
    expect(secrets).toContain("export type PublicConfig = Pick<Config, never>;");
    const empty = gen([]);
    expect(empty).toContain("export interface Config {}");
    expect(syntaxErrors(empty)).toEqual([]);
  });

  it("sanitizes comment text: line terminators, control and bidirectional characters, and */ (C-T1)", () => {
    const c = String.fromCharCode;
    const hostile = [
      "First line\r\nsecond\rthird",
      `${c(0x2028)}fourth${c(0x2029)}fifth${c(0x85)}sixth`,
      `bell${c(7)} escape${c(0x1b)}[31m red ${c(0x202e)}reversed${c(0x2066)} tab\there`,
      "ends */ export const pwned = 1; /*",
    ].join("\n");
    const text = gen([contractItem("NOTE", { description: hostile, example: `a*/b${c(0x2028)}c` })]);
    const part = generatedPart(text);
    expect(syntaxErrors(text)).toEqual([]);
    // Nothing outside the newline among C0/C1 controls, line separators, or bidirectional formatting.
    expect(part).not.toMatch(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/);
    for (const code of [0x2028, 0x2029, 0x202e, 0x2066, 0x0d]) expect(part).not.toContain(c(code));
    // The comment never ends early: the text after */ stays inside it.
    expect(part).not.toMatch(/^export const pwned/m);
    expect(part).toContain("ends *\\/ export const pwned = 1; /*");
    const doc = configMembers(text)[0]?.doc ?? "";
    expect(doc).toContain("   * First line\n   * second\n   * third\n   *\n   * fourth\n   * fifth\n   * sixth");
    expect(doc).toContain("   * bell escape[31m red reversed tab here");
    expect(doc).toContain("@example a*\\/b\n   * c");
  });

  it("commentLines trims the blank lines around text and trailing spaces on each line", () => {
    expect(commentLines("\n\n  hello  \n\nworld \n\n")).toEqual(["  hello", "", "world"]);
  });

  it("escapes invisible characters in literals, so enum values and defaults stay exact", () => {
    const c = String.fromCharCode;
    const odd = `a${c(0x2028)}b${c(0x202e)}c*/d`;
    const text = gen([contractItem("MODE", { type: "enum", enumValues: [odd, "plain"], defaultValue: odd })]);
    const part = generatedPart(text);
    for (const code of [0x2028, 0x202e]) expect(part).not.toContain(c(code));
    expect(part).toContain('"a\\u2028b\\u202ec*/d" | "plain"');
    // In a comment, */ is also neutralized; \/ is a JSON escape for /, so the literal is still exact.
    expect(part).toContain('@default "a\\u2028b\\u202ec*\\/d"');
    expect(JSON.parse('"a\\u2028b\\u202ec*\\/d"')).toBe(odd);
    expect(syntaxErrors(text)).toEqual([]);
  });

  it("refuses a version 1 revision, naming the fix", () => {
    expect(() => gen(ITEMS, { semanticsVersion: 1 })).toThrow(TypesError);
    expect(() => gen(ITEMS, { semanticsVersion: 1 })).toThrow(
      /uses Contract Semantics version 1, which defines no conversion.*Activate a revision at version 2: push it with varlatch contract push --semantics latest, then activate it/,
    );
  });

  it("refuses a semantics version it does not implement", () => {
    const rev = { ...revision(ITEMS), semanticsVersion: 3 };
    expect(() => generateTypesModule(rev, { generatorVersion: GENERATOR })).toThrow(
      /Contract Semantics version 3, which this CLI does not implement.*activate a revision at a version it implements/,
    );
  });

  it("refuses a revision whose content does not match its content hash or version", () => {
    const rev = revision(ITEMS);
    const tampered = { ...rev, contract: { ...rev.contract, items: [contractItem("OTHER")], semanticsVersion: 2 } };
    expect(() => generateTypesModule(tampered, { generatorVersion: GENERATOR })).toThrow("does not match its content hash");
    expect(() => generateTypesModule({ ...rev, semanticsVersion: 1 }, { generatorVersion: GENERATOR })).toThrow(TypesError);
  });

  it("refuses identifiers it cannot print safely", () => {
    const rev = revision(ITEMS);
    expect(() => generateTypesModule({ ...rev, id: "crv_1\n*/ evil" }, { generatorVersion: GENERATOR })).toThrow(TypesError);
    expect(() => generateTypesModule({ ...rev, contentHash: "sha256:*/" }, { generatorVersion: GENERATOR })).toThrow(TypesError);
    expect(() => generateTypesModule(rev, { generatorVersion: "1.0\n*/" })).toThrow(TypesError);
  });
});
