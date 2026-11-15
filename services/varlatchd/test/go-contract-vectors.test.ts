// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Shared vectors for go/lib/contract (ADR-0059 step 4.1b): what
 * @varlatch/contract makes of a Contract a client pushes, written to
 * go/lib/contract/testdata/ts-vectors.json, which the Go package's tests
 * read. Its Contract Semantics vectors (packages/contract/test/vectors)
 * are run by the Go tests directly; these cover the rest:
 *
 * - normalize: an input (its exact JSON text, as a request carries it),
 *   with or without versionUndecided, and either the issues
 *   normalizeContract reports (zod's messages, in its order, and the
 *   Contract rules) or the normalized Contract's canonical bytes and
 *   content hash, which Go must reproduce byte for byte;
 * - diff: diffContracts on pairs of normalized Contracts;
 * - parse: JSON text as bytes (base64) and what JSON.parse makes of it as
 *   the CLI reads a Contract file (Buffer#toString("utf8"), then
 *   JSON.parse), written back with JSON.stringify, or that it throws:
 *   lone surrogates, invalid UTF-8, member order and repeats.
 *
 * The file is checked here: it must equal what this code produces now.
 * After a change, regenerate it and commit the result:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-contract-vectors.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { expect, it } from "vitest";
import { canonicalJson, ContractValidationError, contractHash, diffContracts, normalizeContract } from "@varlatch/contract";

const OUT = new URL("../../../go/lib/contract/testdata/ts-vectors.json", import.meta.url);

const item = (name: string, extra: Record<string, unknown> = {}) => ({ name, required: { kind: "always" }, sensitive: false, type: "string", ...extra });
const contract = (items: unknown[], extra: Record<string, unknown> = {}) => ({ schemaVersion: 1, items, ...extra });
const text = (v: unknown) => JSON.stringify(v);

/** Inputs as JSON text: some only text can say (an exponent beyond a double, member order). */
const NORMALIZE: [string, string, boolean?][] = [
  // Valid, and what normalization does to them.
  ["empty", text(contract([]))],
  ["one item", text(contract([item("DATABASE_URL", { sensitive: true, type: "url" })]))],
  ["every field", text(contract([item("MODE", {
    type: "enum", enumValues: ["prod", "dev", "dev", "test"], defaultValue: "dev", description: "The mode", example: "prod",
    rotationGraceSeconds: 3600, rotationHint: "Rotate in the console ✓",
  })]))],
  ["items sorted by name", text(contract([item("B"), item("A_2"), item("A"), item("A_10")]))],
  ["selectors", text(contract([
    item("ENV_IDS", { required: { kind: "selector", selector: { kind: "environments", environmentIds: ["env_b", "env_a", "env_b"] } } }),
    item("TIER", { required: { kind: "selector", selector: { kind: "tier", tier: "production" } } }),
    item("NEVER", { required: { kind: "never" } }),
  ]))],
  ["sorting by UTF-16 units", text(contract([item("E", { type: "enum", enumValues: ["￿", "😀", "é", "Z", "a", "é́"] })]))],
  ["strings JSON.stringify escapes", text(contract([item("S", { description: "quote \" backslash \\ newline \n tab \t \u0001 \u001f \u007f     </script>", example: "😀 é" })]))],
  ["semantics version 1 is omitted", text(contract([item("A")], { semanticsVersion: 1 }))],
  ["semantics version 2", text(contract([item("A")], { semanticsVersion: 2 }))],
  ["semantics version 3 with an integer", text(contract([item("N", { type: "integer" })], { semanticsVersion: 3 }))],
  ["an integer, the version undecided", text(contract([item("N", { type: "integer" })])), true],
  ["the version undecided, named", text(contract([item("N", { type: "integer" })], { semanticsVersion: 2 })), true],
  ["member order does not matter", '{"items":[{"type":"string","sensitive":true,"required":{"kind":"always"},"name":"A"}],"schemaVersion":1}'],
  ["a number written 1.0", '{"schemaVersion":1.0,"semanticsVersion":2.0,"items":[{"name":"A","required":{"kind":"always"},"sensitive":false,"type":"string","rotationGraceSeconds":6e1}]}'],
  ["a description of 4096 UTF-16 units", text(contract([item("A", { description: "😀".repeat(2048) })]))],
  ["a rotation hint of 1024 code points", text(contract([item("A", { rotationHint: "😀".repeat(1024) })]))],
  ["a name of 256 characters", text(contract([item("A".repeat(256))]))],
  ["a default for every type", text(contract([item("U", { type: "url", defaultValue: "not a url" }), item("B", { type: "boolean", defaultValue: "maybe" })]))],
  // Invalid: the root.
  ["null", "null"],
  ["an array", "[]"],
  ["a string", '"contract"'],
  ["a number", "1"],
  ["true", "true"],
  ["an empty object", "{}"],
  ["another schema version", text({ schemaVersion: 2, items: [] })],
  ["the schema version as text", text({ schemaVersion: "1", items: [] })],
  ["the schema version null", text({ schemaVersion: null, items: [] })],
  ["no items", text({ schemaVersion: 1 })],
  ["items not an array", text({ schemaVersion: 1, items: {} })],
  ["items null", text({ schemaVersion: 1, items: null })],
  ["an unknown member", text(contract([], { extra: 1 }))],
  ["two unknown members", text(contract([], { zeta: 1, alpha: 2 }))],
  ["unknown members and a bad field", '{"zeta":1,"schemaVersion":2,"alpha":true,"items":[]}'],
  // Invalid: the semantics version.
  ["semantics version 1.5", text(contract([], { semanticsVersion: 1.5 }))],
  ["semantics version as text", text(contract([], { semanticsVersion: "2" }))],
  ["semantics version null", text(contract([], { semanticsVersion: null }))],
  ["semantics version 0", text(contract([], { semanticsVersion: 0 }))],
  ["semantics version 4", text(contract([], { semanticsVersion: 4 }))],
  ["semantics version -1", text(contract([], { semanticsVersion: -1 }))],
  ["semantics version 2^53", '{"schemaVersion":1,"semanticsVersion":9007199254740992,"items":[]}'],
  ["semantics version 1e20", '{"schemaVersion":1,"semanticsVersion":1e20,"items":[]}'],
  ["semantics version beyond a double", '{"schemaVersion":1,"semanticsVersion":1e999,"items":[]}'],
  ["semantics version 9 with an integer", text(contract([item("N", { type: "integer" })], { semanticsVersion: 9 }))],
  // Invalid: items.
  ["an item that is not an object", text(contract(["A", null, 3]))],
  ["an empty item", text(contract([{}]))],
  ["every field of the wrong type", text(contract([{ name: 1, required: "always", sensitive: "yes", type: 7, enumValues: "a", defaultValue: 1, description: 2, example: false, rotationGraceSeconds: "10", rotationHint: 3 }]))],
  ["every field null", text(contract([{ name: null, required: null, sensitive: null, type: null, enumValues: null, defaultValue: null, description: null, example: null, rotationGraceSeconds: null, rotationHint: null }]))],
  ["an unknown item member", text(contract([item("A", { secret: true })]))],
  ["unknown members in an item and its required", text(contract([item("A", { required: { kind: "always", x: 1, y: 2 }, z: 3 })]))],
  ["a lowercase name", text(contract([item("database_url")]))],
  ["an empty name", text(contract([item("")]))],
  ["a name of 257 characters", text(contract([item("A".repeat(257))]))],
  ["a name of 257 lowercase characters", text(contract([item("a".repeat(257))]))],
  ["a name with a dash", text(contract([item("A-B")]))],
  ["a name with a newline at the end", text(contract([item("A\n")]))],
  ["the reserved name", text(contract([item("VARLATCH_RUN_CONTEXT")]))],
  ["duplicate names", text(contract([item("A"), item("B"), item("A"), item("A")]))],
  ["an unknown type", text(contract([item("A", { type: "strin" })]))],
  ["an unknown requiredness kind", text(contract([item("A", { required: { kind: "sometimes" } })]))],
  ["a requiredness without kind", text(contract([item("A", { required: {} })]))],
  ["a requiredness kind that is a number", text(contract([item("A", { required: { kind: 1 } })]))],
  ["a requiredness that is an array", text(contract([item("A", { required: [] })]))],
  ["a selector without selector", text(contract([item("A", { required: { kind: "selector" } })]))],
  ["an unknown selector kind", text(contract([item("A", { required: { kind: "selector", selector: { kind: "all" } } })]))],
  ["an unknown tier", text(contract([item("A", { required: { kind: "selector", selector: { kind: "tier", tier: "prod" } } })]))],
  ["no environment ids", text(contract([item("A", { required: { kind: "selector", selector: { kind: "environments", environmentIds: [] } } })]))],
  ["an empty environment id", text(contract([item("A", { required: { kind: "selector", selector: { kind: "environments", environmentIds: ["env_a", "", 3] } } })]))],
  ["an unknown selector member", text(contract([item("A", { required: { kind: "selector", selector: { kind: "tier", tier: "production", also: 1 } } })]))],
  ["enum without values", text(contract([item("A", { type: "enum" })]))],
  ["enum values on a string", text(contract([item("A", { enumValues: ["a"] })]))],
  ["no enum values", text(contract([item("A", { type: "enum", enumValues: [] })]))],
  ["an empty enum value", text(contract([item("A", { type: "enum", enumValues: ["a", ""] })]))],
  ["a default not among the enum values", text(contract([item("A", { type: "enum", enumValues: ["a", "b"], defaultValue: "c" })]))],
  ["a description of 4097 UTF-16 units", text(contract([item("A", { description: "😀".repeat(2048) + "x" })]))],
  ["an example of 4097 characters", text(contract([item("A", { example: "x".repeat(4097) })]))],
  ["a rotation grace of 0", text(contract([item("A", { rotationGraceSeconds: 0 })]))],
  ["a rotation grace of 30 days and a second", text(contract([item("A", { rotationGraceSeconds: 2_592_001 })]))],
  ["a rotation grace of 1.5", text(contract([item("A", { rotationGraceSeconds: 1.5 })]))],
  ["a rotation grace of 0.5", text(contract([item("A", { rotationGraceSeconds: 0.5 })]))],
  ["a rotation grace of 1e20", '{"schemaVersion":1,"items":[{"name":"A","required":{"kind":"always"},"sensitive":false,"type":"string","rotationGraceSeconds":1e20}]}'],
  ["a rotation grace of -1e20", '{"schemaVersion":1,"items":[{"name":"A","required":{"kind":"always"},"sensitive":false,"type":"string","rotationGraceSeconds":-1e20}]}'],
  ["a rotation grace below a double", '{"schemaVersion":1,"items":[{"name":"A","required":{"kind":"always"},"sensitive":false,"type":"string","rotationGraceSeconds":-1e999}]}'],
  ["a rotation grace of true", text(contract([item("A", { rotationGraceSeconds: true })]))],
  ["a name of 256 emoji", text(contract([item("😀".repeat(256))]))],
  ["a description of 4096 emoji", text(contract([item("A", { description: "😀".repeat(4096) })]))],
  ["a description of 4097 emoji", text(contract([item("A", { description: "😀".repeat(4097) })]))],
  ["an enum value of one emoji", text(contract([item("A", { type: "enum", enumValues: ["😀"] })]))],
  ["unknown keys JavaScript orders", '{"schemaVersion":1,"items":[],"b":1,"10":2,"a":3,"2":4}'],
  ["a repeated member", '{"schemaVersion":1,"items":[{"name":"A","required":{"kind":"always"},"sensitive":false,"type":"string"}],"schemaVersion":2}'],
  ["an object as the schema version", text({ schemaVersion: {}, items: [] })],
  ["an empty rotation hint", text(contract([item("A", { rotationHint: "" })]))],
  ["a rotation hint of 1025 code points", text(contract([item("A", { rotationHint: "😀".repeat(1025) })]))],
  ["a rotation hint with a tab", text(contract([item("A", { rotationHint: "a\tb" })]))],
  ["a rotation hint with bidi formatting", text(contract([item("A", { rotationHint: "a‮b" })]))],
  ["a rotation hint with a line separator", text(contract([item("A", { rotationHint: "a b" })]))],
  ["a rotation hint with C1 control", text(contract([item("A", { rotationHint: "a\u0085b" })]))],
  ["an integer at version 1", text(contract([item("N", { type: "integer" })]))],
  ["an integer at version 2", text(contract([item("N", { type: "integer" })], { semanticsVersion: 2 }))],
  ["several items, several problems", text(contract([
    item("A", { type: "enum" }), item("a"), item("B", { rotationGraceSeconds: 0, required: { kind: "never", x: 1 } }), item("A"), item("VARLATCH_RUN_CONTEXT", { enumValues: ["x"] }),
  ], { semanticsVersion: 4 }))],
  ["zod and rule problems together", text(contract([item("A"), item("A", { sensitive: 1 })]))],
  // Lone UTF-16 surrogates, written as escapes: they reach the canonical
  // bytes (as \udxxx) and the hash, and count as one code point each.
  ["a lone high surrogate in a description", withString("description", "a\\ud800b")],
  ["a lone low surrogate in an example", withString("example", "\\udc00")],
  ["a reversed pair", withString("description", "\\udc00\\ud800")],
  ["an escaped pair is its code point", withString("description", "\\ud83d\\ude00 \\uD83D\\uDE00")],
  ["a high surrogate before a pair", withString("rotationHint", "\\ud800\\ud83d\\ude00")],
  ["lone surrogates sort by UTF-16 units", '{"schemaVersion":1,"items":[{"name":"E","required":{"kind":"always"},"sensitive":false,"type":"enum","enumValues":["\\udfff","\\uffff","\\ud83d\\ude00","\\ud800","a","\\ud800"]}]}'],
  ["a description of 4096 lone surrogates", withString("description", "\\ud800".repeat(4096))],
  ["a description of 4097 lone surrogates", withString("description", "\\ud800".repeat(4097))],
  ["an unrecognized key with a lone surrogate", '{"schemaVersion":1,"items":[],"\\ud800":1}'],
  ["unrecognized keys zod quotes without escaping", '{"schemaVersion":1,"items":[],"a\\"b":1,"c\\\\d":2,"e\\nf":3}'],
  ["an enum value that is a lone surrogate, not listed", '{"schemaVersion":1,"items":[{"name":"E","required":{"kind":"always"},"sensitive":false,"type":"enum","enumValues":["a"],"defaultValue":"\\udc00"}]}'],
  // __proto__ is an own member after JSON.parse: a strict object reports it.
  ["__proto__ at the root", '{"schemaVersion":1,"items":[],"__proto__":1}'],
  ["__proto__ in an item", '{"schemaVersion":1,"items":[{"name":"A","required":{"kind":"always"},"sensitive":false,"type":"string","__proto__":{"description":"x"}}]}'],
  ["__proto__ in a requiredness", '{"schemaVersion":1,"items":[{"name":"A","required":{"kind":"always","__proto__":1},"sensitive":false,"type":"string"}]}'],
  ["only __proto__", '{"__proto__":{"schemaVersion":1,"items":[]}}'],
];

/** A one-item Contract whose string member `key` is the JSON text `escaped` (escapes kept as written). */
function withString(key: string, escaped: string): string {
  return `{"schemaVersion":1,"items":[{"name":"A","required":{"kind":"always"},"sensitive":false,"type":"string","${key}":"${escaped}"}]}`;
}

/** JSON text as bytes, for parse vectors. */
const PARSE: [string, number[] | string][] = [
  ["a lone high surrogate", '"a\\ud800b"'],
  ["a lone low surrogate", '"\\udc00"'],
  ["a reversed pair", '"\\udc00\\ud800"'],
  ["an escaped pair", '"\\ud83d\\ude00"'],
  ["an escaped pair, upper case", '"\\uD83D\\uDE00"'],
  ["a pair and a stray low surrogate", '"\\ud83d\\ude00\\ude00"'],
  ["a high surrogate before a pair", '"\\ud800\\ud800\\udc00"'],
  ["a high surrogate before a short escape", '"\\ud800\\u00e9"'],
  ["a high surrogate at the end", '"x\\ud800"'],
  ["every short escape", '"\\/\\b\\f\\n\\r\\t\\"\\\\\\u0041\\u00e9"'],
  ["member order and a repeated key", '{"b":1,"a":2,"1":3,"0":4,"b":5}'],
  ["__proto__ is a member", '{"__proto__":1,"x":[true,false,null]}'],
  ["keys with surrogates", '{"\\ud800":1,"\\ud83d\\ude00":2}'],
  ["integers and negative zero", "[1,-0,0,10,-5,1e3,2E+2,5e-0]"],
  ["whitespace JSON allows", ' \t\r\n[ 1 , {\n} ]\n'],
  ["a truncated three-byte sequence", [0x22, 0xe2, 0x82, 0x22]],
  ["surrogate code points as raw bytes", [0x22, 0xed, 0xa0, 0x80, 0x22]],
  ["an overlong encoding", [0x22, 0xc0, 0xaf, 0x22]],
  ["beyond U+10FFFF", [0x22, 0xf4, 0x90, 0x80, 0x80, 0x22]],
  ["a truncated four-byte sequence", [0x22, 0xf0, 0x9f, 0x98, 0x22]],
  ["a lone continuation byte", [0x22, 0x80, 0x80, 0x22]],
  ["0xff", [0x22, 0xff, 0x22]],
  ["E0 then a low continuation", [0x22, 0xe0, 0x80, 0x41, 0x22]],
  ["ED then a high continuation", [0x22, 0xed, 0xbf, 0xbf, 0x22]],
  ["valid four-byte UTF-8", [0x22, 0xf0, 0x9f, 0x98, 0x80, 0x22]],
  ["invalid UTF-8 in a key", [0x7b, 0x22, 0xc3, 0x22, 0x3a, 0x31, 0x7d]],
  ["a byte order mark", [0xef, 0xbb, 0xbf, 0x31]],
  ["a short \\u escape", '"\\ud80"'],
  ["a bad \\u escape", '"\\u00zz"'],
  ["a bad escape", '"\\x"'],
  ["a raw control character", '"a\u0001b"'],
  ["a raw line feed", '"a\nb"'],
  ["a leading zero", "01"],
  ["a bare decimal point", "1."],
  ["no integer part", ".5"],
  ["a minus sign alone", "-"],
  ["a plus sign", "+1"],
  ["an empty exponent", "1e"],
  ["a trailing comma in an array", "[1,]"],
  ["a trailing comma in an object", '{"a":1,}'],
  ["a single-quoted string", "'a'"],
  ["text after the value", '"x" y'],
  ["a no-break space", "\u00a01"],
  ["nothing", ""],
  ["NaN", "NaN"],
  ["True", "True"],
];

/** Pairs of Contracts for diffContracts. */
const DIFF: [string, unknown, unknown][] = [
  ["identical", contract([item("A")]), contract([item("A")])],
  ["an item added and one removed", contract([item("A"), item("B")]), contract([item("B"), item("C")])],
  ["sensitivity, requiredness and type", contract([item("A"), item("B"), item("C")]), contract([
    item("A", { sensitive: true }), item("B", { required: { kind: "selector", selector: { kind: "tier", tier: "staging" } } }), item("C", { type: "url" }),
  ])],
  ["cosmetic only", contract([item("A", { description: "x" })]), contract([item("A", { description: "y", example: "z", rotationHint: "Rotate it" })])],
  ["enum values cosmetic", contract([item("E", { type: "enum", enumValues: ["a"] })]), contract([item("E", { type: "enum", enumValues: ["a", "b"] })])],
  ["semantics version", contract([item("A")]), contract([item("A")], { semanticsVersion: 3 })],
  ["environments reordered", contract([item("A", { required: { kind: "selector", selector: { kind: "environments", environmentIds: ["b", "a"] } } })]),
    contract([item("A", { required: { kind: "selector", selector: { kind: "environments", environmentIds: ["a", "b"] } } })])],
];

function normalizeVector(name: string, input: string, versionUndecided = false) {
  try {
    const c = normalizeContract(JSON.parse(input), versionUndecided ? { versionUndecided: true } : {});
    return { name, input, versionUndecided, canonical: canonicalJson(c), hash: contractHash(c) };
  } catch (err) {
    if (!(err instanceof ContractValidationError)) throw err;
    return { name, input, versionUndecided, message: err.message, issues: err.issues };
  }
}

it("go/lib/contract/testdata/ts-vectors.json is @varlatch/contract's answers", () => {
  const normalize = NORMALIZE.map(([name, input, undecided]) => normalizeVector(name, input, undecided));
  if (new Set(normalize.map((v) => v.name)).size !== normalize.length) throw new Error("two vectors share a name");
  const diff = DIFF.map(([name, from, to]) => {
    const a = normalizeContract(from);
    const b = normalizeContract(to);
    return { name, from: canonicalJson(a), to: canonicalJson(b), diff: JSON.parse(canonicalJson(diffContracts(a, b))) as unknown };
  });
  const parse = PARSE.map(([name, input]) => {
    const bytes = typeof input === "string" ? Buffer.from(input, "utf8") : Buffer.from(input);
    try {
      return { name, bytes: bytes.toString("base64"), json: JSON.stringify(JSON.parse(bytes.toString("utf8"))) };
    } catch (err) {
      if (!(err instanceof SyntaxError)) throw err;
      return { name, bytes: bytes.toString("base64"), error: true };
    }
  });
  if (new Set(parse.map((v) => v.name)).size !== parse.length) throw new Error("two parse vectors share a name");
  const out = JSON.stringify({ comment: "Written by services/varlatchd/test/go-contract-vectors.test.ts from @varlatch/contract; never edit.", normalize, diff, parse }, null, 2) + "\n";
  if (process.env.VARLATCH_WRITE_GO_VECTORS === "1") {
    writeFileSync(OUT, out);
    return;
  }
  expect(readFileSync(OUT, "utf8") === out, "go/lib/contract/testdata/ts-vectors.json is stale: regenerate it (see the header of this file)").toBe(true);
});
