// SPDX-License-Identifier: Apache-2.0
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { ValidationReport } from "@varlatch/protocol";
import { describe, expect, it } from "vitest";
import { DotenvParseError, parseDotenv } from "../src/dotenv.js";
import { ImportError, checkEntries, decodeStrict, inferType } from "../src/importCommand.js";
import {
  HiddenInput,
  SecretInputError,
  describeGenerated,
  dropLastCharacter,
  isWellFormedText,
  parseGenerateSpec,
  valueFromBytes,
  valueSourceOf,
} from "../src/secretInput.js";
import { validationDocument, validationOutcome } from "../src/validation.js";
import { writeOrCompare } from "./goKit.js";

/**
 * Vectors for the Go CLI's values and import (internal docs/design/go-cli.md,
 * slice 5.3a), from the TypeScript code itself:
 *
 * - dotenv: what parseDotenv makes of a file, or its error;
 * - generateSpec, valueSource, valueFromBytes, wellFormed, hiddenInput,
 *   dropLastCharacter: secretInput.ts's checks and the hidden prompt's
 *   editing, never with a real secret;
 * - validation: validate's outcome and --json document for reports;
 * - inferType, checkEntries, decodeStrict: import's helpers.
 *
 * It also writes the grapheme table the Go hidden prompt's Backspace uses
 * (go/cmd/varlatch/internal/secretinput/graphemes.json): each code point's
 * Grapheme_Cluster_Break, Indic_Conjunct_Break and Extended_Pictographic
 * properties as Intl.Segmenter (the ICU inside this Node.js) shows them,
 * found by probing the segmenter itself. The table is compared only under
 * the Unicode version it was written with.
 *
 * Regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/cli exec vitest run test/go-vectors-values.test.ts
 */

const VECTORS = fileURLToPath(new URL("../../../go/cmd/varlatch/testdata/vectors/values.json", import.meta.url));
const GRAPHEMES = fileURLToPath(new URL("../../../go/cmd/varlatch/internal/secretinput/graphemes.json", import.meta.url));

/** An error as a vector holds it: the message, and whether the command line is wrong. */
function failure(err: unknown): { error: string; usage?: boolean } {
  if (err instanceof SecretInputError) return { error: err.message, usage: err.usage };
  if (err instanceof Error) return { error: err.message };
  throw err;
}

// ---- dotenv ----------------------------------------------------------------

const DOTENV: string[] = [
  "",
  "\n\n",
  "# only a comment",
  "   # an indented comment",
  "A=1",
  "A=1\n",
  "A=1\r\nB=2\r\n",
  "A=1\rB=2",
  "\ufeffA=1",
  "\ufeff\ufeffA=1",
  "export A=1",
  "export\tA=1",
  "exportA=1",
  "export =1",
  "export",
  "A = 1",
  "A\t=\t1\t",
  "  A=1",
  "A=",
  "A=   ",
  "A= value with  spaces  ",
  "A=kept # dropped",
  "A=kept\t# dropped",
  "A=a#b",
  "A=#start",
  "A= #start",
  "A=x #",
  "A='lit $X \\n'",
  "A='lit' # c",
  "A='lit'#c",
  "A='lit' tail",
  "A='a\nb'",
  "A='a\r\nb'",
  "A='never closed\nmore",
  'A="tab\\there \\"q\\" back\\\\slash"',
  'A="\\n\\r\\t\\"\\\\"',
  'A="\\x41 \\u0041 \\$"',
  'A="ends in a backslash\\"',
  'A="ends\\\\"',
  'A="a\nb\\nc"',
  'A="\\\nx"',
  "A=`x y`",
  "A=`a\nb`",
  'A="v" # comment',
  'A="v"   ',
  'A="v"x',
  'A="v\'',
  "A=${B}",
  'A="$D ${E}"',
  "A=postgres://u:p@h/db?x=1",
  "a.b-c=1",
  "_A=1",
  "1A=1",
  "-A=1",
  "A",
  "A:1",
  "=1",
  "A=\u00e9 \u00fcn\u00efc\u00f6d\u00e9 \u{1F600}",
  'A="\u{1F600}\\\u{1F600}"',
  "A='\u{1F600}'",
  "A=1\nB",
  "A=1\nA=2",
  "A=1\n\nB=2\n# c\nC=3",
  "KEY=\"-----BEGIN-----\nline\\n-----END-----\"\r\nB=2\r\n",
  "A=\u0000",
  'A="\u0000"',
  "A=\u00a0x\u00a0",
  "A=x\u2028y",
];

function dotenvVector(source: string) {
  try {
    return { source, entries: parseDotenv(source) };
  } catch (err) {
    if (!(err instanceof DotenvParseError)) throw err;
    return { source, error: err.message };
  }
}

// ---- secretInput -------------------------------------------------------------

const GENERATE_SPECS = [
  "hex:32", "hex:16", "hex:15", "hex:4096", "hex:4097", "base64:48", "base64url:24", "alnum:22", "alnum:21", "alnum:4096", "alnum:40",
  "hex:0", "hex:016", "hex:99999999999999999999", "HEX:32", "hex: 32", "hex:32 ", "uuid", "", "hex", "hex:", "hex:-1", "hex:1e3", "base32:32",
];

const SOURCES: Array<{ value?: string; stdin: boolean; file?: string; generate?: string }> = [
  { stdin: false },
  { value: "v", stdin: false },
  { value: "-x9-value", stdin: false },
  { value: "", stdin: false },
  { stdin: true },
  { stdin: false, file: "k.pem" },
  { stdin: false, file: "" },
  { stdin: false, generate: "hex:32" },
  { stdin: false, generate: "hex:8" },
  { stdin: false, generate: "nope" },
  { value: "v", stdin: true },
  { stdin: true, generate: "hex:32" },
  { stdin: true, generate: "hex:8" },
  { value: "v", stdin: false, file: "f" },
  { stdin: false, file: "f", generate: "alnum:30" },
];

const BYTES: number[][] = [
  [...Buffer.from("s3cr3t\n")],
  [...Buffer.from("s3cr3t\r\n")],
  [...Buffer.from("s3cr3t\n\n")],
  [...Buffer.from("s3cr3t\r\n\r\n")],
  [...Buffer.from("s3cr3t\r")],
  [...Buffer.from("a\nb\n")],
  [...Buffer.from("\n")],
  [...Buffer.from("\r\n")],
  [],
  [...Buffer.from("s3cr3t\0x")],
  [0x73, 0xff, 0x33],
  [0xed, 0xa0, 0x80],
  [0xc3],
  [...Buffer.from("\ufeffv")],
  [...Buffer.from("\u00e9\u{1F600}\n")],
  [...Buffer.from(" spaced \n")],
];

const HIDDEN: string[][] = [
  ["abc\r"],
  ["abc\n"],
  ["abc\u0004"],
  ["\r"],
  ["abcd", "efgh\u0004"],
  ["abcd"],
  ["abcdefgh\u{1F600}", "\u007f", "\r"],
  ["abcdefgh\u{1F600}\u007f\r"],
  ["abcdefgh\u00e9x\b\u007f\r"],
  ["abc\u001b[D", "def\u001bOA", "gh\u001b[1;5C\t\r"],
  ["a\u001b", "[", "1;2", "Hb\r"],
  ["a\u001bxb\r"],
  ["a\u001b\u001b[Ab\r"],
  ["a\u0001\u0002\u0005\u007fb\r"],
  ["a\u0085\u009bb\r"],
  ["\u007f\u007fab\r"],
  ["ab\rcd\r"],
  ["e\u0301\u007f\r"],
  ["\u{1F468}\u200d\u{1F469}\u200d\u{1F467}x\u007f\u007f\r"],
  ["\u{1F1E7}\u{1F1EA}\u{1F1F3}\u{1F1F1}\u007f\r"],
  ["\u1100\u1161\u11a8\u007f\r"],
  ["x\u0915\u094d\u0937\u007f\r"],
  ["tab\there\r"],
];

/** Code points of each kind that matter to segmentation, for the random strings below. */
const POOL = [
  "a", "Z", "1", " ", "\r", "\n", "\u0000", "\u0085", "\u00ad", "\u200b", "\u200c", "\u200d", "\u2028", "\ufeff",
  "\u0301", "\u0308", "\u0903", "\u093f", "\u0e33", "\u0600", "\u0605", "\u{110BD}",
  "\u1100", "\u1161", "\u11a8", "\uac00", "\uac01", "\ud7b0", "\ud7cb", "\ua960",
  "\u0915", "\u0937", "\u094d", "\u09cd", "\u0995", "\u093c", "\u0d4d", "\u0d15",
  "\u{1F600}", "\u{1F468}", "\u{1F469}", "\u{1F3FB}", "\u2764", "\ufe0f", "\u00a9", "\u{1F1E7}", "\u{1F1EA}", "\u{1F1F3}", "\u{E0020}", "\u{E007F}", "\u{1F3F4}",
  "\u00e9", "\u4e2d", "\u{20000}", "\u{1D173}",
];

/** A fixed pseudo-random sequence, so the vectors do not change between runs. */
function* lcg(seed: number): Generator<number> {
  let s = seed;
  for (;;) {
    s = (s * 1103515245 + 12345) % 2147483648;
    yield s;
  }
}

function segmentationTexts(): string[] {
  const texts = [
    "", "a", "abc", "abcdefghe\u0301", "abcdefgh\u{1F468}\u200d\u{1F469}\u200d\u{1F467}", "e\u0301\u0301", "\r\n", "\n\r", "a\r\nb", "\u{1F1E7}\u{1F1EA}\u{1F1F3}\u{1F1F1}\u{1F1E7}", "\u1100\u1161\u11a8\uac00",
    "\u0915\u094d\u0937", "\u0915\u093c\u094d\u0937", "\u0915\u094d\u200d\u0937", "\u0600a", "\u{1F600}\u{1F3FB}\u200d\u{1F600}", "\u{1F3F4}\u{E0067}\u{E0062}\u{E007F}",
    "a\u200db", "\u{1F600}\u0301\u200d\u{1F600}", "\u{1F600}\u0903\u200d\u{1F600}", "\u0000\u0301", "\u0301",
  ];
  const random = lcg(20261118);
  for (let n = 0; n < 2000; n++) {
    const length = 1 + ((random.next().value as number) % 8);
    let text = "";
    for (let i = 0; i < length; i++) text += POOL[(random.next().value as number) % POOL.length];
    texts.push(text);
  }
  return texts;
}

const seg = new Intl.Segmenter(undefined, { granularity: "grapheme" });

/** The table: every code point whose properties are not "Other", as ranges. */
function graphemeTable(): Array<[number, number, string]> {
  const count = (s: string) => {
    let k = 0;
    for (const _ of seg.segment(s)) k++;
    return k;
  };
  const joins = (...parts: string[]) => count(parts.join("")) === 1;
  const KA = "\u0915", VIRAMA = "\u094d", EMOJI = "\u{1F600}", ZWJ = "\u200d";
  const L = "\u1100", V = "\u1161", T = "\u11a8";
  const pictographic = /\p{Extended_Pictographic}/u;
  const ranges: Array<[number, number, string]> = [];
  for (let cp = 0; cp <= 0x10ffff; cp++) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    const c = String.fromCodePoint(cp);
    let gcb: string;
    if (cp === 0x0d) gcb = "CR";
    else if (cp === 0x0a) gcb = "LF";
    else if (cp === 0x200d) gcb = "ZWJ";
    else if (!joins(c, "\u0301")) gcb = "Control"; // GB4: nothing attaches to a control
    else if (joins("a", c)) gcb = joins(EMOJI, c, ZWJ, EMOJI) ? "Extend" : "SpacingMark"; // GB9, GB9a; GB11 takes Extend only
    else if (joins(c, "a")) gcb = "Prepend"; // GB9b
    else if ((cp >= 0x1100 && cp <= 0x11ff) || (cp >= 0xa960 && cp <= 0xa97f) || (cp >= 0xac00 && cp <= 0xd7ff)) {
      // GB6 to GB8
      if (joins(c, L)) gcb = "L";
      else if (joins(c, V) && joins(V, c)) gcb = "V";
      else if (joins(c, V)) gcb = "LV";
      else if (joins(c, T) && joins(V, c)) gcb = "T";
      else if (joins(c, T)) gcb = "LVT";
      else gcb = "Other";
    } else if (cp >= 0x1f1e6 && cp <= 0x1f1ff && joins(c, c) && count(c + c + c) === 2) gcb = "RI"; // GB12, GB13
    else gcb = "Other";
    // GB9c
    let incb = "";
    if (gcb === "Extend" || gcb === "ZWJ" || gcb === "SpacingMark") {
      if (joins(KA, c, KA)) incb = "Linker";
      else if (joins(KA, c, VIRAMA, KA)) incb = "Extend";
    } else if (joins(KA, VIRAMA, c)) incb = "Consonant";
    const key = `${gcb}|${incb}|${pictographic.test(c) ? "P" : ""}`;
    const last = ranges[ranges.length - 1];
    if (last && last[2] === key && (last[1] === cp - 1 || (last[1] === 0xd7ff && cp === 0xe000))) last[1] = cp;
    else ranges.push([cp, cp, key]);
  }
  return ranges.filter((r) => r[2] !== "Other||");
}

// ---- validation --------------------------------------------------------------

const BASE: ValidationReport = { valid: false, missing: [], invalid: [], unresolved: [] } as unknown as ValidationReport;

const REPORTS: Array<[string, unknown]> = [
  ["production", { ...BASE, valid: true, complete: true }],
  ["production", { ...BASE, valid: true }],
  ["dev", { valid: true, missing: [], invalid: [], unresolved: [] }],
  ["dev", { valid: false }],
  ["dev", { valid: true, complete: false, notEvaluated: [{ name: "API_KEY", requires: "secret.reveal", reason: "access" }] }],
  ["dev", { valid: true, notEvaluated: [{ name: "A", requires: "secret.reveal" }] }],
  ["dev", { valid: true, complete: null, notEvaluated: [] }],
  ["production", { ...BASE, missing: ["DATABASE_URL", "API_KEY"], invalid: [{ name: "PORT", reason: "expected a number" }] }],
  ["production", { ...BASE, complete: false, missing: ["X"], notEvaluated: [{ name: "S", requires: "secret.reveal", reason: "access" }] }],
  ["production", { ...BASE, complete: false, notEvaluated: [
    { name: "A", requires: "config.metadata.read", reason: "access" },
    { name: "B", requires: "config.value.read", reason: "access" },
    { name: "C", requires: "secret.reveal", reason: "requirement" },
    { name: "D", requires: "made.up", reason: "access" },
    { name: "E", requires: "made.up", reason: "requirement" },
  ] }],
  ["production", { ...BASE, unresolved: [{ name: "URL", reason: "reference" }] }],
  ["production", { ...BASE, unresolved: [{ name: "URL", reason: "authority" }] }],
  ["production", { ...BASE, complete: false, unresolved: [{ name: "URL", reason: "authority" }], notEvaluated: [{ name: "K", requires: "secret.reveal" }] }],
  ["production", { ...BASE, invalid: [{ name: "N\u001b[31m", reason: "bad\u202e" }], missing: ["M\u0007"] }],
  ["production", { ...BASE, missing: ["A"], complete: 0 }],
  ["production", { valid: 1, complete: "yes" }],
  ["dev", { ...BASE, invalid: [{ name: "X" }], extra: { kept: false } }],
];

// ---- import helpers -----------------------------------------------------------

const INFER: string[] = [
  "", "true", "FALSE", "True", "yes", "1", "0", "-1", "007", "1.5", "-0.5", "1.", ".5", "1e5", "9007199254740993", "12345678901234567890",
  "https://example.com", "http://localhost:3000/x", "ftp://x", "postgres://u:p@h/db", "user@example.com", "a@b", "not an email@", "plain text",
  " 1", "1 ", "+1", "0x10", "\u0661\u0662\u0663",
];

const ENTRY_SETS: Array<Array<{ name: string; value: string; line: number }>> = [
  [{ name: "A", value: "1", line: 1 }],
  [{ name: "VARLATCH_TOKEN", value: "x", line: 1 }, { name: "lower", value: "x", line: 2 }, { name: "A.B", value: "x", line: 3 }],
  [{ name: "A", value: "x\u0000y", line: 4 }],
  [{ name: "A", value: "1", line: 1 }, { name: "B", value: "2", line: 2 }, { name: "A", value: "3", line: 5 }, { name: "B", value: "4", line: 9 }, { name: "A", value: "5", line: 10 }],
  [{ name: "VARLATCH_X", value: "\u0000", line: 1 }, { name: "VARLATCH_X", value: "", line: 2 }],
  [{ name: "_A", value: "1", line: 1 }, { name: "A_1", value: "1", line: 2 }, { name: "1A", value: "1", line: 3 }],
];

const DECODE: number[][] = [
  [...Buffer.from("A=\u00e9\nB=\u{1F600}\n")],
  [...Buffer.from("A=1\nB=2\nC=x"), 0xc3, 0x28, 0x0a],
  [0x41, 0x3d, 0xe2, 0x82],
  [0xef, 0xbb, 0xbf, ...Buffer.from("A=1")],
  [0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf, ...Buffer.from("A=1")],
  [...Buffer.from("A=1\n"), 0xed, 0xa0, 0x80],
  [...Buffer.from("A=1\r\n\r\n"), 0xff],
  [0xf4, 0x90, 0x80, 0x80],
  [],
];

describe("Go CLI vectors: values and import", () => {
  it("values.json is the TypeScript code's answers", () => {
    const vectors = {
      comment: "Generated by apps/cli/test/go-vectors-values.test.ts from the TypeScript CLI; do not edit. Regenerate with VARLATCH_WRITE_GO_VECTORS=1.",
      dotenv: DOTENV.map(dotenvVector),
      generateSpec: GENERATE_SPECS.map((raw) => {
        try {
          const spec = parseGenerateSpec(raw);
          return { raw, spec, description: describeGenerated(spec) };
        } catch (err) {
          return { raw, ...failure(err) };
        }
      }),
      valueSource: SOURCES.map((options) => {
        try {
          return { options, source: valueSourceOf(options) };
        } catch (err) {
          return { options, ...failure(err) };
        }
      }),
      valueFromBytes: BYTES.map((bytes) => {
        try {
          return { bytes, value: valueFromBytes(Buffer.from(bytes), "standard input") };
        } catch (err) {
          return { bytes, ...failure(err) };
        }
      }),
      wellFormed: ["", "abc", "\u00e9\u{1F600}", "a\ud800", "\udc00b", "\u{1F600}"].map((text) => ({ text, wellFormed: isWellFormedText(text) })),
      hiddenInput: HIDDEN.map((chunks) => {
        const input = new HiddenInput();
        let value: string | null = null;
        for (const chunk of chunks) {
          value = input.feed(chunk);
          if (value !== null) break;
        }
        return { chunks, value };
      }),
      dropLastCharacter: segmentationTexts().map((text) => ({
        text,
        result: dropLastCharacter(text),
        segments: [...seg.segment(text)].map((s) => s.segment),
      })),
      validation: REPORTS.map(([environment, report]) => {
        const outcome = validationOutcome(environment, report as ValidationReport);
        return { environment, report, outcome, document: validationDocument(environment, report as ValidationReport, outcome.exitCode) };
      }),
      inferType: [1, 2, 3].flatMap((semanticsVersion) => INFER.map((value) => ({ value, semanticsVersion, type: inferType(value, semanticsVersion) }))),
      checkEntries: ENTRY_SETS.map((entries) => ({ entries, problems: checkEntries(entries) })),
      decodeStrict: DECODE.map((bytes) => {
        try {
          return { bytes, text: decodeStrict(Buffer.from(bytes), ".env") };
        } catch (err) {
          if (!(err instanceof ImportError)) throw err;
          return { bytes, error: err.message };
        }
      }),
    };
    const result = writeOrCompare(VECTORS, `${JSON.stringify(vectors, null, 2)}\n`);
    expect(result.current, "values.json is stale: regenerate it (see this file's comment)").toBe(true);
  });

  it("graphemes.json is this Node.js's segmentation, under the Unicode version it names", () => {
    const writing = process.env.VARLATCH_WRITE_GO_VECTORS === "1";
    if (!writing && existsSync(GRAPHEMES)) {
      const recorded = JSON.parse(readFileSync(GRAPHEMES, "utf8")) as { unicode: string };
      if (recorded.unicode !== process.versions.unicode) return; // another ICU: nothing to compare with
    }
    const table = {
      comment:
        "Written by apps/cli/test/go-vectors-values.test.ts from Intl.Segmenter; do not edit. Each range: first and last code point, and Grapheme_Cluster_Break|Indic_Conjunct_Break|P (Extended_Pictographic).",
      unicode: process.versions.unicode,
      ranges: graphemeTable(),
    };
    const text = `{\n  "comment": ${JSON.stringify(table.comment)},\n  "unicode": ${JSON.stringify(table.unicode)},\n  "ranges": [\n${table.ranges.map((r) => `    ${JSON.stringify(r)}`).join(",\n")}\n  ]\n}\n`;
    const result = writeOrCompare(GRAPHEMES, text);
    expect(result.current, "graphemes.json is stale: regenerate it (see this file's comment)").toBe(true);
  }, 120_000);
});
