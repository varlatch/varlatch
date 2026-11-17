// SPDX-License-Identifier: Apache-2.0
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  ContextError,
  defaultServer,
  deleteCredential,
  listCredentials,
  loadCredential,
  loadLocalState,
  loadRepoConfig,
  rememberServerIfUnset,
  saveCredential,
  saveLocalState,
  setDefaultServer,
} from "@varlatch/context";
import { afterAll, describe, expect, it } from "vitest";
import { writeOrCompare } from "./goKit.js";

/**
 * Vectors for the Go CLI's context and credential store (internal
 * docs/design/go-cli.md, slice 5.1b and decision 11), from the TypeScript
 * code itself:
 *
 * - repoConfig: what loadRepoConfig makes of a varlatch.toml (smol-toml
 *   1.9.0): the configuration, or the error's message;
 * - dateParse: Date.parse, with the local time zone America/New_York;
 * - utf8: how readFileSync(path, "utf8") decodes bytes;
 * - toNumber: Number(text) for short texts (smol-toml's hour checks);
 * - store: credentials.json, settings.json and .varlatch/local.json as
 *   packages/context reads and writes them, from files a CLI or a person
 *   left: the result of each operation and every file afterwards, with its
 *   mode. The Go store must give the same, so a sign-in made by either CLI
 *   works with the other.
 *
 * Regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/cli exec vitest run test/go-vectors-context.test.ts
 */

const VECTORS = fileURLToPath(new URL("../../../go/cmd/varlatch/testdata/vectors/context.json", import.meta.url));

const scratch = realpathSync(mkdtempSync(join(tmpdir(), "varlatch-go-vectors-context-")));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

// ---- varlatch.toml ---------------------------------------------------------

const BASE = 'organization = "acme"\nproject = "web"\n';

/** Values for `organization = <value>`. */
const VALUES = [
  '"acme"', "'acme'", '""', "''", '"a\\"b"', "'a\\b'", '"a\\\\b"', '"\\b\\t\\n\\f\\r\\e\\"\\\\"', '"\\x41"', '"\\u00e9"', '"\\U0001F600"',
  '"\\uD800"', '"\\U00110000"', '"\\UFFFFFFFF"', '"\\u12G4"', '"\\q"', '"\\ "', '"tab\there"', '"a\u0001b"', '"a\u007fb"', '"unterminated',
  '"""multi\nline"""', '"""\nfirst newline trimmed"""', '"""\r\ncrlf trimmed"""', '"""a \\\n   b"""', '"""a \\  \n\n  b"""', '"""a \\ x"""',
  '"""quote"at end"""""', '"""two""quotes"""', '"""ends with four""""', '"""ends with six""""""', "'''literal\n\\n'''", "'''a''''", "'''unterminated",
  '"""a\\\n"""', '"""\\\n  \\u0041"""', "true", "false", "tru", "falsey", "42", "+42", "-42", "0", "+0", "-0", "00", "0123", "1_000", "1__0", "_1", "1_",
  "0x1F", "0xdead_beef", "0X1F", "0o17", "0b101", "0b102", "0x", "0x_1", "+0x1", "3.14", "-0.5", "1e10", "1E-5", "6.02e+23", "1.", ".5", "1.e5", "1e",
  "1_0.0_1", "inf", "+inf", "-inf", "nan", "+nan", "-nan", "infinity", "9007199254740991", "9007199254740992", "-9007199254740991",
  "-9007199254740992", "0x1FFFFFFFFFFFFF", "0x20000000000000", "123456789012345678901234567890", "1979-05-27", "1979-05-27T07:32:00Z",
  "1979-05-27t07:32:00z", "1979-05-27 07:32:00Z", "1979-05-27T07:32:00", "1979-05-27T00:32:00.999999-07:00", "1979-05-27T00:32:00+0700",
  "07:32:00", "07:32", "00:32:00.5", "24:00:00", "25:00:00", "1979-02-30", "1979-13-01", "1979-00-10", "1979-01-32", "1979-05-27T24:00:00Z",
  "1979-05-27T23:60:00Z", "1979-05-27T25:00:00Z", "1979-ab-c7", "1979- 5- 7", "1979-05-27T", "1979-05-27T07", "1979-05-27Tab:cd:efZ",
  "1979-05-27 07:32", "2000-01-01T00:00:00+24:00", "[]", '["a", "b",]', "[1, [2, [3]]]", "[1 2]", "[,]", "[\n  1, # one\n  2\n]", "[1,",
  "{}", "{ a = 1 }", "{ a = 1, }", "{ a = 1, a = 2 }", "{ a.b = 1, a.c = 2 }", "{ a.b = 1, a = 2 }", "{ a = { b = 1 }, a.c = 2 }",
  "{ a = [1], a.b = 2 }", "{ a = 1\n}", "{ a = 1", "x", "=", "",
];

const DOCUMENTS: Array<[string, string]> = [
  ["base", BASE],
  ["full", 'server = "https://repo.example"\norganization = "acme"\nproject = "web"\ndefault_environment = "dev"\n'],
  ["empty", ""],
  ["only-comments", "# a\n# b\n"],
  ["missing-project", 'organization = "acme"\n'],
  ["missing-organization", 'project = "web"\n'],
  ["server-not-string", `${BASE}server = 1\n`],
  ["server-empty", `${BASE}server = ""\n`],
  ["environment-not-string", `${BASE}default_environment = ["dev"]\n`],
  ["bom", `﻿${BASE}`],
  ["bom-twice", `﻿﻿${BASE}`],
  ["crlf", BASE.replace(/\n/g, "\r\n")],
  ["lone-cr", 'organization = "acme"\rproject = "web"\n'],
  ["no-final-newline", 'organization = "acme"\nproject = "web"'],
  ["tabs-and-spaces", '\t organization\t=\t"acme"  \n  project = "web"\t# c\n'],
  ["comment-control", 'organization = "acme" # \u0000\nproject = "web"\n'],
  ["comment-del", 'organization = "acme" # \u007f\nproject = "web"\n'],
  ["comment-tab", 'organization = "acme" # \t ok\nproject = "web"\n'],
  ["nul-in-key", 'organ\u0000ization = "acme"\nproject = "web"\n'],
  ["quoted-keys", '"organization" = "acme"\n\'project\' = "web"\n'],
  ["empty-quoted-key", `${BASE}"" = 1\n`],
  ["multiline-key", `${BASE}"""a""" = 1\n`],
  ["dotted-keys", `${BASE}a.b.c = 1\na.b.d = 2\n`],
  ["dotted-spaces", `${BASE}a . b = 1\n`],
  ["dotted-quoted", `${BASE}a."b.c" = 1\n`],
  ["empty-dotted", `${BASE}a..b = 1\n`],
  ["key-ends-dot", `${BASE}a. = 1\n`],
  ["key-space-inside", `${BASE}a b = 1\n`],
  ["key-unicode", `${BASE}é = 1\n`],
  ["key-no-value", `${BASE}a =\n`],
  ["key-no-equals", `${BASE}a\n`],
  ["key-at-end", `${BASE}a`],
  ["value-then-junk", `${BASE}a = 1 x\n`],
  ["value-then-comment", `${BASE}a = 1 # x\n`],
  ["duplicate", 'organization = "acme"\norganization = "acme"\nproject = "web"\n'],
  ["dotted-over-value", `${BASE}a = 1\na.b = 2\n`],
  ["value-over-dotted", `${BASE}a.b = 1\na = 2\n`],
  ["table", `${BASE}[a]\nb = 1\n`],
  ["table-then-top", `[a]\n${BASE}`],
  ["table-twice", `${BASE}[a]\n[a]\n`],
  ["super-after", `${BASE}[a.b]\nc = 1\n[a]\nd = 2\n`],
  ["super-twice", `${BASE}[a.b]\n[a]\n[a]\n`],
  ["table-over-value", `${BASE}a = 1\n[a]\n`],
  ["table-over-inline", `${BASE}a = {}\n[a]\n`],
  ["table-over-dotted", `${BASE}a.b = 1\n[a]\n`],
  ["dotted-into-table", `${BASE}[a]\nb.c = 1\n[a.b]\n`],
  ["table-dotted-defined", `${BASE}[a.b]\nc = 1\n[a]\nb.d = 1\n`],
  ["array-tables", `${BASE}[[a]]\nx = 1\n[[a]]\nx = 2\n`],
  ["array-table-sub", `${BASE}[[a]]\n[a.b]\nc = 1\n[[a]]\n[a.b]\nc = 2\n`],
  ["array-table-over-table", `${BASE}[a]\n[[a]]\n`],
  ["table-over-array-table", `${BASE}[[a]]\n[a]\n`],
  ["array-table-dotted", `${BASE}[[a.b]]\n[[a.b]]\n[a]\nc = 1\n`],
  ["array-table-over-value", `${BASE}a = []\n[[a]]\n`],
  ["dotted-into-array-table", `${BASE}[[a]]\n[b]\na.c = 1\n`],
  ["array-of-tables-dotted-key", `${BASE}[[a]]\nb.c = 1\n`],
  ["dotted-into-array", `${BASE}[[a]]\n[x]\n[[a.b]]\n`],
  ["table-unclosed", `${BASE}[a\n`],
  ["table-empty", `${BASE}[]\n`],
  ["array-table-unclosed", `${BASE}[[a]\n`],
  ["array-table-space", `${BASE}[ [a] ]\n`],
  ["table-trailing", `${BASE}[a] x\n`],
  ["table-comment", `${BASE}[a] # c\n`],
  ["inline-then-table-dotted", `${BASE}a = { b = 1 }\na.c = 2\n`],
  ["deep-arrays", `${BASE}a = ${"[".repeat(999)}${"]".repeat(999)}\n`],
  ["too-deep-arrays", `${BASE}a = ${"[".repeat(1001)}${"]".repeat(1001)}\n`],
  ["line-9", `${"# x\n".repeat(8)}organization = = 1\n`],
  ["line-10", `${"# x\n".repeat(9)}organization = = 1\n`],
  ["line-99", `${"# x\n".repeat(98)}organization = = 1\n`],
  ["line-100", `${"# x\n".repeat(99)}organization = = 1\n`],
  ["error-first-line", "= 1\n"],
  ["error-after-blank", '\n\norganization = = 1\n\nproject = "web"\n'],
  ["error-astral-column", 'organization = "😀😀" x\n'],
  ["error-at-end", 'organization = "acme'],
  ["error-crlf", 'organization = "acme"\r\nproject = = 1\r\nx = 1\r\n'],
  ["values-at-top-after-table", `[t]\n${BASE}`],
  ["proto-keys", `${BASE}__proto__ = 1\nconstructor = 2\n[toString]\nx = 1\n`],
  ["organization-table", 'project = "web"\n[organization]\nname = "acme"\n'],
  ["organization-dotted", 'project = "web"\norganization.name = "acme"\n'],
  ["unfinished-array-at-end", `${BASE}x = [1,`],
  ["unfinished-table-at-end", `${BASE}x = { a = 1,`],
  ["date-part-malformed", `${BASE}x = 1979-05-2x\n`],
  ["table-array-unclosed-at-end", `${BASE}[[a]`],
];

function tomlVectors(): Array<{ name: string; toml: string; result: unknown }> {
  const dir = join(scratch, "toml");
  mkdirSync(dir, { recursive: true });
  const cases: Array<[string, string]> = [
    ...DOCUMENTS,
    ...VALUES.map((value, i): [string, string] => [`value-${i}`, `organization = ${value}\nproject = "web"\n`]),
  ];
  return cases.map(([name, toml]) => {
    writeFileSync(join(dir, "varlatch.toml"), toml);
    try {
      return { name, toml, result: { config: loadRepoConfig(dir) } };
    } catch (err) {
      if (!(err instanceof ContextError)) throw err;
      return { name, toml, result: { error: err.message } };
    }
  });
}

// ---- Date.parse, UTF-8, Number --------------------------------------------

const DATES = [
  "2026-11-17T10:00:00.000Z", "2026-11-17T10:00:00Z", "2026-11-17T10:00Z", "2026-11-17T10:00", "2026-11-17T10:00:00", "2026-11-17", "2026-11", "2026",
  "+002026-11-17T00:00:00Z", "-000001-01-01T00:00:00Z", "-000000-01-01T00:00:00Z", "+275760-09-13T00:00:00.000Z", "+275760-09-13T00:00:00.001Z",
  "-271821-04-20T00:00:00.000Z", "-271821-04-19T23:59:59.999Z", "2026-11-17t10:00:00z", "2026-11-17T10:00:00.1Z", "2026-11-17T10:00:00.12Z",
  "2026-11-17T10:00:00.1234567Z", "2026-11-17T10:00:00.1234567891234Z", "2026-11-17T10:00:00+01:00", "2026-11-17T10:00:00-0130",
  "2026-11-17T10:00:00+0100", "2026-11-17T10:00:00+24:00", "2026-11-17T10:00:00+23:59", "2026-11-17T10:00:00+1:00", "2026-11-17T24:00:00Z",
  "2026-11-17T24:00:01Z", "2026-11-17T24:00:00.001Z", "2026-11-17T23:59:60Z", "2026-02-29", "2024-02-29", "2026-02-31", "2026-04-31T00:00:00Z",
  "2026-13-01", "2026-00-01", "2026-01-00", "2026-01-32", "2026-1-1", "2026-11-17T1:00Z", "2026-11-17T10", "2026-11-17T10:00:00Zjunk",
  "20261117", "2026/11/17", "11/17/2026", "17/11/2026", "12/31/2020", "1", "5", "12", "99", "100", "2020", "0", "-1", "Nov 17 2026",
  "17 Nov 2026", "November 17, 2026 10:00:00", "Tue, 17 Nov 2026 10:00:00 GMT", "Tue Nov 17 2026 10:00:00 GMT+0100 (Central European Standard Time)",
  "17 Nov 2026 10:00 EST", "17 Nov 2026 10:00 PDT", "17 Nov 2026 10:00 UTC", "17 Nov 2026 10:00 UT", "17 Nov 2026 10:00 Z", "17 Nov 2026 10:00 +0530",
  "17 Nov 2026 10:00 GMT-8", "17 Nov 2026 10:00 GMT+12345", "17 Nov 2026 10:00 -5:", "17 Nov 2026 10:00 am", "17 Nov 2026 10:00 pm", "17 Nov 2026 12:00 am",
  "17 Nov 2026 13:00 pm", "Nov 2026", "Nov", "garbage 2026-11-17", "garbage2026", "x 17 Nov 2026", "2026-11-17 10:00:00", "2026-11-17 10:00:00Z",
  "2026-11-17 10:00:00.5", "2026-11-17 10:00:00.", "2026-11-17 10:00::", "2026-11-17 10::", "10:00 2026-11-17", "2026-11-17T10:00:00 junk",
  "(comment) 17 Nov 2026", "17 Nov 2026 (comment)", "17 Nov 2026)", "17 Nov 2026 +", "Mon, 17 Nov 2026", "Jan 32 2026", "Feb 30 2026", "30 Feb 2026",
  "2026 Nov 17", "2026-Nov-17", "17-Nov-2026", "Nov-17-2026", "1/2/3", "1/2/50", "1/2/49", "13/1/2026", "2026-11-17 10:00", "2026-11-17 10:00",
  "2026-11-17　Z", "é 17 Nov 2026", "17 Nov 2026 10:00:00.123456", "17 Nov 2026 10:00:00.", "17 Nov 2026 25:00", "17 Nov 2026 24:00",
  "17 Nov 2026 10:60", "Nov 17 1000000", "Nov 17 999999", "+999999-01-01", "-999999-01-01", "Jan 1 2000 10:00 +300000:", "Jan 1 2000 10:00 +596524:",
  "true", "[object Object]", "x,y", "", " ", "2026-11-17\u0000junk", "yesterday", "tomorrow", "2026-03-08T02:30:00", "2026-11-01T01:30:00",
];

const UTF8: string[] = [
  "", "41", "c3a9", "e282ac", "f09f9880", "ff", "80", "c0af", "c1bf", "c2", "e282", "e28241", "e0809f", "e0a080", "eda080", "ed9fbf", "f08f8080",
  "f0908080", "f4908080", "f48fbfbf", "f5", "f8888080", "e28241808041f09f41", "efbbbf41", "41ed", "c3", "e282e2", "fe", "f09f98",
];

const NUMBERS = ["", " ", "1", "12", " 1", "1 ", "+1", "-1", ".5", "1.", "1e", "0x", "0x1", "ab", "\t2", "1 ", "In", "07", "1_", "　"];

// ---- the store -------------------------------------------------------------

type Op =
  | { op: "list" }
  | { op: "load"; server: string }
  | { op: "save"; server: string; credential: Record<string, unknown> }
  | { op: "delete"; server: string }
  | { op: "defaultServer" }
  | { op: "setDefault"; server: string | null }
  | { op: "rememberIfUnset"; server: string }
  | { op: "loadLocal" }
  | { op: "saveLocal"; state: Record<string, unknown> };

interface StoreCase {
  name: string;
  /** Files before, relative to the case directory: config/ is VARLATCH_CONFIG_DIR, xdg/varlatch/ the default directory. */
  files?: Record<string, string>;
  /** Inside an agent-safe run, with VARLATCH_CONFIG_DIR unset (the default directory) or set to config/. */
  agentRun?: "default" | "own";
  ops: Op[];
}

const STORE = (servers: Record<string, unknown>, extra: Record<string, unknown> = {}): string => `${JSON.stringify({ servers, ...extra }, null, 2)}\n`;
const A = { token: "vlt_cli_fakeAAAA", issuedAt: "2026-11-17T10:00:00.000Z", expiresAt: "2026-11-18T10:00:00.000Z", credentialId: "cred_a", name: "laptop" };
const B = { token: "vlt_cli_fakeBBBB" };

const STORE_CASES: StoreCase[] = [
  { name: "fresh-save", ops: [{ op: "save", server: "https://a.example/", credential: A }, { op: "list" }, { op: "load", server: "https://a.example" }] },
  { name: "save-keeps-others", files: { "config/credentials.json": STORE({ "https://b.example": { ...B, future: { x: 1 } } }, { top: "kept" }) }, ops: [{ op: "save", server: "https://a.example", credential: A }, { op: "list" }] },
  { name: "save-replaces", files: { "config/credentials.json": STORE({ "https://a.example": { token: "old", extra: 1 }, "https://b.example": B }) }, ops: [{ op: "save", server: "https://a.example//", credential: A }] },
  { name: "save-integer-like-keys", files: { "config/credentials.json": '{"servers": {"b": {"token": "t"}}, "1": "one", "z": 2}\n' }, ops: [{ op: "save", server: "10", credential: B }, { op: "save", server: "2", credential: B }] },
  { name: "save-over-corrupt", files: { "config/credentials.json": "{\"servers\": {" }, ops: [{ op: "save", server: "https://a.example", credential: A }] },
  { name: "save-over-bom", files: { "config/credentials.json": `﻿${STORE({ "https://b.example": B })}` }, ops: [{ op: "list" }, { op: "save", server: "https://a.example", credential: A }] },
  { name: "save-over-null", files: { "config/credentials.json": "null" }, ops: [{ op: "save", server: "https://a.example", credential: A }] },
  { name: "save-null-servers", files: { "config/credentials.json": '{"servers": null, "k": 1}' }, ops: [{ op: "save", server: "https://a.example", credential: A }] },
  { name: "save-array-servers", files: { "config/credentials.json": '{"servers": [1]}' }, ops: [{ op: "save", server: "https://a.example", credential: A }, { op: "save", server: "1", credential: B }] },
  { name: "save-string-servers", files: { "config/credentials.json": '{"servers": "abc"}' }, ops: [{ op: "save", server: "https://a.example", credential: A }] },
  { name: "save-array-file", files: { "config/credentials.json": "[1, 2]" }, ops: [{ op: "save", server: "https://a.example", credential: A }] },
  { name: "save-string-file", files: { "config/credentials.json": '"x"' }, ops: [{ op: "save", server: "https://a.example", credential: A }] },
  { name: "save-number-file", files: { "config/credentials.json": "5" }, ops: [{ op: "save", server: "https://a.example", credential: A }] },
  { name: "list-shapes", files: { "config/credentials.json": '{"servers": {"https://a.example": {"token": "t"}, "https://b.example": "text", "https://c.example": 3, "https://d.example": null}}' }, ops: [{ op: "list" }, { op: "load", server: "https://d.example" }, { op: "load", server: "https://b.example/" }] },
  { name: "list-string-servers", files: { "config/credentials.json": '{"servers": "ab"}' }, ops: [{ op: "list" }, { op: "load", server: "1" }, { op: "load", server: "length" }] },
  { name: "list-duplicate-keys", files: { "config/credentials.json": '{"servers": {"https://a.example": {"token": "first"}, "https://b.example": {"token": "b"}, "https://a.example": {"token": "second"}}}' }, ops: [{ op: "list" }, { op: "save", server: "https://c.example", credential: B }] },
  { name: "delete", files: { "config/credentials.json": STORE({ "https://a.example": A, "https://b.example": B }), "config/settings.json": '{"defaultServer": "https://b.example", "theme": "dark"}\n' }, ops: [{ op: "delete", server: "https://a.example/" }, { op: "defaultServer" }, { op: "delete", server: "https://b.example" }, { op: "defaultServer" }, { op: "delete", server: "https://b.example" }] },
  { name: "delete-missing-file", ops: [{ op: "delete", server: "https://a.example" }] },
  { name: "delete-falsy-entry", files: { "config/credentials.json": '{"servers": {"https://a.example": 0}}' }, ops: [{ op: "delete", server: "https://a.example" }] },
  { name: "delete-array-entry", files: { "config/credentials.json": '{"servers": [{"token": "t"}, {"token": "u"}]}' }, ops: [{ op: "delete", server: "0" }] },
  { name: "default-unset", ops: [{ op: "defaultServer" }, { op: "rememberIfUnset", server: "https://a.example/" }, { op: "rememberIfUnset", server: "https://b.example" }, { op: "defaultServer" }] },
  { name: "default-replace-keeps", files: { "config/settings.json": '{"z": 1, "defaultServer": "https://a.example", "2": [true]}\n' }, ops: [{ op: "setDefault", server: "https://b.example///" }, { op: "setDefault", server: null }] },
  { name: "default-odd", files: { "config/settings.json": '{"defaultServer": 5}' }, ops: [{ op: "defaultServer" }, { op: "rememberIfUnset", server: "https://a.example" }] },
  { name: "default-empty", files: { "config/settings.json": '{"defaultServer": ""}' }, ops: [{ op: "defaultServer" }, { op: "rememberIfUnset", server: "https://a.example" }] },
  { name: "default-corrupt", files: { "config/settings.json": "[" }, ops: [{ op: "defaultServer" }, { op: "setDefault", server: "https://a.example" }] },
  { name: "default-array", files: { "config/settings.json": '["https://a.example"]' }, ops: [{ op: "defaultServer" }, { op: "setDefault", server: "https://a.example" }] },
  { name: "default-forget-absent", ops: [{ op: "setDefault", server: null }] },
  { name: "agent-run-default-store", agentRun: "default", files: { "xdg/varlatch/credentials.json": STORE({ "https://a.example": A }), "xdg/varlatch/settings.json": '{"defaultServer": "https://a.example"}' }, ops: [{ op: "list" }, { op: "load", server: "https://a.example" }, { op: "defaultServer" }, { op: "rememberIfUnset", server: "https://b.example" }, { op: "delete", server: "https://a.example" }, { op: "save", server: "https://b.example", credential: B }, { op: "setDefault", server: "https://a.example" }] },
  { name: "agent-run-own-store", agentRun: "own", files: { "config/credentials.json": STORE({ "https://a.example": A }) }, ops: [{ op: "list" }, { op: "save", server: "https://b.example", credential: B }, { op: "rememberIfUnset", server: "https://b.example" }, { op: "delete", server: "https://a.example" }] },
  { name: "local-missing", ops: [{ op: "loadLocal" }, { op: "saveLocal", state: { selectedEnvironment: "dev", selectedTier: "production", tierCachedAt: "2026-11-17T10:00:00.000Z" } }, { op: "loadLocal" }] },
  { name: "local-keeps-gitignore", files: { "repo/.varlatch/.gitignore": "custom\n", "repo/.varlatch/local.json": '{"serverOverride": "https://x.example", "other": [1]}' }, ops: [{ op: "loadLocal" }, { op: "saveLocal", state: { selectedEnvironment: "qa" } }] },
  { name: "local-shapes", files: { "repo/.varlatch/local.json": "null" }, ops: [{ op: "loadLocal" }] },
  { name: "local-corrupt", files: { "repo/.varlatch/local.json": "{" }, ops: [{ op: "loadLocal" }] },
  { name: "local-bom", files: { "repo/.varlatch/local.json": '﻿{"selectedEnvironment": "dev"}' }, ops: [{ op: "loadLocal" }] },
];

function filesUnder(root: string, at = ""): Record<string, { mode: string; content: string }> {
  const out: Record<string, { mode: string; content: string }> = {};
  for (const name of readdirSync(join(root, at)).sort()) {
    const rel = at ? `${at}/${name}` : name;
    const stat = lstatSync(join(root, rel));
    if (stat.isDirectory()) Object.assign(out, filesUnder(root, rel));
    else out[rel] = { mode: (stat.mode & 0o777).toString(8).padStart(4, "0"), content: readFileSync(join(root, rel), "utf8") };
  }
  return out;
}

function runStoreCase(c: StoreCase, index: number) {
  const dir = join(scratch, `store-${index}`);
  mkdirSync(dir, { recursive: true });
  for (const [rel, content] of Object.entries(c.files ?? {})) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), content);
    chmodSync(join(dir, rel), 0o644);
  }
  const env: NodeJS.ProcessEnv = { XDG_CONFIG_HOME: join(dir, "xdg"), HOME: join(dir, "home") };
  if (c.agentRun !== "default") env.VARLATCH_CONFIG_DIR = join(dir, "config");
  if (c.agentRun) env.VARLATCH_AGENT_RUN = "run_1";
  const repo = join(dir, "repo");
  const results = c.ops.map((op) => {
    try {
      switch (op.op) {
        case "list":
          return { value: listCredentials(env) };
        case "load":
          return { value: loadCredential(op.server, env) };
        case "save":
          saveCredential(op.server, op.credential as never, env);
          return { value: null };
        case "delete":
          return { value: deleteCredential(op.server, env) };
        case "defaultServer":
          return { value: defaultServer(env) };
        case "setDefault":
          setDefaultServer(op.server, env);
          return { value: null };
        case "rememberIfUnset":
          return { value: rememberServerIfUnset(op.server, env) };
        case "loadLocal":
          return { value: loadLocalState(repo) };
        case "saveLocal":
          saveLocalState(repo, op.state);
          return { value: null };
      }
    } catch (err) {
      if (err instanceof ContextError) return { error: { name: "ContextError", message: err.message } };
      if (err instanceof TypeError) return { error: { name: "TypeError" } };
      throw err;
    }
  });
  return { ...c, results, after: filesUnder(dir) };
}

describe("Go CLI context vectors", () => {
  it("are what the TypeScript code answers", () => {
    const savedTZ = process.env.TZ;
    process.env.TZ = "America/New_York";
    let dateParse: Array<{ text: string; value: number | null }>;
    try {
      dateParse = DATES.map((text) => {
        const v = Date.parse(text);
        return { text, value: Number.isNaN(v) ? null : v };
      });
    } finally {
      if (savedTZ === undefined) delete process.env.TZ;
      else process.env.TZ = savedTZ;
    }
    const vectors = {
      comment: "Written by apps/cli/test/go-vectors-context.test.ts from the TypeScript code; do not edit.",
      timeZone: "America/New_York",
      repoConfig: tomlVectors(),
      dateParse,
      utf8: UTF8.map((hex) => ({ hex, text: Buffer.from(hex, "hex").toString("utf8") })),
      toNumber: NUMBERS.map((text) => {
        const v = Number(text);
        return { text, value: Number.isNaN(v) ? null : v };
      }),
      store: STORE_CASES.map(runStoreCase),
    };
    const result = writeOrCompare(VECTORS, `${JSON.stringify(vectors, null, 2)}\n`);
    expect(result.current, "context.json is stale: regenerate it (see this file's comment)").toBe(true);
  });
});
