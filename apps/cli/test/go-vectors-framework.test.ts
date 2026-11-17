// SPDX-License-Identifier: Apache-2.0
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { ERROR_CODES } from "@varlatch/protocol";
import { mcpUserAgent } from "@varlatch/mcp-server/run";
import { VarlatchApiError } from "@varlatch/sdk";
import { afterAll, describe, expect, it } from "vitest";
import { takeApprovalOption } from "../src/approvals.js";
import { AGENT_MARKERS, describeAssisted, resolveAssisted, takeAssistedOption } from "../src/assisted.js";
import { EXIT, apiErrorExit } from "../src/exitCodes.js";
import { OptionsError, parseOptions, type OptionSpec } from "../src/options.js";
import {
  forgetSecrets,
  maskSecrets,
  printable,
  rememberSecret,
  safeApiMajor,
  safeRequestId,
  safeTime,
  safeVersion,
  serverMessage,
} from "../src/safeText.js";
import { USAGE, commandHelp } from "../src/usage.js";
import { formatUserAgent } from "../src/userAgent.js";
import { writeOrCompare } from "./goKit.js";

/**
 * Vectors for the Go CLI's framework (internal docs/design/go-cli.md, slice
 * 5.1a): what the TypeScript code answers for the option parser, the help
 * text, terminal-safe text, assisted mode, the global --approval option, the
 * User-Agents, the exit status of an API error, and the protocol's error
 * codes; and, for go/lib/jsjson, what JSON.parse and JSON.stringify make of
 * a set of JSON texts. The Go tests replay them. Regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/cli exec vitest run test/go-vectors-framework.test.ts
 */

const FRAMEWORK = fileURLToPath(new URL("../../../go/cmd/varlatch/testdata/vectors/framework.json", import.meta.url));
const JSJSON = fileURLToPath(new URL("../../../go/lib/jsjson/testdata/ts-vectors.json", import.meta.url));

const SPECS: Record<string, OptionSpec> = {
  whoami: { values: ["--server"], booleans: ["--json"] },
  lists: { values: ["--environment", "--server"], lists: ["--omit", "--map"], booleans: ["--json", "--dry-run"], positionals: 2, aliases: { "-e": "--environment" } },
  once: { booleans: ["--json", "--yes"], onceBooleans: true },
  endOfOptions: { values: ["--replace"], positionals: 2, endOfOptions: true },
  aliasesOnly: { values: ["--environment"], aliases: { "-e": "--environment", "--env": "--environment" } },
};

const ARGS: string[][] = [
  [],
  ["--json"],
  ["--json", "--json"],
  ["--server", "https://a"],
  ["--server"],
  ["--server", "--json"],
  ["--server", "-x"],
  ["--server", "https://a", "--server", "https://b"],
  ["--chek"],
  ["-x"],
  ["extra"],
  ["one", "two"],
  ["one", "two", "three"],
  ["--omit", "A", "--omit", "B"],
  ["--omit"],
  ["-e", "dev"],
  ["-e", "dev", "--environment", "prod"],
  ["--environment", "prod", "-e", "dev"],
  ["--env", "dev"],
  ["--env", "dev", "-e", "prod"],
  ["--map", "A=B", "x", "--dry-run", "y"],
  ["--", "-value"],
  ["ITEM", "--", "-v"],
  ["--", "a", "b", "c"],
  ["--replace", "X", "--", "--replace"],
  ["--yes", "--json", "--yes"],
  ["--server=https://a"],
  ["-"],
  [""],
  ["--", ""],
];

function parseVector(spec: OptionSpec, args: string[]): unknown {
  try {
    const p = parseOptions(args, spec);
    return {
      values: Object.fromEntries(p.values),
      lists: Object.fromEntries(p.lists),
      booleans: [...p.booleans],
      positionals: p.positionals,
    };
  } catch (err) {
    if (err instanceof OptionsError) return { error: err.message };
    throw err;
  }
}

const TEXTS = [
  "",
  "plain",
  "tab\there",
  "line\nbreak",
  "\u0000\u0001\u001f",
  "del\u007f",
  "c1\u0080\u009f ",
  "bidi‪‫‬‭‮⁦⁧⁨⁩⁪",
  "emoji 🙂 and é",
  "lone \ud800 surrogate",
  "\u001b[31mred\u001b[0m",
  "zero width ​ joiner ‍",
];

const TIMES: unknown[] = [
  null,
  undefined,
  42,
  "",
  "2026-11-17T10:00Z",
  "2026-11-17T10:00:00Z",
  "2026-11-17T10:00:00.5Z",
  "2026-11-17T10:00:00.123456789Z",
  "2026-11-17T10:00:00+02:00",
  "2026-11-17T10:00:00-00:30",
  "2026-02-30T10:00:00Z",
  "2026-13-01T10:00:00Z",
  "2026-11-17T24:00:00Z",
  "2026-11-17T23:59:60Z",
  "0000-01-01T00:00:00Z",
  "9999-12-31T23:59:59.999Z",
  "2026-11-17 10:00:00Z",
  "2026-11-17T10:00:00",
  "2026-11-17T10:00:00.Z",
  "2026-11-17T10:00:00.1234567890Z",
  "2026-11-17T24:30:00Z",
  "2026-11-17T24:00:00.001Z",
  "2026-11-17T25:00:00Z",
  "2026-11-17T10:60:00Z",
  "2026-11-00T10:00:00Z",
  "2026-11-31T10:00:00Z",
  "2026-11-32T10:00:00Z",
  "2026-00-10T10:00:00Z",
  "2024-02-29T10:00:00Z",
  "2025-02-29T10:00:00Z",
  "2026-11-17T10:00:00+24:00",
  "2026-11-17T10:00:00+23:59",
  "2026-11-17T10:00:00+23:60",
  "2026-11-17T10:00:00-23:59",
  "0000-01-01T00:00:00+01:00",
  "9999-12-31T23:59:59-01:00",
  "2026-11-17T10:00:00.000000001Z",
  "2026-11-17T10:00:00.9999Z",
  "2026-11-17T10:00:00.0Z",
  "2026-11-17T10:00z",
  "2026-11-17t10:00Z",
  "\u00a02026-11-17T10:00Z",
  "2026-11-17T10:00Z\n",
  "２０２６-11-17T10:00Z",
];

const VERSIONS: unknown[] = [
  null,
  undefined,
  1,
  "",
  "0.22.0",
  "1.0.0-rc.1+build.5",
  "01.0.0",
  "1.0",
  "v1.0.0",
  "1.0.0-",
  `1.0.0-${"a".repeat(58)}`,
  `1.0.0-${"a".repeat(59)}`,
  "1.0.0-vlt_cli_abcdefghij",
  "1.0.0-secretvalue1",
];

const MAJORS: unknown[] = [0, 1, 999, 1000, -1, 1.5, "1", null, Number.NaN];

const REQUEST_IDS: unknown[] = [
  "req_0123abcd-0123-4567-89ab-0123456789ab",
  "req_0123ABCD-0123-4567-89ab-0123456789ab",
  "req_0123abcd-0123-4567-89ab-0123456789a",
  "0123abcd-0123-4567-89ab-0123456789ab",
  null,
  7,
];

interface MaskCase {
  known: string[];
  token?: string;
  stored: string[];
  text: string;
}

const MASKS: MaskCase[] = [
  { known: [], stored: [], text: "nothing to mask" },
  { known: ["short"], stored: [], text: "short stays" },
  { known: ["secretvalue"], stored: [], text: "a secretvalue and secretvalue" },
  { known: ["abcdefgh", "abcdefghijkl"], stored: [], text: "abcdefghijkl abcdefgh" },
  { known: [], token: "tok_environment_1", stored: [], text: "env tok_environment_1 here" },
  { known: [], stored: ["stored-token-123"], text: "stored stored-token-123" },
  { known: [], stored: [], text: "vlt_cli_AbC-123_x and vlt_svc_q vlt_x vlt__a VLT_cli_a" },
  { known: ["vlt_cli_abc"], stored: [], text: "vlt_cli_abcdef" },
  { known: ["é-secret-é"], stored: [], text: "x é-secret-é y" },
  { known: ["12345678"], stored: [], text: "\u001b12345678\n" },
];

const ASSISTED_ENVS: Record<string, string>[] = [
  {},
  { VARLATCH_ASSISTED: "1" },
  { VARLATCH_ASSISTED: "true" },
  { VARLATCH_ASSISTED: " TRUE " },
  { VARLATCH_ASSISTED: "yes" },
  { VARLATCH_ASSISTED: "0" },
  { VARLATCH_ASSISTED: "false", CLAUDECODE: "1" },
  { VARLATCH_ASSISTED: "", CLAUDECODE: "1" },
  { VARLATCH_ASSISTED: "2", CODEX_THREAD_ID: "t" },
  { CLAUDECODE: "0" },
  { CLAUDECODE: "False", AGENT: "goose" },
  { CLAUDECODE: " " },
  { CLAUDECODE: " ﻿" },
  { CLAUDECODE: " 1" },
  { AI_AGENT: "x" },
  { OPENCODE: "1", AGENT: "1" },
  { VARLATCH_ASSISTED: " true " },
  { VARLATCH_ASSISTED: "TRUEİ" },
  ...AGENT_MARKERS.map((m) => ({ [m]: "1" })),
];

const ARGVS: string[][] = [
  [],
  ["--assisted"],
  ["run", "--assisted", "--", "node", "--assisted"],
  ["--assisted", "--assisted", "status"],
  ["--", "--assisted"],
  ["--approval", "apr_1", "status"],
  ["--approval"],
  ["--approval", "-x"],
  ["--approval", "apr_1", "--approval", "apr_2"],
  ["--approval", "bad id", "--approval", "apr_2"],
  ["--approval", "a".repeat(100), "x"],
  ["--approval", "a".repeat(101), "x"],
  ["run", "--", "--approval", "x"],
  ["--approval", "apr_1", "--", "--approval", "apr_2"],
  ["--approval", "--approval", "apr_1"],
];

const API_ERRORS: { status: number; code: string }[] = [
  { status: 400, code: "INVALID_REQUEST" },
  { status: 401, code: "AUTHENTICATION_REQUIRED" },
  { status: 403, code: "PERMISSION_DENIED" },
  { status: 403, code: "CONTROL_MODE_UNAVAILABLE" },
  { status: 409, code: "APPROVAL_INVALID" },
  { status: 409, code: "STEP_UP_REQUIRED" },
  { status: 423, code: "ORGANIZATION_FROZEN" },
  { status: 403, code: "PASSKEY_VERIFICATION_REQUIRED" },
  { status: 503, code: "MAINTENANCE" },
  { status: 500, code: "MAINTENANCE" },
  { status: 502, code: "INTERNAL" },
  { status: 503, code: "INTERNAL" },
  { status: 504, code: "INTERNAL" },
  { status: 500, code: "INTERNAL" },
  { status: 404, code: "NOT_FOUND" },
  { status: 429, code: "PERMISSION_DENIED" },
  { status: 418, code: "SOMETHING_NEW" },
];

const JSON_TEXTS = [
  "null",
  "true",
  "0",
  "-0",
  "1e21",
  "1e-7",
  "123456789012345678901234567890",
  "0.1",
  "5e-324",
  "1.7976931348623157e308",
  "1e400",
  "[]",
  "{}",
  "[[],{},[{}]]",
  '{"b":1,"a":2,"2":3,"1":4,"01":5,"4294967295":6,"4294967294":7}',
  '{"a":1,"a":2,"b":3}',
  '{"nested":{"list":[1,"two",null,true,{"x":[]}]},"empty":{}}',
  '"<script>&amp;\\u2028\\u2029"',
  '"\\ud800 lone and \\udc00 and \\ud83d\\ude42"',
  '"\\u0000\\u001f\\u007f\\u0080"',
  '"tab\\tnew\\nline\\\\quote\\"slash\\/"',
  '{"version":1,"environments":[{"name":"development","tier":"development","kind":"standard","selected":true}]}',
];

/** JSON.stringify(JSON.parse(text)) and its two-space form, as the CLI prints documents. */
function jsonVector(text: string): unknown {
  const value = JSON.parse(text) as unknown;
  return { text, compact: JSON.stringify(value), indented: JSON.stringify(value, null, 2), indented4: JSON.stringify(value, null, 4) };
}

const dir = mkdtempSync(join(tmpdir(), "varlatch-go-vectors-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

function masked(c: MaskCase, i: number): string {
  const config = join(dir, `mask-${i}`);
  mkdirSync(config, { recursive: true });
  writeFileSync(join(config, "credentials.json"), JSON.stringify({ servers: Object.fromEntries(c.stored.map((t, j) => [`https://s${j}`, { token: t }])) }));
  const saved = { token: process.env.VARLATCH_TOKEN, dir: process.env.VARLATCH_CONFIG_DIR, run: process.env.VARLATCH_AGENT_RUN };
  try {
    if (c.token === undefined) delete process.env.VARLATCH_TOKEN;
    else process.env.VARLATCH_TOKEN = c.token;
    process.env.VARLATCH_CONFIG_DIR = config;
    delete process.env.VARLATCH_AGENT_RUN;
    forgetSecrets();
    for (const k of c.known) rememberSecret(k);
    return maskSecrets(c.text);
  } finally {
    forgetSecrets();
    for (const [k, v] of [["VARLATCH_TOKEN", saved.token], ["VARLATCH_CONFIG_DIR", saved.dir], ["VARLATCH_AGENT_RUN", saved.run]] as const) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

function topics(): string[] {
  const words = new Set<string>();
  for (const line of USAGE.split("\n")) {
    const m = /^ {2}varlatch (\S+)/.exec(line);
    if (m) words.add(m[1] as string);
  }
  return [...words, "nosuch", "", "values set", "Run"].sort();
}

describe("Go CLI framework vectors", () => {
  it("are what the TypeScript code answers", () => {
    const framework = {
      comment: "Written by apps/cli/test/go-vectors-framework.test.ts from the TypeScript CLI's own code; do not edit.",
      usage: USAGE,
      commandHelp: topics().map((topic) => ({ topic, help: commandHelp(topic) })),
      options: Object.entries(SPECS).flatMap(([name, spec]) => ARGS.map((args) => ({ spec: name, args, result: parseVector(spec, args) }))),
      specs: SPECS,
      printable: TEXTS.map((text) => ({ text, printable: printable(text), serverMessage: serverMessage(text) })),
      safeTime: TIMES.map((value) => ({ value: value === undefined ? "<undefined>" : value, result: safeTime(value) ?? null })),
      safeVersion: VERSIONS.map((value) => ({ value: value === undefined ? "<undefined>" : value, result: safeVersion(value) ?? null })),
      safeApiMajor: MAJORS.map((value) => ({ value: Number.isNaN(value) ? "<NaN>" : value, result: safeApiMajor(value) ?? null })),
      safeRequestId: REQUEST_IDS.map((value) => ({ value, result: safeRequestId(value) })),
      maskSecrets: MASKS.map((c, i) => ({ ...c, result: masked(c, i) })),
      assisted: ASSISTED_ENVS.flatMap((env) => [false, true].map((given) => {
        const mode = resolveAssisted(given, env);
        return { env, given, on: mode.on, source: mode.source, marker: mode.marker, described: describeAssisted(mode) };
      })),
      agentMarkers: AGENT_MARKERS,
      globalOptions: ARGVS.map((argv) => {
        const taken = takeAssistedOption(argv);
        const approval = takeApprovalOption(taken.argv);
        return { argv, assisted: taken.given, rest: approval.argv, approval: approval.approval, error: approval.error };
      }),
      userAgents: [
        ...[["linux", "x64"], ["darwin", "arm64"], ["win32", "x64"], ["win32", "arm64"], ["freebsd", "ia32"]].flatMap(([platform, arch]) =>
          [false, true].map((assisted) => ({ kind: "cli", version: "0.22.0", platform, arch, assisted, userAgent: formatUserAgent("0.22.0", assisted, platform!, arch!) })),
        ),
        { kind: "mcp", version: "0.22.0", platform: "linux", arch: "x64", assisted: false, userAgent: mcpUserAgent("0.22.0", "linux", "x64") },
        { kind: "mcp", version: "0.50.0-dev", platform: "darwin", arch: "arm64", assisted: false, userAgent: mcpUserAgent("0.50.0-dev", "darwin", "arm64") },
      ],
      exit: EXIT,
      apiErrorExit: API_ERRORS.map(({ status, code }) => ({
        status,
        code,
        exit: apiErrorExit(new VarlatchApiError(status, { code: code as never, message: "m", requestId: "r" })),
      })),
      errorCodes: ERROR_CODES,
    };
    const jsjson = {
      comment: "Written by apps/cli/test/go-vectors-framework.test.ts from Node.js's JSON.parse and JSON.stringify; do not edit.",
      cases: JSON_TEXTS.map(jsonVector),
    };
    const a = writeOrCompare(FRAMEWORK, `${JSON.stringify(framework, null, 2)}\n`);
    const b = writeOrCompare(JSJSON, `${JSON.stringify(jsjson, null, 2)}\n`);
    expect(a.current, "framework.json is stale: regenerate it (see this file's comment)").toBe(true);
    expect(b.current, "lib/jsjson's ts-vectors.json is stale: regenerate it (see this file's comment)").toBe(true);
  });
});
