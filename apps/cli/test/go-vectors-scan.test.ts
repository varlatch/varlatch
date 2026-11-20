// SPDX-License-Identifier: Apache-2.0
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import {
  BaselineError,
  DEFAULT_LIMITS,
  ScanEngine,
  baselineEntriesOf,
  formatBaseline,
  formatBytes,
  formatScanHuman,
  parseBaseline,
  parseSize,
  scanExitCode,
  scanNotices,
  type BaselineEntry,
  type ScanLimits,
  type ScanReport,
  type ScanSecret,
} from "../src/scan.js";
import { ScanUsageError, hookScript, parseScanArgs } from "../src/scanCommand.js";
import { ScanSourceError, listPaths, listStaged, scanPaths, scanStaged } from "../src/scanSources.js";
import { writeOrCompare } from "./goKit.js";

/**
 * Vectors for the Go CLI's `scan` (internal docs/design/go-cli.md, slice
 * 5.4d), recorded from scan.ts, scanSources.ts and scanCommand.ts in this
 * process:
 *
 * - engine: values and files (bytes) through ScanEngine, with the report as
 *   `--json` holds it, the human lines in both modes, the notices, the exit
 *   status and the baseline `--write-baseline` would write. The Go test
 *   also feeds every case in every chunk size up to 97 bytes.
 * - sizes, baselines, args, hooks: parseSize and formatBytes,
 *   parseBaseline and formatBaseline, parseScanArgs, hookScript.
 * - sources: trees of files and real Git repositories, each listed and
 *   scanned as `--staged` or as paths, with the report or the error. A
 *   case with `difference` is recorded as TypeScript answers it and
 *   compared through that accepted difference (go/README.md).
 *
 * Regenerate after a change to those files:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/cli exec vitest run test/go-vectors-scan.test.ts
 */

const VECTORS = fileURLToPath(new URL("../../../go/cmd/varlatch/testdata/vectors/scan.json", import.meta.url));

const API: ScanSecret = { item: "API_KEY", versionId: "ver_api", retiring: false, value: "api-key-aaaabbbbccccdddd" };
const OLD: ScanSecret = { item: "API_KEY", versionId: "ver_old", retiring: true, value: "api-key-oldoldoldoldold1" };
const DB: ScanSecret = { item: "DB_PASS", versionId: "ver_db", retiring: false, value: "hunter2-hunter2-hunter2" };
const PIN: ScanSecret = { item: "PIN", versionId: "ver_pin", retiring: false, value: "1234567" };
const BLOCK_VALUE = ["-----BEGIN TEST BLOCK-----", "FAKEDATA0FAKEDATA1FAKEDATA2", "FAKEDATA3FAKEDATA4", "-----END TEST BLOCK-----"].join("\n");
const BLOCK: ScanSecret = { item: "TLS_KEY", versionId: "ver_tls", retiring: false, value: BLOCK_VALUE };
const URL_: ScanSecret = { item: "DATABASE_URL", versionId: "ver_url", retiring: false, value: `postgres://app:${DB.value}@db/app` };
const ALL = [API, OLD, DB, PIN, BLOCK];

const b64 = (s: string | Buffer) => (typeof s === "string" ? Buffer.from(s) : s).toString("base64");

// ---- Engine ---------------------------------------------------------------------

interface EngineCase {
  id: string;
  secrets: ScanSecret[];
  /** Path and content (base64), in the order they are scanned. */
  files: Array<[string, string]>;
  limits?: ScanLimits;
  baseline?: BaselineEntry[];
  expect?: unknown;
}

const engineCases: EngineCase[] = [];
const engine = (id: string, secrets: ScanSecret[], files: Record<string, string | Buffer>, extra: Partial<EngineCase> = {}) =>
  engineCases.push({ id, secrets, files: Object.entries(files).map(([p, c]) => [p, b64(c)]), ...extra });

engine("location", [API], { "src/config.ts": `// config\nexport const key =\n  "${API.value}";\n` });
engine("column.bytes", [API], { "a.txt": `é ✓ ${API.value}` });
engine("block.multi-line", [BLOCK], { "deploy/values.yaml": `# fixtures\nkey: |\n${BLOCK_VALUE}\nnext: 1\n` });
engine("block.json", [BLOCK], { "dist/config.json": `{\n  "tls": ${JSON.stringify(BLOCK_VALUE)}\n}\n` });
engine("two-on-a-line", [API, DB], { ".env.production": `# top\nCANARY_LEFT ${API.value} CANARY_MIDDLE ${DB.value} CANARY_RIGHT\n` });
engine("forms.retiring", [API, OLD], { "log.txt": `a=${encodeURIComponent(`${API.value}/`)}\nAuthorization: Basic ${Buffer.from(`user:${OLD.value}`).toString("base64")}\n` });
engine("forms.all", [API], {
  "f.txt": [API.value, JSON.stringify(`${API.value}"`), encodeURIComponent(`${API.value} `), Buffer.from(API.value).toString("base64"), Buffer.from(API.value).toString("base64url")].join("\n"),
});
engine("inside-another", [URL_, DB], { "dist/server.js": `const u="${URL_.value}"` });
engine("retiring-same", [API, { ...API, versionId: "ver_prev", retiring: true }], { a: API.value });
engine("incomplete-prefix", [API], { "dist/app.js": `var x = "${API.value.slice(0, 20)}` });
engine("short-prefix", [API], { a: "abc api-k" });
engine("binary", [DB], { "bin/server": Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0, 0xff]), Buffer.from(DB.value), Buffer.from([0, 1, 2])]) });
engine("over-file-bound", [API], { "big.bin": "x".repeat(101), "small.txt": "fine" }, { limits: { maxFileSize: 100, maxTotalSize: 10_000 } });
engine("over-total-bound", [API], { a: "a".repeat(100), b: "b".repeat(80), c: "c".repeat(40) }, { limits: { maxFileSize: 100, maxTotalSize: 150 } });
engine("sizes.mib", [API], { a: "x" }, { limits: { maxFileSize: 1310720, maxTotalSize: 1572864 + 1 } });
engine("sizes.shown", [API], { big: "x".repeat(3) }, { limits: { maxFileSize: 2, maxTotalSize: 3 * 2 ** 30 } });
engine("short-values", [PIN, API, { ...PIN, item: "AAA_SHORT", versionId: "ver_s" }], { a: "pin=1234567" });
engine("only-short", [PIN], { a: "pin=1234567" });
engine("nothing", [], { a: "anything" });
engine("markers", [API, DB], {
  "test/fixture.ts": [
    `const a = "${API.value}"; // varlatch:allow API_KEY`,
    `const b = "${DB.value}"; // varlatch:allow API_KEY`,
    "// varlatch:allow DB_PASS",
    `const c = "${DB.value}";`,
    `const d = "${API.value}"; // varlatch:allow  API_KEYS`,
    `const e = "${API.value}"; // varlatch:allowAPI_KEY`,
    `const f = "${API.value}"; // varlatch:allow\tAPI_KEY`,
    `const g = "${API.value}"; // varlatch:allow API_KEYx`,
    `const h = "${API.value}"; // varlatch:allow${" ".repeat(17)}API_KEY`,
    `const i = "${API.value}"; // varlatch:allow${" ".repeat(16)}API_KEY`,
    `const j = "${API.value}"; // varlatch:allow api_key`,
  ].join("\n"),
});
engine("markers.long-name", [{ ...API, item: `A${"B".repeat(255)}` }, { ...DB, item: `A${"B".repeat(256)}` }], {
  a: `${API.value} varlatch:allow A${"B".repeat(255)}\n${DB.value} varlatch:allow A${"B".repeat(256)}\n`,
});
engine("markers.multi-line", [BLOCK], {
  first: `k: | # varlatch:allow TLS_KEY\n${BLOCK_VALUE}\n`,
  last: `k: "${BLOCK_VALUE}" # varlatch:allow TLS_KEY\n`,
  start: `# varlatch:allow TLS_KEY ${BLOCK_VALUE}\n`,
});
engine("markers.at-end", [API], { a: `${API.value} varlatch:allow API_KEY`, b: `${API.value} varlatch:allow`, c: `${API.value} varlatch:allow ` });
engine("baseline", [BLOCK, API], { "test/key.pem": BLOCK_VALUE, "other.pem": BLOCK_VALUE, "test/k2": API.value }, { baseline: [{ path: "test/key.pem", item: "TLS_KEY", versionId: "ver_tls" }] });
engine("baseline.other-version", [{ ...BLOCK, versionId: "ver_tls2" }], { "test/key.pem": BLOCK_VALUE }, { baseline: [{ path: "test/key.pem", item: "TLS_KEY", versionId: "ver_tls" }] });
engine("unlisted", [API], { "many.txt": `${API.value}\n`.repeat(1005), "b.txt": API.value });
engine("unlisted.two-items", [API, DB], { "many.txt": `${API.value}\n`.repeat(999) + `${DB.value}\n${API.value}\n${DB.value}\n${API.value}\n` });
engine("unlisted.baseline", [API], { "many.txt": `${API.value}\n`.repeat(1003) }, { baseline: [{ path: "many.txt", item: "API_KEY", versionId: "ver_api" }] });
engine("many-lines", [API], { "long.txt": `${"x\n".repeat(20_000)}${API.value}\n${"y\n".repeat(9000)}${API.value}` });
engine("path.controls", [API], { "a\nb\u009b.txt": API.value, "tab\tname": "clean" });
engine("item-order", [{ ...API, item: "ZED" }, { ...DB, item: "Ébc" }, { ...PIN, item: "zz" }, { ...PIN, item: "Zz", versionId: "v2" }, { ...PIN, item: "ä", versionId: "v3" }], { a: `${DB.value} ${API.value}` });
engine("empty-file", [API], { empty: "" });
engine("crlf", [API], { "w.txt": `a\r\nb ${API.value}\r\n` });

// ---- Sizes, baselines, args, hooks -----------------------------------------------

const SIZES = ["64M", "1G", "512k", "2MiB", "1000", " 7 ", "\u00a08K\u2028", "1kib", "3mb", "4gB", "", "0", "-1", "1.5M", "M", "10T", "1KB B", "9007199254740991", "9007199254740992", "8388608G", "8388607G", "00010", "１０"];
const BYTES = [0, 1, 1023, 1024, 1025, 2047, 1048575, 1048576, 1048577, 1310720, 1153434, 1205862, 1258291, 1572864, 2 ** 30, 2 ** 30 + 1, 3 * 2 ** 30, 2 ** 40, 2 ** 53 - 1];
const BASELINES: string[] = [
  "{",
  "",
  "  ",
  "\ufeff{}",
  "[]",
  "null",
  '"x"',
  JSON.stringify({ version: 2, entries: [] }),
  JSON.stringify({ version: "1", entries: [] }),
  JSON.stringify({ version: { a: 1 }, entries: [] }),
  JSON.stringify({ version: 1 }),
  JSON.stringify({ version: 1, entries: {} }),
  JSON.stringify({ version: 1, entries: [], note: "x" }),
  JSON.stringify({ version: 1, entries: [null] }),
  JSON.stringify({ version: 1, entries: [[]] }),
  JSON.stringify({ version: 1, entries: [{ path: "a", item: "B", versionId: "v", sha256: "ab12" }] }),
  JSON.stringify({ version: 1, entries: [{ path: "a", item: "B" }] }),
  JSON.stringify({ version: 1, entries: [{ path: "", item: "B", versionId: "v" }] }),
  JSON.stringify({ version: 1, entries: [{ path: "a", item: "B", versionId: 3 }] }),
  JSON.stringify({ version: 1.0, entries: [{ path: "a", item: "B", versionId: "v" }, { versionId: "w", item: "C", path: "b/é" }] }),
  '{"version":1,"entries":[],"version":1}',
  '{"entries":[{"path":"a","item":"B","versionId":"v","path":"c"}],"version":1}',
  '{"version":1,"entries":[{"path":"\\ud800","item":"B","versionId":"v"}]}',
  JSON.stringify({ version: 1, entries: [] }) + "\n",
];
const FORMAT_BASELINES: BaselineEntry[][] = [
  [],
  [
    { path: "b", item: "Z", versionId: "v2" },
    { path: "a", item: "Z", versionId: "v1" },
    { path: "b", item: "A", versionId: "v9" },
    { path: "a", item: "Z", versionId: "v1" },
    { path: "a", item: "Z", versionId: "v0" },
  ],
  [
    { path: "\u{1F600}", item: "X", versionId: "v" },
    { path: "\uFF61", item: "X", versionId: "v" },
    { path: "é", item: "X", versionId: "v" },
    { path: "e", item: "X", versionId: "v" },
  ],
];
const ARGS: string[][] = [
  [],
  ["--staged"],
  ["a", "b"],
  ["--staged", "a"],
  ["--bogus", "a"],
  ["-x"],
  ["a", "--max-file-size", "lots"],
  ["a", "--max-file-size"],
  ["a", "--max-file-size", "-1"],
  ["a", "--max-total-size", "2G", "--max-file-size", "1k"],
  ["-e", "staging", "--staged", "--json"],
  ["--environment", "prod", "--server", "https://x", "a"],
  ["--baseline", "b.json", "--write-baseline", "a"],
  ["--baseline", "", "a"],
  ["-", "--", "--staged", "-e"],
  ["--install-hook"],
  ["--install-hook", "-e", "staging"],
  ["--install-hook", "a"],
  ["--install-hook", "--json"],
  ["--install-hook", "--baseline", ""],
  ["--install-hook", "--baseline", "x"],
  ["--install-hook", "--server", "https://x"],
  ["--install-hook", "--max-file-size", "1M"],
  ["--find-files"],
  ["--find-files", "dir", "--json"],
  ["--find-files", "a", "b"],
  ["--find-files", "--staged", "-e", "x", "-e", "y"],
  ["--staged", "--find-files"],
  ["-e"],
  ["--staged", "-e", "-x"],
  ["--staged", "--staged", "--json", "--json"],
  ["--STAGED"],
  ["--staged=1"],
];
const HOOKS: Array<[string, string | undefined]> = [
  ["", undefined],
  [".", undefined],
  ["services/api", undefined],
  ["it's here", "staging"],
  ["", ""],
  ["a b", "prod'uction"],
];

// ---- Sources ---------------------------------------------------------------------

interface Tree {
  files?: Record<string, string>;
  /** Files whose name is not UTF-8: the path's bytes in base64, with the content. */
  rawFiles?: Array<[string, string]>;
  links?: Record<string, string>;
  /** Directories made Git repositories (git init -q -b main) first. */
  repos?: string[];
  /** In order, after the rest: git commands (in a repository, from the case directory), writes and removals. */
  steps?: Array<{ git: [string, ...string[]] } | { write: Record<string, string> } | { remove: string[] }>;
  /** Modes set last. */
  modes?: Record<string, number>;
}

interface SourceCase {
  id: string;
  tree: Tree;
  /** "staged", or the path arguments. */
  scan: "staged" | string[];
  /** The working directory and the project root, from the case directory. */
  cwd: string;
  project: string;
  limits?: ScanLimits;
  notRoot?: boolean;
  rawNames?: boolean;
  /** An accepted difference this case is compared through (go/README.md). */
  difference?: string;
  /** The staged listing, for a case with a difference: each file's path and size, and how many paths the listing did not admit. */
  listing?: { files: Array<{ path: string; size: number }>; notScanned: number };
  expect?: { error: string } | { report: unknown };
}

const sourceCases: SourceCase[] = [];
const source = (id: string, tree: Tree, scan: SourceCase["scan"], extra: Partial<SourceCase> = {}) =>
  sourceCases.push({ id, tree, scan, cwd: ".", project: ".", ...extra });
const g = (...args: [string, ...string[]]) => ({ git: args });
const SECRETS = [API, OLD, DB, PIN];

source("staged.index-not-tree", {
  repos: ["."],
  files: { "README.md": "hello\n" },
  steps: [
    g("add", "README.md"),
    g("commit", "-q", "-m", "init", "--no-verify"),
    { write: { "config.env": `CANARY API_KEY=${API.value}\n` } },
    g("add", "config.env"),
    { write: { "config.env": "API_KEY=\n", "notes.txt": `one\nold ${OLD.value}\n` } },
    g("add", "notes.txt"),
    { remove: ["notes.txt"] },
    { write: { "untracked.txt": DB.value, "README.md": `hello\n${DB.value}\n` } },
  ],
}, "staged");
source("staged.before-first-commit", { repos: ["."], files: { "a.txt": `${DB.value}\n` }, steps: [g("add", "a.txt")] }, "staged");
source("staged.nothing", { repos: ["."] }, "staged");
source("staged.deleted", {
  repos: ["."],
  files: { "a.txt": `${DB.value}\n`, "b.txt": "x\n" },
  steps: [g("add", "."), g("commit", "-q", "-m", "init", "--no-verify"), g("rm", "-q", "a.txt"), { write: { "b.txt": `y ${API.value}\n` } }, g("add", "b.txt")],
}, "staged");
source("staged.submodule", {
  repos: ["."],
  files: { "a.txt": "x\n" },
  steps: [g("add", "a.txt"), g("update-index", "--add", "--cacheinfo", "160000,1111111111111111111111111111111111111111,sub")],
}, "staged");
source("staged.unmerged", {
  repos: ["."],
  files: { "c.txt": "base\n" },
  steps: [
    g("add", "c.txt"),
    g("commit", "-q", "-m", "base", "--no-verify"),
    g("checkout", "-q", "-b", "other"),
    { write: { "c.txt": "other\n" } },
    g("commit", "-q", "-am", "other", "--no-verify"),
    g("checkout", "-q", "main"),
    { write: { "c.txt": `main ${API.value}\n` } },
    g("commit", "-q", "-am", "main", "--no-verify"),
    g("merge", "-q", "other"),
  ],
}, "staged");
source("staged.link", { repos: ["."], links: { "link": API.value }, steps: [g("add", "link")] }, "staged");
source("staged.project-below", { repos: ["."], files: { "leak.txt": `x ${DB.value}\n`, "services/api/ok.txt": "fine\n" }, steps: [g("add", ".")] }, "staged", { cwd: "services/api", project: "services/api" });
source("staged.over-file-bound", { repos: ["."], files: { "big.bin": "\u0001".repeat(2048), "ok.txt": "clean\n" }, steps: [g("add", ".")] }, "staged", { limits: { maxFileSize: 1024, maxTotalSize: 2 ** 30 } });
source("staged.empty-file", { repos: ["."], files: { "empty": "", "a.txt": API.value }, steps: [g("add", ".")] }, "staged");
source("staged.names", { repos: ["."], files: { "café/a.txt": API.value, "sp ace.txt": DB.value }, steps: [g("add", ".")] }, "staged");
source("staged.raw-name", { repos: ["."], rawFiles: [[b64(Buffer.from([0x62, 0xff, 0x2e, 0x74])), DB.value]], steps: [g("add", ".")] }, "staged", { rawNames: true });
source("staged.total-bound", { repos: ["."], files: { "a.txt": `${DB.value}${"a".repeat(80)}`, "b.txt": `${"b".repeat(80)}${API.value}`, "c.txt": "c".repeat(30) }, steps: [g("add", ".")] }, "staged", {
  limits: { maxFileSize: 1000, maxTotalSize: 150 },
  difference: "scan-staged-total",
});
source("staged.not-a-repository", { files: { "a.txt": "x" } }, "staged");

source("paths.walk", {
  files: {
    "dist/app.js": `var k="${Buffer.from(`user:${API.value}`).toString("base64")}";\n`,
    "dist/assets/blob.bin": `\u0000\u0000${DB.value}\u0000`,
    "dist/clean.txt": "nothing here\n",
    "dist/b/z.txt": "z",
    "dist/B.txt": "B",
    "dist/a.txt": "a",
  },
  links: { "dist/link": "/etc/hostname", "dist/dangling": "nowhere" },
}, ["dist", "missing-dir"]);
source("paths.unreadable", { files: { "out/locked.txt": DB.value, "out/closed/x.txt": DB.value, "out/ok.txt": "ok" }, modes: { "out/locked.txt": 0, "out/closed": 0 } }, ["out"], { notRoot: true });
source("paths.argument-link", { files: { "real/a.txt": API.value }, links: { "via": "real" } }, ["via"]);
source("paths.twice", { files: { "a.txt": API.value, "d/b.txt": DB.value } }, ["a.txt", "d", "./a.txt", "d/b.txt", "."]);
source("paths.outside", { files: { "history": `ls\nexport DB_PASS=${DB.value}\n`, "proj/varlatch.toml": "" } }, ["../history"], { cwd: "proj", project: "proj" });
source("paths.cwd-below", { files: { "proj/sub/a.txt": API.value, "proj/varlatch.toml": "" } }, ["a.txt", "."], { cwd: "proj/sub", project: "proj" });
source("paths.raw-name", { rawFiles: [[b64(Buffer.from("d/é-ok.txt")), API.value], [b64(Buffer.from([0x64, 0x2f, 0x78, 0xff])), DB.value]] }, ["d"], { rawNames: true });
source("paths.over-bounds", { files: { "a": "a".repeat(100), "b": "b".repeat(80), "c": `${"c".repeat(20)}${API.value}`, "d": "d".repeat(200) } }, ["."], { limits: { maxFileSize: 150, maxTotalSize: 150 } });
source("paths.empty-dir", { files: { "e/.keep": "" } }, ["e"]);
source("paths.dot", { files: { "x.txt": API.value } }, ["."]);
source("paths.empty-argument", { files: { "x.txt": API.value } }, [""]);
source("paths.not-a-directory-below", { files: { "f.txt": "x" } }, ["f.txt/inner"]);

// ---- Recording -------------------------------------------------------------------

const scratch = realpathSync(mkdtempSync(join(tmpdir(), "varlatch-go-vectors-scan-")));
afterAll(() => {
  spawnSync("chmod", ["-R", "u+rwx", scratch]);
  rmSync(scratch, { recursive: true, force: true });
});

const GIT_ENV = {
  ...process.env,
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "Test",
  GIT_AUTHOR_EMAIL: "test@example.com",
  GIT_COMMITTER_NAME: "Test",
  GIT_COMMITTER_EMAIL: "test@example.com",
};

function git(cwd: string, args: string[]): void {
  const r = spawnSync("git", args, { cwd, env: GIT_ENV, encoding: "utf8" });
  // A merge with a conflict exits 1, which the case means.
  if (r.status !== 0 && args[0] !== "merge") throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
}

function writeFiles(dir: string, files: Record<string, string>): void {
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), content);
  }
}

function build(dir: string, tree: Tree): void {
  for (const r of tree.repos ?? []) {
    mkdirSync(join(dir, r), { recursive: true });
    git(join(dir, r), ["init", "-q", "-b", "main"]);
  }
  writeFiles(dir, tree.files ?? {});
  for (const [raw, content] of tree.rawFiles ?? []) {
    const bytes = Buffer.from(raw, "base64");
    const slash = bytes.lastIndexOf(0x2f);
    if (slash >= 0) mkdirSync(Buffer.concat([Buffer.from(`${dir}/`), bytes.subarray(0, slash)]), { recursive: true });
    writeFileSync(Buffer.concat([Buffer.from(`${dir}/`), bytes]), content);
  }
  for (const [path, target] of Object.entries(tree.links ?? {})) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    symlinkSync(target, join(dir, path));
  }
  for (const step of tree.steps ?? []) {
    if ("git" in step) git(dir, step.git);
    else if ("write" in step) writeFiles(dir, step.write);
    else for (const p of step.remove) rmSync(join(dir, p), { recursive: true });
  }
  for (const [path, mode] of Object.entries(tree.modes ?? {})) chmodSync(join(dir, path), mode);
}

/** The report as `--json` holds it (without the CLI's own fields). */
const plain = (report: ScanReport): unknown => JSON.parse(JSON.stringify(report));

function scanEngineCase(c: EngineCase): ScanReport {
  const e = new ScanEngine(c.secrets, { limits: c.limits ?? DEFAULT_LIMITS, baseline: c.baseline });
  for (const [path, content] of c.files) {
    const data = Buffer.from(content, "base64");
    if (!e.admit(path, data.length)) continue;
    const file = e.begin(path);
    if (file.push(data)) file.end();
    else file.fail("grew past the per-file bound while being read");
  }
  return e.result();
}

/**
 * Git's environment while a case is listed and scanned: no configuration
 * of the machine that records, and no repository above the case's
 * directory (so git's own message for none is the same on every machine).
 * The Go test sets the same.
 */
const LISTING_ENV = { GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", GIT_CEILING_DIRECTORIES: "" };

async function recordSource(c: SourceCase, dir: string): Promise<{ expect: NonNullable<SourceCase["expect"]>; listing?: SourceCase["listing"] }> {
  const saved = Object.fromEntries(Object.keys(LISTING_ENV).map((k) => [k, process.env[k]]));
  Object.assign(process.env, LISTING_ENV, { GIT_CEILING_DIRECTORIES: dirname(dir) });
  try {
    return await recordIn(c, dir);
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

async function recordIn(c: SourceCase, dir: string): Promise<{ expect: NonNullable<SourceCase["expect"]>; listing?: SourceCase["listing"] }> {
  const unfill = (s: string) => s.split(dir).join("{{dir}}");
  const cwd = join(dir, c.cwd);
  const project = join(dir, c.project);
  const engine = new ScanEngine(SECRETS, { limits: c.limits ?? DEFAULT_LIMITS });
  try {
    let listing: SourceCase["listing"];
    if (c.scan === "staged") {
      const staged = await listStaged(cwd, project);
      listing = { files: staged.files.map((f) => ({ path: f.path, size: f.size })), notScanned: staged.notScanned.length };
      for (const n of staged.notScanned) engine.notScanned(n.path, n.reason);
      await scanStaged(engine, staged);
    } else {
      const paths = await listPaths(c.scan, cwd, project);
      for (const n of paths.notScanned) engine.notScanned(n.path, n.reason);
      await scanPaths(engine, paths);
    }
    return { expect: { report: JSON.parse(unfill(JSON.stringify(plain(engine.result())))) }, listing: c.difference ? listing : undefined };
  } catch (err) {
    if (err instanceof ScanSourceError) return { expect: { error: unfill(err.message) } };
    throw err;
  }
}

describe("Go CLI scan vectors", () => {
  it("are recorded from scan.ts, scanSources.ts and scanCommand.ts as they are", async () => {
    const ids = new Set<string>();
    const unique = (id: string) => {
      if (ids.has(id)) throw new Error(`case ${id} twice`);
      ids.add(id);
    };
    const engines = engineCases.map((c) => {
      unique(c.id);
      const report = scanEngineCase(c);
      return {
        ...c,
        expect: {
          report: plain(report),
          exitCode: scanExitCode(report),
          notices: scanNotices(report),
          human: {
            paths: formatScanHuman(report, { environment: "production", mode: "paths" }),
            staged: formatScanHuman(report, { environment: "production", mode: "staged" }),
          },
          baseline: formatBaseline(baselineEntriesOf(report)),
        },
      };
    });
    const sources: SourceCase[] = [];
    for (const c of sourceCases) {
      unique(c.id);
      if (c.notRoot && process.getuid?.() === 0) throw new Error("record the vectors as a user the modes hold for");
      const dir = realpathSync(mkdtempSync(join(scratch, "c-")));
      build(dir, c.tree);
      const { expect: recorded, listing } = await recordSource(c, dir);
      sources.push({ ...c, ...(listing ? { listing } : {}), expect: recorded });
    }
    const baselines = BASELINES.map((text) => {
      try {
        return { text: b64(text), entries: parseBaseline(text) };
      } catch (err) {
        if (!(err instanceof BaselineError)) throw err;
        // A JSON syntax error is compared by its start: what follows is V8's wording.
        const syntax = err.message.startsWith("not valid JSON (");
        return { text: b64(text), error: syntax ? "not valid JSON (" : err.message, syntax };
      }
    });
    const args = ARGS.map((a) => {
      try {
        const o = parseScanArgs(a);
        return { args: a, options: { ...o, baseline: o.baseline ?? null, environment: o.environment ?? null } };
      } catch (err) {
        if (!(err instanceof ScanUsageError)) throw err;
        return { args: a, error: err.message };
      }
    });
    const doc = {
      schema: 1,
      comment: "Recorded from apps/cli/src/scan.ts, scanSources.ts and scanCommand.ts by apps/cli/test/go-vectors-scan.test.ts; do not edit. Regenerate with VARLATCH_WRITE_GO_VECTORS=1.",
      defaultLimits: DEFAULT_LIMITS,
      secrets: SECRETS,
      engine: engines,
      sources,
      sizes: SIZES.map((text) => ({ text, size: parseSize(text) })),
      bytes: BYTES.map((n) => ({ n, text: formatBytes(n) })),
      baselines,
      formatBaselines: FORMAT_BASELINES.map((entries) => ({ entries, text: formatBaseline(entries) })),
      args,
      hooks: HOOKS.map(([projectDir, environment]) => ({ projectDir, environment: environment ?? null, script: hookScript(projectDir, environment) })),
    };
    // One case per line.
    const members = Object.entries(doc).map(([k, v]) =>
      Array.isArray(v) && v.length > 0 && typeof v[0] === "object" ? `${JSON.stringify(k)}: [\n${v.map((x) => JSON.stringify(x)).join(",\n")}\n]` : `${JSON.stringify(k)}: ${JSON.stringify(v)}`,
    );
    const text = `{\n${members.join(",\n")}\n}\n`;
    const result = writeOrCompare(VECTORS, text);
    expect(result.current, "scan.json is stale: regenerate it (see this file's comment)").toBe(true);
    // Each answer occurs.
    const all = JSON.stringify(doc);
    for (const marker of ['"allowedBy":"marker"', '"allowedBy":"baseline"', '"count":', "over the total size bound", "larger than the per-file bound", "unmerged", "a submodule", "symbolic link", "does not exist", "unreadable (EACCES)", "needs a Git working tree", '"exitCode":2', '"incompletePrefixes":1']) {
      expect(all, marker).toContain(marker);
    }
  }, 300_000);
});
