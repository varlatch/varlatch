// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { EMBEDDED_RELEASE } from "@varlatch/backup";

/**
 * The CLI kit's recorder (internal docs/design/go-cli.md, decision 3): runs
 * the TypeScript CLI, bundled from this checkout's apps/cli exactly as users
 * get it, through a table of cases, and records what each did, so the Go CLI
 * can replay the same cases and must give the same bytes
 * (go/cmd/varlatch/internal/transcript).
 *
 * A case gives the arguments, the environment (added to a clean one: PATH,
 * HOME and VARLATCH_CONFIG_DIR inside the case's own directory, and
 * VARLATCH_NODE_CHECK=off, less any the case unsets; nothing
 * from this process, so a coding agent's markers never leak in), a file
 * tree, standard input, and the fake server's script: each request it
 * expects, in order, and its answer. It records standard output, standard
 * error, the exit status, every request the server received, and the case
 * directory's whole final tree (listTree): every file, directory and
 * symbolic link with its mode, the inputs included, so a deleted input or a
 * changed mode shows.
 *
 * `{{server}}` in a case stands for the fake server's origin and `{{dir}}`
 * for the case's directory, in every string the case gives and in what is
 * recorded, so a recording does not depend on the port or the path.
 */

/** 2: the whole final tree, inputs and directories included. */
export const TRANSCRIPT_SCHEMA = 2;

/** Where the Go side reads the recordings. */
export const TRANSCRIPT_DIR = fileURLToPath(new URL("../../../go/cmd/varlatch/testdata/transcripts/", import.meta.url));

export interface Exchange {
  /** The request expected next: its method and path with query. */
  method: string;
  path: string;
  /** The answer. */
  status: number;
  headers?: Record<string, string>;
  answer?: unknown;
}

export interface TranscriptCase {
  id: string;
  /** What the case shows, for the reader of the recording. */
  title: string;
  args: string[];
  env?: Record<string, string>;
  /** Variables removed from the clean environment (VARLATCH_CONFIG_DIR, to reach the default directory). */
  unset?: string[];
  stdin?: string;
  /** Files to create before the run, by path relative to the case directory. */
  files?: Record<string, string>;
  /** The working directory, relative to the case directory; created if missing. */
  cwd?: string;
  server?: Exchange[];
  /**
   * Accepted differences (go/README.md, "The Go CLI's accepted
   * differences") the Go replay applies to this case's recording.
   */
  differences?: string[];
  /**
   * Named patterns for values that depend on when the case ran, matched in
   * the recording and the replay alike (never ignored wholesale). "now": an
   * ISO 8601 timestamp with milliseconds (Date.prototype.toISOString's
   * form) between the start and the end of the run, written as {{now}};
   * "generated": the value `--generate` made, in each request body,
   * written as `{{generated <spec>}}` (generatedPattern); "release": the
   * CLI's own release, `varlatch <version>` in the output (the Generator
   * lines and literals of a module `varlatch types` writes), written as
   * `varlatch {{release}}`, and `{{release}}` in the case's files, given
   * as that version (releasePattern).
   */
  patterns?: string[];
}

export interface RecordedRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
}

export interface RecordedCase extends TranscriptCase {
  expect: {
    status: number;
    stdout: string;
    stderr: string;
    requests: RecordedRequest[];
    /**
     * The case directory's final tree (listTree): a file's content (UTF-8)
     * and POSIX mode, a directory (path ending in "/", no content), a
     * symbolic link (mode "link", content its target).
     */
    files: Record<string, { mode: string; content: string }>;
  };
}

export interface TranscriptFile {
  schema: number;
  comment: string;
  area: string;
  cases: RecordedCase[];
}

/** The request headers a recording keeps (internal docs/design/go-cli.md, decision 2). */
export const RECORDED_HEADERS = ["authorization", "user-agent", "content-type", "accept", "idempotency-key"];

/** Bundles apps/cli/src/main.ts as the release build does, into `dir`. */
export async function bundleCli(dir: string): Promise<string> {
  const outfile = join(dir, "varlatch.cjs");
  await build({
    entryPoints: [fileURLToPath(new URL("../src/main.ts", import.meta.url))],
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node22",
    outfile,
    logLevel: "silent",
  });
  return outfile;
}

const fill = (text: string, server: string, dir: string): string => text.split("{{server}}").join(server).split("{{dir}}").join(dir);
const unfill = (text: string, server: string, dir: string): string => text.split(server).join("{{server}}").split(dir).join("{{dir}}");

function fillDeep(value: unknown, server: string, dir: string): unknown {
  if (typeof value === "string") return fill(value, server, dir);
  if (Array.isArray(value)) return value.map((v) => fillDeep(v, server, dir));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, fillDeep(v, server, dir)]));
  return value;
}

function unfillDeep(value: unknown, server: string, dir: string): unknown {
  if (typeof value === "string") return unfill(value, server, dir);
  if (Array.isArray(value)) return value.map((v) => unfillDeep(v, server, dir));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, unfillDeep(v, server, dir)]));
  return value;
}

/**
 * Everything under `root` (root itself excepted): each file with its
 * content, each directory under its path plus "/", each symbolic link with
 * its target (never followed), with permission bits as four octal digits.
 * The Go replay's transcript.Tree lists the same.
 */
export function listTree(root: string, unfillText: (t: string) => string, at = ""): Record<string, { mode: string; content: string }> {
  const out: Record<string, { mode: string; content: string }> = {};
  for (const name of readdirSync(join(root, at)).sort()) {
    const rel = at ? `${at}/${name}` : name;
    const path = join(root, rel);
    const stat = lstatSync(path);
    const mode = (stat.mode & 0o777).toString(8).padStart(4, "0");
    if (stat.isSymbolicLink()) out[rel] = { mode: "link", content: unfillText(readlinkSync(path)) };
    else if (stat.isDirectory()) {
      out[`${rel}/`] = { mode, content: "" };
      Object.assign(out, listTree(root, unfillText, rel));
    } else out[rel] = { mode, content: unfillText(readFileSync(path, "utf8")) };
  }
  return out;
}

/**
 * The umask every case runs under, here and in the Go replay (its TestMain
 * sets the same), so the modes a recording holds do not depend on the
 * machine that made it.
 */
export const TRANSCRIPT_UMASK = 0o022;

/**
 * An error the TypeScript CLI lets escape: Node.js prints the source line,
 * the stack (with the bundle's path) and its own version, which no
 * recording can hold steadily. The recording keeps its name and message:
 * `{{uncaught TypeError: ...}}`. The Go CLI says what went wrong in one line
 * instead (the "uncaught" accepted difference).
 */
const UNCAUGHT = /\n\nNode\.js v[0-9.]+\n$/;

function uncaught(stderr: string): string {
  const error = /^([A-Za-z]*Error)(?: \[[A-Z_]+\])?: (.*)$/m.exec(stderr);
  return error ? `{{uncaught ${error[1]}: ${error[2]}}}\n` : "{{uncaught}}\n";
}

/** Date.prototype.toISOString's form, as `login` and `env use` write the time. */
const ISO_TIMESTAMP = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z/g;

/**
 * The "release" pattern: `varlatch <version>` (the CLI's own release) as
 * `varlatch {{release}}` in what the CLI did, and `{{release}}` in a
 * case's files as the version. Another release a case names stays as it is.
 */
export function releasePattern(version: string): { fill: (text: string) => string; unfill: (text: string) => string } {
  return {
    fill: (text) => text.split("{{release}}").join(version),
    unfill: (text) => text.split(`varlatch ${version}`).join("varlatch {{release}}"),
  };
}

/** The "now" pattern: each timestamp from `start` to `end` (milliseconds) as {{now}}. */
export function nowPattern(text: string, start: number, end: number): string {
  return text.replace(ISO_TIMESTAMP, (t) => {
    const at = Date.parse(t);
    return at >= start && at <= end ? "{{now}}" : t;
  });
}

/**
 * The "generated" pattern: a value `--generate` made is random, so each
 * request body's `value` is recorded by its generator, `{{generated
 * <spec>}}` (the spec the case's arguments give), when it has exactly the
 * alphabet and length the spec gives and appears nowhere in the output;
 * otherwise as a value-free note of what is wrong with it, so neither the
 * recording nor a failing comparison ever holds the value. The Go replay
 * applies the same (transcript.GeneratedPattern).
 */
export function generatedPattern(args: string[], requests: RecordedRequest[], output: string): RecordedRequest[] {
  const spec = args[args.indexOf("--generate") + 1] ?? "";
  return requests.map((r) => {
    const body = r.body as Record<string, unknown> | null;
    if (body === null || typeof body !== "object" || typeof body.value !== "string") return r;
    const value = body.value;
    const note = !generatedBy(spec, value)
      ? "{{generated value of another shape}}"
      : output.includes(value)
        ? "{{generated value shown in the output}}"
        : `{{generated ${spec}}}`;
    return { ...r, body: { ...body, value: note } };
  });
}

/** Whether value has the alphabet and length the generator spec gives. */
function generatedBy(spec: string, value: string): boolean {
  const m = /^(hex|base64|base64url|alnum):([0-9]+)$/.exec(spec);
  if (!m) return false;
  const n = Number(m[2]);
  const shape =
    m[1] === "hex"
      ? `^[0-9a-f]{${2 * n}}$`
      : m[1] === "base64"
        ? `^[A-Za-z0-9+/]{${Math.floor((4 * n + 2) / 3)}}={${(3 - (n % 3)) % 3}}$`
        : m[1] === "base64url"
          ? `^[A-Za-z0-9_-]{${Math.floor((4 * n + 2) / 3)}}$`
          : `^[A-Za-z0-9]{${n}}$`;
  return new RegExp(shape).test(value);
}

/** Runs one case against the bundle and records it. */
export async function recordCase(bundle: string, c: TranscriptCase): Promise<RecordedCase> {
  if (process.platform !== "win32") process.umask(TRANSCRIPT_UMASK);
  // The real path, as process.cwd() reports it (macOS's temporary directory is behind a symbolic link).
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "varlatch-transcript-")));
  const script = [...(c.server ?? [])];
  const requests: RecordedRequest[] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (d: Buffer) => chunks.push(d));
    req.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      const headers: Record<string, string> = {};
      for (const name of RECORDED_HEADERS) {
        const v = req.headers[name];
        if (typeof v === "string") headers[name] = v;
      }
      let body: unknown = text === "" ? null : text;
      try {
        if (text !== "") body = JSON.parse(text);
      } catch {
        // kept as text
      }
      requests.push({ method: req.method ?? "", path: req.url ?? "", headers, body });
      const next = script.shift();
      if (!next || next.method !== req.method || fill(next.path, origin, dir) !== req.url) {
        res.writeHead(599, { "content-type": "text/plain" });
        res.end("unexpected request");
        return;
      }
      res.writeHead(next.status, next.headers ?? { "content-type": "application/json" });
      res.end(next.answer === undefined ? "" : typeof next.answer === "string" ? next.answer : JSON.stringify(fillDeep(next.answer, origin, dir)));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const release = c.patterns?.includes("release") ? releasePattern(EMBEDDED_RELEASE.version) : { fill: (t: string) => t, unfill: (t: string) => t };
    for (const [path, content] of Object.entries(c.files ?? {})) {
      mkdirSync(dirname(join(dir, path)), { recursive: true });
      writeFileSync(join(dir, path), release.fill(fill(content, origin, dir)));
    }
    const cwd = join(dir, c.cwd ?? ".");
    mkdirSync(cwd, { recursive: true });
    mkdirSync(join(dir, "home"), { recursive: true });
    const env: Record<string, string> = {
      PATH: process.env.PATH ?? "",
      HOME: join(dir, "home"),
      VARLATCH_CONFIG_DIR: join(dir, "config"),
      // The Node.js version warning (nodeRuntime.ts) depends on the Node.js
      // that records, and the Go CLI has none: never part of a recording.
      VARLATCH_NODE_CHECK: "off",
    };
    for (const name of c.unset ?? []) delete env[name];
    for (const [k, v] of Object.entries(c.env ?? {})) env[k] = fill(v, origin, dir);
    const start = Date.now();
    const result = await new Promise<{ status: number; stdout: string; stderr: string }>((resolve, reject) => {
      const child = spawn(process.execPath, [bundle, ...c.args.map((a) => fill(a, origin, dir))], { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (d: Buffer) => (stdout += d.toString("utf8")));
      child.stderr.on("data", (d: Buffer) => (stderr += d.toString("utf8")));
      child.on("error", reject);
      child.on("close", (code, signal) => resolve({ status: code ?? (signal ? 128 : 1), stdout, stderr }));
      child.stdin.end(c.stdin ?? "");
    });
    const end = Date.now();
    const timed = c.patterns?.includes("now") ? (t: string) => nowPattern(t, start, end) : (t: string) => t;
    const now = (t: string) => release.unfill(timed(t));
    for (const name of c.patterns ?? []) if (!["now", "generated", "release"].includes(name)) throw new Error(`case ${c.id}: no pattern ${name}`);
    const generated = (r: RecordedRequest[]) => (c.patterns?.includes("generated") ? generatedPattern(c.args, r, result.stdout + result.stderr) : r);
    const files = listTree(dir, (t) => now(unfill(t, origin, dir)));
    return {
      ...c,
      expect: {
        status: result.status,
        stdout: now(unfill(result.stdout, origin, dir)),
        stderr: now(unfill(result.status === 1 && UNCAUGHT.test(result.stderr) ? uncaught(result.stderr) : result.stderr, origin, dir)),
        requests: generated(JSON.parse(now(JSON.stringify(unfillDeep(requests, origin, dir)))) as RecordedRequest[]),
        files,
      },
    };
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Records every case of an area and returns the file's text. Each case's id
 * must be unique in the area.
 */
export async function recordArea(bundle: string, area: string, cases: TranscriptCase[]): Promise<string> {
  const ids = new Set<string>();
  const recorded: RecordedCase[] = [];
  for (const c of cases) {
    if (ids.has(c.id)) throw new Error(`${area}: case ${c.id} twice`);
    ids.add(c.id);
    recorded.push(await recordCase(bundle, c));
  }
  const file: TranscriptFile = {
    schema: TRANSCRIPT_SCHEMA,
    comment: "Recorded from the TypeScript CLI by apps/cli/test/go-transcripts.test.ts; do not edit. Regenerate with VARLATCH_WRITE_GO_VECTORS=1.",
    area,
    cases: recorded,
  };
  return `${JSON.stringify(file, null, 2)}\n`;
}

/** Writes `text` to `path` when writing vectors; otherwise returns whether the file holds exactly it. */
export function writeOrCompare(path: string, text: string): { written: boolean; current: boolean } {
  if (process.env.VARLATCH_WRITE_GO_VECTORS === "1") {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, text);
    chmodSync(path, 0o644);
    return { written: true, current: true };
  }
  return { written: false, current: existsSync(path) && readFileSync(path, "utf8") === text };
}
