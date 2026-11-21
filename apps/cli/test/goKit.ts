// SPDX-License-Identifier: Apache-2.0
import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import net, { type AddressInfo } from "node:net";
import { constants as osConstants, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sealedBoxOpen } from "@varlatch/sync";
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
 *
 * A case can also act while the CLI runs: answer the browser sign-in's
 * loopback callback the way the sign-in page does (callback), and send
 * Ctrl-C once standard error says something (signal).
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
   * written as `{{generated <spec>}}` (generatedPattern);
   * "now+<s>": one between the start and the end plus <s> seconds, written
   * as {{now+<s>}}; "callback": the browser sign-in's loopback port in its
   * printed address, written as {{port}}; "release": the CLI's own
   * release, `varlatch <version>` in the output (the Generator lines and
   * literals of a module `varlatch types` writes), written as
   * `varlatch {{release}}`, and `{{release}}` in the case's files, given
   * as that version (releasePattern); "agent-run": an agent-safe run's
   * identifier, Placeholders and Broker port (agentRunPattern).
   */
  patterns?: string[];
  /**
   * The browser sign-in's callback: once standard output holds the printed
   * address (a line with `callback=`), POST `body` to the callback it names,
   * as the sign-in page does, and `times` times in all (1 by default), each
   * on a connection of its own; what each got is recorded.
   */
  callback?: { body: string; times?: number };
  /** Ctrl-C: SIGINT once standard error holds `after`. */
  signal?: { after: string };
  /**
   * Runs the CLI on a pseudo-terminal (util-linux script(1)): its
   * controlling terminal and stdin, and its stdout, its stderr or both; the
   * other stream is captured as usual, and what the terminal displayed is
   * `expect.terminal`, its "\r\n" as "\n". The Go replay opens the
   * terminal itself (transcript.onTerminal), and skips the case where it
   * has none.
   */
  terminal?: "stdout" | "stderr" | "both";
  /**
   * The fake platforms' script (platformServer): the requests the Platform
   * Adapters send to api.github.com, coolify.conformance.test and
   * convex.conformance.test, in order, and their answers. A case that
   * reaches a platform gives one, so every request it sends is recorded.
   */
  platform?: Exchange[];
}

/** A request the fake platforms received: its host, and a sealed GitHub value opened (openSealed). */
export interface PlatformRequest {
  method: string;
  host: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
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
    /** What each callback POST got: its status, or "refused" when nothing took the connection. */
    callbacks?: string[];
    /** What a terminal case's terminal displayed (TranscriptCase.terminal). */
    terminal?: string;
    requests: RecordedRequest[];
    /** Every request the fake platforms received, when the case gives them a script. */
    platformRequests?: PlatformRequest[];
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
export const RECORDED_HEADERS = ["authorization", "user-agent", "content-type", "accept", "idempotency-key", "varlatch-approval"];

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

/** The fake server's host and port: `{{server-host}}`, as an agent-safe run's proxy address names it. */
const hostOf = (server: string): string => server.replace(/^http:\/\//, "");
const fill = (text: string, server: string, dir: string): string =>
  text.split("{{server}}").join(server).split("{{server-host}}").join(hostOf(server)).split("{{dir}}").join(dir);
const unfill = (text: string, server: string, dir: string): string =>
  unfillDir(text.split(server).join("{{server}}").split(hostOf(server)).join("{{server-host}}"), dir);

/**
 * The case directory as {{dir}}, both as it is printed and as a JSON string
 * holds it (each backslash doubled: on Windows `C:\\Users\\...` in a --json
 * document or a JSON file the CLI wrote is the directory too). On Linux and
 * macOS a directory holds no backslash, so the two forms are the same. The Go
 * replay's transcript.UnfillDir is the same.
 */
export function unfillDir(text: string, dir: string): string {
  const escaped = dir.split("\\").join("\\\\");
  const out = escaped === dir ? text : text.split(escaped).join("{{dir}}");
  return out.split(dir).join("{{dir}}");
}

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

/**
 * The shortest value a run's masking replaces wherever it occurs (the
 * matcher's MIN_LENGTH, and the stored Secrets' minimum).
 */
const MASKABLE_LENGTH = 8;

/**
 * The texts a case gives the CLI that it may treat as values: `values` are
 * its variables, its stdin and its arguments (a value in flight, such as
 * `values set PORT 8080`'s, is masked whatever its length); `maskable` are
 * its variables and stdin of MASKABLE_LENGTH bytes or more, which masking
 * replaces wherever they occur. A PORT=8080 case once ran in a directory
 * whose random name held 8080, and masking the value rewrote the path. The
 * Go replay's transcript.CaseValues is the same.
 */
export function caseValues(c: TranscriptCase): { values: string[]; maskable: string[] } {
  const usable = (v: string) => v.length >= 2 && !v.includes("{{");
  const own = [...Object.values(c.env ?? {}), c.stdin ?? ""].filter(usable);
  return {
    values: [...own, ...c.args.filter(usable)],
    maskable: own.filter((v) => Buffer.byteLength(v) >= MASKABLE_LENGTH),
  };
}

/**
 * A new directory for one case, varlatch-transcript- and sixteen random
 * consonants (no digit, no word), as its real path (macOS's temporary
 * directory is behind a symbolic link). Only the random name is the
 * harness's: one that any of the case's values overlaps is discarded and
 * another drawn. The rest of the path is the system's
 * (C:\Users\runneradmin\AppData\Local\Temp on a Windows runner holds "run"
 * and "admin"): it fails only when it holds a maskable value, which would
 * rewrite it on every run. The Go replay's transcript.CaseDir is the same.
 */
export function caseDir({ values, maskable }: { values: string[]; maskable: string[] }): string {
  const letters = "bcdfghjklmnpqrstvwxz";
  for (let attempt = 0; attempt < 100; attempt++) {
    const name = Array.from(randomBytes(16), (b) => letters[b % letters.length]).join("");
    const dir = join(tmpdir(), `varlatch-transcript-${name}`);
    try {
      mkdirSync(dir, { mode: 0o700 });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "EEXIST") continue;
      throw err;
    }
    // The native realpath: on Windows it gives the long name of each part
    // (C:\Users\runneradmin, not RUNNER~1), as the CLI prints it and Go's
    // filepath.EvalSymlinks gives it.
    const real = realpathSync.native(dir);
    if (maskable.some((v) => real.includes(v))) {
      rmSync(dir, { recursive: true, force: true });
      throw new Error(`the temporary directory ${tmpdir()} holds one of the case's variables or its stdin`);
    }
    // An occurrence that takes in any of the name's characters.
    if (!values.some((v) => real.slice(Math.max(0, real.length - name.length - v.length + 1)).includes(v))) return real;
    rmSync(dir, { recursive: true, force: true });
  }
  throw new Error(`no name in ${tmpdir()} that none of the case's values overlaps`);
}

/** The "now+<s>" pattern: each timestamp from `start` to `end` plus `seconds`, as {{now+<s>}}. */
export function laterPattern(text: string, start: number, end: number, seconds: number): string {
  return text.replace(ISO_TIMESTAMP, (t) => {
    const at = Date.parse(t) - seconds * 1000;
    return at >= start && at <= end ? `{{now+${seconds}}}` : t;
  });
}

/** The loopback callback's port in a printed sign-in address. */
const CALLBACK_PORT = /(callback=http%3A%2F%2F127\.0\.0\.1%3A)\d+(%2F)/g;

/** The "callback" pattern: the loopback port as {{port}}. */
export function callbackPattern(text: string): string {
  return text.replace(CALLBACK_PORT, "$1{{port}}$2");
}

/**
 * The "agent-run" pattern: what an agent-safe run makes at random, each as
 * a name: the run's identifier as run_{{id}}, a Placeholder as
 * {{placeholder}}, and the Broker's loopback port as 127.0.0.1:{{port}}
 * (the fake server's own address is {{server}} or {{server-host}} by then).
 */
export function agentRunPattern(text: string): string {
  return text
    .replace(/run_[0-9a-f]{16}(?![0-9a-f])/g, "run_{{id}}")
    .replace(/vlch_ph_v1_[0-9a-f]{32}/g, "{{placeholder}}")
    .replace(/127\.0\.0\.1:\d+/g, "127.0.0.1:{{port}}");
}

/** The patterns a case names, applied in order to a recorded text. */
export function applyPatterns(patterns: readonly string[], text: string, start: number, end: number): string {
  let out = text;
  for (const name of patterns) {
    const later = /^now\+(\d+)$/.exec(name);
    if (name === "now") out = nowPattern(out, start, end);
    else if (later) out = laterPattern(out, start, end, Number(later[1]));
    else if (name === "callback") out = callbackPattern(out);
    else if (name === "agent-run") out = agentRunPattern(out);
    else if (name === "release") out = releasePattern(EMBEDDED_RELEASE.version).unfill(out);
    else if (name !== "generated") throw new Error(`no pattern ${name}`); // generated applies to request bodies (generatedPattern)
  }
  return out;
}

/** POSTs `body` to `url` on a connection of its own: the status, or "refused". */
function postOnce(url: string, body: string): Promise<string> {
  return new Promise((resolve) => {
    const req = http.request(url, { method: "POST", agent: false, headers: { "Content-Type": "application/json", Connection: "close" } }, (res) => {
      res.resume();
      res.on("end", () => resolve(String(res.statusCode)));
    });
    req.on("error", () => resolve("refused"));
    req.end(body);
  });
}

/**
 * The fake platforms (5.8b): the host names the Platform Adapters address,
 * served by one HTTPS server with a certificate for them, which the CLI
 * trusts through NODE_EXTRA_CA_CERTS. The TypeScript CLI reaches it through
 * an HTTPS proxy (NODE_USE_ENV_PROXY=1 and HTTPS_PROXY: Node.js's fetch then
 * sends CONNECT host:443, which the kit's proxy tunnels to the fake); the
 * Go CLI's replay routes the same names to it (VARLATCH_TEST_PLATFORM).
 * Neither reaches a real platform.
 */
export const PLATFORM_HOSTS = ["api.github.com", "coolify.conformance.test", "convex.conformance.test"];

/** The fake GitHub repository's key pair: X25519, the secret key the bytes 1 to 32 (go/cmd/varlatch/internal/transcript has the same). */
const PLATFORM_SECRET_KEY = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
export const PLATFORM_PUBLIC_KEY = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=";
/**
 * What a case's platform answer says in place of the public key: both fake
 * platforms serve PLATFORM_PUBLIC_KEY there, so a recording holds this
 * word, never a high-entropy value a secret scan would read as a key.
 */
export const PLATFORM_PUBLIC_KEY_WORD = "{{platform-public-key}}";

/** The request headers a platform recording keeps: the credential shows which variable was read. Not the User-Agent: Coolify and Convex get fetch's default, which is the runtime's, not the adapter's. */
const PLATFORM_HEADERS = ["authorization", "content-type", "accept", "x-github-api-version"];

/**
 * A sealed GitHub value is random each time it is sealed: a recording keeps
 * what it holds, `{{sealed <value>}}`, opened with the fake's key (or
 * `{{sealed, not opened}}`), never the box.
 */
function openSealed(body: unknown): unknown {
  if (body === null || typeof body !== "object" || Array.isArray(body)) return body;
  const sealed = (body as Record<string, unknown>).encrypted_value;
  if (typeof sealed !== "string") return body;
  const opened = sealedBoxOpen(Buffer.from(sealed, "base64"), Buffer.from(PLATFORM_PUBLIC_KEY, "base64"), PLATFORM_SECRET_KEY);
  return { ...body, encrypted_value: opened ? `{{sealed ${Buffer.from(opened).toString("utf8")}}}` : "{{sealed, not opened}}" };
}

let platformCert: { dir: string; cert: string; key: string } | null = null;

/** The fake platforms' certificate, made once per run (openssl), for every PLATFORM_HOSTS name. */
function platformCertificate(): { cert: string; key: string; file: string } {
  if (!platformCert) {
    const dir = mkdtempSync(join(tmpdir(), "varlatch-platform-"));
    const san = PLATFORM_HOSTS.map((h) => `DNS:${h}`).join(",");
    execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
      "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem"), "-subj", "/CN=varlatch-transcript-platforms", "-addext", `subjectAltName=${san}`], { stdio: "ignore" });
    platformCert = { dir, cert: readFileSync(join(dir, "cert.pem"), "utf8"), key: readFileSync(join(dir, "key.pem"), "utf8") };
    process.on("exit", () => rmSync(dir, { recursive: true, force: true }));
  }
  return { cert: platformCert.cert, key: platformCert.key, file: join(platformCert.dir, "cert.pem") };
}

/** The fake platforms for one case: the HTTPS server answering its script, and the proxy the TypeScript CLI reaches it through. */
async function platformServer(script: Exchange[]): Promise<{ env: Record<string, string>; requests: PlatformRequest[]; close: () => Promise<void> }> {
  const certificate = platformCertificate();
  const queue = [...script];
  const requests: PlatformRequest[] = [];
  const fake = https.createServer({ cert: certificate.cert, key: certificate.key }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (d: Buffer) => chunks.push(d));
    req.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      const headers: Record<string, string> = {};
      for (const name of PLATFORM_HEADERS) {
        const v = req.headers[name];
        if (typeof v === "string") headers[name] = v;
      }
      let body: unknown = text === "" ? null : text;
      try {
        if (text !== "") body = JSON.parse(text);
      } catch {
        // kept as text
      }
      requests.push({ method: req.method ?? "", host: req.headers.host ?? "", path: req.url ?? "", headers, body: openSealed(body) });
      const next = queue.shift();
      if (!next || next.method !== req.method || next.path !== req.url) {
        res.writeHead(599, { "content-type": "text/plain" });
        res.end("unexpected request");
        return;
      }
      res.writeHead(next.status, next.headers ?? { "content-type": "application/json" });
      res.end(
        next.answer === undefined
          ? ""
          : typeof next.answer === "string"
            ? next.answer
            : JSON.stringify(next.answer).split(JSON.stringify(PLATFORM_PUBLIC_KEY_WORD)).join(JSON.stringify(PLATFORM_PUBLIC_KEY)),
      );
    });
  });
  await new Promise<void>((resolve) => fake.listen(0, "127.0.0.1", resolve));
  const port = (fake.address() as AddressInfo).port;
  const proxy = http.createServer((_req, res) => {
    res.writeHead(403);
    res.end();
  });
  proxy.on("connect", (req: http.IncomingMessage, socket: net.Socket, head: Buffer) => {
    const [host, hostPort] = (req.url ?? "").split(":");
    if (!PLATFORM_HOSTS.includes(host ?? "") || hostPort !== "443") {
      socket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
      return;
    }
    const upstream = net.connect(port, "127.0.0.1", () => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
    });
    upstream.on("error", () => socket.destroy());
    socket.on("error", () => upstream.destroy());
  });
  await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
  const proxyPort = (proxy.address() as AddressInfo).port;
  return {
    env: { NODE_USE_ENV_PROXY: "1", HTTPS_PROXY: `http://127.0.0.1:${proxyPort}`, NODE_EXTRA_CA_CERTS: certificate.file },
    requests,
    close: async () => {
      proxy.closeAllConnections?.();
      fake.closeAllConnections?.();
      await new Promise<void>((resolve) => proxy.close(() => resolve()));
      await new Promise<void>((resolve) => fake.close(() => resolve()));
    },
  };
}

/** Runs one case against the bundle and records it. */
export async function recordCase(bundle: string, c: TranscriptCase): Promise<RecordedCase> {
  if (process.platform !== "win32") process.umask(TRANSCRIPT_UMASK);
  const dir = caseDir(caseValues(c));
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
  const platforms = c.platform ? await platformServer(c.platform) : null;
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
    // On Windows the home directory is USERPROFILE (os.homedir()), as the
    // Go replay sets it.
    if (process.platform === "win32") env.USERPROFILE = join(dir, "home");
    for (const name of c.unset ?? []) delete env[name];
    for (const [k, v] of Object.entries(c.env ?? {})) env[k] = fill(v, origin, dir);
    // Not part of the case's environment: how this recorder reaches its fake platforms.
    Object.assign(env, platforms?.env ?? {});
    const start = Date.now();
    const callbacks: string[] = [];
    const argv = [bundle, ...c.args.map((a) => fill(a, origin, dir))];
    const result = c.terminal ? await onTerminal(c, argv, cwd, env) : await new Promise<{ status: number; stdout: string; stderr: string; terminal?: string }>((resolve, reject) => {
      const child = spawn(process.execPath, argv, { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      let called = false;
      let signalled = false;
      child.stdout.on("data", (d: Buffer) => {
        stdout += d.toString("utf8");
        const address = /callback=([^\s]+)\n/.exec(stdout);
        if (c.callback && address && !called) {
          called = true;
          const url = decodeURIComponent(address[1] as string);
          void (async () => {
            for (let i = 0; i < (c.callback?.times ?? 1); i++) callbacks.push(await postOnce(url, c.callback?.body ?? ""));
          })();
        }
      });
      child.stderr.on("data", (d: Buffer) => {
        stderr += d.toString("utf8");
        if (c.signal && !signalled && stderr.includes(c.signal.after)) {
          signalled = true;
          child.kill("SIGINT");
        }
      });
      child.on("error", reject);
      // A process ended by a signal it did not handle reports 128 + the signal's number, as a shell does.
      child.on("close", (code, signal) => resolve({ status: code ?? (signal === "SIGINT" ? 130 : signal ? 128 : 1), stdout, stderr }));
      child.stdin.end(c.stdin ?? "");
    });
    // The callbacks' answers, before the result is read.
    for (let i = 0; c.callback && callbacks.length < (c.callback.times ?? 1) && i < 100; i++) await new Promise((r) => setTimeout(r, 50));
    const end = Date.now();
    const now = (t: string) => applyPatterns(c.patterns ?? [], t, start, end);
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
        ...(c.callback ? { callbacks } : {}),
        ...(platforms ? { platformRequests: JSON.parse(now(JSON.stringify(unfillDeep(platforms.requests, origin, dir)))) as PlatformRequest[] } : {}),
        ...(result.terminal === undefined ? {} : { terminal: now(unfill(result.terminal, origin, dir)) }),
      },
    };
  } finally {
    await platforms?.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Runs a terminal case (TranscriptCase.terminal): `node <argv>` under
 * util-linux script(1), which gives it a new pseudo-terminal, with the
 * stream that is not the terminal redirected to a file outside the case
 * directory. Asynchronous: the case's server answers in this process.
 */
function onTerminal(c: TranscriptCase, argv: string[], cwd: string, env: Record<string, string>): Promise<{ status: number; stdout: string; stderr: string; terminal: string }> {
  if (c.signal || c.callback || c.stdin) throw new Error(`case ${c.id}: a terminal case has no signal, callback or stdin`);
  const quote = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
  const streams = mkdtempSync(join(tmpdir(), "varlatch-terminal-"));
  const outFile = join(streams, "stdout");
  const errFile = join(streams, "stderr");
  const redirect = { both: "", stdout: `2>${quote(errFile)}`, stderr: `>${quote(outFile)}` }[c.terminal ?? "both"];
  const line = `exec ${[process.execPath, ...argv].map(quote).join(" ")} ${redirect}`;
  return new Promise((resolve, reject) => {
    const child = spawn("script", ["-qec", line, "/dev/null"], { cwd, env: { ...env, SHELL: "/bin/sh" }, stdio: ["pipe", "pipe", "pipe"] });
    let shown = "";
    child.stdout.on("data", (d: Buffer) => (shown += d.toString("utf8")));
    child.on("error", reject);
    child.on("close", (code, signal) => {
      const read = (f: string) => (existsSync(f) ? readFileSync(f, "utf8") : "");
      // script(1) ended by a signal: 128 plus its number, as a shell reports it (the replay's exitStatus).
      const status = code ?? (signal ? 128 + (osConstants.signals[signal] ?? 0) : 1);
      const out = { status, stdout: read(outFile), stderr: read(errFile), terminal: shown.replace(/\r\n/g, "\n") };
      rmSync(streams, { recursive: true, force: true });
      resolve(out);
    });
    child.stdin.end();
  });
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
