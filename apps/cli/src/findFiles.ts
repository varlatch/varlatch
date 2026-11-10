// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import type { Dir, Dirent } from "node:fs";
import { lstat, open, opendir, readlink, realpath } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { ENV_TEMPLATES } from "./agents/hook.js";
import { displayPath } from "./scan.js";

/**
 * `varlatch scan --find-files [<dir>]` (ADR-0054 Decision 8): list the files
 * under a directory that look like copies of secrets by their name, say
 * whether Git ignores each one, and point to `varlatch import`.
 *
 * Discovery uses file names and metadata (directory entries, lstat),
 * without reading candidate contents, and never follows a symbolic link. It
 * needs no project, no server, and no credential, and discloses nothing.
 *
 * Git is asked as little as possible. Git ignore checks read configuration
 * and ignore rules; unsupported setups report unknown (see "Asking Git").
 * Concurrent changes to those inputs can cause Git to read a candidate file;
 * preventing such races is outside this command's guarantee. File contents
 * and raw Git diagnostics are never displayed.
 *
 * Names are bytes: a name that is not UTF-8 keeps its identity through the
 * walk and Git, and is shown escaped.
 */

export const FIND_FILES_REPORT_VERSION = 1;

/** Directories never entered: version control and dependencies, as the agents hook skips them. */
const SKIP_DIRS: ReadonlySet<string> = new Set([".git", ".hg", ".svn", "node_modules"]);

export interface FindLimits {
  /** Directory entries read before the walk stops. */
  maxEntries: number;
  /** Directory levels below the starting directory that are entered. */
  maxDepth: number;
}

export const FIND_LIMITS: FindLimits = { maxEntries: 200_000, maxDepth: 20 };

/** How long one Git command may take before its answer is given up. */
const GIT_TIMEOUT_MS = 30_000;

/** What a name looks like: a dotenv file, or a key or certificate file. */
export type CopyKind = "dotenv" | "key";

/**
 * The ADR's patterns, matched case-sensitively as Git does on Linux:
 * `.env`, `.env.*` except the templates `.env.example` and `.env.schema`,
 * `*.pem`, and `*.key`. A name that is not UTF-8 is matched as bytes (pass
 * it decoded as latin1).
 */
export function copyKindOf(name: string): CopyKind | null {
  if (name === ".env" || (name.startsWith(".env.") && !ENV_TEMPLATES.has(name))) return "dotenv";
  if (name.endsWith(".pem") || name.endsWith(".key")) return "key";
  return null;
}

export type GitState = "not-ignored" | "ignored" | "no-repository" | "unknown";

export interface FoundFile {
  /** Relative to the starting directory, `/`-separated, as bytes. */
  path: Buffer;
  kind: CopyKind;
  /** A symbolic link is listed by its own name; its target is never looked at. */
  symlink: boolean;
  git: GitState;
  /** Why the Git state is unknown. */
  gitError?: string;
}

export interface FindFilesReport {
  root: Buffer;
  files: FoundFile[];
  /** Directories not searched, `/`-terminated, relative to the root. */
  notSearched: { path: Buffer; reason: string }[];
  entriesChecked: number;
  /** The walk stopped at maxEntries: what follows was not looked at. */
  stopped: boolean;
}

export class FindFilesError extends Error {
  override name = "FindFilesError";
}

// ---- Bytes -------------------------------------------------------------------

const SEP = Buffer.from(sep);
const SLASH = Buffer.from("/");
const DOT_GIT = Buffer.from(".git");
const utf8 = new TextDecoder("utf-8", { fatal: true });

function utf8OrNull(bytes: Uint8Array): string | null {
  try {
    return utf8.decode(bytes);
  } catch {
    return null;
  }
}

/** `dir` + separator + `name`, for absolute paths. */
function child(dir: Buffer, name: Buffer): Buffer {
  return dir.length > 0 && dir[dir.length - 1] === SEP[0] ? Buffer.concat([dir, name]) : Buffer.concat([dir, SEP, name]);
}

/** Whether `abs` lies below the directory `dir`. */
function isBelow(abs: Buffer, dir: Buffer): boolean {
  const base = dir.length > 0 && dir[dir.length - 1] === SEP[0] ? dir.subarray(0, -1) : dir;
  return abs.length > base.length + 1 && abs[base.length] === SEP[0] && abs.subarray(0, base.length).equals(base);
}

function parentOf(abs: Buffer): Buffer | null {
  const at = abs.lastIndexOf(SEP[0]!);
  if (at < 0 || abs.length <= 1) return null;
  return at === 0 ? SEP : abs.subarray(0, at);
}

function baseName(abs: Buffer): string {
  return abs.subarray(abs.lastIndexOf(SEP[0]!) + 1).toString("latin1");
}

/**
 * Bytes as shown on a terminal. UTF-8 without controls is shown as is;
 * anything else is shown quoted, with controls escaped (`\n`, `\u009b`) and
 * each byte that is not UTF-8 as `\xfe`.
 */
export function displayBytes(bytes: Uint8Array): string {
  const text = utf8OrNull(bytes);
  if (text !== null) return displayPath(text);
  let out = "";
  for (let i = 0; i < bytes.length; ) {
    const b = bytes[i]!;
    const len = b < 0x80 ? 1 : b >= 0xc2 && b <= 0xdf ? 2 : b >= 0xe0 && b <= 0xef ? 3 : b >= 0xf0 && b <= 0xf4 ? 4 : 0;
    const ch = len > 0 && i + len <= bytes.length ? utf8OrNull(bytes.subarray(i, i + len)) : null;
    if (ch === null) {
      out += `\\x${b.toString(16).padStart(2, "0")}`;
      i++;
    } else {
      out += escapeChar(ch);
      i += len;
    }
  }
  return `"${out}"`;
}

/** One character inside a quoted display: quotes, backslashes, and controls escaped. */
function escapeChar(ch: string): string {
  if (ch === '"' || ch === "\\") return `\\${ch}`;
  const shown = displayPath(ch);
  return shown === ch ? ch : shown.slice(1, -1);
}

/** A path in JSON: `<key>` as UTF-8 (lossy when it is not), and `<key>Base64` with the exact bytes when it is not. */
function jsonPath(bytes: Buffer, key: string): Record<string, string> {
  return utf8OrNull(bytes) !== null ? { [key]: bytes.toString("utf8") } : { [key]: bytes.toString("utf8"), [`${key}Base64`]: bytes.toString("base64") };
}

function reasonOf(err: unknown): string {
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  if (code === "ENOENT") return "does not exist";
  return `unreadable (${code ?? (err instanceof Error ? err.message : String(err))})`;
}

// ---- The walk ----------------------------------------------------------------

interface Found extends FoundFile {
  abs: Buffer;
}

interface Walk {
  root: Buffer;
  files: Found[];
  notSearched: { path: Buffer; reason: string }[];
  /** Directories that hold a `.git` entry: each may be the top of its own repository. */
  repoDirs: Buffer[];
  entriesChecked: number;
  stopped: boolean;
}

/**
 * Walk `dir` (resolved from `cwd`) by name, without following links or
 * opening files. Entries are read incrementally and counted as they are
 * read, so the entry bound also bounds memory; each directory's entries
 * are sorted (within the bound) for a stable order.
 */
export async function walkForCopies(dir: string, cwd: string, limits: FindLimits = FIND_LIMITS): Promise<Walk> {
  let root: Buffer;
  try {
    // Resolve the directory given (it may itself be a link); nothing below it is followed.
    root = (await realpath(Buffer.from(resolve(cwd, dir)), { encoding: "buffer" })) as Buffer;
  } catch (err) {
    throw new FindFilesError(`cannot search ${displayPath(dir)}: ${reasonOf(err)}`);
  }
  if (!(await lstat(root)).isDirectory()) throw new FindFilesError(`--find-files takes a directory; ${displayPath(dir)} is not one`);

  const walk: Walk = { root, files: [], notSearched: [], repoDirs: [root], entriesChecked: 0, stopped: false };
  const visit = async (abs: Buffer, rel: Buffer | null, depth: number): Promise<void> => {
    const shown = rel === null ? Buffer.from("./") : Buffer.concat([rel, SLASH]);
    const entries: Dirent<Buffer>[] = [];
    let handle: Dir;
    try {
      handle = await opendir(abs, { encoding: "buffer" as BufferEncoding, bufferSize: 256 });
    } catch (err) {
      walk.notSearched.push({ path: shown, reason: `directory ${reasonOf(err)}` });
      return;
    }
    try {
      for await (const entry of handle as unknown as AsyncIterable<Dirent<Buffer>>) {
        if (walk.entriesChecked >= limits.maxEntries) {
          walk.stopped = true;
          break; // closes the directory
        }
        walk.entriesChecked++;
        entries.push(entry);
      }
    } catch (err) {
      walk.notSearched.push({ path: shown, reason: `directory ${reasonOf(err)} while being read` });
    }
    entries.sort((a, b) => Buffer.compare(a.name, b.name));
    if (rel !== null && entries.some((e) => e.name.equals(DOT_GIT))) walk.repoDirs.push(abs);
    for (const entry of entries) {
      const path = rel === null ? entry.name : Buffer.concat([rel, SLASH, entry.name]);
      const name = entry.name.toString("latin1");
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(name) || walk.stopped) continue;
        if (depth >= limits.maxDepth) {
          walk.notSearched.push({ path: Buffer.concat([path, SLASH]), reason: `below the depth bound of ${limits.maxDepth} directory levels` });
          continue;
        }
        await visit(child(abs, entry.name), path, depth + 1);
        continue;
      }
      // Only regular files and links to anything; a link is never followed.
      const symlink = entry.isSymbolicLink();
      if (!symlink && !entry.isFile()) continue;
      const kind = copyKindOf(name);
      if (kind) walk.files.push({ abs: child(abs, entry.name), path, kind, symlink, git: "unknown" });
    }
  };
  await visit(root, null, 0);
  return walk;
}

// ---- Asking Git --------------------------------------------------------------
//
// Git is used as little as possible: one `git check-ignore --no-index` per
// repository, which reads no index and no objects. Before it runs, the
// repository is found and looked at here, by name, and anything unusual
// makes the state "unknown" instead: Git could otherwise be made to open a
// file that is a secret copy. Checked with a FIFO in place of each file of
// a repository: this command opens the gitfile, `commondir`, `config`,
// `config.worktree`, `info/exclude`, `objects/info/alternates`, the
// excludes file, and the `.gitignore` files (never through a link).

/** Git gets none of the caller's GIT_* variables, no system and no global configuration. */
function gitEnv(extra: Record<string, string>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) if (!k.startsWith("GIT_")) env[k] = v;
  return { ...env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", ...extra };
}

interface GitResult {
  code: number;
  stdout: Buffer;
}

/** Why Git gave no answer, in fixed words: Git's own diagnostics could quote a file, so they are never shown. */
class GitFailure extends Error {
  override name = "GitFailure";
}

/**
 * Run git with a timeout: a Git that waits on something is given up, never
 * waited for. Its stderr is discarded, never shown.
 */
function runGit(cwd: string, args: string[], env: NodeJS.ProcessEnv, input?: Buffer): Promise<GitResult> {
  return new Promise((resolvePromise, reject) => {
    const proc = spawn("git", ["-c", "core.fsmonitor=false", ...args], {
      cwd,
      env,
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "ignore"],
    });
    const out: Buffer[] = [];
    const timer = setTimeout(() => {
      proc.kill("SIGKILL");
      reject(new GitFailure(`Git timed out (${GIT_TIMEOUT_MS / 1000} s)`));
    }, GIT_TIMEOUT_MS);
    proc.stdin?.on("error", () => {});
    proc.stdout!.on("data", (d: Buffer) => out.push(d));
    proc.on("error", () => {
      clearTimeout(timer);
      reject(new GitFailure("Git could not be started"));
    });
    proc.on("close", (code) => {
      clearTimeout(timer);
      resolvePromise({ code: code ?? 1, stdout: Buffer.concat(out) });
    });
    proc.stdin?.end(input);
  });
}

/** "missing", "ok" for a regular file with no other name (not a link, not hard-linked), or why it is unusual. */
async function plainFile(path: Buffer): Promise<"missing" | "ok" | string> {
  let st;
  try {
    st = await lstat(path);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return code === "ENOENT" || code === "ENOTDIR" ? "missing" : `${displayBytes(path)}: ${reasonOf(err)}`;
  }
  if (st.isSymbolicLink()) return `${displayBytes(path)} is a symbolic link`;
  if (!st.isFile()) return `${displayBytes(path)} is not a regular file`;
  if (st.nlink > 1) return `${displayBytes(path)} has another name (a hard link)`;
  return "ok";
}

/**
 * Whether Git may read the file a configuration names: "missing", "ok", or
 * why not. Each name on the way, through symbolic links, must not look like
 * a secret copy, and the file must be a regular file with no other name.
 */
async function namedFile(path: Buffer): Promise<"missing" | "ok" | string> {
  let current = path;
  for (let hops = 0; hops < 40; hops++) {
    if (copyKindOf(baseName(current))) return `${displayBytes(current)} has the name of a secret copy`;
    const verdict = await plainFile(current);
    if (!verdict.endsWith(" is a symbolic link")) return verdict;
    const target = (await readlink(current, { encoding: "buffer" })) as Buffer;
    current = target[0] === SEP[0] ? target : child(parentOf(current) ?? SEP, target);
  }
  return `${displayBytes(path)}: too many symbolic links`;
}

async function isDir(path: Buffer): Promise<boolean> {
  try {
    return (await lstat(path)).isDirectory();
  } catch {
    return false;
  }
}

/** A path stored in a small file Git keeps (`.git` file, `commondir`): a directory, or why it is unusual. */
async function pointer(file: Buffer, prefix: string, base: Buffer): Promise<Buffer | string> {
  const verdict = await plainFile(file);
  if (verdict !== "ok") return verdict === "missing" ? `${displayBytes(file)} is missing` : verdict;
  const handle = await open(file, "r");
  let raw: Buffer;
  try {
    const buf = Buffer.alloc(4097);
    const { bytesRead } = await handle.read(buf, 0, buf.length, 0);
    raw = buf.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
  const text = raw.length <= 4096 ? utf8OrNull(raw) : null;
  const m = text === null ? null : new RegExp(`^${prefix}([^\\n\\r]+)\\r?\\n?$`).exec(text);
  if (!m) return `${displayBytes(file)} is not what Git writes there`;
  const target = m[1]!.startsWith("/") ? Buffer.from(m[1]!) : child(base, Buffer.from(m[1]!));
  if (!(await isDir(target))) return `${displayBytes(file)} does not point to a directory`;
  return target;
}

interface Repository {
  /** The top of the working tree: the directory that holds `.git`. */
  top: Buffer;
  gitDir: Buffer;
  commonDir: Buffer;
}

/**
 * The repository Git would find from `start`, found the way Git looks for
 * it, without running Git. Null outside any repository; a string when
 * anything about it is unusual (a linked `.git`, a bare repository, a
 * pointer that is not a plain file pointing to a directory).
 */
async function findRepository(start: Buffer): Promise<Repository | null | string> {
  for (let dir: Buffer | null = start; dir !== null; dir = parentOf(dir)) {
    const dotGit = child(dir, DOT_GIT);
    let st;
    try {
      st = await lstat(dotGit);
    } catch {
      st = null;
    }
    if (st === null) {
      if ((await isDir(child(dir, Buffer.from("objects")))) && (await isDir(child(dir, Buffer.from("refs"))))) {
        return `${displayBytes(dir)} looks like a bare repository`;
      }
      continue;
    }
    let gitDir: Buffer;
    if (st.isDirectory()) gitDir = dotGit;
    else if (st.isFile()) {
      const target = await pointer(dotGit, "gitdir: ", dir);
      if (typeof target === "string") return target;
      gitDir = target;
    } else return `${displayBytes(dotGit)} is ${st.isSymbolicLink() ? "a symbolic link" : "not a directory or a file"}`;
    let commonDir = gitDir;
    const commondir = child(gitDir, Buffer.from("commondir"));
    if ((await plainFile(commondir)) !== "missing") {
      const target = await pointer(commondir, "", gitDir);
      if (typeof target === "string") return target;
      commonDir = target;
    }
    return { top: dir, gitDir, commonDir };
  }
  return null;
}

interface ConfigFacts {
  /** Why the file is unusual, if it is. */
  unusual: string | null;
  includes: boolean;
  /** The last core.excludesFile, as written. */
  excludesFile: string | null;
}

const NO_REPOSITORY = join(tmpdir(), "varlatch-find-files-no-repository");

/**
 * What a configuration file says, read by `git config --file <f>
 * --no-includes` with no repository and no other configuration, so that
 * only that file is opened. Keys and values are compared as bytes.
 */
async function readConfig(file: Buffer): Promise<ConfigFacts> {
  const facts: ConfigFacts = { unusual: null, includes: false, excludesFile: null };
  const name = utf8OrNull(file);
  if (name === null) return { ...facts, unusual: `${displayBytes(file)} is not a UTF-8 path` };
  const r = await runGit(tmpdir(), ["config", "--file", name, "--no-includes", "--list", "-z"], gitEnv({ GIT_DIR: NO_REPOSITORY }));
  if (r.code !== 0) return { ...facts, unusual: `Git could not read ${displayBytes(file)} (exit status ${r.code})` };
  for (const entry of nulList(r.stdout)) {
    const nl = entry.indexOf(10);
    const key = (nl < 0 ? entry : entry.subarray(0, nl)).toString("latin1").toLowerCase();
    const value = nl < 0 ? Buffer.alloc(0) : entry.subarray(nl + 1);
    if (key === "include.path" || (key.startsWith("includeif.") && key.endsWith(".path"))) facts.includes = true;
    else if (key === "core.worktree") facts.unusual ??= `${displayBytes(file)} sets core.worktree`;
    else if (key === "core.excludesfile") {
      const text = utf8OrNull(value);
      if (text === null) facts.unusual ??= `${displayBytes(file)} sets a core.excludesFile that is not UTF-8`;
      else facts.excludesFile = text;
    }
  }
  return facts;
}

interface GlobalConfig {
  unusual: string | null;
  excludesFile: string | null;
}

/**
 * The global configuration, read here (Git itself never gets it): only
 * core.excludesFile is used. Git reads the XDG file first and
 * `~/.gitconfig` second, so a value in `~/.gitconfig` wins. An include
 * could set the excludes file, and includes are not read, so any include
 * makes every state unknown.
 */
async function readGlobalConfig(): Promise<GlobalConfig> {
  const home = process.env.HOME || homedir();
  const xdg = process.env.XDG_CONFIG_HOME || join(home, ".config");
  const files =
    process.env.GIT_CONFIG_GLOBAL !== undefined ? [process.env.GIT_CONFIG_GLOBAL] : [join(xdg, "git", "config"), join(home, ".gitconfig")];
  const global: GlobalConfig = { unusual: null, excludesFile: null };
  for (const file of files) {
    if (file === "/dev/null") continue;
    const path = Buffer.from(file);
    const verdict = await namedFile(path);
    if (verdict === "missing") continue;
    if (verdict !== "ok") return { ...global, unusual: verdict };
    const facts = await readConfig(path);
    if (facts.unusual) return { ...global, unusual: facts.unusual };
    if (facts.includes) return { ...global, unusual: `${displayBytes(path)} includes other files, which are not read` };
    global.excludesFile = facts.excludesFile ?? global.excludesFile;
  }
  return global;
}

/** The excludes file Git would read, checked; or why it is unusual. */
async function excludesFileOf(value: string | null): Promise<{ path: string } | string> {
  const home = process.env.HOME || homedir();
  let path: string;
  if (value === null) path = join(process.env.XDG_CONFIG_HOME || join(home, ".config"), "git", "ignore");
  else if (value.startsWith("~/")) path = join(home, value.slice(2));
  else if (value.startsWith("/")) path = value;
  else return `core.excludesFile ${displayPath(value)} is not an absolute path`;
  const verdict = await namedFile(Buffer.from(path));
  if (verdict !== "missing" && verdict !== "ok") return `core.excludesFile: ${verdict}`;
  return { path };
}

/**
 * Why Git must not run for this repository, or the excludes file to give
 * it. Unusual: a file Git opens that is a link or has another name, an
 * alternate object store, an include or core.worktree in the repository's
 * configuration, or an excludes file that could be a secret copy.
 */
async function repositoryCheck(repo: Repository, global: GlobalConfig): Promise<{ excludesFile: string } | string> {
  if (global.unusual) return `the global Git configuration: ${global.unusual}`;
  const config = child(repo.commonDir, Buffer.from("config"));
  const worktreeConfig = child(repo.gitDir, Buffer.from("config.worktree"));
  const required = [child(repo.gitDir, Buffer.from("HEAD")), config];
  const optional = [worktreeConfig, child(child(repo.commonDir, Buffer.from("info")), Buffer.from("exclude"))];
  for (const file of required) {
    const verdict = await plainFile(file);
    if (verdict !== "ok") return verdict === "missing" ? `${displayBytes(file)} is missing` : verdict;
  }
  for (const file of optional) {
    const verdict = await plainFile(file);
    if (verdict !== "ok" && verdict !== "missing") return verdict;
  }
  const alternates = child(repo.commonDir, Buffer.from("objects/info/alternates"));
  if ((await lstat(alternates).catch(() => null)) !== null) return `the repository uses another object store (${displayBytes(alternates)})`;
  let excludesFile = global.excludesFile;
  for (const file of [config, worktreeConfig]) {
    if ((await plainFile(file)) === "missing") continue;
    const facts = await readConfig(file);
    if (facts.unusual) return facts.unusual;
    if (facts.includes) return `${displayBytes(file)} includes other files, which Git would read`;
    excludesFile = facts.excludesFile ?? excludesFile;
  }
  const excludes = await excludesFileOf(excludesFile);
  return typeof excludes === "string" ? excludes : { excludesFile: excludes.path };
}

function nulList(buf: Buffer): Buffer[] {
  const out: Buffer[] = [];
  let start = 0;
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] === 0) {
      if (i > start) out.push(buf.subarray(start, i));
      start = i + 1;
    }
  }
  if (start < buf.length) out.push(buf.subarray(start));
  return out;
}

/**
 * Why Git must not read the `.gitignore` files that apply to these files
 * (one in each directory from the top of the working tree down to each
 * file's directory): one is a link, has another name, or is not a regular
 * file. Git opens them without following a symbolic link, but a hard link
 * or a FIFO would still be read.
 */
async function gitignoreCheck(top: Buffer, prefix: number, files: Found[]): Promise<string | null> {
  const seen = new Set<string>();
  for (const f of files) {
    const rel = f.abs.subarray(prefix);
    let dir = top;
    let at = 0;
    for (;;) {
      const key = dir.toString("latin1");
      if (!seen.has(key)) {
        seen.add(key);
        const verdict = await plainFile(child(dir, Buffer.from(".gitignore")));
        if (verdict !== "missing" && verdict !== "ok") return verdict;
      }
      const slash = rel.indexOf(SEP[0]!, at);
      if (slash < 0) break;
      dir = child(top, rel.subarray(0, slash));
      at = slash + 1;
    }
  }
  return null;
}

/** Set each file's Git state, with one `git check-ignore --no-index` per repository. */
export async function gitStates(walk: Walk): Promise<void> {
  const unknown = (files: Found[], reason: string) => {
    for (const f of files) Object.assign(f, { git: "unknown", gitError: reason });
  };
  // Each file belongs to the deepest directory above it that may be a repository's top.
  const dirs = [...walk.repoDirs].sort((a, b) => b.length - a.length);
  const byDir = new Map<string, { dir: Buffer; files: Found[] }>();
  for (const file of walk.files) {
    const dir = dirs.find((d) => isBelow(file.abs, d)) ?? walk.root;
    const key = dir.toString("latin1");
    const group = byDir.get(key);
    if (group) group.files.push(file);
    else byDir.set(key, { dir, files: [file] });
  }
  let global: GlobalConfig | null = null;
  for (const { dir, files } of byDir.values()) {
    try {
      const repo = await findRepository(dir);
      if (repo === null) {
        for (const f of files) f.git = "no-repository";
        continue;
      }
      if (typeof repo === "string") {
        unknown(files, repo);
        continue;
      }
      global ??= await readGlobalConfig();
      const check = await repositoryCheck(repo, global);
      if (typeof check === "string") {
        unknown(files, check);
        continue;
      }
      const top = utf8OrNull(repo.top);
      const ceiling = utf8OrNull(parentOf(repo.top) ?? SEP);
      if (top === null || ceiling === null) {
        unknown(files, "the repository's directory name is not UTF-8");
        continue;
      }
      const prefix = repo.top.length + (repo.top[repo.top.length - 1] === SEP[0] ? 0 : 1);
      const ignoreFiles = await gitignoreCheck(repo.top, prefix, files);
      if (ignoreFiles) {
        unknown(files, ignoreFiles);
        continue;
      }
      const input = Buffer.concat(files.flatMap((f) => [f.abs.subarray(prefix), Buffer.from([0])]));
      // Git looks for the repository from its top and no higher; --no-index reads no index.
      const r = await runGit(
        top,
        ["-c", `core.excludesFile=${check.excludesFile}`, "check-ignore", "--no-index", "-z", "--stdin"],
        gitEnv({ GIT_CEILING_DIRECTORIES: ceiling }),
        input,
      );
      // Exit 0: some paths are ignored; 1: none is.
      if (r.code !== 0 && r.code !== 1) {
        // Git's message is not shown: only that it refused or failed, and its exit status.
        unknown(files, `Git refused or failed (exit status ${r.code})`);
        continue;
      }
      const ignored = new Set(nulList(r.stdout).map((p) => p.toString("latin1")));
      for (const f of files) f.git = ignored.has(f.abs.subarray(prefix).toString("latin1")) ? "ignored" : "not-ignored";
    } catch (err) {
      unknown(files, err instanceof GitFailure ? err.message : `the repository could not be checked (${reasonOf(err)})`);
    }
  }
}

/** Walk, then ask Git about what was found. */
export async function findCopies(dir: string, cwd: string, limits: FindLimits = FIND_LIMITS): Promise<FindFilesReport> {
  const walk = await walkForCopies(dir, cwd, limits);
  if (walk.files.length > 0) await gitStates(walk);
  return {
    root: walk.root,
    files: walk.files.map(({ abs: _abs, ...f }) => f),
    notSearched: walk.notSearched,
    entriesChecked: walk.entriesChecked,
    stopped: walk.stopped,
  };
}

/** 1 when a file was found; 2 when none was but the search was incomplete; 0 otherwise. */
export function findFilesExitCode(report: FindFilesReport): number {
  if (report.files.length > 0) return 1;
  return report.stopped || report.notSearched.length > 0 ? 2 : 0;
}

const GIT_TEXT: Record<GitState, string> = {
  "not-ignored": "not ignored by Git, so it can be committed",
  ignored: "ignored by Git",
  "no-repository": "not in a Git repository",
  unknown: "Git status unknown",
};

export function formatFindFilesHuman(report: FindFilesReport, limits: FindLimits = FIND_LIMITS): string[] {
  const lines: string[] = [];
  if (report.files.length > 0) {
    lines.push(`Files that look like copies of secrets, by name, under ${displayBytes(report.root)}:`);
    for (const f of report.files) {
      const git = f.git === "unknown" && f.gitError ? `${GIT_TEXT.unknown}: ${displayPath(f.gitError)}` : GIT_TEXT[f.git];
      lines.push(`  ${displayBytes(f.path)}: ${f.symlink ? "a symbolic link, not followed; " : ""}${git}`);
    }
  }
  if (report.notSearched.length > 0) {
    if (lines.length > 0) lines.push("");
    lines.push(`Not searched (${report.notSearched.length}), so not known to be clean:`);
    for (const n of report.notSearched) lines.push(`  ${displayBytes(n.path)}: ${n.reason}`);
  }
  if (report.stopped) {
    if (lines.length > 0) lines.push("");
    lines.push(`The search stopped after ${limits.maxEntries} entries; what follows was not searched. Search a smaller directory.`);
  }
  if (lines.length > 0) lines.push("");
  const count = (state: GitState) => report.files.filter((f) => f.git === state).length;
  const notes = [count("not-ignored") > 0 ? `${count("not-ignored")} not ignored by Git` : ""].filter(Boolean);
  lines.push(
    report.files.length > 0
      ? `varlatch scan: ${report.files.length} file(s) look like copies of secrets${notes.length > 0 ? ` (${notes.join(", ")})` : ""}; ` +
          `${report.entriesChecked} entries checked by name, without reading their contents.`
      : `varlatch scan: no file looks like a copy of a secret; ${report.entriesChecked} entries checked by name, without reading their contents.`,
  );
  if (report.files.length === 0) return lines;
  if (report.files.some((f) => f.kind === "dotenv")) {
    lines.push("Move a dotenv file into Varlatch and delete it: varlatch import <file> --delete-source");
  }
  if (report.files.some((f) => f.kind === "key")) {
    lines.push("Store a key or certificate as one Secret, then delete the file: varlatch values set <ITEM> --from-file <file>");
  }
  if (count("not-ignored") > 0) {
    lines.push("A file Git does not ignore may already be committed (git log --all -- <file>): rotate the secrets of one that was.");
  }
  lines.push("See docs/reference/secret-scanning.md and docs/reference/import.md.");
  return lines;
}

/** The JSON document: paths as UTF-8, with `pathBase64` (`rootBase64`) holding the exact bytes of a name that is not UTF-8. */
export function findFilesJson(report: FindFilesReport) {
  return {
    version: FIND_FILES_REPORT_VERSION,
    mode: "find-files",
    exitCode: findFilesExitCode(report),
    ...jsonPath(report.root, "root"),
    files: report.files.map((f) => ({
      ...jsonPath(f.path, "path"),
      kind: f.kind,
      symlink: f.symlink,
      git: f.git,
      ...(f.gitError !== undefined ? { gitError: f.gitError } : {}),
    })),
    notSearched: report.notSearched.map((n) => ({ ...jsonPath(n.path, "path"), reason: n.reason })),
    entriesChecked: report.entriesChecked,
    stopped: report.stopped,
  };
}
