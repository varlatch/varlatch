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
 * whether Git ignores or tracks each one, and point to `varlatch import`.
 *
 * Names only: the walk reads directory entries and never opens a file, a
 * matched one included, and never follows a symbolic link. It needs no
 * project, no server, and no credential, and discloses nothing.
 *
 * Git is asked only when it cannot read a matched file either: before Git
 * runs for a repository, the configuration it would load is read here, by
 * name and without includes, and a repository whose configuration could
 * make Git open another file by name (an include, an excludes file, a linked
 * info/exclude) that looks like a secret copy is reported as unknown instead.
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

export type GitState = "tracked" | "not-ignored" | "ignored" | "no-repository" | "unknown";

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

// ---- What Git would read -----------------------------------------------------

/** Variables that would choose another repository or add configuration; Git gets none of them. */
const GIT_ENV_DROPPED = ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_CONFIG", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT"];

function gitEnv(extra: Record<string, string>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (GIT_ENV_DROPPED.includes(k) || /^GIT_CONFIG_(KEY|VALUE)_\d+$/.test(k)) continue;
    env[k] = v;
  }
  // The system configuration is not read: its location depends on how Git was built.
  return { ...env, GIT_CONFIG_NOSYSTEM: "1", ...extra };
}

interface GitResult {
  code: number;
  stdout: Buffer;
  stderr: string;
}

/** Run git with a timeout: a Git that waits on something is given up, never waited for. */
function runGit(cwd: string, args: string[], env: NodeJS.ProcessEnv, input?: Buffer): Promise<GitResult> {
  return new Promise((resolvePromise, reject) => {
    const proc = spawn("git", ["-c", "core.fsmonitor=false", ...args], {
      cwd,
      env,
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    });
    const out: Buffer[] = [];
    let err = "";
    const timer = setTimeout(() => {
      proc.kill("SIGKILL");
      reject(new Error(`git ${args[0]} did not answer within ${GIT_TIMEOUT_MS / 1000} s`));
    }, GIT_TIMEOUT_MS);
    proc.stdin?.on("error", () => {});
    proc.stdout!.on("data", (d: Buffer) => out.push(d));
    proc.stderr!.on("data", (d: Buffer) => (err += d.toString()));
    proc.on("error", (e) => {
      clearTimeout(timer);
      reject(new Error(`could not run git: ${e.message}`));
    });
    proc.on("close", (code) => {
      clearTimeout(timer);
      resolvePromise({ code: code ?? 1, stdout: Buffer.concat(out), stderr: err.trim() });
    });
    proc.stdin?.end(input);
  });
}

function firstLine(r: GitResult, what: string): string {
  return r.stderr.split("\n")[0] || `git ${what} exited ${r.code}`;
}

/**
 * Whether Git may read the file at `path`: "missing" when there is none (Git
 * skips it), "ok" for a regular file, or the reason it may not. Every name on
 * the way, links included, is checked against the patterns, and only names
 * are looked at.
 */
async function readableByGit(path: Buffer): Promise<"missing" | "ok" | string> {
  if (path.toString("latin1") === "/dev/null") return "missing";
  let current = path;
  for (let hops = 0; hops < 40; hops++) {
    if (copyKindOf(baseName(current))) return `${displayBytes(current)} has the name of a secret copy`;
    let st;
    try {
      st = await lstat(current);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") return "missing";
      return `${displayBytes(current)}: ${reasonOf(err)}`;
    }
    if (st.isFile()) return "ok";
    if (!st.isSymbolicLink()) return `${displayBytes(current)} is not a regular file`;
    const target = (await readlink(current, { encoding: "buffer" })) as Buffer;
    current = target[0] === SEP[0] ? target : child(parentOf(current) ?? SEP, target);
  }
  return `${displayBytes(path)}: too many symbolic links`;
}

/** A configuration path as Git expands it, or null when it cannot be expanded here. */
function expandPath(value: string, relativeTo: Buffer): Buffer | null {
  if (value.startsWith("~/")) return Buffer.from(join(process.env.HOME || homedir(), value.slice(2)));
  if (value.startsWith("~") || value.startsWith("%(")) return null;
  if (value.startsWith("/")) return Buffer.from(value);
  return child(relativeTo, Buffer.from(value));
}

interface ConfigScan {
  /** Why Git must not run, if it must not. */
  unsafe: string | null;
  /** core.excludesFile values, already expanded (null: not expandable here). */
  excludes: (string | null)[];
}

const NO_REPOSITORY = join(tmpdir(), "varlatch-find-files-no-repository");

/**
 * Read configuration files the way Git would, includes followed here rather
 * than by Git: each file is parsed by `git config --file <f> --no-includes`
 * outside any repository, after its name was checked.
 */
async function scanConfig(files: Buffer[], cwd: string): Promise<ConfigScan> {
  const result: ConfigScan = { unsafe: null, excludes: [] };
  const env = gitEnv({ GIT_CONFIG_GLOBAL: "/dev/null", GIT_DIR: NO_REPOSITORY });
  const visit = async (file: Buffer, depth: number): Promise<void> => {
    if (result.unsafe) return;
    if (depth > 10) {
      result.unsafe = "includes nested more than 10 deep";
      return;
    }
    const verdict = await readableByGit(file);
    if (verdict === "missing") return;
    if (verdict !== "ok") {
      result.unsafe = verdict;
      return;
    }
    const name = utf8OrNull(file);
    if (name === null) {
      result.unsafe = `${displayBytes(file)} is not a UTF-8 path`;
      return;
    }
    const r = await runGit(cwd, ["config", "--file", name, "--no-includes", "--list", "-z"], env);
    if (r.code !== 0) {
      result.unsafe = `${displayBytes(file)}: ${firstLine(r, "config")}`;
      return;
    }
    for (const entry of r.stdout.toString("utf8").split("\0")) {
      if (entry === "") continue;
      const nl = entry.indexOf("\n");
      const key = nl < 0 ? entry : entry.slice(0, nl);
      const value = nl < 0 ? "" : entry.slice(nl + 1);
      const lower = key.toLowerCase();
      if (lower === "include.path" || (lower.startsWith("includeif.") && lower.endsWith(".path"))) {
        const target = expandPath(value, parentOf(file) ?? SEP);
        if (target === null) {
          result.unsafe = `${displayBytes(file)} includes ${displayPath(value)}, which is not checked here`;
          return;
        }
        await visit(target, depth + 1);
        if (result.unsafe) return;
      } else if (lower === "core.excludesfile") {
        result.excludes.push(value);
      }
    }
  };
  for (const file of files) await visit(file, 0);
  return result;
}

function globalConfigFiles(): Buffer[] {
  const home = process.env.HOME || homedir();
  const xdg = process.env.XDG_CONFIG_HOME || join(home, ".config");
  if (process.env.GIT_CONFIG_GLOBAL !== undefined) return [Buffer.from(process.env.GIT_CONFIG_GLOBAL)];
  return [Buffer.from(join(home, ".gitconfig")), Buffer.from(join(xdg, "git", "config"))];
}

function defaultExcludesFile(): Buffer {
  const xdg = process.env.XDG_CONFIG_HOME || join(process.env.HOME || homedir(), ".config");
  return Buffer.from(join(xdg, "git", "ignore"));
}

interface Repository {
  /** The directory that holds `.git`, or the bare repository itself: Git looks no higher. */
  dir: Buffer;
  gitDir: Buffer;
  commonDir: Buffer;
}

/** Read a small file Git keeps in the repository (`.git` file, `commondir`), after checking its name. */
async function readGitPointer(path: Buffer): Promise<string | null> {
  if ((await readableByGit(path)) !== "ok") return null;
  const handle = await open(path, "r");
  try {
    const buf = Buffer.alloc(4096);
    const { bytesRead } = await handle.read(buf, 0, buf.length, 0);
    return buf.subarray(0, bytesRead).toString("utf8").split("\n")[0]!.trim();
  } finally {
    await handle.close();
  }
}

async function exists(path: Buffer): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch {
    return false;
  }
}

async function isDir(path: Buffer): Promise<boolean> {
  try {
    return (await lstat(path)).isDirectory();
  } catch {
    return false;
  }
}

/**
 * The repository Git would find from `start`, found the way Git looks for
 * it (a `.git` directory or file, or a bare repository), without running
 * Git. Null outside any repository; a string when it cannot be told.
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
    let gitDir: Buffer | null = null;
    if (st?.isDirectory()) gitDir = dotGit;
    else if (st) {
      const resolved = st.isSymbolicLink() ? await realpath(dotGit, { encoding: "buffer" }).catch(() => null) : null;
      if (resolved && (await isDir(resolved as Buffer))) gitDir = resolved as Buffer;
      else {
        const line = await readGitPointer(dotGit);
        const m = line ? /^gitdir: (.+)$/.exec(line) : null;
        if (!m) return `${displayBytes(dotGit)} is not a Git directory or a gitdir file`;
        gitDir = m[1]!.startsWith("/") ? Buffer.from(m[1]!) : child(dir, Buffer.from(m[1]!));
      }
    } else if (
      (await exists(child(dir, Buffer.from("HEAD")))) &&
      (await isDir(child(dir, Buffer.from("objects")))) &&
      (await isDir(child(dir, Buffer.from("refs"))))
    ) {
      gitDir = dir;
    }
    if (gitDir === null) continue;
    gitDir = ((await realpath(gitDir, { encoding: "buffer" }).catch(() => gitDir)) as Buffer) ?? gitDir;
    let commonDir = gitDir;
    const pointer = child(gitDir, Buffer.from("commondir"));
    if ((await readableByGit(pointer)) === "ok") {
      const line = await readGitPointer(pointer);
      if (line) commonDir = line.startsWith("/") ? Buffer.from(line) : child(gitDir, Buffer.from(line));
      commonDir = ((await realpath(commonDir, { encoding: "buffer" }).catch(() => commonDir)) as Buffer) ?? commonDir;
    }
    return { dir, gitDir, commonDir };
  }
  return null;
}

/** Why Git must not run: a file it reads in the repository (HEAD, the index) is a link to a secret copy's name. */
async function internalsUnsafe(repo: Repository): Promise<string | null> {
  for (const file of [child(repo.gitDir, Buffer.from("HEAD")), child(repo.commonDir, Buffer.from("HEAD")), child(repo.gitDir, Buffer.from("index"))]) {
    const verdict = await readableByGit(file);
    if (verdict !== "missing" && verdict !== "ok") return verdict;
  }
  return null;
}

/** The repository's own configuration files, as Git reads them for a working tree or a linked worktree. */
function localConfigFiles(repo: Repository): Buffer[] {
  return [child(repo.commonDir, Buffer.from("config")), child(repo.gitDir, Buffer.from("config")), child(repo.gitDir, Buffer.from("config.worktree"))];
}

/**
 * Why `git check-ignore` must not run: an excludes file (core.excludesFile,
 * or its default) or info/exclude that could be a secret copy. A relative
 * core.excludesFile is relative to where Git runs, the top of the working tree.
 */
async function excludesUnsafe(scans: ConfigScan[], repo: Repository, top: Buffer): Promise<string | null> {
  const values = scans.flatMap((s) => s.excludes);
  const files: Buffer[] = values.length === 0 ? [defaultExcludesFile()] : [];
  for (const value of values) {
    const expanded = expandPath(value ?? "", top);
    if (expanded === null) return `core.excludesFile ${displayPath(value ?? "")} is not checked here`;
    files.push(expanded);
  }
  files.push(child(child(repo.commonDir, Buffer.from("info")), Buffer.from("exclude")));
  for (const file of files) {
    const verdict = await readableByGit(file);
    if (verdict !== "missing" && verdict !== "ok") return verdict;
  }
  return null;
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

const TRACKED_PATHSPECS = [":(glob)**/.env", ":(glob)**/.env.*", ":(glob)**/*.pem", ":(glob)**/*.key"];

const UNSAFE_PREFIX = "the Git configuration could make Git read other files";

/** Set each file's Git state: one `ls-files` and one `check-ignore --stdin` per repository. */
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
  // Configuration files are parsed with GIT_DIR naming no repository, so no other configuration is read.
  const neutral = tmpdir();
  let globalScan: ConfigScan | null = null;
  const localScans = new Map<string, ConfigScan>();
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
      globalScan ??= await scanConfig(globalConfigFiles(), neutral);
      const cwd = utf8OrNull(dir);
      const ceiling = utf8OrNull(parentOf(repo.dir) ?? SEP);
      if (cwd === null || ceiling === null) {
        unknown(files, "the directory's name is not UTF-8");
        continue;
      }
      // Every configuration file Git would load, includes followed here, before Git runs at all.
      const repoKey = repo.gitDir.toString("latin1");
      let localScan = localScans.get(repoKey);
      if (!localScan) {
        localScan = await scanConfig(localConfigFiles(repo), neutral);
        localScans.set(repoKey, localScan);
      }
      const configUnsafe = globalScan.unsafe ?? localScan.unsafe ?? (await internalsUnsafe(repo));
      if (configUnsafe) {
        unknown(files, `${UNSAFE_PREFIX} (${configUnsafe})`);
        continue;
      }
      // Git looks no higher than the repository checked above.
      const env = gitEnv({ GIT_CEILING_DIRECTORIES: ceiling });
      const r = await runGit(cwd, ["rev-parse", "--absolute-git-dir", "--show-toplevel"], env);
      if (r.code !== 0 && /not a git repository/i.test(r.stderr)) {
        // Not a repository Git accepts (an empty .git, say), and Git looks no higher.
        for (const f of files) f.git = "no-repository";
        continue;
      }
      if (r.code !== 0) {
        unknown(files, firstLine(r, "rev-parse"));
        continue;
      }
      const [gitDirOut, topOut] = r.stdout.toString("latin1").split("\n");
      const gitDir = (await realpath(Buffer.from(gitDirOut ?? "", "latin1"), { encoding: "buffer" })) as Buffer;
      if (!gitDir.equals(repo.gitDir)) {
        unknown(files, "Git found another repository than the one checked");
        continue;
      }
      if (!topOut) {
        unknown(files, "a repository without a working tree");
        continue;
      }
      const top = (await realpath(Buffer.from(topOut, "latin1"), { encoding: "buffer" })) as Buffer;
      const excludes = await excludesUnsafe([globalScan, localScan], repo, top);
      if (excludes) {
        unknown(files, `${UNSAFE_PREFIX} (${excludes})`);
        continue;
      }
      const topText = utf8OrNull(top);
      if (topText === null) {
        unknown(files, "the repository's directory name is not UTF-8");
        continue;
      }
      const rel = new Map<string, Found>();
      for (const f of files) {
        if (!isBelow(f.abs, top)) {
          f.gitError = "outside the repository's working tree";
          continue;
        }
        rel.set(f.abs.subarray(top.length + (top[top.length - 1] === SEP[0] ? 0 : 1)).toString("latin1"), f);
      }
      const listed = await runGit(topText, ["ls-files", "-z", "--cached", "--", ...TRACKED_PATHSPECS], env);
      if (listed.code !== 0) throw new Error(firstLine(listed, "ls-files"));
      for (const path of nulList(listed.stdout)) {
        const f = rel.get(path.toString("latin1"));
        if (f) f.git = "tracked";
      }
      const untracked = [...rel].filter(([, f]) => f.git !== "tracked");
      if (untracked.length === 0) continue;
      const input = Buffer.concat(untracked.flatMap(([p]) => [Buffer.from(p, "latin1"), Buffer.from([0])]));
      // Exit 0: some paths are ignored; 1: none is.
      const checked = await runGit(topText, ["check-ignore", "-z", "--stdin"], env, input);
      if (checked.code !== 0 && checked.code !== 1) throw new Error(firstLine(checked, "check-ignore"));
      const ignored = new Set(nulList(checked.stdout).map((p) => p.toString("latin1")));
      for (const [path, f] of untracked) f.git = ignored.has(path) ? "ignored" : "not-ignored";
    } catch (err) {
      unknown(files, err instanceof Error ? err.message : String(err));
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
  tracked: "tracked by Git, so it is in the repository's history",
  "not-ignored": "not ignored by Git, so a commit could add it",
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
  const notes = [
    count("tracked") > 0 ? `${count("tracked")} tracked by Git` : "",
    count("not-ignored") > 0 ? `${count("not-ignored")} not ignored` : "",
  ].filter(Boolean);
  lines.push(
    report.files.length > 0
      ? `varlatch scan: ${report.files.length} file(s) look like copies of secrets${notes.length > 0 ? ` (${notes.join(", ")})` : ""}; ` +
          `${report.entriesChecked} entries checked by name. No file was opened.`
      : `varlatch scan: no file looks like a copy of a secret; ${report.entriesChecked} entries checked by name. No file was opened.`,
  );
  if (report.files.length === 0) return lines;
  if (report.files.some((f) => f.kind === "dotenv")) {
    lines.push("Move a dotenv file into Varlatch and delete it: varlatch import <file> --delete-source");
  }
  if (report.files.some((f) => f.kind === "key")) {
    lines.push("Store a key or certificate as one Secret, then delete the file: varlatch values set <ITEM> --from-file <file>");
  }
  if (count("tracked") > 0) {
    lines.push("Removing a tracked file does not remove it from Git history: rotate the secrets it holds.");
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
