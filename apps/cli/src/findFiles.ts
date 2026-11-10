// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import type { Dirent } from "node:fs";
import { lstat, readdir, realpath } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
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
 */

export const FIND_FILES_REPORT_VERSION = 1;

/** Directories never entered: version control and dependencies, as the agents hook skips them. */
const SKIP_DIRS: ReadonlySet<string> = new Set([".git", ".hg", ".svn", "node_modules"]);

export interface FindLimits {
  /** Directory entries looked at before the walk stops. */
  maxEntries: number;
  /** Directory levels below the starting directory that are entered. */
  maxDepth: number;
}

export const FIND_LIMITS: FindLimits = { maxEntries: 200_000, maxDepth: 20 };

/** What a name looks like: a dotenv file, or a key or certificate file. */
export type CopyKind = "dotenv" | "key";

/**
 * The ADR's patterns, matched case-sensitively as Git does on Linux:
 * `.env`, `.env.*` except the templates `.env.example` and `.env.schema`,
 * `*.pem`, and `*.key`.
 */
export function copyKindOf(name: string): CopyKind | null {
  if (name === ".env" || (name.startsWith(".env.") && !ENV_TEMPLATES.has(name))) return "dotenv";
  if (name.endsWith(".pem") || name.endsWith(".key")) return "key";
  return null;
}

export type GitState = "tracked" | "not-ignored" | "ignored" | "no-repository" | "unknown";

export interface FoundFile {
  /** Relative to the starting directory, with `/` separators. */
  path: string;
  kind: CopyKind;
  /** A symbolic link is listed by its own name; its target is never looked at. */
  symlink: boolean;
  git: GitState;
  /** Why the Git state is unknown. */
  gitError?: string;
}

export interface FindFilesReport {
  root: string;
  files: FoundFile[];
  notSearched: { path: string; reason: string }[];
  entriesChecked: number;
  /** The walk stopped at maxEntries: what follows was not looked at. */
  stopped: boolean;
}

export class FindFilesError extends Error {
  override name = "FindFilesError";
}

function relativePath(root: string, abs: string): string {
  const rel = relative(root, abs);
  return sep === "/" ? rel : rel.split(sep).join("/");
}

function reasonOf(err: unknown): string {
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  if (code === "ENOENT") return "does not exist";
  return `unreadable (${code ?? (err instanceof Error ? err.message : String(err))})`;
}

interface Walk {
  root: string;
  files: (FoundFile & { abs: string })[];
  notSearched: { path: string; reason: string }[];
  /** Directories that hold a `.git` entry: each may be the top of its own repository. */
  repoDirs: string[];
  entriesChecked: number;
  stopped: boolean;
}

/** Walk `dir` (resolved from `cwd`) by name, in a stable order, without following links or opening files. */
export async function walkForCopies(dir: string, cwd: string, limits: FindLimits = FIND_LIMITS): Promise<Walk> {
  let root: string;
  try {
    // Resolve the directory given (it may itself be a link); nothing below it is followed.
    root = await realpath(resolve(cwd, dir));
  } catch (err) {
    throw new FindFilesError(`cannot search ${dir}: ${reasonOf(err)}`);
  }
  if (!(await lstat(root)).isDirectory()) throw new FindFilesError(`--find-files takes a directory; ${dir} is not one`);

  const walk: Walk = { root, files: [], notSearched: [], repoDirs: [root], entriesChecked: 0, stopped: false };
  const visit = async (abs: string, depth: number): Promise<void> => {
    let entries: Dirent[];
    try {
      entries = await readdir(abs, { withFileTypes: true });
    } catch (err) {
      walk.notSearched.push({ path: `${relativePath(root, abs) || "."}/`, reason: `directory ${reasonOf(err)}` });
      return;
    }
    entries.sort((a, b) => Buffer.compare(Buffer.from(a.name), Buffer.from(b.name)));
    if (abs !== root && entries.some((e) => e.name === ".git")) walk.repoDirs.push(abs);
    for (const entry of entries) {
      if (walk.stopped) return;
      if (++walk.entriesChecked > limits.maxEntries) {
        walk.entriesChecked = limits.maxEntries;
        walk.stopped = true;
        return;
      }
      const child = join(abs, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        if (depth >= limits.maxDepth) {
          walk.notSearched.push({ path: `${relativePath(root, child)}/`, reason: `below the depth bound of ${limits.maxDepth} directory levels` });
          continue;
        }
        await visit(child, depth + 1);
        continue;
      }
      // Only regular files and links to anything; a link is never followed.
      const symlink = entry.isSymbolicLink();
      if (!symlink && !entry.isFile()) continue;
      const kind = copyKindOf(entry.name);
      if (kind) walk.files.push({ abs: child, path: relativePath(root, child), kind, symlink, git: "unknown" });
    }
  };
  await visit(root, 0);
  return walk;
}

/** Git, run for its answer only: the repository is chosen by directory, never by inherited GIT_* variables. */
function git(cwd: string, args: string[], input?: string): Promise<{ code: number; stdout: Buffer; stderr: string }> {
  const env = { ...process.env };
  for (const name of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"]) delete env[name];
  return new Promise((resolvePromise, reject) => {
    const child = spawn("git", ["-c", "core.fsmonitor=false", ...args], {
      cwd,
      env,
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    });
    const out: Buffer[] = [];
    let err = "";
    child.stdin?.on("error", () => {});
    child.stdout!.on("data", (d: Buffer) => out.push(d));
    child.stderr!.on("data", (d: Buffer) => (err += d.toString()));
    child.on("error", (e) => reject(new Error(`could not run git: ${e.message}`)));
    child.on("close", (code) => resolvePromise({ code: code ?? 1, stdout: Buffer.concat(out), stderr: err.trim() }));
    child.stdin?.end(input);
  });
}

function nulList(buf: Buffer): string[] {
  return buf.toString("utf8").split("\0").filter((s) => s !== "");
}

const TRACKED_PATHSPECS = [":(glob)**/.env", ":(glob)**/.env.*", ":(glob)**/*.pem", ":(glob)**/*.key"];

/** Set each file's Git state: one `ls-files` and one `check-ignore --stdin` per repository. */
export async function gitStates(walk: Walk): Promise<void> {
  // Each file belongs to the deepest directory above it that may be a repository's top.
  const dirs = [...walk.repoDirs].sort((a, b) => b.length - a.length);
  const byDir = new Map<string, Walk["files"]>();
  for (const file of walk.files) {
    const dir = dirs.find((d) => file.abs.startsWith(d + sep)) ?? walk.root;
    const group = byDir.get(dir);
    if (group) group.push(file);
    else byDir.set(dir, [file]);
  }
  const byTop = new Map<string, Walk["files"]>();
  for (const [dir, files] of byDir) {
    let top: string;
    try {
      const r = await git(dir, ["rev-parse", "--show-toplevel"]);
      if (r.code !== 0) {
        const outside = /not a git repository/i.test(r.stderr);
        for (const f of files) {
          f.git = outside ? "no-repository" : "unknown";
          if (!outside) f.gitError = r.stderr.split("\n")[0] || `git rev-parse exited ${r.code}`;
        }
        continue;
      }
      top = r.stdout.toString("utf8").trim();
      if (!top) {
        for (const f of files) Object.assign(f, { git: "unknown", gitError: "a bare repository" });
        continue;
      }
      top = await realpath(top);
    } catch (err) {
      for (const f of files) Object.assign(f, { git: "unknown", gitError: err instanceof Error ? err.message : String(err) });
      continue;
    }
    const group = byTop.get(top);
    if (group) group.push(...files);
    else byTop.set(top, [...files]);
  }
  for (const [top, files] of byTop) {
    const rel = new Map(files.map((f) => [relativePath(top, f.abs), f]));
    try {
      const listed = await git(top, ["ls-files", "-z", "--cached", "--", ...TRACKED_PATHSPECS]);
      if (listed.code !== 0) throw new Error(listed.stderr.split("\n")[0] || `git ls-files exited ${listed.code}`);
      for (const path of nulList(listed.stdout)) {
        const f = rel.get(path);
        if (f) f.git = "tracked";
      }
      const untracked = [...rel].filter(([, f]) => f.git !== "tracked");
      if (untracked.length === 0) continue;
      // Exit 0: some paths are ignored; 1: none is.
      const checked = await git(top, ["check-ignore", "-z", "--stdin"], untracked.map(([p]) => `${p}\0`).join(""));
      if (checked.code !== 0 && checked.code !== 1) throw new Error(checked.stderr.split("\n")[0] || `git check-ignore exited ${checked.code}`);
      const ignored = new Set(nulList(checked.stdout));
      for (const [path, f] of untracked) f.git = ignored.has(path) ? "ignored" : "not-ignored";
    } catch (err) {
      for (const f of files) Object.assign(f, { git: "unknown", gitError: err instanceof Error ? err.message : String(err) });
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
    lines.push(`Files that look like copies of secrets, by name, under ${displayPath(report.root)}:`);
    for (const f of report.files) {
      const git = f.git === "unknown" && f.gitError ? `${GIT_TEXT.unknown} (${f.gitError})` : GIT_TEXT[f.git];
      lines.push(`  ${displayPath(f.path)}: ${f.symlink ? "a symbolic link, not followed; " : ""}${git}`);
    }
  }
  if (report.notSearched.length > 0) {
    if (lines.length > 0) lines.push("");
    lines.push(`Not searched (${report.notSearched.length}), so not known to be clean:`);
    for (const n of report.notSearched) lines.push(`  ${displayPath(n.path)}: ${n.reason}`);
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

export function findFilesJson(report: FindFilesReport) {
  return { version: FIND_FILES_REPORT_VERSION, mode: "find-files", exitCode: findFilesExitCode(report), ...report };
}
