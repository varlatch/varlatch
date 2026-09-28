// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { createReadStream } from "node:fs";
import { lstat, readdir, realpath } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import type { FileScan, ScanEngine } from "./scan.js";

/**
 * What `varlatch scan` reads (ADR-0038 Decision 14).
 *
 * - `--staged`: the blobs recorded in the Git index for every path the next
 *   commit adds or changes, read from the object store, never from the
 *   working tree. A Secret that was staged and then edited or deleted in the
 *   working tree is still found. Inside a Git hook, Git's own environment
 *   (for example the temporary index of `git commit -a`) is used as is.
 * - Paths: files and directories, walked without following symbolic links.
 *
 * Listing comes first and reads no content, so a scan with nothing to read
 * never asks the server for values.
 */

export class ScanSourceError extends Error {
  override name = "ScanSourceError";
}

/** A path relative to `root`, with `/` separators. */
export function relativePath(root: string, abs: string): string {
  const rel = relative(root, abs);
  return sep === "/" ? rel : rel.split(sep).join("/");
}

/** Run git and collect stdout; a non-zero exit is an error carrying git's message. */
function git(cwd: string, args: string[], input?: string): Promise<Buffer> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn("git", args, { cwd, stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"] });
    const out: Buffer[] = [];
    let err = "";
    // git may exit before reading all of its input; its exit status tells.
    child.stdin?.on("error", () => {});
    child.stdout!.on("data", (d: Buffer) => out.push(d));
    child.stderr!.on("data", (d: Buffer) => (err += d.toString()));
    child.on("error", (e) => reject(new ScanSourceError(`could not run git: ${e.message}`)));
    child.on("close", (code) => {
      if (code === 0) resolvePromise(Buffer.concat(out));
      else reject(new ScanSourceError(`git ${args[0]} failed: ${err.trim() || `exit ${code}`}`));
    });
    child.stdin?.end(input);
  });
}

export interface StagedFile {
  /** Display path, relative to the project root. */
  path: string;
  sha: string;
  size: number;
}

export interface StagedListing {
  top: string;
  files: StagedFile[];
  notScanned: { path: string; reason: string }[];
}

/** The top level of the Git working tree containing `cwd`. */
export async function gitTopLevel(cwd: string): Promise<string> {
  let top: string;
  try {
    top = (await git(cwd, ["rev-parse", "--show-toplevel"])).toString("utf8").trim();
  } catch (err) {
    throw new ScanSourceError(
      `--staged needs a Git working tree: ${err instanceof Error ? err.message.replace(/^git rev-parse failed: /, "") : String(err)}`,
    );
  }
  if (!top) throw new ScanSourceError("--staged needs a Git working tree, not a bare repository");
  return realpath(top);
}

/** Every path the index adds or changes relative to HEAD (all of it before the first commit). */
export async function listStaged(cwd: string, projectRoot: string): Promise<StagedListing> {
  const top = await gitTopLevel(cwd);
  const root = await realpath(projectRoot);
  const raw = await git(top, ["diff", "--cached", "--raw", "-z", "--no-abbrev", "--no-renames", "--no-ext-diff", "--no-color"]);
  const tokens = raw.toString("utf8").split("\0");
  const candidates: { path: string; sha: string }[] = [];
  const notScanned: { path: string; reason: string }[] = [];
  for (let i = 0; i + 1 < tokens.length; i += 2) {
    const meta = tokens[i]!;
    const gitPath = tokens[i + 1]!;
    const m = /^:(\d{6}) (\d{6}) ([0-9a-f]+) ([0-9a-f]+) ([A-Z])\d*$/.exec(meta);
    if (!m) throw new ScanSourceError(`unexpected output from git diff: ${JSON.stringify(meta)}`);
    const [, , mode, , sha, status] = m as unknown as [string, string, string, string, string, string];
    const path = relativePath(root, join(top, gitPath));
    if (status === "D") continue;
    if (status === "U") {
      notScanned.push({ path, reason: "unmerged: resolve the conflict and stage the result" });
      continue;
    }
    if (mode === "160000") {
      notScanned.push({ path, reason: "a submodule: scan it in its own repository" });
      continue;
    }
    candidates.push({ path, sha: sha! });
  }
  if (candidates.length === 0) return { top, files: [], notScanned };
  // Sizes from the object store, without reading content.
  const checked = (await git(top, ["cat-file", "--batch-check"], candidates.map((c) => `${c.sha}\n`).join("")))
    .toString("utf8")
    .split("\n");
  const files: StagedFile[] = [];
  candidates.forEach((c, i) => {
    const line = checked[i] ?? "";
    const m = /^([0-9a-f]+) (\w+) (\d+)$/.exec(line);
    if (!m || m[1] !== c.sha) {
      notScanned.push({ path: c.path, reason: "the staged object is missing from the repository" });
      return;
    }
    if (m[2] !== "blob") {
      notScanned.push({ path: c.path, reason: `not a file (${m[2]})` });
      return;
    }
    files.push({ path: c.path, sha: c.sha, size: Number(m[3]) });
  });
  return { top, files, notScanned };
}

/**
 * Stream the staged blobs through the engine with one `git cat-file --batch`.
 * Files the engine does not admit (over a bound) are never requested.
 */
export async function scanStaged(engine: ScanEngine, listing: StagedListing): Promise<void> {
  const wanted = listing.files.filter((f) => engine.admit(f.path, f.size));
  if (wanted.length === 0) return;
  await new Promise<void>((resolvePromise, reject) => {
    const child = spawn("git", ["cat-file", "--batch"], { cwd: listing.top, stdio: ["pipe", "pipe", "pipe"] });
    let err = "";
    let index = 0;
    let header: Buffer[] = [];
    let remaining = -1; // content bytes left in the current object; -1 while reading a header
    let trailer = false;
    let current: FileScan | null = null;
    let overBound = false;
    let failed: Error | null = null;

    const startObject = (line: string) => {
      const file = wanted[index];
      const m = /^([0-9a-f]+) (\w+) (\d+)$/.exec(line);
      if (!file || !m || m[1] !== file.sha) {
        throw new ScanSourceError(`unexpected output from git cat-file: ${JSON.stringify(line)}`);
      }
      current = engine.begin(file.path);
      overBound = false;
      remaining = Number(m[3]);
      if (remaining === 0) finishObject();
    };
    const finishObject = () => {
      if (current) {
        if (overBound) current.fail("grew past the per-file bound while being read");
        else current.end();
      }
      current = null;
      index++;
      remaining = -1;
      trailer = true;
    };

    child.stdout.on("data", (chunk: Buffer) => {
      if (failed) return;
      try {
        let at = 0;
        while (at < chunk.length) {
          if (trailer) {
            // The newline git writes after each object's content.
            trailer = false;
            at++;
            continue;
          }
          if (remaining < 0) {
            const nl = chunk.indexOf(10, at);
            if (nl < 0) {
              header.push(chunk.subarray(at));
              return;
            }
            header.push(chunk.subarray(at, nl));
            const line = Buffer.concat(header).toString("utf8");
            header = [];
            at = nl + 1;
            startObject(line);
            continue;
          }
          const take = Math.min(remaining, chunk.length - at);
          if (current && !overBound && !current.push(chunk.subarray(at, at + take))) overBound = true;
          remaining -= take;
          at += take;
          if (remaining === 0) finishObject();
        }
      } catch (e) {
        failed = e instanceof Error ? e : new Error(String(e));
        child.kill();
      }
    });
    child.stderr.on("data", (d: Buffer) => (err += d.toString()));
    child.on("error", (e) => reject(new ScanSourceError(`could not run git: ${e.message}`)));
    child.on("close", (code) => {
      if (failed) return reject(failed);
      if (code !== 0) return reject(new ScanSourceError(`git cat-file failed: ${err.trim() || `exit ${code}`}`));
      if (index !== wanted.length) return reject(new ScanSourceError("git cat-file ended early"));
      resolvePromise();
    });
    child.stdin.on("error", () => {});
    child.stdin.end(wanted.map((f) => `${f.sha}\n`).join(""));
  });
}

// ---- Paths -------------------------------------------------------------------

export interface PathFile {
  abs: string;
  path: string;
  size: number;
}

export interface PathListing {
  files: PathFile[];
  notScanned: { path: string; reason: string }[];
}

function reasonOf(err: unknown): string {
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  if (code === "ENOENT") return "does not exist";
  if (code === "EACCES" || code === "EPERM") return `unreadable (${code})`;
  return `unreadable (${code ?? (err instanceof Error ? err.message : String(err))})`;
}

/** Walk the given files and directories, in a stable order, without following symbolic links. */
export async function listPaths(args: string[], cwd: string, projectRoot: string): Promise<PathListing> {
  const root = await realpath(projectRoot);
  const files: PathFile[] = [];
  const notScanned: { path: string; reason: string }[] = [];
  const seen = new Set<string>();
  const visit = async (abs: string, display: string): Promise<void> => {
    if (seen.has(abs)) return;
    seen.add(abs);
    let st;
    try {
      st = await lstat(abs);
    } catch (err) {
      notScanned.push({ path: display, reason: reasonOf(err) });
      return;
    }
    if (st.isSymbolicLink()) {
      notScanned.push({ path: display, reason: "a symbolic link, not followed: scan its target directly" });
      return;
    }
    if (st.isFile()) {
      files.push({ abs, path: display, size: st.size });
      return;
    }
    if (!st.isDirectory()) {
      notScanned.push({ path: display, reason: "not a regular file" });
      return;
    }
    let names: string[];
    try {
      names = await readdir(abs);
    } catch (err) {
      notScanned.push({ path: display, reason: `directory ${reasonOf(err)}` });
      return;
    }
    names.sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    for (const name of names) {
      const child = join(abs, name);
      await visit(child, relativePath(root, child));
    }
  };
  for (const arg of args) {
    const given = resolve(cwd, arg);
    let abs: string;
    try {
      // Resolve the argument itself (for example a symlinked build directory);
      // nothing below it is followed.
      abs = await realpath(given);
    } catch (err) {
      notScanned.push({ path: relativePath(root, given), reason: reasonOf(err) });
      continue;
    }
    await visit(abs, relativePath(root, abs) || ".");
  }
  return { files, notScanned };
}

/** Stream each listed file through the engine, one at a time. */
export async function scanPaths(engine: ScanEngine, listing: PathListing): Promise<void> {
  for (const file of listing.files) {
    if (!engine.admit(file.path, file.size)) continue;
    const scan = engine.begin(file.path);
    let over = false;
    try {
      const stream = createReadStream(file.abs, { highWaterMark: 1 << 16 });
      for await (const chunk of stream) {
        if (!scan.push(chunk as Buffer)) {
          over = true;
          stream.destroy();
          break;
        }
      }
    } catch (err) {
      scan.fail(reasonOf(err));
      continue;
    }
    if (over) scan.fail("grew past the per-file bound while being read");
    else scan.end();
  }
}
