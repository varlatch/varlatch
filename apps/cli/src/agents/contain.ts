// SPDX-License-Identifier: Apache-2.0
import { randomBytes } from "node:crypto";
import { chmodSync, closeSync, constants, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readdirSync, renameSync, rmdirSync, rmSync, type Stats, statSync, writeSync } from "node:fs";
import { dirname, join, normalize, relative, sep } from "node:path";

/**
 * Containment for `varlatch agents install`: install, check and remove never
 * read, write or remove anything through a symbolic link below the scope's
 * root (the project root, or the home directory). A directory on the way to
 * a file the run would read, write, remove or prune that is a link refuses
 * the whole run before anything is touched (78), and each write and removal
 * checks again just before it. A link as the last component is left as it
 * is (the human gets the edit), as before.
 *
 * A file is replaced, never written in place: a temporary file next to it,
 * written while only its owner can read it, synced, given the replaced
 * file's mode, then renamed over it. A file with several names (an AGENTS.md
 * and the CLAUDE.md that is it) stays one file; a file with a name the CLI
 * cannot see is refused before anything changes.
 */

/** Thrown for a refusal; install.ts turns it into an AgentsInstallError (78). */
export class ContainmentError extends Error {
  override name = "ContainmentError";
}

/** The first component of `rel`, a path below `root`, that is a symbolic link (or a junction); null when there is none, or the path stops existing. */
export function linkBelow(root: string, rel: string): string | null {
  let current = "";
  for (const part of normalize(rel).split(sep)) {
    if (part === "" || part === ".") continue;
    current = current === "" ? part : join(current, part);
    let isLink: boolean;
    try {
      isLink = lstatSync(join(root, current)).isSymbolicLink();
    } catch {
      return null;
    }
    if (isLink) return current;
  }
  return null;
}

/** The refusal of a run, found before it touched anything. */
export function linkRefusal(link: string, filesByHand: string[] = []): ContainmentError {
  const message =
    `${link.split(sep).join("/")} is a symbolic link, so the CLI does not read, write or remove anything through it; ` +
    "nothing was changed. Replace it with a directory, then run this again";
  if (filesByHand.length === 0) return new ContainmentError(message);
  return new ContainmentError(`${message}, or remove these files by hand:\n  ${filesByHand.join("\n  ")}`);
}

/** Refuses when a directory on the way to `rel` (inclusive) is a link. */
function checkBelow(root: string, rel: string): void {
  const link = linkBelow(root, rel);
  if (link !== null) {
    throw new ContainmentError(
      `${link.split(sep).join("/")} is a symbolic link, so the CLI does not read, write or remove anything through it; ` +
        "replace it with a directory, then run this again",
    );
  }
}

/** The names install itself may give one file: an AGENTS.md and the CLAUDE.md that is that file. */
const ALIAS_CANDIDATES = ["AGENTS.md", "CLAUDE.md", join(".claude", "CLAUDE.md")];

function hardLinkRefusal(rel: string, nothingChanged: boolean): ContainmentError {
  const what = nothingChanged ? "nothing was changed" : "the CLI stopped before changing it";
  return new ContainmentError(
    `${rel.split(sep).join("/")} has another name (a hard link) the CLI cannot see, so ${what}; replace it with a plain copy of itself, then run this again`,
  );
}

/**
 * The names of the regular file `rel` inside `root`, `rel` first, and
 * whether they are all its names: every name must be one of the alias
 * candidates found in the root, or there is a name the CLI cannot see.
 */
function aliases(root: string, rel: string): { names: string[]; complete: boolean } {
  const info = lstatSync(join(root, rel));
  const names = [rel];
  if (info.nlink <= 1) return { names, complete: true };
  for (const candidate of ALIAS_CANDIDATES) {
    if (candidate === rel) continue;
    try {
      const other = lstatSync(join(root, candidate));
      if (other.isFile() && other.dev === info.dev && other.ino === info.ino) names.push(candidate);
    } catch {
      // Not there.
    }
  }
  return { names, complete: names.length === info.nlink };
}

/** Refuses, before anything changes, a file the run would change that has a name the CLI cannot see. */
export function checkHardLinks(root: string, rel: string): void {
  let regular = false;
  try {
    regular = lstatSync(join(root, rel)).isFile();
  } catch {
    return;
  }
  if (!regular) return;
  let complete = false;
  try {
    complete = aliases(root, rel).complete;
  } catch {
    complete = false;
  }
  if (!complete) throw hardLinkRefusal(rel, true);
}

function tempName(rel: string): string {
  return join(dirname(rel), `.${rel.split(sep).pop() ?? ""}.varlatch-${randomBytes(6).toString("hex")}.tmp`);
}

/**
 * Writes `data` into a new temporary file next to `rel`. A replacement is
 * created 0600, so that nobody else can read it while it is written, and
 * given `mode` once synced; a new file is created with the default mode less
 * the umask, as writeFileSync would.
 */
function writeTemp(root: string, rel: string, data: string, mode: number | null): string {
  const tmp = tempName(rel);
  const path = join(root, tmp);
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, mode === null ? 0o666 : 0o600);
  try {
    try {
      const bytes = Buffer.from(data, "utf8");
      let written = 0;
      while (written < bytes.length) written += writeSync(fd, bytes, written, bytes.length - written);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    if (mode !== null) chmodSync(path, mode);
  } catch (err) {
    rmSync(path, { force: true });
    throw err;
  }
  return tmp;
}

/**
 * Replaces `rel` (below `root`) with `data`. A file with several names is
 * replaced only when every name is one install gives it: each name is
 * renamed onto the new file, so they stay one file. A crash between those
 * renames leaves each name complete, one old and one new.
 */
export function writeContained(root: string, rel: string, data: string): void {
  checkBelow(root, dirname(rel));
  const dir = dirname(rel);
  if (dir !== ".") mkdirSync(join(root, dir), { recursive: true });
  // The directories just made are real ones, but check again what existed.
  checkBelow(root, dir);
  let mode: number | null = null;
  let names = [rel];
  let info: Stats | null = null;
  try {
    info = lstatSync(join(root, rel));
  } catch {
    info = null;
  }
  if (info?.isFile()) {
    mode = info.mode & 0o7777;
    let found: { names: string[]; complete: boolean };
    try {
      found = aliases(root, rel);
    } catch {
      throw hardLinkRefusal(rel, false);
    }
    if (!found.complete) throw hardLinkRefusal(rel, false);
    names = found.names;
  }
  const tmp = writeTemp(root, rel, data, mode);
  try {
    renameSync(join(root, tmp), join(root, rel));
  } catch (err) {
    rmSync(join(root, tmp), { force: true });
    throw err;
  }
  for (const alias of names.slice(1)) {
    const link = tempName(alias);
    linkSync(join(root, rel), join(root, link));
    try {
      renameSync(join(root, link), join(root, alias));
    } catch (err) {
      rmSync(join(root, link), { force: true });
      throw err;
    }
  }
}

/** Removes the file `rel` (below `root`), if it is there. */
export function removeContained(root: string, rel: string): void {
  checkBelow(root, dirname(rel));
  rmSync(join(root, rel), { force: true });
}

/** Removes the empty directory `rel` (below `root`), never a link. */
function rmdirContained(root: string, rel: string): void {
  checkBelow(root, rel);
  let isDir = false;
  try {
    isDir = lstatSync(join(root, rel)).isDirectory();
  } catch {
    return;
  }
  if (isDir) rmdirSync(join(root, rel));
}

/** After --remove: the emptied directories under `base` go, and their parents if nothing else is in them; no link below the root is followed or removed. */
export function pruneEmptyContained(root: string, base: string): void {
  const prune = (rel: string): void => {
    const dir = join(root, rel);
    try {
      if (!lstatSync(dir).isDirectory()) return;
    } catch {
      return;
    }
    for (const entry of readdirSync(dir, { withFileTypes: true })) if (entry.isDirectory()) prune(join(rel, entry.name));
    if (readdirSync(dir).length === 0) rmdirContained(root, rel);
  };
  prune(base);
  for (let dir = dirname(join(root, base)); dir !== root && dir.startsWith(root); dir = dirname(dir)) {
    try {
      statSync(dir);
    } catch {
      break;
    }
    if (readdirSync(dir).length > 0) break;
    rmdirContained(root, relative(root, dir));
  }
}
