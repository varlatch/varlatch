// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";

/**
 * The Windows expectations of the CLI kit (internal docs/design/go-cli.md,
 * slice 5.9a). The kit records on Linux. A case whose recorded outcome
 * names a path below its directory (`{{dir}}/...`) comes out differently on
 * Windows, where both CLIs join paths with backslashes; for exactly those
 * cases the TypeScript recorder, run on Windows, records a second
 * expectation, kept beside the Linux file under `windows/`, and the Go
 * replay on Windows compares with it. Every other case replays on Windows
 * against its Linux recording, the directory inside a JSON string included
 * (the replay maps its escaped form back to `{{dir}}`, goKit.ts's
 * unfillDir).
 *
 * Recorded by the `windows-expectations` workflow on windows-latest (a
 * pull request labelled `record-windows`, or by hand), which uploads them
 * as an artifact; commit what it gives. The Go test
 * TestWindowsExpectationsComplete fails on every platform when a case that
 * needs one has none, or one is left for a case that no longer does.
 */

/** Whether this process records the Windows expectations (only on Windows). */
export const RECORD_WINDOWS = process.platform === "win32";

/** A path below a placeholder directory: what makes a case need a Windows expectation. The Go side's pathBelowDir is the same. */
export const PATH_BELOW_DIR = /\{\{(dir|home)\}\}[/\\]/;

/** Where the Windows expectations of a recorded file are: `windows/<name>` beside it. */
export function windowsFile(linuxFile: string): string {
  return join(dirname(linuxFile), "windows", basename(linuxFile));
}

/** The committed Linux recording, parsed. */
export function readRecording<T>(linuxFile: string): T {
  return JSON.parse(readFileSync(linuxFile, "utf8")) as T;
}

/** The comment every Windows expectations file carries. */
export const WINDOWS_COMMENT =
  "Windows expectations, recorded from the TypeScript CLI on Windows by the windows-expectations workflow (apps/cli/test/goWindows.ts); do not edit. Only the cases whose Linux recording names a path below their directory are here.";

/**
 * The order of the varlatch skill's files in `agents install`'s changes is
 * the order the TypeScript CLI walks the skill directories in: on Windows
 * it varies between runs, while the Go CLI lists them sorted (go/README.md,
 * `skill-order`). So a Windows recording keeps each run of consecutive
 * skill-file entries sorted, and the Go replay compares them as a multiset
 * (go/cmd/varlatch/internal/transcript's SkillOrderFree, the same rule).
 */
const SKILL_FILE = /\.(agents|claude)[/\\]skills[/\\]varlatch[/\\]/;

/** Whether a path or a line names one of the skill's files. */
export const namesSkillFile = (s: string): boolean => SKILL_FILE.test(s);

/** items with each maximal run of consecutive items that name a skill file sorted by key (code-unit order). */
export function sortSkillRuns<T>(items: readonly T[], named: (item: T) => boolean, key: (item: T) => string): T[] {
  const out = [...items];
  for (let i = 0; i < out.length; ) {
    if (!named(out[i] as T)) {
      i++;
      continue;
    }
    let j = i;
    while (j < out.length && named(out[j] as T)) j++;
    const run = out.slice(i, j).sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0));
    out.splice(i, j - i, ...run);
    i = j;
  }
  return out;
}

const changePath = (e: unknown): string => {
  const path = e && typeof e === "object" ? (e as { path?: unknown }).path : undefined;
  return typeof path === "string" ? path : "";
};

/** A changes list with each run of entries whose path names a skill file sorted by path. */
export const sortSkillChanges = (list: readonly unknown[]): unknown[] => sortSkillRuns(list, (e) => namesSkillFile(changePath(e)), changePath);

function sortChanges(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortChanges);
  if (v && typeof v === "object") {
    return Object.fromEntries(
      Object.entries(v).map(([k, value]) => {
        const sorted = sortChanges(value);
        return [k, k === "changes" && Array.isArray(sorted) ? sortSkillChanges(sorted) : sorted];
      }),
    );
  }
  return v;
}

/**
 * text with the skill's files in sorted runs: in a JSON document exactly
 * as JSON.stringify(doc, null, 2) and a newline write it, each run of
 * "changes" entries whose path names a skill file; in any other text, each
 * run of consecutive lines that name one. Everything else keeps its bytes.
 */
export function skillOrderFree(text: string): string {
  if (text.startsWith("{")) {
    try {
      const doc: unknown = JSON.parse(text);
      if (`${JSON.stringify(doc, null, 2)}\n` === text) return `${JSON.stringify(sortChanges(doc), null, 2)}\n`;
    } catch {
      // not JSON: lines
    }
  }
  return sortSkillRuns(text.split("\n"), namesSkillFile, (l) => l).join("\n");
}
