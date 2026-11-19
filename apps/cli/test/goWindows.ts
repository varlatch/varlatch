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
