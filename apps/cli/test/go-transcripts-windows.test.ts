// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TRANSCRIPT_DIR, TRANSCRIPT_SCHEMA, type RecordedCase, type TranscriptFile, bundleCli, recordCase, writeOrCompare } from "./goKit.js";
import { AREAS } from "./goTranscriptCases.js";
import { PATH_BELOW_DIR, RECORD_WINDOWS, WINDOWS_COMMENT, readRecording, skillOrderFree, windowsFile } from "./goWindows.js";

/**
 * The transcripts' Windows expectations (goWindows.ts): on Windows, each
 * area's cases whose Linux recording names a path below their directory
 * are run against the TypeScript CLI bundled from this checkout, and what
 * each did is written to (or compared with)
 * go/cmd/varlatch/testdata/transcripts/windows/<area>.json. Elsewhere it is
 * skipped. The Linux recording must be current first (go-transcripts.test.ts).
 */

/** A Windows expectations file: the area, and each case's id with what it did on Windows. */
export interface WindowsTranscriptFile {
  schema: number;
  comment: string;
  area: string;
  platform: "windows";
  cases: Array<{ id: string; expect: RecordedCase["expect"] }>;
}

const dir = mkdtempSync(join(tmpdir(), "varlatch-go-transcripts-windows-"));
let bundle = "";

beforeAll(async () => {
  if (RECORD_WINDOWS) bundle = await bundleCli(dir);
}, 120_000);

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe.runIf(RECORD_WINDOWS)("Go CLI transcripts, Windows expectations", () => {
  for (const [area, cases] of Object.entries(AREAS)) {
    it(`${area}: the cases that name a path, recorded on Windows`, async () => {
      const linuxFile = join(TRANSCRIPT_DIR, `${area}.json`);
      const linux = readRecording<TranscriptFile>(linuxFile);
      const needed = new Set(linux.cases.filter((c) => PATH_BELOW_DIR.test(JSON.stringify(c.expect))).map((c) => c.id));
      if (needed.size === 0) return;
      const recorded: WindowsTranscriptFile["cases"] = [];
      for (const c of cases) {
        if (!needed.has(c.id)) continue;
        const { expect: outcome } = await recordCase(bundle, c);
        // The skill's files in sorted runs: their order varies between runs on Windows.
        recorded.push({ id: c.id, expect: { ...outcome, stdout: skillOrderFree(outcome.stdout) } });
      }
      const file: WindowsTranscriptFile = { schema: TRANSCRIPT_SCHEMA, comment: WINDOWS_COMMENT, area, platform: "windows", cases: recorded };
      const result = writeOrCompare(windowsFile(linuxFile), `${JSON.stringify(file, null, 2)}\n`);
      expect(result.current, `windows/${area}.json is stale: record it again (goWindows.ts)`).toBe(true);
    }, 600_000);
  }
});
