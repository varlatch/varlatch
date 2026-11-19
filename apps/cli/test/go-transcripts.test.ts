// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TRANSCRIPT_DIR, bundleCli, recordArea, writeOrCompare } from "./goKit.js";
import { AREAS } from "./goTranscriptCases.js";
import { RECORD_WINDOWS } from "./goWindows.js";

/**
 * The Go CLI's transcripts (internal docs/design/go-cli.md, decision 3):
 * each area's cases run against the TypeScript CLI bundled from this
 * checkout, and the recording must equal the file the Go replay reads
 * (go/cmd/varlatch/testdata/transcripts/<area>.json). After a change to the
 * cases, regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/cli exec vitest run test/go-transcripts.test.ts
 *
 * A difference without a change to the cases means the TypeScript CLI
 * changed, which the freeze (ADR-0059 Decision 11) allows only for a
 * security fix: re-record in the pull request that ports it to Go.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-go-transcripts-"));
let bundle = "";

beforeAll(async () => {
  bundle = await bundleCli(dir);
}, 120_000);

afterAll(() => rmSync(dir, { recursive: true, force: true }));

// Recorded on Linux; on Windows, go-transcripts-windows.test.ts records the
// cases that differ there.
describe.skipIf(RECORD_WINDOWS)("Go CLI transcripts", () => {
  for (const [area, cases] of Object.entries(AREAS)) {
    it(`${area} is recorded from the TypeScript CLI as it is`, async () => {
      const text = await recordArea(bundle, area, cases);
      const result = writeOrCompare(join(TRANSCRIPT_DIR, `${area}.json`), text);
      expect(result.current, `${area}.json is stale: regenerate it (see this file's comment)`).toBe(true);
    }, 300_000);
  }
});
