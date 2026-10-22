// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/**
 * `varlatch upgrade` and `varlatch self-update` exit 69 (EX_UNAVAILABLE)
 * when GitHub cannot be reached or is overloaded, as the CLI does for its
 * own server, and 1 for any other failed lookup. The real CLI, bundled, with
 * `fetch` replaced before it starts.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-lookup-exit-"));
const bundle = join(dir, "varlatch.cjs");

beforeAll(async () => {
  await build({
    entryPoints: [fileURLToPath(new URL("../src/main.ts", import.meta.url))],
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node22",
    outfile: bundle,
    logLevel: "silent",
  });
  writeFileSync(
    join(dir, "github.mjs"),
    `globalThis.fetch = async () => {
  if (process.env.GITHUB_STUB === "unreachable") throw new TypeError("fetch failed");
  return new Response("", { status: Number(process.env.GITHUB_STUB) });
};
`,
  );
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

function cli(args: string[], github: string): Promise<{ code: number | null; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--import", join(dir, "github.mjs"), bundle, ...args], {
      cwd: dir,
      env: { PATH: process.env.PATH, HOME: dir, VARLATCH_CONFIG_DIR: join(dir, "config"), VARLATCH_ASSISTED: "0", GITHUB_STUB: github },
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("close", (code) => resolve({ code, stderr }));
  });
}

describe("exit status of a failed release lookup", () => {
  for (const command of [["upgrade", "--check", "--dir", dir], ["self-update", "--check"]]) {
    it(`${command[0]}: 69 when GitHub cannot be reached`, async () => {
      const r = await cli(command, "unreachable");
      expect(r.code).toBe(69);
      expect(r.stderr).toContain("Could not reach GitHub");
    });

    it(`${command[0]}: 69 when GitHub answers 502`, async () => {
      expect((await cli(command, "502")).code).toBe(69);
    });

    it(`${command[0]}: 1 when the repository has no release`, async () => {
      const r = await cli(command, "404");
      expect(r.code).toBe(1);
      expect(r.stderr).toContain("No releases found");
    });
  }
});
