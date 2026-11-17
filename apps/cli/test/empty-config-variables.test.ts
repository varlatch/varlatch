// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { saveToken } from "@varlatch/context";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/**
 * An empty VARLATCH_CONFIG_DIR or HOME counts as unset: the CLI never keeps
 * or reads its credential store in the working directory because of one.
 */

const dir = mkdtempSync(join(tmpdir(), "varlatch-empty-env-"));
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
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

function cli(args: string[], cwd: string, env: Record<string, string>): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bundle, ...args], { cwd, env: { PATH: process.env.PATH ?? "", ...env }, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

describe("empty configuration variables", () => {
  it("with no home directory at all, a command exits 64 with a message, not a stack trace", async () => {
    const preload = join(dir, "no-home.cjs");
    writeFileSync(preload, 'const os = require("node:os"); os.userInfo = () => { throw new Error("no passwd entry"); };\n');
    const cwd = join(dir, "nohome");
    mkdirSync(cwd, { recursive: true });
    const r = await new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
      const child = spawn(process.execPath, ["--require", preload, bundle, "status"], { cwd, env: { PATH: process.env.PATH ?? "", HOME: "" }, stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
      child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
      child.on("error", reject);
      child.on("close", (code) => resolve({ code, stdout, stderr }));
    });
    expect(r.code).toBe(64);
    expect(r.stderr.trim()).toBe(
      "varlatch: the home directory is unknown: HOME is empty or unset, and the system records none for this user. Set HOME, or VARLATCH_CONFIG_DIR",
    );
    expect(readdirSync(cwd)).toEqual([]);
  });

  it("an empty VARLATCH_CONFIG_DIR does not read a credential store in the working directory", async () => {
    const checkout = join(dir, "checkout");
    mkdirSync(checkout, { recursive: true });
    saveToken("http://127.0.0.1:9", "vl_from_the_checkout", { VARLATCH_CONFIG_DIR: checkout });
    const xdg = join(dir, "xdg");
    const r = await cli(["status", "--json"], checkout, { HOME: join(dir, "home"), XDG_CONFIG_HOME: xdg, VARLATCH_CONFIG_DIR: "" });
    expect(r.stdout).not.toContain("127.0.0.1:9");
    expect(r.stderr).not.toContain("127.0.0.1:9");
  });

  it("agents install --scope user with an empty HOME uses the user's home directory, never the working directory", async () => {
    const cwd = join(dir, "cwd");
    mkdirSync(cwd, { recursive: true });
    const r = await cli(["agents", "install", "--scope", "user", "--check", "--json"], cwd, { HOME: "", XDG_CONFIG_HOME: join(dir, "xdg2") });
    expect(readdirSync(cwd)).toEqual([]);
    // 78 only when the person's own home holds a linked skill directory.
    if (r.code !== 78) expect(JSON.parse(r.stdout).root).toBe(userInfo().homedir);
  });
});
