// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { NODE_CHECK_ENV, NODE_SECURITY_FLOOR, nodeRuntimeWarning } from "../src/nodeRuntime.js";

/**
 * The CLI warns on stderr when its Node.js release lacks the security fixes
 * of its line, or its line no longer gets any; stdout and the exit status
 * stay as they were, and the guardrail hook stays quiet.
 */

describe("nodeRuntimeWarning", () => {
  it.each([
    ["22.23.3", "22.23.4"],
    ["22.0.0", "22.23.4"],
    ["24.22.0", "24.22.1"],
    ["24.9.9", "24.22.1"],
    ["26.12.0", "26.12.1"],
    ["26.11.1", "26.12.1"],
  ])("Node.js %s is told to update to %s", (version, floor) => {
    expect(nodeRuntimeWarning(version, {})).toBe(
      `varlatch: Node.js ${version} is missing security fixes; update it to ${floor} or later. VARLATCH_NODE_CHECK=off hides this warning.`,
    );
  });

  it.each(["22.23.4", "22.24.0", "24.22.1", "24.23.0", "26.12.1", "26.13.0", "v26.12.1", "26.12.1-pre"])("Node.js %s has the fixes", (version) => {
    expect(nodeRuntimeWarning(version, {})).toBeNull();
  });

  it.each(["16.20.2", "18.20.8", "20.19.5", "21.7.3", "23.11.1", "25.9.0"])("Node.js %s is on a line without security fixes", (version) => {
    expect(nodeRuntimeWarning(version, {})).toBe(
      `varlatch: Node.js ${version} no longer receives security fixes; use Node.js 22, 24 or 26 ` +
        "(at least 22.23.4, 24.22.1 or 26.12.1). VARLATCH_NODE_CHECK=off hides this warning.",
    );
  });

  it("does not judge a line newer than every listed one", () => {
    expect(nodeRuntimeWarning("27.0.0", {})).toBeNull();
    expect(nodeRuntimeWarning("28.1.0", {})).toBeNull();
  });

  it("does not judge a version it cannot read", () => {
    expect(nodeRuntimeWarning("", {})).toBeNull();
    expect(nodeRuntimeWarning("unknown", {})).toBeNull();
  });

  it("is hidden only by VARLATCH_NODE_CHECK=off", () => {
    expect(NODE_CHECK_ENV).toBe("VARLATCH_NODE_CHECK");
    expect(nodeRuntimeWarning("26.12.0", { VARLATCH_NODE_CHECK: "off" })).toBeNull();
    for (const value of ["", "0", "false", "on", "OFF"]) {
      expect(nodeRuntimeWarning("26.12.0", { VARLATCH_NODE_CHECK: value })).not.toBeNull();
    }
  });

  it("lists the October 2026 security releases as the floor", () => {
    expect(NODE_SECURITY_FLOOR).toEqual({ 22: "22.23.4", 24: "24.22.1", 26: "26.12.1" });
  });
});

describe("the bundled CLI", () => {
  const dir = mkdtempSync(join(tmpdir(), "varlatch-node-runtime-"));
  const bundle = join(dir, "varlatch.cjs");
  // Loaded before the bundle: the CLI then reads this release as its own.
  const vulnerable = join(dir, "node-26.12.0.cjs");

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
    writeFileSync(vulnerable, `Object.defineProperty(process, "versions", { value: { ...process.versions, node: "26.12.0" } });\n`);
    mkdirSync(join(dir, "home"));
  });

  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  interface Result {
    code: number | null;
    stdout: string;
    stderr: string;
  }

  function cli(args: string[], opts: { preload?: string; env?: Record<string, string>; stdin?: string } = {}): Promise<Result> {
    return new Promise((resolve) => {
      const child = spawn(process.execPath, [...(opts.preload ? ["--require", opts.preload] : []), bundle, ...args], {
        cwd: dir,
        env: { PATH: process.env.PATH ?? "", HOME: join(dir, "home"), XDG_CONFIG_HOME: join(dir, "xdg"), VARLATCH_ASSISTED: "0", ...opts.env },
        stdio: ["pipe", "pipe", "pipe"],
      });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
      child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
      child.on("close", (code) => resolve({ code, stdout, stderr }));
      child.stdin.end(opts.stdin ?? "");
    });
  }

  const WARNING =
    "varlatch: Node.js 26.12.0 is missing security fixes; update it to 26.12.1 or later. VARLATCH_NODE_CHECK=off hides this warning.\n";

  it("warns on stderr and leaves stdout and the exit status as they were", async () => {
    const plain = await cli(["version"], { env: { VARLATCH_NODE_CHECK: "off" } });
    expect(plain.code).toBe(0);
    expect(plain.stdout).toMatch(/^varlatch \S+ \(migration \d+\)\n$/);
    expect(plain.stderr).toBe("");

    const warned = await cli(["version"], { preload: vulnerable });
    expect(warned).toEqual({ code: 0, stdout: plain.stdout, stderr: WARNING });
  });

  it("warns once, ahead of a failure's own message, whose exit status is unchanged", async () => {
    const r = await cli(["no-such-command"], { preload: vulnerable });
    expect(r.code).toBe(64);
    expect(r.stderr.startsWith(WARNING)).toBe(true);
    expect(r.stderr.indexOf("varlatch: Node.js")).toBe(r.stderr.lastIndexOf("varlatch: Node.js"));
    expect(r.stderr).toContain("varlatch: unknown command no-such-command");
  });

  it("is quiet with VARLATCH_NODE_CHECK=off", async () => {
    const r = await cli(["version"], { preload: vulnerable, env: { VARLATCH_NODE_CHECK: "off" } });
    expect(r.code).toBe(0);
    expect(r.stderr).toBe("");
  });

  it("keeps the guardrail hook quiet", async () => {
    expect(await cli(["agents", "hook", "--format", "claude"], { preload: vulnerable, stdin: "garbage" })).toEqual({ code: 0, stdout: "", stderr: "" });
  });

  it("says nothing more on this test run's own Node.js than its release calls for", async () => {
    const r = await cli(["version"]);
    expect(r.code).toBe(0);
    const expected = nodeRuntimeWarning(process.versions.node, {});
    expect(r.stderr).toBe(expected === null ? "" : `${expected}\n`);
  });
});
