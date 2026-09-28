// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { cliAsset, detectInstall, expectedDigest, runSelfUpdate, SelfUpdateError, type ReleaseSource } from "../src/selfUpdate.js";

const cli = (version: string) =>
  `#!/usr/bin/env node\n/*! Varlatch CLI. Test build. */\nconsole.log("varlatch ${version} (migration 1)");\n`;
const sha = (text: string) => createHash("sha256").update(text).digest("hex");

/** A release with the single-file CLI and SHA256SUMS (and, optionally, a signature bundle). */
function release(version: string, opts: { body?: string; sums?: string; signed?: boolean } = {}): ReleaseSource {
  const body = opts.body ?? cli(version);
  const files: Record<string, string> = {
    [cliAsset(version)]: body,
    SHA256SUMS: opts.sums ?? `${sha(cli(version))}  ${cliAsset(version)}\n${sha("x")}  other.txt\n`,
  };
  if (opts.signed) files["SHA256SUMS.sigstore.json"] = "{}";
  return {
    release: async (wanted) => ({ version: wanted ?? version, url: `https://example.test/v${version}`, assets: Object.keys(files) }),
    download: async (name) => new TextEncoder().encode(files[name]),
  };
}

/** An installed release build of `version` in a fresh directory outside any checkout. */
function installed(version: string): string {
  const dir = mkdtempSync(join(tmpdir(), "varlatch-self-update-test-"));
  const path = join(dir, "varlatch");
  writeFileSync(path, cli(version), { mode: 0o755 });
  return path;
}

function fakeCosign(exitCode: number): string {
  const path = join(mkdtempSync(join(tmpdir(), "varlatch-cosign-")), "cosign");
  writeFileSync(path, `#!/bin/sh\necho "cosign says no" >&2\nexit ${exitCode}\n`, { mode: 0o755 });
  return path;
}

const base = { repo: "varlatch/varlatch", check: false, json: false, yes: true, allowUnverified: true, current: "0.10.1", log: () => {} };

describe("expectedDigest", () => {
  it("finds the asset's own line, in text or binary mode", () => {
    const sums = `${"a".repeat(64)}  one.cjs\n${"b".repeat(64)} *two.cjs\r\n`;
    expect(expectedDigest(sums, "one.cjs")).toBe("a".repeat(64));
    expect(expectedDigest(sums, "two.cjs")).toBe("b".repeat(64));
  });

  it("fails for an unlisted asset instead of passing it", () => {
    expect(() => expectedDigest(`${"a".repeat(64)}  one.cjs\n`, "one.cjs.evil")).toThrow(SelfUpdateError);
  });
});

describe("detectInstall", () => {
  it("recognizes the release build by its banner", () => {
    expect(detectInstall(installed("0.10.1"))).toBe("release");
  });

  it("treats a build inside a checkout as source, banner or not", () => {
    const repo = mkdtempSync(join(tmpdir(), "varlatch-checkout-"));
    mkdirSync(join(repo, ".git"));
    mkdirSync(join(repo, "dist"));
    writeFileSync(join(repo, "dist", "varlatch.cjs"), cli("0.10.1"));
    expect(detectInstall(join(repo, "dist", "varlatch.cjs"))).toBe("source");
  });

  it("does not claim other files", () => {
    const path = installed("0.10.1");
    writeFileSync(path, "#!/bin/sh\necho hi\n");
    expect(detectInstall(path)).toBe("unknown");
    expect(detectInstall("/nonexistent/varlatch")).toBe("unknown");
  });
});

describe("runSelfUpdate", () => {
  it("--check reports the latest release without touching the file", async () => {
    const path = installed("0.10.1");
    const lines: string[] = [];
    const status = await runSelfUpdate({ ...base, check: true, json: true, script: path, source: release("0.11.0"), log: (l) => lines.push(l) });
    expect(status).toMatchObject({ current: "0.10.1", latest: "0.11.0", updateAvailable: true, install: "release" });
    expect(JSON.parse(lines[0] ?? "")).toMatchObject({ latest: "0.11.0", releaseUrl: "https://example.test/v0.11.0" });
    expect(readFileSync(path, "utf8")).toBe(cli("0.10.1"));
  });

  it("replaces the CLI with a verified release and leaves no temporary file", async () => {
    const path = installed("0.10.1");
    await runSelfUpdate({ ...base, script: path, source: release("0.11.0") });
    expect(readFileSync(path, "utf8")).toBe(cli("0.11.0"));
    expect(statSync(path).mode & 0o777).toBe(0o755);
    expect(readdirSync(join(path, ".."))).toEqual(["varlatch"]);
  });

  it("replaces a symlink on PATH instead of writing through it", async () => {
    const target = installed("0.10.1");
    const link = join(mkdtempSync(join(tmpdir(), "varlatch-bin-")), "varlatch");
    symlinkSync(target, link);
    await runSelfUpdate({ ...base, script: link, source: release("0.11.0") });
    expect(readFileSync(link, "utf8")).toBe(cli("0.11.0"));
    expect(readFileSync(target, "utf8")).toBe(cli("0.10.1"));
  });

  it("refuses a file that does not match SHA256SUMS", async () => {
    const path = installed("0.10.1");
    const tampered = release("0.11.0", { body: cli("0.11.0") + "// extra\n" });
    await expect(runSelfUpdate({ ...base, script: path, source: tampered })).rejects.toThrow(/does not match SHA256SUMS/);
    expect(readFileSync(path, "utf8")).toBe(cli("0.10.1"));
  });

  it("refuses a CLI that SHA256SUMS does not list", async () => {
    const path = installed("0.10.1");
    const unlisted = release("0.11.0", { sums: `${sha("x")}  other.txt\n` });
    await expect(runSelfUpdate({ ...base, script: path, source: unlisted })).rejects.toThrow(/does not list/);
  });

  it("refuses a build that reports a different version", async () => {
    const path = installed("0.10.1");
    const body = cli("0.9.0");
    const wrong = release("0.11.0", { body, sums: `${sha(body)}  ${cliAsset("0.11.0")}\n` });
    await expect(runSelfUpdate({ ...base, script: path, source: wrong })).rejects.toThrow(/reports version 0\.9\.0/);
    expect(readFileSync(path, "utf8")).toBe(cli("0.10.1"));
  });

  it("with --yes, needs --allow-unverified when the signature is not checked", async () => {
    const path = installed("0.10.1");
    await expect(runSelfUpdate({ ...base, allowUnverified: false, script: path, source: release("0.11.0") }))
      .rejects.toThrow(/carries none.*--allow-unverified/);
    await expect(runSelfUpdate({ ...base, allowUnverified: false, script: path, source: release("0.11.0", { signed: true }), cosign: "/nonexistent/cosign" }))
      .rejects.toThrow(/cosign is not installed/);
    expect(readFileSync(path, "utf8")).toBe(cli("0.10.1"));
  });

  it("installs a signed release once cosign verifies it, and never when it does not", async () => {
    const path = installed("0.10.1");
    await expect(runSelfUpdate({ ...base, allowUnverified: true, script: path, source: release("0.11.0", { signed: true }), cosign: fakeCosign(1) }))
      .rejects.toThrow(/does NOT verify/);
    expect(readFileSync(path, "utf8")).toBe(cli("0.10.1"));
    await runSelfUpdate({ ...base, allowUnverified: false, script: path, source: release("0.11.0", { signed: true }), cosign: fakeCosign(0) });
    expect(readFileSync(path, "utf8")).toBe(cli("0.11.0"));
  });

  it("asks before installing, and a no leaves the CLI as it was", async () => {
    const path = installed("0.10.1");
    const questions: string[] = [];
    await runSelfUpdate({ ...base, yes: false, script: path, source: release("0.11.0"), confirm: async (q) => { questions.push(q); return false; } });
    expect(questions).toHaveLength(1);
    expect(readFileSync(path, "utf8")).toBe(cli("0.10.1"));
  });

  it("does nothing when up to date and refuses to go back", async () => {
    const path = installed("0.10.1");
    const lines: string[] = [];
    await runSelfUpdate({ ...base, script: path, source: release("0.10.1"), log: (l) => lines.push(l) });
    expect(lines).toEqual(["varlatch 0.10.1 is up to date."]);
    await expect(runSelfUpdate({ ...base, script: path, source: release("0.10.0") })).rejects.toThrow(/older 0\.10\.0/);
  });

  it("refuses a source checkout and names what to do instead", async () => {
    const repo = mkdtempSync(join(tmpdir(), "varlatch-checkout-"));
    mkdirSync(join(repo, ".git"));
    writeFileSync(join(repo, "main.js"), "");
    await expect(runSelfUpdate({ ...base, script: join(repo, "main.js"), source: release("0.11.0") })).rejects.toThrow(/source checkout.*git pull/);
  });
});
