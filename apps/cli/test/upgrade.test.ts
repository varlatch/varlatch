// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { compareVersions, parseManifest, UpgradeError } from "../src/upgrade.js";

describe("compareVersions", () => {
  it("orders plain releases numerically, not lexically", () => {
    expect(compareVersions("0.10.0", "0.9.0")).toBeGreaterThan(0);
    expect(compareVersions("0.6.0", "0.7.0")).toBeLessThan(0);
    expect(compareVersions("1.0.0", "0.99.99")).toBeGreaterThan(0);
  });

  it("treats equal versions as equal, with or without the v prefix", () => {
    expect(compareVersions("0.7.0", "v0.7.0")).toBe(0);
  });

  it("sorts prereleases before their release", () => {
    expect(compareVersions("0.7.0-rc1", "0.7.0")).toBeLessThan(0);
    expect(compareVersions("0.7.0", "0.7.0-rc1")).toBeGreaterThan(0);
    expect(compareVersions("0.7.0-rc1", "0.7.0-rc2")).toBeLessThan(0);
  });

  it("pads missing segments with zero", () => {
    expect(compareVersions("1.0", "1.0.0")).toBe(0);
    expect(compareVersions("1.0.1", "1.0")).toBeGreaterThan(0);
  });
});

describe("parseManifest", () => {
  const valid = JSON.stringify({
    schemaVersion: 1,
    version: "0.7.0",
    apiMajor: 1,
    images: { varlatchd: { tag: "x:0.7.0", digest: "x@sha256:aa" } },
  });

  it("accepts a schemaVersion 1 manifest", () => {
    const m = parseManifest(valid, "test");
    expect(m.version).toBe("0.7.0");
    expect(m.images["varlatchd"]?.digest).toBe("x@sha256:aa");
  });

  it("rejects non-JSON and unknown schemas with the source in the message", () => {
    expect(() => parseManifest("not json", "here.json")).toThrow(UpgradeError);
    expect(() => parseManifest("not json", "here.json")).toThrow(/here\.json/);
    expect(() => parseManifest(JSON.stringify({ schemaVersion: 2, version: "1", images: {} }), "s")).toThrow(
      /schemaVersion 2/,
    );
  });
});

import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, statSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { vi } from "vitest";
import { runUpgrade } from "../src/upgrade.js";
import * as backup from "../src/backup.js";
import type { Manifest } from "@varlatch/backup";

it("retries a failed pull without claiming success or overwriting rollback files", async () => {
  const dir = mkdtempSync(join(tmpdir(), "varlatch-upgrade-test-"));
  const bin = join(dir, "bin");
  mkdirSync(bin);
  const manifest = (version: string) => JSON.stringify({ schemaVersion: 1, version, apiMajor: 1, migrationVersion: 18, supportedPostgresMajor: 17, supportedRestoreSources: [{ version: "0.6.0", migrationVersion: 18 }], images: {} });
  writeFileSync(join(dir, "varlatch-release.json"), manifest("0.6.0"));
  writeFileSync(join(dir, "docker-compose.yml"), "old compose");
  writeFileSync(join(bin, "docker"), `#!/bin/sh
if [ "$2" = "--profile" ] && [ ! -f fail-once ]; then touch fail-once; exit 1; fi
if [ "$2" = "exec" ]; then head -c 3145728 /dev/zero; fi
if [ "$2" = "ps" ]; then echo '{"Health":"healthy"}'; fi
exit 0
`, { mode: 0o700 });
  vi.stubEnv("PATH", `${bin}:${process.env.PATH}`);
  vi.stubGlobal("fetch", async (input: unknown) => {
    const url = String(input);
    if (url === "https://assets/manifest") return new Response(manifest("0.7.0"));
    if (url === "https://assets/supervisor") return new Response("// supervisor");
    if (url === "https://assets/compose") return new Response("new compose");
    return Response.json({ tag_name: "v0.7.0", html_url: "https://release", assets: [
      { name: "varlatch-release.json", url: "https://assets/manifest" },
      { name: "docker-compose.release.yml", url: "https://assets/compose" },
      { name: "convex-supervisor.cjs", url: "https://assets/supervisor" },
    ] });
  });
  const capture = vi.spyOn(backup, "createBackup").mockResolvedValue(join(dir, "verified.vltbak"));
  const verify = vi.spyOn(backup, "verifyBackup").mockResolvedValue({} as Manifest);
  const blocked = { pass: false, blocking: [{ id: "mirror.catch-up", title: "Dashboard read models (Mirrors)", class: "mandatory" as const, status: "unknown" as const }], advisory: [], outsideGate: [] };
  const gate = vi.fn().mockResolvedValueOnce({ verdict: blocked, cli: null }).mockResolvedValue({ verdict: { ...blocked, pass: true, blocking: [] }, cli: null });
  const opts = { dir, repo: "test/repo", version: "0.7.0", yes: true, skipDbBackup: false, kekBackupVerified: false, checkOnly: false, gate };
  try {
    await expect(runUpgrade(opts)).rejects.toThrow(/Image pull/);
    expect(JSON.parse(readFileSync(join(dir, "varlatch-release.json"), "utf8")).version).toBe("0.6.0");
    expect(existsSync(join(dir, "varlatch-release.json.pending"))).toBe(true);
    expect(capture).toHaveBeenCalledOnce();
    expect(verify).toHaveBeenCalledWith(expect.arrayContaining(["--in", join(dir, "verified.vltbak"), "--record"]), dir, expect.objectContaining({ version: "0.7.0" }));
    verify.mockRejectedValueOnce(new Error("Archive integrity failed"));
    await expect(runUpgrade(opts)).rejects.toThrow(/Archive integrity failed/);
    expect(capture).toHaveBeenCalledOnce();
    expect(existsSync(join(dir, "varlatch-release.json.pending"))).toBe(true);
    // D11: applied but the gate is not passing (unknown blocks) → still pending.
    await expect(runUpgrade(opts)).rejects.toThrow(/applied but not complete/);
    expect(JSON.parse(readFileSync(join(dir, "varlatch-release.json"), "utf8")).version).toBe("0.6.0");
    expect(existsSync(join(dir, "varlatch-release.json.pending"))).toBe(true);
    await runUpgrade(opts);
    expect(gate).toHaveBeenCalledTimes(2);
    expect(capture).toHaveBeenCalledOnce();
    expect(verify).toHaveBeenCalledTimes(4);
    expect(JSON.parse(readFileSync(join(dir, "varlatch-release.json"), "utf8")).version).toBe("0.7.0");
    expect(readFileSync(join(dir, "docker-compose.yml.pre-0.7.0"), "utf8")).toBe("old compose");
    expect(existsSync(join(dir, "varlatch-release.json.pending"))).toBe(false);
  } finally {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
    rmSync(dir, { recursive: true, force: true });
  }
});

it("refreshes the ingress overlays the installation has, keeps the rest, and reloads a changed Caddyfile", async () => {
  const dir = mkdtempSync(join(tmpdir(), "varlatch-upgrade-overlays-"));
  const bin = join(dir, "bin"), release = join(dir, "release");
  mkdirSync(bin); mkdirSync(release);
  const manifest = (version: string) => JSON.stringify({ schemaVersion: 1, version, apiMajor: 1, migrationVersion: 18, supportedPostgresMajor: 17, supportedRestoreSources: [{ version: "0.6.0", migrationVersion: 18 }], images: {} });
  writeFileSync(join(dir, "varlatch-release.json"), manifest("0.6.0"));
  writeFileSync(join(dir, "docker-compose.yml"), "old compose");
  writeFileSync(join(dir, "docker-compose.caddy.yml"), "old caddy overlay");
  writeFileSync(join(dir, "Caddyfile"), "old caddyfile");
  writeFileSync(join(dir, "docker-compose.tailscale.yml"), "installed tailscale overlay");
  // The release ships the Caddy overlay and Caddyfile, not the Tailscale one.
  writeFileSync(join(release, "varlatch-release.json"), manifest("0.7.0"));
  writeFileSync(join(release, "docker-compose.release.yml"), "new compose");
  writeFileSync(join(release, "convex-supervisor.cjs"), "// supervisor");
  writeFileSync(join(release, "docker-compose.caddy.yml"), "new caddy overlay");
  writeFileSync(join(release, "Caddyfile"), "new caddyfile");
  writeFileSync(join(release, "docker-compose.tailnet-https.yml"), "not installed here");
  const calls = join(dir, "calls.log");
  writeFileSync(join(bin, "docker"), `#!/bin/sh
echo "$*" >> ${calls}
if [ "$2" = "ps" ] && [ "$3" = "-q" ]; then echo "container-id"; exit 0; fi
if [ "$2" = "ps" ]; then echo '{"Health":"healthy"}'; fi
exit 0
`, { mode: 0o700 });
  vi.stubEnv("PATH", `${bin}:${process.env.PATH}`);
  vi.spyOn(backup, "createBackup").mockResolvedValue(join(dir, "verified.vltbak"));
  vi.spyOn(backup, "verifyBackup").mockResolvedValue({} as Manifest);
  try {
    await runUpgrade({
      dir, repo: "test/repo", version: "0.7.0", yes: true, skipDbBackup: false, kekBackupVerified: false, checkOnly: false,
      releaseDir: release, gate: async () => ({ verdict: { pass: true, blocking: [], advisory: [], outsideGate: [] }, cli: null }),
    });
    expect(readFileSync(join(dir, "docker-compose.caddy.yml"), "utf8")).toBe("new caddy overlay");
    expect(readFileSync(join(dir, "Caddyfile"), "utf8")).toBe("new caddyfile");
    expect(readFileSync(join(dir, "Caddyfile.pre-0.7.0"), "utf8")).toBe("old caddyfile");
    expect(readFileSync(join(dir, "docker-compose.caddy.yml.pre-0.7.0"), "utf8")).toBe("old caddy overlay");
    // Not in this release: kept as installed. Not installed: not added.
    expect(readFileSync(join(dir, "docker-compose.tailscale.yml"), "utf8")).toBe("installed tailscale overlay");
    expect(existsSync(join(dir, "docker-compose.tailnet-https.yml"))).toBe(false);
    expect(readFileSync(calls, "utf8")).toMatch(/exec -T caddy caddy reload --config \/etc\/caddy\/Caddyfile/);
  } finally {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    rmSync(dir, { recursive: true, force: true });
  }
});

it("refuses before any change when the release requires a variable the installation does not set (#110)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "varlatch-upgrade-required-"));
  const release = join(dir, "release");
  mkdirSync(release);
  const manifest = (version: string) => JSON.stringify({ schemaVersion: 1, version, apiMajor: 1, migrationVersion: 18, supportedPostgresMajor: 17, supportedRestoreSources: [{ version: "0.6.0", migrationVersion: 18 }], images: {} });
  writeFileSync(join(dir, "varlatch-release.json"), manifest("0.6.0"));
  writeFileSync(join(dir, "docker-compose.yml"), "old compose");
  writeFileSync(join(dir, ".env"), "# hand-written\nVARLATCH_WEB_PORT=8787\nVARLATCH_PUBLIC_URL=\n");
  writeFileSync(join(release, "varlatch-release.json"), manifest("0.7.0"));
  writeFileSync(join(release, "docker-compose.release.yml"), "VARLATCH_PUBLIC_URL: ${VARLATCH_PUBLIC_URL:?set it}\nVARLATCH_ISSUER: ${VARLATCH_PUBLIC_URL:?set it}\nX: ${OPTIONAL:-}\n");
  writeFileSync(join(release, "convex-supervisor.cjs"), "// supervisor");
  vi.stubEnv("VARLATCH_PUBLIC_URL", "");
  const capture = vi.spyOn(backup, "createBackup").mockRejectedValue(new Error("backup reached"));
  const opts = { dir, repo: "test/repo", version: "0.7.0", yes: true, skipDbBackup: false, kekBackupVerified: false, checkOnly: false, releaseDir: release };
  try {
    await expect(runUpgrade(opts)).rejects.toThrow(/0\.7\.0 requires VARLATCH_PUBLIC_URL in .*\.env.*nothing has changed/);
    expect(capture).not.toHaveBeenCalled();
    expect(readFileSync(join(dir, "docker-compose.yml"), "utf8")).toBe("old compose");
    expect(existsSync(join(dir, "varlatch-release.json.pending"))).toBe(false);
    // Negative control: once .env sets it, the upgrade proceeds to the backup.
    writeFileSync(join(dir, ".env"), "VARLATCH_PUBLIC_URL=https://vault.example.com\n");
    await expect(runUpgrade(opts)).rejects.toThrow(/backup reached/);
    expect(capture).toHaveBeenCalledOnce();
  } finally {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    rmSync(dir, { recursive: true, force: true });
  }
});
