// SPDX-License-Identifier: Apache-2.0
import { EMBEDDED_RELEASE } from "@varlatch/backup";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, closeSync, existsSync, mkdtempSync, openSync, readSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, posix, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { compareVersions, downloadAssetBytes, fetchRelease, type GithubRelease } from "./upgrade.js";

/**
 * `varlatch self-update`: replace this CLI with a release's single-file
 * build, `varlatch-cli-<version>.cjs`, the way "Install the operator CLI"
 * (docs/operations/backup.md) does by hand. It checks the signature on
 * SHA256SUMS when the release carries one (with cosign, against this
 * repository's release workflow for the tag), checks the file against
 * SHA256SUMS, shows what it verified, and replaces the file it runs from
 * only after confirmation, with a rename, so there is never a half-written
 * CLI. A CLI run from a source checkout is refused: update the checkout.
 *
 * This touches only the CLI file. An installation on this host upgrades with
 * `varlatch upgrade`, which never replaces the host CLI.
 */

export class SelfUpdateError extends Error {}

const SUMS = "SHA256SUMS";
const SIGNATURE = "SHA256SUMS.sigstore.json";
const OIDC_ISSUER = "https://token.actions.githubusercontent.com";
const BANNER = "/*! Varlatch CLI.";

export const cliAsset = (version: string): string => `varlatch-cli-${version}.cjs`;

/** Where the release comes from; GitHub by default, a fake in tests. */
export interface ReleaseSource {
  release(version: string | undefined): Promise<{ version: string; url: string; assets: string[] }>;
  download(name: string): Promise<Uint8Array>;
}

export function githubSource(repo: string): ReleaseSource {
  let release: GithubRelease | undefined;
  return {
    async release(version) {
      release = await fetchRelease(repo, version);
      return { version: release.tag_name.replace(/^v/, ""), url: release.html_url, assets: release.assets.map((a) => a.name) };
    },
    async download(name) {
      if (!release) throw new SelfUpdateError("No release selected.");
      return await downloadAssetBytes(release, name);
    },
  };
}

/**
 * "release": the single-file build, which this command may replace.
 * "source": run from a checkout (its dist/varlatch.cjs carries the release
 * banner too, so the checkout test comes first). "unknown": anything else.
 */
export type InstallKind = "release" | "source" | "unknown";

export function detectInstall(script: string): InstallKind {
  let real: string;
  try {
    real = realpathSync(script);
  } catch {
    return "unknown";
  }
  for (let dir = dirname(real); ; dir = dirname(dir)) {
    if (existsSync(join(dir, ".git"))) return "source";
    if (dirname(dir) === dir) break;
  }
  const head = Buffer.alloc(512);
  const fd = openSync(real, "r");
  try {
    const n = readSync(fd, head, 0, head.length, 0);
    return head.subarray(0, n).toString("utf8").includes(BANNER) ? "release" : "unknown";
  } finally {
    closeSync(fd);
  }
}

/** The digest SHA256SUMS lists for `asset`; an unlisted asset is an error, never a pass. */
export function expectedDigest(sums: string, asset: string): string {
  for (const line of sums.split("\n")) {
    const m = /^([0-9a-f]{64}) [ *](.+?)\r?$/.exec(line);
    if (m && m[2] === asset) return m[1] as string;
  }
  throw new SelfUpdateError(`${SUMS} does not list ${asset}. Nothing was installed.`);
}

export type SignatureCheck =
  | { state: "verified"; identity: string }
  | { state: "unsigned" }
  | { state: "unchecked"; reason: string };

/** Keyless Sigstore check of SHA256SUMS, as docs/operations/verify-release.md runs it. */
export function verifySignature(dir: string, repo: string, version: string, cosign: string): SignatureCheck {
  const identity = `https://github.com/${repo}/.github/workflows/release.yml@refs/tags/v${version}`;
  const run = spawnSync(cosign, [
    "verify-blob", join(dir, SUMS), "--bundle", join(dir, SIGNATURE),
    "--certificate-identity", identity, "--certificate-oidc-issuer", OIDC_ISSUER,
  ], { encoding: "utf8" });
  if (run.error) return { state: "unchecked", reason: "the release is signed, but cosign is not installed" };
  if (run.status !== 0) {
    throw new SelfUpdateError(`The signature on ${SUMS} does NOT verify for ${identity}. Nothing was installed.\n${(run.stderr ?? "").trim()}`);
  }
  return { state: "verified", identity };
}

export interface SelfUpdateOptions {
  version?: string | undefined;
  repo: string;
  check: boolean;
  json: boolean;
  yes: boolean;
  allowUnverified: boolean;
  /** The file this CLI runs from (process.argv[1]). */
  script: string;
  /** Defaults: this build's embedded release, GitHub, `cosign` on PATH, a terminal prompt. */
  current?: string;
  source?: ReleaseSource;
  cosign?: string;
  confirm?: (question: string) => Promise<boolean>;
  log?: (line: string) => void;
}

export interface SelfUpdateCheck {
  current: string;
  latest: string;
  updateAvailable: boolean;
  releaseUrl: string;
  install: InstallKind;
  path: string;
}

async function ask(question: string): Promise<boolean> {
  if (!process.stdin.isTTY) {
    throw new SelfUpdateError("Not a terminal: pass --yes to update without a prompt.");
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = (await rl.question(`${question} [y/N] `)).trim().toLowerCase();
    return answer === "y" || answer === "yes";
  } finally {
    rl.close();
  }
}

export interface ReplaceTarget {
  platform: NodeJS.Platform;
  /** The Node.js that runs this CLI (process.execPath). */
  execPath: string;
  /** The CLI file being replaced. */
  path: string;
  /** The release being installed. */
  version: string;
}

/**
 * What to say when writing next to the CLI or renaming over it failed with
 * `code`, or null to let the error speak for itself. Windows has no sudo.
 * There, renaming over a file another program has open fails with EPERM, as
 * a missing right does, so that message names both; EBUSY is a file in use.
 */
export function replaceFailure(code: string | undefined, target: ReplaceTarget): string | null {
  const { platform, execPath, path, version } = target;
  const denied = code === "EACCES" || code === "EPERM" || code === "EROFS";
  if (platform !== "win32") {
    if (!denied) return null;
    return (
      `Cannot write ${posix.dirname(path)}. Rerun with the rights to replace ${path}, for example:\n` +
      `  sudo ${execPath} ${path} self-update ${version}`
    );
  }
  if (code === "EBUSY") {
    return `Cannot replace ${path}: another process has it open. Close other varlatch processes and anything else using the file, then run the update again.`;
  }
  if (!denied) return null;
  return (
    `Cannot replace ${path}. Rerun from a terminal with the rights to replace it, such as one run as administrator:\n` +
    `  "${execPath}" "${path}" self-update ${version}\n` +
    `In PowerShell, put "& " before that command. Or install the CLI in a directory you own, such as %LOCALAPPDATA%\\Programs\\Varlatch. ` +
    "If another program has the file open, close it and try again."
  );
}

export async function runSelfUpdate(opts: SelfUpdateOptions): Promise<SelfUpdateCheck> {
  const log = opts.log ?? ((line: string) => console.log(line));
  const current = opts.current ?? EMBEDDED_RELEASE.version;
  const source = opts.source ?? githubSource(opts.repo);
  const path = resolve(opts.script);
  const install = detectInstall(path);

  const release = await source.release(opts.version?.replace(/^v/, ""));
  const status: SelfUpdateCheck = {
    current,
    latest: release.version,
    updateAvailable: compareVersions(release.version, current) > 0,
    releaseUrl: release.url,
    install,
    path,
  };
  if (opts.check) {
    if (opts.json) log(JSON.stringify(status));
    else log(status.updateAvailable ? `varlatch ${release.version} is available (this is ${current}): ${release.url}` : `varlatch ${current} is up to date.`);
    return status;
  }

  if (install === "source") {
    throw new SelfUpdateError(`This CLI runs from a source checkout (${realpathSync(path)}). Update the checkout instead: git pull, then pnpm install && pnpm build.`);
  }
  if (install === "unknown") {
    throw new SelfUpdateError(`${path} is not a Varlatch release build, so self-update will not replace it. Install ${cliAsset(release.version)} from ${release.url}.`);
  }
  const cmp = compareVersions(release.version, current);
  if (cmp === 0) {
    log(`varlatch ${current} is up to date.`);
    return status;
  }
  if (cmp < 0) throw new SelfUpdateError(`Refusing to replace ${current} with the older ${release.version}.`);

  const asset = cliAsset(release.version);
  if (!release.assets.includes(asset) || !release.assets.includes(SUMS)) {
    throw new SelfUpdateError(`Release ${release.version} has no ${asset} with ${SUMS}; releases before 0.9.0 predate the single-file CLI.`);
  }

  const work = mkdtempSync(join(tmpdir(), "varlatch-self-update-"));
  try {
    log(`Downloading ${asset}...`);
    const cli = await source.download(asset);
    const sums = await source.download(SUMS);
    writeFileSync(join(work, SUMS), sums);
    let signature: SignatureCheck = { state: "unsigned" };
    if (release.assets.includes(SIGNATURE)) {
      writeFileSync(join(work, SIGNATURE), await source.download(SIGNATURE));
      signature = verifySignature(work, opts.repo, release.version, opts.cosign ?? "cosign");
    }
    const digest = createHash("sha256").update(cli).digest("hex");
    if (digest !== expectedDigest(new TextDecoder().decode(sums), asset)) {
      throw new SelfUpdateError(`${asset} does not match ${SUMS}. Nothing was installed.`);
    }

    log("");
    log(`  varlatch ${current} -> ${release.version}`);
    log(`  install:   ${path}`);
    log(`  checksum:  ok (${SUMS})`);
    log(`  signature: ${signature.state === "verified" ? `verified (${signature.identity})`
      : signature.state === "unsigned" ? "none: this release carries no signature"
      : `NOT checked: ${signature.reason}`}`);
    log(`  changes:   ${release.url}`);
    log("");
    if (opts.yes) {
      if (signature.state !== "verified" && !opts.allowUnverified) {
        throw new SelfUpdateError(
          `The signature on ${SUMS} was not checked (${signature.state === "unsigned" ? "the release carries none" : signature.reason}). ` +
            "Pass --allow-unverified to rely on the checksum alone. Nothing was installed.",
        );
      }
    } else if (!(await (opts.confirm ?? ask)(`Replace ${path} with ${release.version}?`))) {
      log("Nothing was installed.");
      return status;
    }

    // Only now run the new build: its own version must be the one we asked for.
    const staged = join(work, asset);
    writeFileSync(staged, cli);
    const reported = spawnSync(process.execPath, [staged, "--version"], { encoding: "utf8", timeout: 30_000 }).stdout ?? "";
    const version = /^varlatch (\S+)/.exec(reported.trim())?.[1];
    if (version !== release.version) {
      throw new SelfUpdateError(`The downloaded CLI reports version ${version ?? "(none)"}, not ${release.version}. Nothing was installed.`);
    }

    // Written next to the target and renamed over it: the swap is atomic, and
    // a symlink on PATH is replaced rather than followed.
    const next = join(dirname(path), `.varlatch-self-update-${process.pid}`);
    try {
      writeFileSync(next, cli, { mode: 0o755 });
      chmodSync(next, 0o755);
      renameSync(next, path);
    } catch (err) {
      rmSync(next, { force: true });
      const message = replaceFailure((err as NodeJS.ErrnoException).code, {
        platform: process.platform,
        execPath: process.execPath,
        path,
        version: release.version,
      });
      if (message) throw new SelfUpdateError(message);
      throw err;
    }
    log(`Installed varlatch ${release.version} at ${path}.`);
    log(`If this host runs a Varlatch installation, upgrade it to the same release: varlatch upgrade ${release.version}`);
    return { ...status, current: release.version, updateAvailable: false };
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}
