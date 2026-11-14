// SPDX-License-Identifier: Apache-2.0
/**
 * The CLIs under test (scripts/conformance/clients.json): released
 * TypeScript CLIs pinned by version, release commit and hash, never
 * "latest". This module holds the pure rules; clients.mjs downloads and
 * verifies, following docs/operations/verify-release.md, and fails closed.
 */
import { VERSION } from "./inventory.mjs";

const SHA256 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const REPOSITORY = /^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/;

/** The asset a release carries for its CLI. */
export const cliAsset = (version) => `varlatch-cli-${version}.cjs`;

/** The signing identity of a release: its own release workflow, at its own tag. */
export const releaseIdentity = (repository, version) =>
  `https://github.com/${repository}/.github/workflows/release.yml@refs/tags/v${version}`;

/** Where a release asset is downloaded from. */
export const releaseAssetUrl = (repository, version, asset) =>
  `https://github.com/${repository}/releases/download/v${version}/${encodeURIComponent(asset)}`;

/** Problems with clients.json's own shape; empty when it is valid. */
export function validateClients(clients) {
  const problems = [];
  if (clients?.schema !== 1) return ["schema: expected 1"];
  if (!REPOSITORY.test(String(clients.repository))) problems.push("repository: expected owner/name");
  if (clients.issuer !== "https://token.actions.githubusercontent.com") problems.push("issuer: expected GitHub's OIDC issuer, https://token.actions.githubusercontent.com");
  if (!/^[a-z0-9.-]+\/[a-z0-9._/-]+$/.test(String(clients.imageSignatures))) problems.push("imageSignatures: expected the registry repository that holds the release images' signatures");
  const cosign = clients.cosign;
  if (!cosign || !VERSION.test(String(cosign.version))) problems.push("cosign.version: expected x.y.z");
  const binaries = Object.entries(cosign?.binaries ?? {});
  if (binaries.length === 0) problems.push("cosign.binaries: expected at least one platform");
  for (const [platform, binary] of binaries) {
    if (!/^[a-z0-9]+-[a-z0-9]+$/.test(platform)) problems.push(`cosign.binaries.${platform}: expected <platform>-<arch>, as Node names them`);
    if (typeof binary?.asset !== "string" || !/^cosign-[a-z0-9-]+$/.test(binary.asset)) problems.push(`cosign.binaries.${platform}: asset must name a cosign release asset`);
    if (!SHA256.test(String(binary?.sha256))) problems.push(`cosign.binaries.${platform}: sha256 must be 64 lower-case hex digits`);
  }
  const clis = Object.entries(clients.cli ?? {});
  if (clis.length === 0) problems.push("cli: expected at least one pinned CLI");
  for (const [version, cli] of clis) {
    if (!VERSION.test(version)) problems.push(`cli.${version}: a CLI is pinned by its x.y.z version, never a name such as latest`);
    if (!COMMIT.test(String(cli?.commit))) problems.push(`cli.${version}: commit must be the release commit's 40-digit hash`);
    if (!SHA256.test(String(cli?.sha256))) problems.push(`cli.${version}: sha256 must be 64 lower-case hex digits`);
  }
  return problems;
}

/**
 * Parses a SHA256SUMS file (`<hash>  <name>`, or `<hash> *<name>`). A line
 * in any other form makes the whole file unusable: it throws.
 */
export function parseSha256Sums(text) {
  const entries = [];
  for (const [n, raw] of text.split("\n").entries()) {
    const line = raw.replace(/\r$/, "");
    if (line === "") continue;
    const m = /^([0-9a-f]{64}) [ *](.+)$/.exec(line);
    if (!m) throw new Error(`SHA256SUMS line ${n + 1} is not "<sha256>  <name>"`);
    entries.push({ sha256: m[1], name: m[2] });
  }
  return entries;
}

/**
 * Why a downloaded asset cannot be used; empty when it can. The signed
 * SHA256SUMS must list it exactly once, with the hash the download has, and
 * that hash must be the one clients.json pins (when it pins one: a release
 * target's assets are trusted through the signature alone).
 */
export function assetProblems({ entries, asset, actual, pinned }) {
  const listed = entries.filter((e) => e.name === asset);
  if (listed.length === 0) return [`SHA256SUMS has no entry for ${asset}`];
  if (listed.length > 1) return [`SHA256SUMS lists ${asset} ${listed.length} times`];
  const problems = [];
  if (listed[0].sha256 !== actual) problems.push(`${asset} has sha256 ${actual}, but SHA256SUMS lists ${listed[0].sha256}`);
  if (pinned !== undefined && actual !== pinned) problems.push(`${asset} has sha256 ${actual}, but clients.json pins ${pinned}`);
  return problems;
}

/**
 * Why a CLI's `--version` output does not show the requested version; null
 * when it does. A release prints `varlatch <version> (migration <n>)`.
 */
export function versionProblem(output, version) {
  const first = String(output).trim().split("\n")[0] ?? "";
  const m = /^varlatch (\S+)(?: |$)/.exec(first);
  if (!m) return `--version printed ${JSON.stringify(first.slice(0, 120))}, not "varlatch <version> ..."`;
  if (m[1] !== version) return `--version reports ${m[1]}, not the requested ${version}`;
  return null;
}

/** The pinned cosign binary for this machine (Node's platform and arch), or why there is none. */
export function cosignBinaryFor(clients, platform, arch) {
  const key = `${platform}-${arch}`;
  const binary = clients.cosign?.binaries?.[key];
  if (!binary) {
    const known = Object.keys(clients.cosign?.binaries ?? {}).join(", ") || "none";
    throw new Error(`clients.json pins no cosign binary for ${key} (pinned: ${known})`);
  }
  return { key, ...binary, version: clients.cosign.version };
}
