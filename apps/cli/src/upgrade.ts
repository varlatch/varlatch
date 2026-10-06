// SPDX-License-Identifier: Apache-2.0
import { createBackup, verifyBackup } from "./backup.js";
import { EMBEDDED_RELEASE, releaseSchema } from "@varlatch/backup";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, createWriteStream, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { pipeline } from "node:stream/promises";
import { dirname, join } from "node:path";
import type { GateVerdict } from "./doctor.js";
import { parseDotenv } from "./dotenv.js";
import { createInterface } from "node:readline/promises";

/**
 * `varlatch upgrade` — the canonical compose upgrade (ADR-0019 §19c) as one
 * command: fetch the target release's digest-pinned compose + manifest from
 * GitHub, back up both databases, gate on a verified KEK backup, apply, pull,
 * up (varlatch-migrate gates varlatchd), wait for /readyz, reconcile the
 * Application Plane, and complete only when the target release's upgrade
 * gate passes (ADR-0035 D11); until then the release stays pending and a
 * rerun resumes. Forward-only: downgrades are refused; rollback is
 * restore-from-backup with the previous release set (printed at the end).
 *
 * This is operator tooling for the host that runs the stack — it drives
 * `docker compose` and never talks to the Varlatch API, so it needs no login.
 */

export class UpgradeError extends Error {}

export interface ReleaseManifest {
  schemaVersion: number;
  migrationVersion?: number;
  version: string;
  apiMajor: number;
  images: Record<string, { tag: string | null; digest: string | null }>;
}

export interface UpgradeOptions {
  version?: string | undefined;
  dir: string;
  repo: string;
  yes: boolean;
  backupDir?: string | undefined;
  backupArgs?: string[];
  skipDbBackup: boolean;
  kekBackupVerified: boolean;
  checkOnly: boolean;
  /** Local artifact directory, also used by release-transition integration tests. */
  releaseDir?: string;
  /** The completion check (tests); defaults to the target release's `doctor --gate`. */
  gate?: (dir: string) => Promise<GateRun>;
}

export interface GateRun {
  verdict: GateVerdict;
  /** The target release's CLI, extracted from its varlatchd image (a temporary file), if it has one. */
  cli: string | null;
}

export const DEFAULT_RELEASE_REPO = "varlatch/varlatch";

const MANIFEST_FILE = "varlatch-release.json";
const COMPOSE_FILE = "docker-compose.yml";
const RELEASE_COMPOSE_ASSET = "docker-compose.release.yml";
/**
 * Ingress overlays (ADR-0035 D6) are released with each version. An upgrade
 * refreshes the ones this installation has; releases before they were
 * published leave them as they are.
 */
export const OVERLAY_ASSETS = ["docker-compose.tailscale.yml", "docker-compose.tailnet-https.yml", "tailscale-serve.json", "docker-compose.caddy.yml", "Caddyfile"];

/** Semver-ish compare: negative when a < b. Prereleases sort before their
    release (0.7.0-rc1 < 0.7.0); prerelease-vs-prerelease compares lexically. */
export function compareVersions(a: string, b: string): number {
  const parse = (v: string): { nums: number[]; pre: string } => {
    const [core = "", ...pre] = v.replace(/^v/, "").split("-");
    return { nums: core.split(".").map((n) => Number(n) || 0), pre: pre.join("-") };
  };
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < Math.max(pa.nums.length, pb.nums.length); i++) {
    const d = (pa.nums[i] ?? 0) - (pb.nums[i] ?? 0);
    if (d !== 0) return d;
  }
  if (pa.pre === pb.pre) return 0;
  if (pa.pre === "") return 1;
  if (pb.pre === "") return -1;
  return pa.pre < pb.pre ? -1 : 1;
}

export function parseManifest(text: string, source: string): ReleaseManifest {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new UpgradeError(`${source}: not valid JSON`);
  }
  const m = parsed as ReleaseManifest;
  if (m.schemaVersion !== 1 || typeof m.version !== "string" || typeof m.images !== "object") {
    throw new UpgradeError(`${source}: unrecognized manifest (schemaVersion ${String(m.schemaVersion)})`);
  }
  return m;
}

export interface GithubAsset {
  name: string;
  url: string;
}
export interface GithubRelease {
  tag_name: string;
  html_url: string;
  assets: GithubAsset[];
}

function githubHeaders(accept: string): Record<string, string> {
  const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  return {
    accept,
    "user-agent": "varlatch-cli",
    "x-github-api-version": "2022-11-28",
    ...(token ? { authorization: `Bearer ${token}` } : {}),
  };
}

export async function fetchRelease(repo: string, version: string | undefined): Promise<GithubRelease> {
  const path = version ? `releases/tags/v${version.replace(/^v/, "")}` : "releases/latest";
  const url = `https://api.github.com/repos/${repo}/${path}`;
  const res = await fetch(url, { headers: githubHeaders("application/vnd.github+json") });
  if (res.status === 404) {
    throw new UpgradeError(
      version
        ? `No release v${version} in ${repo}.`
        : `No releases found in ${repo}. Private repository? Set GITHUB_TOKEN.`,
    );
  }
  if (!res.ok) throw new UpgradeError(`GitHub API ${res.status} for ${url}`);
  return (await res.json()) as GithubRelease;
}

async function downloadAsset(release: GithubRelease, name: string): Promise<string> {
  if (!release.assets.some((a) => a.name === name)) {
    throw new UpgradeError(
      `Release ${release.tag_name} has no ${name} asset — it predates the release-set tooling and cannot be applied by varlatch upgrade.`,
    );
  }
  return new TextDecoder().decode(await downloadAssetBytes(release, name));
}

/** A release asset's exact bytes (what SHA256SUMS covers). */
export async function downloadAssetBytes(release: GithubRelease, name: string): Promise<Uint8Array> {
  const asset = release.assets.find((a) => a.name === name);
  if (!asset) throw new UpgradeError(`Release ${release.tag_name} has no ${name} asset.`);
  const res = await fetch(asset.url, { headers: githubHeaders("application/octet-stream") });
  if (!res.ok) throw new UpgradeError(`Downloading ${name} failed (HTTP ${res.status})`);
  return new Uint8Array(await res.arrayBuffer());
}

function compose(dir: string, args: string[], label: string): void {
  console.log(`\n$ docker compose ${args.join(" ")}`);
  const result = spawnSync("docker", ["compose", ...args], { cwd: dir, stdio: "inherit" });
  if (result.error) throw new UpgradeError(`docker not runnable: ${result.error.message}`);
  if (result.status !== 0) throw new UpgradeError(`${label} failed (docker compose exited ${result.status}).`);
}


async function waitForHealthy(dir: string, service: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const result = spawnSync("docker", ["compose", "ps", "--format", "json", service], {
      cwd: dir,
      encoding: "utf8",
    });
    const line = (result.stdout ?? "").trim().split("\n")[0];
    if (line) {
      try {
        const info = JSON.parse(line) as { Health?: string; State?: string };
        if (info.Health === "healthy") return;
        if (info.State === "exited" || info.State === "dead") {
          throw new UpgradeError(`${service} ${info.State ?? "stopped"} during upgrade — inspect: docker compose logs ${service}`);
        }
      } catch (err) {
        if (err instanceof UpgradeError) throw err;
      }
    }
    if (Date.now() > deadline) {
      throw new UpgradeError(`${service} did not become healthy within ${timeoutMs / 1000}s — inspect: docker compose logs ${service}`);
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
}

/** Waits until every long-running service is running and, where it has a healthcheck, healthy. */
async function waitForServices(dir: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const out = spawnSync("docker", ["compose", "ps", "--format", "json"], { cwd: dir, encoding: "utf8" }).stdout ?? "";
    try {
      const { parseComposePs } = await import("./doctor.js");
      const rows = parseComposePs(out);
      if (rows.length && rows.every((r) => r.State === "running" && (!r.Health || r.Health === "healthy"))) return;
    } catch { /* retry */ }
    await new Promise((r) => setTimeout(r, 3000));
  }
  // Not fatal here: the gate reports which service is not healthy.
}

/**
 * convex-backend's image is the same across releases and its supervisor is a
 * bind-mounted file, so `up -d` keeps the previous supervisor process
 * running: recreate the container when it started before the file changed.
 */
async function restartStaleSupervisor(dir: string): Promise<void> {
  const file = join(dir, "convex-supervisor.cjs");
  const id = spawnSync("docker", ["compose", "ps", "-q", "convex-backend"], { cwd: dir, encoding: "utf8" }).stdout?.trim();
  if (!existsSync(file) || !id) return;
  const startedAt = spawnSync("docker", ["inspect", "--format", "{{.State.StartedAt}}", id], { encoding: "utf8" }).stdout?.trim() ?? null;
  const loaded = spawnSync("docker", ["exec", id, "cat", "/tmp/varlatch-supervisor.sha256"], { encoding: "utf8" }).stdout?.trim() ?? "";
  const hashes = { file: createHash("sha256").update(readFileSync(file)).digest("hex"), loaded: /^[0-9a-f]{64}$/.test(loaded) ? loaded : null };
  const { checkSupervisor } = await import("./doctor.js");
  if (checkSupervisor(statSync(file).mtimeMs, startedAt, hashes)?.status !== "fail") return;
  console.log("\nThe Convex supervisor changed: recreating convex-backend so it runs the new one.");
  compose(dir, ["up", "-d", "--no-deps", "--force-recreate", "convex-backend"], "convex-backend restart");
  await waitForHealthy(dir, "convex-backend", 180_000);
}

/**
 * Copy the CLI out of the image varlatchd runs, through a container that is
 * created but never started. Not out of the running container: `docker cp`
 * from it remounts its read-only secret bind mounts (by default of
 * /dev/null), which a Docker daemon in a user namespace (rootless Docker,
 * Docker inside a sysbox container) is not permitted to do.
 */
function copyReleaseCli(dir: string, cli: string): boolean {
  const id = spawnSync("docker", ["compose", "ps", "-q", "varlatchd"], { cwd: dir, encoding: "utf8" }).stdout?.trim().split("\n")[0];
  const image = id ? spawnSync("docker", ["inspect", "--format", "{{.Image}}", id], { encoding: "utf8" }).stdout?.trim() : "";
  const container = image ? spawnSync("docker", ["create", image], { encoding: "utf8" }).stdout?.trim() : "";
  if (!container) return false;
  try {
    return spawnSync("docker", ["cp", `${container}:/opt/varlatch/varlatch.cjs`, cli], { stdio: "ignore" }).status === 0 && existsSync(cli);
  } finally {
    spawnSync("docker", ["rm", "-v", container], { stdio: "ignore" });
  }
}

/**
 * D11: the target release judges its own completion. Its CLI ships in its
 * varlatchd image; its `doctor --gate` runs here, on the host. An image
 * without one (or an older doctor) falls back to this CLI's gate.
 */
async function releaseGate(dir: string): Promise<GateRun> {
  await waitForServices(dir, 180_000);
  const tmp = mkdtempSync(join(tmpdir(), "varlatch-release-cli-"));
  const cli = join(tmp, "varlatch.cjs");
  if (copyReleaseCli(dir, cli)) {
    const run = spawnSync(process.execPath, [cli, "doctor", "--gate", "--json", "--wait", "30", "--dir", dir], {
      encoding: "utf8", maxBuffer: 16 * 1024 * 1024, timeout: 300_000,
    });
    try {
      const out = run.stdout ?? "";
      const report = JSON.parse(out.slice(out.indexOf("{"))) as { gate?: GateVerdict };
      if (report.gate) return { verdict: report.gate, cli };
    } catch { /* fall back below */ }
  } else {
    rmSync(tmp, { recursive: true, force: true });
  }
  console.log("(The target image carries no CLI with an upgrade gate; using this CLI's.)");
  const { evaluateGate, runDoctor } = await import("./doctor.js");
  return { verdict: evaluateGate(await runDoctor({ dir, waitSeconds: 30 })), cli: existsSync(cli) ? cli : null };
}

async function confirm(question: string, yes: boolean): Promise<boolean> {
  if (yes) return true;
  if (!process.stdin.isTTY) {
    throw new UpgradeError("Not a terminal: pass --yes and supply the backup key file options for non-interactive upgrades.");
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await rl.question(`${question} [y/N] `);
    return answer.trim().toLowerCase() === "y" || answer.trim().toLowerCase() === "yes";
  } finally {
    rl.close();
  }
}

/**
 * The variables the release's Compose file refuses to start without
 * (`${NAME:?...}`) that neither the installation's .env nor the environment
 * sets (#110). Checked before anything changes: once the new file is in
 * place, every `docker compose` command would stop on the missing value.
 */
export function missingComposeVariables(compose: string, dir: string, env: NodeJS.ProcessEnv): string[] {
  const required = new Set([...compose.matchAll(/\$\{([A-Za-z_][A-Za-z0-9_]*):\?/g)].map((m) => m[1] as string));
  if (required.size === 0) return [];
  const envPath = join(dir, ".env");
  let file = new Map<string, string>();
  if (existsSync(envPath)) {
    try {
      file = new Map(parseDotenv(readFileSync(envPath, "utf8")).map((e) => [e.name, e.value]));
    } catch {
      return []; // Compose's own parser decides; the image pull reports it.
    }
  }
  return [...required].filter((name) => !(env[name] || file.get(name)));
}

export async function runUpgrade(opts: UpgradeOptions): Promise<void> {
  const composePath = join(opts.dir, COMPOSE_FILE);
  if (!opts.checkOnly && !existsSync(composePath)) {
    throw new UpgradeError(`No ${COMPOSE_FILE} in ${opts.dir} — run from the compose directory or pass --dir.`);
  }

  const currentManifestPath = join(opts.dir, MANIFEST_FILE);
  const current = existsSync(currentManifestPath)
    ? parseManifest(readFileSync(currentManifestPath, "utf8"), currentManifestPath)
    : undefined;

  console.log(opts.releaseDir
    ? `Reading the release from ${opts.releaseDir}...`
    : `Fetching ${opts.version ? `release v${opts.version}` : "latest release"} from ${opts.repo}...`);
  const release = opts.releaseDir
    ? { tag_name: opts.version ?? "local", html_url: opts.releaseDir, assets: [] }
    : await fetchRelease(opts.repo, opts.version);
  const asset = (name: string) => opts.releaseDir ? Promise.resolve(readFileSync(join(opts.releaseDir, name), "utf8")) : downloadAsset(release, name);
  const optionalAsset = (name: string): Promise<string | null> =>
    opts.releaseDir
      ? Promise.resolve(existsSync(join(opts.releaseDir, name)) ? readFileSync(join(opts.releaseDir, name), "utf8") : null)
      : release.assets.some((a) => a.name === name) ? downloadAsset(release, name) : Promise.resolve(null);
  const targetManifest = await asset(MANIFEST_FILE);
  const target = parseManifest(targetManifest, `${release.tag_name}/${MANIFEST_FILE}`);

  console.log(`\nInstalled: ${current ? current.version : "(unknown — no local varlatch-release.json)"}`);
  console.log(`Target:    ${target.version}  (${release.html_url})`);
  if (current) {
    const cmp = compareVersions(target.version, current.version);
    if (cmp === 0) {
      console.log("Already on this release — nothing to do.");
      return;
    }
    if (cmp < 0) {
      throw new UpgradeError(
        `Refusing downgrade ${current.version} -> ${target.version}: migrations are forward-only (ADR-0019). ` +
          "Rollback = restore the pre-upgrade database backup and run the previous release set with the same KEK.",
      );
    }
    if (target.apiMajor !== current.apiMajor) {
      console.log(`NOTE: API major changes ${current.apiMajor} -> ${target.apiMajor}; re-check API clients after upgrading.`);
    }
  }
  for (const [name, image] of Object.entries(target.images)) {
    console.log(`  ${name.padEnd(15)} ${image.digest ?? image.tag ?? "?"}`);
  }
  if (opts.checkOnly) return;
  const pendingPath = `${currentManifestPath}.pending`;
  if (existsSync(pendingPath)) {
    const pending = parseManifest(readFileSync(pendingPath, "utf8"), pendingPath);
    if (pending.version !== target.version) throw new UpgradeError(`Finish the pending upgrade to ${pending.version} before selecting another release.`);
  }

  const releaseCompose = await asset(RELEASE_COMPOSE_ASSET);
  const missing = missingComposeVariables(releaseCompose, opts.dir, process.env);
  if (missing.length > 0) {
    throw new UpgradeError(
      `${target.version} requires ${missing.join(", ")} in ${join(opts.dir, ".env")}, and it is not set. ` +
        (missing.includes("VARLATCH_PUBLIC_URL") ? "VARLATCH_PUBLIC_URL is the address people open in the browser. " : "") +
        "Set it and run the upgrade again; nothing has changed.",
    );
  }
  const supervisor = await asset("convex-supervisor.cjs");
  const overlays: [string, string][] = [];
  for (const name of OVERLAY_ASSETS) {
    if (!existsSync(join(opts.dir, name))) continue;
    const content = await optionalAsset(name);
    if (content === null) console.log(`Note: ${release.tag_name} ships no ${name}; the installed one is kept.`);
    else overlays.push([name, content]);
  }

  console.log(`\nRead the release notes first: ${release.html_url}`);
  if (!current && !(await confirm("No local release manifest (source-built install?). Continue anyway?", opts.yes))) {
    throw new UpgradeError("Aborted.");
  }
  if (!(await confirm(`Upgrade this installation to ${target.version}?`, opts.yes))) {
    throw new UpgradeError("Aborted.");
  }

  // ADR-0033: assertions and skipped dumps cannot satisfy the upgrade gate.
  if (opts.skipDbBackup || opts.kekBackupVerified) throw new UpgradeError("Legacy backup attestation flags are no longer supported; supply BEK and candidate KEK files.");
  const backupArgs = [...(opts.backupArgs ?? [])];
  const backupTarget = releaseSchema.safeParse(JSON.parse(targetManifest));
  if (!backupTarget.success) throw new UpgradeError("Target release has no machine-checkable backup compatibility manifest");
  const receiptPath = join(opts.dir, `backup.pre-${target.version}.json`);
  const pending = existsSync(pendingPath);
  const legacy = current?.version === "0.7.0" && current.migrationVersion === undefined;
  let archive: string;
  if (pending) {
    if (!existsSync(receiptPath)) throw new UpgradeError("Pending upgrade has no verified archive receipt; do not recapture partially upgraded state");
    archive = (JSON.parse(readFileSync(receiptPath, "utf8")) as { archive: string }).archive;
  } else {
    if (legacy) backupArgs.push("--legacy-release", currentManifestPath);
    archive = await createBackup(backupArgs, opts.dir);
  }
  // Recheck the actual archive on every retry; receipts are paths, not attestations.
  await verifyBackup([...backupArgs, "--in", archive, ...(!legacy && !pending ? ["--record"] : [])], opts.dir, backupTarget.data);
  writeFileSync(receiptPath, JSON.stringify({ archive, targetRelease: target.version }) + "\n", { mode: 0o600 });

  // Apply the release set: keep the previous files for rollback.
  const previousSuffix = `.pre-${target.version}`;
  if (existsSync(composePath) && !existsSync(`${composePath}${previousSuffix}`)) copyFileSync(composePath, `${composePath}${previousSuffix}`);
  if (current && !existsSync(`${currentManifestPath}${previousSuffix}`)) copyFileSync(currentManifestPath, `${currentManifestPath}${previousSuffix}`);
  const supervisorPath = join(opts.dir, "convex-supervisor.cjs");
  if (existsSync(supervisorPath) && !existsSync(`${supervisorPath}${previousSuffix}`)) copyFileSync(supervisorPath, `${supervisorPath}${previousSuffix}`);
  // Written in place (a bind mount follows the inode) and only when it
  // changed, so its modification time tells whether convex-backend is stale.
  if (!existsSync(supervisorPath) || readFileSync(supervisorPath, "utf8") !== supervisor) writeFileSync(supervisorPath, supervisor);
  // Overlays likewise: kept for rollback, written in place, only when changed.
  let caddyfileChanged = false;
  for (const [name, content] of overlays) {
    const path = join(opts.dir, name);
    if (!existsSync(`${path}${previousSuffix}`)) copyFileSync(path, `${path}${previousSuffix}`);
    if (readFileSync(path, "utf8") === content) continue;
    writeFileSync(path, content);
    if (name === "Caddyfile") caddyfileChanged = true;
  }
  writeFileSync(pendingPath, targetManifest);
  writeFileSync(composePath, releaseCompose);
  console.log(`\nApplied release set (previous files kept as *${previousSuffix}).`);

  compose(opts.dir, ["--profile", "deploy", "pull"], "Image pull");
  compose(opts.dir, ["up", "-d", "--remove-orphans"], "Stack start");
  console.log("\nWaiting for varlatchd to become healthy (varlatch-migrate gates it)...");
  await waitForHealthy(opts.dir, "varlatchd", 180_000);
  await restartStaleSupervisor(opts.dir);
  // Caddy does not re-read its Caddyfile by itself (the Tailscale sidecar
  // re-applies its serve config on change).
  if (caddyfileChanged && spawnSync("docker", ["compose", "ps", "-q", "caddy"], { cwd: opts.dir, encoding: "utf8" }).stdout?.trim()) {
    compose(opts.dir, ["exec", "-T", "caddy", "caddy", "reload", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"], "Caddy configuration reload");
  }
  compose(opts.dir, ["run", "--rm", "convex-deploy"], "Application Plane reconciliation");

  // D11: complete only when the gate passes; otherwise stay pending.
  console.log("\nChecking upgrade completion (the target release's upgrade gate)...");
  const { formatGate } = await import("./doctor.js");
  const { verdict, cli } = await (opts.gate ?? releaseGate)(opts.dir);
  try {
    console.log(formatGate(verdict));
    if (!verdict.pass) {
      throw new UpgradeError(
        `The upgrade to ${target.version} is applied but not complete: the gate checks above must pass. ` +
          `It stays pending; fix them and rerun \`varlatch upgrade ${target.version}\` — it resumes without a new backup.`,
      );
    }
    renameSync(pendingPath, currentManifestPath);

    console.log(`\nUpgraded to ${target.version}: every upgrade gate check passed.`);
    console.log("Keep the pre-upgrade backups until you accept the release.");
    console.log(`Recovery archive: ${archive}. Use its BEK and matching Root KEK with a compatible release.`);
    console.log("Never run old binaries on a forward-migrated schema.");
    if (compareVersions(EMBEDDED_RELEASE.version, target.version) !== 0) {
      // A stale host CLI records failed compatibility checks against archives
      // captured by the new release; scheduled backups must use the new CLI.
      const hostCopy = join(opts.dir, `varlatch-cli-${target.version}.cjs`);
      if (cli) {
        copyFileSync(cli, hostCopy);
        chmodSync(hostCopy, 0o755);
      }
      console.log(
        `\nThis CLI is ${EMBEDDED_RELEASE.version}; use ${cli ? hostCopy : `varlatch-cli-${target.version}.cjs from ${release.html_url}`} ` +
          `from now on (replace ${process.argv[1] ?? "your copy"}) — before the next backup run.`,
      );
    }
  } finally {
    if (cli) rmSync(dirname(cli), { recursive: true, force: true });
  }
}
