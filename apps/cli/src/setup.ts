// SPDX-License-Identifier: Apache-2.0
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { doctorExitCode, formatDoctor, runDoctor } from "./doctor.js";

/**
 * `varlatch setup` (ADR-0035 D7): takes a Compose directory (a release bundle
 * or infra/compose) to a running, bootstrapped Installation, asking only for
 * the public URL. Every phase first checks real state, so a rerun after a
 * failed pull, a reboot, or an interrupted enrollment continues where it
 * stopped; nothing already generated is ever regenerated or overwritten.
 */

export class SetupError extends Error {}

export const CONFIG_FILE = "varlatch-install.json";
export const ENV_HEADER = "# Managed by `varlatch setup`";
export const ENV_KEEP = "# --- your additions below this line are kept by setup ---";

/**
 * How browsers reach the Installation (ADR-0035 D6; design note Q6):
 * public — a bundled Caddy with an automatic certificate for a public name;
 * tailnet — the Tailscale sidecar serves https://<machine>.<tailnet>.ts.net;
 * external — the operator's own reverse proxy (also LAN-only installations).
 */
export type Ingress = "public" | "tailnet" | "external";
export const INGRESS: Ingress[] = ["public", "tailnet", "external"];

export interface InstallConfig {
  schemaVersion: 1;
  /**
   * The browser-facing origin: passkey RP ID, token issuer, enroll-link base.
   * With the tailnet ingress it is discovered from the node (empty until then).
   */
  publicUrl: string;
  /** Absent in configurations written before ingress modes: external. */
  ingress?: Ingress;
  /** Tailnet ingress: the Tailscale machine name asked for. */
  tailnetMachine?: string;
  /** Tailnet ingress: the tailnet's MagicDNS suffix, discovered from the node. */
  tailnetName?: string;
  /** Host port of the dashboard (the only service that needs one). */
  webPort: number;
  bindAddress: string;
  /**
   * The browser-facing Convex origin when it is NOT <publicUrl>/convex — an
   * adopted installation that keeps its separate Convex domain (ADR-0035
   * D13: ingress changes are a separate, optional migration).
   */
  convexOrigin?: string;
  /**
   * Where an adopted installation keeps its secret files, by *_HOST_PATH
   * variable (e.g. a Root KEK at /data/varlatch/varlatch-kek). Setup uses
   * these instead of ./secrets and never generates secrets for them.
   */
  secretPaths?: Record<string, string>;
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function validatePublicUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new SetupError(`Not a URL: ${raw}`);
  }
  if (url.pathname !== "/" || url.search || url.hash) throw new SetupError(`Use an origin without path or query: ${raw}`);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && LOOPBACK.has(url.hostname))) {
    throw new SetupError(`${url.origin}: browsers only allow passkeys on HTTPS (or http://localhost for local use)`);
  }
  return url.origin;
}

/** A public name Caddy can obtain a certificate for: https, a DNS name, no port. */
export function validatePublicHost(origin: string): string {
  const url = new URL(origin);
  if (url.protocol !== "https:" || url.port) throw new SetupError(`${origin}: a public domain needs an https:// URL without a port`);
  const host = url.hostname;
  if (LOOPBACK.has(host) || /^[\d.]+$/.test(host) || host.includes(":") || !host.includes(".")) {
    throw new SetupError(`${host}: a public domain needs a DNS name that points to this machine`);
  }
  if (host.endsWith(".ts.net")) throw new SetupError(`${host}: a ts.net name is the tailnet option, not a public domain`);
  return url.origin;
}

/** The Compose files each ingress runs with (written to .env as COMPOSE_FILE). */
export function composeFiles(ingress: Ingress): string[] {
  return ingress === "public" ? ["docker-compose.yml", "docker-compose.caddy.yml"]
    : ingress === "tailnet" ? ["docker-compose.yml", "docker-compose.tailscale.yml", "docker-compose.tailnet-https.yml"]
    : ["docker-compose.yml"];
}
const INGRESS_FILES: Record<Ingress, string[]> = {
  public: ["docker-compose.caddy.yml", "Caddyfile"],
  tailnet: ["docker-compose.tailscale.yml", "docker-compose.tailnet-https.yml", "tailscale-serve.json"],
  external: [],
};

export const TAILNET_MACHINE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

export interface TailscaleStatus {
  BackendState?: string;
  MagicDNSSuffix?: string;
  CertDomains?: string[] | null;
  Self?: { DNSName?: string };
}

/**
 * The tailnet ingress URL from the node's own status — its actual name, which
 * may differ from the one asked for (Tailscale appends a suffix when it is
 * taken). Null while the node has not joined yet.
 */
export function tailnetUrl(status: TailscaleStatus): { url: string; tailnet: string } | null {
  const name = status.Self?.DNSName?.replace(/\.$/, "");
  if (status.BackendState !== "Running" || !name || !status.MagicDNSSuffix) return null;
  if (!(status.CertDomains ?? []).includes(name)) {
    throw new SetupError(
      `HTTPS certificates are not enabled for the tailnet ${status.MagicDNSSuffix}: in the Tailscale admin console, ` +
        "open DNS and enable HTTPS certificates (MagicDNS must be on), then rerun `varlatch setup`.",
    );
  }
  return { url: `https://${name}`, tailnet: status.MagicDNSSuffix };
}

/**
 * Per-service secrets as files (#28), never in .env. Container users read
 * the mounted files, so they are 0644 inside a 0700 directory; the backup
 * key is only ever read by the host CLI.
 */
export const SECRET_FILES: { file: string; bytes: number; mode: number; hostPath?: string }[] = [
  { file: "varlatch-kek", bytes: 32, mode: 0o644, hostPath: "VARLATCH_KEK_HOST_PATH" },
  { file: "backup-key", bytes: 32, mode: 0o600 },
  { file: "postgres-superuser-password", bytes: 24, mode: 0o644, hostPath: "POSTGRES_SUPERUSER_PASSWORD_HOST_PATH" },
  { file: "varlatch-migrate-password", bytes: 24, mode: 0o644, hostPath: "VARLATCH_MIGRATE_PASSWORD_HOST_PATH" },
  { file: "varlatch-runtime-password", bytes: 24, mode: 0o644, hostPath: "VARLATCH_RUNTIME_PASSWORD_HOST_PATH" },
  { file: "convex-db-password", bytes: 24, mode: 0o644, hostPath: "CONVEX_DB_PASSWORD_HOST_PATH" },
  { file: "convex-instance-secret", bytes: 32, mode: 0o644, hostPath: "CONVEX_INSTANCE_SECRET_HOST_PATH" },
];

/** Where a secret file lives: the adopted path if recorded, else ./secrets. */
export function secretPath(dir: string, s: (typeof SECRET_FILES)[number], paths?: Record<string, string>): string {
  const recorded = s.hostPath ? paths?.[s.hostPath] : undefined;
  return resolve(dir, recorded ?? `./secrets/${s.file}`);
}

/**
 * Creates missing secret files for a FRESH installation; never touches
 * existing ones. For an existing installation it generates nothing — not
 * even a backup key, which its backups may already hold elsewhere.
 */
export function ensureSecrets(dir: string, opts: { existingInstallation: boolean; paths?: Record<string, string> }): { created: string[]; kept: string[] } {
  const secretsDir = join(dir, "secrets");
  mkdirSync(secretsDir, { recursive: true, mode: 0o700 });
  chmodSync(secretsDir, 0o700);
  const relevant = SECRET_FILES.filter((s) => !(opts.existingInstallation && s.file === "backup-key"));
  const missing = relevant.filter((s) => !existsSync(secretPath(dir, s, opts.paths)));
  // A fresh Root KEK or password would lock an existing database away.
  if (opts.existingInstallation && missing.length) {
    throw new SetupError(
      `This Compose project already has a database, but ${missing.map((s) => secretPath(dir, s, opts.paths)).join(", ")} ` +
        "is missing. Setup never generates keys or passwords for an existing installation: restore those files " +
        "(or run `varlatch admin backup restore` onto a fresh project).",
    );
  }
  for (const s of missing) writeFileSync(secretPath(dir, s, opts.paths), randomBytes(s.bytes).toString("hex") + "\n", { mode: s.mode });
  return { created: missing.map((s) => s.file), kept: relevant.filter((s) => !missing.includes(s)).map((s) => s.file) };
}

/** The managed .env: derived from the install config; paths only, no secret values. */
export function renderEnv(config: InstallConfig, additions = ""): string {
  const lines = [
    `${ENV_HEADER} from ${CONFIG_FILE} — edit that file and rerun setup.`,
    "# Secrets are files in ./secrets, mounted only into the services that need",
    "# them (#28); nothing secret belongs here.",
    `VARLATCH_PUBLIC_URL=${config.publicUrl}`,
    `CONVEX_CLOUD_ORIGIN=${config.convexOrigin ?? `${config.publicUrl}/convex`}`,
    `CONVEX_SITE_ORIGIN=${config.convexOrigin ?? `${config.publicUrl}/convex`}`,
    "VARLATCH_JWKS_URL=http://varlatchd:8686/.well-known/jwks.json",
    "VARLATCH_CONVEX_URL=http://convex-backend:3210",
    `BIND_ADDRESS=${config.bindAddress}`,
    `VARLATCH_WEB_PORT=${config.webPort}`,
    // One public origin (ADR-0035 D5): varlatchd and Convex need no host port.
    // With a separate Convex origin the operator's port lines stay theirs.
    ...(config.convexOrigin ? [] : ["# One public origin (ADR-0035 D5): varlatchd and Convex need no host port.", "VARLATCHD_PORT=0", "CONVEX_PORT=0"]),
    ...SECRET_FILES.filter((s) => s.hostPath).map((s) => `${s.hostPath}=${config.secretPaths?.[s.hostPath!] ?? `./secrets/${s.file}`}`),
    ...ingressEnv(config),
    ENV_KEEP,
  ];
  return `${lines.join("\n")}\n${additions}`;
}

function ingressEnv(config: InstallConfig): string[] {
  const ingress = config.ingress ?? "external";
  if (ingress === "external") return [];
  const lines = [`# Ingress: ${ingress} (ADR-0035 D6).`, `COMPOSE_FILE=${composeFiles(ingress).join(":")}`];
  if (ingress === "public") lines.push(`VARLATCH_PUBLIC_HOST=${new URL(config.publicUrl).hostname}`);
  else {
    lines.push(
      `VARLATCH_TAILNET_MACHINE=${config.tailnetMachine ?? "varlatch"}`,
      // Required by the overlay before the node has joined and named its tailnet.
      `VARLATCH_TAILNET_NAME=${config.tailnetName ?? "pending.invalid"}`,
      "TS_AUTHKEY_HOST_PATH=./secrets/tailscale-authkey",
    );
  }
  return lines;
}

export type BootstrapAction =
  | { kind: "done"; adminId: string }
  | { kind: "bootstrap" }
  | { kind: "recover"; identityId: string }
  | { kind: "recover-new-admin" };

export interface BootstrapStatus {
  initialized: boolean;
  bootstrapped: boolean;
  admins: { id: string; enabled: boolean; hasPasskey: boolean }[];
}

/** Complete only when an enabled Installation Admin has a passkey (ADR-0035 D7). */
export function bootstrapAction(status: BootstrapStatus): BootstrapAction {
  const ready = status.admins.find((a) => a.enabled && a.hasPasskey);
  if (ready) return { kind: "done", adminId: ready.id };
  if (!status.bootstrapped) return { kind: "bootstrap" };
  const pending = status.admins.find((a) => a.enabled);
  // Bootstrapped, but the enrollment never finished (or bootstrap was
  // headless): host-authorized recovery gives that admin a passkey link.
  return pending ? { kind: "recover", identityId: pending.id } : { kind: "recover-new-admin" };
}

export function parseEnrollLink(output: string): string | null {
  return output.match(/https?:\/\/\S+\/enroll#\S+/)?.[0] ?? null;
}

export type EscrowMethod = "passphrase" | "shamir" | "copy";

export interface SetupOptions {
  dir: string;
  /** Asked interactively when absent; external when only --public-url is given. */
  ingress?: Ingress | undefined;
  publicUrl?: string | undefined;
  /** Tailnet ingress: the Tailscale machine name (default "varlatch"). */
  tailnetMachine?: string | undefined;
  /** Tailnet ingress: a file holding the auth key the node joins with once. */
  tailscaleAuthKeyFile?: string | undefined;
  webPort?: number | undefined;
  /** Print the enrollment link and stop instead of waiting for it. */
  noWait: boolean;
  enrollTimeoutMs: number;
  /** Root KEK escrow method; asked interactively when absent. */
  escrow?: EscrowMethod | undefined;
  escrowPassphraseFile?: string | undefined;
  shares?: number | undefined;
  threshold?: number | undefined;
  /** Non-interactive confirmation that the copies are stored off this host. */
  attest: boolean;
}

export interface CustodyStatus {
  rootKekVersion: number;
  attestations: Record<"root-kek" | "backup-key", { method: string; at: string } | null>;
}

const ATTEST_METHOD: Record<EscrowMethod, string> = { passphrase: "passphrase-escrow", shamir: "shamir-split", copy: "copy" };

/** Escrow is complete only when both recovery keys carry a current attestation (ADR-0035 D7/D9). */
export function escrowComplete(status: CustodyStatus): boolean {
  return Boolean(status.attestations["root-kek"] && status.attestations["backup-key"]);
}

// ---- Docker plumbing -------------------------------------------------------

export function docker(dir: string, args: string[], opts: { stream?: boolean; input?: string } = {}): string {
  const result = spawnSync("docker", ["compose", ...args], {
    cwd: dir,
    encoding: "utf8",
    input: opts.input,
    stdio: [opts.input === undefined ? "ignore" : "pipe", opts.stream ? "inherit" : "pipe", opts.stream ? "inherit" : "pipe"],
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error) throw new SetupError(`docker is not runnable: ${result.error.message}`);
  if (result.status !== 0) {
    throw new SetupError(`docker compose ${args.slice(0, 3).join(" ")} failed (exit ${result.status}). Inspect: docker compose logs`);
  }
  return (result.stdout ?? "").trim();
}

function projectName(dir: string): string {
  const compose = readFileSync(join(dir, "docker-compose.yml"), "utf8");
  return compose.match(/^name:\s*["']?([a-z0-9][a-z0-9_-]*)/m)?.[1] ?? basename(resolve(dir)).toLowerCase().replace(/[^a-z0-9_-]/g, "");
}

function hasDatabaseVolume(dir: string): boolean {
  const result = spawnSync("docker", ["volume", "inspect", `${projectName(dir)}_postgres-data`], { stdio: "ignore" });
  return result.status === 0;
}

export async function waitHealthy(dir: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const out = docker(dir, ["ps", "-a", "--format", "json"]);
    const rows = (out.startsWith("[") ? JSON.parse(out) : out.split("\n").filter(Boolean).map((l) => JSON.parse(l))) as
      { Service: string; State: string; Health?: string; ExitCode?: number }[];
    const failed = rows.find((r) => r.State === "exited" && r.ExitCode !== 0);
    if (failed) throw new SetupError(`${failed.Service} exited with ${failed.ExitCode}. Inspect: docker compose logs ${failed.Service}`);
    const long = rows.filter((r) => r.State !== "exited");
    if (long.length >= 4 && long.every((r) => r.State === "running" && (!r.Health || r.Health === "healthy"))) return;
    if (Date.now() > deadline) {
      const waiting = long.filter((r) => r.Health !== "healthy").map((r) => `${r.Service} (${r.Health || r.State})`);
      throw new SetupError(`Services not healthy after ${timeoutMs / 1000}s: ${waiting.join(", ")}. Inspect: docker compose logs`);
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
}

export const varlatchd = (dir: string, args: string[]) => docker(dir, ["exec", "-T", "varlatchd", "node", "dist/cli.js", ...args]);

async function hidden(question: string): Promise<string> {
  if (!process.stdin.isTTY) throw new SetupError("Not a terminal: pass --escrow-passphrase-file");
  process.stdout.write(question);
  const stdin = process.stdin;
  stdin.setRawMode(true);
  stdin.resume();
  return await new Promise((resolveValue) => {
    let value = "";
    const onData = (chunk: Buffer) => {
      for (const ch of chunk.toString("utf8")) {
        if (ch === "\r" || ch === "\n") {
          stdin.setRawMode(false); stdin.pause(); stdin.off("data", onData); process.stdout.write("\n");
          resolveValue(value); return;
        }
        if (ch === "\u0003") process.exit(130);
        value = ch === "\u007f" ? value.slice(0, -1) : value + ch;
      }
    };
    stdin.on("data", onData);
  });
}

/** Phase 6 (ADR-0035 D7/D9): Root KEK escrow, backup-key custody, attestations. */
export async function escrowPhase(dir: string, opts: Pick<SetupOptions, "escrow" | "escrowPassphraseFile" | "shares" | "threshold" | "attest">): Promise<boolean> {
  const status = () => JSON.parse(varlatchd(dir, ["admin", "custody", "status"])) as CustodyStatus;
  const current = status();
  if (escrowComplete(current)) {
    const a = current.attestations;
    console.log(`  ✓ attested: Root KEK ${a["root-kek"]!.at.slice(0, 10)} (${a["root-kek"]!.method}), backup key ${a["backup-key"]!.at.slice(0, 10)}`);
    return true;
  }
  console.log("  Without the Root KEK and the backup key no archive can be restored. Keep a copy of");
  console.log("  each OFF this host, and apart from each other.");
  let method = opts.escrow;
  if (!method) {
    const answer = (await ask("  Root KEK escrow — [1] passphrase-protected file (recommended)  [2] split among people  [3] I copy it myself: ", "--escrow passphrase|shamir|copy")).trim();
    method = answer === "2" ? "shamir" : answer === "3" ? "copy" : "passphrase";
  }
  if (method === "passphrase") {
    let passphrase: string;
    if (opts.escrowPassphraseFile) {
      passphrase = readFileSync(opts.escrowPassphraseFile, "utf8").replace(/\r?\n$/, "");
    } else {
      passphrase = await hidden("  Escrow passphrase (min 12 characters): ");
      if ((await hidden("  Repeat it: ")) !== passphrase) throw new SetupError("Passphrases differ");
    }
    if (passphrase.length < 12) throw new SetupError("The escrow passphrase needs at least 12 characters");
    // The passphrase reaches only the export process: on stdin into a shell in
    // the container — never container config, a command line, or a file.
    const blob = docker(dir, ["exec", "-T", "varlatchd", "sh", "-c",
      'IFS= read -r VARLATCH_KEK_PASSPHRASE; export VARLATCH_KEK_PASSPHRASE; exec node dist/cli.js admin kek export'],
      { input: `${passphrase}\n` });
    JSON.parse(blob);
    mkdirSync(join(dir, "recovery"), { recursive: true, mode: 0o700 });
    const file = join(dir, "recovery", `varlatch-kek-escrow-${new Date().toISOString().slice(0, 10)}.json`);
    writeFileSync(file, blob + "\n", { mode: 0o600 });
    console.log(`  Wrote ${file}.`);
    console.log("  The file is safe to store anywhere (even next to backups); keep the passphrase separately.");
  } else if (method === "shamir") {
    const shares = opts.shares ?? 5, threshold = opts.threshold ?? 3;
    const out = varlatchd(dir, ["admin", "kek", "split", "--shares", String(shares), "--threshold", String(threshold)]);
    console.log(`  Any ${threshold} of these ${shares} shares rebuild the Root KEK; give each to a different person:\n`);
    console.log(out.split("\n").map((l) => `    ${l}`).join("\n"));
  } else {
    console.log("  Copy secrets/varlatch-kek to a place outside this host (password manager, offline media).");
  }
  console.log("  Copy the backup key your backups use (setup generates secrets/backup-key) off this host too — not next to the Root KEK copy.");
  const confirmed = opts.attest || (process.stdin.isTTY && (await ask('  Type "stored" once both are stored off this host: ', "--attest")).trim() === "stored");
  if (!confirmed) {
    console.log("  Not recorded. Rerun `varlatch setup` (or pass --attest) once the copies are stored.");
    return false;
  }
  varlatchd(dir, ["admin", "custody", "attest", "--key", "root-kek", "--method", ATTEST_METHOD[method]]);
  varlatchd(dir, ["admin", "custody", "attest", "--key", "backup-key", "--method", "copy"]);
  console.log("  ✓ recorded as your attestation (dated; the installation cannot verify copies elsewhere)");
  return true;
}

// ---- The command -----------------------------------------------------------

async function askIngress(): Promise<Ingress> {
  console.log("  How will people reach Varlatch?");
  console.log("    [1] A public domain — Varlatch obtains the HTTPS certificate itself. The name must point to this");
  console.log("        machine and ports 80 and 443 must be reachable from the internet.");
  console.log("    [2] Only your tailnet — https://<machine>.<tailnet>.ts.net. Needs a Tailscale auth key, with MagicDNS");
  console.log("        and HTTPS certificates enabled in the Tailscale admin console.");
  console.log("    [3] Your own reverse proxy — also for LAN-only installations. Varlatch listens on 127.0.0.1.");
  const answer = (await ask("  Choice [3]: ", "--ingress public|tailnet|external")).trim();
  return answer === "1" ? "public" : answer === "2" ? "tailnet" : "external";
}

/**
 * Tailnet ingress: start only the sidecar, let it join, and read the name it
 * actually got — the public URL (and passkey RP ID) — before anything issues
 * an enrollment link. A different name on a rerun means the machine or tailnet
 * was renamed: a domain change, not a setup rerun.
 */
async function joinTailnet(dir: string, config: InstallConfig, opts: SetupOptions): Promise<InstallConfig> {
  const keyPath = join(dir, "secrets", "tailscale-authkey");
  const enrolled = spawnSync("docker", ["volume", "inspect", `${projectName(dir)}_tailscale-state`], { stdio: "ignore" }).status === 0;
  if (!enrolled && !existsSync(keyPath)) {
    if (!opts.tailscaleAuthKeyFile && !process.stdin.isTTY) throw new SetupError("Not a terminal: pass --tailscale-auth-key-file");
    const key = opts.tailscaleAuthKeyFile
      ? readFileSync(opts.tailscaleAuthKeyFile, "utf8").trim()
      : (await hidden("  Tailscale auth key (tskey-auth-…; used once to join): ")).trim();
    if (!key.startsWith("tskey-")) throw new SetupError("That does not look like a Tailscale auth key (tskey-…)");
    writeFileSync(keyPath, `${key}\n`, { mode: 0o600 });
  }
  docker(dir, ["up", "-d", "tailscale"], { stream: true });
  const deadline = Date.now() + 3 * 60_000;
  for (;;) {
    let status: TailscaleStatus = {};
    try { status = JSON.parse(docker(dir, ["exec", "-T", "tailscale", "tailscale", "status", "--json"])) as TailscaleStatus; } catch { /* starting */ }
    const found = tailnetUrl(status);
    if (found) {
      if (config.publicUrl && config.publicUrl !== found.url) {
        throw new SetupError(
          `This installation's URL is ${config.publicUrl}, but the node is now ${found.url} (machine or tailnet renamed). ` +
            "Changing the URL re-binds every passkey; it is a separate procedure, not a setup rerun.",
        );
      }
      console.log(`  ✓ tailnet node joined: ${found.url}`);
      return { ...config, publicUrl: found.url, tailnetName: found.tailnet };
    }
    if (Date.now() > deadline) {
      throw new SetupError(
        `The Tailscale node did not join (state ${status.BackendState ?? "unknown"}). Check the auth key in secrets/tailscale-authkey ` +
          "(it must not be expired or used up), then rerun `varlatch setup`. Inspect: docker compose logs tailscale",
      );
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
}

/** Public ingress: Caddy must hold a certificate for the host before anyone is sent there. */
async function waitForCertificate(dir: string, host: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const found = spawnSync("docker", ["compose", "exec", "-T", "caddy", "sh", "-c", `ls /data/caddy/certificates/*/${host}/${host}.crt`], { cwd: dir, stdio: "ignore" });
    if (found.status === 0) { console.log(`  ✓ HTTPS certificate for ${host}`); return; }
    if (Date.now() > deadline) {
      const errors = docker(dir, ["logs", "--tail", "200", "caddy"]).split("\n").filter((l) => /"level":"error"/.test(l)).slice(-3);
      throw new SetupError(
        `No HTTPS certificate for ${host} yet. Check that ${host} resolves to this machine in public DNS and that ports 80 and 443 ` +
          `are reachable from the internet, then rerun \`varlatch setup\`.${errors.length ? `\n  Caddy: ${errors.map((e) => JSON.parse(e).error ?? e).join("\n  Caddy: ")}` : ""}`,
      );
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
}

async function ask(question: string, flagHint: string): Promise<string> {
  if (!process.stdin.isTTY) throw new SetupError(`Not a terminal: pass ${flagHint}`);
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try { return await rl.question(question); } finally { rl.close(); }
}

export function loadInstallConfig(dir: string): InstallConfig | null {
  const path = join(dir, CONFIG_FILE);
  if (!existsSync(path)) return null;
  const config = JSON.parse(readFileSync(path, "utf8")) as InstallConfig;
  if (config.schemaVersion !== 1) throw new SetupError(`${CONFIG_FILE}: unsupported schemaVersion`);
  return config;
}

export async function runSetup(opts: SetupOptions): Promise<number> {
  const dir = resolve(opts.dir);
  if (!existsSync(join(dir, "docker-compose.yml"))) throw new SetupError(`No docker-compose.yml in ${dir}: run setup in a release bundle or infra/compose`);
  const step = (n: number, text: string) => console.log(`\n[${n}/7] ${text}`);

  if (opts.ingress && !INGRESS.includes(opts.ingress)) throw new SetupError(`--ingress must be one of ${INGRESS.join(", ")}`);

  // 1. Installation Configuration — the only operator input.
  step(1, "Installation configuration");
  let config = loadInstallConfig(dir);
  const saveConfig = (next: InstallConfig) => writeFileSync(join(dir, CONFIG_FILE), JSON.stringify(next, null, 2) + "\n");
  if (config) {
    if (opts.ingress && opts.ingress !== (config.ingress ?? "external")) {
      throw new SetupError(`This installation uses the ${config.ingress ?? "external"} ingress. Changing it moves the public URL; it is a separate procedure, not a setup rerun.`);
    }
    if (opts.publicUrl && config.publicUrl && validatePublicUrl(opts.publicUrl) !== config.publicUrl) {
      throw new SetupError(
        `This installation's public URL is ${config.publicUrl}. Changing it re-binds every passkey ` +
          "(a hostname change is a re-enrollment event, ADR-0035); it is a separate procedure, not a setup rerun.",
      );
    }
    console.log(`  ✓ ${config.publicUrl || "tailnet address pending"} (${config.ingress ?? "external"} ingress, from ${CONFIG_FILE})`);
  } else {
    const ingress = opts.ingress ?? (opts.publicUrl ? "external" : await askIngress());
    const base = { schemaVersion: 1 as const, ingress, webPort: opts.webPort ?? 8787, bindAddress: "127.0.0.1" };
    if (ingress === "tailnet") {
      const machine = opts.tailnetMachine ?? "varlatch";
      if (!TAILNET_MACHINE.test(machine)) throw new SetupError(`${machine}: a Tailscale machine name uses lowercase letters, digits and hyphens`);
      config = { ...base, publicUrl: "", tailnetMachine: machine };
    } else {
      let publicUrl = validatePublicUrl(opts.publicUrl ?? (await ask(
        ingress === "public" ? "  Public URL (https://your.domain — it must point to this machine): " : "  Public URL (what users type in the browser): ",
        "--public-url",
      )));
      if (ingress === "public") publicUrl = validatePublicHost(publicUrl);
      config = { ...base, publicUrl };
    }
    saveConfig(config);
    console.log(`  ✓ ${config.publicUrl || `tailnet machine "${config.tailnetMachine}"`} (${ingress} ingress) → ${CONFIG_FILE}`);
  }
  const ingress = config.ingress ?? "external";
  const missingFiles = INGRESS_FILES[ingress].filter((f) => !existsSync(join(dir, f)));
  if (missingFiles.length) throw new SetupError(`The ${ingress} ingress needs ${missingFiles.join(", ")} in ${dir}: use a release bundle that includes them, or infra/compose`);

  // 2. Secrets as files and the managed .env (derived, never hand-set).
  step(2, "Secrets and configuration");
  const envPath = join(dir, ".env");
  let additions = "";
  if (existsSync(envPath)) {
    const current = readFileSync(envPath, "utf8");
    if (!current.startsWith(ENV_HEADER)) {
      throw new SetupError(
        ".env exists and was not written by setup: this looks like a hand-configured installation. " +
          "Setup does not take one over silently — existing installations move to managed configuration " +
          "through `varlatch adopt` (ADR-0035 D13).",
      );
    }
    const keep = current.indexOf(ENV_KEEP);
    additions = keep >= 0 ? current.slice(keep + ENV_KEEP.length + 1) : "";
  }
  const secrets = ensureSecrets(dir, { existingInstallation: hasDatabaseVolume(dir), ...(config.secretPaths ? { paths: config.secretPaths } : {}) });
  writeFileSync(envPath, renderEnv(config, additions), { mode: 0o600 });
  mkdirSync(join(dir, "backups"), { recursive: true, mode: 0o700 }); // operator-owned, not Docker-created
  console.log(secrets.created.length ? `  ✓ generated ${secrets.created.join(", ")}` : "  ✓ secrets present (none regenerated)");
  if (ingress === "tailnet") {
    config = await joinTailnet(dir, config, opts);
    saveConfig(config);
    writeFileSync(envPath, renderEnv(config, additions), { mode: 0o600 });
  }

  // 3. Start (builds or pulls as the Compose file says) and wait for health.
  step(3, "Start the installation");
  docker(dir, ["up", "-d", "--remove-orphans"], { stream: true });
  await waitHealthy(dir, 10 * 60_000);
  console.log("  ✓ all services healthy");
  if (ingress === "public") await waitForCertificate(dir, new URL(config.publicUrl).hostname, 5 * 60_000);

  // 4. Application Plane reconciliation — no admin key to handle (D3/D4).
  step(4, "Application Plane");
  docker(dir, ["run", "--rm", "convex-deploy"], { stream: true });

  // 5. Bootstrap: done only when an Installation Admin can sign in.
  step(5, "First administrator");
  const status = () => bootstrapAction(JSON.parse(varlatchd(dir, ["admin", "bootstrap-status"])) as BootstrapStatus);
  let action = status();
  if (action.kind !== "done") {
    const issue =
      action.kind === "bootstrap" ? ["admin", "bootstrap"]
      : action.kind === "recover" ? ["admin", "recover", "--identity", action.identityId]
      : ["admin", "recover", "--new-admin"];
    const link = parseEnrollLink(varlatchd(dir, issue));
    if (!link) throw new SetupError("Could not obtain an enrollment link from varlatchd");
    if (action.kind !== "bootstrap") console.log("  An administrator exists but never finished enrolling a passkey; issuing a new link.");
    console.log("\n  Open this link in the browser where you want to sign in, and create a passkey.");
    console.log("  It works once and expires in 15 minutes; cancelling the prompt does not use it up.\n");
    console.log(`    ${link}\n`);
    if (opts.noWait) {
      console.log("  Rerun `varlatch setup` after enrolling to finish.");
      return 3;
    }
    const deadline = Date.now() + opts.enrollTimeoutMs;
    while ((action = status()).kind !== "done") {
      if (Date.now() > deadline) {
        console.log("  Enrollment not completed. Rerun `varlatch setup` for a fresh link — nothing else is repeated.");
        return 3;
      }
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  console.log(`  ✓ Installation Admin ${action.adminId} has a passkey`);

  // 6. Recovery keys: escrow and custody attestations.
  step(6, "Recovery keys");
  const escrowed = await escrowPhase(dir, opts);

  // 7. Health, including Mirror catch-up (doctor waits for its watermark).
  step(7, "Installation health");
  const report = await runDoctor({ dir, waitSeconds: 30 });
  console.log(formatDoctor(report).split("\n").map((l) => `  ${l}`).join("\n"));
  const code = doctorExitCode(report);
  if (code !== 0) {
    console.log("\nSetup finished with mandatory failures above; fix them and rerun `varlatch setup`.");
    return code;
  }
  if (!escrowed) {
    console.log(`\nRunning at ${config.publicUrl}, but recovery-key escrow is pending: rerun \`varlatch setup\` to finish.`);
    return 4;
  }
  console.log(`\nSetup complete: ${config.publicUrl}`);
  return 0;
}
