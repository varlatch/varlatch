// SPDX-License-Identifier: Apache-2.0
/**
 * Target `go-binary:<path>`: the Go `varlatchd` (ADR-0059) at <path>, run as
 * a process (the harness never links the server's code; the process
 * boundary keeps it Apache-2.0).
 *
 *   up        a fresh installation: a new directory with the data directory,
 *             a random Root KEK (mode 0600), varlatchd.conf (listening on a
 *             free loopback port, the access log in the directory), and the
 *             server's own output; varlatchd serve, until /readyz answers.
 *             With VARLATCH_GO_BINARY_FROM=<dir>, the data directory and the
 *             Root KEK are copies of <dir>/data and <dir>/root-kek instead:
 *             an installation prepared elsewhere (go.yml's restore drill
 *             restores a Go archive there in a fresh container), which the
 *             run then exercises in full. With VARLATCH_GO_BINARY_KEEP=<dir>
 *             (a new directory), `down` copies the data directory and the
 *             Root KEK to <dir>/data and <dir>/root-kek after varlatchd has
 *             stopped, before the installation is removed: G6 (go/release/
 *             g6.sh) runs the next release on what this one wrote
 *   origin    varlatchd itself: it serves the dashboard and the API
 *   restart   SIGTERM, then serve again on the same data
 *   logs      what varlatchd wrote to standard output and error
 *   request-log
 *             the access log (go/server/httpserver AccessRecord), the
 *             requests varlatchd's request window counted: millisecond
 *             arrival and completion times, the client address, method,
 *             path, status and X-Forwarded-For
 *   bootstrap, recover
 *             `varlatchd admin bootstrap|recover`, whose output is the
 *             TypeScript admin CLI's (an admin command a varlatchd does not
 *             have answers NOT_IMPLEMENTED_YET, and so does this adapter)
 *   serveCli  restarts varlatchd with serve_cli set. Turning it on the
 *             first time prepares the release it serves (cliRelease): the
 *             Go CLI of this checkout for this machine, built with
 *             varlatchd's version and the conformance tag, and the
 *             installers, signed by `varlatchd admin
 *             conformance-sign-release` with a test Sigstore whose trusted
 *             root that CLI's verify-release reads; varlatchd is pointed at
 *             it (VARLATCH_CONFORMANCE_CLI_RELEASE). A varlatchd that does
 *             not know the setting refuses it (exit 78), and this adapter
 *             answers NOT_IMPLEMENTED_YET
 *   probe     device sign-in's probes (expire-pending-device-sign-ins,
 *             device-sign-in-addresses, proxy-addresses) and deletion's
 *             (deletion-due), through
 *             `varlatchd admin conformance-probe`, which a varlatchd built
 *             with the conformance build tag has (go build -tags
 *             conformance); `up` refuses a binary without it
 *   goServer  the go-server capability: `fixture <name> [args]`, the realtime
 *             suite's fixtures (Organizations, people, browser sessions,
 *             audit events, a removal) through `varlatchd admin
 *             conformance-fixture`, from the same conformance build; JSON
 *   webhookReceiver
 *             the webhooks suite's receiver (lib/webhook-receiver.cjs) on a
 *             free loopback port that varlatchd.conf's outbound_allow
 *             opens, a process of its own: `url` starts it, `requests`
 *             reads what it recorded; `down` stops it by its recorded PID
 *   objectStore
 *             MinIO, pinned by digest, on a free loopback port that
 *             outbound_allow opens: `start` runs it; `down` removes it
 *   hostAdmin `audit-export ...` through the daemon's control socket: its
 *             exit status and output
 *   oidcIssuer
 *             the oidc suite's issuer (lib/oidc-issuer.cjs) over https on a
 *             free loopback port that outbound_allow opens, its
 *             self-signed certificate among varlatchd's roots (SSL_CERT_FILE)
 *
 * Optional capabilities (targets/capabilities.json, their only source): the
 * device sign-in probes, go-server, webhook-receiver, object-store, host-admin and oidc-issuer;
 * maintenance and serve-cli.
 * The only processes it signals are the ones it started, by the PID it
 * recorded, after checking that PID still runs this installation's
 * configuration.
 *
 * varlatchd runs under go-binary-supervisor.mjs, which holds a pipe from
 * this process: if the runner ends without `down` (a test worker killed, a
 * crash), the pipe closes and the supervisor stops varlatchd and removes
 * the installation directory.
 */

import { spawn, spawnSync } from "node:child_process";
import { deadlineSpawnSync } from "../lib/deadline.mjs";
import { createHash, randomBytes } from "node:crypto";
import { accessSync, appendFileSync, chmodSync, closeSync, constants, cpSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { fixtureStatus } from "../lib/fixture-status.mjs";
import { NOT_IMPLEMENTED_YET } from "../lib/operations.mjs";
import { reservePort } from "../lib/ports.mjs";
import { issuerCertificate, ISSUER_SOURCE, OBJECT_STORE_IMAGE, objectStoreKeys, objectStoreReady, PLATFORM_FAKE_HOSTS, platformFakesCertificate, pullObjectStore } from "./compose-stack.mjs";

export const name = "go-binary";

const READY_TIMEOUT_MS = 30_000;
/** One /readyz request's deadline: a server that accepts and never answers must not hold up the loop. */
const READY_PROBE_TIMEOUT_MS = 2_000;
const STOP_TIMEOUT_MS = 25_000;
const SUPERVISOR = join(dirname(fileURLToPath(import.meta.url)), "go-binary-supervisor.mjs");
/** The supervisor of each running installation, by directory. */
const supervisors = new Map();
/** varlatchd's exit status for an admin command that is not built yet (EX_UNAVAILABLE). */
const EXIT_NOT_BUILT = 69;
/** varlatchd's exit status for a configuration error (EX_CONFIG). */
const EXIT_CONFIG = 78;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** An error for an operation the server does not have yet. */
export class NotImplementedYet extends Error {
  constructor(message) {
    super(message);
    this.code = NOT_IMPLEMENTED_YET;
  }
}

// Below the ephemeral range, so no client socket holds one by the time a
// fixture binds it, minutes after the install (lib/ports.mjs).
const freePort = () => reservePort();

function config(state, extra = "") {
  return [
    "# Written by scripts/conformance/targets/go-binary.mjs for one run.",
    `listen = 127.0.0.1:${state.port}`,
    `public_url = ${state.origin}`,
    `data_dir = ${state.dataDir}`,
    `root_kek_file = ${state.kekFile}`,
    `access_log = ${state.accessLog}`,
    // The webhooks suite's receiver: the one private destination allowed.
    // and the audit-export suite's object store.
    // And the sync suite's fake platforms.
    ...(state.receiverPort ? [`outbound_allow = ${[state.receiverPort, state.objectStorePort, state.oidcPort, state.fakesPort].filter(Boolean).map((p) => `127.0.0.1/32:${p}`).join(",")}`] : []),
    extra,
  ].join("\n") + "\n";
}

/** Starts a fresh installation; hands its state to onState before creating anything. */
export async function up({ argument, onState = () => {} }) {
  const binary = resolve(argument);
  try {
    accessSync(binary, constants.X_OK);
    if (!statSync(binary).isFile()) throw new Error("not a file");
  } catch (err) {
    throw new Error(`go-binary: ${binary} is not an executable file (${err.message})`);
  }
  // The probes are in a conformance build only.
  const probe = spawnSync(binary, ["admin", "conformance-probe", "proxy-addresses"], { encoding: "utf8", timeout: 30_000 });
  if (probe.status !== 0 || probe.stdout.trim() !== "[]") {
    throw new Error(`go-binary: ${binary} has no conformance probes; build it with: go build -tags conformance ./cmd/varlatchd (${(probe.stderr || probe.stdout).trim().slice(0, 200)})`);
  }
  const dir = mkdtempSync(join(tmpdir(), "conformance-go-"));
  const port = await freePort();
  const receiverPort = await freePort();
  const objectStorePort = await freePort();
  const oidcPort = await freePort();
  const fakesPort = await freePort();
  const fakesControlPort = await freePort();
  const state = {
    target: `go-binary:${argument}`,
    binary,
    dir,
    port,
    origin: `http://localhost:${port}`,
    dataDir: join(dir, "data"),
    kekFile: join(dir, "root-kek"),
    conf: join(dir, "varlatchd.conf"),
    serverLog: join(dir, "varlatchd.log"),
    accessLog: join(dir, "access.log"),
    pidFile: join(dir, "varlatchd.pid"),
    // The runner's process: a target operation run in a process of its
    // own (serve-cli's restart) hands its supervisor to it.
    ownerPid: process.pid,
    ownerStart: processStart(process.pid),
    receiverPort,
    receiverPidFile: join(dir, "receiver.pid"),
    objectStorePort,
    oidcPort,
    oidcDir: join(dir, "oidc"),
    oidcPidFile: join(dir, "oidc-issuer.pid"),
    fakesPort,
    fakesControlPort,
    fakesPidFile: join(dir, "platform-fakes.pid"),
  };
  onState(state);
  try {
    const from = process.env.VARLATCH_GO_BINARY_FROM;
    if (from) {
      cpSync(join(from, "data"), state.dataDir, { recursive: true });
      chmodSync(state.dataDir, 0o700);
      writeFileSync(state.kekFile, readFileSync(join(from, "root-kek")), { mode: 0o600 });
    } else {
      mkdirSync(state.dataDir, { mode: 0o700 });
      writeFileSync(state.kekFile, `${randomBytes(32).toString("hex")}\n`, { mode: 0o600 });
    }
    chmodSync(state.kekFile, 0o600);
    issuerCertificate(state.oidcDir);
    platformFakesCertificate(state.oidcDir);
    // varlatchd's roots: the system's, the issuer's certificate and the
    // fake platforms'.
    const system = ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"].find((f) => existsSync(f));
    writeFileSync(join(state.oidcDir, "roots.pem"), `${system ? readFileSync(system, "utf8") : ""}\n${readFileSync(join(state.oidcDir, "cert.pem"), "utf8")}${readFileSync(join(state.oidcDir, "fakes-cert.pem"), "utf8")}`);
    writeFileSync(state.conf, config(state));
    await start(state);
  } catch (err) {
    err.state = state;
    throw err;
  }
  return state;
}

/** Stops the server and removes the installation. */
export async function down(state) {
  await stop(state).catch(() => {});
  keep(state);
  stopReceiver(state);
  stopIssuer(state);
  stopPlatformFakes(state);
  // The object store, by the name only this installation's has.
  if (state?.dir) spawnSync("docker", ["rm", "-fv", objectStoreName(state)], { stdio: "ignore" });
  if (state?.dir && state.dir.startsWith(join(tmpdir(), "conformance-go-"))) rmSync(state.dir, { recursive: true, force: true });
}

/**
 * VARLATCH_GO_BINARY_KEEP: the stopped installation's data directory and
 * Root KEK, copied out. Only when varlatchd has stopped (its PID gone), so
 * the copy is of a closed database; a directory that exists is never
 * written into.
 */
function keep(state) {
  const to = process.env.VARLATCH_GO_BINARY_KEEP;
  if (!to || !state?.dataDir || !existsSync(state.dataDir)) return;
  if (ownPid(state) !== null) {
    console.error(`VARLATCH_GO_BINARY_KEEP: varlatchd still runs; ${to} was not written`);
    return;
  }
  if (existsSync(to)) {
    console.error(`VARLATCH_GO_BINARY_KEEP: ${to} exists; it was not written`);
    return;
  }
  mkdirSync(to, { recursive: true, mode: 0o700 });
  cpSync(state.dataDir, join(to, "data"), { recursive: true });
  writeFileSync(join(to, "root-kek"), readFileSync(state.kekFile), { mode: 0o600 });
}

export const origin = (state) => state.origin;

/** The recorded PID, when it still runs this installation's varlatchd. */
function ownPid(state) {
  if (!existsSync(state.pidFile)) return null;
  const pid = Number(readFileSync(state.pidFile, "utf8").trim());
  if (!Number.isInteger(pid) || pid <= 1) return null;
  try {
    const cmdline = readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0");
    return cmdline.includes(state.conf) && cmdline.includes("serve") ? pid : null;
  } catch {
    // Not on Linux, or gone: signal it only if it is alive.
    try {
      process.kill(pid, 0);
      return process.platform === "linux" ? null : pid;
    } catch {
      return null;
    }
  }
}

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function start(state) {
  const log = openSync(state.serverLog, "a");
  let child;
  try {
    // Started from a process that is not the runner (a target operation
    // of its own, which ends at once), the supervisor watches the runner
    // instead of a pipe from this process.
    const handedOver = state.ownerPid && state.ownerPid !== process.pid;
    const owner = `${state.ownerPid}${state.ownerStart ? `:${state.ownerStart}` : ""}`;
    child = spawn(process.execPath, [SUPERVISOR, ...(handedOver ? ["--owner", owner] : []), state.dir, state.pidFile, state.serverLog, state.binary, "serve", "--config", state.conf], {
      stdio: [handedOver ? "ignore" : "pipe", log, log],
      detached: Boolean(handedOver),
      // The system's roots, the oidc suite's issuer certificate and the
      // fake platforms'; and the conformance build's host override, which
      // leads the platforms' host names to the fakes (the allow list still
      // decides: their port is the one entry for them).
      env: {
        ...process.env,
        ...(state.oidcDir ? { SSL_CERT_FILE: join(state.oidcDir, "roots.pem") } : {}),
        ...(state.fakesPort ? { VARLATCH_CONFORMANCE_OUTBOUND_HOSTS: PLATFORM_FAKE_HOSTS.map((h) => `${h}=127.0.0.1:${state.fakesPort}`).join(",") } : {}),
        // The release serve_cli serves, once serveCli has prepared it.
        ...(existsSync(join(cliReleaseDir(state), "SHA256SUMS")) ? { VARLATCH_CONFORMANCE_CLI_RELEASE: cliReleaseDir(state) } : {}),
      },
    });
  } finally {
    closeSync(log);
  }
  let exited = null;
  child.on("exit", (code, signal) => (exited = { code, signal }));
  // Neither the supervisor nor its pipe keeps the runner alive; when the
  // runner ends, the pipe closes and the supervisor cleans up.
  child.unref();
  child.stdin?.unref?.();
  child.stdin?.on("error", () => {});
  // A handed-over supervisor is stopped by its PID, as any other process's.
  if (child.stdin) supervisors.set(state.dir, child);
  const deadline = Date.now() + READY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (exited) {
      const err = new Error(`varlatchd exited ${exited.code ?? exited.signal} before it was ready:\n${tail(state)}`);
      err.exitCode = exited.code;
      throw err;
    }
    const ok = await fetch(`${state.origin}/readyz`, { signal: AbortSignal.timeout(READY_PROBE_TIMEOUT_MS) }).then(
      (r) => r.status === 200,
      () => false,
    );
    if (ok) return;
    await sleep(200);
  }
  throw new Error(`varlatchd was not ready within ${READY_TIMEOUT_MS / 1000} s:\n${tail(state)}`);
}

const ended = (child) => child.exitCode !== null || child.signalCode !== null;

async function stop(state) {
  const sup = state?.dir ? supervisors.get(state.dir) : undefined;
  supervisors.delete(state?.dir);
  const pid = ownPid(state);
  if (sup && !ended(sup)) {
    // The supervisor stops varlatchd and keeps the directory.
    let timer;
    const done = new Promise((r) => {
      sup.once("exit", r);
      timer = setTimeout(r, STOP_TIMEOUT_MS + 5_000);
    });
    sup.stdin.write("stop\n");
    await done;
    clearTimeout(timer);
    if (!ended(sup)) {
      if (pid && alive(pid)) process.kill(pid, "SIGKILL");
      sup.kill("SIGKILL");
    }
    sup.stdin.destroy();
    // Its varlatchd has ended with it, unless the one running now is
    // another supervisor's (a target operation's restart handed over):
    // that one is stopped by its PID, below.
    if (!pid || !alive(pid)) return;
  }
  // No supervisor here (another process started it, or it ended), or a
  // varlatchd it did not start: the recorded PID, if it still runs this
  // installation.
  if (!pid || !alive(pid)) return;
  process.kill(pid, "SIGTERM");
  const deadline = Date.now() + STOP_TIMEOUT_MS;
  while (alive(pid) && Date.now() < deadline) await sleep(100);
  if (alive(pid)) process.kill(pid, "SIGKILL");
  while (alive(pid)) await sleep(50);
}

function tail(state, lines = 40) {
  try {
    return readFileSync(state.serverLog, "utf8").trimEnd().split("\n").slice(-lines).join("\n");
  } catch {
    return "(no server output)";
  }
}

export async function restart(state) {
  await stop(state);
  await start(state);
}

export async function logs(state) {
  return existsSync(state.serverLog) ? readFileSync(state.serverLog, "utf8") : "";
}

/** The access log as request-log records: the requests the request window counted. */
export function requestsFromAccessLog(text) {
  const records = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    let r;
    try {
      r = JSON.parse(line);
    } catch {
      continue;
    }
    if (r.window !== true) continue;
    const record = {
      client: r.client,
      method: r.method,
      path: r.path,
      status: r.status,
      arrivedAt: Date.parse(r.arrived),
      completedAt: Date.parse(r.completed),
      resolutionMs: 1,
    };
    if (typeof r.forwardedFor === "string") record.forwardedFor = r.forwardedFor;
    records.push(record);
  }
  return records.sort((a, b) => a.completedAt - b.completedAt);
}

export async function requestLog(state) {
  return requestsFromAccessLog(existsSync(state.accessLog) ? readFileSync(state.accessLog, "utf8") : "");
}

/** Runs `varlatchd admin ...`: its output, or NotImplementedYet while the command is not built. */
function admin(state, args) {
  const r = deadlineSpawnSync(state.binary, ["admin", ...args, "--config", state.conf], { encoding: "utf8", timeout: 60_000 });
  if (r.timedOut) throw new Error(`varlatchd admin ${args[0]} timed out at the operation's deadline`);
  if (r.status === EXIT_NOT_BUILT && r.stderr.startsWith(`${NOT_IMPLEMENTED_YET}:`)) {
    throw new NotImplementedYet(r.stderr.trim().slice(NOT_IMPLEMENTED_YET.length + 2));
  }
  if (r.status !== 0) throw new Error(`varlatchd admin ${args[0]} exited ${r.status ?? r.signal}: ${(r.stderr || r.stdout).trim().slice(0, 500)}`);
  return r.stdout;
}

/**
 * The host-admin capability: one `varlatchd admin` host command whose
 * refusal a suite checks (`audit-export ...` only), through the daemon's
 * control socket. Its exit status and output, whatever the status.
 */
export async function hostAdmin(state, ...args) {
  if (args[0] !== "audit-export") throw new Error(`host-admin: unknown command ${args[0]}`);
  const r = deadlineSpawnSync(state.binary, ["admin", ...args, "--config", state.conf], { encoding: "utf8", timeout: 60_000 });
  return { status: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

/**
 * The go-host capability (the go-doctor suite, ADR-0059 step 6.5): the Go
 * installation's own host commands, run on its host as `varlatch doctor`
 * runs them. `doctor` is `varlatchd admin doctor --json`: its exit status
 * and its report.
 */
export async function goHost(state, operation) {
  if (operation !== "doctor") throw new Error(`go-host: unknown operation ${operation}`);
  const r = deadlineSpawnSync(state.binary, ["admin", "doctor", "--json", "--config", state.conf], { encoding: "utf8", timeout: 120_000 });
  let report = null;
  try {
    report = JSON.parse(r.stdout ?? "");
  } catch {
    report = null;
  }
  return { status: r.status ?? 1, report, stderr: (r.stderr ?? "").slice(0, 2000) };
}

export async function bootstrap(state) {
  return admin(state, ["bootstrap"]);
}

export async function recover(state, identity, { cliCredential = false } = {}) {
  return admin(state, ["recover", "--identity", identity, ...(cliCredential ? ["--cli-credential"] : [])]);
}

/**
 * The go-server capability (the realtime suite, gate G11): `fixture <name>
 * [args]` runs `varlatchd admin conformance-fixture`, which writes what the
 * suite's streams need while the /v1 writes that would make it are not
 * built (ADR-0059 step 4). Its JSON answer.
 */
export async function goServer(state, operation, ...args) {
  if (operation !== "fixture" || !["world", "orgs", "session", "events", "remove-member"].includes(args[0])) {
    throw new Error(`go-server: unknown operation ${[operation, ...args.slice(0, 1)].join(" ")}`);
  }
  return JSON.parse(admin(state, ["conformance-fixture", ...args]));
}

/**
 * Opens a maintenance window for `ttlMs`: `varlatchd admin maintenance
 * begin`, through the daemon's control socket, the same `503 MAINTENANCE`
 * admission a restore uses (ADR-0059 step 4.14).
 */
export async function maintenance(state, ttlMs) {
  admin(state, ["maintenance", "begin", "--ttl", `${Number(ttlMs)}ms`]);
}

/** A fixed, named probe of server state (the target contract): `varlatchd admin conformance-probe`. */
export async function probe(state, probeName, ...args) {
  if (!["audit-event-count", "expire-pending-device-sign-ins", "device-sign-in-addresses", "proxy-addresses", "deletion-due", "sync-repair-due", "sync-trigger-position", "github-app-pending-expired", "audit-export-drain-due", "deletion-teardown", "sync-runs"].includes(probeName)) throw new Error(`unknown probe ${probeName}`);
  return JSON.parse(admin(state, ["conformance-probe", probeName, ...args]));
}

/**
 * Serving the CLI on or off, asked of varlatchd: the setting goes into its
 * configuration and it restarts. A varlatchd that does not know the setting
 * refuses to start (exit 78, unknown setting); the configuration is then
 * put back, varlatchd started again, and the answer is NotImplementedYet.
 */
export async function serveCli(state, on) {
  if (on) prepareCliRelease(state);
  const before = readFileSync(state.conf, "utf8");
  await stop(state);
  writeFileSync(state.conf, config(state, `serve_cli = ${on ? "on" : "off"}`));
  try {
    await start(state);
    return;
  } catch (err) {
    if (err.exitCode !== EXIT_CONFIG || !/unknown setting \\?"serve_cli\\?"/.test(tail(state, 5))) throw err;
  }
  writeFileSync(state.conf, before);
  appendFileSync(state.serverLog, "--- conformance: serve_cli is not a varlatchd setting yet; started again without it\n");
  await start(state);
  throw new NotImplementedYet("varlatchd has no serve_cli setting yet");
}

/**
 * A process's start time on Linux (field 22 of /proc/<pid>/stat), null
 * elsewhere: with its PID, it names the runner a handed-over supervisor
 * watches, so a reused PID is not taken for it (go-binary-supervisor.mjs).
 */
function processStart(pid) {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    return stat.slice(stat.lastIndexOf(")") + 2).split(" ")[19] ?? null;
  } catch {
    return null;
  }
}

/** The release serve_cli serves in a conformance run, once prepared. */
const cliReleaseDir = (state) => join(state.dir, "cli-release");

const GO_MODULE = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "go");

/**
 * The release serve_cli serves (internal docs/design/go-step6.md, slice
 * 6.8): this machine's Go CLI built from this checkout with varlatchd's
 * version, the installers stamped with it, and SHA256SUMS signed by a test
 * Sigstore that `varlatchd admin conformance-sign-release` makes, whose
 * trusted root the CLI's verify-release reads (it is linked in, as
 * main.conformanceTrustedRoot, in a conformance build only). Made once per
 * installation. A varlatchd without the command leaves it unprepared.
 */
function prepareCliRelease(state) {
  const dir = cliReleaseDir(state);
  if (existsSync(join(dir, "SHA256SUMS"))) return;
  const reported = spawnSync(state.binary, ["--version"], { encoding: "utf8" });
  const version = /^varlatchd (\S+)$/m.exec(reported.stdout ?? "")?.[1];
  if (reported.status !== 0 || !version) throw new Error(`varlatchd --version: ${reported.stderr || reported.stdout}`);
  const goos = { linux: "linux", darwin: "darwin", win32: "windows" }[process.platform];
  const goarch = { x64: "amd64", arm64: "arm64" }[process.arch];
  if (!goos || !goarch) throw new Error(`no Go CLI for ${process.platform}/${process.arch}`);
  const staging = `${dir}.staging`;
  rmSync(staging, { recursive: true, force: true });
  mkdirSync(staging, { recursive: true });
  const cli = join(staging, `varlatch-${version}-${goos}-${goarch}${goos === "windows" ? ".exe" : ""}`);
  const ldflags = `-X github.com/varlatch/varlatch/go/lib/buildinfo.Version=${version} -X main.conformanceTrustedRoot=${join(dir, "trusted_root.json")}`;
  const build = spawnSync("go", ["build", "-tags", "conformance", "-trimpath", "-ldflags", ldflags, "-o", cli, "./cmd/varlatch"], {
    cwd: GO_MODULE,
    encoding: "utf8",
    env: { ...process.env, CGO_ENABLED: "0" },
  });
  if (build.status !== 0) throw new Error(`building the Go CLI for serve_cli: ${build.stderr || build.error}`);
  for (const name of ["install.sh", "install.ps1"]) {
    writeFileSync(join(staging, name), readFileSync(join(GO_MODULE, "install", name), "utf8").replace("@VARLATCH_VERSION@", version));
  }
  const signed = spawnSync(state.binary, ["admin", "conformance-sign-release", staging, version], { encoding: "utf8" });
  if (signed.status !== 0) {
    rmSync(staging, { recursive: true, force: true });
    if (/unknown command conformance-sign-release/.test(signed.stderr ?? "")) return;
    throw new Error(`varlatchd admin conformance-sign-release: ${signed.stderr || signed.stdout}`);
  }
  // The CLI reads its trusted root where the release ends up.
  rmSync(dir, { recursive: true, force: true });
  cpSync(staging, dir, { recursive: true });
  rmSync(staging, { recursive: true, force: true });
}

const PLATFORM_FAKES = join(dirname(fileURLToPath(import.meta.url)), "..", "lib", "platform-fakes.cjs");

/** The fake platforms' recorded PID, when it still runs this installation's fakes. */
function platformFakesPid(state) {
  if (!state?.fakesPidFile || !existsSync(state.fakesPidFile)) return null;
  const pid = Number(readFileSync(state.fakesPidFile, "utf8").trim());
  if (!Number.isInteger(pid) || pid <= 1) return null;
  try {
    const cmdline = readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0");
    return cmdline.includes(PLATFORM_FAKES) && cmdline.includes(state.dir) ? pid : null;
  } catch {
    return null;
  }
}

function stopPlatformFakes(state) {
  const pid = platformFakesPid(state);
  if (pid) process.kill(pid, "SIGTERM");
}

async function platformFakesControl(state, method, path, body) {
  return fetch(`http://127.0.0.1:${state.fakesControlPort}${path}`, { method, ...(body ? { body } : {}), signal: AbortSignal.timeout(5000) }).then(
    (r) => (r.ok ? r.json() : null),
    () => null,
  );
}

/**
 * The platform-fakes capability: `start` runs the fake platforms
 * (lib/platform-fakes.cjs) on the loopback port varlatchd.conf allows and
 * the host override leads to, when they are not running; `state` what they
 * hold and every request they saw; `drift <resource> <key> <value>` changes
 * a Coolify value behind Varlatch's back; `github <json>` sets up the fake
 * GitHub's App side (POST /_github). A process of its own, stopped by
 * `down` by its recorded PID, and gone by itself once the installation
 * directory is.
 */
export async function platformFakes(state, action, ...args) {
  if (action === "state") {
    const got = await platformFakesControl(state, "GET", "/_state");
    if (!got) throw new Error("the fake platforms are not running: start them first");
    return got;
  }
  if (action === "drift") {
    const [resource, key, value] = args;
    const got = await platformFakesControl(state, "POST", "/_drift", JSON.stringify({ resource, key, value }));
    if (!got) throw new Error(`the fake platforms could not drift ${resource} ${key}`);
    return got;
  }
  if (action === "github") {
    const got = await platformFakesControl(state, "POST", "/_github", args[0]);
    if (!got) throw new Error(`the fake GitHub refused ${args[0]?.slice(0, 80)}`);
    return got;
  }
  if (action !== "start") throw new Error(`unknown platform-fakes action ${action}`);
  if (!(await platformFakesControl(state, "GET", "/_state"))) {
    // As the other fixtures: polled until FIXTURE_START_MS, and one that
    // does not start says its exit, its port and its log.
    await startFixture(state, {
      name: "the fake platforms",
      args: [PLATFORM_FAKES, String(state.fakesPort), String(state.fakesControlPort),
        join(state.oidcDir, "fakes-cert.pem"), join(state.oidcDir, "fakes-key.pem"), state.dir],
      pidFile: state.fakesPidFile,
      port: state.fakesControlPort,
      ready: () => platformFakesControl(state, "GET", "/_state"),
    });
  }
  return { coolify: "https://coolify.conformance.test", convex: "https://convex.conformance.test", github: "acme" };
}

const RECEIVER = join(dirname(fileURLToPath(import.meta.url)), "..", "lib", "webhook-receiver.cjs");

/** The receiver's recorded PID, when it still runs this installation's receiver. */
function receiverPid(state) {
  if (!state?.receiverPidFile || !existsSync(state.receiverPidFile)) return null;
  const pid = Number(readFileSync(state.receiverPidFile, "utf8").trim());
  if (!Number.isInteger(pid) || pid <= 1) return null;
  try {
    const cmdline = readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0");
    return cmdline.includes(RECEIVER) && cmdline.includes(state.dir) ? pid : null;
  } catch {
    return null;
  }
}

function stopReceiver(state) {
  const pid = receiverPid(state);
  if (pid) process.kill(pid, "SIGTERM");
}

async function receiverRequests(state) {
  return fetch(`http://127.0.0.1:${state.receiverPort}/_received`, { signal: AbortSignal.timeout(5000) }).then(
    (r) => (r.ok ? r.json() : null),
    () => null,
  );
}

/**
 * The webhook-receiver capability: `url` starts the receiver
 * (lib/webhook-receiver.cjs) on the loopback port varlatchd.conf allows,
 * when it is not running, and answers its URL; `requests` what it
 * recorded. A process of its own, apart from varlatchd (a restart keeps
 * it), stopped by `down` by its recorded PID, and gone by itself once the
 * installation directory is.
 */
export async function webhookReceiver(state, action) {
  if (action === "requests") {
    const got = await receiverRequests(state);
    if (!got) throw new Error("the webhook receiver is not running: ask for its url first");
    return got;
  }
  if (action !== "url") throw new Error(`unknown webhook-receiver action ${action}`);
  if (!(await receiverRequests(state))) {
    await startFixture(state, {
      name: "the webhook receiver",
      args: [RECEIVER, state.dir, String(state.receiverPort)],
      pidFile: state.receiverPidFile,
      port: state.receiverPort,
      ready: () => receiverRequests(state),
    });
  }
  return { url: `http://127.0.0.1:${state.receiverPort}` };
}

const ISSUER = fileURLToPath(ISSUER_SOURCE);

/** How long a fixture process (the OIDC issuer, the webhook receiver, the fake platforms) may take to answer after it starts. */
const FIXTURE_START_MS = 30_000;

/**
 * Starts a fixture as a process of its own (detached; it exits once the
 * installation's directory is gone) and waits until `ready()` answers. Its
 * output goes to <dir>/<file>.log, so a fixture that does not start says
 * why: the error names its exit (or that it still runs), its port and the
 * log's last lines, instead of only that it did not start.
 */
async function startFixture(state, { name, args, pidFile, port, ready }) {
  const log = join(state.dir, `${basenameOf(args[0])}.log`);
  const fd = openSync(log, "a");
  let exit = null;
  const child = spawn(process.execPath, args, { stdio: ["ignore", fd, fd], detached: true });
  closeSync(fd);
  child.on("exit", (code, signal) => {
    exit = signal ? `killed by ${signal}` : `exited ${code}`;
  });
  writeFileSync(pidFile, `${child.pid}\n`);
  child.unref();
  const deadline = Date.now() + FIXTURE_START_MS;
  while (Date.now() < deadline && exit === null) {
    if (await ready()) return;
    await sleep(100);
  }
  if (exit === null && (await ready())) return;
  const tail = (existsSync(log) ? readFileSync(log, "utf8") : "").trim().split("\n").slice(-8).join(" | ");
  throw new Error(`${name} did not start: ${fixtureStatus(exit, alive(child.pid), FIXTURE_START_MS)}, on 127.0.0.1:${port}; its log (${log}): ${tail || "(empty)"}`);
}

const basenameOf = (file) => file.split(/[\\/]/).pop().replace(/\.c?js$/, "");

function issuerControl(state, method, path, body) {
  return spawnSync(process.execPath, [ISSUER, "control", join(state.oidcDir, "cert.pem"), String(state.oidcPort), method, path, ...(body ? [body] : [])],
    { encoding: "utf8", timeout: 20_000 });
}

function stopIssuer(state) {
  if (!state?.oidcPidFile || !existsSync(state.oidcPidFile)) return;
  const pid = Number(readFileSync(state.oidcPidFile, "utf8").trim());
  if (pid > 0) {
    try {
      process.kill(pid, "SIGTERM");
    } catch {
      // Already gone.
    }
  }
}

/**
 * The oidc-issuer capability: `start` runs the issuer
 * (lib/oidc-issuer.cjs) on the loopback port varlatchd.conf allows, a
 * process of its own, when it is not running, and answers its URL; `keys
 * <json>` sets its JWKS; `counts` what it was fetched. `down` stops it by
 * its recorded PID; it is gone by itself once the installation is.
 */
export async function oidcIssuer(state, action, ...args) {
  const running = () => issuerControl(state, "GET", "/_conformance/counts").status === 0;
  if (action === "start") {
    if (!running()) {
      await startFixture(state, {
        name: "the oidc issuer",
        args: [ISSUER, "serve", state.dir, state.oidcDir, String(state.oidcPort)],
        pidFile: state.oidcPidFile,
        port: state.oidcPort,
        ready: async () => running(),
      });
    }
    return { issuer: `https://127.0.0.1:${state.oidcPort}` };
  }
  const r = action === "keys" ? issuerControl(state, "PUT", "/_conformance/jwks", args[0]) : action === "counts" ? issuerControl(state, "GET", "/_conformance/counts") : null;
  if (!r) throw new Error(`unknown oidc-issuer action ${action}`);
  if (r.status !== 0) throw new Error(`oidc-issuer ${action}: ${(r.stderr || r.stdout).trim().slice(0, 300)}`);
  return JSON.parse(r.stdout);
}

const objectStoreName = (state) => `conformance-go-object-store-${state.dir.split("-").pop().toLowerCase().replace(/[^a-z0-9]/g, "")}`;

/**
 * The object-store capability: `start` runs MinIO (pinned by digest) on
 * the loopback port varlatchd.conf's outbound_allow opens; again, it
 * answers the running one. `down` removes it, by its name.
 */
export async function objectStore(state, action) {
  if (action !== "start") throw new Error(`unknown object-store action ${action}`);
  const name = objectStoreName(state);
  const keys = objectStoreKeys(state.dir);
  const running = spawnSync("docker", ["inspect", "-f", "{{.State.Running}}", name], { encoding: "utf8" });
  if (running.status !== 0 || running.stdout.trim() !== "true") {
    spawnSync("docker", ["rm", "-fv", name], { stdio: "ignore" });
    pullObjectStore();
    const r = spawnSync("docker", ["run", "-d", "--name", name, "-p", `127.0.0.1:${state.objectStorePort}:9000`,
      "-e", `MINIO_ROOT_USER=${keys.accessKeyId}`, "-e", `MINIO_ROOT_PASSWORD=${keys.secretAccessKey}`,
      OBJECT_STORE_IMAGE, "server", "/data"], { encoding: "utf8" });
    if (r.status !== 0) throw new Error(`docker run ${name} failed: ${r.stderr.trim().slice(-300)}`);
  }
  const endpoint = `http://127.0.0.1:${state.objectStorePort}`;
  await objectStoreReady(endpoint);
  return { endpoint, hostEndpoint: endpoint, region: "us-east-1", ...keys };
}

export function describe(state) {
  return { binary: state.binary, origin: state.origin, directory: state.dir };
}

export async function diagnostics(state) {
  return tail(state, 80);
}

/**
 * The implementation fingerprint: the binary's sha256, not its path, so the
 * same build compares equal wherever it is and another build at the same
 * path does not.
 */
export function fingerprintBinary(path) {
  return { target: name, sha256: createHash("sha256").update(readFileSync(path)).digest("hex") };
}
export const fingerprint = (state) => (state?.binary ? fingerprintBinary(state.binary) : null);

/** Expectations are kept for the Go server whatever its path. */
export const expectKey = () => name;
