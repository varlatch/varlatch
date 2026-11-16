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
 *             run then exercises in full
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
 *   serveCli  restarts varlatchd with serve_cli set; until varlatchd knows
 *             the setting it refuses it (exit 78), and this adapter answers
 *             NOT_IMPLEMENTED_YET
 *   probe     device sign-in's probes (expire-pending-device-sign-ins,
 *             device-sign-in-addresses, proxy-addresses), through
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
 *
 * Optional capabilities (targets/capabilities.json, their only source): the
 * device sign-in probes, go-server, webhook-receiver, object-store and host-admin. Maintenance and
 * serve-cli come with the operations that need them (expect/go-binary.json
 * lists them).
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
import { createHash, randomBytes } from "node:crypto";
import { accessSync, appendFileSync, chmodSync, closeSync, constants, cpSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { NOT_IMPLEMENTED_YET } from "../lib/operations.mjs";
import { OBJECT_STORE_IMAGE, objectStoreKeys, objectStoreReady } from "./compose-stack.mjs";

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

async function freePort() {
  const server = createServer();
  await new Promise((res, rej) => {
    server.once("error", rej);
    server.listen(0, "127.0.0.1", res);
  });
  const { port } = server.address();
  await new Promise((res) => server.close(res));
  return port;
}

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
    ...(state.receiverPort ? [`outbound_allow = ${[state.receiverPort, state.objectStorePort].filter(Boolean).map((p) => `127.0.0.1/32:${p}`).join(",")}`] : []),
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
    receiverPort,
    receiverPidFile: join(dir, "receiver.pid"),
    objectStorePort,
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
  stopReceiver(state);
  // The object store, by the name only this installation's has.
  if (state?.dir) spawnSync("docker", ["rm", "-fv", objectStoreName(state)], { stdio: "ignore" });
  if (state?.dir && state.dir.startsWith(join(tmpdir(), "conformance-go-"))) rmSync(state.dir, { recursive: true, force: true });
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
    child = spawn(process.execPath, [SUPERVISOR, state.dir, state.pidFile, state.serverLog, state.binary, "serve", "--config", state.conf], {
      stdio: ["pipe", log, log],
    });
  } finally {
    closeSync(log);
  }
  let exited = null;
  child.on("exit", (code, signal) => (exited = { code, signal }));
  // Neither the supervisor nor its pipe keeps the runner alive; when the
  // runner ends, the pipe closes and the supervisor cleans up.
  child.unref();
  child.stdin.unref?.();
  child.stdin.on("error", () => {});
  supervisors.set(state.dir, child);
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
    while (pid && alive(pid)) await sleep(50);
    return;
  }
  // No supervisor here (another process started it, or it ended): the
  // recorded PID, if it still runs this installation.
  if (!pid) return;
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
  const r = spawnSync(state.binary, ["admin", ...args, "--config", state.conf], { encoding: "utf8", timeout: 60_000 });
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
  const r = spawnSync(state.binary, ["admin", ...args, "--config", state.conf], { encoding: "utf8", timeout: 60_000 });
  return { status: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
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
  if (!["expire-pending-device-sign-ins", "device-sign-in-addresses", "proxy-addresses"].includes(probeName)) throw new Error(`unknown probe ${probeName}`);
  return JSON.parse(admin(state, ["conformance-probe", probeName, ...args]));
}

/**
 * Serving the CLI on or off, asked of varlatchd: the setting goes into its
 * configuration and it restarts. A varlatchd that does not know the setting
 * refuses to start (exit 78, unknown setting); the configuration is then
 * put back, varlatchd started again, and the answer is NotImplementedYet.
 */
export async function serveCli(state, on) {
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
    const child = spawn(process.execPath, [RECEIVER, state.dir, String(state.receiverPort)], { stdio: "ignore", detached: true });
    writeFileSync(state.receiverPidFile, `${child.pid}\n`);
    child.unref();
    for (let i = 0; i < 50 && !(await receiverRequests(state)); i++) await sleep(100);
    if (!(await receiverRequests(state))) throw new Error("the webhook receiver did not start");
  }
  return { url: `http://127.0.0.1:${state.receiverPort}` };
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
