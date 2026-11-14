// SPDX-License-Identifier: Apache-2.0
/**
 * Target `go-binary:<path>`: the Go `varlatchd` (ADR-0059) at <path>, run as
 * a process (the harness never links the server's code; the process
 * boundary keeps it Apache-2.0).
 *
 *   up        a fresh installation: a new directory with the data directory,
 *             a random Root KEK (mode 0600), varlatchd.conf (listening on a
 *             free loopback port, the access log in the directory), and the
 *             server's own output; varlatchd serve, until /readyz answers
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
 *             TypeScript admin CLI's; until ADR-0059 step 3.4 they answer
 *             NOT_IMPLEMENTED_YET, and so does this adapter
 *   serveCli  restarts varlatchd with serve_cli set; until varlatchd knows
 *             the setting it refuses it (exit 78), and this adapter answers
 *             NOT_IMPLEMENTED_YET
 *
 * No optional capability yet: the probes, maintenance and serve-cli come
 * with the operations that need them (expect/go-binary.json lists them).
 * The only processes it signals are the ones it started, by the PID it
 * recorded, after checking that PID still runs this installation's
 * configuration.
 */

import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { accessSync, appendFileSync, chmodSync, closeSync, constants, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { NOT_IMPLEMENTED_YET } from "../lib/operations.mjs";

export const name = "go-binary";
export const capabilities = [];

const READY_TIMEOUT_MS = 30_000;
const STOP_TIMEOUT_MS = 25_000;
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
  const dir = mkdtempSync(join(tmpdir(), "conformance-go-"));
  const port = await freePort();
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
  };
  onState(state);
  try {
    mkdirSync(state.dataDir, { mode: 0o700 });
    writeFileSync(state.kekFile, `${randomBytes(32).toString("hex")}\n`, { mode: 0o600 });
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
    child = spawn(state.binary, ["serve", "--config", state.conf], { detached: true, stdio: ["ignore", log, log] });
  } finally {
    closeSync(log);
  }
  let exited = null;
  child.on("exit", (code, signal) => (exited = { code, signal }));
  child.unref();
  writeFileSync(state.pidFile, `${child.pid}\n`);
  const deadline = Date.now() + READY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (exited) {
      const err = new Error(`varlatchd exited ${exited.code ?? exited.signal} before it was ready:\n${tail(state)}`);
      err.exitCode = exited.code;
      throw err;
    }
    const ok = await fetch(`${state.origin}/readyz`).then((r) => r.status === 200, () => false);
    if (ok) return;
    await sleep(200);
  }
  throw new Error(`varlatchd was not ready within ${READY_TIMEOUT_MS / 1000} s:\n${tail(state)}`);
}

async function stop(state) {
  const pid = ownPid(state);
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

export async function bootstrap(state) {
  return admin(state, ["bootstrap"]);
}

export async function recover(state, identity, { cliCredential = false } = {}) {
  return admin(state, ["recover", "--identity", identity, ...(cliCredential ? ["--cli-credential"] : [])]);
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
