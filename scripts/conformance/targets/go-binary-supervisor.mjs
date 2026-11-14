// SPDX-License-Identifier: Apache-2.0
/**
 * The process that owns one go-binary varlatchd (targets/go-binary.mjs),
 * so that an abrupt end of the runner, which skips its `finally` blocks,
 * leaves no server and no installation directory behind.
 *
 *   node go-binary-supervisor.mjs <dir> <pid file> <log> <binary> <args...>
 *
 * It starts <binary> <args...> with its output in <log>, writes its PID to
 * <pid file>, and exits with its exit status when it ends. Its standard
 * input is a pipe from the runner:
 *
 *   - the line `stop`: stop varlatchd (SIGTERM, SIGKILL after 25 s) and
 *     keep the directory, which the runner restarts or removes itself;
 *   - the pipe closing without `stop` (the runner ended), or SIGTERM,
 *     SIGINT or SIGHUP: stop varlatchd, then remove <dir>, which must be a
 *     conformance-go- directory under the temporary directory.
 */
import { spawn } from "node:child_process";
import { appendFileSync, closeSync, openSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";

const STOP_TIMEOUT_MS = 25_000;
const [dir, pidFile, logFile, binary, ...args] = process.argv.slice(2);
if (!dir || !pidFile || !logFile || !binary) {
  console.error("usage: go-binary-supervisor.mjs <dir> <pid file> <log> <binary> <args...>");
  process.exit(2);
}

const log = openSync(logFile, "a");
const child = spawn(binary, args, { stdio: ["ignore", log, log] });
closeSync(log);
child.on("error", (err) => {
  appendFileSync(logFile, `--- go-binary-supervisor: could not start ${binary}: ${err.message}\n`);
  process.exit(127);
});
if (child.pid) writeFileSync(pidFile, `${child.pid}\n`);

let parentGone = false;
let stopping = false;
function stopServer() {
  if (stopping || child.exitCode !== null || child.signalCode !== null) return;
  stopping = true;
  child.kill("SIGTERM");
  setTimeout(() => child.kill("SIGKILL"), STOP_TIMEOUT_MS).unref();
}

function removeDir() {
  const root = join(resolve(tmpdir()), "conformance-go-");
  const target = resolve(dir);
  if (target.startsWith(root) && !target.slice(root.length).includes(sep)) rmSync(target, { recursive: true, force: true });
}

child.on("exit", (code, signal) => {
  if (parentGone) removeDir();
  process.exit(code ?? (signal ? 1 : 0));
});

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  if (input.split("\n").includes("stop")) stopServer();
});
const orphaned = () => {
  if (!stopping) parentGone = true;
  stopServer();
  // varlatchd may already have ended on its own.
  if (child.exitCode !== null || child.signalCode !== null) {
    if (parentGone) removeDir();
    process.exit(0);
  }
};
process.stdin.on("end", orphaned);
process.stdin.on("error", orphaned);
for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"]) process.on(signal, orphaned);
