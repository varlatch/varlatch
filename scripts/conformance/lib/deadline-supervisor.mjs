// SPDX-License-Identifier: Apache-2.0
/**
 * deadlineSpawnSync's supervisor (lib/deadline.mjs): runs one command in a
 * process group of its own and answers on standard output, as JSON, its
 * exit status, signal, output and whether the deadline fired.
 *
 *   node deadline-supervisor.mjs <deadline epoch ms> <grace ms> <pipe|inherit> <command> [args...]
 *
 * Standard input is passed to the command (pipe mode). At the deadline the
 * whole group gets SIGTERM, and SIGKILL after the grace; once the command
 * itself has exited, the group gets SIGKILL anyway, so nothing it started
 * outlives the call.
 */
import { spawn } from "node:child_process";

const [deadlineArg, graceArg, mode, command, ...args] = process.argv.slice(2);
const deadline = Number(deadlineArg);
const grace = Number(graceArg);
const out = [];
const err = [];
let timedOut = false;
let answered = false;
const answer = (o) => {
  if (answered) return;
  answered = true;
  process.stdout.write(JSON.stringify(o));
};

const killGroup = (pid, signal) => {
  try {
    process.kill(-pid, signal);
  } catch {
    // The group is already gone.
  }
};

const child = spawn(command, args, { detached: true, stdio: mode === "inherit" ? ["ignore", "inherit", "inherit"] : ["pipe", "pipe", "pipe"] });
if (mode !== "inherit") {
  child.stdout.on("data", (d) => out.push(d));
  child.stderr.on("data", (d) => err.push(d));
  process.stdin.pipe(child.stdin).on("error", () => {});
}
let hard;
const soft = setTimeout(() => {
  timedOut = true;
  killGroup(child.pid, "SIGTERM");
  hard = setTimeout(() => killGroup(child.pid, "SIGKILL"), grace);
}, Math.max(0, deadline - Date.now()));
child.on("error", (e) => {
  clearTimeout(soft);
  clearTimeout(hard);
  answer({ status: null, signal: null, timedOut, stdout: "", stderr: String(e.message), spawnError: e.code ?? "spawn" });
});
// Once the command itself has exited, whatever it left behind in its group
// goes with it (and releases the output pipes it may hold).
child.on("exit", () => {
  clearTimeout(soft);
  clearTimeout(hard);
  killGroup(child.pid, "SIGKILL");
});
child.on("close", (status, signal) => {
  answer({
    status, signal, timedOut,
    stdout: Buffer.concat(out).toString("base64"), stderr: Buffer.concat(err).toString("base64"),
  });
});
