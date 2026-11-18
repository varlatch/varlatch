// SPDX-License-Identifier: Apache-2.0
/**
 * deadlineSpawnSync's supervisor (lib/deadline.mjs). It is started detached,
 * so it leads a process group of its own, and it runs one command in that
 * group (not detached): the command and everything it starts share the
 * supervisor's group, whose ID stays reserved while the supervisor, its
 * leader, is alive. It answers on file descriptor 3 (apart from the
 * command's own output, which inherit mode passes through), as JSON followed by
 * END_MARKER, the command's exit status, signal, output and whether the
 * deadline fired; then it kills its whole group, itself included, so
 * nothing the command started outlives the call.
 *
 *   node deadline-supervisor.mjs <deadline epoch ms> <grace ms> <pipe|inherit> <command> [args...]
 *
 * Standard input is passed to the command (pipe mode). At the deadline the
 * group gets SIGTERM (the supervisor ignores it), and SIGKILL after the
 * grace. If the supervisor's parent goes away (the wrapper killed, a SIGINT
 * to the harness's group, which this group does not share), the group is
 * killed at once.
 */
import { spawn } from "node:child_process";
import { write } from "node:fs";
import { END_MARKER } from "./deadline-marker.mjs";

const [deadlineArg, graceArg, mode, command, ...args] = process.argv.slice(2);
const deadline = Number(deadlineArg);
const grace = Number(graceArg);
const parent = process.ppid;
const out = [];
const err = [];
let timedOut = false;
let answered = false;

// The deadline's SIGTERM goes to the whole group, the supervisor included,
// which stays to answer.
process.on("SIGTERM", () => {});

const killGroup = (signal) => {
  try {
    process.kill(-process.pid, signal);
  } catch {
    // Nothing left to signal.
  }
};

/** Writes the answer once, then ends the group (and the supervisor). */
const answerAndEnd = (o) => {
  if (answered) return;
  answered = true;
  write(3, JSON.stringify(o) + END_MARKER, () => killGroup("SIGKILL"));
};
const snapshot = (status, signal) => ({
  status, signal, timedOut,
  stdout: Buffer.concat(out).toString("base64"), stderr: Buffer.concat(err).toString("base64"),
});

// A deadline already past spawns nothing.
if (!(deadline > Date.now())) {
  timedOut = true;
  answerAndEnd({ ...snapshot(null, null), spawned: false });
} else {
  const child = spawn(command, args, { stdio: mode === "inherit" ? ["ignore", "inherit", "inherit"] : ["pipe", "pipe", "pipe"] });
  if (mode !== "inherit") {
    child.stdout.on("data", (d) => out.push(d));
    child.stderr.on("data", (d) => err.push(d));
    process.stdin.pipe(child.stdin).on("error", () => {});
  }
  // The parent gone: end the group now, not at the deadline.
  const watch = setInterval(() => {
    if (process.ppid !== parent) killGroup("SIGKILL");
  }, 200);
  watch.unref();
  setTimeout(() => {
    timedOut = true;
    killGroup("SIGTERM");
    // Past the grace: answer with what there is, and end the group.
    setTimeout(() => answerAndEnd(snapshot(null, "SIGKILL")), grace).unref();
  }, Math.max(0, deadline - Date.now())).unref();
  child.on("error", (e) => answerAndEnd({ ...snapshot(null, null), stderr: String(e.message), spawnError: e.code ?? "spawn" }));
  // The command exited: its output is complete once its pipes close, which
  // a process it left behind may hold open, so at most a moment later.
  child.on("exit", (status, signal) => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      answerAndEnd(snapshot(status, signal));
    };
    child.on("close", finish);
    setTimeout(finish, 200).unref();
  });
}
