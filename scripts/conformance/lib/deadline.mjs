// SPDX-License-Identifier: Apache-2.0
/**
 * A target operation's deadline. A suite that bounds a call
 * (suite-kit's targetOp with timeoutMs) passes the deadline to
 * target-op.mjs in CONFORMANCE_OP_DEADLINE (epoch milliseconds), and the
 * target's own child processes run under it through deadlineSpawnSync:
 * `docker compose exec` and `varlatchd admin` stop at the deadline, with
 * every process they started, so a bounded operation leaves no orphan
 * behind. targetOp's own kill of the wrapper comes later, as a backstop.
 */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { END_MARKER } from "./deadline-marker.mjs";

export const DEADLINE_ENV = "CONFORMANCE_OP_DEADLINE";
const SUPERVISOR = fileURLToPath(new URL("./deadline-supervisor.mjs", import.meta.url));
/** After the deadline's SIGTERM, how long a process group has before SIGKILL. */
export const GRACE_MS = 1000;

/** Milliseconds left before the operation's deadline; undefined without one. */
export function remainingMs(env = process.env) {
  const at = Number(env[DEADLINE_ENV]);
  return Number.isFinite(at) && at > 0 ? Math.max(0, at - Date.now()) : undefined;
}

/**
 * spawnSync, bounded by the operation's deadline when there is one (and by
 * `timeout` when given). Under a deadline the command runs under a
 * supervisor (lib/deadline-supervisor.mjs) started detached, so it leads a
 * process group of its own, which the command and everything it starts
 * share: at the deadline the group gets SIGTERM, then SIGKILL after
 * GRACE_MS; once the command has exited the supervisor answers and kills
 * its group, itself included, so nothing outlives the call; and if this
 * process goes away the supervisor kills its group at once. The answer is
 * spawnSync's, with `timedOut` set whenever the deadline fired. A deadline
 * already past runs nothing. Without a deadline the command runs as plain
 * spawnSync.
 */
export function deadlineSpawnSync(command, args, options = {}) {
  const left = remainingMs();
  if (left === undefined) return spawnSync(command, args, options);
  const limit = Math.min(left, options.timeout ?? Infinity);
  const encoding = options.encoding;
  const decode = (b64) => (encoding ? Buffer.from(b64, "base64").toString(encoding) : Buffer.from(b64, "base64"));
  const failed = (message, signal = null) => ({
    status: null, signal, timedOut: true, stdout: decode(""), stderr: decode(""),
    error: Object.assign(new Error(message), { code: "ETIMEDOUT" }),
  });
  const inherit = options.stdio !== undefined && options.stdio !== "pipe";
  const r = spawnSync(process.execPath, [SUPERVISOR, String(Date.now() + limit), String(GRACE_MS), inherit ? "inherit" : "pipe", command, ...args], {
    cwd: options.cwd,
    env: options.env,
    input: options.input ?? "",
    detached: true,
    // The answer comes on fd 3, apart from the command's own output.
    stdio: ["pipe", inherit ? "inherit" : "pipe", inherit ? "inherit" : "pipe", "pipe"],
    maxBuffer: options.maxBuffer ?? 256 * 1024 * 1024,
    // A backstop only: the supervisor ends its group itself.
    timeout: Math.max(0, limit) + GRACE_MS + 10_000,
    killSignal: "SIGKILL",
  });
  // The supervisor ends by killing its own group, so it dies of SIGKILL
  // after a complete answer: the end marker says the answer is complete.
  const raw = r.output?.[3]?.toString("utf8") ?? "";
  if (!raw.endsWith(END_MARKER)) return failed("the deadline supervisor gave no complete answer", r.signal);
  const answer = JSON.parse(raw.slice(0, -END_MARKER.length));
  return {
    status: answer.status, signal: answer.signal, timedOut: answer.timedOut,
    stdout: decode(answer.stdout ?? ""), stderr: answer.spawnError ? answer.stderr : decode(answer.stderr ?? ""),
    ...(answer.spawnError ? { error: Object.assign(new Error(answer.stderr), { code: answer.spawnError }) } : {}),
  };
}
