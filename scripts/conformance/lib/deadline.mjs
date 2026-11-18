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
 * `timeout` when given). Under a deadline the command runs in a process
 * group of its own (lib/deadline-supervisor.mjs): at the deadline the whole
 * group gets SIGTERM, then SIGKILL after GRACE_MS, and once the command has
 * exited the group gets SIGKILL anyway, so nothing it started outlives the
 * call. The answer is spawnSync's, with `timedOut` set whenever the
 * deadline fired. A deadline already past runs nothing. Without a deadline
 * the command runs as plain spawnSync.
 */
export function deadlineSpawnSync(command, args, options = {}) {
  const left = remainingMs();
  if (left === undefined) return spawnSync(command, args, options);
  const limit = Math.min(left, options.timeout ?? Infinity);
  const encoding = options.encoding;
  const decode = (b64) => (encoding ? Buffer.from(b64, "base64").toString(encoding) : Buffer.from(b64, "base64"));
  if (limit <= 0) {
    return { status: null, signal: null, timedOut: true, stdout: decode(""), stderr: decode(""), error: Object.assign(new Error("the operation's deadline has passed"), { code: "ETIMEDOUT" }) };
  }
  const inherit = options.stdio !== undefined && options.stdio !== "pipe";
  const r = spawnSync(process.execPath, [SUPERVISOR, String(Date.now() + limit), String(GRACE_MS), inherit ? "inherit" : "pipe", command, ...args], {
    cwd: options.cwd,
    env: options.env,
    input: options.input,
    encoding: "utf8",
    maxBuffer: options.maxBuffer ?? 256 * 1024 * 1024,
    // A backstop only: the supervisor ends the group itself.
    timeout: limit + GRACE_MS + 10_000,
    killSignal: "SIGKILL",
  });
  let answer;
  try {
    answer = JSON.parse(r.stdout);
  } catch {
    return { status: null, signal: r.signal, timedOut: true, stdout: decode(""), stderr: decode(""), error: r.error ?? new Error("the deadline supervisor gave no answer") };
  }
  return {
    status: answer.status, signal: answer.signal, timedOut: answer.timedOut,
    stdout: decode(answer.stdout ?? ""), stderr: answer.spawnError ? answer.stderr : decode(answer.stderr ?? ""),
    ...(answer.spawnError ? { error: Object.assign(new Error(answer.stderr), { code: answer.spawnError }) } : {}),
  };
}
