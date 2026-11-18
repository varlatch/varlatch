// SPDX-License-Identifier: Apache-2.0
/**
 * A target operation's deadline. A suite that bounds a call
 * (suite-kit's targetOp with timeoutMs) passes the deadline to
 * target-op.mjs in CONFORMANCE_OP_DEADLINE (epoch milliseconds), and the
 * target's own child processes run under it through deadlineSpawnSync:
 * `docker compose exec` and `varlatchd admin` stop at the deadline, with
 * every process they started, so a killed operation leaves no orphan
 * behind. targetOp's own kill of the wrapper comes later, as a backstop.
 */
import { spawnSync } from "node:child_process";

export const DEADLINE_ENV = "CONFORMANCE_OP_DEADLINE";

/** Milliseconds left before the operation's deadline; undefined without one. */
export function remainingMs(env = process.env) {
  const at = Number(env[DEADLINE_ENV]);
  return Number.isFinite(at) && at > 0 ? Math.max(0, at - Date.now()) : undefined;
}

/**
 * spawnSync, bounded by the operation's deadline when there is one (and by
 * `timeout` when given). Under a deadline the command runs under coreutils
 * `timeout`, which signals the whole process group it starts, so the
 * command's own children stop with it (the docker CLI runs Compose as a
 * child plugin); the answer then has `timedOut` set.
 */
export function deadlineSpawnSync(command, args, options = {}) {
  const left = remainingMs();
  if (left === undefined) return spawnSync(command, args, options);
  const limit = Math.min(left, options.timeout ?? Infinity);
  const { timeout: _ignored, ...rest } = options;
  const seconds = Math.max(0.1, limit / 1000).toFixed(3);
  // -k: a command that ignores the TERM is killed a second later.
  const r = spawnSync("timeout", ["-k", "1", seconds, command, ...args], { ...rest, timeout: limit + 5000, killSignal: "SIGKILL" });
  // coreutils timeout exits 124 when the command timed out (137 after -k).
  return Object.assign(r, { timedOut: r.status === 124 || r.status === 137 || r.error?.code === "ETIMEDOUT" });
}
