// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import { constants } from "node:os";
import type { SecretEntry } from "@varlatch/matcher";
import type { EffectiveConfiguration } from "@varlatch/protocol";
import { OutputRedaction, type RedactionMode } from "./redact.js";

/**
 * Default `varlatch run`: fetch, inject, forward signals, return the child's
 * exit code. This path applies no contract validation or type conversion,
 * and redacts output only with `--redact` or in assisted mode (ADR-0043).
 */

/**
 * Reserved launcher metadata. Only strict runs set it; every run removes an
 * inherited one, so a context left by an outer run never describes an inner
 * run's Environment, and no stored value is ever injected under this name.
 */
export const RUN_CONTEXT = "VARLATCH_RUN_CONTEXT";

/**
 * The command's environment: `base` with every delivered value over it.
 * An item named with `--omit` is not delivered, and an inherited copy under
 * its name is removed, so the command never holds it (ADR-0043 Decision 4,
 * amended).
 */
export function buildEnv(
  base: NodeJS.ProcessEnv,
  effective: EffectiveConfiguration,
  omitted: ReadonlySet<string> = new Set(),
): NodeJS.ProcessEnv {
  const env = { ...base };
  delete env[RUN_CONTEXT];
  for (const name of omitted) delete env[name];
  for (const item of effective.items ?? []) {
    if (item.name === RUN_CONTEXT || omitted.has(item.name)) continue;
    if (item.value !== null && item.value !== undefined) {
      env[item.name] = item.value;
    }
  }
  return env;
}

/** Items the server did not give this identity; an omitted item was not asked for, so it is not one of them. */
export function withheldItems(effective: EffectiveConfiguration, omitted: ReadonlySet<string> = new Set()): string[] {
  return (effective.items ?? [])
    .filter((i) => (i.value === null || i.value === undefined) && !omitted.has(i.name))
    .map((i) => i.name);
}

/**
 * Why the `--omit` names cannot be used, or null. Each must name an item
 * stored in the environment or defined in its Contract: a misspelled name
 * is an error, never ignored, or the item the operator meant to keep from
 * the command would reach it.
 */
export function omitProblem(omitted: Iterable<string>, known: ReadonlySet<string>): string | null {
  const unknown = [...new Set(omitted)].filter((n) => !known.has(n)).sort();
  if (unknown.length === 0) return null;
  return `--omit must name an item stored in this environment or in its Contract; not found: ${unknown.join(", ")}`;
}

/**
 * The exit status for a command ended by `signal`: 128 plus the signal's
 * number, as a shell reports it (130 for SIGINT, 143 for SIGTERM, 129 for
 * SIGHUP). A signal this platform does not number gives 143, the SIGTERM
 * status, so the status still says the command was ended by a signal.
 */
export function signalExitCode(signal: string): number {
  const number: unknown = (constants.signals as Record<string, unknown>)[signal];
  return 128 + (typeof number === "number" && number > 0 ? number : constants.signals.SIGTERM);
}

/**
 * Start the child and return its exit code, or `signalExitCode` when a
 * signal ended it; every mode of `varlatch run` starts its command here.
 * With `redact` (the sensitive values delivered in `env`, and in assisted
 * mode also inherited values under known Secret names), its stdout and
 * stderr are piped through output redaction, even when this process's own
 * output is a terminal; stdin, signals, and the exit code are unchanged,
 * and the run ends once the child has exited and both pipes have closed.
 */
/**
 * The signals `varlatch run` passes on to its command. Beyond Ctrl-C
 * (SIGINT) and a stop (SIGTERM), a service manager or script that signals
 * only the CLI's process (a reload with SIGHUP, log rotation with SIGUSR1)
 * must reach the command, or the CLI would exit and leave it running.
 * Job-control and terminal signals (SIGTSTP, SIGCONT, SIGWINCH) are left
 * alone: they reach the command through the terminal. Windows has only the
 * first two. Listening for SIGUSR1 also keeps Node from starting its
 * debugger on it.
 */
export const FORWARDED_SIGNALS: readonly NodeJS.Signals[] =
  process.platform === "win32"
    ? ["SIGINT", "SIGTERM"]
    : ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT", "SIGUSR1", "SIGUSR2"];

/**
 * Forwarded signals that usually end a run: with `--redact`, held bytes are
 * then discarded rather than released at the end of the stream. SIGHUP is
 * here even though a service may treat it as "reload": discarding is the
 * conservative choice. SIGUSR1 and SIGUSR2 do not end a run.
 */
const INTERRUPTING: ReadonlySet<NodeJS.Signals> = new Set(["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"]);

export function runChild(
  command: string,
  args: string[],
  env: NodeJS.ProcessEnv,
  redact?: SecretEntry[],
  mode: RedactionMode = "redact",
): Promise<number> {
  return new Promise((resolvePromise, reject) => {
    const redaction = redact ? new OutputRedaction(redact, mode) : undefined;
    for (const line of redaction?.notices() ?? []) console.error(line);
    const child = spawn(command, args, { stdio: redaction ? ["inherit", "pipe", "pipe"] : "inherit", env });
    const relayed = redaction?.relay([
      [child.stdout!, process.stdout],
      [child.stderr!, process.stderr],
    ]);
    const forwarding = FORWARDED_SIGNALS.map((signal) => {
      const forward = (): void => {
        if (INTERRUPTING.has(signal)) redaction?.interrupt();
        child.kill(signal);
      };
      process.on(signal, forward);
      return [signal, forward] as const;
    });
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      for (const [forwarded, forward] of forwarding) process.off(forwarded, forward);
      const exitCode = signal ? signalExitCode(signal) : (code ?? 1);
      if (relayed) relayed.then(() => resolvePromise(exitCode), reject);
      else resolvePromise(exitCode);
    });
  });
}
