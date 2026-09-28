// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
import type { SecretEntry } from "@varlatch/matcher";
import type { EffectiveConfiguration } from "@varlatch/protocol";
import { OutputRedaction } from "./redact.js";

/**
 * Default `varlatch run`: fetch, inject, forward signals, return the child's
 * exit code. This path applies no contract validation or type conversion,
 * and redacts output only with `--redact`.
 */

/**
 * Reserved launcher metadata. Only strict runs set it; every run removes an
 * inherited one, so a context left by an outer run never describes an inner
 * run's Environment, and no stored value is ever injected under this name.
 */
export const RUN_CONTEXT = "VARLATCH_RUN_CONTEXT";

export function buildEnv(
  base: NodeJS.ProcessEnv,
  effective: EffectiveConfiguration,
): NodeJS.ProcessEnv {
  const env = { ...base };
  delete env[RUN_CONTEXT];
  for (const item of effective.items ?? []) {
    if (item.name === RUN_CONTEXT) continue;
    if (item.value !== null && item.value !== undefined) {
      env[item.name] = item.value;
    }
  }
  return env;
}

export function withheldItems(effective: EffectiveConfiguration): string[] {
  return (effective.items ?? [])
    .filter((i) => i.value === null || i.value === undefined)
    .map((i) => i.name);
}

/**
 * Start the child and return its exit code. With `redact` (the sensitive
 * values delivered in `env`), its stdout and stderr are piped through output
 * redaction; stdin, signals, and the exit code are unchanged, and the run
 * ends once the child has exited and both pipes have closed.
 */
export function runChild(
  command: string,
  args: string[],
  env: NodeJS.ProcessEnv,
  redact?: SecretEntry[],
): Promise<number> {
  return new Promise((resolvePromise, reject) => {
    const redaction = redact ? new OutputRedaction(redact) : undefined;
    for (const line of redaction?.notices() ?? []) console.error(line);
    const child = spawn(command, args, { stdio: redaction ? ["inherit", "pipe", "pipe"] : "inherit", env });
    const relayed = redaction?.relay([
      [child.stdout!, process.stdout],
      [child.stderr!, process.stderr],
    ]);
    const forward = (signal: NodeJS.Signals) => () => {
      redaction?.interrupt();
      child.kill(signal);
    };
    const sigint = forward("SIGINT");
    const sigterm = forward("SIGTERM");
    process.on("SIGINT", sigint);
    process.on("SIGTERM", sigterm);
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      process.off("SIGINT", sigint);
      process.off("SIGTERM", sigterm);
      const exitCode = signal ? 128 + (signal === "SIGKILL" ? 9 : 15) : (code ?? 1);
      if (relayed) relayed.then(() => resolvePromise(exitCode), reject);
      else resolvePromise(exitCode);
    });
  });
}
