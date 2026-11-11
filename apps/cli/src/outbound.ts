// SPDX-License-Identifier: Apache-2.0
import { spawnSync } from "node:child_process";

/**
 * The host side of `varlatchd admin outbound check` (ADR-0057 Decision 10):
 * every destination an Organization configured, with the outbound policy's
 * verdict, and the VARLATCH_OUTBOUND_ALLOW value that would allow the
 * refused ones. varlatchd runs it inside its container; it makes DNS
 * lookups only.
 */

export const OUTBOUND_USAGE = "Usage: varlatch admin outbound check [--allow <value>] [--org <organization>] [--json] [--dir <compose-directory>]";

export interface OutboundCheckRun {
  /** varlatchd's exit code: 0 all allowed, 1 something refused, 2 something unresolved; null when it did not run. */
  status: number | null;
  stdout: string;
  stderr: string;
}

/**
 * Run the check in the Compose directory `dir`: in the running varlatchd
 * container (`exec`), or in a one-off container of the service as the
 * Compose file now names it (`run`), which is how `varlatch upgrade` runs
 * the new release's image against the database before it starts.
 */
export function runOutboundCheck(dir: string, args: string[], via: "exec" | "run" = "exec", timeoutMs = 120_000): OutboundCheckRun {
  const command =
    via === "exec"
      ? ["compose", "exec", "-T", "varlatchd", "node", "dist/cli.js", "admin", "outbound", "check", ...args]
      : ["compose", "run", "--rm", "--no-deps", "-T", "varlatchd", "admin", "outbound", "check", ...args];
  const result = spawnSync("docker", command, { cwd: dir, encoding: "utf8", maxBuffer: 16 * 1024 * 1024, timeout: timeoutMs, stdio: ["ignore", "pipe", "pipe"] });
  return { status: result.error ? null : result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

interface Report {
  destinations?: { organization: string; kind: string; id: string; host: string; port: number; verdict: string; reason?: string }[];
  suggested?: string | null;
  apart?: { host: string; port: number; why: string }[];
}

/**
 * The upgrade's advisory finding (ADR-0057 Decision 10): the refused
 * destinations and the line to add, or null when nothing is refused. It
 * never blocks the upgrade.
 */
export function outboundAdvisory(run: OutboundCheckRun): string[] | null {
  if (run.status === null || run.status === 0) return null;
  let report: Report;
  try {
    report = JSON.parse(run.stdout.slice(run.stdout.indexOf("{"))) as Report;
  } catch {
    return null;
  }
  const refused = (report.destinations ?? []).filter((d) => d.verdict === "refused");
  if (refused.length === 0) return null;
  const lines = [
    "ADVISORY: this release refuses outbound requests to private and internal addresses unless the host allows them.",
    `${refused.length} configured destination${refused.length === 1 ? " is" : "s are"} refused; deliveries to ${refused.length === 1 ? "it" : "them"} wait, nothing is lost:`,
    ...refused.map((d) => `  ${d.organization}  ${d.kind}  ${d.id}  ${d.host}:${d.port}  (${d.reason})`),
  ];
  if (report.suggested) {
    lines.push("To allow them, add to .env and restart varlatchd (docker compose up -d varlatchd):", `  VARLATCH_OUTBOUND_ALLOW=${report.suggested}`);
  }
  for (const a of report.apart ?? []) lines.push(`  Not suggested: ${a.host}:${a.port}: ${a.why}`);
  lines.push("Details: varlatch admin outbound check (https://docs.varlatch.com/reference/outbound-policy/)");
  return lines;
}
