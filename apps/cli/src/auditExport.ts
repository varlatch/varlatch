// SPDX-License-Identifier: Apache-2.0
import type {
  AuditExport,
  AuditExportChangeInput,
  AuditExportCheck,
  AuditExportCheckInput,
  AuditExportCreateInput,
  AuditExportDestinationInput,
  AuditExportRetention,
  AuditExportStatus,
} from "@varlatch/sdk";

/**
 * `varlatch audit-export create|show|change|remove|check` (ADR-0056): an
 * Organization's audit log copied to an S3-compatible bucket it controls.
 * The secret access key is never taken from the command line: --secret-stdin,
 * --secret-file <path>, or a hidden prompt on a terminal (never in assisted
 * mode). A destination change, a new key, a shorter or removed retention and
 * removal need the person's approval with a trusted passkey, which the
 * shared step-up handling asks for; removal also names the Organization
 * again with --confirm.
 */

export const AUDIT_EXPORT_CAPABILITY = "audit.storage-export";

const DESTINATION = "[--endpoint <url>] [--region <region>] [--bucket <bucket>] [--prefix <prefix>] [--path-style | --no-path-style]";
const KEY = "--access-key-id <id> [--secret-stdin | --secret-file <path>]";
const SCOPE = "[--org <organization>] [--server <url>]";
export const AUDIT_EXPORT_USAGE = [
  `Usage: varlatch audit-export show [--json] ${SCOPE}`,
  `       varlatch audit-export create --endpoint <url> --region <region> --bucket <bucket> [--prefix <prefix>] [--path-style]`,
  `                                    ${KEY} [--retention <compliance|governance>:<days>] [--from <beginning|now>] [--json] ${SCOPE}`,
  `       varlatch audit-export change ${DESTINATION}`,
  `                                    [--retention <mode>:<days> | --no-retention] [--json] ${SCOPE}`,
  `       varlatch audit-export change ${KEY} [--json] ${SCOPE}`,
  `       varlatch audit-export remove --confirm <organization> [--json] ${SCOPE}`,
  `       varlatch audit-export check [${DESTINATION.slice(1, -1)}] [${KEY}] [--retention <mode>:<days>] [--json] ${SCOPE}`,
].join("\n");

export const AUDIT_EXPORT_SUBCOMMANDS = ["show", "create", "change", "remove", "check"] as const;
export type AuditExportSubcommand = (typeof AUDIT_EXPORT_SUBCOMMANDS)[number];

/** A command line that cannot be right: exit 64. */
export class AuditExportUsageError extends Error {
  override name = "AuditExportUsageError";
}

/** The server cannot do it, or there is nothing to act on: exit 1. */
export class AuditExportError extends Error {
  override name = "AuditExportError";
}

/** `--retention <mode>:<days>`. */
export function parseRetention(raw: string): AuditExportRetention {
  const m = /^(compliance|governance):([1-9]\d{0,3})$/.exec(raw);
  if (!m || Number(m[2]) > 3650) {
    throw new AuditExportUsageError(`--retention takes <compliance|governance>:<days>, days from 1 to 3650: ${raw}`);
  }
  return { mode: m[1] as AuditExportRetention["mode"], days: Number(m[2]) };
}

/** The destination fields the command line names; undefined for those it does not. */
export function destinationFields(values: ReadonlyMap<string, string>, booleans: ReadonlySet<string>): Partial<AuditExportDestinationInput> {
  if (booleans.has("--path-style") && booleans.has("--no-path-style")) {
    throw new AuditExportUsageError("--path-style and --no-path-style cannot both be given");
  }
  const out: Partial<AuditExportDestinationInput> = {};
  const endpoint = values.get("--endpoint");
  const region = values.get("--region");
  const bucket = values.get("--bucket");
  const prefix = values.get("--prefix");
  if (endpoint !== undefined) out.endpoint = endpoint;
  if (region !== undefined) out.region = region;
  if (bucket !== undefined) out.bucket = bucket;
  if (prefix !== undefined) out.prefix = prefix;
  if (booleans.has("--path-style")) out.pathStyle = true;
  if (booleans.has("--no-path-style")) out.pathStyle = false;
  return out;
}

/** Whether the command line names a key: then a secret source must come with it, and only one. */
export function keyRequested(values: ReadonlyMap<string, string>, booleans: ReadonlySet<string>): boolean {
  const secretGiven = booleans.has("--secret-stdin") || values.has("--secret-file");
  if (booleans.has("--secret-stdin") && values.has("--secret-file")) {
    throw new AuditExportUsageError("give the secret access key one way only: --secret-stdin or --secret-file <path>");
  }
  if (secretGiven && !values.has("--access-key-id")) throw new AuditExportUsageError("--secret-stdin and --secret-file go with --access-key-id");
  return values.has("--access-key-id");
}

/** `create`'s body, without the key (read separately). */
export function createInput(
  values: ReadonlyMap<string, string>,
  booleans: ReadonlySet<string>,
): Omit<AuditExportCreateInput, "credential"> {
  const d = destinationFields(values, booleans);
  if (booleans.has("--no-path-style")) throw new AuditExportUsageError("create takes --path-style or nothing (virtual-hosted)");
  for (const flag of ["--endpoint", "--region", "--bucket"] as const) {
    if (!values.has(flag)) throw new AuditExportUsageError(`create needs ${flag}`);
  }
  if (!values.has("--access-key-id")) throw new AuditExportUsageError("create needs --access-key-id, and the secret by --secret-stdin, --secret-file or the prompt");
  if (booleans.has("--no-retention")) throw new AuditExportUsageError("--no-retention goes with change; create without --retention sets none");
  const from = values.get("--from") ?? "beginning";
  if (from !== "beginning" && from !== "now") throw new AuditExportUsageError(`--from takes beginning or now: ${from}`);
  const retention = values.get("--retention");
  return {
    destination: d as AuditExportDestinationInput,
    retention: retention === undefined ? null : parseRetention(retention),
    from,
  };
}

/** What `change` asks for: the destination and retention, or the key on its own. */
export type ChangeRequest =
  | { kind: "settings"; destination: Partial<AuditExportDestinationInput>; retention: AuditExportRetention | null | undefined }
  | { kind: "key" };

export function changeRequest(values: ReadonlyMap<string, string>, booleans: ReadonlySet<string>): ChangeRequest {
  const destination = destinationFields(values, booleans);
  const retentionRaw = values.get("--retention");
  if (retentionRaw !== undefined && booleans.has("--no-retention")) throw new AuditExportUsageError("--retention and --no-retention cannot both be given");
  const retention = retentionRaw !== undefined ? parseRetention(retentionRaw) : booleans.has("--no-retention") ? null : undefined;
  const settings = Object.keys(destination).length > 0 || retention !== undefined;
  if (keyRequested(values, booleans)) {
    if (settings) throw new AuditExportUsageError("change the key on its own: each change is approved separately");
    return { kind: "key" };
  }
  if (!settings) throw new AuditExportUsageError("name what changes: destination options, --retention or --no-retention, or a new key with --access-key-id");
  return { kind: "settings", destination, retention };
}

/** `change`'s body, at the export's current version. */
export function changeInput(request: Extract<ChangeRequest, { kind: "settings" }>, current: AuditExport): AuditExportChangeInput {
  return {
    expectedVersion: current.version,
    ...(Object.keys(request.destination).length > 0 ? { destination: request.destination } : {}),
    ...(request.retention !== undefined ? { retention: request.retention } : {}),
  };
}

/**
 * `check`'s body: the destination named, the export's own where none is;
 * a key given, or none to use the stored one (the server then probes only
 * the export's own destination).
 */
export function checkInput(
  values: ReadonlyMap<string, string>,
  booleans: ReadonlySet<string>,
  current: AuditExport | null,
): Omit<AuditExportCheckInput, "credential"> {
  const named = destinationFields(values, booleans);
  const base = current
    ? { endpoint: current.destination.endpoint, region: current.destination.region, bucket: current.destination.bucket, prefix: current.destination.prefix, pathStyle: current.destination.pathStyle }
    : null;
  const destination = { ...(base ?? {}), ...named };
  if (!destination.endpoint || !destination.region || !destination.bucket) {
    throw new AuditExportUsageError("there is no export to check: give --endpoint, --region and --bucket, and a key");
  }
  const retention = values.get("--retention");
  return {
    destination: destination as AuditExportDestinationInput,
    retention: retention !== undefined ? parseRetention(retention) : current?.retention ?? null,
  };
}

/** The live export, or a failure naming what to do. */
export function liveExport(status: AuditExportStatus, organization: string): AuditExport {
  const e = status.export;
  if (!e || (e.state !== "active" && e.state !== "draining")) {
    throw new AuditExportError(`${organization} has no audit export. Create one with: varlatch audit-export create ... Nothing was changed.`);
  }
  return e;
}

const retentionWords = (r: AuditExportRetention | null) => (r ? `${r.mode}, ${r.days} day${r.days === 1 ? "" : "s"}` : "none");

const LOCK_WORDS: Record<AuditExport["objectLock"], string> = {
  verified: "verified",
  accepted: "lock headers accepted, not verified for this provider",
  "not-set": "no retention set",
};

function hostOf(endpoint: string): string {
  try {
    return new URL(endpoint).host;
  } catch {
    return endpoint;
  }
}

/** The human format of `show`. */
export function statusLines(organization: string, status: AuditExportStatus): string[] {
  const lines: string[] = [];
  if (!status.enabled) lines.push("Audit export is stopped by the host operator on this installation (VARLATCH_AUDIT_EXPORT=off): nothing is delivered.");
  const e = status.export;
  if (!e) {
    lines.push(`${organization} has no audit export.`, "Create one with: varlatch audit-export create --endpoint <url> --region <region> --bucket <bucket> --access-key-id <id>");
    return lines;
  }
  const d = e.destination;
  lines.push(
    `Audit export of ${organization}: ${e.state}${e.state === "draining" && e.drainDeadline ? ` (until ${e.drainDeadline} at the latest)` : ""}`,
    `  destination   ${hostOf(d.endpoint)}, bucket ${d.bucket}, prefix ${d.prefix === "" ? "(none)" : d.prefix}${d.pathStyle ? ", path-style" : ""}`,
    `  retention     ${retentionWords(e.retention)}; Object Lock ${LOCK_WORDS[e.objectLock]}`,
    `  stream        ${e.streamId}, delivered up to position ${e.cursor}`,
  );
  if (e.lag) {
    lines.push(`  pending       ${e.lag.pending} event${e.lag.pending === 1 ? "" : "s"}${e.lag.oldestPendingAt ? `, the oldest from ${e.lag.oldestPendingAt}` : ""}`);
  }
  lines.push(`  last written  ${e.lastSuccessAt ?? "never"}${e.lastAttemptAt && e.lastAttemptAt !== e.lastSuccessAt ? `; last attempt ${e.lastAttemptAt}` : ""}`);
  lines.push(`  heartbeat     ${e.lastHeartbeatAt ? `last for ${e.lastHeartbeatAt}` : "none yet"} (one an hour; none in the bucket for two hours means the copy stopped)`);
  if (e.lastError) lines.push(`  last error    ${e.lastError}${e.failingSince ? ` (failing since ${e.failingSince})` : ""}`);
  if (e.stoppedReason === "object_conflict") {
    lines.push("  STOPPED       an object with the planned name exists with other content; nothing was overwritten. Change the destination or remove the export.");
  }
  if (e.unsupportedPlanFormat !== null) {
    lines.push(
      `  STOPPED       a pending object was planned in format ${e.unsupportedPlanFormat}, which this release cannot upload;`,
      "                the host operator finishes it with an earlier release or runs varlatchd admin audit-export discard-plan.",
    );
  }
  lines.push(
    `  key           ${e.keyCanRead === null ? "object read not determined" : e.keyCanRead ? "can read objects" : "write-only"}` +
      `, ${e.retentionReadable === null ? "retention read not determined" : e.retentionReadable ? "can read retention" : "cannot read retention"}`,
    `  version       ${e.version}`,
  );
  return lines;
}

/** The human format of `check`. */
export function checkLines(check: AuditExportCheck): string[] {
  if (!check.ok) return [`The destination check failed: ${check.message ?? "no reason given"}`, "Nothing was saved."];
  return [
    "The destination passed the check: it refuses to overwrite an existing object (If-None-Match).",
    `Object Lock: ${check.objectLock === null ? "not checked" : LOCK_WORDS[check.objectLock]}.`,
    `The key ${check.keyCanRead === null ? "may or may not read objects (not determined)" : check.keyCanRead ? "can read objects" : "cannot read objects (write-only)"}.`,
    "Nothing was saved.",
  ];
}
