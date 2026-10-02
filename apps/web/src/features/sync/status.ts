// SPDX-License-Identifier: AGPL-3.0-or-later
import type { PlatformConnection, SyncTarget } from "@varlatch/protocol";
import { platformMeta } from "./platform-meta";

/**
 * Sync Target presentation: where a target pushes, how healthy it is, and
 * which fix to offer. Pure, so the rules are tested without rendering.
 */

export type TargetTone = "ok" | "warn" | "error" | "muted" | "live";

export type TargetFix = "replace-credential" | "reaffirm" | "retry" | "resume" | "reconnect";

export interface TargetStatus {
  tone: TargetTone;
  /** "In sync", "Failing", "Paused", … */
  label: string;
  /** Short muted context, e.g. "3 attempts". */
  detail?: string | undefined;
  /** The platform's last error, when failing. */
  error?: string | undefined;
  /** The one action that fixes it, when there is one. */
  fix?: TargetFix | undefined;
  /** When the state began or the last push happened. */
  at?: string | null | undefined;
}

/** True when an error text reads like the platform refused the credential. */
export function isCredentialError(text: string | null | undefined): boolean {
  return /\b(401|403)\b|unauthori[sz]ed|bad credentials|forbidden|invalid (api )?(token|key|credential)|authentication failed/i.test(
    text ?? "",
  );
}

/** "AdapterError: GitHub public key fetch failed (401)" -> "GitHub public key fetch failed (401)". */
export function cleanError(text: string | null | undefined): string | undefined {
  if (!text) return undefined;
  return text
    .replace(/^degraded:\s*/i, "")
    .replace(/^[A-Za-z]*Error:\s*/, "")
    .trim();
}

export function targetStatus(t: SyncTarget): TargetStatus {
  const reaffirm = (t.lastResult ?? "").includes("re-affirmation required");
  if (t.state === "paused") return { tone: "muted", label: "Paused", at: t.updatedAt ?? t.createdAt, fix: "resume" };
  if (t.state === "disabled") {
    if (t.disabledReason === "connection-revoked") {
      return { tone: "error", label: "Stopped", detail: "connection revoked", fix: "reconnect", at: t.updatedAt };
    }
    return {
      tone: "error",
      label: "Stopped",
      detail: `after ${t.failureCount} failed attempt${t.failureCount === 1 ? "" : "s"}`,
      error: cleanError(t.lastResult),
      fix: isCredentialError(t.lastResult) ? "replace-credential" : "resume",
      at: t.lastAttemptAt,
    };
  }
  if (reaffirm) {
    return { tone: "warn", label: "Needs re-affirmation", detail: "a mapped item became a secret", fix: "reaffirm", at: t.lastAttemptAt };
  }
  if (t.failureCount > 0 || (t.lastResult && t.lastResult !== "ok")) {
    return {
      tone: "error",
      label: "Failing",
      detail: t.failureCount > 0 ? `${t.failureCount} attempt${t.failureCount === 1 ? "" : "s"}` : undefined,
      error: cleanError(t.lastResult),
      fix: isCredentialError(t.lastResult) ? "replace-credential" : "retry",
      at: t.lastAttemptAt,
    };
  }
  if (!t.lastAttemptAt) return { tone: "live", label: "Waiting for first push", at: null };
  if (t.needsSync) return { tone: "live", label: "Syncing", at: t.lastAttemptAt };
  return { tone: "ok", label: "In sync", at: t.lastAttemptAt };
}

/** Where a target pushes: a primary mono label and an optional qualifier. */
export function targetDestination(
  t: SyncTarget,
  connection?: PlatformConnection | undefined,
): { primary: string; qualifier?: string | undefined } {
  const d = t.destination;
  if (d.repo) {
    const owner = connection?.platform === "github-actions" ? connection.baseIdentity : undefined;
    return {
      primary: owner && !d.repo.includes("/") ? `${owner}/${d.repo}` : d.repo,
      qualifier: d.environment ? `environment ${d.environment}` : undefined,
    };
  }
  if (d.applicationUuid) return { primary: d.applicationUuid, qualifier: "application" };
  // Convex: the connection's deployment is the destination.
  return { primary: connection ? hostOf(connection.baseIdentity) : "deployment" };
}

/** One line: "GitHub Actions acme-org/api (production)". */
export function targetLabel(t: SyncTarget, connection?: PlatformConnection | undefined): string {
  const dest = targetDestination(t, connection);
  const platform = connection ? platformMeta(connection.platform).label : "integration";
  const env = t.destination.environment ? ` (${t.destination.environment})` : "";
  return `${platform} ${dest.primary}${env}`;
}

export function hostOf(urlOrName: string): string {
  try {
    return new URL(urlOrName).host || urlOrName;
  } catch {
    return urlOrName;
  }
}

/** "All items", "All items except CONVEX_*", "Explicit list · 4 items". */
export function mappingSummary(t: SyncTarget): { label: string; excluded?: string[]; renames: number } {
  if (t.mapping.kind === "wildcard") {
    const ex = t.mapping.exclude ?? [];
    return ex.length > 0 ? { label: "All items except", excluded: ex, renames: 0 } : { label: "All items", renames: 0 };
  }
  const n = t.mapping.items.length;
  return { label: `Explicit list · ${n} item${n === 1 ? "" : "s"}`, renames: t.mapping.items.filter((i) => i.rename).length };
}

/** Behaviour flags worth a word on the card. */
export function targetOptions(t: SyncTarget): string[] {
  const out: string[] = [];
  if (t.redeploy) out.push(t.destination.deployAction === "restart" ? "restarts after changes" : "redeploys after changes");
  if (t.removeOrphans) out.push("removes names that leave");
  if (t.destination.buildTime === "true") out.push("build-time keys");
  if (t.destination.buildTime === "false") out.push("runtime-only keys");
  return out;
}

export interface ConnectionHealth {
  tone: TargetTone;
  label: string;
  /** Set when the platform rejected the credential. */
  credentialRejected: boolean;
  at?: string | null | undefined;
}

/** A connection is as healthy as the targets that use it. */
export function connectionHealth(targets: SyncTarget[]): ConnectionHealth {
  const live = targets.filter((t) => t.state !== "paused");
  if (targets.length === 0) return { tone: "muted", label: "Not used yet", credentialRejected: false };
  if (live.length === 0) return { tone: "muted", label: "All targets paused", credentialRejected: false };
  const rejected = live.find((t) => (t.failureCount > 0 || t.state === "disabled") && isCredentialError(t.lastResult));
  if (rejected) return { tone: "error", label: "Credential rejected", credentialRejected: true, at: rejected.lastAttemptAt };
  const failing = live.filter((t) => t.state === "disabled" || t.failureCount > 0 || (t.lastResult && t.lastResult !== "ok"));
  if (failing.length > 0) {
    return {
      tone: "error",
      label: `${failing.length} target${failing.length === 1 ? "" : "s"} failing`,
      credentialRejected: false,
      at: failing[0]!.lastAttemptAt,
    };
  }
  if (live.every((t) => !t.lastAttemptAt)) return { tone: "live", label: "Waiting for first push", credentialRejected: false };
  return { tone: "ok", label: "Healthy", credentialRejected: false };
}
