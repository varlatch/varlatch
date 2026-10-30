// SPDX-License-Identifier: AGPL-3.0-or-later
import type { PlatformConnection, SyncTarget, SyncTargetNote } from "@varlatch/protocol";
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

/**
 * The names a run held, with why: varlatchd appends "; held: NAME: reason;
 * …" to a run's result and counts no failure for them (ADR-0031
 * amendment 2026-10-22). Undefined when nothing was held.
 */
export function heldText(result: string | null | undefined): string | undefined {
  const at = (result ?? "").indexOf("; held: ");
  if (at < 0) return undefined;
  return (result ?? "").slice(at + "; held: ".length).replace(/; redeploy failed \(.*$/s, "").trim() || undefined;
}

/**
 * What a Target holds, from its notes (each held name, and a count of the
 * rest), or else from its last result: undefined when it holds nothing.
 */
export function heldSummary(t: SyncTarget): { detail: string; error: string } | undefined {
  const notes = t.lastNotes ?? [];
  const named = notes.filter((n) => n.code === "held" && n.name);
  const more = notes.reduce((sum, n) => sum + (n.code === "held-more" ? (n.count ?? 0) : 0), 0);
  const count = named.length + more;
  if (count > 0) {
    return {
      detail: `${count} name${count === 1 ? "" : "s"} not pushed`,
      error: named.map((n) => n.name).join(", ") + (more > 0 ? ` and ${more} more` : ""),
    };
  }
  const text = heldText(t.lastResult);
  return text ? { detail: "some names not pushed", error: text } : undefined;
}

/**
 * The platform's error when a push landed but its redeploy did not:
 * varlatchd records "ok; redeploy failed (<error>)" without counting a
 * failure, because the values were stored.
 */
export function redeployError(result: string | null | undefined): string | undefined {
  const match = /; redeploy failed \((.*?)\)?$/s.exec(result ?? "");
  return match ? cleanError(match[1]) : undefined;
}

/**
 * A refetch interval for a list of Targets: every 2 s while one of them can
 * still send. Nothing announces the end of a run (a fenced or out-of-budget
 * run records no event), so "Pushing" and "Pausing" are kept current by
 * asking (ADR-0050).
 */
export function refetchWhileRunning(data: { items?: SyncTarget[] } | undefined): number | false {
  return (data?.items ?? []).some((t) => t.drained === false) ? 2000 : false;
}

export function targetStatus(t: SyncTarget): TargetStatus {
  const reaffirm = (t.lastResult ?? "").includes("re-affirmation required");
  if (t.state === "paused") {
    // A run that was going when the pause landed may still send its one
    // request; until it can start no other, the pause is still taking hold
    // (ADR-0050). Older servers do not say, and read as paused.
    if (t.drained === false) return { tone: "live", label: "Pausing", detail: "a push is finishing", at: t.updatedAt ?? t.createdAt };
    return { tone: "muted", label: "Paused", at: t.updatedAt ?? t.createdAt, fix: "resume" };
  }
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
  // Every failed run counts in failureCount; a successful one resets it and
  // records "ok" (values written) or "converged" (nothing to change).
  if (t.failureCount > 0) {
    return {
      tone: "error",
      label: "Failing",
      detail: `${t.failureCount} attempt${t.failureCount === 1 ? "" : "s"}`,
      error: cleanError(t.lastResult),
      fix: isCredentialError(t.lastResult) ? "replace-credential" : "retry",
      at: t.lastAttemptAt,
    };
  }
  const redeploy = redeployError(t.lastResult);
  if (redeploy) {
    return { tone: "warn", label: "Redeploy failed", detail: "values pushed", error: redeploy, at: t.lastAttemptAt };
  }
  // Held names fail nothing: the rest was pushed, and they wait for a
  // changed value (or, on a Coolify application, for Coolify to resolve them).
  const held = heldSummary(t);
  if (held) {
    return { tone: "warn", label: "Values held", detail: held.detail, error: held.error, at: t.lastAttemptAt };
  }
  if (t.drained === false) return { tone: "live", label: "Pushing", at: t.runStartedAt ?? t.lastAttemptAt };
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
  if (d.serviceUuid) return { primary: d.serviceUuid, qualifier: "service" };
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
  if (t.redeploy) {
    out.push(
      t.destination.serviceUuid
        ? "restarts the service after changes"
        : t.destination.deployAction === "restart"
          ? "restarts after changes"
          : "redeploys after changes",
    );
  }
  if (t.removeOrphans) out.push("removes names that leave");
  if (t.destination.buildTime === "true") out.push("build-time keys");
  if (t.destination.buildTime === "false") out.push("runtime-only keys");
  if (t.destination.platformExpands) out.push(`Coolify resolves ${t.destination.platformExpands.split(",").join(", ")}`);
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
  const failing = live.filter((t) => t.state === "disabled" || t.failureCount > 0);
  if (failing.length > 0) {
    return {
      tone: "error",
      label: `${failing.length} target${failing.length === 1 ? "" : "s"} failing`,
      credentialRejected: false,
      at: failing[0]!.lastAttemptAt,
    };
  }
  const redeploys = live.filter((t) => redeployError(t.lastResult));
  if (redeploys.length > 0) {
    return {
      tone: "warn",
      label: `${redeploys.length} redeploy${redeploys.length === 1 ? "" : "s"} failed`,
      credentialRejected: false,
      at: redeploys[0]!.lastAttemptAt,
    };
  }
  const holding = live.filter((t) => heldSummary(t));
  if (holding.length > 0) {
    return {
      tone: "warn",
      label: `${holding.length} target${holding.length === 1 ? "" : "s"} holding values`,
      credentialRejected: false,
      at: holding[0]!.lastAttemptAt,
    };
  }
  if (live.every((t) => !t.lastAttemptAt)) return { tone: "live", label: "Waiting for first push", credentialRejected: false };
  return { tone: "ok", label: "Healthy", credentialRejected: false };
}

/**
 * A usage note in words (ADR-0031 amendment 2026-10-21): how the
 * destination itself uses a pushed name. Notes never fail a push.
 */
export function noteText(note: SyncTargetNote): string {
  const where = note.containers?.join(", ") ?? "";
  switch (note.code) {
    case "held":
      return `${note.name}: not pushed. ${note.reason ?? ""}`.trim();
    case "held-more":
      return `${note.count ?? 0} more name${note.count === 1 ? "" : "s"} not pushed`;
    case "shadowed":
      return `${note.name}: the compose file sets it in ${where}, which wins over the pushed value`;
    case "not-delivered":
      return `${note.name}: no container uses it`;
    case "unknown-form":
      return `${note.name}: used in ${where} in a form Varlatch does not read`;
    case "generated-once":
      return `${note.name}: Coolify generated it once; a database may read it only on first start, so change it with care`;
    case "kept-by-platform":
      return `${note.name}: removed; Coolify may keep or re-create the name, and Varlatch does not delete it again`;
    case "usage-unchecked":
      return `Usage not checked: ${note.reason ?? "unknown"}`;
  }
}

/** Whether a note asks for a look (the rest are context). */
export function noteWarns(note: SyncTargetNote): boolean {
  return note.code === "held" || note.code === "held-more" || note.code === "shadowed" || note.code === "not-delivered" || note.code === "generated-once";
}
