// SPDX-License-Identifier: AGPL-3.0-or-later
import type { InstallationRelease, ReleaseCheckFailure } from "@varlatch/protocol";
import { formatDate, timeAgo } from "../../lib/time";
import { hostCommand, type Deployment } from "./deployment";

/**
 * Installation → Release (ADR-0049): what the host's `varlatch upgrade
 * --check` last found, as varlatchd compares it with its own version. The
 * dashboard reports what was checked and when; it never says "up to date",
 * and it never upgrades anything (ADR-0019).
 */

export const DEFAULT_RELEASE_REPO = "varlatch/varlatch";
/** As the doctor's `release.latest`: a "no newer release" answer older than this is not current. */
export const RELEASE_CHECK_STALE_MS = 14 * 24 * 3600_000;
export const DOCS_UPGRADE_URL = "https://docs.varlatch.com/operations/upgrade/";
export const DOCS_IMAGE_UPGRADE_URL = "https://github.com/varlatch/varlatch/blob/main/infra/coolify/README.md#pinning-and-upgrading-by-digest";
export const DOCS_CHECK_URL = "https://docs.varlatch.com/operations/upgrade/#newer-releases-in-the-dashboard";

export const FAILURE_TEXT: Record<ReleaseCheckFailure, string> = {
  unreachable: "GitHub could not be reached",
  "rate-limited": "GitHub's rate limit was reached",
  "not-found": "the repository has no published release",
  "invalid-answer": "GitHub's answer was not a release",
};

export interface ReleaseSummary {
  tone: "warn" | "ok" | "muted";
  headline: string;
  detail: string;
  /** A "no newer release" answer older than RELEASE_CHECK_STALE_MS. */
  stale: boolean;
}

export function releaseSummary(r: InstallationRelease, now: number): ReleaseSummary {
  const latest = r.latest;
  if (!latest) {
    return r.unreadable
      ? { tone: "muted", headline: "The check record is unreadable", detail: "Run the check on the host again to replace it.", stale: false }
      : { tone: "muted", headline: "Not checked", detail: "This installation has no record of a release check. Run it on the host.", stale: false };
  }
  // An old check still proves that a newer release exists.
  if (r.newer) {
    return { tone: "warn", headline: `${latest.version} is available`, detail: `This installation runs ${r.running}. Checked ${timeAgo(latest.checkedAt, now)}.`, stale: false };
  }
  const stale = now - Date.parse(latest.checkedAt) > RELEASE_CHECK_STALE_MS;
  return stale
    ? { tone: "muted", headline: "Not checked recently", detail: `No newer release as of ${formatDate(latest.checkedAt)}, ${timeAgo(latest.checkedAt, now)}.`, stale: true }
    : { tone: "ok", headline: `No newer release as of ${formatDate(latest.checkedAt)}`, detail: `This installation runs ${r.running}.`, stale: false };
}

/** The last attempt's failure, when the last attempt failed. */
export function lastFailure(r: InstallationRelease, now: number): string | null {
  const attempt = r.lastAttempt;
  if (!attempt?.failed) return null;
  return `The last check, ${timeAgo(attempt.checkedAt, now)}, failed: ${FAILURE_TEXT[attempt.failed]}.`;
}

/** The upgrade to run on the host; null in a container, where it is a deployment of the release's image. */
export function upgradeLines(deployment: Deployment): string[] | null {
  return deployment === "host" ? [hostCommand(deployment, "varlatch upgrade")] : null;
}

/** The check to schedule. */
export function checkLines(deployment: Deployment): string[] {
  return [hostCommand(deployment, "varlatch upgrade --check")];
}
