// SPDX-License-Identifier: AGPL-3.0-or-later
import { compareVersions, readReleaseCheck, releaseUrl, type ReleaseCheck } from "@varlatch/backup";
import type { InstallationRelease } from "@varlatch/protocol";

/**
 * What GET /v1/installation/release answers (ADR-0049): the host's last look
 * for a newer release, compared with this server's own version at read time,
 * so the notice ends when the upgrade lands, not at the next check. A check's
 * age never expires `newer: true`. The link is built here from validated
 * fields; the record holds no URL.
 */
export function installationRelease(stateDir: string | null, running: string): InstallationRelease {
  let check: ReleaseCheck | null = null;
  let unreadable = false;
  if (stateDir) {
    try {
      check = readReleaseCheck(stateDir);
    } catch {
      unreadable = true;
    }
  }
  const success = check?.lastSuccess ?? null;
  return {
    running,
    newer: success ? compareVersions(success.latest.version, running) > 0 : null,
    latest: success
      ? {
          version: success.latest.version,
          publishedAt: success.latest.publishedAt,
          url: releaseUrl(success.repo, success.latest.version),
          repo: success.repo,
          releaseSet: success.releaseSet,
          checkedAt: success.checkedAt,
        }
      : null,
    lastAttempt: check ? { checkedAt: check.lastAttempt.checkedAt, repo: check.lastAttempt.repo, failed: check.lastAttempt.failed } : null,
    unreadable,
  };
}
