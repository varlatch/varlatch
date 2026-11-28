// SPDX-License-Identifier: AGPL-3.0-or-later
import type { InstallationRelease, ReleaseCheckFailure, ReleaseTarget, UpgradePreflightLine } from "@varlatch/protocol";
import { formatDate, timeAgo } from "../../lib/time";
import { hostCommand, type Deployment } from "./deployment";

/**
 * Installation → Release (ADR-0049, ADR-0065 phase 1): what the host's
 * `varlatch upgrade --check` last found and verified, as varlatchd compares
 * it with its own version and judges the upgrade's pre-flight. The dashboard
 * reports what was checked and when; it never says "up to date", and it
 * never upgrades anything: it shows the commands the host runs.
 */

export const DEFAULT_RELEASE_REPO = "varlatch/varlatch";
/** As the doctor's `release.latest`: a "no newer release" answer older than this is not current. */
export const RELEASE_CHECK_STALE_MS = 14 * 24 * 3600_000;
export const DOCS_UPGRADE_URL = "https://docs.varlatch.com/operations/upgrade/";
export const DOCS_CHECK_URL = "https://docs.varlatch.com/operations/upgrade/#newer-releases-in-the-dashboard";
export const DOCS_SCHEDULE_URL = "https://docs.varlatch.com/operations/upgrade/#scheduling-the-release-check";
export const DOCS_PREFLIGHT_URL = "https://docs.varlatch.com/operations/upgrade/#the-pre-flight-checklist";
export const DOCS_DIGEST_URL = "https://docs.varlatch.com/self-hosting/docker-and-coolify/#upgrading-by-digest";
export const DOCS_VERIFY_URL = "https://docs.varlatch.com/operations/verify-release/";
export const DOCS_BACKUP_URL = "https://docs.varlatch.com/operations/backup/#s3-compatible-destinations";

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

/** The check to schedule. */
export function checkLines(deployment: Deployment): string[] {
  return [hostCommand(deployment, "varlatch upgrade --check")];
}

/**
 * The deployment the server reports (ADR-0065 Decision 8: known, not
 * chosen); null from a server that does not, where the page asks.
 */
export function reportedDeployment(r: InstallationRelease): Deployment | null {
  if (r.deployment === "systemd") return "host";
  if (r.deployment === "image") return "container";
  return null;
}

/** The verified target, when the host's check verified the newer release. */
export function verifiedTarget(r: InstallationRelease): (ReleaseTarget & { verified: NonNullable<ReleaseTarget["verified"]> }) | null {
  const t = r.target;
  return t && t.verified ? (t as ReleaseTarget & { verified: NonNullable<ReleaseTarget["verified"]> }) : null;
}

/** Whether the target is a jump that skips releases: checked against another release than this one. */
export function isJump(r: InstallationRelease): boolean {
  const t = verifiedTarget(r);
  return !!t && t.verified.previous?.version !== r.running;
}

/** The rollback-safety sentence the upgrade card shows. */
export function rollbackSentence(r: InstallationRelease): { tone: "ok" | "warn" | "muted"; text: string } {
  const t = verifiedTarget(r);
  if (!t || r.rollbackSafe == null) return { tone: "muted", text: "Rollback-safety is not known until the host's release check verifies this release." };
  if (r.rollbackSafe) return { tone: "ok", text: "Rollback-safe: going back needs no restore." };
  if (isJump(r)) {
    const against = t.verified.previous?.version ?? "no earlier release";
    return { tone: "warn", text: `Not rollback-safe for ${r.running}: ${t.version} was checked against ${against}. Upgrade one release at a time.` };
  }
  return { tone: "warn", text: `Not rollback-safe for ${r.running}: going back means restoring the pre-upgrade snapshot, which loses every change made after it.` };
}

/** The digest part of the verified image reference, sha256:... */
export function imageDigest(image: string): string {
  const at = image.lastIndexOf("@");
  return at < 0 ? image : image.slice(at + 1);
}

/** The image by its digest alone, as the docs pin it. */
export function imageByDigest(image: string): string {
  const at = image.lastIndexOf("@");
  if (at < 0) return image;
  const name = image.slice(0, at).replace(/:[^/:]*$/, "");
  return `${name}@${image.slice(at + 1)}`;
}

export interface GuideStep {
  title: string;
  lines?: string[];
  note?: string;
}

export interface UpgradeGuide {
  /** One heading per way of deploying it (a container's Compose, Coolify, docker run share the image). */
  sections: { title: string; steps: GuideStep[]; testId: string }[];
  /** Shown above the commands for a jump that skips releases. */
  oneAtATime: string | null;
}

/**
 * The exact commands to upgrade this installation on the host (ADR-0065
 * Decisions 4 and 8): a systemd host's `sudo varlatch upgrade <version>`,
 * one release at a time for a jump; an image's verified digest, the schema
 * check and the redeploy steps. The dashboard never runs any of them.
 */
export function upgradeGuide(r: InstallationRelease, deployment: Deployment): UpgradeGuide | null {
  const latest = r.latest;
  if (!latest || !r.newer) return null;
  const version = latest.version;
  const jump = isJump(r);
  const oneAtATime = jump
    ? `${version} declares itself rollback-safe only for the release before it. Going one release at a time (sudo varlatch upgrade <version> for each release after ${r.running}, oldest first) keeps each step rollback-safe where each release declares it.`
    : null;
  if (deployment === "host") {
    const pre = version.includes("-") && !r.running.includes("-") ? " --prerelease" : "";
    const steps: GuideStep[] = [];
    if (jump) {
      steps.push({ title: "One release at a time, oldest first, for each release between", lines: ["sudo varlatch upgrade <version>"] });
      steps.push({ title: `Or straight to ${version}, which is not rollback-safe for ${r.running}: it asks you to confirm`, lines: [`sudo varlatch upgrade ${version}${pre}`] });
    } else {
      steps.push({
        title: r.rollbackSafe === false ? "Upgrade; it says why going back would need the pre-upgrade snapshot, and asks you to confirm" : "Upgrade",
        lines: [`sudo varlatch upgrade ${version}${pre}`],
      });
    }
    return { sections: [{ title: "On the host", steps, testId: "release-guide-host" }], oneAtATime };
  }
  const image = verifiedTarget(r)?.verified.image ?? null;
  const digest = image ? imageDigest(image) : "sha256:<the digest its release notes name>";
  const pinned = image ? imageByDigest(image) : "ghcr.io/varlatch/varlatchd@sha256:<new-digest>";
  const backup: GuideStep = { title: "Back up first, and keep a copy off the host", lines: ["docker exec <container> varlatchd admin backup run"] };
  const schema: GuideStep = {
    title: "Check the schema with the new image, the running container left as it is (your mounts)",
    lines: [
      "docker run --rm --read-only -v /srv/varlatch/data:/var/lib/varlatch \\",
      "  -v /srv/varlatch/keys:/keys:ro \\",
      "  -v /srv/varlatch/varlatchd.conf:/etc/varlatch/varlatchd.conf:ro \\",
      `  ${pinned} admin schema status`,
    ],
  };
  const ready: GuideStep = { title: "Confirm it serves", note: "GET /readyz answers 200." };
  return {
    sections: [
      {
        title: "Coolify",
        testId: "release-guide-coolify",
        steps: [backup, schema, { title: "Set the digest on the application, then redeploy it", lines: [`VARLATCH_VARLATCHD_DIGEST=${digest}`] }, ready],
      },
      {
        title: "Docker Compose or docker run",
        testId: "release-guide-docker",
        steps: [
          backup,
          schema,
          {
            title: "Deploy the new image by its digest: with the Compose file, set the digest and recreate the service; with docker run, recreate the container from it",
            lines: [`VARLATCH_VARLATCHD_DIGEST=${digest} docker compose up -d`, `# or: ${pinned}`],
          },
          ready,
        ],
      },
    ],
    oneAtATime,
  };
}

/** A pre-flight line's tone. */
export function preflightTone(line: UpgradePreflightLine): "ok" | "error" | "muted" {
  return line.status === "pass" ? "ok" : line.status === "fail" ? "error" : "muted";
}

/** The docs page a failing line's fix is on, when there is one. */
export function preflightDocs(line: UpgradePreflightLine): { href: string; label: string } | null {
  switch (line.id) {
    case "release-check":
      return line.remedy?.includes("Verifying a release")
        ? { href: DOCS_VERIFY_URL, label: "Verifying a release" }
        : { href: DOCS_SCHEDULE_URL, label: "Scheduling the release check" };
    case "backup":
      return { href: DOCS_BACKUP_URL, label: "S3-compatible destinations" };
    case "helper":
      return { href: "https://docs.varlatch.com/operations/upgrade/#upgrading-from-the-web-app", label: "Upgrading from the web app" };
    default:
      return null;
  }
}
