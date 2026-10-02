// SPDX-License-Identifier: AGPL-3.0-or-later
import type { InstallationBackups } from "@varlatch/protocol";
import { timeAgo } from "../../lib/time";

type Archive = InstallationBackups["archives"][number];

export function archivePassed(a: Archive): boolean {
  const v = a.verification;
  return Boolean(v && v.integrity && v.compatibility && v.keyMatch);
}

/** One-line health summary for the backups cards, plus a 7-day strip. */
export function backupHealth(data: InstallationBackups, now: number) {
  const latest = data.archives[0];
  const verified = data.archives.filter((a) => a.verification).sort((a, b) => b.verification!.checkedAt.localeCompare(a.verification!.checkedAt))[0];
  const ageHours = latest ? (now - new Date(latest.createdAt).getTime()) / 3_600_000 : Infinity;
  const tone: "ok" | "warn" | "error" = data.warnings.length > 0 || ageHours > 48 ? (ageHours > 72 || !latest ? "error" : "warn") : "ok";
  const headline = latest
    ? `Last archive ${timeAgo(latest.createdAt, now)}${verified && archivePassed(verified) ? " · verified" : ""}`
    : "No archive yet";
  const detail = data.warnings[0] ?? (verified ? `Last verification ${timeAgo(verified.verification!.checkedAt, now)}` : "No archive has been verified yet");
  const lastWeek = Array.from({ length: 7 }, (_, i) => {
    const d = new Date(now - (6 - i) * 86_400_000);
    const day = d.toISOString().slice(0, 10);
    return { day, count: data.archives.filter((a) => a.createdAt.slice(0, 10) === day).length };
  });
  return { tone, headline, detail, lastWeek, latest, verified };
}
