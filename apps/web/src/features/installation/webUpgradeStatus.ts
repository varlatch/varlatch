// SPDX-License-Identifier: AGPL-3.0-or-later
import type { InstallationRelease, UpgradeRequestState } from "@varlatch/protocol";
import { verifiedTarget } from "./releaseStatus";

/**
 * The one-click upgrade on a systemd host (ADR-0065 phase 2, capability
 * installation.upgrade): the dashboard asks, the host helper acts. Offered
 * only when every pre-flight line passes, the helper's among them; the
 * request is one version, approved with a trusted passkey; what the host did
 * comes back as the request's state.
 */

export const DOCS_WEB_UPGRADE_URL = "https://docs.varlatch.com/operations/upgrade/#upgrading-from-the-web-app";

/** The version a click upgrades to, or null when one click is not offered. */
export function oneClickVersion(r: InstallationRelease): string | null {
  const target = verifiedTarget(r);
  const lines = r.preflight;
  if (r.deployment !== "systemd" || !r.newer || !target || !lines || lines.length === 0) return null;
  if (!lines.some((l) => l.id === "helper") || lines.some((l) => l.status !== "pass")) return null;
  if (r.latest?.version !== target.version || r.rollbackSafe !== true) return null;
  return target.version;
}

/** A fresh request id: upr_ and 26 base32 characters, from the browser's random source. */
export function newRequestId(random: (n: number) => Uint8Array = (n) => crypto.getRandomValues(new Uint8Array(n))): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  return "upr_" + Array.from(random(26), (b) => alphabet[b % 32]).join("");
}

type State = UpgradeRequestState["state"];

/** Whether the state ends the request. */
export function isOver(state: State): boolean {
  return ["none", "done", "refused", "failed", "undone", "interrupted", "cancelled", "expired"].includes(state);
}

/** The steps the tab shows while the host works (Decision 8), in order. */
export const STEPS: { states: State[]; label: string }[] = [
  { states: ["waiting", "taken"], label: "Waiting for the host" },
  { states: ["verifying"], label: "Verifying the release" },
  { states: ["backing-up"], label: "Backing up, and checking the copy delivered to your backup destination" },
  { states: ["restarting"], label: "Restarting Varlatch" },
  { states: ["checking"], label: "Checking its health" },
  { states: ["done"], label: "Done" },
];

/** The index of the step a state is at; -1 for none. */
export function stepOf(state: State): number {
  return STEPS.findIndex((s) => s.states.includes(state));
}

/** The step a request that failed or was refused ended at; -1 for none. */
export function failedStep(st: UpgradeRequestState): number {
  switch (st.state) {
    case "refused":
      return st.reason === "disabled" || st.reason === "expired" ? 0 : 1;
    case "failed":
      return st.reason === "backup" ? 2 : st.reason === "undo" ? 4 : 1;
    case "undone":
      return 4;
  }
  return -1;
}

/** What a refusal's class means, in words. Nothing changed. */
const REFUSED: Record<string, string> = {
  disabled: "this host does not accept upgrade requests (sudo varlatch upgrade --enable-web turns them on)",
  expired: "the request expired before the host took it",
  "not-newer": "the version is not newer than the one installed",
  prerelease: "the version is a prerelease",
  superseded: "a newer release was published since: the next release check offers it",
  "not-latest": "the version is not the newest release",
  "not-rollback-safe": "the release is not rollback-safe for the installed one: upgrade one release at a time, with the commands",
  "ends-rollback-window": "the release would end the migration's rollback window",
  undone: "this host already undid an upgrade to this version: read why, then upgrade by hand with sudo varlatch upgrade",
  held: "the installation is held after a restore: resume it first (sudo varlatch admin restore resume)",
  pending: "another upgrade or rollback is not over: run sudo varlatch upgrade on the host",
  maintenance: "a maintenance gate is set",
  schema: "the database's schema is newer than the release's",
  "no-backup-destination": "no backup destination is configured: set one up first",
  unreachable: "the host could not ask GitHub which release is the newest, or download it",
};

const FAILED: Record<string, string> = {
  verification: "The release did not verify: its SHA256SUMS is not signed by the release workflow, or a file does not match it. Nothing was changed. Do not install it; verify it by hand.",
  backup: "The backup failed (the archive's check, the upload, or the check of the copy delivered to your backup destination). Nothing was changed, and Varlatch never stopped.",
  error: "The host stopped before anything was changed. sudo journalctl -u varlatch-upgrade.service says why.",
  undo: "A health check failed and the undo did not complete. Run sudo varlatch upgrade on the host, which says what is left and goes on with it.",
};

/** The outcome of a request that is over, in words, with its tone; null while it runs. */
export function outcomeText(st: UpgradeRequestState, tooLate = false): { tone: "ok" | "warn" | "danger" | "neutral"; text: string } | null {
  const v = st.request?.version ?? "the release";
  if (tooLate && !isOver(st.state)) {
    return { tone: "warn", text: "Too late to cancel: the host has taken this request. It goes on, or refuses, as the steps below show." };
  }
  switch (st.state) {
    case "done":
      return { tone: "ok", text: `Upgraded to ${v}. The audit log records it as installation.upgraded.` };
    case "refused":
      return { tone: "warn", text: `The host refused: ${REFUSED[st.reason ?? ""] ?? "see the host's log"}. Nothing was changed.` };
    case "failed":
      return { tone: "danger", text: FAILED[st.reason ?? ""] ?? FAILED.error! };
    case "undone":
      return {
        tone: "danger",
        text: `A health check of ${v} failed, so the host went back: ${st.request?.from ?? "the previous release"} serves, on its database as it was. sudo cat /etc/varlatch/upgrade.json on the host says which check failed. ${v} is not offered here again; a newer release is.`,
      };
    case "interrupted":
      return { tone: "danger", text: "The upgrade was interrupted. The host finishes or undoes it at its next start, or with sudo varlatch upgrade." };
    case "cancelled":
      return { tone: "neutral", text: "Cancelled before the host took it. Nothing was changed." };
    case "expired":
      return { tone: "warn", text: "The host did not take the request within 10 minutes, so it expired. Nothing was changed." };
  }
  return null;
}

/** Whether the version a server answers is another than the one the tab began with: the new release opened. */
export function opened(running: string, serverVersion: string | undefined): boolean {
  return serverVersion !== undefined && serverVersion !== running;
}
