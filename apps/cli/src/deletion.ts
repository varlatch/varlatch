// SPDX-License-Identifier: Apache-2.0
import type { OrganizationDeletion } from "@varlatch/sdk";

/**
 * Deleting Projects and Organizations from the CLI (ADR-0051 Decision 11):
 * the command forms, and the text that says what a deletion did and what it
 * cannot reach. Pure, so it is tested without a server.
 */

export const PROJECT_DELETION_CAPABILITY = "projects.delete";
export const ORGANIZATION_DELETION_CAPABILITY = "organizations.delete";

export class DeletionUsageError extends Error {}

export type OrgDeleteMode =
  | { mode: "schedule"; afterDays?: number }
  | { mode: "approve"; deletionId: string; confirmed: boolean }
  | { mode: "cancel"; deletionId: string };

/**
 * `org delete <slug>` takes exactly one of --confirm (schedule), --approve or
 * --cancel. --after goes with scheduling only. --confirm may also go with
 * --approve, where it is how assisted mode records the human's approval.
 * Throws DeletionUsageError with the reason.
 */
export function orgDeleteMode(slug: string, values: Map<string, string>): OrgDeleteMode {
  const confirm = values.get("--confirm");
  const approve = values.get("--approve");
  const cancel = values.get("--cancel");
  const after = values.get("--after");
  if (approve !== undefined && cancel !== undefined) throw new DeletionUsageError("--approve and --cancel cannot be combined");
  if (confirm !== undefined && confirm !== slug) {
    throw new DeletionUsageError(`--confirm names ${confirm}, but this command deletes ${slug}; approval for one Organization never covers another`);
  }
  if (cancel !== undefined) {
    if (confirm !== undefined) throw new DeletionUsageError("a cancel needs no --confirm");
    if (after !== undefined) throw new DeletionUsageError("--after goes with scheduling, not with --cancel");
    return { mode: "cancel", deletionId: cancel };
  }
  if (approve !== undefined) {
    if (after !== undefined) throw new DeletionUsageError("--after goes with scheduling, not with --approve");
    return { mode: "approve", deletionId: approve, confirmed: confirm !== undefined };
  }
  if (after === undefined) return { mode: "schedule" };
  if (!/^\d+$/.test(after) || Number(after) < 1 || Number(after) > 30) {
    throw new DeletionUsageError(`--after takes a whole number of days from 1 to 30, not ${after}`);
  }
  return { mode: "schedule", afterDays: Number(after) };
}

/** What deletion does not reach (ADR-0051 Decision 10), in plain words. */
export function deletionLimits(kind: "project" | "organization"): string[] {
  const lines = [
    "Deletion covers this installation's live database. It does not reach:",
    "  PostgreSQL's old row versions and write-ahead log, its replicas and snapshots of its volume, which keep the data for a while;",
    `  requests already authorized: the server may still hold their keys or values in memory${kind === "organization" ? ", and one in flight when the deletion runs may still complete" : ""};`,
    "  backups taken before it completes: they keep the data until their retention removes them, and restoring one brings it back;",
    "  values already pushed to platforms: they stay there;",
    "  values revealed, downloaded or exported: they stay wherever they were copied. Rotate them at their provider to make old copies useless.",
  ];
  if (kind === "organization") {
    lines.push(
      "A GitHub App stays as it is on GitHub: uninstall it or delete it there, and revoke copies of its private key. Installation tokens already issued stay valid until they expire.",
    );
  }
  return lines;
}

export function projectDeletionLines(
  result: { slug: string; environments: number; values: number; versionsErased: number; capabilitiesRevoked: number; targetsRevoked: number; teamLinksRemoved: number },
  organization: string,
): string[] {
  return [
    `Project ${result.slug} deleted from ${organization}.`,
    `Erased ${result.versionsErased} value versions of ${result.values} items in ${result.environments} environments; ` +
      `revoked ${result.capabilitiesRevoked} Capabilities and ${result.targetsRevoked} Sync Targets; removed ${result.teamLinksRemoved} Team links.`,
    `The slug ${result.slug} can be used again; a new Project with it starts empty and inherits nothing tied to this one. The audit log keeps this Project's events.`,
    ...deletionLimits("project"),
  ];
}

/** The open request, as `org deletion` and the other modes print it. */
export function deletionStateLines(deletion: OrganizationDeletion, organization: string, now: Date = new Date()): string[] {
  const due = Date.parse(deletion.runAfter) <= now.getTime();
  const lines = [
    `Deletion ${deletion.id} of ${organization}: scheduled ${deletion.scheduledAt} by ${deletion.requestedBy}.`,
    `It runs no earlier than ${deletion.runAfter}.`,
  ];
  if (!deletion.approvalRequired) {
    lines.push("No second approval is needed: the Organization had one admin when it was scheduled.");
  } else if (deletion.approvedBy) {
    lines.push(`Approved by ${deletion.approvedBy} at ${deletion.approvedAt}.`);
  } else {
    lines.push(
      `It waits for another admin's approval${due ? ", and never runs without it" : ""}: varlatch org delete ${organization} --approve ${deletion.id}`,
    );
  }
  lines.push(
    `${organization} is frozen until then: changes are refused, reads still work, so a last copy can be made.`,
    `Any admin can cancel it until it runs: varlatch org delete ${organization} --cancel ${deletion.id}`,
  );
  return lines;
}

export function cancelledLines(deletion: OrganizationDeletion, organization: string): string[] {
  return [
    `Deletion ${deletion.id} of ${organization} cancelled; ${organization} is no longer frozen.`,
    "Machine identities and webhooks it suspended are back. Sync Targets stay paused: resume them when you choose. Invitations it revoked must be issued again.",
  ];
}

/** After the deletion runs, the people who could read the audit log export it with this. */
export function tombstoneExportLine(organizationId: string): string {
  return `After it runs, the people who can then read ${organizationId}'s audit log export it with: varlatch audit export --deleted-org ${organizationId}`;
}
