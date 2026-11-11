// SPDX-License-Identifier: Apache-2.0
import type { IncidentFreeze, IncidentFreezeLift, IncidentFreezeState, ResumingTarget } from "@varlatch/sdk";

/**
 * `varlatch org freeze` and `varlatch org unfreeze` (ADR-0055 Decision 11):
 * the incident freeze. Freezing stops every read and write of the
 * Organization's members and machines at once, apart from reading its
 * metadata and audit log, operations that only take authority away, and
 * the lift. Lifting always needs the person's approval with a trusted
 * passkey: the CLI prints the approval URL and waits (ADR-0054 Decision 3).
 */

export const INCIDENT_FREEZE_CAPABILITY = "organizations.incident-freeze";

export const FREEZE_USAGE =
  "Usage: varlatch org freeze <slug> --reason <text> --confirm <slug> [--server <url>]\n" +
  "       varlatch org unfreeze <slug> [--json] [--server <url>]";

export class FreezeUsageError extends Error {
  override name = "FreezeUsageError";
}

/** The reason as the server takes it: 1 to 200 characters after trimming. */
export function freezeReason(raw: string | undefined): string {
  const reason = (raw ?? "").trim();
  if (reason.length === 0) throw new FreezeUsageError("--reason is required: say why, members see it");
  if (reason.length > 200) throw new FreezeUsageError("--reason is at most 200 characters");
  return reason;
}

/** What a freeze stops and what keeps working, said before and after freezing. */
export const FREEZE_EFFECTS = [
  "Every read and write of its members and machines is refused, values included: varlatch run, CI jobs and deploys that fetch from it fail.",
  "Still possible: reading members, identities, Grants and the audit log; revoking credentials, Grants and Capabilities; removing members; pausing Sync Targets.",
  "Sync Targets stop pushing; webhooks keep delivering the audit log.",
  "If your deploy or rollback credentials come from this organization, keep a break-glass credential outside Varlatch first.",
];

export function frozenLines(freeze: IncidentFreeze, slug: string): string[] {
  return [
    `${slug} is frozen for an incident since ${freeze.frozenAt} [${freeze.id}].`,
    ...FREEZE_EFFECTS.map((l) => `  ${l}`),
    `Lift it with your approval: varlatch org unfreeze ${slug}`,
  ];
}

function targetLine(t: ResumingTarget): string {
  return `  ${t.projectSlug}/${t.environmentName} -> ${t.platform} ${t.destination} [${t.id}]`;
}

/** What the lift will do, printed before asking for the approval. */
export function liftConfirmationLines(state: IncidentFreezeState, slug: string): string[] {
  const freeze = state.freeze!;
  return [
    `${slug} is frozen since ${freeze.frozenAt} by ${freeze.frozenBy.name ?? freeze.frozenBy.id}: ${freeze.reason}`,
    "Lifting undoes nothing done during the freeze: revoked credentials and Grants stay revoked.",
    ...(state.resumingTargets.length === 0
      ? ["No Sync Target resumes pushing."]
      : [`Sync Targets that resume pushing (${state.resumingTargets.length}):`, ...state.resumingTargets.map(targetLine)]),
  ];
}

export function liftedLines(result: IncidentFreezeLift, slug: string): string[] {
  return [
    `Freeze of ${slug} lifted at ${result.freeze.liftedAt} [${result.freeze.id}].`,
    ...(result.resumingTargets.length === 0
      ? []
      : [`Sync Targets resuming (${result.resumingTargets.length}):`, ...result.resumingTargets.map(targetLine)]),
  ];
}
