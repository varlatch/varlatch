// SPDX-License-Identifier: Apache-2.0
import type { MachineReach, OrgIdentity, ReachAction } from "@varlatch/sdk";

/**
 * `varlatch identity reach` (capability identity.reach, ADR-0054 Decision
 * 8): what a machine identity's Grants allow, per Project and Environment,
 * with the Tailnet Requirements that would constrain each action shown as
 * conditions. Read-only. The helpers here need no request.
 */

export const REACH_CAPABILITY = "identity.reach";

export const REACH_USAGE = "Usage: varlatch identity reach <identity-id|name> [--json] [--server <url>]";

/** A machine named on the command line could not be resolved. */
export class MachineError extends Error {
  override name = "MachineError";
}

/** The machine identity `arg` names by its exact name: exactly one. */
export function resolveMachine(identities: OrgIdentity[], arg: string): OrgIdentity {
  const named = identities.filter((i) => i.kind !== "human" && i.name === arg);
  if (named.length === 1) return named[0]!;
  if (named.length > 1) {
    throw new MachineError(`Several machines are named ${arg}; name one by its identity ID: ${named.map((i) => i.id).join(", ")}.`);
  }
  throw new MachineError(`${arg} is not a machine identity of this organization (varlatch identity list shows them).`);
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** One action, with the conditions that would constrain it. */
function actionWords(a: ReachAction, condition: (id: string) => string): string {
  return a.conditions.length === 0 ? a.action : `${a.action} (${a.conditions.map(condition).join(" and ")})`;
}

/** The reach for people: the identity's state, then project by project, environment by environment. */
export function reachLines(reach: MachineReach): string[] {
  const id = reach.identity;
  const state = id.state === "disabled" && id.disabledReason === "organization-deletion" ? "disabled by the organization's deletion" : id.state;
  const lines = [`Reach of ${id.name} (${id.id}, ${id.kind}, ${state}, ${plural(id.liveCredentials, "live credential", "live credentials")}).`];
  const conditions = new Map(reach.requirements.map((r) => [r.id, r.condition]));
  const condition = (rid: string) => conditions.get(rid) ?? `Requirement ${rid}`;
  const list = (actions: ReachAction[]) => actions.map((a) => actionWords(a, condition)).join(", ");
  if (reach.organizationActions.length > 0) lines.push("", `Organization-wide: ${list(reach.organizationActions)}`);
  if (reach.projects.length === 0) {
    lines.push("", "No Grant allows it anything in a project.");
  }
  for (const p of reach.projects) {
    lines.push("", `${p.slug} (${p.name}):`);
    if (p.actions.length > 0) lines.push(`  project: ${list(p.actions)}`);
    for (const e of p.environments) lines.push(`  ${e.name}: ${list(e.actions)}`);
  }
  if (reach.requirements.length > 0) {
    lines.push(
      "",
      "Conditions are Tailnet Requirements: each must be met by the device a request comes from. They are listed, not checked against any device.",
    );
  }
  if (reach.notes.length > 0) lines.push("", ...reach.notes);
  return lines;
}
