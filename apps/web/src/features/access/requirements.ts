// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Requirement, RequirementTarget, TailnetSelector, Tier } from "@varlatch/protocol";
import type { Names } from "./model";

/**
 * Network requirements (ADR-0014) as the dashboard shows and edits them.
 * Within one requirement a device passes by matching ANY of its devices,
 * tags or users; a value is readable only when EVERY requirement that
 * applies to it passes (services/varlatchd/src/authz/evaluate.ts).
 */

/** What the requirement form edits: a whole tier, restricted by tags. */
export type RequirementForm = { tier: Tier; tailnet: string; tags: string[] };

export function parseTags(text: string): string[] {
  return text
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
}

/**
 * Why the form cannot edit this requirement, or null when it can. The form
 * writes target and selector whole, so anything it cannot show would be
 * lost on save. Keeping those fields is not enough either: devices, tags
 * and users are alternatives, so a tag added next to pinned devices lets
 * more devices in.
 */
export function formEditBlocker(req: Requirement): string | null {
  const scoped = req.target.kind !== "tier";
  const named = (req.selector.nodes?.length ?? 0) > 0 || (req.selector.users?.length ?? 0) > 0;
  if (!scoped && !named) return null;
  const what =
    scoped && named
      ? "applies to specific environments and names devices or users"
      : scoped
        ? "applies to specific environments"
        : "names devices or users";
  return `This requirement ${what}, which this form cannot edit without changing what it allows. Change it through the API, or remove it and add a new one.`;
}

/** The PATCH body for a form edit. Refuses requirements the form cannot represent. */
export function requirementUpdate(initial: Requirement, form: RequirementForm) {
  const blocker = formEditBlocker(initial);
  if (blocker) throw new Error(blocker);
  return {
    expectedVersion: initial.version,
    target: { kind: "tier" as const, tier: form.tier },
    selector: { tailnet: form.tailnet.trim(), tags: form.tags },
  };
}

export function requirementCreate(form: RequirementForm) {
  return {
    target: { kind: "tier" as const, tier: form.tier },
    selector: { tailnet: form.tailnet.trim(), tags: form.tags },
  };
}

export type TargetPart =
  | { kind: "tier"; tier: Tier }
  | {
      kind: "environment";
      id: string;
      /** Absent when the environment is not visible or no longer exists. */
      project?: string;
      name?: string;
      tier?: Tier;
      /** A root environment's requirement also covers environments derived from it. */
      includesDerived: boolean;
    };

export function targetParts(target: RequirementTarget, names: Names): TargetPart[] {
  if (target.kind === "tier") return [{ kind: "tier", tier: target.tier }];
  return target.environmentIds.map((id) => {
    const env = names.environment(id);
    if (!env) return { kind: "environment", id, includesDerived: false };
    const project = names.project(env.projectId)?.slug;
    return {
      kind: "environment",
      id,
      ...(project ? { project } : {}),
      name: env.name,
      tier: env.tier as Tier,
      includesDerived: !env.parentEnvironmentId,
    };
  });
}

export type MatchPart = { kind: "device" | "tag" | "user"; value: string };

/** The alternatives a device can match, in evaluation order. */
export function matchParts(selector: TailnetSelector): MatchPart[] {
  return [
    ...(selector.nodes ?? []).map((value) => ({ kind: "device" as const, value })),
    ...(selector.tags ?? []).map((value) => ({ kind: "tag" as const, value })),
    ...(selector.users ?? []).map((value) => ({ kind: "user" as const, value })),
  ];
}

function targetLabel(part: TargetPart): string {
  if (part.kind === "tier") return `the ${part.tier} tier`;
  const where = part.name ? `${part.project ? `${part.project} / ` : ""}${part.name}` : `environment ${part.id}`;
  return part.includesDerived ? `${where} (and environments derived from it)` : where;
}

/** Plain-text version of a requirement, for `title` attributes and tests. */
export function requirementSentence(req: Requirement, names: Names): string {
  const targets = targetParts(req.target, names).map(targetLabel).join(", ");
  const matches = matchParts(req.selector)
    .map((m) => `${m.kind} ${m.value}`)
    .join(", ");
  return `Values in ${targets} can only be read from devices on ${req.selector.tailnet} that match any of: ${matches}`;
}
