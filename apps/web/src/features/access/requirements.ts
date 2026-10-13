// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Environment, Requirement, RequirementTarget, TailnetSelector, Tier } from "@varlatch/protocol";
import type { Names } from "./model";

/**
 * Network requirements (ADR-0014) as the dashboard shows and edits them.
 * Within one requirement a device passes by matching ANY of its devices,
 * tags or users on its tailnet; a value is readable only when EVERY
 * requirement that applies to it passes (services/varlatchd/src/authz/evaluate.ts).
 * A tier target covers every environment of that tier, now and later; an
 * environments target covers each listed environment, and every environment
 * whose root (its parent, or itself) is listed.
 */

/** Everything a requirement holds, as the editor edits it: every field, so nothing is lost on save. */
export type RequirementDraft = {
  target: RequirementTarget;
  selector: { tailnet: string; nodes: string[]; tags: string[]; users: string[] };
};

export function draftFrom(req: Pick<Requirement, "target" | "selector">): RequirementDraft {
  return {
    target: req.target.kind === "tier" ? { kind: "tier", tier: req.target.tier } : { kind: "environments", environmentIds: [...req.target.environmentIds] },
    selector: {
      tailnet: req.selector.tailnet,
      nodes: [...(req.selector.nodes ?? [])],
      tags: [...(req.selector.tags ?? [])],
      users: [...(req.selector.users ?? [])],
    },
  };
}

export const NEW_REQUIREMENT: RequirementDraft = {
  target: { kind: "tier", tier: "production" },
  selector: { tailnet: "", nodes: [], tags: [], users: [] },
};

/**
 * The API body: target and selector whole; empty lists are left out, as the
 * API stores them. The tailnet goes exactly as entered: the evaluator
 * compares it exactly (evaluate.ts), so trimming or lowercasing it here
 * would change who passes without the review showing it.
 */
export function draftBody(draft: RequirementDraft): { target: RequirementTarget; selector: TailnetSelector } {
  const { tailnet, nodes, tags, users } = draft.selector;
  return {
    target: draft.target.kind === "tier" ? { kind: "tier", tier: draft.target.tier } : { kind: "environments", environmentIds: [...draft.target.environmentIds] },
    selector: { tailnet, ...(nodes.length ? { nodes } : {}), ...(tags.length ? { tags } : {}), ...(users.length ? { users } : {}) },
  };
}

/** A tailnet name as shown: quoted when it has spaces, which would otherwise not be seen. */
export function shownTailnet(tailnet: string): string {
  return /^\S+$/.test(tailnet) ? tailnet : JSON.stringify(tailnet);
}

export function sameDraft(a: RequirementDraft, b: RequirementDraft): boolean {
  return JSON.stringify(draftBody(a)) === JSON.stringify(draftBody(b));
}

// Tailscale's own rule for tags (tailcfg.CheckTag): "tag:", a letter, then letters, digits or dashes.
const TAG = /^tag:[A-Za-z][A-Za-z0-9-]*$/;
const STABLE_ID = /^[A-Za-z0-9]{1,64}$/;
const DNS_NAME = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;

export type ListKind = "nodes" | "tags" | "users";

/** Why a single entry cannot be added to a list, or null. */
export function entryError(kind: ListKind, value: string): string | null {
  if (kind === "tags" && !TAG.test(value)) return 'A tag is "tag:" followed by a letter, then letters, digits or dashes';
  if (kind === "nodes" && !STABLE_ID.test(value)) return "A device is named by its node ID (its StableID), letters and digits only";
  if (kind === "users" && (!value.includes("@") || /\s/.test(value))) return "A user is a Tailscale login name, such as alice@example.com";
  return null;
}

/**
 * Why the draft cannot be saved, or an empty list. A tailnet kept exactly as
 * `stored` has it is not checked again: the editor never changes it on its own.
 */
export function draftErrors(draft: RequirementDraft, stored?: RequirementDraft): string[] {
  const errors: string[] = [];
  if (draft.target.kind === "environments" && draft.target.environmentIds.length === 0) errors.push("Choose at least one environment");
  const tailnet = draft.selector.tailnet;
  if (stored && tailnet === stored.selector.tailnet) {
    // unchanged
  } else if (!tailnet.trim()) errors.push("Enter the tailnet, such as example.ts.net");
  else if (tailnet !== tailnet.trim()) errors.push("Remove the spaces around the tailnet name: Tailscale compares it exactly");
  else if (!DNS_NAME.test(tailnet)) errors.push("The tailnet is a DNS name, such as example.ts.net");
  const { nodes, tags, users } = draft.selector;
  if (nodes.length + tags.length + users.length === 0) errors.push("Name at least one device, tag or user");
  for (const kind of ["nodes", "tags", "users"] as const) {
    for (const value of draft.selector[kind]) {
      const error = entryError(kind, value);
      if (error) errors.push(`${value}: ${error}`);
    }
  }
  return errors;
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

/** The scope a target covers, in words: "the production tier", or the environments. */
export function scopeLabel(target: RequirementTarget, names: Names): string {
  return targetParts(target, names).map(targetLabel).join(", ");
}

/** Plain-text version of a requirement, for `title` attributes, the review and tests. */
export function requirementSentence(req: Pick<Requirement, "target" | "selector">, names: Names): string {
  const matches = matchParts(req.selector)
    .map((m) => `${m.kind} ${m.value}`)
    .join(", ");
  return `Values in ${scopeLabel(req.target, names)} can only be read from devices on ${shownTailnet(req.selector.tailnet)} that match any of: ${matches}`;
}

/** Which environments a target covers now, by the evaluator's rule; and the tier that also covers later ones. */
export function coverage(target: RequirementTarget, environments: Environment[]): { ids: Set<string>; tier: Tier | null; unseen: string[] } {
  if (target.kind === "tier") {
    return { ids: new Set(environments.filter((e) => e.tier === target.tier).map((e) => e.id)), tier: target.tier, unseen: [] };
  }
  const listed = new Set(target.environmentIds);
  const ids = new Set(environments.filter((e) => listed.has(e.id) || listed.has(e.parentEnvironmentId ?? e.id)).map((e) => e.id));
  const known = new Set(environments.map((e) => e.id));
  return { ids, tier: null, unseen: target.environmentIds.filter((id) => !known.has(id)) };
}

export type Consequence = { text: string };

export type Consequences = {
  /** More devices pass, or fewer values are covered. Any entry needs an explicit confirmation. */
  loosens: Consequence[];
  /** Fewer devices pass, or more values are covered: people may lose access. */
  tightens: Consequence[];
};

function envLabel(env: Environment, names: Names): string {
  const project = names.project(env.projectId)?.slug;
  return `${project ? `${project} / ` : ""}${env.name}`;
}

const WHAT: Record<ListKind, (v: string) => string> = {
  nodes: (v) => `the device with node ID ${v}`,
  tags: (v) => `devices tagged ${v}`,
  users: (v) => `devices of ${v}`,
};

/**
 * What changing `before` into `after` does. Anything that cannot be shown
 * to only tighten counts as loosening: environments the viewer cannot
 * see, environments created later, a different tailnet.
 */
export function consequences(before: RequirementDraft, after: RequirementDraft, environments: Environment[], names: Names): Consequences {
  const loosens: Consequence[] = [];
  const tightens: Consequence[] = [];
  const byId = new Map(environments.map((e) => [e.id, e]));
  const label = (ids: string[]) => ids.map((id) => envLabel(byId.get(id)!, names)).join(", ");

  // Coverage: values that stop or start needing this requirement.
  if (JSON.stringify(before.target) !== JSON.stringify(after.target)) {
    const was = coverage(before.target, environments);
    const now = coverage(after.target, environments);
    const lost = [...was.ids].filter((id) => !now.ids.has(id));
    const gained = [...now.ids].filter((id) => !was.ids.has(id));
    if (lost.length) loosens.push({ text: `Values in ${label(lost)} no longer need this requirement` });
    if (was.tier && was.tier !== now.tier) {
      loosens.push({ text: `The ${was.tier} tier is no longer covered as a whole: its environments that you cannot see, and those added later, will not need this requirement` });
    }
    const unseenLost = was.unseen.filter((id) => !(after.target.kind === "environments" && after.target.environmentIds.includes(id)));
    if (unseenLost.length) {
      loosens.push({ text: `It stops covering ${unseenLost.length === 1 ? "an environment" : `${unseenLost.length} environments`} you cannot see (${unseenLost.join(", ")}), and whatever derives from ${unseenLost.length === 1 ? "it" : "them"}` });
    }
    if (gained.length) tightens.push({ text: `Values in ${label(gained)} now need this requirement` });
    if (now.tier && now.tier !== was.tier) tightens.push({ text: `The whole ${now.tier} tier is covered, environments added to it later included` });
    const unseenGained = now.unseen.filter((id) => !(before.target.kind === "environments" && before.target.environmentIds.includes(id)));
    if (unseenGained.length) tightens.push({ text: `It covers ${unseenGained.join(", ")}, which you cannot see` });
  }

  // Who passes: alternatives within the requirement, on its tailnet. The
  // evaluator compares the tailnet exactly, so any difference counts.
  const scope = scopeLabel(after.target, names);
  const tailnetBefore = shownTailnet(before.selector.tailnet);
  const tailnetAfter = shownTailnet(after.selector.tailnet);
  if (before.selector.tailnet !== after.selector.tailnet) {
    const subtle = before.selector.tailnet.trim().toLowerCase() === after.selector.tailnet.trim().toLowerCase();
    const why = subtle ? " (Tailscale compares tailnet names exactly, so a change of case or spaces alone changes which devices pass)" : "";
    loosens.push({ text: `Devices on ${tailnetAfter} that match it can now read values in ${scope}${why}` });
    tightens.push({ text: `Devices on ${tailnetBefore} no longer pass it` });
  }
  for (const kind of ["nodes", "tags", "users"] as const) {
    const was = new Set(before.selector[kind]);
    const now = new Set(after.selector[kind]);
    for (const v of now) if (!was.has(v)) loosens.push({ text: `${capitalize(WHAT[kind](v))} on ${tailnetAfter} can now read values in ${scope}` });
    for (const v of was) if (!now.has(v)) tightens.push({ text: `${capitalize(WHAT[kind](v))} can no longer read values it covers` });
  }
  return { loosens, tightens };
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
