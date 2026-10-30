// SPDX-License-Identifier: Apache-2.0
import type { ExposureReport, MemberRemoval, MemberReview, OrgIdentity } from "@varlatch/sdk";

/**
 * `varlatch member` (capability members.lifecycle, ADR-0052): list, remove,
 * leave and role changes. The helpers here need no request: resolving a
 * member named on the command line, and saying what a removal did and what
 * it left to review.
 */

export const MEMBERS_CAPABILITY = "members.lifecycle";

/** The shape of an identity ID (idn_ and lowercase base32). */
export const IDENTITY_ID = /^idn_[a-z2-7]+$/;

type Requirement = NonNullable<ExposureReport["authorityAtRemoval"]>["requirements"][number];

/** A Requirement as it was defined at removal, in words: what it applied to and which devices satisfied it. */
export function requirementWords(r: Requirement): string {
  const target = r.target as { kind?: string; tier?: string; environmentIds?: string[] } | null;
  const selector = (r.selector ?? {}) as { tailnet?: string; tags?: string[]; users?: string[]; nodes?: string[] };
  const on = target?.kind === "tier" ? `the ${target.tier} tier` : target?.kind === "environments" ? `environments ${(target.environmentIds ?? []).join(", ")}` : "its target";
  const by = [
    selector.tags?.length ? `tags ${selector.tags.join(", ")}` : null,
    selector.users?.length ? `users ${selector.users.join(", ")}` : null,
    selector.nodes?.length ? `nodes ${selector.nodes.join(", ")}` : null,
  ].filter(Boolean);
  return `on ${on}, a device in ${selector.tailnet ?? "a tailnet"}${by.length ? ` with ${by.join(" or ")}` : ""}`;
}

/** A member named on the command line could not be resolved; nothing was changed. */
export class MemberError extends Error {
  override name = "MemberError";
}

/** Whether an identity is a live member: a person with a role here, not removed. */
function isMember(i: OrgIdentity): boolean {
  return i.kind === "human" && Boolean(i.orgRole) && !i.removedAt;
}

/**
 * The live member `arg` names: an identity ID, or the exact name of exactly
 * one live member. An ID is matched against every identity first, so the ID
 * of a former member or a machine is refused, never read as someone's name.
 */
export function resolveMember(identities: OrgIdentity[], arg: string): OrgIdentity {
  const byId = identities.find((i) => i.id === arg);
  if (byId) {
    if (isMember(byId)) return byId;
    const what = byId.kind !== "human" ? `a ${byId.kind} identity` : byId.removedAt ? "a former member" : "not a member";
    throw new MemberError(`${arg} (${byId.name}) is ${what}, not a member of this organization. Nothing was changed.`);
  }
  const members = identities.filter(isMember);
  const named = members.filter((i) => i.name === arg);
  if (named.length === 1) return named[0]!;
  if (named.length > 1) {
    throw new MemberError(
      `Several members are named ${arg}; name one by its identity ID: ${named.map((i) => i.id).join(", ")}. Nothing was changed.`,
    );
  }
  throw new MemberError(`${arg} is not a member of this organization (varlatch member list shows who is). Nothing was changed.`);
}

/**
 * A current or former member `arg` names, for the exposure report: an
 * identity ID of a person who has or had a membership here, or the exact
 * name of exactly one such person.
 */
export function resolvePerson(identities: OrgIdentity[], arg: string): OrgIdentity {
  const people = identities.filter((i) => i.kind === "human" && (Boolean(i.orgRole) || Boolean(i.removedAt)));
  const byId = identities.find((i) => i.id === arg);
  if (byId) {
    if (people.includes(byId)) return byId;
    throw new MemberError(`${arg} (${byId.name}) is ${byId.kind !== "human" ? `a ${byId.kind} identity` : "not a member"}, never a member of this organization.`);
  }
  const named = people.filter((i) => i.name === arg);
  if (named.length === 1) return named[0]!;
  if (named.length > 1) {
    throw new MemberError(`Several people are named ${arg}; name one by its identity ID: ${named.map((i) => i.id).join(", ")}.`);
  }
  throw new MemberError(`${arg} is not a current or former member of this organization (varlatch member list shows who is).`);
}

const WAY_WORDS: Record<string, string> = {
  revealed: "revealed",
  delivered: "delivered to a process",
  export: "read for export",
  written: "written by them",
};

/** A version's state, in words. */
function stateWords(v: ExposureReport["received"][number]): string {
  const served = v.servedAs === "current" ? "still served (current)" : v.servedAs === "retiring" ? `still served (retiring until ${v.retiringUntil})` : null;
  const notServed = {
    replaced: "no longer served (replaced)",
    "value-deleted": "no longer served (value deleted)",
    "environment-deleted": "no longer served (environment deleted)",
    unknown: "unknown here",
  }[v.notServedBecause ?? "unknown"];
  const base = served ?? notServed;
  return v.confirmation ? `revoked at the provider, confirmed ${v.confirmation.confirmedAt}; ${base}` : base;
}

/**
 * The report for people: what they received, what they could reach at
 * removal, what is not covered, and what they set up. `envName` and
 * `requirementWords` turn IDs into names when known.
 */
export function exposureLines(
  report: ExposureReport,
  envName: (id: string | null) => string,
): string[] {
  const m = report.member;
  const lines = [
    `Exposure report for ${m.name} (${m.removedAt ? `former member, removed ${m.removedAt}` : `${m.role ?? "no role"}`}).`,
  ];
  if (!report.coverage.complete) {
    lines.push(
      `Older history is still being indexed: events from ${report.coverage.from ?? "?"} to ${report.coverage.to ?? "?"} are not covered yet.`,
    );
  }
  lines.push("", "Received (observed in the audit log; a delivery is not proof that a copy was kept):");
  if (report.received.length === 0) lines.push("  nothing");
  for (const v of report.received) {
    lines.push(`  ${v.itemName}  ${v.versionId}  in ${envName(v.owningEnvironmentId)}: ${stateWords(v)}`);
    for (const r of v.receipts) {
      const through = r.environmentId !== v.owningEnvironmentId ? ` through ${envName(r.environmentId)}` : "";
      lines.push(`    ${WAY_WORDS[r.way] ?? r.way}${through}, ${r.firstAt === r.lastAt ? r.firstAt : `${r.firstAt} to ${r.lastAt}`}`);
    }
    if (v.rotationHint && v.served) lines.push(`    to rotate: ${v.rotationHint}`);
  }
  if (report.received.some((v) => !v.served && !v.confirmation)) {
    lines.push("  No longer served is not safe: replacing a value in Varlatch does not revoke the old credential at its provider.");
  }
  const authority = report.authorityAtRemoval;
  if (authority) {
    lines.push("", `Could reach when removed (${authority.removedAt}):`);
    if (authority.environments.length === 0) lines.push("  nothing");
    for (const e of authority.environments) {
      const condition = e.conditionalOn.length === 0 ? "unconditional" : `conditional on Tailnet Requirement ${e.conditionalOn.join(", ")}`;
      lines.push(`  ${envName(e.environmentId)}: ${e.actions.map((a) => a.action).join(", ")} (reading values ${condition})`);
    }
    // The Requirements as they were defined at removal: a later edit does not change them.
    if (authority.requirements.length > 0) {
      lines.push("  Tailnet Requirements as defined at removal:");
      for (const r of authority.requirements) lines.push(`    ${r.requirementId}: ${requirementWords(r)}`);
    }
  }
  lines.push(
    "",
    "Not covered: what they could reach before removal and no longer could then, and values that reached a broker, an agent or a platform; those are listed below as indirect paths.",
  );
  const review = reviewLines(report.indirect);
  lines.push("", review.length === 0 ? "Indirect paths: none." : "Indirect paths (what they set up; not evidence that they held a value):", ...review);
  return lines;
}

/** `word` as one shell word, quoted only when it needs to be, for a command a human copies. */
export function shellWord(word: string): string {
  return /^[A-Za-z0-9_./:@%+=,-]+$/.test(word) ? word : `'${word.replace(/'/g, `'\\''`)}'`;
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

const CHANGE_WORDS: Record<string, string> = {
  created: "created",
  repointed: "re-pointed",
  destination_changed: "destination changed",
  credential_replaced: "credential replaced",
};

/** What the person set up that may keep working without them, one line per thing. Empty when nothing. */
export function reviewLines(review: MemberReview): string[] {
  const lines: string[] = [];
  const section = (title: string, items: string[]) => {
    if (items.length === 0) return;
    lines.push(`  ${title}:`);
    for (const item of items) lines.push(`    ${item}`);
  };
  const changes = (c: string[]) => c.map((x) => CHANGE_WORDS[x] ?? x).join(", ");
  section(
    "Integrations",
    review.syncTargets.map((t) => `${t.id}  ${t.platform}, ${t.state}, environment ${t.environmentId}  (${changes(t.changes)})`),
  );
  section(
    "Connections",
    review.connections.map(
      (c) => `${c.id}  ${c.name} (${c.platform}, ${c.credentialKind === "github-app" ? "GitHub App" : "token"}${c.revoked ? ", revoked" : ""})  (${changes(c.changes)})`,
    ),
  );
  section(
    "Webhooks (each signing secret was shown to its creator)",
    review.webhooks.map((w) => `${w.id}  ${w.host || "(no host)"}${w.revoked ? ", revoked" : ""}`),
  );
  section(
    "OIDC bindings",
    review.oidcBindings.map((b) => `${b.id}  ${b.identityName} from ${b.issuer}${b.revoked ? ", revoked" : ""}`),
  );
  section(
    "Machine credentials whose token they were shown",
    review.credentials.map((c) => `${c.id}  ${c.name ?? "(unnamed)"} for ${c.identityName}: ${c.state}`),
  );
  section(
    "Personal environments",
    review.personalEnvironments.map((e) => `${e.id}  ${e.name}`),
  );
  return lines;
}

/** What a removal or a leave did, and what is left to review. */
export function removalLines(removal: MemberRemoval, name: string, organization: string): string[] {
  const lines = [
    removal.left ? `You left ${organization}.` : `Removed ${name} from ${organization}.`,
    `Revoked ${plural(removal.grantsRevoked, "Grant", "Grants")}, left ${plural(removal.groupsLeft, "group or team", "groups and teams")}, ` +
      `revoked ${plural(removal.invitationsRevoked, "pending invitation", "pending invitations")}.`,
    removal.left
      ? "Your sign-in and credentials are unaffected; they reach nothing in this organization from now on."
      : "Their sign-in and credentials are unaffected; from their next request they reach nothing in this organization.",
  ];
  const review = reviewLines(removal.review);
  if (review.length === 0) {
    lines.push("Nothing they set up here needs review.");
  } else {
    lines.push("", "To review (the removal changed none of it; it may keep working without them):", ...review);
  }
  return lines;
}
