// SPDX-License-Identifier: Apache-2.0
import type { MemberRemoval, MemberReview, OrgIdentity } from "@varlatch/sdk";

/**
 * `varlatch member` (capability members.lifecycle, ADR-0052): list, remove,
 * leave and role changes. The helpers here need no request: resolving a
 * member named on the command line, and saying what a removal did and what
 * it left to review.
 */

export const MEMBERS_CAPABILITY = "members.lifecycle";

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
