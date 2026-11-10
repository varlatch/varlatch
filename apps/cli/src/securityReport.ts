// SPDX-License-Identifier: Apache-2.0
import type { CredentialReview, ReviewedCredential, VarlatchClient } from "@varlatch/sdk";

/**
 * `varlatch security report` (ADR-0054 Decision 8): visibility only, never a
 * change. Today it holds the credential review (capability
 * security.credential-review): the Organization's machine credentials never
 * used, unused for 30 days, or without expiry, with their identity and last
 * use. Nothing is revoked or retired automatically; acting on it stays a
 * human decision (ADR-0034).
 */

export const CREDENTIAL_REVIEW_CAPABILITY = "security.credential-review";

export const SECURITY_USAGE = "Usage: varlatch security report [--json] [--org <organization>] [--server <url>]";

/** The server cannot answer: it predates the credential review. */
export class CredentialReviewUnsupportedError extends Error {
  override name = "CredentialReviewUnsupportedError";
}

export type CredentialReviewApi = Pick<VarlatchClient, "meta" | "credentialReview">;

/** Ask the server, after checking that it can answer (ADR-0018 §3: capabilities, not versions). */
export async function fetchCredentialReview(api: CredentialReviewApi, organization: string): Promise<CredentialReview> {
  const meta = await api.meta();
  if (!meta.capabilities.includes(CREDENTIAL_REVIEW_CAPABILITY)) {
    throw new CredentialReviewUnsupportedError(
      `varlatch security report: this server (${meta.serverVersion}) has no credential review ` +
        `(it lacks the ${CREDENTIAL_REVIEW_CAPABILITY} capability); upgrade the server. ` +
        "varlatch credential list <identity-id> shows one identity's credentials with their last use.",
    );
  }
  return api.credentialReview(organization);
}

/** "3 days ago", "5 hours ago", "just now": coarse on purpose, last use is about a minute granular. */
export function ago(at: string, now: number): string {
  const seconds = Math.max(0, Math.floor((now - Date.parse(at)) / 1000));
  const unit = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"} ago`;
  if (seconds < 60) return "just now";
  if (seconds < 3600) return unit(Math.floor(seconds / 60), "minute");
  if (seconds < 86400) return unit(Math.floor(seconds / 3600), "hour");
  return unit(Math.floor(seconds / 86400), "day");
}

function identityWords(identity: ReviewedCredential["identity"]): string {
  const state =
    identity.state === "live"
      ? ""
      : identity.disabledReason === "organization-deletion"
        ? ", suspended by the organization's deletion"
        : `, ${identity.state}`;
  return `${identity.name} (${identity.id}, ${identity.kind}${state})`;
}

function credentialLine(c: ReviewedCredential, now: number): string {
  const facts = [
    `last used ${c.lastUsedAt ? ago(c.lastUsedAt, now) : "never"}`,
    c.expiresAt ? `expires ${c.expiresAt}` : "no expiry",
    `created ${ago(c.createdAt, now)}`,
    ...(c.issuedBy ? [`issued by ${c.issuedBy.name}`] : []),
  ];
  return `  ${c.id}  ${c.name ?? "unnamed"}  for ${identityWords(c.identity)}: ${facts.join(", ")}`;
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** The human format: a summary line, then one group per reason; a credential can appear in several. */
export function credentialReviewLines(organization: string, review: CredentialReview, now: number): string[] {
  const { summary } = review;
  const lines = [
    summary.listed === 0
      ? `Credential review for ${organization}: none of ${plural(summary.reviewed, "machine credential", "machine credentials")} needs a look.`
      : `Credential review for ${organization}: ${summary.listed} of ${plural(summary.reviewed, "machine credential", "machine credentials")} ` +
        `${summary.listed === 1 ? "needs" : "need"} a look.`,
  ];
  const groups: { reason: ReviewedCredential["reasons"][number]; title: string }[] = [
    { reason: "never-used", title: "Never used" },
    { reason: "idle", title: `Unused for ${review.idleDays} days or more` },
    { reason: "no-expiry", title: "No expiry" },
  ];
  for (const { reason, title } of groups) {
    const items = review.items.filter((c) => c.reasons.includes(reason));
    if (items.length === 0) continue;
    lines.push("", `${title} (${items.length})`, ...items.map((c) => credentialLine(c, now)));
  }
  lines.push(
    "",
    summary.listed === 0
      ? "Reporting only: nothing is revoked or retired automatically."
      : "Reporting only: nothing is revoked or retired automatically. To revoke one: " +
          "varlatch credential revoke <identity-id> <credential-id>",
  );
  return lines;
}
