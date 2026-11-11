// SPDX-License-Identifier: Apache-2.0
import { OUTBOUND_HOST_NOTE, OUTBOUND_REFUSAL_LABELS } from "@varlatch/protocol";
import { VarlatchApiError, type CredentialReview, type RefusedDestination, type RefusedDestinations, type ReviewedCredential, type VarlatchClient } from "@varlatch/sdk";

/**
 * `varlatch security report` (ADR-0054 Decision 8): visibility only, never a
 * change. Today it holds the credential review (capability
 * security.credential-review): the Organization's machine credentials never
 * used, unused for 30 days, or without expiry, with their identity and last
 * use, and the service credentials that expire within 7 days or have
 * expired. Nothing is revoked or retired automatically; acting on it stays a
 * human decision (ADR-0034).
 *
 * Where the server can say (capability security.refused-destinations), it
 * also lists the organization's destinations this installation's outbound
 * policy refuses (ADR-0057 Decision 8): webhooks, Connections and OIDC
 * issuers, with why and since when. That part needs organization.manage;
 * without it, the report says it is not shown.
 */

export const CREDENTIAL_REVIEW_CAPABILITY = "security.credential-review";

export const SECURITY_USAGE = "Usage: varlatch security report [--json] [--org <organization>] [--server <url>]";

/** The server cannot answer: it predates the credential review. */
export class CredentialReviewUnsupportedError extends Error {
  override name = "CredentialReviewUnsupportedError";
}

export const REFUSED_DESTINATIONS_CAPABILITY = "security.refused-destinations";

/** The refused destinations, or why they are not part of the report. */
export type RefusedPart =
  | { shown: true; destinations: RefusedDestinations }
  | { shown: false; reason: "not-supported" | "not-permitted" };

export type SecurityReportApi = Pick<VarlatchClient, "meta" | "credentialReview" | "refusedDestinations">;

/** The whole report: the credential review, and the refused destinations where the server and the caller's access allow. */
export async function fetchSecurityReport(api: SecurityReportApi, organization: string): Promise<{ review: CredentialReview; refused: RefusedPart }> {
  const meta = await api.meta();
  if (!meta.capabilities.includes(CREDENTIAL_REVIEW_CAPABILITY)) {
    throw new CredentialReviewUnsupportedError(
      `varlatch security report: this server (${meta.serverVersion}) has no credential review ` +
        `(it lacks the ${CREDENTIAL_REVIEW_CAPABILITY} capability); upgrade the server. ` +
        "varlatch credential list <identity-id> shows one identity's credentials with their last use.",
    );
  }
  const review = await api.credentialReview(organization);
  if (!meta.capabilities.includes(REFUSED_DESTINATIONS_CAPABILITY)) return { review, refused: { shown: false, reason: "not-supported" } };
  try {
    return { review, refused: { shown: true, destinations: await api.refusedDestinations(organization) } };
  } catch (err) {
    if (err instanceof VarlatchApiError && (err.status === 403 || err.status === 404)) return { review, refused: { shown: false, reason: "not-permitted" } };
    throw err;
  }
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

/**
 * The use and expiry policy summary: never used, idle, or without expiry.
 * Expired credentials are not part of it; the expiry warnings are counted
 * on their own line, so neither line can contradict the other.
 */
export function usagePolicyLine(review: CredentialReview): string {
  const { summary } = review;
  const of = `of ${plural(summary.reviewed, "machine credential", "machine credentials")}`;
  return summary.listed === 0
    ? `Use and expiry policy: none ${of} is unused or without expiry.`
    : `Use and expiry policy: ${summary.listed} ${of} ${summary.listed === 1 ? "is" : "are"} never used, unused for ${review.idleDays} days, or without expiry.`;
}

/** The expiry warnings, counted on their own. */
export function expiryLine(expiry: CredentialReview["expiry"]): string {
  const { soon, expired } = expiry.summary;
  if (soon === 0 && expired === 0) return `Expiry warnings: no service credential expires within ${expiry.warningDays} days or has expired.`;
  const parts = [
    ...(soon > 0 ? [`${plural(soon, "service credential expires", "service credentials expire")} within ${expiry.warningDays} days`] : []),
    ...(expired > 0 ? [`${plural(expired, "has", "have")} expired`] : []),
  ];
  return `Expiry warnings: ${parts.join(", ")}.`;
}

/** The human format: summary lines, then one group per reason; a credential can appear in several. */
export function credentialReviewLines(organization: string, review: CredentialReview, now: number): string[] {
  const { summary } = review;
  // Servers before 0.21.0 send no expiry warnings.
  const expiry = review.expiry as CredentialReview["expiry"] | undefined;
  const lines = [`Credential review for ${organization}`, `  ${usagePolicyLine(review)}`, ...(expiry ? [`  ${expiryLine(expiry)}`] : [])];
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
  const expiring = expiry?.items ?? [];
  if (expiry && expiring.length > 0) {
    lines.push(
      "",
      `Expires within ${expiry.warningDays} days or expired (${expiring.length})`,
      ...expiring.map((c) => `${credentialLine({ ...c, reasons: [] }, now)}${c.state === "expired" ? " (expired)" : ""}`),
    );
  }
  lines.push(
    "",
    summary.listed === 0 && expiring.length === 0
      ? "Reporting only: nothing is revoked or retired automatically."
      : "Reporting only: nothing is revoked or retired automatically. To revoke one: " +
          "varlatch credential revoke <identity-id> <credential-id>",
  );
  return lines;
}

const KIND_WORDS: Record<RefusedDestination["kind"], string> = { webhook: "webhook", coolify: "Coolify", convex: "Convex", "oidc-issuer": "OIDC issuer" };

/** One refused destination: what it is, where it points, why, and its earliest recorded refusal. */
function refusedLine(d: RefusedDestination, sinceDays: number, now: number): string {
  const what = `${KIND_WORDS[d.kind]}${d.name ? ` "${d.name}"` : ""} (${d.id})`;
  // The audit log's earliest refusal in the window, not the start of one continuous refusal.
  const since = d.since ? `first recorded within the last ${sinceDays} days: ${ago(d.since, now)}` : `no refusal recorded in the last ${sinceDays} days`;
  return `  ${what}  ${d.scheme}://${d.host}:${d.port}  ${OUTBOUND_REFUSAL_LABELS[d.reason]}, ${since}`;
}

/** Destinations whose names did not resolve: not refused, and not known to be allowed either. */
function unresolvedLine(unresolved: number, checked: number | undefined): string {
  const of = checked === undefined ? "" : ` of ${checked}`;
  return `${unresolved}${of} destination${unresolved === 1 && !of ? "" : "s"} could not be checked: ${unresolved === 1 ? "its name did" : "their names did"} not resolve. They are checked again when they connect.`;
}

/**
 * The refused destinations part (ADR-0057 Decision 8), after the credential
 * review; nothing when the server cannot say. "None refused" is an all-clear
 * only when every configured destination was checked.
 */
export function refusedDestinationLines(organization: string, refused: RefusedPart, now: number): string[] {
  if (!refused.shown) {
    return refused.reason === "not-permitted" ? ["", "Refused destinations: not shown, because your access does not include it (needs organization.manage)."] : [];
  }
  const { items, sinceDays } = refused.destinations;
  const checked = refused.destinations.checked as number | undefined;
  const unresolved = (refused.destinations.unresolved as number | undefined) ?? 0;
  if (items.length === 0) {
    if (unresolved > 0) return ["", `Refused destinations for ${organization}: none of those checked.`, `  ${unresolvedLine(unresolved, checked)}`];
    if (checked === 0) return ["", `Refused destinations for ${organization}: none. The organization has no webhooks, Coolify or Convex connections, or OIDC issuers.`];
    return ["", `Refused destinations for ${organization}: none. This installation connects to every destination the organization configured.`];
  }
  return [
    "",
    `Refused destinations for ${organization} (${items.length})`,
    ...items.map((d) => refusedLine(d, sinceDays, now)),
    ...(unresolved > 0 ? [`  ${unresolvedLine(unresolved, checked)}`] : []),
    "",
    OUTBOUND_HOST_NOTE,
  ];
}
