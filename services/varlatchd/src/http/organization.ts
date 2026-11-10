// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Context } from "hono";
import type { Action } from "../authz/evaluate.js";
import type { AppCtx } from "../domain/ctx.js";
import { getOrganization, type OrgRow } from "../domain/orgs.js";
import { countWouldBlockAfter, passkeyVerificationReports, type PendingAccessReport } from "../domain/securityreport.js";
import { AUTHORIZED_ACTION, ENTRY_REPORT, routeParam, type Principal } from "./support.js";

/**
 * Where a request's principal enters an Organization (ADR-0054 Decision 7).
 * Every /v1/organizations/:org route gets its Organization here, directly
 * or through scope, projectScope and envScope in app.ts;
 * test/organization-entry.test.ts fails for a route that does not, and for
 * any other Organization lookup in http/.
 *
 * - The :org route parameter (slug or ID) resolves to a live Organization
 *   exactly as getOrganization does: unknown or deleted is
 *   RESOURCE_NOT_FOUND, for members and outsiders alike. Nothing here
 *   authorizes; routes still do, hiding existence where they did.
 * - Then the per-request Organization checks run for the requesting
 *   principal and credential (organizationEntryChecks), and are awaited.
 *
 * `ctx` may be a retrieval snapshot's (inSnapshot): the lookup and the
 * checks then read from that snapshot, as before, and write nothing.
 *
 * This is for the requester only. getOrgRole, loadGrants and
 * captureAuthority load a subject's authority, also for other people (a
 * member's removal, the exposure report, machine reach), and stay
 * independent of it.
 */
export async function resolveOrganization(ctx: AppCtx, c: Context): Promise<OrgRow> {
  const org = await getOrganization(ctx, routeParam(c, "org"));
  await organizationEntryChecks(ctx, c, c.get("principal") as Principal | undefined, org);
  return org;
}

/** The requester as the security report sees it. */
export function entryRequester(principal: Principal) {
  return {
    identityId: principal.identity.id,
    identityKind: principal.identity.kind,
    credentialId: principal.credentialId,
    credentialKind: principal.credentialKind,
  };
}

/**
 * The per-request Organization checks: run once per request, with the
 * requesting principal and its credential, after the Organization resolved
 * and before the route authorizes anything (ADR-0054 Decisions 7 and 9).
 *
 * passkey-verification, in report mode: a person's credential whose
 * sign-in evidence lacks user verification or a trusted passkey is noted
 * here, against the mode and version read now (in the snapshot, on a
 * retrieval). Nothing is refused and nothing is written here: this runs
 * before authorization, so counting here would count outsiders and
 * refused requests. The note is counted at the request's outcome
 * (countEntryReport), only when the request succeeded, in a short
 * transaction of its own after any retrieval snapshot ended.
 *
 * Enforcement (a later step) will refuse here, and must not tell an
 * outsider that the Organization exists before any distinct refusal.
 */
export async function organizationEntryChecks(ctx: AppCtx, c: Context, principal: Principal | undefined, org: OrgRow): Promise<void> {
  if (!principal) return;
  const [pending] = await passkeyVerificationReports(ctx.db, entryRequester(principal), [org.id]);
  if (pending) c.set(ENTRY_REPORT, pending);
}

/**
 * At the request's outcome: count the entry check's note when the request
 * succeeded (a status below 400: it was authorized, and a write in it
 * committed), as the first action it was authorized for. The count's own
 * transaction counts only a live member of a live Organization. Never
 * fails the request.
 */
export async function countEntryReport(ctx: AppCtx, c: Context): Promise<void> {
  const pending = c.get(ENTRY_REPORT) as PendingAccessReport | undefined;
  if (!pending || c.res.status >= 400) return;
  const action = c.get(AUTHORIZED_ACTION) as Action | undefined;
  await countWouldBlockAfter(ctx, pending, action ?? "organization.access");
}
