// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Context } from "hono";
import type { AppCtx } from "../domain/ctx.js";
import { getOrganization, type OrgRow } from "../domain/orgs.js";
import { routeParam, type Principal } from "./support.js";

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
 *   principal and credential (organizationEntryChecks).
 *
 * `ctx` may be a retrieval snapshot's (inSnapshot): the lookup then reads
 * from that snapshot, as before.
 *
 * This is for the requester only. getOrgRole, loadGrants and
 * captureAuthority load a subject's authority, also for other people (a
 * member's removal, the exposure report, machine reach), and stay
 * independent of it.
 */
export async function resolveOrganization(ctx: AppCtx, c: Context): Promise<OrgRow> {
  const org = await getOrganization(ctx, routeParam(c, "org"));
  organizationEntryChecks(ctx, c.get("principal") as Principal, org);
  return org;
}

/**
 * The per-request Organization checks: run once per request, with the
 * requesting principal and its credential, after the Organization resolved
 * and before the route authorizes anything (ADR-0054 Decisions 7 and 9).
 *
 * There are none yet: this does nothing, so every route behaves as it did.
 * When checks arrive (report-mode counting first, enforcement later):
 *
 * - A refusal must not tell an outsider that the Organization exists.
 * - On retrieval routes `ctx` is a read-only snapshot: a report-mode count
 *   is written in a separate short transaction after the decision, never
 *   here inside the snapshot.
 */
export function organizationEntryChecks(_ctx: AppCtx, _principal: Principal, _org: OrgRow): void {
  // Intentionally empty: no per-request Organization check exists yet.
}
