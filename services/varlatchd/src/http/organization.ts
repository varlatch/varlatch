// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Context } from "hono";
import type { Action } from "../authz/evaluate.js";
import { recordAuditEvent } from "../audit/events.js";
import type { AppCtx } from "../domain/ctx.js";
import { openFreeze, organizationFrozen, type FreezeException, type OrganizationFrozenError } from "../domain/liveness.js";
import { getOrganization, getOrgRole, type OrgRow } from "../domain/orgs.js";
import { passkeyVerification, type EntryBlock } from "../domain/passkeyverification.js";
import { queueAccessCount, type PendingAccessReport } from "../domain/securityreport.js";
import { AUTHORIZED_ACTION, ENTRY_BLOCK, ENTRY_REPORT, routeParam, type Principal } from "./support.js";

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
export async function resolveOrganization(ctx: AppCtx, c: Context, options: ResolveOptions = {}): Promise<OrgRow> {
  const org = await getOrganization(ctx, routeParam(c, "org"));
  await organizationEntryChecks(ctx, c, c.get("principal") as Principal | undefined, org, options);
  return org;
}

export interface ResolveOptions {
  /**
   * The exception under which this route runs while the Organization is
   * frozen for an incident (ADR-0055 Decisions 3 and 4). A route that names
   * none is refused, for the Organization's members and machines, with
   * ORGANIZATION_FROZEN. test/organization-entry.test.ts lists every route
   * with its exception.
   */
  duringIncidentFreeze?: FreezeException | undefined;
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
 * passkey-verification (passkeyverification.ts): a person's credential
 * whose sign-in evidence lacks user verification or a trusted passkey is
 * checked here, against the mode and version read now (in the snapshot,
 * on a retrieval). Nothing is refused and nothing is written here: this
 * runs before authorization.
 *
 * - In report mode the check is noted, and counted at the request's
 *   outcome (queueEntryReport), only when the request succeeded, after the
 *   response, in a short transaction of its own after any retrieval
 *   snapshot ended. Counting here would count outsiders and refused
 *   requests.
 * - In enforce mode the block is noted (ENTRY_BLOCK), and the request's
 *   authorization refuses it: a decision that would have allowed the
 *   request in this Organization answers PASSKEY_VERIFICATION_REQUIRED
 *   instead (decide, http/support.ts). Throwing here would answer before
 *   the route's existence hiding, and so tell an outsider that the
 *   Organization exists; deciding at authorization, every other denial
 *   answers first, and an outsider gets exactly the answer they got
 *   before.
 */
export async function organizationEntryChecks(
  ctx: AppCtx,
  c: Context,
  principal: Principal | undefined,
  org: OrgRow,
  options: ResolveOptions = {},
): Promise<void> {
  if (!principal) return;
  await refuseFrozenEntry(ctx, principal, org, options.duringIncidentFreeze);
  const outcome = await passkeyVerification(ctx.db, entryRequester(principal), [org.id]);
  const [pending] = outcome.reports;
  if (pending) c.set(ENTRY_REPORT, pending);
  const reason = outcome.blocked.get(org.id);
  if (reason) c.set(ENTRY_BLOCK, { organizationId: org.id, reason } satisfies EntryBlock);
}

/**
 * At the request's outcome: queue the entry check's note for counting when
 * the request succeeded (a status below 400: it was authorized, and a write
 * in it committed), as the first action it was authorized for. The count
 * runs after the response, best-effort, with bounded waits; its own
 * transaction counts only a live member of a live Organization. Nothing
 * here waits for it, and it never fails or slows the request.
 */
export function queueEntryReport(ctx: AppCtx, c: Context): void {
  const pending = c.get(ENTRY_REPORT) as PendingAccessReport | undefined;
  if (!pending || c.res.status >= 400) return;
  const action = c.get(AUTHORIZED_ACTION) as Action | undefined;
  queueAccessCount(ctx, pending, action ?? "organization.access");
}

/**
 * The incident freeze at entry (ADR-0055 Decision 4): while the
 * Organization is frozen, a request from a live member or from one of the
 * Organization's machine identities, on a route that names no exception,
 * is refused with ORGANIZATION_FROZEN. A principal with no standing in the
 * Organization passes through to the route's own authorization, which
 * refuses it as before, with the same existence hiding: an outsider learns
 * nothing about the freeze. Read in `ctx`, so inside a retrieval snapshot
 * the freeze is read at the snapshot boundary. The refusal is audited once,
 * at the request's outcome (auditFrozenRefusal).
 */
async function refuseFrozenEntry(ctx: AppCtx, principal: Principal, org: OrgRow, exception: FreezeException | undefined): Promise<void> {
  if (exception !== undefined) return;
  const freeze = await openFreeze(ctx.db, org.id);
  if (!freeze) return;
  const standing =
    principal.identity.kind === "human"
      ? (await getOrgRole(ctx, org.id, principal.identity.id)) !== null
      : principal.identity.organization_id === org.id;
  if (standing) throw organizationFrozen(freeze, org.id);
}

/** Seconds a client should wait before trying an Organization frozen for an incident again. */
export const FROZEN_RETRY_AFTER_SECONDS = 300;

/**
 * Record a refusal by the incident freeze (ADR-0055 Decision 8):
 * `authorization.denied` with reason `organization_frozen` and the freeze
 * id, attributed to the request's credential. Called once per refused
 * request, at its outcome, after the transaction or snapshot that refused
 * it ended, in a short transaction of its own. Never sampled. Best effort:
 * a failure to record is logged and never changes the answer.
 */
export async function auditFrozenRefusal(ctx: AppCtx, c: Context, err: OrganizationFrozenError): Promise<void> {
  const principal = c.get("principal") as Principal | undefined;
  try {
    await recordAuditEvent(ctx.db, {
      eventType: "authorization.denied",
      decision: "deny",
      actorIdentityId: principal?.identity.id ?? null,
      credentialId: principal?.credentialId ?? null,
      organizationId: err.organizationId,
      requestId: c.get("requestId") as string,
      resource: { freezeId: err.freezeId },
      metadata: { reason: "organization_frozen", freezeId: err.freezeId, method: c.req.method, route: c.req.routePath },
    });
  } catch (e) {
    console.error("could not audit a refusal by the incident freeze:", e);
  }
}
