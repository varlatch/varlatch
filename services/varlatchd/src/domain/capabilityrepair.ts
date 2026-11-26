// SPDX-License-Identifier: AGPL-3.0-or-later
import { recordAuditEvents } from "../audit/events.js";
import { lockRowsById, lockedQuery } from "../db/locks.js";
import { withTx } from "../db/tx.js";
import { MAX_TTL_SECONDS } from "./capabilities.js";
import type { AppCtx } from "./ctx.js";

/**
 * How far back the repair looks for retirements: a Capability lives a day
 * at most, so one still unexpired was issued within the last day, and the
 * retirement that ends it came at most a day before it.
 */
const WINDOW_SECONDS = 2 * MAX_TTL_SECONDS;

/**
 * An upgrade's repair, run at every start before varlatchd serves: before
 * retirement revoked an identity's Capabilities, and before issuance read
 * its Broker and Agent again under their locks, a retirement could leave
 * Capabilities live, and a reactivation made them work again.
 *
 * Revokes each unexpired Capability that a retirement of its Agent or its
 * Broker ends, by the audit log's history of that identity: an
 * identity.retired after the Capability was issued, or one before it with
 * no identity.reactivated in between (issued while the identity was
 * retired). A suspension by an Organization's deletion records no
 * identity.retired, so it keeps its Capabilities, as cancelling the
 * deletion restores the identity. Each revocation is audited as
 * retirement's own (capability.revoked, reason identity-retired), with no
 * actor. Finds nothing once repaired. Returns how many it revoked.
 */
export async function revokeCapabilitiesOfRetiredIdentities(ctx: AppCtx): Promise<number> {
  // Per Organization, through audit_events_org_time_idx: the identities
  // retired within the window.
  const candidates = (
    await ctx.db.query(
      `SELECT DISTINCT o.id AS organization_id, e.identity_id
       FROM organizations o
       CROSS JOIN LATERAL (
         SELECT resource->>'identityId' AS identity_id FROM audit_events
         WHERE organization_id = o.id AND occurred_at > now() - make_interval(secs => $1)
           AND event_type = 'identity.retired'
       ) e
       WHERE e.identity_id IS NOT NULL
       ORDER BY 1, 2`,
      [WINDOW_SECONDS],
    )
  ).rows as { organization_id: string; identity_id: string }[];
  let revoked = 0;
  for (const { organization_id: organizationId, identity_id: identityId } of candidates) {
    revoked += await withTx(ctx.db, async (db) => {
      // The lock order (liveness.ts): the Organization (step 1), which the
      // audit events reference, then the Capabilities (step 10).
      await lockRowsById(db, "organizations", [organizationId], "key share");
      const ended = (
        await lockedQuery(
          db,
          { table: "capabilities", mode: "no key update" },
          `SELECT c.id FROM capabilities c
           WHERE c.organization_id = $1 AND (c.agent_identity_id = $2 OR c.broker_identity_id = $2)
             AND c.revoked_at IS NULL AND c.expires_at > now()
             AND EXISTS (
               SELECT 1 FROM audit_events r
               WHERE r.organization_id = $1 AND r.occurred_at > now() - make_interval(secs => $3)
                 AND r.event_type = 'identity.retired' AND r.resource->>'identityId' = $2
                 AND r.occurred_at > COALESCE((
                   SELECT max(a.occurred_at) FROM audit_events a
                   WHERE a.organization_id = $1 AND a.occurred_at > now() - make_interval(secs => $3)
                     AND a.occurred_at <= c.created_at
                     AND a.event_type = 'identity.reactivated' AND a.resource->>'identityId' = $2
                 ), '-infinity'::timestamptz))
           ORDER BY c.id FOR NO KEY UPDATE OF c`,
          [organizationId, identityId, WINDOW_SECONDS],
        )
      ).rows as { id: string }[];
      if (ended.length === 0) return 0;
      await db.query("UPDATE capabilities SET revoked_at = now() WHERE id = ANY($1::text[])", [ended.map((r) => r.id)]);
      await recordAuditEvents(
        db,
        ended.map((r) => ({
          eventType: "capability.revoked" as const,
          decision: "info" as const,
          actorIdentityId: null,
          organizationId,
          action: "secret.use",
          resource: { capabilityId: r.id },
          metadata: { reason: "identity-retired", identityId },
        })),
      );
      return ended.length;
    });
  }
  return revoked;
}
