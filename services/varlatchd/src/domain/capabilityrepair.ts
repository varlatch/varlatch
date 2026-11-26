// SPDX-License-Identifier: AGPL-3.0-or-later
import { recordAuditEvents } from "../audit/events.js";
import { lockRowsById, lockedQuery } from "../db/locks.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";

/** An identity's latest identity.retired or identity.reactivated, by audit order. */
export interface Lifecycle {
  eventType: "identity.retired" | "identity.reactivated";
  eventOrder: bigint;
}

/**
 * Whether a retirement ends a Capability, for one of its identities (its
 * Agent or its Broker). The audit log's order (event_order, the order the
 * events committed in) decides, never timestamps:
 *
 * - an identity retired now (disabled, not by an Organization's deletion)
 *   ends it;
 * - an identity with no retirement or reactivation in its history keeps it
 *   (a suspension by an Organization's deletion records neither, and
 *   cancelling the deletion restores the identity with its Capabilities);
 * - otherwise it is kept only when the identity's latest such event is a
 *   reactivation that precedes the Capability's capability.issued. A
 *   latest retirement ends it, and so does a reactivation after the
 *   issuance (the identity was retired when it was issued, or since), or
 *   an issuance whose event is not found: its history cannot show it valid.
 *
 * Every issuance records capability.issued in its own transaction, and a
 * retirement since this release revokes the identity's Capabilities, so a
 * Capability issued by this release is never ended by this rule unless a
 * retirement ended it already: the repair is safe to run again.
 */
export function endedByRetirement(
  identity: { retiredNow: boolean; lifecycle: Lifecycle | null },
  issuedOrder: bigint | null,
): boolean {
  if (identity.retiredNow) return true;
  const { lifecycle } = identity;
  if (!lifecycle) return false;
  if (lifecycle.eventType === "identity.retired") return true;
  return issuedOrder === null || issuedOrder < lifecycle.eventOrder;
}

/**
 * How far around a Capability's created_at its capability.issued is looked
 * for (same transaction; the margin only bounds the read). Not found within
 * it, the Capability's history cannot show it valid.
 */
const ISSUED_MARGIN = "1 day";

/**
 * The repair of Capabilities a retirement left live, run before Capabilities
 * are issued or exercised (CapabilityRepair): before this release,
 * retirement did not revoke an identity's Capabilities, and issuance did not
 * read its Broker and Agent again under their locks, so a retirement could
 * leave Capabilities live, and a reactivation made them work again.
 *
 * Per Organization with unexpired, unrevoked Capabilities, in one
 * transaction: those Capabilities locked, then each one a retirement of its
 * Agent or its Broker ends (endedByRetirement) revoked, audited as
 * retirement's own (capability.revoked, reason identity-retired), with no
 * actor. Its whole audit history is read, not a window: an imported
 * Capability may outlive a day, and a retirement may be older than the
 * Capability it ends. Returns how many it revoked.
 */
export async function revokeCapabilitiesOfRetiredIdentities(ctx: AppCtx): Promise<number> {
  const orgs = (
    await ctx.db.query(
      `SELECT DISTINCT organization_id FROM capabilities
       WHERE revoked_at IS NULL AND expires_at > now() ORDER BY 1`,
    )
  ).rows as { organization_id: string }[];
  let revoked = 0;
  for (const { organization_id: organizationId } of orgs) {
    revoked += await withTx(ctx.db, async (db) => {
      // The lock order (liveness.ts): the Organization (step 1), which the
      // audit events reference, then the Capabilities (step 10). A
      // retirement holds them too while it revokes.
      await lockRowsById(db, "organizations", [organizationId], "key share");
      const caps = (
        await lockedQuery(
          db,
          { table: "capabilities", mode: "no key update" },
          `SELECT id, agent_identity_id, broker_identity_id FROM capabilities
           WHERE organization_id = $1 AND revoked_at IS NULL AND expires_at > now()
           ORDER BY id FOR NO KEY UPDATE`,
          [organizationId],
        )
      ).rows as { id: string; agent_identity_id: string; broker_identity_id: string }[];
      if (caps.length === 0) return 0;
      const identityIds = [...new Set(caps.flatMap((c) => [c.agent_identity_id, c.broker_identity_id]))];
      const retiredNow = new Set(
        (
          await db.query(
            `SELECT id FROM identities
             WHERE id = ANY($1::text[]) AND disabled AND suspended_by_deletion IS NULL`,
            [identityIds],
          )
        ).rows.map((r) => (r as { id: string }).id),
      );
      const lifecycle = new Map(
        (
          await db.query(
            `SELECT DISTINCT ON (resource->>'identityId') resource->>'identityId' AS identity_id, event_type,
                    event_order::text AS event_order
             FROM audit_events
             WHERE organization_id = $1 AND event_type IN ('identity.retired', 'identity.reactivated')
               AND resource->>'identityId' = ANY($2::text[])
             ORDER BY resource->>'identityId', event_order DESC`,
            [organizationId, identityIds],
          )
        ).rows.map((r) => {
          const row = r as { identity_id: string; event_type: Lifecycle["eventType"]; event_order: string };
          return [row.identity_id, { eventType: row.event_type, eventOrder: BigInt(row.event_order) }] as const;
        }),
      );
      // Only a Capability whose identity was reactivated needs its issuance's place.
      const reactivated = caps.filter((c) =>
        [c.agent_identity_id, c.broker_identity_id].some((i) => lifecycle.get(i)?.eventType === "identity.reactivated"),
      );
      const issued = new Map<string, bigint>();
      if (reactivated.length > 0) {
        for (const r of (
          await db.query(
            `SELECT e.resource->>'capabilityId' AS capability_id, e.event_order::text AS event_order
             FROM capabilities c JOIN audit_events e
               ON e.organization_id = c.organization_id
              AND e.occurred_at BETWEEN c.created_at - $3::interval AND c.created_at + $3::interval
              AND e.event_type = 'capability.issued' AND e.resource->>'capabilityId' = c.id
             WHERE c.organization_id = $1 AND c.id = ANY($2::text[])`,
            [organizationId, reactivated.map((c) => c.id), ISSUED_MARGIN],
          )
        ).rows as { capability_id: string; event_order: string }[]) {
          issued.set(r.capability_id, BigInt(r.event_order));
        }
      }
      const ended: { id: string; identityId: string }[] = [];
      for (const c of caps) {
        const by = [c.agent_identity_id, c.broker_identity_id].find((i) =>
          endedByRetirement({ retiredNow: retiredNow.has(i), lifecycle: lifecycle.get(i) ?? null }, issued.get(c.id) ?? null),
        );
        if (by) ended.push({ id: c.id, identityId: by });
      }
      if (ended.length === 0) return 0;
      await db.query("UPDATE capabilities SET revoked_at = now() WHERE id = ANY($1::text[])", [ended.map((e) => e.id)]);
      await recordAuditEvents(
        db,
        ended.map((e) => ({
          eventType: "capability.revoked" as const,
          decision: "info" as const,
          actorIdentityId: null,
          organizationId,
          action: "secret.use",
          resource: { capabilityId: e.id },
          metadata: { reason: "identity-retired", identityId: e.identityId },
        })),
      );
      return ended.length;
    });
  }
  return revoked;
}

/**
 * Whether the repair has run on the database this process serves:
 * Capabilities are neither issued nor exercised until it has
 * (requireCapabilityRepair), so a repair that fails, or that a maintenance
 * gate holds back, fails closed. Started not ready; a restore, or a
 * migration's gate, makes it not ready again (invalidate), since what they
 * bring back was never repaired.
 *
 * The repair runs inside the maintenance admission, as a request does:
 * never behind a gate, and a gate's drain waits for it.
 *
 * Rolling upgrades on PostgreSQL: varlatchd has no fence against a process
 * of an earlier release still writing to the same database. The repair runs
 * at every start, so a varlatchd started after the last earlier-release
 * process stopped repairs what that process left; canonical Compose
 * replaces its single varlatchd, stopping the old one before the new one
 * starts.
 */
export class CapabilityRepair {
  private repaired = false;
  /** Changed by invalidate: an attempt begun before it does not count. */
  private generation = 0;
  private running: Promise<boolean> | null = null;

  constructor(
    private readonly repair: (ctx: AppCtx) => Promise<number> = revokeCapabilitiesOfRetiredIdentities,
    private readonly log: Pick<Console, "log" | "error"> = console,
  ) {}

  get ready(): boolean {
    return this.repaired;
  }

  invalidate(): void {
    this.generation++;
    this.repaired = false;
  }

  /**
   * One attempt, unless repaired already or one is running: inside the
   * maintenance admission, so none behind a gate (false). A failure is
   * logged; the next attempt tries again.
   */
  attempt(ctx: AppCtx): Promise<boolean> {
    if (this.repaired) return Promise.resolve(true);
    if (this.running) return this.running;
    let leave: (() => void) | null;
    try {
      leave = ctx.maintenance ? ctx.maintenance.enter() : () => {};
    } catch (err) {
      // The maintenance state cannot be read: isolation stands, so the
      // repair waits, as behind a gate.
      this.log.error(MAINTENANCE_UNREADABLE, err);
      return Promise.resolve(false);
    }
    if (!leave) return Promise.resolve(false);
    const generation = this.generation;
    this.running = (async () => {
      try {
        const n = await this.repair(ctx);
        if (n > 0) this.log.log(`revoked ${n} Capabilities of retired identities`);
        if (generation !== this.generation) return false;
        this.repaired = true;
        return true;
      } catch (err) {
        this.log.error(
          "varlatchd: cannot revoke the Capabilities of retired identities; Capabilities are refused (503) until it succeeds, tried again shortly:",
          err,
        );
        return false;
      } finally {
        leave();
        this.running = null;
      }
    })();
    return this.running;
  }

  /**
   * Every intervalMs: a restore's or a migration's gate makes it not ready
   * (what is behind it may be replaced), and, not ready, an attempt. Returns
   * the stop.
   */
  start(ctx: AppCtx, intervalMs = 2000): () => void {
    const timer = setInterval(() => {
      let kind: string | undefined;
      try {
        kind = ctx.maintenance?.gate?.kind as string | undefined;
      } catch (err) {
        // Unreadable, the maintenance state may hide a restore's gate:
        // not ready, and read again at the next tick. Never thrown out of
        // the timer, which would end the process.
        this.invalidate();
        this.log.error(MAINTENANCE_UNREADABLE, err);
        return;
      }
      if (kind !== undefined && kind !== "capture") this.invalidate();
      if (!this.repaired) void this.attempt(ctx);
    }, intervalMs);
    timer.unref();
    return () => clearInterval(timer);
  }
}

const MAINTENANCE_UNREADABLE =
  "varlatchd: the maintenance state cannot be read; Capabilities are refused (503) until it can and the repair has run, tried again shortly:";

/** Capabilities wait for the repair (CapabilityRepair): 503 MAINTENANCE until then. */
export function requireCapabilityRepair(ctx: AppCtx): void {
  if (ctx.capabilityRepair && !ctx.capabilityRepair.ready) {
    throw new DomainError(
      "MAINTENANCE",
      "Capabilities are unavailable until varlatchd has revoked the Capabilities of retired identities; retry later",
    );
  }
}
