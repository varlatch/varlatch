// SPDX-License-Identifier: AGPL-3.0-or-later
import { recordAuditEvents } from "../audit/events.js";
import { lockRowsById, lockedQuery } from "../db/locks.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";

/** An identity's identity.retired or identity.reactivated event, by audit order. */
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
 * - an identity with no identity.retired in its history keeps it (a
 *   suspension by an Organization's deletion records none, cancelling the
 *   deletion restores the identity with its Capabilities, and reactivating
 *   an already-enabled identity is no retirement);
 * - otherwise, with the identity's latest identity.retired at latestRetired,
 *   the Capability is ended when its capability.issued is not found (its
 *   history cannot show it post-reactivation), precedes latestRetired, or
 *   has identity.retired as the identity's latest lifecycle event at or
 *   before issuedOrder (atIssuance, catching an issuance that raced while
 *   retired and was later reactivated).
 *
 * Every issuance records capability.issued in its own transaction, a
 * redundant identity.reactivated on an enabled identity never brackets an
 * issuance with a retirement, and a retirement since this release revokes
 * the identity's Capabilities, so a Capability issued by this release is
 * never ended by this rule unless a retirement ended it already: the repair
 * is safe to run again.
 */
export function endedByRetirement(
  identity: { retiredNow: boolean; latestRetired: bigint | null; atIssuance: Lifecycle | null },
  issuedOrder: bigint | null,
): boolean {
  if (identity.retiredNow) return true;
  if (identity.latestRetired === null) return false;
  if (issuedOrder === null || issuedOrder < identity.latestRetired) return true;
  return identity.atIssuance?.eventType === "identity.retired";
}

/** How many Capabilities one repair transaction holds at most. */
export const REPAIR_BATCH = 200;

/**
 * Each identity's latest identity.retired in the Organization ($1), for the
 * identities $2: backward along audit_events_identity_lifecycle_idx
 * (migration 53).
 */
export const LATEST_RETIRED_SQL = `SELECT i.id AS identity_id, e.event_order::text AS event_order
  FROM unnest($2::text[]) AS i(id)
  CROSS JOIN LATERAL (
    SELECT event_order FROM audit_events
    WHERE organization_id = $1 AND event_type IN ('identity.retired', 'identity.reactivated')
      AND event_type = 'identity.retired'
      AND resource->>'identityId' = i.id
    ORDER BY event_order DESC LIMIT 1) e`;

/**
 * Each (identity_id, issued_order) pair's ($2, $3) latest identity.retired
 * or identity.reactivated at or before issued_order in the Organization ($1):
 * one backward step of audit_events_identity_lifecycle_idx (migration 53)
 * each.
 */
export const LIFECYCLE_AT_SQL = `SELECT p.identity_id, p.issued_order::text AS issued_order, e.event_type, e.event_order::text AS event_order
  FROM unnest($2::text[], $3::bigint[]) AS p(identity_id, issued_order)
  CROSS JOIN LATERAL (
    SELECT event_type, event_order FROM audit_events
    WHERE organization_id = $1 AND event_type IN ('identity.retired', 'identity.reactivated')
      AND resource->>'identityId' = p.identity_id
      AND event_order <= p.issued_order
    ORDER BY event_order DESC LIMIT 1) e`;

/**
 * Each Capability's capability.issued in the Organization ($1), for the
 * Capabilities $2, by audit_events_capability_issued_idx (migration 53):
 * its place in the audit order. Its whole history, not a window around its
 * created_at; a Capability with none is not in the result.
 */
export const ISSUED_SQL = `SELECT c.id AS capability_id, e.event_order::text AS event_order
  FROM unnest($2::text[]) AS c(id)
  CROSS JOIN LATERAL (
    SELECT event_order FROM audit_events
    WHERE organization_id = $1 AND event_type = 'capability.issued' AND resource->>'capabilityId' = c.id
    ORDER BY event_order LIMIT 1) e`;

/**
 * The Organization's ($1) next at most $3 unexpired, unrevoked Capabilities
 * after the id $2, locked: a range of capabilities_live_idx (migration 53)
 * from the cursor on, with no sort of the rest.
 */
export const LIVE_BATCH_SQL = `SELECT id, agent_identity_id, broker_identity_id FROM capabilities
       WHERE organization_id = $1 AND id > $2 AND revoked_at IS NULL AND expires_at > now()
       ORDER BY id LIMIT $3 FOR NO KEY UPDATE`;

/**
 * The repair of Capabilities a retirement left live, run before Capabilities
 * are issued or exercised (CapabilityRepair): before this release,
 * retirement did not revoke an identity's Capabilities, and issuance did not
 * read its Broker and Agent again under their locks, so a retirement could
 * leave Capabilities live, and a reactivation made them work again.
 *
 * Per Organization with unexpired, unrevoked Capabilities, in batches of at
 * most batchSize by id, each in its own transaction: the batch locked, then
 * each one a retirement of its Agent or its Broker ends (endedByRetirement)
 * revoked, audited as retirement's own (capability.revoked, reason
 * identity-retired), with no actor. The audit reads go by index (migration
 * 53), over the whole history, not a window: an imported Capability may
 * outlive a day, and a retirement may be older than the Capability it ends.
 *
 * Batches are safe one after another: no Capability is issued until the
 * repair has run, a retirement since revokes its identity's Capabilities
 * itself, and a reactivation since commits after the issuance and cannot
 * clear a retirement before or at issuance. Returns how many it revoked.
 */
export async function revokeCapabilitiesOfRetiredIdentities(
  ctx: AppCtx,
  opts: { batchSize?: number } = {},
): Promise<number> {
  const batchSize = opts.batchSize ?? REPAIR_BATCH;
  const orgs = (
    await ctx.db.query(
      `SELECT DISTINCT organization_id FROM capabilities
       WHERE revoked_at IS NULL AND expires_at > now() ORDER BY 1`,
    )
  ).rows as { organization_id: string }[];
  let revoked = 0;
  for (const { organization_id: organizationId } of orgs) {
    let after = "";
    for (;;) {
      const batch = await withTx(ctx.db, (db) => repairBatch(db, organizationId, after, batchSize));
      revoked += batch.revoked;
      if (batch.last === null) break;
      after = batch.last;
    }
  }
  return revoked;
}

/**
 * One batch: the Organization's next at most batchSize live Capabilities
 * after the id `after`. Returns how many it revoked, and the last id when
 * the batch was full (more may follow).
 */
async function repairBatch(
  db: AppCtx["db"],
  organizationId: string,
  after: string,
  batchSize: number,
): Promise<{ revoked: number; last: string | null }> {
  // The lock order (liveness.ts): the Organization (step 1), which the
  // audit events reference, then the Capabilities (step 10). A
  // retirement holds them too while it revokes.
  await lockRowsById(db, "organizations", [organizationId], "key share");
  const caps = (
    await lockedQuery(
      db,
      { table: "capabilities", mode: "no key update" },
      LIVE_BATCH_SQL,
      [organizationId, after, batchSize],
    )
  ).rows as { id: string; agent_identity_id: string; broker_identity_id: string }[];
  const last = caps.length === batchSize ? caps[caps.length - 1]!.id : null;
  if (caps.length === 0) return { revoked: 0, last };
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
  const notRetiredNow = identityIds.filter((i) => !retiredNow.has(i));
  const latestRetired = new Map<string, bigint>();
  if (notRetiredNow.length > 0) {
    for (const r of (await db.query(LATEST_RETIRED_SQL, [organizationId, notRetiredNow])).rows as {
      identity_id: string;
      event_order: string;
    }[]) {
      latestRetired.set(r.identity_id, BigInt(r.event_order));
    }
  }
  // Only a Capability whose non-retired identity has a retirement in its
  // history needs its issuance's place.
  const needIssued = caps.filter((c) =>
    [c.agent_identity_id, c.broker_identity_id].some((i) => !retiredNow.has(i) && latestRetired.has(i)),
  );
  const issued = new Map<string, bigint>();
  if (needIssued.length > 0) {
    for (const r of (await db.query(ISSUED_SQL, [organizationId, needIssued.map((c) => c.id)])).rows as {
      capability_id: string;
      event_order: string;
    }[]) {
      issued.set(r.capability_id, BigInt(r.event_order));
    }
  }
  // Only a Capability issued at or after its identity's latest retirement
  // needs the lifecycle state at issuance (to catch an issuance while
  // retired that was later reactivated, without tripping on a spurious
  // reactivation after a valid issuance).
  const atPairIds: string[] = [];
  const atPairOrders: string[] = [];
  const atPairsSeen = new Set<string>();
  for (const c of needIssued) {
    const issuedOrder = issued.get(c.id);
    if (issuedOrder === undefined) continue;
    for (const i of [c.agent_identity_id, c.broker_identity_id]) {
      if (retiredNow.has(i)) continue;
      const rOrder = latestRetired.get(i);
      if (rOrder === undefined || issuedOrder < rOrder) continue;
      const k = `${i}:${issuedOrder}`;
      if (atPairsSeen.has(k)) continue;
      atPairsSeen.add(k);
      atPairIds.push(i);
      atPairOrders.push(issuedOrder.toString());
    }
  }
  const atIssuance = new Map<string, Lifecycle>();
  if (atPairIds.length > 0) {
    for (const r of (await db.query(LIFECYCLE_AT_SQL, [organizationId, atPairIds, atPairOrders])).rows as {
      identity_id: string;
      issued_order: string;
      event_type: Lifecycle["eventType"];
      event_order: string;
    }[]) {
      atIssuance.set(`${r.identity_id}:${r.issued_order}`, { eventType: r.event_type, eventOrder: BigInt(r.event_order) });
    }
  }
  const ended: { id: string; identityId: string }[] = [];
  for (const c of caps) {
    const issuedOrder = issued.get(c.id) ?? null;
    const by = [c.agent_identity_id, c.broker_identity_id].find((i) =>
      endedByRetirement(
        {
          retiredNow: retiredNow.has(i),
          latestRetired: latestRetired.get(i) ?? null,
          atIssuance: issuedOrder === null ? null : (atIssuance.get(`${i}:${issuedOrder}`) ?? null),
        },
        issuedOrder,
      ),
    );
    if (by) ended.push({ id: c.id, identityId: by });
  }
  if (ended.length === 0) return { revoked: 0, last };
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
  return { revoked: ended.length, last };
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
 * at every start (once the listeners serve), so a varlatchd started after the last earlier-release
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
   * At once, then every intervalMs: a restore's or a migration's gate makes
   * it not ready (what is behind it may be replaced), and, not ready, an
   * attempt. varlatchd starts it once its listeners serve, so a long repair
   * never holds the start: Capabilities answer 503 until it has run, and
   * everything else is served meanwhile. Returns the stop.
   */
  start(ctx: AppCtx, intervalMs = 2000): () => void {
    const tick = () => {
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
    };
    const first = setImmediate(tick);
    const timer = setInterval(tick, intervalMs);
    timer.unref();
    return () => {
      clearImmediate(first);
      clearInterval(timer);
    };
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
