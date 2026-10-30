// SPDX-License-Identifier: AGPL-3.0-or-later
import { recordAuditEvent } from "../audit/events.js";
import { exposureFromEvent, indexExposures, indexIntegrations, integrationFromEvent, type ExposureWay } from "../audit/exposure.js";
import type { OrgRole } from "../authz/evaluate.js";
import type { Querier } from "../db/migrate.js";
import { withSnapshot, withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";
import { memberReview, type MemberReview } from "./members.js";

/**
 * The exposure report (ADR-0052 Decisions 6 and 7): what a person received
 * (observed in audit), what they could reach at removal (the snapshot),
 * and what is unknown, never mixed. Bounded work: it reads the exposure and
 * integration indexes, never the person's audit history.
 */

// ---------------------------------------------------------------------------
// Backfill of the indexes from audit events recorded before live indexing.

const BACKFILL_EVENT_TYPES = [
  "secret.disclosed",
  "value.disclosed",
  "value.written",
  "value.rotation_started",
  "sync.target_created",
  "sync.target_updated",
  "sync.connection_created",
  "sync.connection_credential_replaced",
];

export interface BackfillLimits {
  /** Indexable events processed per batch. */
  events: number;
  /** Items (versions) indexed per batch; a batch stops after the event that reaches it. */
  items: number;
  /**
   * Audit positions read per batch: a batch looks at most this many events
   * (through the event_order index), matching or not, so its work is
   * bounded however sparse the indexable events are.
   */
  span: number;
}

const DEFAULT_LIMITS: BackfillLimits = { events: 500, items: 5000, span: 20_000 };

const parse = (v: unknown) => (typeof v === "string" ? (JSON.parse(v) as Record<string, unknown>) : (v as Record<string, unknown> | null));

/**
 * One batch of the backfill, in one transaction with its cursor: a restart
 * resumes exactly after the last committed batch, and an overlap with live
 * indexing changes nothing (the times only widen). The batch reads the
 * audit positions (cursor, cursor + span], and stops early at the event
 * or item limit; the cursor then moves to the last event it indexed, else
 * to the end of the range, nonmatching events included. Returns whether
 * the backfill is finished.
 */
export async function backfillExposureOnce(ctx: AppCtx, limits: Partial<BackfillLimits> = {}): Promise<{ done: boolean; events: number }> {
  const { events: maxEvents, items: maxItems, span } = { ...DEFAULT_LIMITS, ...limits };
  return withTx(ctx.db, async (db) => {
    const state = (await db.query("SELECT cursor::text, until_order::text, finished_at FROM exposure_backfill WHERE singleton FOR UPDATE")).rows[0] as
      | { cursor: string; until_order: string; finished_at: string | null }
      | undefined;
    if (!state || state.finished_at) return { done: true, events: 0 };
    const until = BigInt(state.until_order);
    const rangeEnd = BigInt(state.cursor) + BigInt(span) < until ? BigInt(state.cursor) + BigInt(span) : until;
    const res = await db.query(
      `SELECT event_order::text, event_type, actor_identity_id, organization_id, resource, metadata, occurred_at
       FROM audit_events
       WHERE event_order > $1::bigint AND event_order <= $2::bigint AND event_type = ANY($3)
       ORDER BY event_order LIMIT $4`,
      [state.cursor, rangeEnd.toString(), BACKFILL_EVENT_TYPES, maxEvents],
    );
    const rows = res.rows as {
      event_order: string;
      event_type: string;
      actor_identity_id: string | null;
      organization_id: string | null;
      resource: unknown;
      metadata: unknown;
      occurred_at: string | Date;
    }[];
    const exposures: { entry: NonNullable<ReturnType<typeof exposureFromEvent>>; at: string | Date }[] = [];
    const integrations: { entry: NonNullable<ReturnType<typeof integrationFromEvent>>; at: string | Date }[] = [];
    let cursor = state.cursor;
    let items = 0;
    let processed = 0;
    for (const row of rows) {
      const event = {
        eventType: row.event_type,
        actorIdentityId: row.actor_identity_id,
        organizationId: row.organization_id,
        resource: parse(row.resource),
        metadata: parse(row.metadata),
      };
      const exposure = exposureFromEvent(event);
      if (exposure) {
        exposures.push({ entry: exposure, at: row.occurred_at });
        items += exposure.items.length;
      }
      const integration = integrationFromEvent(event);
      if (integration) integrations.push({ entry: integration, at: row.occurred_at });
      cursor = row.event_order;
      processed++;
      if (items >= maxItems) break;
    }
    // Merged and in key order, like live indexing (no lock-order cycles).
    await indexExposures(db, exposures);
    await indexIntegrations(db, integrations);
    // Every indexable event of the range seen: the cursor moves past the
    // nonmatching rest of it too.
    const exhausted = processed === rows.length && rows.length < maxEvents;
    const next = exhausted ? rangeEnd : BigInt(cursor);
    const done = next >= until;
    await db.query(
      "UPDATE exposure_backfill SET cursor = $1::bigint, finished_at = CASE WHEN $2 THEN now() END WHERE singleton",
      [next.toString(), done],
    );
    return { done, events: processed };
  });
}

/**
 * Runs the backfill in the background: best-effort, never throws. After it
 * finishes it keeps looking, rarely: restoring an archive taken while it
 * was unfinished brings unfinished state back, and it resumes from there.
 */
export function startExposureBackfillLoop(ctx: AppCtx, opts: { busyMs?: number; idleMs?: number } = {}): () => void {
  const busyMs = opts.busyMs ?? 2_000;
  const idleMs = opts.idleMs ?? 60_000;
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const schedule = (ms: number) => {
    if (stopped) return;
    timer = setTimeout(() => void tick(), ms);
    timer.unref?.();
  };
  const tick = async () => {
    let next = busyMs;
    const leave = ctx.maintenance?.enter();
    if (ctx.maintenance && !leave) return schedule(busyMs);
    try {
      // A cheap read first: once finished, nothing is locked.
      const state = (await ctx.db.query("SELECT finished_at FROM exposure_backfill WHERE singleton")).rows[0] as { finished_at: unknown } | undefined;
      if (!state || state.finished_at) next = idleMs;
      else if ((await backfillExposureOnce(ctx)).done) next = idleMs;
    } catch (err) {
      console.error("exposure backfill error:", err);
    } finally {
      leave?.();
    }
    schedule(next);
  };
  void tick();
  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
  };
}

// ---------------------------------------------------------------------------
// The report.

export type VersionState = "served" | "not-served" | "revocation-confirmed";

export interface ReceivedVersion {
  itemName: string;
  versionId: string;
  /** The environment whose value owns the version; null when the version is unknown here. */
  owningEnvironmentId: string | null;
  projectId: string | null;
  state: VersionState;
  /** While served: as the current version, or as the retiring one until its deadline. */
  servedAs: "current" | "retiring" | null;
  retiringUntil: string | null;
  /** Why it is no longer served. */
  notServedBecause: "replaced" | "value-deleted" | "environment-deleted" | "unknown" | null;
  /** Still served by Varlatch, whatever was confirmed: a confirmation does not stop Varlatch serving it. */
  served: boolean;
  confirmation: { confirmedAt: string; actorIdentityId: string } | null;
  rotationHint: string | null;
  receipts: { environmentId: string; way: ExposureWay; firstAt: string; lastAt: string }[];
}

export interface AuthorityAtRemoval {
  removalId: string;
  removedAt: string;
  role: OrgRole;
  left: boolean;
  environments: {
    environmentId: string;
    actions: { action: string; sources: { source: string; role: OrgRole | null; grantId: string | null; viaGroupId: string | null; roleId: string | null }[] }[];
    /** Requirement IDs (copies below) that reading values here was conditional on; none: unconditional. */
    conditionalOn: string[];
  }[];
  requirements: { requirementId: string; requirementVersion: number | null; target: unknown; selector: unknown }[];
}

export interface ExposureReport {
  member: { identityId: string; name: string; role: OrgRole | null; removedAt: string | null };
  /** Whether the indexes cover all of the audit history; when not, the period still being indexed. */
  coverage: { complete: true } | { complete: false; from: string | null; to: string | null };
  received: ReceivedVersion[];
  /** Null for a current member, or a member removed before removals recorded it. */
  authorityAtRemoval: AuthorityAtRemoval | null;
  /** What they set up: indirect paths, never evidence that they held values (Decision 4). */
  indirect: MemberReview;
}

const iso = (v: string | Date | null | undefined) => (v ? new Date(v).toISOString() : null);

/**
 * The exposure report for a current or former member, from one REPEATABLE
 * READ snapshot. Its work is proportional to what it reports.
 */
export async function memberExposure(ctx: AppCtx, organizationId: string, identityId: string): Promise<ExposureReport> {
  return withSnapshot(ctx.db, async (db, now) => {
    const member = (
      await db.query(
        `SELECT i.id, i.name, m.role, m.removed_at FROM org_memberships m JOIN identities i ON i.id = m.identity_id
         WHERE m.organization_id = $1 AND m.identity_id = $2`,
        [organizationId, identityId],
      )
    ).rows[0] as { id: string; name: string; role: OrgRole; removed_at: string | Date | null } | undefined;
    if (!member) throw new DomainError("RESOURCE_NOT_FOUND", "Member not found");

    const rows = (
      await db.query(
        `SELECT x.version_id, x.item_name, x.environment_id, x.way, x.first_at, x.last_at,
                ev.environment_id AS owner_env, ev.current_version_id, ev.retiring_version_id, ev.rotation_deadline,
                ev.deleted_at AS value_deleted, e.deleted_at AS env_deleted, e.project_id,
                c.confirmed_at, c.actor_identity_id AS confirmed_by
         FROM member_exposure x
         LEFT JOIN value_versions v ON v.id = x.version_id
         LEFT JOIN env_values ev ON ev.id = v.value_id
         LEFT JOIN environments e ON e.id = ev.environment_id
         LEFT JOIN projects p ON p.id = e.project_id AND p.organization_id = x.organization_id
         LEFT JOIN exposure_confirmations c ON c.organization_id = x.organization_id AND c.version_id = x.version_id
         WHERE x.organization_id = $1 AND x.identity_id = $2
         ORDER BY x.item_name, x.version_id, x.environment_id, x.way`,
        [organizationId, identityId],
      )
    ).rows as Record<string, unknown>[];

    // Rotation hints from each involved project's active Contract.
    const projectIds = [...new Set(rows.map((r) => r.project_id).filter((p): p is string => typeof p === "string"))];
    const hints = new Map<string, string>();
    if (projectIds.length > 0) {
      const contracts = await db.query(
        `SELECT p.id, r.contract FROM projects p JOIN contract_revisions r ON r.id = p.active_contract_revision_id
         WHERE p.id = ANY($1) AND p.organization_id = $2`,
        [projectIds, organizationId],
      );
      for (const c of contracts.rows as { id: string; contract: unknown }[]) {
        const contract = parse(c.contract) as { items?: { name: string; rotationHint?: string }[] } | null;
        for (const item of contract?.items ?? []) if (item.rotationHint) hints.set(`${c.id}\u0000${item.name}`, item.rotationHint);
      }
    }

    const received = new Map<string, ReceivedVersion>();
    for (const r of rows) {
      const versionId = r.version_id as string;
      let entry = received.get(versionId);
      if (!entry) {
        const known = typeof r.owner_env === "string";
        const deadline = r.rotation_deadline ? new Date(r.rotation_deadline as string) : null;
        const servedAs =
          !known || r.value_deleted || r.env_deleted
            ? null
            : r.current_version_id === versionId
              ? "current"
              : r.retiring_version_id === versionId && deadline && deadline > now
                ? "retiring"
                : null;
        const served = servedAs !== null;
        entry = {
          itemName: r.item_name as string,
          versionId,
          owningEnvironmentId: known ? (r.owner_env as string) : null,
          projectId: (r.project_id as string | null) ?? null,
          state: r.confirmed_at ? "revocation-confirmed" : served ? "served" : "not-served",
          servedAs,
          retiringUntil: servedAs === "retiring" ? iso(deadline) : null,
          notServedBecause: served ? null : !known ? "unknown" : r.env_deleted ? "environment-deleted" : r.value_deleted ? "value-deleted" : "replaced",
          served,
          confirmation: r.confirmed_at ? { confirmedAt: iso(r.confirmed_at as string)!, actorIdentityId: r.confirmed_by as string } : null,
          rotationHint: r.project_id ? (hints.get(`${r.project_id as string}\u0000${r.item_name as string}`) ?? null) : null,
          receipts: [],
        };
        received.set(versionId, entry);
      }
      entry.receipts.push({
        environmentId: r.environment_id as string,
        way: r.way as ExposureWay,
        firstAt: iso(r.first_at as string)!,
        lastAt: iso(r.last_at as string)!,
      });
    }

    const removal = (
      await db.query(
        `SELECT id, role, removed_at, actor_identity_id FROM membership_removals WHERE organization_id = $1 AND identity_id = $2`,
        [organizationId, identityId],
      )
    ).rows[0] as { id: string; role: OrgRole; removed_at: string | Date; actor_identity_id: string } | undefined;
    let authorityAtRemoval: AuthorityAtRemoval | null = null;
    if (removal) {
      const authority = (
        await db.query(
          `SELECT environment_id, action, source, role, grant_id, via_group_id, role_id FROM removal_authority
           WHERE removal_id = $1 ORDER BY environment_id, action, source`,
          [removal.id],
        )
      ).rows as Record<string, string | null>[];
      const conditions = (
        await db.query("SELECT environment_id, requirement_id FROM removal_conditions WHERE removal_id = $1 ORDER BY environment_id, requirement_id", [removal.id])
      ).rows as { environment_id: string; requirement_id: string }[];
      const requirements = (
        await db.query(
          "SELECT requirement_id, requirement_version, target, selector FROM removal_requirements WHERE removal_id = $1 ORDER BY requirement_id",
          [removal.id],
        )
      ).rows as { requirement_id: string; requirement_version: number | null; target: unknown; selector: unknown }[];
      const envs = new Map<string, AuthorityAtRemoval["environments"][number]>();
      for (const a of authority) {
        const envId = a.environment_id as string;
        const env = envs.get(envId) ?? { environmentId: envId, actions: [], conditionalOn: [] };
        envs.set(envId, env);
        let action = env.actions.find((x) => x.action === a.action);
        if (!action) env.actions.push((action = { action: a.action as string, sources: [] }));
        action.sources.push({
          source: a.source as string,
          role: (a.role as OrgRole | null) ?? null,
          grantId: a.grant_id ?? null,
          viaGroupId: a.via_group_id ?? null,
          roleId: a.role_id ?? null,
        });
      }
      for (const c of conditions) envs.get(c.environment_id)?.conditionalOn.push(c.requirement_id);
      authorityAtRemoval = {
        removalId: removal.id,
        removedAt: iso(removal.removed_at)!,
        role: removal.role,
        left: removal.actor_identity_id === identityId,
        environments: [...envs.values()],
        requirements: requirements.map((r) => ({
          requirementId: r.requirement_id,
          requirementVersion: r.requirement_version ?? null,
          target: parse(r.target),
          selector: parse(r.selector),
        })),
      };
    }

    const backfill = (
      await db.query(
        `SELECT b.finished_at,
                (SELECT occurred_at FROM audit_events WHERE event_order > b.cursor ORDER BY event_order LIMIT 1) AS gap_from,
                (SELECT occurred_at FROM audit_events WHERE event_order = b.until_order) AS gap_to
         FROM exposure_backfill b WHERE b.singleton`,
      )
    ).rows[0] as { finished_at: string | null; gap_from: string | null; gap_to: string | null } | undefined;
    const coverage: ExposureReport["coverage"] =
      !backfill || backfill.finished_at ? { complete: true } : { complete: false, from: iso(backfill.gap_from), to: iso(backfill.gap_to) };

    return {
      member: {
        identityId: member.id,
        name: member.name,
        role: member.removed_at ? null : member.role,
        removedAt: iso(member.removed_at),
      },
      coverage,
      received: [...received.values()],
      authorityAtRemoval,
      indirect: await memberReview(db, organizationId, identityId),
    };
  });
}

// ---------------------------------------------------------------------------
// Confirmations (Decision 7).

/** The value that owns an exposed version, and whether it and its environment are live. */
export async function exposedVersion(
  db: Querier,
  organizationId: string,
  identityId: string,
  versionId: string,
): Promise<{ itemName: string; environmentId: string | null; projectId: string | null; live: boolean } | null> {
  const res = await db.query(
    `SELECT x.item_name, ev.environment_id, e.project_id, (ev.deleted_at IS NULL AND e.deleted_at IS NULL AND p.id IS NOT NULL) AS live
     FROM member_exposure x
     LEFT JOIN value_versions v ON v.id = x.version_id
     LEFT JOIN env_values ev ON ev.id = v.value_id
     LEFT JOIN environments e ON e.id = ev.environment_id
     LEFT JOIN projects p ON p.id = e.project_id AND p.organization_id = x.organization_id
     WHERE x.organization_id = $1 AND x.identity_id = $2 AND x.version_id = $3
     LIMIT 1`,
    [organizationId, identityId, versionId],
  );
  const row = res.rows[0] as { item_name: string; environment_id: string | null; project_id: string | null; live: boolean | null } | undefined;
  if (!row) return null;
  return { itemName: row.item_name, environmentId: row.environment_id, projectId: row.project_id, live: row.live === true };
}

/**
 * Records that an exposed version was revoked or rotated at its provider:
 * once per version, audited as exposure.revocation_confirmed. The caller
 * has checked the permission; a repeated confirmation returns the first.
 */
export async function confirmRevocation(
  ctx: AppCtx,
  organizationId: string,
  identityId: string,
  versionId: string,
  version: { itemName: string; environmentId: string | null },
  actorIdentityId: string,
): Promise<{ versionId: string; confirmedAt: string; actorIdentityId: string; created: boolean }> {
  return withTx(ctx.db, async (db) => {
    const inserted = await db.query(
      `INSERT INTO exposure_confirmations (organization_id, version_id, identity_id, actor_identity_id)
       VALUES ($1,$2,$3,$4) ON CONFLICT (organization_id, version_id) DO NOTHING
       RETURNING confirmed_at, actor_identity_id`,
      [organizationId, versionId, identityId, actorIdentityId],
    );
    const created = inserted.rows.length > 0;
    const row = (
      created
        ? inserted.rows[0]
        : (await db.query("SELECT confirmed_at, actor_identity_id FROM exposure_confirmations WHERE organization_id = $1 AND version_id = $2", [organizationId, versionId])).rows[0]
    ) as { confirmed_at: string | Date; actor_identity_id: string };
    if (created) {
      await recordAuditEvent(db, {
        eventType: "exposure.revocation_confirmed",
        decision: "info",
        actorIdentityId,
        organizationId,
        resource: { identityId, versionId, itemName: version.itemName, environmentId: version.environmentId },
      });
    }
    return { versionId, confirmedAt: iso(row.confirmed_at)!, actorIdentityId: row.actor_identity_id, created };
  });
}
