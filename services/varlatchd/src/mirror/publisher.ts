// SPDX-License-Identifier: AGPL-3.0-or-later
import { mintConvexToken } from "../auth/jwt.js";
import type { AppCtx } from "../domain/ctx.js";
import type { MirrorStatusReporter } from "./status.js";

/**
 * One-way Mirror publisher (ADR-0005): varlatchd pushes read models into the
 * Convex Application Plane using its narrow mirror identity — never the
 * Convex admin key (ADR-0019 §6). Mirror loss or staleness degrades UI only,
 * so failures are logged and never fail Secret Plane operations.
 */

export interface MirrorConfig {
  convexUrl: string;
  issuer: string;
}

async function callMutation(
  config: MirrorConfig,
  token: string,
  path: string,
  args: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
): Promise<unknown> {
  const res = await fetchImpl(`${config.convexUrl}/api/mutation`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ path, args, format: "json" }),
    signal: AbortSignal.timeout(10_000),
  });
  const body = (await res.json().catch(() => null)) as
    | { status?: string; errorMessage?: string; value?: unknown }
    | null;
  if (!res.ok || body?.status !== "success") {
    throw new Error(
      `Convex mutation ${path} failed: ${body?.errorMessage ?? `HTTP ${res.status}`}`,
    );
  }
  return body.value;
}

async function mirrorToken(ctx: AppCtx, config: MirrorConfig): Promise<string> {
  const { token } = await mintConvexToken(ctx, config.issuer, {
    sub: "varlatchd-mirror",
    name: "varlatchd mirror publisher",
    orgIds: [],
    installationAdmin: false,
    role: "mirror",
  });
  return token;
}

/**
 * Full sync of display-safe read models. Deliberately simple for MVP:
 * republish everything; Convex upserts by (kind, resourceId). Payloads carry
 * metadata only — never Values, key material, or credentials.
 */
export async function syncAllMirrors(
  ctx: AppCtx,
  config: MirrorConfig,
  fetchImpl: typeof fetch = fetch,
): Promise<{ pushed: number }> {
  const token = await mirrorToken(ctx, config);
  let pushed = 0;
  const push = async (
    kind: string,
    resourceId: string,
    organizationId: string | null,
    data: Record<string, unknown>,
  ) => {
    await callMutation(config, token, "mirror:upsert", {
      kind,
      resourceId,
      organizationId,
      data,
    }, fetchImpl);
    pushed++;
  };

  const orgs = await ctx.db.query(
    "SELECT id, slug, name, created_at FROM organizations WHERE deleted_at IS NULL",
  );
  for (const o of orgs.rows as Record<string, string>[]) {
    await push("organization", o.id as string, o.id as string, {
      slug: o.slug,
      name: o.name,
      createdAt: o.created_at,
    });
  }

  const projects = await ctx.db.query(
    "SELECT id, organization_id, slug, name, contract_authority, active_contract_revision_id, created_at FROM projects",
  );
  for (const p of projects.rows as Record<string, string | null>[]) {
    await push("project", p.id as string, p.organization_id as string, {
      slug: p.slug,
      name: p.name,
      contractAuthority: p.contract_authority,
      activeContractRevisionId: p.active_contract_revision_id,
    });
  }

  const envs = await ctx.db.query(
    `SELECT e.id, e.name, e.kind, e.tier, e.parent_environment_id, e.expires_at,
            p.organization_id, e.project_id
     FROM environments e JOIN projects p ON p.id = e.project_id
     WHERE e.deleted_at IS NULL`,
  );
  for (const e of envs.rows as Record<string, string | null>[]) {
    await push("environment", e.id as string, e.organization_id as string, {
      name: e.name,
      kind: e.kind,
      tier: e.tier,
      projectId: e.project_id,
      parentEnvironmentId: e.parent_environment_id,
      expiresAt: e.expires_at,
    });
  }

  // Tombstoned environments (ADR-0025) are pruned from the mirror on every
  // full sync so a removal missed by the incremental loop cannot linger.
  const deletedEnvs = await ctx.db.query(
    "SELECT id FROM environments WHERE deleted_at IS NOT NULL",
  );
  for (const e of deletedEnvs.rows as { id: string }[]) {
    await callMutation(config, token, "mirror:remove", { kind: "environment", resourceId: e.id }, fetchImpl);
  }

  return { pushed };
}

/**
 * Incremental publish cursor over audit_events, same (occurred_at, id) walk
 * as webhook delivery. Held in memory only: the periodic full sync
 * reconciles anything missed across restarts.
 */
export interface MirrorCursor {
  order: string;
}

export async function latestEventCursor(ctx: AppCtx): Promise<MirrorCursor> {
  const res = await ctx.db.query("SELECT coalesce(max(event_order),0)::text AS position FROM audit_events");
  return { order: (res.rows[0] as { position: string }).position };
}

/**
 * Walk audit events recorded since the cursor and publish one changeSignal
 * per touched org so the UI can invalidate the matching authoritative
 * queries. The events themselves are not mirrored (ADR-0036: nothing read
 * them, and they grew with the audit history); the dashboard reads audit
 * history from /v1.
 * Every state mutation records an audit event (ADR-0016), which makes the
 * audit stream a complete change feed: the signal carries the event-type
 * prefixes ("grant", "project", …) seen in the batch, metadata only.
 */
export async function syncNewMirrorEvents(
  ctx: AppCtx,
  config: MirrorConfig,
  cursor: MirrorCursor,
  fetchImpl: typeof fetch = fetch,
): Promise<{ cursor: MirrorCursor; pushed: number }> {
  const events = await ctx.db.query(
    `SELECT id, event_order::text, event_type, occurred_at, actor_identity_id, organization_id,
            action, decision, resource
     FROM audit_events
     WHERE event_order > $1
     ORDER BY event_order LIMIT 200`,
    [cursor.order],
  );
  const rows = events.rows as Record<string, string | null>[];
  if (rows.length === 0) return { cursor, pushed: 0 };

  const token = await mirrorToken(ctx, config);
  let pushed = 0;
  const push = async (
    kind: string,
    resourceId: string,
    organizationId: string,
    data: Record<string, unknown>,
  ) => {
    await callMutation(config, token, "mirror:upsert", {
      kind,
      resourceId,
      organizationId,
      data,
    }, fetchImpl);
    pushed++;
  };

  const signals = new Map<string, { domains: Set<string>; lastEventId: string; occurredAt: string }>();
  // Org-less events (credential lifecycle on /v1/me, authentication) never
  // reach an org signal; they signal the acting identity instead so
  // me-scoped pages can invalidate. Same metadata-only payload; readable
  // only by that identity (mirror.listMine scopes by the JWT subject).
  const identitySignals = new Map<
    string,
    { domains: Set<string>; lastEventId: string; occurredAt: string }
  >();
  for (const ev of rows) {
    const orgId = ev.organization_id;
    if (!orgId) {
      const identityId = ev.actor_identity_id;
      if (identityId) {
        const signal = identitySignals.get(identityId) ?? {
          domains: new Set<string>(),
          lastEventId: "",
          occurredAt: "",
        };
        signal.domains.add((ev.event_type as string).split(".")[0] as string);
        signal.lastEventId = ev.id as string;
        signal.occurredAt = ev.occurred_at as string;
        identitySignals.set(identityId, signal);
      }
      continue;
    }
    const resource = typeof ev.resource === "string" ? JSON.parse(ev.resource) : ev.resource;
    if (ev.event_type === "environment.deleted") {
      const environmentId = (resource as { environmentId?: string } | null)?.environmentId;
      if (environmentId) {
        await callMutation(config, token, "mirror:remove", {
          kind: "environment",
          resourceId: environmentId,
        }, fetchImpl);
        pushed++;
      }
    }
    const signal = signals.get(orgId) ?? {
      domains: new Set<string>(),
      lastEventId: "",
      occurredAt: "",
    };
    signal.domains.add((ev.event_type as string).split(".")[0] as string);
    signal.lastEventId = ev.id as string;
    signal.occurredAt = ev.occurred_at as string;
    signals.set(orgId, signal);
  }
  for (const [orgId, signal] of signals) {
    await push("changeSignal", orgId, orgId, {
      lastEventId: signal.lastEventId,
      occurredAt: signal.occurredAt,
      domains: [...signal.domains],
    });
  }
  for (const [identityId, signal] of identitySignals) {
    await callMutation(config, token, "mirror:upsert", {
      kind: "identitySignal",
      resourceId: identityId,
      organizationId: null,
      data: {
        lastEventId: signal.lastEventId,
        occurredAt: signal.occurredAt,
        domains: [...signal.domains],
      },
    }, fetchImpl);
    pushed++;
  }

  const last = rows[rows.length - 1] as { event_order: string };
  return { cursor: { order: last.event_order }, pushed };
}

/**
 * Removes Mirrors of retired kinds (per-event `auditEvent`, ADR-0036) in
 * bounded batches. Returns true once none remain. Until the Convex function
 * that does it is deployed the call fails; the caller retries next time.
 */
export async function purgeRetiredMirrors(
  ctx: AppCtx,
  config: MirrorConfig,
  fetchImpl: typeof fetch = fetch,
  maxBatches = 40,
): Promise<boolean> {
  const token = await mirrorToken(ctx, config);
  for (let i = 0; i < maxBatches; i++) {
    const result = (await callMutation(config, token, "mirror:purgeRetired", { kind: "auditEvent" }, fetchImpl)) as
      | { done?: boolean }
      | undefined;
    if (result?.done) return true;
  }
  return false;
}

export function startMirrorLoop(
  ctx: AppCtx,
  config: MirrorConfig,
  fullSyncMs = 60_000,
  incrementalMs = 2_000,
  reporter?: MirrorStatusReporter,
): () => void {
  let stopped = false;
  let cursor: MirrorCursor | null = null;
  const logFailure = (err: unknown) => {
    reporter?.failure(err);
    console.error(
      `mirror sync failed (UI staleness only): ${err instanceof Error ? err.message : String(err)}`,
    );
  };
  let retiredPurged = false;
  const fullTick = async () => {
    if (stopped) return;
    const leave = ctx.maintenance?.enter();
    if (ctx.maintenance && !leave) return;
    try {
      await syncAllMirrors(ctx, config);
      reporter?.fullSync();
      if (!retiredPurged) {
        // Cleanup only: a failure (e.g. functions not yet deployed) never
        // marks publication as failing.
        retiredPurged = await purgeRetiredMirrors(ctx, config).catch(() => false);
      }
    } catch (err) {
      logFailure(err);
    } finally { leave?.(); }
  };
  let incrementalBusy = false;
  const incrementalTick = async () => {
    if (stopped || incrementalBusy) return;
    const leave = ctx.maintenance?.enter();
    if (ctx.maintenance && !leave) return;
    incrementalBusy = true;
    try {
      cursor ??= await latestEventCursor(ctx);
      cursor = (await syncNewMirrorEvents(ctx, config, cursor)).cursor;
      reporter?.incremental(cursor.order);
    } catch (err) {
      logFailure(err);
    } finally {
      incrementalBusy = false;
      leave?.();
    }
  };
  void (async () => {
    // Anchor the cursor before the initial full sync so events recorded
    // during the sync are picked up incrementally rather than lost.
    await incrementalTick();
    await fullTick();
  })();
  const fullTimer = setInterval(() => void fullTick(), fullSyncMs);
  const incrementalTimer = setInterval(() => void incrementalTick(), incrementalMs);
  fullTimer.unref();
  incrementalTimer.unref();
  return () => {
    stopped = true;
    clearInterval(fullTimer);
    clearInterval(incrementalTimer);
  };
}
