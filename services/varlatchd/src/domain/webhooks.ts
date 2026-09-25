// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHmac, randomBytes } from "node:crypto";
import { recordAuditEvent } from "../audit/events.js";
import { serializeAuditEvent, redactWebhookUrl } from "../audit/serialize.js";
import type { Envelope } from "../crypto/aead.js";
import { decryptWebhookSecret, encryptWebhookSecret } from "../crypto/hierarchy.js";
import { newId } from "../db/ids.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";
import { orgKekOf, type OrgRow } from "./orgs.js";

/**
 * Audit webhooks: an organization registers an HTTPS endpoint and receives
 * batches of its own audit events, signed with a per-webhook secret
 * (HMAC-SHA256 over "<unix-seconds>.<body>", Stripe-style, so receivers can
 * verify origin and reject replays). Delivery is a cursor walk over
 * audit_events — at-least-once, ordered, no queue — and starts at creation
 * time: a webhook never receives history. Webhooks are an operational sink;
 * the append-only audit_events table remains the authoritative record
 * (ADR-0016).
 */

export const SIGNATURE_HEADER = "x-varlatch-signature";
const DELIVERY_BATCH = 100;
const DELIVERY_TIMEOUT_MS = 10_000;

export interface WebhookRow {
  id: string;
  organization_id: string;
  url: string;
  event_types: string[] | null;
  created_at: string;
  revoked_at: string | null;
  failure_count: number;
  last_attempt_at: string | null;
  last_status: string | null;
  version: number;
  updated_at: string | null;
}

export function signWebhookBody(secret: string, timestampSeconds: number, body: string): string {
  return createHmac("sha256", secret).update(`${timestampSeconds}.${body}`, "utf8").digest("hex");
}

export async function createWebhook(
  ctx: AppCtx,
  org: OrgRow,
  input: { url: string; eventTypes?: string[] | undefined },
  actorIdentityId: string,
): Promise<{ webhook: WebhookRow; secret: string }> {
  let parsed: URL;
  try {
    parsed = new URL(input.url);
  } catch {
    throw new DomainError("VALIDATION_FAILED", "Invalid webhook URL");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new DomainError("VALIDATION_FAILED", "Webhook URL must be http(s)");
  }
  if (parsed.username || parsed.password) {
    throw new DomainError("VALIDATION_FAILED", "Webhook URL must not contain userinfo credentials");
  }
  const id = newId("webhook");
  // The verification secret is returned exactly once and rests encrypted
  // under the org KEK — it must be recoverable to sign future deliveries,
  // so hashing (the credential pattern) does not apply.
  const secret = `vlt_whsec_${randomBytes(32).toString("base64url")}`;
  const envelope = encryptWebhookSecret(orgKekOf(ctx, org), org.id, id, secret);
  return withTx(ctx.db, async (db) => {
    const eventId = await recordAuditEvent(db, {
      eventType: "webhook.created",
      decision: "info",
      actorIdentityId,
      organizationId: org.id,
      action: "organization.manage",
      resource: { webhookId: id },
      metadata: {
        url: redactWebhookUrl(input.url),
        ...(input.eventTypes ? { eventTypes: input.eventTypes.join(",") } : {}),
      },
    });
    // The cursor starts at the creation event itself: within one transaction
    // now() is constant, so anchoring on (now(), eventId) keeps this
    // webhook's own registration out of its first delivery.
    const res = await db.query(
      `INSERT INTO webhooks (id, organization_id, url, event_types, secret_envelope, created_by, cursor_occurred_at, cursor_event_id, cursor_order)
       VALUES ($1,$2,$3,$4,$5,$6,now(),$7,(SELECT event_order FROM audit_events WHERE id = $7))
       RETURNING id, organization_id, url, event_types, created_at, revoked_at, failure_count, last_attempt_at, last_status, version, updated_at`,
      [
        id,
        org.id,
        input.url,
        input.eventTypes ?? null,
        JSON.stringify(envelope),
        actorIdentityId,
        eventId,
      ],
    );
    return { webhook: res.rows[0] as WebhookRow, secret };
  });
}

export async function listWebhooks(ctx: AppCtx, organizationId: string): Promise<WebhookRow[]> {
  const res = await ctx.db.query(
    `SELECT id, organization_id, url, event_types, created_at, revoked_at, failure_count, last_attempt_at, last_status, version, updated_at
     FROM webhooks WHERE organization_id = $1 AND revoked_at IS NULL
     ORDER BY created_at, id`,
    [organizationId],
  );
  return res.rows as WebhookRow[];
}

/**
 * In-place webhook update (ADR-0029 §8): URL and/or event-type filter.
 * Delivery identity and progress are preserved — the signing secret and
 * cursor are untouched, so undelivered events (including backlog) go to the
 * new URL/filter on subsequent delivery attempts. eventTypes replaces the
 * whole filter; null clears it (all events). URLs with userinfo are
 * rejected: audit diffs must stay credential-safe.
 */
export async function updateWebhook(
  ctx: AppCtx,
  organizationId: string,
  webhookId: string,
  patch: { expectedVersion: number; url?: string | undefined; eventTypes?: string[] | null | undefined },
  actorIdentityId: string,
): Promise<WebhookRow> {
  if (patch.url !== undefined) {
    let parsed: URL;
    try {
      parsed = new URL(patch.url);
    } catch {
      throw new DomainError("VALIDATION_FAILED", "Invalid webhook URL");
    }
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      throw new DomainError("VALIDATION_FAILED", "Webhook URL must be http(s)");
    }
    if (parsed.username || parsed.password) {
      throw new DomainError("VALIDATION_FAILED", "Webhook URL must not contain userinfo credentials");
    }
  }
  return withTx(ctx.db, async (db) => {
    const res = await db.query(
      `SELECT id, organization_id, url, event_types, created_at, revoked_at, failure_count, last_attempt_at, last_status, version, updated_at
       FROM webhooks WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL FOR UPDATE`,
      [webhookId, organizationId],
    );
    const row = res.rows[0] as WebhookRow | undefined;
    if (!row) throw new DomainError("RESOURCE_NOT_FOUND", "Webhook not found");
    if (row.version !== patch.expectedVersion) {
      throw new DomainError("VERSION_CONFLICT", "Webhook was modified concurrently; reload and retry");
    }
    const url = patch.url ?? row.url;
    const eventTypes = patch.eventTypes === undefined ? row.event_types : patch.eventTypes;
    const unchanged =
      url === row.url &&
      (eventTypes === null
        ? row.event_types === null
        : row.event_types !== null &&
          eventTypes.length === row.event_types.length &&
          eventTypes.every((t, i) => t === row.event_types?.[i]));
    if (unchanged) return row;
    const updated = await db.query(
      `UPDATE webhooks SET url = $1, event_types = $2, version = version + 1, updated_at = now()
       WHERE id = $3 RETURNING version, updated_at`,
      [url, eventTypes, webhookId],
    );
    const out = updated.rows[0] as { version: number; updated_at: string };
    await recordAuditEvent(db, {
      eventType: "webhook.updated",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "organization.manage",
      resource: { webhookId },
      metadata: {
        oldUrl: redactWebhookUrl(row.url),
        newUrl: redactWebhookUrl(url),
        oldEventTypes: row.event_types?.join(",") ?? null,
        newEventTypes: eventTypes?.join(",") ?? null,
        version: out.version,
      },
    });
    return { ...row, url, event_types: eventTypes, version: out.version, updated_at: out.updated_at };
  });
}

export async function revokeWebhook(
  ctx: AppCtx,
  organizationId: string,
  webhookId: string,
  actorIdentityId: string,
): Promise<void> {
  await withTx(ctx.db, async (db) => {
    const res = await db.query(
      "UPDATE webhooks SET revoked_at = now() WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL RETURNING id",
      [webhookId, organizationId],
    );
    if (!res.rows[0]) throw new DomainError("RESOURCE_NOT_FOUND", "Webhook not found");
    await recordAuditEvent(db, {
      eventType: "webhook.revoked",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "organization.manage",
      resource: { webhookId },
    });
  });
}

/**
 * One delivery pass over all active webhooks. Each webhook advances its
 * (occurred_at, id) cursor only after a 2xx response, so failures retry the
 * same batch on the next pass (at-least-once). Failures never throw: they
 * are recorded on the row and logged.
 */
export async function deliverWebhooksOnce(
  ctx: AppCtx,
  fetchImpl: typeof fetch = fetch,
): Promise<void> {
  const hooks = await ctx.db.query(
    `SELECT w.id, w.organization_id, w.url, w.event_types, w.secret_envelope,
            w.cursor_occurred_at, w.cursor_event_id, w.cursor_order, o.wrapped_org_kek
     FROM webhooks w JOIN organizations o ON o.id = w.organization_id
     WHERE w.revoked_at IS NULL AND o.deleted_at IS NULL`,
  );
  for (const raw of hooks.rows as Record<string, unknown>[]) {
    try {
      await deliverOne(ctx, raw, fetchImpl);
    } catch (err) {
      console.error(`webhook delivery failed (${String(raw.id)}):`, err);
    }
  }
}

async function deliverOne(
  ctx: AppCtx,
  raw: Record<string, unknown>,
  fetchImpl: typeof fetch,
): Promise<void> {
  const webhookId = raw.id as string;
  const organizationId = raw.organization_id as string;
  const eventTypes = raw.event_types as string[] | null;
  const params: unknown[] = [
    organizationId,
    raw.cursor_order,
    DELIVERY_BATCH,
  ];
  let where =
    "organization_id = $1 AND event_order > $2";
  if (eventTypes && eventTypes.length > 0) {
    where += " AND event_type = ANY($4)";
    params.push(eventTypes);
  }
  const events = await ctx.db.query(
    `SELECT * FROM audit_events WHERE ${where} ORDER BY event_order LIMIT $3`,
    params,
  );
  const rows = events.rows as Record<string, unknown>[];
  if (rows.length === 0) return;

  const envelope =
    typeof raw.secret_envelope === "string"
      ? (JSON.parse(raw.secret_envelope) as Envelope)
      : (raw.secret_envelope as Envelope);
  // orgKekOf only needs the org id and its wrapped KEK (joined above).
  const orgForKek = {
    id: organizationId,
    wrapped_org_kek: raw.wrapped_org_kek,
  } as OrgRow;
  const secret = decryptWebhookSecret(
    orgKekOf(ctx, orgForKek),
    organizationId,
    webhookId,
    envelope,
  );
  const body = JSON.stringify({
    webhookId,
    organizationId,
    events: rows.map(serializeAuditEvent),
  });
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = signWebhookBody(secret, timestamp, body);

  let status: string;
  let ok = false;
  try {
    const res = await fetchImpl(raw.url as string, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        [SIGNATURE_HEADER]: `t=${timestamp},v1=${signature}`,
      },
      body,
      signal: AbortSignal.timeout(DELIVERY_TIMEOUT_MS),
      redirect: "error",
    });
    ok = res.ok;
    status = String(res.status);
  } catch (err) {
    status = err instanceof Error ? err.name : "error";
  }

  const last = rows[rows.length - 1] as { occurred_at: string; id: string; event_order: string };
  if (ok) {
    await ctx.db.query(
      `UPDATE webhooks SET cursor_order = GREATEST(cursor_order, $2), cursor_event_id = $3,
              failure_count = 0, last_attempt_at = now(), last_status = $4
       WHERE id = $1`,
      [webhookId, last.event_order, last.id, status],
    );
  } else {
    await ctx.db.query(
      `UPDATE webhooks SET failure_count = failure_count + 1,
              last_attempt_at = now(), last_status = $2
       WHERE id = $1`,
      [webhookId, status],
    );
  }
}

/** Periodic delivery, modeled on the mirror loop: best-effort, never throws. */
export function startWebhookLoop(ctx: AppCtx, intervalMs = 30_000): () => void {
  let busy = false;
  const tick = async () => {
    if (busy) return;
    const leave = ctx.maintenance?.enter();
    if (ctx.maintenance && !leave) return;
    busy = true;
    try { await deliverWebhooksOnce(ctx); }
    catch (err) { console.error("webhook loop error:", err); }
    finally { busy = false; leave?.(); }
  };
  const timer = setInterval(tick, intervalMs);
  timer.unref();
  void tick();
  return () => clearInterval(timer);
}

export { redactWebhookUrl } from "../audit/serialize.js";
