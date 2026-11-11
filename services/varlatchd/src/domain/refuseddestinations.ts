// SPDX-License-Identifier: AGPL-3.0-or-later
import type { InstallationOutbound, RefusedDestinations } from "@varlatch/protocol";
import { outboundCheck, refusedDestinations } from "../net/outbound-check.js";
import { allowListWarnings, outboundOf } from "../net/outbound.js";
import type { AppCtx } from "./ctx.js";

/**
 * Where refused outbound destinations are visible (ADR-0057 Decision 8),
 * beyond the operator's terminal: the Installation page, for Installation
 * Admins, and each Organization's Security page and `varlatch security
 * report`, for its admins.
 *
 * Both run the check `varlatchd admin outbound check` and doctor run
 * (net/outbound-check.ts) with the policy varlatchd started with: DNS
 * lookups only, never a request to a destination. What they return never
 * holds a resolved address, a path, a query or a credential: the check
 * reads only a webhook URL's or Connection's host and port, and the
 * addresses it resolved stay here.
 */

/** How far back `since` looks in the audit log. */
export const REFUSED_SINCE_DAYS = 30;

const iso = (v: Date | string): string => (v instanceof Date ? v : new Date(v)).toISOString();

/**
 * The Organization's configured destinations the policy refuses, each with
 * when its first refusal in the last REFUSED_SINCE_DAYS days was recorded
 * (`outbound.refused`, for that object, host and port). Never the allow
 * list: that is the host's.
 */
export async function organizationRefusedDestinations(ctx: AppCtx, organizationId: string): Promise<RefusedDestinations> {
  const report = await outboundCheck(ctx.db, outboundOf(ctx), { org: organizationId });
  // The check's filter also matches a slug; only this Organization's rows, whatever a slug says.
  const refused = refusedDestinations(report).filter((d) => d.organizationId === organizationId);
  const since = new Map<string, string>();
  if (refused.length > 0) {
    const rows = (
      await ctx.db.query(
        `SELECT coalesce(resource->>'webhookId', resource->>'connectionId', resource->>'oidcBindingId') AS object_id,
                metadata->>'host' AS host, metadata->>'port' AS port, min(occurred_at) AS since
         FROM audit_events
         WHERE organization_id = $1 AND event_type = 'outbound.refused'
           AND occurred_at >= now() - make_interval(days => $2)
           AND coalesce(resource->>'webhookId', resource->>'connectionId', resource->>'oidcBindingId') = ANY($3)
         GROUP BY 1, 2, 3`,
        [organizationId, REFUSED_SINCE_DAYS, refused.map((d) => d.id)],
      )
    ).rows as { object_id: string; host: string | null; port: string | null; since: Date | string }[];
    for (const r of rows) since.set(`${r.object_id}|${r.host}|${r.port}`, iso(r.since));
  }
  return {
    generatedAt: new Date().toISOString(),
    sinceDays: REFUSED_SINCE_DAYS,
    items: refused.map((d) => ({
      kind: d.kind,
      id: d.id,
      name: d.name,
      scheme: d.scheme,
      host: d.host,
      port: d.port,
      reason: d.reason,
      since: since.get(`${d.id}|${d.host}|${d.port}`) ?? null,
    })),
  };
}

/**
 * For Installation Admins: VARLATCH_OUTBOUND_ALLOW as parsed, doctor's
 * warnings about it, every refused destination by Organization, and the
 * value that would allow the refused names.
 */
export async function installationOutbound(ctx: AppCtx): Promise<InstallationOutbound> {
  const policy = outboundOf(ctx);
  const report = await outboundCheck(ctx.db, policy);
  // By Organization; within one, in the check's order (webhooks, Connections, issuers).
  const refused = refusedDestinations(report).sort((a, b) => (a.organization < b.organization ? -1 : a.organization > b.organization ? 1 : 0));
  const ids = [...new Set(refused.map((d) => d.organizationId))];
  const orgs = new Map(
    ids.length === 0
      ? []
      : ((await ctx.db.query("SELECT id, slug, name FROM organizations WHERE id = ANY($1)", [ids])).rows as { id: string; slug: string; name: string }[]).map(
          (o) => [o.id, o] as const,
        ),
  );
  return {
    generatedAt: new Date().toISOString(),
    allow: report.allow,
    warnings: allowListWarnings(policy.entries),
    refused: refused.map((d) => {
      const org = orgs.get(d.organizationId);
      return {
        organization: { id: d.organizationId, slug: org?.slug ?? d.organization, name: org?.name ?? d.organization },
        kind: d.kind,
        id: d.id,
        name: d.name,
        scheme: d.scheme,
        host: d.host,
        port: d.port,
        reason: d.reason,
        notSuggested: d.notSuggested,
      };
    }),
    suggested: report.suggested,
    unresolved: report.destinations.filter((d) => d.verdict === "unresolved").length,
  };
}
