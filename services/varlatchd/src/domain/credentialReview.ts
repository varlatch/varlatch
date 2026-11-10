// SPDX-License-Identifier: AGPL-3.0-or-later
import type { AppCtx } from "./ctx.js";

/**
 * Credential review (ADR-0054 Decision 8): per Organization, the machine
 * credentials worth a look, each with its identity and last use. Reporting
 * only: it changes no authorization and no issuance, and nothing is retired
 * automatically (ADR-0034 keeps that a non-goal; last use makes idleness
 * visible, acting on it stays a human decision).
 *
 * Reviewed: the credentials of the Organization's machine identities (every
 * kind but human) that could still authenticate if their identity were live:
 * not revoked, not expired, use budget not spent. Short-lived kinds are left
 * out: an OIDC exchange credential and an agent-run credential always carry
 * an expiry of at most an hour, so they leave the review on their own.
 *
 * A reviewed credential is listed when at least one reason applies:
 * - never-used: no successful authentication yet;
 * - idle: last used more than IDLE_DAYS days ago;
 * - no-expiry: it never expires.
 *
 * last_used_at is updated at most once a minute (ADR-0034 §5); that is fine
 * at this scale. Metadata only, never a token or a hash.
 */

/** Days without use after which a used credential counts as idle. */
export const IDLE_DAYS = 30;

/** Credential kinds short-lived by construction (expiry of at most an hour). */
const SHORT_LIVED_KINDS = ["oidc", "agent-run"] as const;

export type ReviewReason = "never-used" | "idle" | "no-expiry";
export type IdentityState = "live" | "disabled" | "retired";

export interface ReviewedCredential {
  id: string;
  name: string | null;
  kind: string;
  createdAt: string;
  expiresAt: string | null;
  lastUsedAt: string | null;
  issuedBy: { id: string; name: string } | null;
  identity: {
    id: string;
    name: string;
    kind: string;
    state: IdentityState;
    disabledReason: "organization-deletion" | null;
  };
  reasons: ReviewReason[];
}

export interface CredentialReview {
  generatedAt: string;
  idleDays: number;
  summary: { reviewed: number; listed: number; neverUsed: number; idle: number; noExpiry: number };
  items: ReviewedCredential[];
}

interface Row {
  id: string;
  name: string | null;
  kind: string;
  created_at: string | Date;
  expires_at: string | Date | null;
  last_used_at: string | Date | null;
  issued_by: string | null;
  issued_by_name: string | null;
  identity_id: string;
  identity_name: string;
  identity_kind: string;
  disabled: boolean;
  suspended_by_deletion: string | null;
  idle: boolean;
  now: string | Date;
}

const iso = (v: string | Date) => new Date(v).toISOString();

export async function credentialReview(ctx: AppCtx, organizationId: string): Promise<CredentialReview> {
  // One statement, so every comparison uses the same now().
  const res = await ctx.db.query(
    `SELECT c.id, c.name, c.kind, c.created_at, c.expires_at, c.last_used_at,
            c.issued_by, ib.name AS issued_by_name,
            i.id AS identity_id, i.name AS identity_name, i.kind AS identity_kind,
            i.disabled, i.suspended_by_deletion,
            (c.last_used_at IS NOT NULL AND c.last_used_at < now() - $2::int * interval '1 day') AS idle,
            now() AS now
     FROM credentials c
     JOIN identities i ON i.id = c.identity_id
     LEFT JOIN identities ib ON ib.id = c.issued_by
     WHERE i.organization_id = $1
       AND i.kind <> 'human'
       AND c.kind <> ALL($3::text[])
       AND c.revoked_at IS NULL
       AND (c.expires_at IS NULL OR c.expires_at > now())
       AND (c.max_uses IS NULL OR c.use_count < c.max_uses)
     ORDER BY i.name, i.id, c.created_at, c.id`,
    [organizationId, IDLE_DAYS, [...SHORT_LIVED_KINDS]],
  );
  const rows = res.rows as Row[];
  const items: ReviewedCredential[] = [];
  for (const r of rows) {
    const reasons: ReviewReason[] = [];
    if (r.last_used_at === null) reasons.push("never-used");
    if (r.idle) reasons.push("idle");
    if (r.expires_at === null) reasons.push("no-expiry");
    if (reasons.length === 0) continue;
    const state: IdentityState = !r.disabled ? "live" : r.suspended_by_deletion ? "disabled" : "retired";
    items.push({
      id: r.id,
      name: r.name ?? null,
      kind: r.kind,
      createdAt: iso(r.created_at),
      expiresAt: r.expires_at ? iso(r.expires_at) : null,
      lastUsedAt: r.last_used_at ? iso(r.last_used_at) : null,
      issuedBy: r.issued_by ? { id: r.issued_by, name: r.issued_by_name ?? r.issued_by } : null,
      identity: {
        id: r.identity_id,
        name: r.identity_name,
        kind: r.identity_kind,
        state,
        disabledReason: state === "disabled" ? "organization-deletion" : null,
      },
      reasons,
    });
  }
  const count = (reason: ReviewReason) => items.filter((i) => i.reasons.includes(reason)).length;
  const now = rows[0]?.now;
  return {
    generatedAt: now ? iso(now) : new Date().toISOString(),
    idleDays: IDLE_DAYS,
    summary: {
      reviewed: rows.length,
      listed: items.length,
      neverUsed: count("never-used"),
      idle: count("idle"),
      noExpiry: count("no-expiry"),
    },
    items,
  };
}
