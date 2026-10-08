// SPDX-License-Identifier: AGPL-3.0-or-later
import { recordAuditEvent } from "../audit/events.js";
import { issueCredential } from "../auth/credentials.js";
import {
  decodeUnverified,
  OidcVerificationError,
  verifyOidcToken,
  type OidcClaims,
} from "../auth/oidc.js";
import { newId } from "../db/ids.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";

/**
 * OIDC machine authentication (ADR-0007 foresaw CI federation): an admin
 * binds issuer + audience + subject (+ optional exact-match claims) to one
 * machine Identity; a workload then exchanges its platform-issued OIDC
 * token for a short-lived 'oidc' credential. Bindings are an
 * Authentication Method — they establish identity only; authority remains
 * the Identity's Grants, evaluated per request as always.
 */

const DEFAULT_TTL_SECONDS = 600;
export const MAX_TTL_SECONDS = 3600;

export interface OidcBindingRow {
  id: string;
  identity_id: string;
  organization_id: string;
  issuer: string;
  audience: string;
  subject: string;
  claims: Record<string, string> | string | null;
  created_at: string;
  revoked_at: string | null;
}

function claimsOf(row: OidcBindingRow): Record<string, string> | null {
  if (row.claims == null) return null;
  return typeof row.claims === "string"
    ? (JSON.parse(row.claims) as Record<string, string>)
    : row.claims;
}

/** Exact match, or prefix match when the binding subject ends with '*'. */
export function subjectMatches(pattern: string, sub: string): boolean {
  if (pattern.endsWith("*")) return sub.startsWith(pattern.slice(0, -1));
  return pattern === sub;
}

function audienceMatches(aud: OidcClaims["aud"], expected: string): boolean {
  return Array.isArray(aud) ? aud.includes(expected) : aud === expected;
}

export async function createOidcBinding(
  ctx: AppCtx,
  organizationId: string,
  identityId: string,
  input: {
    issuer: string;
    audience: string;
    subject: string;
    claims?: Record<string, string> | undefined;
  },
  actorIdentityId: string,
): Promise<OidcBindingRow> {
  let issuer: URL;
  try {
    issuer = new URL(input.issuer);
  } catch {
    throw new DomainError("VALIDATION_FAILED", "Invalid issuer URL");
  }
  // OIDC issuers are https, no query/fragment (OIDC Core §2).
  if (issuer.protocol !== "https:" || issuer.search || issuer.hash) {
    throw new DomainError("VALIDATION_FAILED", "Issuer must be a plain https URL");
  }
  return withTx(ctx.db, async (db) => {
    const id = newId("oidcBinding");
    const res = await db.query(
      `INSERT INTO oidc_bindings (id, identity_id, organization_id, issuer, audience, subject, claims, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING id, identity_id, organization_id, issuer, audience, subject, claims, created_at, revoked_at`,
      [
        id,
        identityId,
        organizationId,
        input.issuer,
        input.audience,
        input.subject,
        input.claims ? JSON.stringify(input.claims) : null,
        actorIdentityId,
      ],
    );
    await recordAuditEvent(db, {
      eventType: "oidc_binding.created",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "identity.manage",
      resource: { identityId, oidcBindingId: id },
      metadata: { issuer: input.issuer, audience: input.audience, subject: input.subject },
    });
    return res.rows[0] as OidcBindingRow;
  });
}

export async function listOidcBindings(
  ctx: AppCtx,
  organizationId: string,
  identityId: string,
): Promise<OidcBindingRow[]> {
  const res = await ctx.db.query(
    `SELECT id, identity_id, organization_id, issuer, audience, subject, claims, created_at, revoked_at
     FROM oidc_bindings
     WHERE organization_id = $1 AND identity_id = $2 AND revoked_at IS NULL
     ORDER BY created_at, id`,
    [organizationId, identityId],
  );
  return res.rows as OidcBindingRow[];
}

export async function revokeOidcBinding(
  ctx: AppCtx,
  organizationId: string,
  identityId: string,
  bindingId: string,
  actorIdentityId: string,
): Promise<void> {
  await withTx(ctx.db, async (db) => {
    const res = await db.query(
      `UPDATE oidc_bindings SET revoked_at = now()
       WHERE id = $1 AND organization_id = $2 AND identity_id = $3 AND revoked_at IS NULL
       RETURNING id`,
      [bindingId, organizationId, identityId],
    );
    if (!res.rows[0]) throw new DomainError("RESOURCE_NOT_FOUND", "Binding not found");
    await recordAuditEvent(db, {
      eventType: "oidc_binding.revoked",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "identity.manage",
      resource: { identityId, oidcBindingId: bindingId },
    });
  });
}

/** All failures collapse to INVALID_CREDENTIAL; distinctions exist in audit. */
async function reject(ctx: AppCtx, reason: string, requestId?: string): Promise<never> {
  await recordAuditEvent(ctx.db, {
    eventType: "authentication.failed",
    decision: "deny",
    requestId: requestId ?? null,
    metadata: { method: "oidc", reason },
  });
  throw new DomainError("INVALID_CREDENTIAL", "OIDC token was not accepted");
}

export async function exchangeOidcToken(
  ctx: AppCtx,
  token: string,
  opts: {
    organization: string;
    ttlSeconds?: number | undefined;
    requestId?: string | undefined;
    fetchImpl?: typeof fetch | undefined;
  },
): Promise<{ credentialId: string; token: string; expiresAt: string; identityId: string }> {
  const ttl = opts.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > MAX_TTL_SECONDS) {
    throw new DomainError("VALIDATION_FAILED", `ttlSeconds must be 1..${MAX_TTL_SECONDS}`);
  }

  let peek: OidcClaims;
  try {
    peek = decodeUnverified(token);
  } catch {
    return reject(ctx, "malformed", opts.requestId);
  }

  // Bindings for this issuer, active identities only. Existence is hidden:
  // unknown issuer, no binding, and failed verification all collapse.
  const res = await ctx.db.query(
    `SELECT b.id, b.identity_id, b.organization_id, b.issuer, b.audience, b.subject, b.claims,
            b.created_at, b.revoked_at
     FROM oidc_bindings b
     JOIN identities i ON i.id = b.identity_id
     JOIN organizations o ON o.id = b.organization_id
     WHERE (o.id = $2 OR o.slug = $2) AND b.issuer = $1 AND b.revoked_at IS NULL AND i.disabled = false`,
    [typeof peek.iss === "string" ? peek.iss : "", opts.organization],
  );
  const bindings = res.rows as OidcBindingRow[];
  if (bindings.length === 0) return reject(ctx, "no-binding", opts.requestId);

  let claims: OidcClaims;
  try {
    claims = await verifyOidcToken(token, bindings[0]!.issuer, opts.fetchImpl ?? fetch);
  } catch (err) {
    return reject(
      ctx,
      err instanceof OidcVerificationError ? err.message : "verification-error",
      opts.requestId,
    );
  }

  const matched = bindings.filter((b) => {
    if (!audienceMatches(claims.aud, b.audience)) return false;
    if (!subjectMatches(b.subject, claims.sub)) return false;
    const extra = claimsOf(b);
    if (extra) {
      for (const [key, expected] of Object.entries(extra)) {
        if (claims[key] !== expected) return false;
      }
    }
    return true;
  });
  if (matched.length === 0) return reject(ctx, "no-matching-binding", opts.requestId);
  const identities = new Set(matched.map((b) => b.identity_id));
  if (identities.size > 1) return reject(ctx, "ambiguous-binding", opts.requestId);

  const binding = matched[0] as OidcBindingRow;
  const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();
  const issued = await issueCredential(ctx.db, {
    identityId: binding.identity_id,
    kind: "oidc",
    name: `oidc:${claims.sub.slice(0, 180)}`,
    expiresAt,
    actorIdentityId: binding.identity_id,
    organizationId: binding.organization_id,
    metadata: {
      method: "oidc",
      oidcBindingId: binding.id,
      issuer: binding.issuer,
      subject: claims.sub,
    },
  });
  return {
    credentialId: issued.credentialId,
    token: issued.token,
    expiresAt,
    identityId: binding.identity_id,
  };
}
