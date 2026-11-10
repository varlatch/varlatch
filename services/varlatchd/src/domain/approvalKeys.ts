// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Querier } from "../db/migrate.js";
import type { PasskeyTrust, TrustedVia } from "./passkeys.js";

/**
 * The approval keys of an Organization's admins (ADR-0054 Decisions 4 and
 * 11): for each live admin, which of their passkeys are trusted and which
 * are unconfirmed. Only a trusted passkey can give a step-up approval, so an
 * admin without one cannot approve loosening a control, whatever the
 * controls' modes.
 *
 * Read-only and metadata only: a passkey's name, provenance and dates, never
 * its credential id, public key or counter, and no passkey ids either (the
 * page has nothing to act on: confirming is the person's own ceremony on
 * their account Security page, recovery is the host operator's).
 *
 * Admins are the live memberships with the admin role whose person is not
 * disabled, as the last-admin rule counts them. A passkey without a
 * provenance row counts as unconfirmed, as everywhere else.
 */

export interface ApprovalKey {
  name: string | null;
  trust: PasskeyTrust;
  trustedVia: TrustedVia | null;
  createdAt: string | null;
  trustedAt: string | null;
}

export interface AdminApprovalKeys {
  identity: { id: string; name: string };
  trusted: number;
  unconfirmed: number;
  /** When one of their passkeys was last confirmed with a trusted one; null when none ever was. */
  lastConfirmedAt: string | null;
  /** Trusted first, then unconfirmed; oldest first within each. */
  passkeys: ApprovalKey[];
}

export interface ApprovalKeys {
  generatedAt: string;
  summary: { admins: number; withTrustedKey: number; withoutTrustedKey: number };
  items: AdminApprovalKeys[];
}

interface Row {
  identity_id: string;
  identity_name: string;
  passkey_id: string | null;
  passkey_name: string | null;
  created_at: Date | string | null;
  trust: PasskeyTrust | null;
  trusted_via: TrustedVia | null;
  trusted_at: Date | string | null;
  now: Date | string;
}

const iso = (v: Date | string | null): string | null => (v === null ? null : new Date(v).toISOString());

export async function approvalKeys(db: Querier, organizationId: string): Promise<ApprovalKeys> {
  const res = await db.query(
    `SELECT i.id AS identity_id, i.name AS identity_name,
            p.id AS passkey_id, p.name AS passkey_name, p."createdAt" AS created_at,
            pp.trust, pp.trusted_via, pp.trusted_at, now() AS now
     FROM org_memberships m
     JOIN identities i ON i.id = m.identity_id
     LEFT JOIN auth_user_links l ON l.identity_id = i.id
     LEFT JOIN passkey p ON p."userId" = l.better_auth_user_id
     LEFT JOIN passkey_provenance pp ON pp.passkey_id = p.id
     WHERE m.organization_id = $1 AND m.role = 'admin' AND m.removed_at IS NULL
       AND i.kind = 'human' AND NOT i.disabled
     ORDER BY i.name, i.id, p."createdAt" NULLS FIRST, p.id`,
    [organizationId],
  );
  const rows = res.rows as Row[];
  const byAdmin = new Map<string, AdminApprovalKeys>();
  for (const r of rows) {
    let admin = byAdmin.get(r.identity_id);
    if (!admin) {
      admin = { identity: { id: r.identity_id, name: r.identity_name }, trusted: 0, unconfirmed: 0, lastConfirmedAt: null, passkeys: [] };
      byAdmin.set(r.identity_id, admin);
    }
    if (r.passkey_id === null) continue;
    const trust: PasskeyTrust = r.trust ?? "unconfirmed";
    const key: ApprovalKey = {
      name: r.passkey_name,
      trust,
      trustedVia: trust === "trusted" ? r.trusted_via : null,
      createdAt: iso(r.created_at),
      trustedAt: trust === "trusted" ? iso(r.trusted_at) : null,
    };
    admin.passkeys.push(key);
    if (trust === "trusted") admin.trusted += 1;
    else admin.unconfirmed += 1;
    if (key.trustedVia === "confirmed" && key.trustedAt && (!admin.lastConfirmedAt || key.trustedAt > admin.lastConfirmedAt)) {
      admin.lastConfirmedAt = key.trustedAt;
    }
  }
  const items = [...byAdmin.values()];
  for (const admin of items) {
    // Stable sort: trusted first, keeping the oldest-first order within each.
    admin.passkeys.sort((a, b) => (a.trust === b.trust ? 0 : a.trust === "trusted" ? -1 : 1));
  }
  const withTrustedKey = items.filter((a) => a.trusted > 0).length;
  const now = rows[0]?.now;
  return {
    generatedAt: now ? new Date(now).toISOString() : new Date().toISOString(),
    summary: { admins: items.length, withTrustedKey, withoutTrustedKey: items.length - withTrustedKey },
    items,
  };
}
