// SPDX-License-Identifier: AGPL-3.0-or-later
import { recordAuditEvent } from "../audit/events.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { DomainError, notFound } from "./errors.js";

/**
 * Invitation management (capability invitations.manage): an organization's
 * invitations are its `invite` setup grants (ADR-0006/0010). Listing and
 * revocation read and write metadata only: the token is shown once, at
 * issuance, and only its hash is stored; nothing here selects even that.
 */

export type InvitationStatus = "pending" | "consumed" | "expired" | "revoked";

export interface InvitationRow {
  id: string;
  invite_name: string | null;
  invite_role: "admin" | "member";
  created_at: string;
  expires_at: string;
  created_by: string | null;
  consumed_at: string | null;
  revoked_at: string | null;
  /** Evaluated by the database, against the same clock as consumption. */
  expired: boolean;
  /** created_at as text, for the cursor (keeps microsecond precision). */
  cursor_time: string;
}

export function invitationStatus(row: Pick<InvitationRow, "consumed_at" | "revoked_at" | "expired">): InvitationStatus {
  if (row.revoked_at) return "revoked";
  if (row.consumed_at) return "consumed";
  if (row.expired) return "expired";
  return "pending";
}

const COLUMNS = `id, invite_name, invite_role, created_at, created_at::text AS cursor_time, expires_at,
  created_by, consumed_at, revoked_at, expires_at <= now() AS expired`;

/**
 * One page of the organization's invitations, newest first by
 * (created_at, id), the cursor's tuple. Pending only unless `status` is
 * "all"; a pending invitation is unconsumed, unrevoked, and unexpired.
 */
export async function listInvitations(
  ctx: AppCtx,
  organizationId: string,
  opts: { status: "pending" | "all"; limit: number; after: [string, string] | null },
): Promise<{ rows: InvitationRow[]; more: boolean }> {
  const params: unknown[] = [organizationId, opts.limit + 1];
  let where = "kind = 'invite' AND invite_organization_id = $1";
  if (opts.status === "pending") {
    where += " AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > now()";
  }
  if (opts.after) {
    params.push(opts.after[0], opts.after[1]);
    where += " AND (created_at, id) < ($3::timestamptz, $4)";
  }
  const res = await ctx.db.query(
    `SELECT ${COLUMNS} FROM setup_grants WHERE ${where} ORDER BY created_at DESC, id DESC LIMIT $2`,
    params,
  );
  const rows = res.rows as InvitationRow[];
  return { rows: rows.slice(0, opts.limit), more: rows.length > opts.limit };
}

/**
 * Revoke a pending invitation: its token stops working at once, including
 * for an enrollment ceremony already started with it, because consumption
 * locks the same row and refuses a revoked grant. Only a pending invitation
 * can be revoked; any other is a VERSION_CONFLICT naming its status, since
 * the caller's view of it is stale.
 */
export async function revokeInvitation(
  ctx: AppCtx,
  organizationId: string,
  invitationId: string,
  actorIdentityId: string,
): Promise<InvitationRow> {
  return withTx(ctx.db, async (db) => {
    const res = await db.query(
      `SELECT ${COLUMNS} FROM setup_grants
       WHERE id = $1 AND kind = 'invite' AND invite_organization_id = $2 FOR UPDATE`,
      [invitationId, organizationId],
    );
    const row = res.rows[0] as InvitationRow | undefined;
    if (!row) throw notFound("Invitation");
    const status = invitationStatus(row);
    if (status !== "pending") {
      throw new DomainError("VERSION_CONFLICT", `Invitation is no longer pending: it is ${status}`, { status });
    }
    const updated = await db.query(
      `UPDATE setup_grants SET revoked_at = now() WHERE id = $1 RETURNING ${COLUMNS}`,
      [invitationId],
    );
    await recordAuditEvent(db, {
      eventType: "invitation.revoked",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "identity.manage",
      resource: { invitationId },
      metadata: { role: row.invite_role, inviteeName: row.invite_name },
    });
    return updated.rows[0] as InvitationRow;
  });
}
