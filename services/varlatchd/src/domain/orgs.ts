// SPDX-License-Identifier: AGPL-3.0-or-later
import { recordAuditEvent } from "../audit/events.js";
import { createWrappedOrgKek, unwrapOrgKek } from "../crypto/hierarchy.js";
import type { Envelope } from "../crypto/aead.js";
import { newId } from "../db/ids.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { DomainError, notFound } from "./errors.js";
import type { OrgRole } from "../authz/evaluate.js";

export interface OrgRow {
  id: string;
  slug: string;
  name: string;
  wrapped_org_kek: Envelope;
  deleted_at: string | null;
  created_at: string;
}

const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;

export async function createOrganization(
  ctx: AppCtx,
  input: { slug: string; name: string },
  actorIdentityId: string,
): Promise<OrgRow> {
  if (!SLUG_PATTERN.test(input.slug)) {
    throw new DomainError("VALIDATION_FAILED", "Invalid organization slug");
  }
  return withTx(ctx.db, async (db) => {
    const id = newId("organization");
    const { wrapped } = createWrappedOrgKek(ctx.rootKek, id);
    try {
      await db.query(
        "INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ($1,$2,$3,$4)",
        [id, input.slug, input.name, JSON.stringify(wrapped)],
      );
    } catch (err) {
      if (err instanceof Error && /unique|duplicate/i.test(err.message)) {
        throw new DomainError("VALIDATION_FAILED", "Organization slug already exists");
      }
      throw err;
    }
    // Any authenticated human may create an organization and becomes its
    // Organization Admin (ADR-0010 §6).
    await db.query(
      "INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ($1,$2,'admin')",
      [id, actorIdentityId],
    );
    await recordAuditEvent(db, {
      eventType: "organization.created",
      decision: "info",
      actorIdentityId,
      organizationId: id,
      resource: { organizationSlug: input.slug },
    });
    return getOrganization(ctx, id, db);
  });
}

export async function getOrganization(
  ctx: AppCtx,
  slugOrId: string,
  db = ctx.db,
): Promise<OrgRow> {
  const res = await db.query(
    "SELECT * FROM organizations WHERE (id = $1 OR slug = $1) AND deleted_at IS NULL",
    [slugOrId],
  );
  const row = res.rows[0] as OrgRow | undefined;
  if (!row) throw notFound("Organization");
  return row;
}

export async function getOrgRole(
  ctx: AppCtx,
  organizationId: string,
  identityId: string,
): Promise<OrgRole | null> {
  const res = await ctx.db.query(
    "SELECT role FROM org_memberships WHERE organization_id = $1 AND identity_id = $2",
    [organizationId, identityId],
  );
  const row = res.rows[0] as { role: OrgRole } | undefined;
  return row?.role ?? null;
}

export async function listOrganizationsFor(
  ctx: AppCtx,
  identityId: string,
): Promise<OrgRow[]> {
  const res = await ctx.db.query(
    `SELECT o.* FROM organizations o
     JOIN org_memberships m ON m.organization_id = o.id
     WHERE m.identity_id = $1 AND o.deleted_at IS NULL
     ORDER BY o.created_at, o.id`,
    [identityId],
  );
  return res.rows as OrgRow[];
}

/** Unwraps the organization KEK; callers must never persist or log it. */
export function orgKekOf(ctx: AppCtx, org: OrgRow): Buffer {
  const wrapped =
    typeof org.wrapped_org_kek === "string"
      ? (JSON.parse(org.wrapped_org_kek) as Envelope)
      : org.wrapped_org_kek;
  return unwrapOrgKek(ctx.rootKek, wrapped, org.id);
}
