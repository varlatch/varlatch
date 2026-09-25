// SPDX-License-Identifier: AGPL-3.0-or-later
import { recordAuditEvent } from "../audit/events.js";
import { newId } from "../db/ids.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { DomainError, notFound } from "./errors.js";

export interface ProjectRow {
  id: string;
  organization_id: string;
  slug: string;
  name: string;
  contract_authority: "git" | "managed";
  active_contract_revision_id: string | null;
  created_at: string;
}

const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;

export async function createProject(
  ctx: AppCtx,
  organizationId: string,
  input: { slug: string; name: string; contractAuthority: "git" | "managed" },
  actorIdentityId: string,
): Promise<ProjectRow> {
  if (!SLUG_PATTERN.test(input.slug)) {
    throw new DomainError("VALIDATION_FAILED", "Invalid project slug");
  }
  return withTx(ctx.db, async (db) => {
    const id = newId("project");
    try {
      await db.query(
        `INSERT INTO projects (id, organization_id, slug, name, contract_authority)
         VALUES ($1,$2,$3,$4,$5)`,
        [id, organizationId, input.slug, input.name, input.contractAuthority],
      );
    } catch (err) {
      if (err instanceof Error && /unique|duplicate/i.test(err.message)) {
        throw new DomainError("VALIDATION_FAILED", "Project slug already exists in this organization");
      }
      throw err;
    }
    await recordAuditEvent(db, {
      eventType: "project.created",
      decision: "info",
      actorIdentityId,
      organizationId,
      resource: { projectId: id, projectSlug: input.slug },
      metadata: { contractAuthority: input.contractAuthority },
    });
    return getProject(ctx, organizationId, id, db);
  });
}

export async function getProject(
  ctx: AppCtx,
  organizationId: string,
  slugOrId: string,
  db = ctx.db,
): Promise<ProjectRow> {
  const res = await db.query(
    "SELECT * FROM projects WHERE organization_id = $1 AND (id = $2 OR slug = $2)",
    [organizationId, slugOrId],
  );
  const row = res.rows[0] as ProjectRow | undefined;
  if (!row) throw notFound("Project");
  return row;
}

export async function listProjects(
  ctx: AppCtx,
  organizationId: string,
): Promise<ProjectRow[]> {
  const res = await ctx.db.query(
    "SELECT * FROM projects WHERE organization_id = $1 ORDER BY created_at, id",
    [organizationId],
  );
  return res.rows as ProjectRow[];
}
