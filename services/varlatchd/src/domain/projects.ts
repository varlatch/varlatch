// SPDX-License-Identifier: AGPL-3.0-or-later
import { recordAuditEvent } from "../audit/events.js";
import { newId } from "../db/ids.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { DomainError, notFound } from "./errors.js";
import { lockLiveScope } from "./liveness.js";

export interface ProjectRow {
  id: string;
  organization_id: string;
  slug: string;
  name: string;
  contract_authority: "git" | "managed";
  active_contract_revision_id: string | null;
  created_at: string;
  /** A tombstone (ADR-0051): set when the Project was deleted. Lookups return live Projects only. */
  deleted_at: string | null;
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
    await lockLiveScope(db, { organizationId });
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

/**
 * Rename is display-plane only: the slug is what the CLI, URLs, contracts and
 * grants use, and it never changes. The audit event carries both names so
 * older audit lines stay interpretable.
 */
export async function renameProject(
  ctx: AppCtx,
  organizationId: string,
  projectId: string,
  name: string,
  actorIdentityId: string,
): Promise<ProjectRow> {
  if (!name || name.length > 200) {
    throw new DomainError("VALIDATION_FAILED", "Invalid project name");
  }
  return withTx(ctx.db, async (db) => {
    await lockLiveScope(db, { organizationId, projectId, projectMode: "no key update" });
    const prev = await db.query(
      "SELECT slug, name FROM projects WHERE organization_id = $1 AND id = $2",
      [organizationId, projectId],
    );
    const row = prev.rows[0] as { slug: string; name: string } | undefined;
    if (!row) throw notFound("Project");
    await db.query("UPDATE projects SET name = $1 WHERE id = $2", [name, projectId]);
    await recordAuditEvent(db, {
      eventType: "project.renamed",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "project.manage",
      resource: { projectId, projectSlug: row.slug },
      metadata: { previousName: row.name, name },
    });
    return getProject(ctx, organizationId, projectId, db);
  });
}

export async function getProject(
  ctx: AppCtx,
  organizationId: string,
  slugOrId: string,
  db = ctx.db,
): Promise<ProjectRow> {
  const res = await db.query(
    "SELECT * FROM projects WHERE organization_id = $1 AND (id = $2 OR slug = $2) AND deleted_at IS NULL",
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
    "SELECT * FROM projects WHERE organization_id = $1 AND deleted_at IS NULL ORDER BY created_at, id",
    [organizationId],
  );
  return res.rows as ProjectRow[];
}

export interface ProjectDeletion {
  environments: number;
  values: number;
  versionsErased: number;
  capabilitiesRevoked: number;
  targetsRevoked: number;
  teamLinksRemoved: number;
}

/**
 * Deletes a Project (ADR-0051 Decision 2): one transaction that tombstones
 * it and every environment, erases every value version (payload and
 * wrapped DEK; previously deleted environments and values included, since
 * no Project key exists to destroy), clears version pointers, revokes the
 * environments' Capabilities and the Project's Sync Targets (fencing any
 * push in progress and releasing their destination claims), and removes
 * Teams' links to it. Contract Revisions stay with the tombstone, and audit
 * events keep their IDs and names. The audit event comes last.
 *
 * Under the writer protocol: the Organization only checked, the Project
 * exclusively, so writers in progress finish first and later ones find it
 * deleted; then every environment, and every Target, in ID order.
 */
export async function deleteProject(
  ctx: AppCtx,
  organizationId: string,
  projectId: string,
  actorIdentityId: string,
): Promise<ProjectDeletion> {
  return withTx(ctx.db, async (db) => {
    await lockLiveScope(db, { organizationId, projectId, projectMode: "update" });
    const project = (await db.query("SELECT slug, name FROM projects WHERE id = $1", [projectId])).rows[0] as { slug: string; name: string };
    const envs = (
      await db.query("SELECT id, deleted_at FROM environments WHERE project_id = $1 ORDER BY id FOR UPDATE", [projectId])
    ).rows as { id: string; deleted_at: string | null }[];
    const envIds = envs.map((e) => e.id);
    const targets = (
      await db.query("SELECT id FROM sync_targets WHERE project_id = $1 AND revoked_at IS NULL ORDER BY id FOR UPDATE", [projectId])
    ).rows as { id: string }[];

    // Derived environments first, then roots: an order of updates only.
    await db.query(
      "UPDATE environments SET deleted_at = now() WHERE project_id = $1 AND deleted_at IS NULL AND parent_environment_id IS NOT NULL",
      [projectId],
    );
    await db.query("UPDATE environments SET deleted_at = now() WHERE project_id = $1 AND deleted_at IS NULL", [projectId]);
    const values = await db.query(
      `UPDATE env_values
       SET deleted_at = COALESCE(deleted_at, now()), current_version_id = NULL,
           retiring_version_id = NULL, rotation_deadline = NULL, rotation_started_at = NULL
       WHERE environment_id = ANY($1) RETURNING id`,
      [envIds],
    );
    const erased = await db.query(
      `UPDATE value_versions SET payload = NULL, wrapped_dek = NULL, erased_at = now()
       WHERE erased_at IS NULL AND value_id IN (SELECT id FROM env_values WHERE environment_id = ANY($1))
       RETURNING id`,
      [envIds],
    );
    const capabilities = await db.query(
      "UPDATE capabilities SET revoked_at = now() WHERE environment_id = ANY($1) AND revoked_at IS NULL RETURNING id",
      [envIds],
    );
    // Revocation fences a push in progress (ADR-0050 Decision 1) and
    // releases the destination claim.
    await db.query(
      `UPDATE sync_targets
       SET revoked_at = now(), generation = generation + 1, lease_expires_at = NULL, repair_cycle_started_at = NULL,
           version = version + 1, updated_at = now()
       WHERE id = ANY($1)`,
      [targets.map((t) => t.id)],
    );
    const teamLinks = await db.query("DELETE FROM team_projects WHERE project_id = $1 RETURNING team_id", [projectId]);
    await db.query("UPDATE projects SET deleted_at = now() WHERE id = $1", [projectId]);

    const counts: ProjectDeletion = {
      environments: envs.filter((e) => !e.deleted_at).length,
      values: values.rows.length,
      versionsErased: erased.rows.length,
      capabilitiesRevoked: capabilities.rows.length,
      targetsRevoked: targets.length,
      teamLinksRemoved: teamLinks.rows.length,
    };
    await recordAuditEvent(db, {
      eventType: "project.deleted",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "project.manage",
      resource: { projectId, projectSlug: project.slug },
      metadata: { name: project.name, ...counts },
    });
    return counts;
  });
}
