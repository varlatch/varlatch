// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Tier } from "@varlatch/contract";
import { recordAuditEvent } from "../audit/events.js";
import { newId } from "../db/ids.js";
import { withTx } from "../db/tx.js";
import { activeContractOf } from "./contracts.js";
import type { AppCtx } from "./ctx.js";
import { DomainError, notFound } from "./errors.js";
import type { ProjectRow } from "./projects.js";

export interface EnvironmentRow {
  id: string;
  project_id: string;
  name: string;
  kind: "shared" | "personal" | "preview";
  tier: Tier;
  parent_environment_id: string | null;
  owner_identity_id: string | null;
  expires_at: string | null;
  deleted_at: string | null;
  created_at: string;
}

const ROOT_NAME = /^[a-z0-9][a-z0-9._-]{0,62}$/;
const DERIVED_NAME = /^[a-z0-9][a-z0-9._-]{0,62}\/[a-z0-9][a-z0-9._-]{0,62}$/;

export interface CreateEnvironmentInput {
  // `| undefined` matches zod-optional outputs under exactOptionalPropertyTypes.
  name: string;
  tier?: Tier | undefined;
  kind?: "shared" | "personal" | "preview" | undefined;
  parentEnvironmentId?: string | undefined;
  ownerIdentityId?: string | undefined;
  expiresAt?: string | undefined;
}

/**
 * Environment creation rules (ADR-0012): roots are shared and declare a tier;
 * derived environments (one level only) inherit the parent tier immutably,
 * must be personal or preview, and personal children of production-tier are
 * disallowed in MVP (ADR-0020).
 */
export async function createEnvironment(
  ctx: AppCtx,
  organizationId: string,
  projectId: string,
  input: CreateEnvironmentInput,
  actorIdentityId: string,
): Promise<EnvironmentRow> {
  return withTx(ctx.db, async (db) => {
    const id = newId("environment");
    let tier: Tier;
    let kind: EnvironmentRow["kind"];
    let parentId: string | null = null;

    if (input.parentEnvironmentId) {
      const parent = await getEnvironment(ctx, projectId, input.parentEnvironmentId, db);
      if (parent.parent_environment_id !== null) {
        throw new DomainError(
          "VALIDATION_FAILED",
          "Derived environments cannot themselves be parents (one-level inheritance)",
        );
      }
      if (input.tier !== undefined && input.tier !== parent.tier) {
        throw new DomainError(
          "VALIDATION_FAILED",
          "Derived environments inherit their parent's tier and cannot change it",
        );
      }
      kind = input.kind ?? "personal";
      if (kind === "shared") {
        throw new DomainError("VALIDATION_FAILED", "Derived environments must be personal or preview");
      }
      if (kind === "personal" && parent.tier === "production") {
        throw new DomainError(
          "VALIDATION_FAILED",
          "Personal environments derived from production-tier are not allowed",
        );
      }
      if (!DERIVED_NAME.test(input.name) || !input.name.startsWith(`${parent.name}/`)) {
        throw new DomainError(
          "VALIDATION_FAILED",
          "Derived environment names use the parent/suffix form",
        );
      }
      tier = parent.tier;
      parentId = parent.id;
    } else {
      if (!input.tier) {
        throw new DomainError("VALIDATION_FAILED", "Root environments must declare a tier");
      }
      if (input.kind && input.kind !== "shared") {
        throw new DomainError("VALIDATION_FAILED", "Root environments are shared");
      }
      if (!ROOT_NAME.test(input.name)) {
        throw new DomainError("VALIDATION_FAILED", "Invalid environment name");
      }
      tier = input.tier;
      kind = "shared";
    }

    if (input.expiresAt !== undefined && kind !== "preview") {
      throw new DomainError("VALIDATION_FAILED", "Only preview environments may expire");
    }

    try {
      await db.query(
        `INSERT INTO environments
           (id, project_id, name, kind, tier, parent_environment_id, owner_identity_id, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [
          id,
          projectId,
          input.name,
          kind,
          tier,
          parentId,
          input.ownerIdentityId ?? (kind === "personal" ? actorIdentityId : null),
          input.expiresAt ?? null,
        ],
      );
    } catch (err) {
      if (err instanceof Error && /unique|duplicate/i.test(err.message)) {
        throw new DomainError("VALIDATION_FAILED", "Environment name already exists in this project");
      }
      throw err;
    }
    await recordAuditEvent(db, {
      eventType: "environment.created",
      decision: "info",
      actorIdentityId,
      organizationId,
      resource: { projectId, environmentId: id, environmentName: input.name },
      metadata: { kind, tier, derived: parentId !== null },
    });
    return getEnvironment(ctx, projectId, id, db);
  });
}

export async function getEnvironment(
  ctx: AppCtx,
  projectId: string,
  nameOrId: string,
  db = ctx.db,
): Promise<EnvironmentRow> {
  const res = await db.query(
    "SELECT * FROM environments WHERE project_id = $1 AND (id = $2 OR name = $2) AND deleted_at IS NULL",
    [projectId, nameOrId],
  );
  const row = res.rows[0] as EnvironmentRow | undefined;
  if (!row) throw notFound("Environment");
  return row;
}

export async function listEnvironments(
  ctx: AppCtx,
  projectId: string,
): Promise<EnvironmentRow[]> {
  const res = await ctx.db.query(
    "SELECT * FROM environments WHERE project_id = $1 AND deleted_at IS NULL ORDER BY created_at, id",
    [projectId],
  );
  return res.rows as EnvironmentRow[];
}

/**
 * Environment removal (ADR-0025): explicit tombstone deletion. Contract
 * references block loudly (change the Contract first); Grants naming the
 * environment go inert under default-deny; outstanding Capabilities are
 * revoked transactionally. Values are soft-deleted with the environment;
 * encrypted version history stays at rest — no erasure claims.
 */
export async function deleteEnvironment(
  ctx: AppCtx,
  organizationId: string,
  project: ProjectRow,
  env: EnvironmentRow,
  actorIdentityId: string,
): Promise<void> {
  // Active-contract references are checked against the project row's active
  // revision; read-only, so safe outside the deletion transaction.
  const contract = await activeContractOf(ctx, project);
  const referencedBy = (contract?.items ?? []).filter(
    (item) =>
      item.required.kind === "selector" &&
      item.required.selector.kind === "environments" &&
      item.required.selector.environmentIds.includes(env.id),
  );
  if (referencedBy.length > 0) {
    throw new DomainError(
      "VALIDATION_FAILED",
      `The active Contract Revision references this environment (required selector on: ${referencedBy
        .map((i) => i.name)
        .join(", ")}); activate a revision without the reference first`,
      { items: referencedBy.map((i) => i.name) },
    );
  }

  await withTx(ctx.db, async (db) => {
    const mappings = await db.query(
      "SELECT varlock_name FROM varlock_env_mappings WHERE project_id = $1 AND environment_id = $2",
      [project.id, env.id],
    );
    if (mappings.rows.length > 0) {
      const names = (mappings.rows as { varlock_name: string }[]).map((r) => r.varlock_name);
      throw new DomainError(
        "VALIDATION_FAILED",
        `The Varlock Environment Mapping references this environment (${names.join(", ")}); remap or remove the name(s) first`,
        { varlockNames: names },
      );
    }
    const children = await db.query(
      "SELECT name FROM environments WHERE parent_environment_id = $1 AND deleted_at IS NULL",
      [env.id],
    );
    if (children.rows.length > 0) {
      const names = (children.rows as { name: string }[]).map((r) => r.name);
      throw new DomainError(
        "VALIDATION_FAILED",
        `This environment has live derived environments (${names.join(", ")}); delete them first`,
        { children: names },
      );
    }

    const res = await db.query(
      "UPDATE environments SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL RETURNING id",
      [env.id],
    );
    if (res.rows.length === 0) throw notFound("Environment");
    await db.query(
      "UPDATE env_values SET deleted_at = now(), current_version_id = NULL WHERE environment_id = $1 AND deleted_at IS NULL",
      [env.id],
    );
    const revoked = await db.query(
      "UPDATE capabilities SET revoked_at = now() WHERE environment_id = $1 AND revoked_at IS NULL RETURNING id",
      [env.id],
    );
    await recordAuditEvent(db, {
      eventType: "environment.deleted",
      decision: "info",
      actorIdentityId,
      organizationId,
      resource: { projectId: project.id, environmentId: env.id, environmentName: env.name },
      metadata: {
        kind: env.kind,
        tier: env.tier,
        derived: env.parent_environment_id !== null,
        expired: isExpired(env),
        capabilitiesRevoked: revoked.rows.length,
      },
    });
  });
}

/** Expiry is evaluated synchronously against authoritative time (ADR-0020). */
export function isExpired(env: EnvironmentRow, now = new Date()): boolean {
  return env.expires_at !== null && new Date(env.expires_at).getTime() <= now.getTime();
}

/** Root identity for selector/contract evaluation (itself for roots). */
export function rootIdOf(env: EnvironmentRow): string {
  return env.parent_environment_id ?? env.id;
}
