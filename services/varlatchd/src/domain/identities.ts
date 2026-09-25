// SPDX-License-Identifier: AGPL-3.0-or-later
import { recordAuditEvent } from "../audit/events.js";
import {
  type CredentialKind,
  issueCredential,
  revokeCredential,
  type IdentityRow,
} from "../auth/credentials.js";
import { newId } from "../db/ids.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";

export type MachineKind = "service" | "workload" | "ci" | "broker" | "agent";

/**
 * Machine identities belong to exactly one organization and start with zero
 * Grants (ADR-0015 §9). Service/workload identities receive an opaque
 * credential exactly once at creation. Agents get none by default (ADR-0022
 * §8): the agent-safe flow never hands the child a reusable /v1 credential —
 * the Agent Identity exists to own Grants that Capability exercises evaluate.
 */
export async function createMachineIdentity(
  ctx: AppCtx,
  organizationId: string,
  input: {
    name: string;
    kind: MachineKind;
    credentialTtlSeconds?: number | undefined;
    credentialMaxUses?: number | undefined;
  },
  actorIdentityId: string,
): Promise<{
  identity: IdentityRow;
  credential: string | null;
  credentialExpiresAt: string | null;
}> {
  if (!input.name || input.name.length > 200) {
    throw new DomainError("VALIDATION_FAILED", "Invalid identity name");
  }
  return withTx(ctx.db, async (db) => {
    const id = newId("identity");
    await db.query(
      "INSERT INTO identities (id, kind, name, organization_id) VALUES ($1,$2,$3,$4)",
      [id, input.kind, input.name, organizationId],
    );
    await recordAuditEvent(db, {
      eventType: "identity.created",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "identity.manage",
      resource: { identityId: id },
      metadata: { kind: input.kind },
    });
    let credential: string | null = null;
    let credentialExpiresAt: string | null = null;
    // CI identities are expected to federate (ADR-0007); no static token by default.
    if (input.kind === "service" || input.kind === "workload" || input.kind === "broker") {
      if (input.credentialTtlSeconds) {
        credentialExpiresAt = new Date(
          Date.now() + input.credentialTtlSeconds * 1000,
        ).toISOString();
      }
      const issued = await issueCredential(db, {
        identityId: id,
        kind: "service",
        name: `${input.name} credential`,
        expiresAt: credentialExpiresAt ?? undefined,
        maxUses: input.credentialMaxUses,
        actorIdentityId,
      });
      credential = issued.token;
    }
    return {
      identity: {
        id,
        kind: input.kind,
        name: input.name,
        disabled: false,
        installation_admin: false,
        organization_id: organizationId,
      },
      credential,
      credentialExpiresAt,
    };
  });
}

export interface CredentialMetadataRow {
  id: string;
  kind: CredentialKind;
  name: string | null;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
}

/**
 * Machine identity lifecycle (ADR-0034). Metadata only — token material is
 * unrecoverable by construction (ADR-0007) and never appears here.
 */
export async function listIdentityCredentials(
  ctx: AppCtx,
  identityId: string,
): Promise<CredentialMetadataRow[]> {
  const res = await ctx.db.query(
    `SELECT id, kind, name, created_at, expires_at, revoked_at, last_used_at
     FROM credentials WHERE identity_id = $1 ORDER BY created_at DESC, id`,
    [identityId],
  );
  return res.rows as CredentialMetadataRow[];
}

/**
 * Retire = disable the identity AND revoke every unrevoked credential in one
 * transaction (ADR-0034 §3). Disabling alone would be a trap: `disabled` is
 * reversible, so a later reactivation would silently resurrect every
 * credential minted before retirement.
 */
export async function retireIdentity(
  ctx: AppCtx,
  organizationId: string,
  identityId: string,
  actorIdentityId: string,
): Promise<void> {
  await withTx(ctx.db, async (db) => {
    await db.query("UPDATE identities SET disabled = true WHERE id = $1", [identityId]);
    const live = await db.query(
      "SELECT id FROM credentials WHERE identity_id = $1 AND revoked_at IS NULL ORDER BY created_at, id",
      [identityId],
    );
    // Bulk revocation goes through the single revocation primitive so every
    // credential gets its own credential.revoked audit line.
    for (const row of live.rows as { id: string }[]) {
      await revokeCredential(db, row.id, actorIdentityId, { organizationId });
    }
    await recordAuditEvent(db, {
      eventType: "identity.retired",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "identity.manage",
      resource: { identityId },
      metadata: { revokedCredentials: live.rows.length },
    });
  });
}

/**
 * Reactivation clears the flag only: a reactivated identity has zero working
 * credentials until an admin deliberately issues one (ADR-0034 §3).
 */
export async function reactivateIdentity(
  ctx: AppCtx,
  organizationId: string,
  identityId: string,
  actorIdentityId: string,
): Promise<void> {
  await withTx(ctx.db, async (db) => {
    await db.query("UPDATE identities SET disabled = false WHERE id = $1", [identityId]);
    await recordAuditEvent(db, {
      eventType: "identity.reactivated",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "identity.manage",
      resource: { identityId },
    });
  });
}

/**
 * Rename is display-plane only — grants, credentials, OIDC bindings, and
 * tailnet requirements reference the idn_ id. The audit event carries both
 * names so historical audit lines stay interpretable (ADR-0034 §4).
 */
export async function renameIdentity(
  ctx: AppCtx,
  organizationId: string,
  identityId: string,
  name: string,
  actorIdentityId: string,
): Promise<void> {
  if (!name || name.length > 200) {
    throw new DomainError("VALIDATION_FAILED", "Invalid identity name");
  }
  await withTx(ctx.db, async (db) => {
    const prev = await db.query("SELECT name FROM identities WHERE id = $1", [identityId]);
    const previous = (prev.rows[0] as { name: string } | undefined)?.name;
    await db.query("UPDATE identities SET name = $1 WHERE id = $2", [name, identityId]);
    await recordAuditEvent(db, {
      eventType: "identity.renamed",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "identity.manage",
      resource: { identityId },
      metadata: { previousName: previous ?? null, name },
    });
  });
}

export async function listOrgIdentities(
  ctx: AppCtx,
  organizationId: string,
): Promise<
  (IdentityRow & {
    last_seen_at: string | null;
    org_role: string | null;
    email: string | null;
    image: string | null;
  })[]
> {
  // Humans enrolled through Better Auth carry an email and optional avatar
  // image via auth_user_links; machines (and unlinked humans) yield nulls.
  const res = await ctx.db.query(
    `SELECT i.id, i.kind, i.name, i.disabled, i.installation_admin, i.organization_id,
            i.last_seen_at, m.role AS org_role, u."email" AS email, u."image" AS image
     FROM identities i
     LEFT JOIN org_memberships m
       ON m.identity_id = i.id AND m.organization_id = $1
     LEFT JOIN auth_user_links l ON l.identity_id = i.id
     LEFT JOIN "user" u ON u.id = l.better_auth_user_id
     WHERE i.organization_id = $1 OR m.identity_id IS NOT NULL
     ORDER BY i.created_at, i.id`,
    [organizationId],
  );
  return res.rows as (IdentityRow & {
    last_seen_at: string | null;
    org_role: string | null;
    email: string | null;
    image: string | null;
  })[];
}
