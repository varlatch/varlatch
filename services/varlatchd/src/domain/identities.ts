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
import { lockLiveScope } from "./liveness.js";
import { lockedQuery } from "../db/locks.js";
import type { Querier } from "../db/migrate.js";
import type { ProtectedGate } from "./approvals.js";
import { approvalMetadata, prepareProtectedOperation, type PreparedOperation } from "./protected.js";
import {
  credentialIssueBinding,
  identityCreateBinding,
  identityReactivateBinding,
  readMachineIdentity,
} from "./identitystepup.js";

export type MachineKind = "service" | "workload" | "ci" | "broker" | "agent";

/**
 * The machine kinds that hold service credentials: the ones creation issues
 * one for. CI identities federate instead (ADR-0007) and Agents never hold a
 * reusable credential (ADR-0022 §8), so neither is ever issued one.
 */
export const SERVICE_CREDENTIAL_KINDS: ReadonlySet<string> = new Set<MachineKind>(["service", "workload", "broker"]);

/**
 * What a machine credential issued now expires at: `ttlSeconds` from now,
 * or never (revocation only) without one.
 */
function expiryOf(ttlSeconds: number | undefined): string | null {
  return ttlSeconds ? new Date(Date.now() + ttlSeconds * 1000).toISOString() : null;
}

/** Audit metadata for a credential whose lifetime credential-lifetime chose (the request gave none). */
const lifetimeMetadata = (prepared: PreparedOperation) => (prepared.ttlDefaulted ? { lifetimeDefaulted: true } : {});

/**
 * What a protected operation here takes besides its input: the requester's
 * authorization, rechecked in the operation's transaction once an approval
 * was consumed ("the person still holds the action", ADR-0054 Decision 3).
 */
export interface ProtectedOptions {
  authorizeIn?: ((db: Querier) => Promise<void>) | undefined;
}

/**
 * Machine identities belong to exactly one organization and start with zero
 * Grants (ADR-0015 §9). Service/workload identities receive an opaque
 * credential exactly once at creation. Agents get none by default (ADR-0022
 * §8): the agent-safe flow never hands the child a reusable /v1 credential —
 * the Agent Identity exists to own Grants that Capability exercises evaluate.
 *
 * A protected operation (ADR-0054): admin-step-up's identity.create, and
 * credential-lifetime's when a credential is issued. Under
 * credential-lifetime at enforce, the credential gets the Organization's
 * default lifetime when none was asked for, and one above its maximum is
 * refused before anything is created (prepareProtectedOperation). Under
 * admin-step-up at enforce, it needs the requester's approval, bound to the
 * Organization and the request with the lifetime credential-lifetime
 * decided (identitystepup.ts); one approval covers both controls.
 */
export async function createMachineIdentity(
  ctx: AppCtx,
  gate: ProtectedGate,
  organizationId: string,
  input: {
    name: string;
    kind: MachineKind;
    credentialTtlSeconds?: number | undefined;
    credentialMaxUses?: number | undefined;
  },
  options: ProtectedOptions = {},
): Promise<{
  identity: IdentityRow;
  credential: string | null;
  credentialExpiresAt: string | null;
}> {
  if (!input.name || input.name.length > 200) {
    throw new DomainError("VALIDATION_FAILED", "Invalid identity name");
  }
  const actorIdentityId = gate.requester.identityId;
  const issues = SERVICE_CREDENTIAL_KINDS.has(input.kind);
  return withTx(ctx.db, async (db) => {
    const prepared = await prepareProtectedOperation(db, gate, {
      scope: { organizationId, people: [actorIdentityId] },
      checks: [
        { control: "admin-step-up", operation: "identity.create" },
        // ci and agent identities get no credential: nothing to bound.
        ...(issues
          ? [{ control: "credential-lifetime" as const, operation: "identity.create" as const, ttlSeconds: input.credentialTtlSeconds }]
          : []),
      ],
      binding: async (_db, decided) => identityCreateBinding({ id: organizationId }, input, issues, decided.effectiveTtlSeconds),
      authorizeIn: options.authorizeIn,
    });
    const id = newId("identity");
    await db.query(
      "INSERT INTO identities (id, kind, name, organization_id) VALUES ($1,$2,$3,$4)",
      [id, input.kind, input.name, organizationId],
    );
    // Report mode (ADR-0054 Decision 9), before the first audit insert:
    // admin-step-up, and credential-lifetime when a credential is issued.
    await prepared.count(db);
    await recordAuditEvent(db, {
      eventType: "identity.created",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "identity.manage",
      resource: { identityId: id },
      metadata: { kind: input.kind, ...approvalMetadata(prepared.approval) },
    });
    let credential: string | null = null;
    let credentialExpiresAt: string | null = null;
    // CI identities are expected to federate (ADR-0007); no static token by default.
    if (issues) {
      credentialExpiresAt = expiryOf(prepared.effectiveTtlSeconds);
      const issued = await issueCredential(db, {
        identityId: id,
        kind: "service",
        name: `${input.name} credential`,
        expiresAt: credentialExpiresAt ?? undefined,
        maxUses: input.credentialMaxUses,
        actorIdentityId,
        organizationId,
        // The approval that covered the creation covers its first
        // credential too: recorded on both events, as credential.issue does.
        metadata: { ...lifetimeMetadata(prepared), ...approvalMetadata(prepared.approval) },
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

/**
 * Issue another service credential for an existing machine identity
 * (capability identity.credentials.issue). It is the deliberate issuance a
 * reactivated identity waits for (ADR-0034 §3), the new half of a rotation
 * (mint new, then revoke old), and how several programs sharing one
 * identity's Grants each get a named, separately revocable credential.
 * Limits and default as at creation: no TTL means no expiry (revocation
 * only), unless the Organization enforces credential-lifetime, whose default
 * then applies; a TTL above its maximum is refused before anything else
 * here (prepareProtectedOperation). The route answers not-found for an
 * unknown identity first; a direct caller gets the TTL refusal, which says
 * nothing about the identity.
 */
export async function issueMachineCredential(
  ctx: AppCtx,
  gate: ProtectedGate,
  organizationId: string,
  identityId: string,
  input: { name: string; ttlSeconds?: number | undefined; maxUses?: number | undefined },
  options: ProtectedOptions = {},
): Promise<{ credentialId: string; token: string; expiresAt: string | null; maxUses: number | null }> {
  if (!input.name || input.name.length > 200) {
    throw new DomainError("VALIDATION_FAILED", "Invalid credential name");
  }
  const actorIdentityId = gate.requester.identityId;
  return withTx(ctx.db, async (db) => {
    const prepared = await prepareProtectedOperation(db, gate, {
      scope: { organizationId, people: [actorIdentityId, { id: identityId, mode: "share" }] },
      checks: [
        { control: "admin-step-up", operation: "credential.issue" },
        { control: "credential-lifetime", operation: "credential.issue", ttlSeconds: input.ttlSeconds },
      ],
      binding: async (db, decided) => {
        // Refusals first (amendment A), read without a lock: the identity
        // is checked again, live and of a service kind, FOR SHARE below.
        const identity = await readMachineIdentity(db, organizationId, identityId);
        if (!identity || !SERVICE_CREDENTIAL_KINDS.has(identity.kind) || identity.disabled) {
          throw new DomainError("RESOURCE_NOT_FOUND", "Not found");
        }
        return credentialIssueBinding({ id: organizationId }, identity, input, decided.effectiveTtlSeconds);
      },
      authorizeIn: options.authorizeIn,
    });
    // FOR SHARE serializes with retire's UPDATE: a retirement committed first
    // is seen here, and one committing after this issuance revokes the new
    // credential with the rest, so a reactivation never resurrects it.
    const res = await lockedQuery(
      db,
      { table: "identities", mode: "share", key: "$1" },
      "SELECT kind, disabled FROM identities WHERE id = $1 AND organization_id = $2 FOR SHARE",
      [identityId, organizationId],
    );
    const row = res.rows[0] as { kind: string; disabled: boolean } | undefined;
    if (!row || !SERVICE_CREDENTIAL_KINDS.has(row.kind) || row.disabled) {
      throw new DomainError("RESOURCE_NOT_FOUND", "Not found");
    }
    const expiresAt = expiryOf(prepared.effectiveTtlSeconds);
    const maxUses = input.maxUses ?? null;
    // Report mode (ADR-0054 Decision 9), before issueCredential's audit insert.
    await prepared.count(db);
    const issued = await issueCredential(db, {
      identityId,
      kind: "service",
      name: input.name,
      expiresAt: expiresAt ?? undefined,
      maxUses: maxUses ?? undefined,
      actorIdentityId,
      organizationId,
      // Identifiers only (ADR-0016 §8); null records "no expiry" and "unlimited".
      metadata: { name: input.name, expiresAt, maxUses, ...lifetimeMetadata(prepared), ...approvalMetadata(prepared.approval) },
    });
    return { credentialId: issued.credentialId, token: issued.token, expiresAt, maxUses };
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
  client: string | null;
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
    `SELECT id, kind, name, created_at, expires_at, revoked_at, last_used_at, client
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
    await lockLiveScope(db, { organizationId, duringIncidentFreeze: "recovery", people: [actorIdentityId, { id: identityId, mode: "update" }] });
    await db.query("UPDATE identities SET disabled = true WHERE id = $1", [identityId]);
    // Step 7 (liveness.ts): every live credential, in id order, in the
    // mode its revocation takes, before the first revocation's audit
    // event. They are revoked, and audited, in their usual order.
    await lockedQuery(
      db,
      { table: "credentials", mode: "no key update" },
      "SELECT id FROM credentials WHERE identity_id = $1 AND revoked_at IS NULL ORDER BY id FOR NO KEY UPDATE",
      [identityId],
    );
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

const suspendedByDeletion = () =>
  new DomainError("ORGANIZATION_DELETING", "This identity was suspended by the Organization's deletion; cancelling the deletion restores it");

/**
 * Reactivation clears the flag only: a reactivated identity has zero working
 * credentials until an admin deliberately issues one (ADR-0034 §3).
 *
 * A protected operation (ADR-0054): admin-step-up's identity.reactivate.
 * Under enforce, reactivating a disabled identity needs the requester's
 * approval, bound to the identity (identitystepup.ts). Reactivating an
 * enabled one changes nothing and needs none; an identity suspended by a
 * deletion is refused before any approval is asked for. Both are decided
 * again under the identity's row lock: an identity retired between the
 * unlocked read and the lock is refused (STATE_CHANGED), never reactivated
 * without the approval it then needs.
 */
export async function reactivateIdentity(
  ctx: AppCtx,
  gate: ProtectedGate,
  organizationId: string,
  identityId: string,
  options: ProtectedOptions = {},
): Promise<void> {
  const actorIdentityId = gate.requester.identityId;
  await withTx(ctx.db, async (db) => {
    let boundEnabled = false;
    const prepared = await prepareProtectedOperation(db, gate, {
      scope: { organizationId, people: [actorIdentityId, { id: identityId, mode: "update" }] },
      checks: [{ control: "admin-step-up", operation: "identity.reactivate" }],
      binding: async (db) => {
        const identity = await readMachineIdentity(db, organizationId, identityId);
        if (!identity) throw new DomainError("RESOURCE_NOT_FOUND", "Not found");
        if (identity.suspendedByDeletion) throw suspendedByDeletion();
        if (!identity.disabled) {
          boundEnabled = true;
          return null;
        }
        return identityReactivateBinding({ id: organizationId }, identity);
      },
      authorizeIn: options.authorizeIn,
    });
    // An identity suspended by a deletion request comes back only through
    // that request's cancellation (ADR-0051 Decision 5).
    const suspended = await lockedQuery(db, { table: "identities", mode: "update", key: "$1" }, "SELECT suspended_by_deletion, disabled FROM identities WHERE id = $1 FOR UPDATE", [identityId]);
    const before = suspended.rows[0] as { suspended_by_deletion: string | null; disabled: boolean } | undefined;
    if (before?.suspended_by_deletion) throw suspendedByDeletion();
    // Enabled when the approval was decided, disabled now (retired since):
    // this reactivation would need an approval it was not asked for.
    if (boundEnabled && before?.disabled) {
      throw new DomainError("STATE_CHANGED", "The identity was retired while it was being reactivated; nothing changed. Reactivate it again");
    }
    await db.query("UPDATE identities SET disabled = false WHERE id = $1", [identityId]);
    // Report mode counts only a reactivation of a disabled identity; an enabled one stays as it was.
    if (before?.disabled) await prepared.count(db);
    await recordAuditEvent(db, {
      eventType: "identity.reactivated",
      decision: "info",
      actorIdentityId,
      organizationId,
      action: "identity.manage",
      resource: { identityId },
      ...(prepared.approval ? { metadata: approvalMetadata(prepared.approval) } : {}),
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
    await lockLiveScope(db, { organizationId, people: [actorIdentityId, { id: identityId, mode: "update" }] });
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
    removed_at: string | null;
    email: string | null;
    image: string | null;
  })[]
> {
  // Humans enrolled through Better Auth carry an email and optional avatar
  // image via auth_user_links; machines (and unlinked humans) yield nulls.
  // Former members stay listed, with removed_at, so history keeps their
  // names (ADR-0052 Decision 1).
  const res = await ctx.db.query(
    `SELECT i.id, i.kind, i.name, i.disabled, i.installation_admin, i.organization_id,
            i.last_seen_at, m.role AS org_role, m.removed_at, u."email" AS email, u."image" AS image
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
    removed_at: string | null;
    email: string | null;
    image: string | null;
  })[];
}
