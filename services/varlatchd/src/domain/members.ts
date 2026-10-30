// SPDX-License-Identifier: AGPL-3.0-or-later
import { recordAuditEvent } from "../audit/events.js";
import { indexIntegration } from "../audit/exposure.js";
import {
  evaluate,
  requirementsCovering,
  type Action,
  type OrgRole,
  type ResourceContext,
} from "../authz/evaluate.js";
import { newId } from "../db/ids.js";
import type { Querier } from "../db/migrate.js";
import { withSerializableTx, withSnapshot } from "../db/tx.js";
import { loadGrants, loadTailnetRequirements } from "../http/support.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";
import { lockLiveScope } from "./liveness.js";

/**
 * Removing a person from an Organization, a member leaving, and role
 * changes (ADR-0052 Decisions 1 to 5). Each runs as one SERIALIZABLE
 * transaction (withSerializableTx), so its authority checks, the last-admin
 * rule and the authority snapshot all read one state, and a concurrent
 * policy change is ordered before or after it, or one of the two retries.
 * Audit events are appended last, after every read and change, to keep the
 * audit counter's hold short.
 */

/** The value actions the authority snapshot records, per environment. */
export const SNAPSHOT_ACTIONS = [
  "config.metadata.read",
  "config.value.read",
  "secret.reveal",
  "secret.use",
] as const satisfies readonly Action[];

/** The snapshot actions Tailnet Requirements constrain. */
const CONDITIONED_ACTIONS: ReadonlySet<string> = new Set(["config.value.read", "secret.reveal", "secret.use"]);

export interface Actor {
  id: string;
  kind: string;
}

export type CredentialState = "valid" | "expired" | "exhausted" | "revoked" | "retired";

/**
 * What a person set up that may keep working without them (ADR-0052
 * Decision 4). Removal changes none of it; the list says what to review.
 */
export interface MemberReview {
  syncTargets: {
    id: string;
    projectId: string;
    environmentId: string;
    platform: string;
    state: "active" | "paused" | "disabled" | "revoked";
    changes: string[];
  }[];
  connections: {
    id: string;
    name: string;
    platform: string;
    credentialKind: string;
    revoked: boolean;
    changes: string[];
  }[];
  webhooks: { id: string; host: string; revoked: boolean }[];
  oidcBindings: { id: string; identityId: string; identityName: string; issuer: string; revoked: boolean }[];
  credentials: {
    id: string;
    name: string | null;
    identityId: string;
    identityName: string;
    state: CredentialState;
  }[];
  personalEnvironments: { id: string; name: string; projectId: string }[];
}

export interface RemovalResult {
  removalId: string;
  identityId: string;
  role: OrgRole;
  left: boolean;
  removedAt: string;
  grantsRevoked: number;
  groupsLeft: number;
  invitationsRevoked: number;
  review: MemberReview;
}

interface MembershipRow {
  role: OrgRole;
}

async function liveMembership(db: Querier, organizationId: string, identityId: string): Promise<MembershipRow | null> {
  const res = await db.query(
    "SELECT role FROM org_memberships WHERE organization_id = $1 AND identity_id = $2 AND removed_at IS NULL",
    [organizationId, identityId],
  );
  return (res.rows[0] as MembershipRow | undefined) ?? null;
}

/**
 * The shared Organization lock of ADR-0051's writer protocol. It is
 * compatible with the key-share lock an invitation acceptance's membership
 * insert takes, so the two never deadlock; Organization deletion's
 * exclusive lock excludes it.
 */
async function lockOrganization(db: Querier, organizationId: string): Promise<void> {
  // The writer protocol's Organization lock and liveness, freeze included
  // (ADR-0051): no membership changes while the Organization is being deleted.
  await lockLiveScope(db, { organizationId });
}

/**
 * Removal, demotion and promotion need a live built-in admin membership; an
 * explicit Grant does not substitute (ADR-0052 Decision 2).
 */
async function requireLiveAdmin(db: Querier, organizationId: string, actor: Actor): Promise<void> {
  const membership = actor.kind === "human" ? await liveMembership(db, organizationId, actor.id) : null;
  if (membership?.role !== "admin") {
    throw new DomainError("PERMISSION_DENIED", "Only an Organization Admin can remove members or change their role");
  }
}

/** The last admin can neither be removed, nor leave, nor be demoted. */
async function requireAnotherAdmin(db: Querier, organizationId: string, identityId: string): Promise<void> {
  const res = await db.query(
    `SELECT count(*)::int AS n FROM org_memberships m JOIN identities i ON i.id = m.identity_id
     WHERE m.organization_id = $1 AND m.role = 'admin' AND m.removed_at IS NULL
       AND m.identity_id <> $2 AND NOT i.disabled`,
    [organizationId, identityId],
  );
  if ((res.rows[0] as { n: number }).n === 0) {
    throw new DomainError(
      "VALIDATION_FAILED",
      "This is the Organization's last admin. Make another member an admin first.",
      { reason: "last-admin" },
    );
  }
}

/**
 * Records what the person could reach (ADR-0052 Decision 5), before
 * anything is cleaned up: per environment, the value actions their built-in
 * role and Grants granted and where each came from, and copies of the
 * Tailnet Requirements those actions were conditional on. Requirements are
 * never evaluated here: there is no request, so no device to decide them
 * against.
 */
async function captureAuthority(
  ctx: AppCtx,
  db: Querier,
  organizationId: string,
  removalId: string,
  identityId: string,
  role: OrgRole,
): Promise<void> {
  const scoped = { ...ctx, db };
  const grants = await loadGrants(scoped, organizationId, identityId);
  const requirements = await loadTailnetRequirements(scoped, organizationId);
  const envs = await db.query(
    `SELECT e.id, e.project_id, e.tier, e.parent_environment_id FROM environments e
     JOIN projects p ON p.id = e.project_id
     WHERE p.organization_id = $1 AND e.deleted_at IS NULL ORDER BY e.id`,
    [organizationId],
  );
  const authority = {
    env: [] as string[],
    action: [] as string[],
    source: [] as string[],
    role: [] as (string | null)[],
    grant: [] as (string | null)[],
    group: [] as (string | null)[],
    roleId: [] as (string | null)[],
  };
  const conditions = { env: [] as string[], requirement: [] as string[] };
  const copied = new Map<string, (typeof requirements)[number]>();
  for (const e of envs.rows as { id: string; project_id: string; tier: "development" | "staging" | "production"; parent_environment_id: string | null }[]) {
    const resource: ResourceContext = {
      organizationId,
      projectId: e.project_id,
      environment: { id: e.id, rootId: e.parent_environment_id ?? e.id, tier: e.tier },
    };
    let conditioned = false;
    for (const action of SNAPSHOT_ACTIONS) {
      const result = evaluate({ action, resource, orgRole: role, grants, requirements: [], tailnetContext: null });
      if (!result.allowed) continue;
      if (CONDITIONED_ACTIONS.has(action)) conditioned = true;
      const push = (source: string, r: string | null, grant: string | null, group: string | null, roleId: string | null) => {
        authority.env.push(e.id);
        authority.action.push(action);
        authority.source.push(source);
        authority.role.push(r);
        authority.grant.push(grant);
        authority.group.push(group);
        authority.roleId.push(roleId);
      };
      if (result.provenance.role) push(`role:${result.provenance.role}`, result.provenance.role, null, null, null);
      for (const g of result.provenance.applied ?? []) {
        push(`grant:${g.grantId}`, null, g.grantId, g.viaGroupId ?? null, g.roleId ?? null);
      }
    }
    if (!conditioned) continue;
    for (const r of requirementsCovering(requirements, resource)) {
      copied.set(r.id, r);
      conditions.env.push(e.id);
      conditions.requirement.push(r.id);
    }
  }
  if (authority.env.length > 0) {
    await db.query(
      `INSERT INTO removal_authority (removal_id, environment_id, action, source, role, grant_id, via_group_id, role_id)
       SELECT $1::text, u.* FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[]) AS u`,
      [removalId, authority.env, authority.action, authority.source, authority.role, authority.grant, authority.group, authority.roleId],
    );
  }
  if (copied.size > 0) {
    const reqs = [...copied.values()];
    await db.query(
      `INSERT INTO removal_requirements (removal_id, requirement_id, requirement_version, target, selector)
       SELECT $1::text, u.* FROM unnest($2::text[], $3::int[], $4::jsonb[], $5::jsonb[]) AS u`,
      [
        removalId,
        reqs.map((r) => r.id),
        reqs.map((r) => r.version ?? null),
        reqs.map((r) => JSON.stringify(r.target)),
        reqs.map((r) => JSON.stringify(r.selector)),
      ],
    );
    await db.query(
      `INSERT INTO removal_conditions (removal_id, environment_id, requirement_id)
       SELECT $1::text, u.* FROM unnest($2::text[], $3::text[]) AS u`,
      [removalId, conditions.env, conditions.requirement],
    );
  }
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}

/**
 * What the person created or changed that may still work without them
 * (ADR-0052 Decision 4): from creators recorded on each row and from the
 * integration index. Names and states only.
 */
export async function memberReview(db: Querier, organizationId: string, identityId: string): Promise<MemberReview> {
  const targets = await db.query(
    `SELECT t.id, t.project_id, t.environment_id, c.platform, t.state, t.revoked_at,
            CASE WHEN t.created_by = $2 THEN ARRAY['created'] ELSE ARRAY[]::text[] END
              || COALESCE(mi.changes, ARRAY[]::text[]) AS changes
     FROM sync_targets t
     JOIN platform_connections c ON c.id = t.connection_id
     LEFT JOIN member_integrations mi
       ON mi.organization_id = t.organization_id AND mi.identity_id = $2 AND mi.kind = 'target' AND mi.resource_id = t.id
     WHERE t.organization_id = $1 AND (t.created_by = $2 OR mi.resource_id IS NOT NULL)
     ORDER BY t.created_at, t.id`,
    [organizationId, identityId],
  );
  const connections = await db.query(
    `SELECT c.id, c.name, c.platform, c.credential_kind, c.revoked_at,
            CASE WHEN c.created_by = $2 THEN ARRAY['created'] ELSE ARRAY[]::text[] END
              || COALESCE(mi.changes, ARRAY[]::text[]) AS changes
     FROM platform_connections c
     LEFT JOIN member_integrations mi
       ON mi.organization_id = c.organization_id AND mi.identity_id = $2 AND mi.kind = 'connection' AND mi.resource_id = c.id
     WHERE c.organization_id = $1 AND (c.created_by = $2 OR mi.resource_id IS NOT NULL)
     ORDER BY c.created_at, c.id`,
    [organizationId, identityId],
  );
  const webhooks = await db.query(
    "SELECT id, url, revoked_at FROM webhooks WHERE organization_id = $1 AND created_by = $2 ORDER BY created_at, id",
    [organizationId, identityId],
  );
  const bindings = await db.query(
    `SELECT b.id, b.identity_id, i.name AS identity_name, b.issuer, b.revoked_at
     FROM oidc_bindings b JOIN identities i ON i.id = b.identity_id
     WHERE b.organization_id = $1 AND b.created_by = $2 ORDER BY b.created_at, b.id`,
    [organizationId, identityId],
  );
  const credentials = await db.query(
    `SELECT c.id, c.name, c.identity_id, i.name AS identity_name,
            CASE
              WHEN c.revoked_at IS NOT NULL THEN 'revoked'
              WHEN i.disabled THEN 'retired'
              WHEN c.expires_at IS NOT NULL AND c.expires_at <= now() THEN 'expired'
              WHEN c.max_uses IS NOT NULL AND c.use_count >= c.max_uses THEN 'exhausted'
              ELSE 'valid'
            END AS state
     FROM credentials c JOIN identities i ON i.id = c.identity_id
     WHERE c.issued_by = $2 AND i.kind <> 'human' AND i.organization_id = $1
     ORDER BY c.created_at, c.id`,
    [organizationId, identityId],
  );
  const personal = await db.query(
    `SELECT e.id, e.name, e.project_id FROM environments e JOIN projects p ON p.id = e.project_id
     WHERE p.organization_id = $1 AND e.kind = 'personal' AND e.owner_identity_id = $2 AND e.deleted_at IS NULL
     ORDER BY e.created_at, e.id`,
    [organizationId, identityId],
  );
  const unique = (xs: string[]) => [...new Set(xs)];
  return {
    syncTargets: (targets.rows as Record<string, unknown>[]).map((r) => ({
      id: r.id as string,
      projectId: r.project_id as string,
      environmentId: r.environment_id as string,
      platform: r.platform as string,
      state: r.revoked_at ? "revoked" : (r.state as "active" | "paused" | "disabled"),
      changes: unique(r.changes as string[]),
    })),
    connections: (connections.rows as Record<string, unknown>[]).map((r) => ({
      id: r.id as string,
      name: r.name as string,
      platform: r.platform as string,
      credentialKind: r.credential_kind as string,
      revoked: r.revoked_at !== null,
      changes: unique(r.changes as string[]),
    })),
    webhooks: (webhooks.rows as { id: string; url: string; revoked_at: string | null }[]).map((r) => ({
      id: r.id,
      host: hostOf(r.url),
      revoked: r.revoked_at !== null,
    })),
    oidcBindings: (bindings.rows as Record<string, unknown>[]).map((r) => ({
      id: r.id as string,
      identityId: r.identity_id as string,
      identityName: r.identity_name as string,
      issuer: r.issuer as string,
      revoked: r.revoked_at !== null,
    })),
    credentials: (credentials.rows as Record<string, unknown>[]).map((r) => ({
      id: r.id as string,
      name: (r.name as string | null) ?? null,
      identityId: r.identity_id as string,
      identityName: r.identity_name as string,
      state: r.state as CredentialState,
    })),
    personalEnvironments: (personal.rows as { id: string; name: string; project_id: string }[]).map((r) => ({
      id: r.id,
      name: r.name,
      projectId: r.project_id,
    })),
  };
}

/**
 * The review list before a removal or a leave, for the confirmation
 * dialog: for a live admin about any live member, and for a member about
 * themselves.
 */
export async function previewMemberReview(
  ctx: AppCtx,
  organizationId: string,
  identityId: string,
  actor: Actor,
): Promise<MemberReview> {
  return withSnapshot(ctx.db, async (db) => {
    if (actor.id !== identityId) await requireLiveAdmin(db, organizationId, actor);
    if (!(await liveMembership(db, organizationId, identityId))) {
      throw new DomainError("RESOURCE_NOT_FOUND", "Member not found");
    }
    return memberReview(db, organizationId, identityId);
  });
}

/**
 * Removes a person from the Organization, or lets a member leave when the
 * actor is the person (ADR-0052 Decision 2): the authority snapshot first,
 * then removed_at on the membership, their direct Grants revoked, their
 * group and team links removed and the pending invitations they issued
 * revoked, then one membership.removed event. Their sign-in and
 * credentials are untouched; from the next request they reach nothing here.
 */
export async function removeMember(
  ctx: AppCtx,
  organizationId: string,
  identityId: string,
  actor: Actor,
): Promise<RemovalResult> {
  const left = actor.id === identityId;
  return withSerializableTx(ctx.db, async (db) => {
    await lockOrganization(db, organizationId);
    if (!left) await requireLiveAdmin(db, organizationId, actor);
    const membership = await liveMembership(db, organizationId, identityId);
    if (!membership) throw new DomainError("RESOURCE_NOT_FOUND", "Member not found");
    if (membership.role === "admin") await requireAnotherAdmin(db, organizationId, identityId);

    const ended = await endMembership(ctx, db, organizationId, identityId, membership.role, actor.id);
    const { removalId, removedAt, grants, groups, invitations } = ended;
    const review = await memberReview(db, organizationId, identityId);

    await recordAuditEvent(db, {
      eventType: "membership.removed",
      decision: "info",
      actorIdentityId: actor.id,
      organizationId,
      action: left ? null : "identity.manage",
      resource: { identityId, removalId },
      metadata: {
        role: membership.role,
        left,
        grantsRevoked: grants,
        groupsLeft: groups,
        invitationsRevoked: invitations,
      },
    });
    return {
      removalId,
      identityId,
      role: membership.role,
      left,
      removedAt,
      grantsRevoked: grants,
      groupsLeft: groups,
      invitationsRevoked: invitations,
      review,
    };
  });
}

/**
 * Ends a live membership inside the caller's transaction, without its
 * audit event (the caller appends it last): records the authority
 * snapshot first, then sets removed_at, revokes the person's direct
 * Grants, removes their group and team links and revokes the invitations
 * they issued that are still pending. Removal and leaving call it after
 * their checks; Organization deletion's finalization calls it for every
 * member, without the actor check and the last-admin rule, because the
 * Organization itself is going (ADR-0051 Decision 6).
 */
export async function endMembership(
  ctx: AppCtx,
  db: Querier,
  organizationId: string,
  identityId: string,
  role: OrgRole,
  actorId: string,
): Promise<{ removalId: string; removedAt: string; grants: number; groups: number; invitations: number }> {
  const removalId = newId("membershipRemoval");
  const inserted = await db.query(
    `INSERT INTO membership_removals (id, organization_id, identity_id, role, actor_identity_id)
     VALUES ($1,$2,$3,$4,$5) RETURNING removed_at`,
    [removalId, organizationId, identityId, role, actorId],
  );
  const removedAt = (inserted.rows[0] as { removed_at: Date | string }).removed_at;
  await captureAuthority(ctx, db, organizationId, removalId, identityId, role);
  // now() is the transaction's time, the same as the removal record's.
  await db.query(
    `UPDATE org_memberships SET removed_at = now(), version = version + 1
     WHERE organization_id = $1 AND identity_id = $2`,
    [organizationId, identityId],
  );
  const grants = await db.query(
    `UPDATE grants SET revoked_at = now()
     WHERE organization_id = $1 AND subject_identity_id = $2 AND revoked_at IS NULL RETURNING id`,
    [organizationId, identityId],
  );
  const groups = await db.query(
    `DELETE FROM group_members gm USING groups g
     WHERE g.id = gm.group_id AND g.organization_id = $1 AND gm.identity_id = $2 RETURNING gm.group_id`,
    [organizationId, identityId],
  );
  const invitations = await db.query(
    `UPDATE setup_grants SET revoked_at = now()
     WHERE kind = 'invite' AND invite_organization_id = $1 AND created_by = $2
       AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > now()
     RETURNING id`,
    [organizationId, identityId],
  );
  return {
    removalId,
    removedAt: new Date(removedAt).toISOString(),
    grants: grants.rows.length,
    groups: groups.rows.length,
    invitations: invitations.rows.length,
  };
}

/**
 * Admin ↔ member (ADR-0052 Decision 3), with removal's permission,
 * transaction and last-admin rule. Demotion removes the built-in admin
 * bundle only: explicit and group Grants stay, since authorization is
 * additive. The same role again changes nothing and records nothing.
 */
export async function changeMemberRole(
  ctx: AppCtx,
  organizationId: string,
  identityId: string,
  role: OrgRole,
  actor: Actor,
): Promise<{ identityId: string; role: OrgRole; previousRole: OrgRole }> {
  return withSerializableTx(ctx.db, async (db) => {
    await lockOrganization(db, organizationId);
    await requireLiveAdmin(db, organizationId, actor);
    const membership = await liveMembership(db, organizationId, identityId);
    if (!membership) throw new DomainError("RESOURCE_NOT_FOUND", "Member not found");
    if (membership.role === role) return { identityId, role, previousRole: role };
    if (membership.role === "admin") await requireAnotherAdmin(db, organizationId, identityId);
    await db.query(
      `UPDATE org_memberships SET role = $3, version = version + 1
       WHERE organization_id = $1 AND identity_id = $2 AND removed_at IS NULL`,
      [organizationId, identityId, role],
    );
    await recordAuditEvent(db, {
      eventType: "membership.role_changed",
      decision: "info",
      actorIdentityId: actor.id,
      organizationId,
      action: "identity.manage",
      resource: { identityId },
      metadata: { previousRole: membership.role, role },
    });
    return { identityId, role, previousRole: membership.role };
  });
}

export type IntegrationChange = "created" | "repointed" | "destination_changed" | "credential_replaced";

/**
 * The integration index (ADR-0052 Decision 6): written in the transaction
 * that changes the Sync Target or Platform Connection, before its audit
 * event. Like the exposure index, it is never written while the
 * transaction holds the audit counter, so a backfill batch holding index
 * rows cannot close a lock cycle through it. The kinds of change
 * accumulate and the first and last times only ever widen.
 */
export async function recordIntegrationChange(
  db: Querier,
  entry: {
    organizationId: string;
    identityId: string;
    kind: "target" | "connection";
    resourceId: string;
    changes: IntegrationChange[];
  },
): Promise<void> {
  if (entry.changes.length === 0) return;
  await indexIntegration(db, entry);
}
