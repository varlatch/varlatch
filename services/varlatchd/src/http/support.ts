// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHmac, randomUUID } from "node:crypto";
import type { Context } from "hono";
import type { ErrorCode } from "@varlatch/protocol";
import type { Action, Evaluation, GrantRecord, TailnetRequirementRecord } from "../authz/evaluate.js";
import { evaluate, type ResourceContext, type TailnetContext } from "../authz/evaluate.js";
import { recordAuditEvent, type AuditEventInput } from "../audit/events.js";
import type { CredentialRow, IdentityRow } from "../auth/credentials.js";
import type { AppCtx } from "../domain/ctx.js";
import { DomainError } from "../domain/errors.js";
import { getOrgRole } from "../domain/orgs.js";

export const STATUS_BY_CODE: Record<ErrorCode, number> = {
  AUTHENTICATION_REQUIRED: 401,
  INVALID_CREDENTIAL: 401,
  PERMISSION_DENIED: 403,
  RESOURCE_NOT_FOUND: 404,
  VALIDATION_FAILED: 422,
  VERSION_CONFLICT: 409,
  ROTATION_IN_PROGRESS: 409,
  IDEMPOTENCY_CONFLICT: 409,
  CONTRACT_INVALID: 422,
  CONTRACT_DRIFT: 409,
  CONTRACT_MAPPING_UNRESOLVED: 422,
  ENVIRONMENT_EXPIRED: 410,
  TAILNET_CONTEXT_REQUIRED: 403,
  TAILNET_CONTEXT_UNAVAILABLE: 403,
  RATE_LIMITED: 429,
  MAINTENANCE: 503,
  INTERNAL: 500,
  STATE_CHANGED: 409,
};

export function requestId(): string {
  return `req_${randomUUID()}`;
}

export function errorBody(code: ErrorCode, message: string, reqId: string, details?: Record<string, unknown>) {
  return { error: { code, message, requestId: reqId, ...(details ? { details } : {}) } };
}

export interface Principal {
  identity: IdentityRow;
  credentialId: string;
  credentialKind: CredentialRow["kind"];
}

/**
 * Load the subject's effective Grants, expanding the ADR-0028 reuse
 * constructs into flat GrantRecords the pure evaluator consumes:
 *  - direct identity Grants and Grants targeting any Group the identity is in
 *    (group fan-out; the Group id is recorded as provenance),
 *  - each Grant's Role reference expanded to the Role's current Actions
 *    (empty on a revoked/missing Role — default-deny preserved),
 *  - team-scoped Grants expanded to one project-scoped record per owned
 *    Project, so grantApplies never sees a raw team scope.
 * Everything is additive; an identity in no Group with no Roles behaves
 * exactly as before.
 */
export async function loadGrants(
  ctx: AppCtx,
  organizationId: string,
  subjectIdentityId: string,
): Promise<GrantRecord[]> {
  const res = await ctx.db.query(
    `SELECT g.id, g.subject_identity_id, g.subject_group_id, g.scope,
            g.actions, g.role_id, r.actions AS role_actions, r.revoked_at AS role_revoked,
            r.version AS role_version
     FROM grants g
     LEFT JOIN roles r ON r.id = g.role_id
     WHERE g.organization_id = $1 AND g.revoked_at IS NULL
       AND (
         g.subject_identity_id = $2
         OR g.subject_group_id IN (
           SELECT gm.group_id FROM group_members gm
           JOIN groups grp ON grp.id = gm.group_id
           WHERE gm.identity_id = $2 AND grp.revoked_at IS NULL
         )
       )`,
    [organizationId, subjectIdentityId],
  );
  const rows = res.rows as {
    id: string;
    subject_identity_id: string | null;
    subject_group_id: string | null;
    scope: unknown;
    actions: string[] | null;
    role_id: string | null;
    role_actions: string[] | null;
    role_revoked: string | null;
    role_version: number | null;
  }[];

  // Resolve team scopes to their owned projects once per team touched.
  const teamIds = [
    ...new Set(
      rows
        .map((r) => (typeof r.scope === "string" ? JSON.parse(r.scope) : r.scope) as GrantRecord["scope"])
        .filter((s) => s.kind === "team")
        .map((s) => (s as { teamId: string }).teamId),
    ),
  ];
  const teamProjects = new Map<string, string[]>();
  for (const teamId of teamIds) {
    const tp = await ctx.db.query("SELECT project_id FROM team_projects WHERE team_id = $1", [teamId]);
    teamProjects.set(teamId, (tp.rows as { project_id: string }[]).map((p) => p.project_id));
  }

  const grants: GrantRecord[] = [];
  for (const r of rows) {
    // A Role reference contributes the Role's current actions; a revoked or
    // missing Role expands to nothing (never a wildcard).
    const actions = (
      r.role_id ? (r.role_revoked ? [] : (r.role_actions ?? [])) : (r.actions ?? [])
    ) as GrantRecord["actions"];
    if (actions.length === 0) continue;
    const scope = (typeof r.scope === "string" ? JSON.parse(r.scope) : r.scope) as GrantRecord["scope"];
    const base = {
      id: r.id,
      subjectIdentityId: r.subject_identity_id ?? subjectIdentityId,
      actions,
      ...(r.subject_group_id ? { viaGroupId: r.subject_group_id } : {}),
      ...(r.role_id ? { roleId: r.role_id } : {}),
      ...(r.role_id && r.role_version !== null ? { roleVersion: r.role_version } : {}),
    };
    if (scope.kind === "team") {
      for (const projectId of teamProjects.get(scope.teamId) ?? []) {
        grants.push({ ...base, scope: { kind: "project", projectId } });
      }
    } else {
      grants.push({ ...base, scope });
    }
  }
  return grants;
}

export async function loadTailnetRequirements(
  ctx: AppCtx,
  organizationId: string,
): Promise<TailnetRequirementRecord[]> {
  const res = await ctx.db.query(
    "SELECT id, target, config, version FROM requirements WHERE organization_id = $1 AND kind = 'tailnet' AND revoked_at IS NULL",
    [organizationId],
  );
  return (res.rows as { id: string; target: unknown; config: unknown; version: number }[]).map((r) => ({
    id: r.id,
    version: r.version,
    target: (typeof r.target === "string" ? JSON.parse(r.target) : r.target) as TailnetRequirementRecord["target"],
    selector: (typeof r.config === "string" ? JSON.parse(r.config) : r.config) as TailnetRequirementRecord["selector"],
  }));
}

export interface AuthorizeOptions {
  /** When true a denial for lack of visibility maps to RESOURCE_NOT_FOUND. */
  hideExistence?: boolean;
}

/** One authorization decision. A denial carries its audit event unrecorded. */
export type Decision =
  | { allowed: true; evaluation: Evaluation }
  | { allowed: false; error: DomainError; denialEvent: AuditEventInput | null };

/**
 * Evaluate one action without writing anything, so it can run inside a
 * read-only retrieval snapshot (ADR-0038 Decision 6). A denial is returned
 * with its audit event and error; {@link enforce} records and throws them.
 */
export async function decide(
  ctx: AppCtx,
  c: Context,
  principal: Principal,
  action: Action,
  resource: ResourceContext,
  opts: AuthorizeOptions = {},
): Promise<Decision> {
  const role =
    principal.identity.kind === "human"
      ? await getOrgRole(ctx, resource.organizationId, principal.identity.id)
      : null;
  // Machine identities act only inside their own organization.
  if (
    principal.identity.kind !== "human" &&
    principal.identity.organization_id !== resource.organizationId
  ) {
    return {
      allowed: false,
      error: new DomainError("RESOURCE_NOT_FOUND", "Organization not found"),
      denialEvent: null,
    };
  }
  const grants = await loadGrants(ctx, resource.organizationId, principal.identity.id);
  const requirements = await loadTailnetRequirements(ctx, resource.organizationId);
  const tailnetContext = (c.get("tailnetContext") as TailnetContext | undefined) ?? null;

  const result = evaluate({ action, resource, orgRole: role, grants, requirements, tailnetContext });
  if (result.allowed) return { allowed: true, evaluation: result };

  const denialEvent: AuditEventInput = {
    eventType: "authorization.denied",
    decision: "deny",
    actorIdentityId: principal.identity.id,
    credentialId: principal.credentialId,
    organizationId: resource.organizationId,
    action,
    resource: {
      projectId: resource.projectId ?? null,
      environmentId: resource.environment?.id ?? null,
    },
    authz: {
      denial: result.denial,
      ...(result.provenance.applied ? { applied: result.provenance.applied } : {}),
      requirements: result.requirements,
    },
    requestId: c.get("requestId") as string,
  };

  if (result.denial === "requirement-failed") {
    const missingContext = result.requirements.some(
      (r) => !r.satisfied && r.reason === "no-tailnet-context",
    );
    return {
      allowed: false,
      denialEvent,
      error: new DomainError(
        missingContext ? "TAILNET_CONTEXT_REQUIRED" : "TAILNET_CONTEXT_UNAVAILABLE",
        missingContext
          ? "This operation requires trusted Tailnet Context"
          : "Tailnet Context does not satisfy the required selector",
      ),
    };
  }
  // No applicable grant. Callers with zero visibility get not-found-equivalent;
  // a machine identity is inherently aware of its own organization.
  const visible =
    role !== null ||
    grants.length > 0 ||
    (principal.identity.kind !== "human" &&
      principal.identity.organization_id === resource.organizationId) ||
    !opts.hideExistence;
  return {
    allowed: false,
    denialEvent,
    error: visible
      ? new DomainError("PERMISSION_DENIED", "Not authorized for this action")
      : new DomainError("RESOURCE_NOT_FOUND", "Organization not found"),
  };
}

/** Record a denial's audit event, if it has one. Allowed decisions record nothing. */
export async function recordDenial(ctx: AppCtx, decision: Decision): Promise<void> {
  if (!decision.allowed && decision.denialEvent) await recordAuditEvent(ctx.db, decision.denialEvent);
}

export type Denied = Extract<Decision, { allowed: false }>;

/** Record a denial's audit event, then throw its error. */
export async function reject(ctx: AppCtx, decision: Denied): Promise<never> {
  await recordDenial(ctx, decision);
  throw decision.error;
}

/** An allowed decision's evaluation; a denial is recorded, then thrown. */
export async function enforce(ctx: AppCtx, decision: Decision): Promise<Evaluation> {
  if (decision.allowed) return decision.evaluation;
  await recordDenial(ctx, decision);
  throw decision.error;
}

/**
 * Full authorization for one action (ADR-0015/0018): loads role, grants, and
 * requirements, evaluates, audits denials, and maps denial classes:
 * no visibility -> 404-equivalent; visible but denied -> PERMISSION_DENIED;
 * requirement failed -> distinct diagnosable TAILNET_* code.
 * Returns the Evaluation so allow-path callers can persist decision-time
 * provenance (ADR-0029 §6) — e.g. the Sync Target disclosure gate.
 */
export async function authorize(
  ctx: AppCtx,
  c: Context,
  principal: Principal,
  action: Action,
  resource: ResourceContext,
  opts: AuthorizeOptions = {},
): Promise<Evaluation> {
  return enforce(ctx, await decide(ctx, c, principal, action, resource, opts));
}

/** Cursor helpers: opaque base64 of (occurredAt,id) or (createdAt,id). */
export function encodeCursor(parts: string[]): string {
  return Buffer.from(JSON.stringify(parts), "utf8").toString("base64url");
}

export function decodeCursor(cursor: string): string[] | null {
  try {
    const parsed = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"));
    return Array.isArray(parsed) && parsed.every((p) => typeof p === "string") ? parsed : null;
  } catch {
    return null;
  }
}

export function bodyHash(body: unknown, key: Buffer): string {
  return "hmac-v1:" + createHmac("sha256", key).update("varlatch:idempotency:v1\0").update(JSON.stringify(body) ?? "null", "utf8").digest("hex");
}
