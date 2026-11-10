// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  evaluate,
  requirementsCovering,
  type Action,
  type Evaluation,
  type ResourceContext,
  type TailnetRequirementRecord,
} from "../authz/evaluate.js";
import type { Querier } from "../db/migrate.js";
import { withSnapshot } from "../db/tx.js";
import { loadGrants, loadTailnetRequirements } from "../http/support.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";

/**
 * Machine reach (ADR-0054 Decision 8): what a machine identity's Grants
 * allow, per Project and Environment, with the Tailnet Requirements that
 * would constrain each action shown as conditions. Computed like ADR-0052's
 * authority snapshot: Grants are evaluated with no Requirements, and the
 * Requirements covering each Environment are attached to the actions they
 * constrain. A Requirement is never evaluated here: there is no request,
 * so no device to decide it against, and an action it constrains is
 * conditional, never denied. Computed on request, never stored; it changes
 * no authorization and issues nothing.
 */

/** Actions decided for the Organization as a whole (no Project). */
const ORGANIZATION_ACTIONS = [
  "organization.read",
  "organization.manage",
  "project.manage",
  "identity.read",
  "identity.manage",
  "policy.read",
  "policy.manage",
  "audit.read",
  "config.sync.manage",
] as const satisfies readonly Action[];

/** Actions decided for one Project. */
const PROJECT_ACTIONS = [
  "project.read",
  "project.manage",
  "contract.read",
  "contract.submit",
  "contract.activate",
] as const satisfies readonly Action[];

/** Actions decided for one Environment. */
const ENVIRONMENT_ACTIONS = [
  "environment.read",
  "environment.manage",
  "config.metadata.read",
  "config.value.read",
  "config.value.write",
  "secret.reveal",
  "secret.use",
  "config.sync.manage",
] as const satisfies readonly Action[];

/** The Environment actions Tailnet Requirements constrain (evaluate.ts). */
const CONDITIONED_ACTIONS: ReadonlySet<Action> = new Set(["config.value.read", "secret.reveal", "secret.use"]);

export type ReachState = "live" | "disabled" | "retired";

export interface ReachGrantSource {
  grantId: string;
  viaGroupId: string | null;
  roleId: string | null;
}

export interface ReachAction {
  action: Action;
  /** The Grants that allow it, with the Group or Role each came through. */
  grants: ReachGrantSource[];
  /** IDs of the Requirements that would constrain it (see `requirements`); empty means none. */
  conditions: string[];
}

export interface MachineReach {
  identity: {
    id: string;
    name: string;
    kind: string;
    state: ReachState;
    /** Why a disabled identity is disabled; null otherwise. */
    disabledReason: "organization-deletion" | null;
    /** Credentials that are unrevoked, unexpired and not used up. */
    liveCredentials: number;
  };
  /** Actions allowed for the Organization as a whole. */
  organizationActions: ReachAction[];
  projects: {
    id: string;
    slug: string;
    name: string;
    actions: ReachAction[];
    environments: {
      id: string;
      name: string;
      tier: "development" | "staging" | "production";
      kind: string;
      parentEnvironmentId: string | null;
      actions: ReachAction[];
    }[];
  }[];
  requirements: {
    id: string;
    version: number | null;
    target: TailnetRequirementRecord["target"];
    selector: TailnetRequirementRecord["selector"];
    /** The condition in words, such as "needs tailnet example.ts.net: tag:prod". */
    condition: string;
  }[];
  /** What else to know about this identity's reach, in words. */
  notes: string[];
}

/** A Requirement's selector as the condition it sets, in words. */
export function conditionWords(selector: TailnetRequirementRecord["selector"]): string {
  const tailnet = /^\S+$/.test(selector.tailnet) ? selector.tailnet : JSON.stringify(selector.tailnet);
  const by = [
    ...(selector.tags ?? []),
    ...(selector.users ?? []).map((u) => `user:${u}`),
    ...(selector.nodes ?? []).map((n) => `node:${n}`),
  ];
  return `needs tailnet ${tailnet}${by.length ? `: ${by.join(" or ")}` : ""}`;
}

function allowed(evaluation: Evaluation, action: Action, conditions: string[]): ReachAction | null {
  if (!evaluation.allowed) return null;
  return {
    action,
    grants: (evaluation.provenance.applied ?? []).map((g) => ({
      grantId: g.grantId,
      viaGroupId: g.viaGroupId ?? null,
      roleId: g.roleId ?? null,
    })),
    conditions,
  };
}

function decideAll(
  actions: readonly Action[],
  resource: ResourceContext,
  grants: Awaited<ReturnType<typeof loadGrants>>,
  conditions: string[] = [],
): ReachAction[] {
  const out: ReachAction[] = [];
  for (const action of actions) {
    // Grants alone: a machine has no built-in Organization role, and
    // Requirements are attached as conditions, not evaluated.
    const evaluation = evaluate({ action, resource, orgRole: null, grants, requirements: [], tailnetContext: null });
    const entry = allowed(evaluation, action, CONDITIONED_ACTIONS.has(action) ? conditions : []);
    if (entry) out.push(entry);
  }
  return out;
}

interface IdentityLookup {
  id: string;
  name: string;
  kind: string;
  disabled: boolean;
  suspended_by_deletion: string | null;
  organization_id: string | null;
  member: boolean;
}

async function lookupMachine(db: Querier, organizationId: string, identityId: string): Promise<IdentityLookup> {
  const res = await db.query(
    `SELECT i.id, i.name, i.kind, i.disabled, i.suspended_by_deletion, i.organization_id,
            EXISTS (SELECT 1 FROM org_memberships m WHERE m.organization_id = $2 AND m.identity_id = i.id) AS member
     FROM identities i WHERE i.id = $1`,
    [identityId, organizationId],
  );
  const row = res.rows[0] as IdentityLookup | undefined;
  if (row?.kind === "human" && row.member) {
    // A person of this Organization, current or former: their view is the
    // exposure report (ADR-0052), not this one.
    throw new DomainError(
      "VALIDATION_FAILED",
      "This identity is a person. Reach is for machine identities; for a member, see their exposure report.",
      { reason: "human-identity" },
    );
  }
  // Another Organization's machine, a person never in this one, and an
  // unknown ID are all the same: not found.
  if (!row || row.kind === "human" || row.organization_id !== organizationId) {
    throw new DomainError("RESOURCE_NOT_FOUND", "Not found");
  }
  return row;
}

/** A machine identity's reach in one Organization, read from one snapshot. */
export async function machineReach(ctx: AppCtx, organizationId: string, identityId: string): Promise<MachineReach> {
  return withSnapshot(ctx.db, async (db) => {
    const scoped = { ...ctx, db };
    const identity = await lookupMachine(db, organizationId, identityId);
    const credentials = await db.query(
      `SELECT count(*)::int AS n FROM credentials
       WHERE identity_id = $1 AND revoked_at IS NULL
         AND (expires_at IS NULL OR expires_at > now())
         AND (max_uses IS NULL OR use_count < max_uses)`,
      [identity.id],
    );
    const grants = await loadGrants(scoped, organizationId, identity.id);
    const requirements = await loadTailnetRequirements(scoped, organizationId);
    const projects = await db.query(
      "SELECT id, slug, name FROM projects WHERE organization_id = $1 AND deleted_at IS NULL ORDER BY name, id",
      [organizationId],
    );
    // Live Environments only: deleted ones are gone, and an expired one
    // serves nothing. Ordered by name.
    const envs = await db.query(
      `SELECT e.id, e.project_id, e.name, e.kind, e.tier, e.parent_environment_id FROM environments e
       JOIN projects p ON p.id = e.project_id
       WHERE p.organization_id = $1 AND p.deleted_at IS NULL AND e.deleted_at IS NULL
         AND (e.expires_at IS NULL OR e.expires_at > now())
       ORDER BY e.name, e.id`,
      [organizationId],
    );
    const envRows = envs.rows as {
      id: string;
      project_id: string;
      name: string;
      kind: string;
      tier: "development" | "staging" | "production";
      parent_environment_id: string | null;
    }[];

    const used = new Map<string, TailnetRequirementRecord>();
    const outProjects: MachineReach["projects"] = [];
    for (const p of projects.rows as { id: string; slug: string; name: string }[]) {
      const projectActions = decideAll(PROJECT_ACTIONS, { organizationId, projectId: p.id }, grants);
      const environments: MachineReach["projects"][number]["environments"] = [];
      for (const e of envRows.filter((x) => x.project_id === p.id)) {
        // A derived Environment is decided with its root's ID and its
        // (inherited) tier, so Grants and Requirements on the root cover it.
        const resource: ResourceContext = {
          organizationId,
          projectId: p.id,
          environment: { id: e.id, rootId: e.parent_environment_id ?? e.id, tier: e.tier },
        };
        const covering = requirementsCovering(requirements, resource);
        const actions = decideAll(ENVIRONMENT_ACTIONS, resource, grants, covering.map((r) => r.id));
        if (actions.length === 0) continue;
        if (actions.some((a) => a.conditions.length > 0)) for (const r of covering) used.set(r.id, r);
        environments.push({
          id: e.id,
          name: e.name,
          tier: e.tier,
          kind: e.kind,
          parentEnvironmentId: e.parent_environment_id,
          actions,
        });
      }
      if (projectActions.length === 0 && environments.length === 0) continue;
      outProjects.push({ id: p.id, slug: p.slug, name: p.name, actions: projectActions, environments });
    }

    const state: ReachState = !identity.disabled ? "live" : identity.suspended_by_deletion ? "disabled" : "retired";
    const notes: string[] = [];
    if (state === "retired") {
      notes.push("This identity is retired: it cannot sign in, so none of this is usable until it is reactivated and given a new credential.");
    } else if (state === "disabled") {
      notes.push("This identity is suspended while the Organization is being deleted: none of this is usable unless the deletion is cancelled.");
    }
    if (identity.kind === "broker") {
      // Capability issuance is kind-based (ADR-0022): the Agent's Grants
      // decide, not the Broker's, so the Broker's own Grants are not all.
      notes.push(
        "As a Broker it also issues agent-run credentials and Capabilities for this Organization's Agents. Those are not its Grants: agent runs exercise a subset of an Agent's reach through Capabilities (one Environment, named Config Items and destinations), checked against the Agent's Grants on every use.",
      );
    } else if (identity.kind === "agent") {
      notes.push(
        "Agent-run credentials a Broker issues for this Agent make read requests only, within these Grants. Agent runs use Secrets through a Broker's Capabilities, each a subset of this reach (one Environment, named Config Items and destinations).",
      );
    }

    return {
      identity: {
        id: identity.id,
        name: identity.name,
        kind: identity.kind,
        state,
        disabledReason: state === "disabled" ? "organization-deletion" : null,
        liveCredentials: (credentials.rows[0] as { n: number }).n,
      },
      organizationActions: decideAll(ORGANIZATION_ACTIONS, { organizationId }, grants),
      projects: outProjects,
      requirements: [...used.values()].map((r) => ({
        id: r.id,
        version: r.version ?? null,
        target: r.target,
        selector: r.selector,
        condition: conditionWords(r.selector),
      })),
      notes,
    };
  });
}
