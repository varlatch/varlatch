// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Tier } from "@varlatch/contract";

/**
 * Pure authorization evaluator (ADR-0015): roles expand into implied Grants,
 * union with explicit Grants, default deny; Requirements then restrict.
 * Grants permit; Requirements restrict; neither ever does the other's job.
 * Rights are evaluated per request against current authoritative state —
 * the caller loads that state; this module only decides.
 */

export type Action =
  | "organization.read"
  | "organization.manage"
  | "project.read"
  | "project.manage"
  | "environment.read"
  | "environment.manage"
  | "config.metadata.read"
  | "config.value.read"
  | "config.value.write"
  | "secret.reveal"
  | "secret.use"
  | "contract.read"
  | "contract.submit"
  | "contract.activate"
  | "identity.read"
  | "identity.manage"
  | "policy.read"
  | "policy.manage"
  | "audit.read"
  | "config.sync.manage";

export type OrgRole = "admin" | "member";

export type GrantScope =
  | { kind: "organization" }
  | { kind: "project"; projectId: string }
  | {
      kind: "environments";
      projectId: string;
      selector:
        | { kind: "environments"; environmentIds: string[] }
        | { kind: "tier"; tier: Tier };
    }
  // A team scope targets every Project the Team owns (ADR-0028). It is
  // pre-expanded to project scopes inside loadGrants, so a raw team scope
  // never reaches grantApplies (which fails it closed defensively).
  | { kind: "team"; teamId: string };

export interface GrantRecord {
  id: string;
  subjectIdentityId: string;
  scope: GrantScope;
  actions: Action[];
  /** Provenance (ADR-0028): the Group whose membership pulled this Grant in. */
  viaGroupId?: string;
  /** Provenance: the Role this Grant's actions were expanded from, if any. */
  roleId?: string;
  /** The Role's configuration version at load time (ADR-0029 §6). */
  roleVersion?: number;
}

/** The resource an action targets, resolved by the caller. */
export interface ResourceContext {
  organizationId: string;
  projectId?: string;
  environment?: {
    id: string;
    /** The root environment's ID (itself for roots). */
    rootId: string;
    tier: Tier;
  };
}

export interface TailnetRequirementRecord {
  id: string;
  /** The Requirement's configuration version at load time (ADR-0029 §6). */
  version?: number;
  /** Which resources the requirement targets. */
  target:
    | { kind: "tier"; tier: Tier }
    | { kind: "environments"; environmentIds: string[] };
  /** Which tailnet identities satisfy it. */
  selector: {
    tailnet: string;
    tags?: string[];
    users?: string[];
    nodes?: string[];
  };
}

/** Verified Tailnet Context (ADR-0014) — only ever built from the tailnet listener. */
export interface TailnetContext {
  tailnet: string;
  nodeId: string;
  tags: string[];
  userLogin?: string;
}

export type RequirementOutcome =
  | { requirementId: string; requirementVersion?: number; satisfied: true; by: string }
  | {
      requirementId: string;
      requirementVersion?: number;
      satisfied: false;
      reason: "no-tailnet-context" | "tailnet-mismatch" | "selector-mismatch";
    };

/**
 * Decision-time snapshot of one applied Grant's mutable facts (ADR-0029 §6):
 * because Roles are editable and Group membership is unversioned, the
 * grantId alone no longer explains a historical decision — audit events
 * record the facts the evaluator actually consumed.
 */
export interface AppliedGrant {
  grantId: string;
  actions: Action[];
  viaGroupId?: string;
  roleId?: string;
  roleVersion?: number;
}

export interface Evaluation {
  allowed: boolean;
  /** Denial class for error mapping; present when !allowed. */
  denial?: "no-grant" | "requirement-failed";
  provenance: {
    role?: OrgRole;
    grantIds: string[];
    /** Groups whose membership contributed an applied Grant (ADR-0028). */
    groupIds?: string[];
    /** Roles whose actions an applied Grant was expanded from (ADR-0028). */
    roleIds?: string[];
    /** Per-grant decision-time facts for audit snapshots (ADR-0029 §6). */
    applied?: AppliedGrant[];
  };
  requirements: RequirementOutcome[];
}

/** Actions requiring tailnet Requirements to be checked (retrieval/reveal class). */
const TAILNET_CONSTRAINED_ACTIONS: ReadonlySet<Action> = new Set([
  "config.value.read",
  "secret.reveal",
  "secret.use",
]);

const ALL_ORG_ACTIONS: readonly Action[] = [
  "organization.read",
  "organization.manage",
  "project.read",
  "project.manage",
  "environment.read",
  "environment.manage",
  "config.metadata.read",
  "config.value.read",
  "config.value.write",
  "secret.reveal",
  "secret.use",
  "contract.read",
  "contract.submit",
  "contract.activate",
  "identity.read",
  "identity.manage",
  "policy.read",
  "policy.manage",
  "audit.read",
  "config.sync.manage",
];

/**
 * The fixed Organization Member bundle (ADR-0015 §5):
 * development = broad mutation; staging = broad consumption, explicit
 * mutation; production = existence/navigation metadata only.
 */
function memberAllows(action: Action, resource: ResourceContext): boolean {
  // Org-wide navigation.
  if (
    action === "organization.read" ||
    action === "project.read" ||
    action === "contract.read"
  ) {
    return true;
  }
  const tier = resource.environment?.tier;
  if (!tier) {
    // Non-environment-scoped actions beyond navigation are not in the bundle.
    return false;
  }
  switch (tier) {
    case "development":
      return (
        action === "environment.read" ||
        action === "environment.manage" ||
        action === "config.metadata.read" ||
        action === "config.value.read" ||
        action === "config.value.write" ||
        action === "secret.reveal"
      );
    case "staging":
      return (
        action === "environment.read" ||
        action === "config.metadata.read" ||
        action === "config.value.read" ||
        action === "secret.reveal"
      );
    case "production":
      return action === "environment.read" || action === "config.metadata.read";
  }
}

function grantApplies(
  grant: GrantRecord,
  action: Action,
  resource: ResourceContext,
): boolean {
  if (!grant.actions.includes(action)) return false;
  switch (grant.scope.kind) {
    case "organization":
      return true;
    case "project":
      return resource.projectId === grant.scope.projectId;
    case "environments": {
      if (resource.projectId !== grant.scope.projectId) return false;
      const env = resource.environment;
      if (!env) return false;
      const sel = grant.scope.selector;
      if (sel.kind === "tier") return env.tier === sel.tier;
      // Explicit-environment selectors match the environment itself or its
      // root: a grant on a root covers its derived children, which share the
      // root's risk context (ADR-0012 §8) and inherit its values.
      return (
        sel.environmentIds.includes(env.id) || sel.environmentIds.includes(env.rootId)
      );
    }
    case "team":
      // Team scopes are expanded to project scopes in loadGrants; a raw one
      // reaching here matches nothing (fail closed, preserves default-deny).
      return false;
  }
}

function requirementTargets(
  req: TailnetRequirementRecord,
  resource: ResourceContext,
): boolean {
  const env = resource.environment;
  if (!env) return false;
  if (req.target.kind === "tier") return env.tier === req.target.tier;
  return (
    req.target.environmentIds.includes(env.id) ||
    req.target.environmentIds.includes(env.rootId)
  );
}

function evaluateTailnetRequirement(
  req: TailnetRequirementRecord,
  ctx: TailnetContext | null,
): RequirementOutcome {
  const base = {
    requirementId: req.id,
    ...(req.version !== undefined ? { requirementVersion: req.version } : {}),
  };
  if (!ctx) {
    return { ...base, satisfied: false, reason: "no-tailnet-context" };
  }
  if (ctx.tailnet !== req.selector.tailnet) {
    return { ...base, satisfied: false, reason: "tailnet-mismatch" };
  }
  const s = req.selector;
  if (s.nodes?.includes(ctx.nodeId)) {
    return { ...base, satisfied: true, by: `node:${ctx.nodeId}` };
  }
  const tag = s.tags?.find((t) => ctx.tags.includes(t));
  if (tag) return { ...base, satisfied: true, by: tag };
  if (ctx.userLogin && s.users?.includes(ctx.userLogin)) {
    return { ...base, satisfied: true, by: `user:${ctx.userLogin}` };
  }
  return { ...base, satisfied: false, reason: "selector-mismatch" };
}

export interface EvaluateInput {
  action: Action;
  resource: ResourceContext;
  /** The subject's role in the resource's organization, if a human member. */
  orgRole: OrgRole | null;
  /** Unrevoked Grants for this subject in this organization. */
  grants: GrantRecord[];
  /** Active tailnet Requirements in this organization. */
  requirements: TailnetRequirementRecord[];
  /** Verified Tailnet Context, or null when the request lacks one. */
  tailnetContext: TailnetContext | null;
}

export function evaluate(input: EvaluateInput): Evaluation {
  const { action, resource } = input;

  const applied = input.grants.filter((g) => grantApplies(g, action, resource));
  const grantIds = applied.map((g) => g.id);
  const groupIds = [...new Set(applied.map((g) => g.viaGroupId).filter((x): x is string => !!x))];
  const roleIds = [...new Set(applied.map((g) => g.roleId).filter((x): x is string => !!x))];

  let roleAllows = false;
  if (input.orgRole === "admin" && ALL_ORG_ACTIONS.includes(action)) {
    roleAllows = true;
  } else if (input.orgRole === "member" && memberAllows(action, resource)) {
    roleAllows = true;
  }

  const appliedFacts: AppliedGrant[] = applied.map((g) => ({
    grantId: g.id,
    actions: g.actions,
    ...(g.viaGroupId ? { viaGroupId: g.viaGroupId } : {}),
    ...(g.roleId ? { roleId: g.roleId } : {}),
    ...(g.roleVersion !== undefined ? { roleVersion: g.roleVersion } : {}),
  }));

  const provenance = {
    ...(roleAllows && input.orgRole ? { role: input.orgRole } : {}),
    grantIds,
    ...(groupIds.length > 0 ? { groupIds } : {}),
    ...(roleIds.length > 0 ? { roleIds } : {}),
    ...(appliedFacts.length > 0 ? { applied: appliedFacts } : {}),
  };

  if (!roleAllows && grantIds.length === 0) {
    return { allowed: false, denial: "no-grant", provenance, requirements: [] };
  }

  // Requirements restrict — admins do not bypass them (ADR-0015 §4).
  const applicable = TAILNET_CONSTRAINED_ACTIONS.has(action)
    ? input.requirements.filter((r) => requirementTargets(r, resource))
    : [];
  const outcomes = applicable.map((r) =>
    evaluateTailnetRequirement(r, input.tailnetContext),
  );
  if (outcomes.some((o) => !o.satisfied)) {
    return { allowed: false, denial: "requirement-failed", provenance, requirements: outcomes };
  }
  return { allowed: true, provenance, requirements: outcomes };
}
