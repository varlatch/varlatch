// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Querier } from "../db/migrate.js";
import { canonicalJson, type ApprovalBinding, type ApprovalChange } from "./approvals.js";

/**
 * requirement-protection (ADR-0054 Decision 5, step 4.2): what an approval
 * for editing or revoking a Tailnet Requirement binds, per the binding
 * catalogue (`requirement.update`, `requirement.revoke`), and the summary
 * its approver reads. Creating a Requirement only restricts and is never
 * protected.
 *
 * - requirement.update: target the Requirement; body its resulting target
 *   (`{tier}`, or `{environmentIds}` as a set) and selector (`tailnet`, and
 *   `tags`, `users`, `nodes` as sets, a left-out list binding `[]`, which
 *   matches the same devices); the version the request expects.
 * - requirement.revoke: target the Requirement; no body; the version the
 *   server reads, since the request carries none, checked again under the
 *   Requirement's row lock before the revocation.
 *
 * Neither carries a secret. The query binds `{}`: neither route reads one.
 */

export type RequirementTarget = { kind: "tier"; tier: string } | { kind: "environments"; environmentIds: string[] };

export interface RequirementSelector {
  tailnet: string;
  tags?: string[] | undefined;
  users?: string[] | undefined;
  nodes?: string[] | undefined;
}

export interface RequirementState {
  target: RequirementTarget;
  selector: RequirementSelector;
}

export interface CurrentRequirement extends RequirementState {
  id: string;
  version: number;
}

const parse = <T>(v: unknown): T => (typeof v === "string" ? JSON.parse(v) : v) as T;

/** A live Requirement of the Organization, read without a lock; null when there is none. */
export async function readRequirement(db: Querier, organizationId: string, requirementId: string): Promise<CurrentRequirement | null> {
  const row = (await db.query(
    "SELECT id, target, config, version FROM requirements WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL",
    [requirementId, organizationId],
  )).rows[0] as { id: string; target: unknown; config: unknown; version: number } | undefined;
  return row ? { id: row.id, target: parse(row.target), selector: parse(row.config), version: row.version } : null;
}

/**
 * Whether an edit changes nothing the Requirement means: the same bound
 * form (key order, the order of a set, duplicates and a left-out list
 * aside). Such an edit needs no approval (amendment A); the route still
 * writes it exactly as it did before the controls existed.
 */
export function sameRequirementState(a: RequirementState, b: RequirementState): boolean {
  return canonicalJson(normalizedRequirement(a)) === canonicalJson(normalizedRequirement(b));
}

const set = (values: readonly string[] | undefined) => [...new Set(values ?? [])].sort();

/** The bound form: sets sorted and without duplicates, a left-out list as []. */
export function normalizedRequirement(state: RequirementState) {
  return {
    target: state.target.kind === "tier"
      ? { kind: "tier", tier: state.target.tier }
      : { kind: "environments", environmentIds: set(state.target.environmentIds) },
    selector: {
      tailnet: state.selector.tailnet,
      tags: set(state.selector.tags),
      users: set(state.selector.users),
      nodes: set(state.selector.nodes),
    },
  };
}

/**
 * The Organization's environments among `ids`, as people read them:
 * project/environment. An id of no environment of this Organization keeps
 * its id: a Requirement's target is not checked against the Organization
 * when it is written, and no other Organization's name is ever shown.
 */
async function environmentNames(db: Querier, organizationId: string, ids: readonly string[]): Promise<Map<string, string>> {
  if (ids.length === 0) return new Map();
  const rows = (await db.query(
    `SELECT e.id, e.name, p.slug FROM environments e JOIN projects p ON p.id = e.project_id
     WHERE e.id = ANY($1) AND p.organization_id = $2`,
    [[...ids], organizationId],
  )).rows as { id: string; name: string; slug: string }[];
  return new Map(rows.map((r) => [r.id, `${r.slug}/${r.name}`]));
}

function describeTarget(target: RequirementTarget, names: Map<string, string>): string {
  if (target.kind === "tier") return `the ${target.tier} tier`;
  return `environments ${set(target.environmentIds).map((id) => names.get(id) ?? id).join(", ")}`;
}

function describeSelector(selector: RequirementSelector): string {
  const n = normalizedRequirement({ target: { kind: "tier", tier: "" }, selector }).selector;
  const parts = [
    n.tags.length ? `tags ${n.tags.join(", ")}` : null,
    n.users.length ? `users ${n.users.join(", ")}` : null,
    n.nodes.length ? `nodes ${n.nodes.join(", ")}` : null,
  ].filter((p): p is string => p !== null);
  return `tailnet ${n.tailnet}: ${parts.join("; ")}`;
}

/**
 * Whether a change of target can leave something the old target covered
 * uncovered: another kind or tier, or an environment taken out. Adding
 * environments only restricts.
 */
function targetLoosens(before: RequirementTarget, after: RequirementTarget): boolean {
  if (before.kind !== after.kind) return true;
  if (before.kind === "tier" && after.kind === "tier") return before.tier !== after.tier;
  if (before.kind === "environments" && after.kind === "environments") {
    const kept = new Set(after.environmentIds);
    return before.environmentIds.some((id) => !kept.has(id));
  }
  return true;
}

/**
 * Whether a change of selector can admit a device the old one refused:
 * another tailnet, or a tag, user or node added (a selector matches any of
 * them). Taking one out only restricts.
 */
function selectorLoosens(before: RequirementSelector, after: RequirementSelector): boolean {
  if (before.tailnet !== after.tailnet) return true;
  const added = (a: string[] | undefined, b: string[] | undefined) => {
    const had = new Set(a ?? []);
    return (b ?? []).some((v) => !had.has(v));
  };
  return added(before.tags, after.tags) || added(before.users, after.users) || added(before.nodes, after.nodes);
}

/** The binding of an edit that changes something: the Requirement, its resulting state, the version the request expects. */
export async function requirementUpdateBinding(
  db: Querier,
  org: { id: string },
  current: CurrentRequirement,
  next: RequirementState,
  expectedVersion: number,
): Promise<ApprovalBinding> {
  const envIds = [
    ...(current.target.kind === "environments" ? current.target.environmentIds : []),
    ...(next.target.kind === "environments" ? next.target.environmentIds : []),
  ];
  const names = await environmentNames(db, org.id, envIds);
  const changes: ApprovalChange[] = [];
  const before = { target: describeTarget(current.target, names), selector: describeSelector(current.selector) };
  const after = { target: describeTarget(next.target, names), selector: describeSelector(next.selector) };
  if (before.target !== after.target) {
    changes.push({ field: "target", from: before.target, to: after.target, loosens: targetLoosens(current.target, next.target) });
  }
  if (before.selector !== after.selector) {
    changes.push({ field: "selector", from: before.selector, to: after.selector, loosens: selectorLoosens(current.selector, next.selector) });
  }
  return {
    operation: "requirement.update",
    organizationId: org.id,
    target: { requirementId: current.id },
    body: normalizedRequirement(next),
    query: {},
    expectedVersion,
    summary: { title: `Change the Tailnet Requirement on ${before.target}`, changes },
  };
}

/** The binding of a revocation: the Requirement and the version the server read. */
export async function requirementRevokeBinding(
  db: Querier,
  org: { id: string },
  current: CurrentRequirement,
): Promise<ApprovalBinding> {
  const names = await environmentNames(db, org.id, current.target.kind === "environments" ? current.target.environmentIds : []);
  return {
    operation: "requirement.revoke",
    organizationId: org.id,
    target: { requirementId: current.id },
    body: null,
    query: {},
    expectedVersion: current.version,
    summary: {
      title: `Remove the Tailnet Requirement on ${describeTarget(current.target, names)} (${describeSelector(current.selector)}). What it constrained is no longer constrained`,
      changes: [],
    },
  };
}
