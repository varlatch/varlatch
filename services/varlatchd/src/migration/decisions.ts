// SPDX-License-Identifier: AGPL-3.0-or-later
import { evaluate, type Action, type ResourceContext } from "../authz/evaluate.js";
import type { Querier } from "../db/migrate.js";
import type { AppCtx } from "../domain/ctx.js";
import { getOrgRole } from "../domain/orgs.js";
import { loadGrants, loadTailnetRequirements } from "../http/support.js";
import type { Tier } from "@varlatch/contract";

/**
 * Decision 8's decision table (ADR-0059 step 7, go-step7): the old
 * evaluator's answer at the frozen point for every identity, credential
 * state, resource and action, with the tailnet Requirements in force, as
 * a request without Tailnet Context sees them. It loads state exactly as
 * a request does (http/support.ts decide: the Organization role, the
 * Grants with their Groups, Roles and Teams expanded, the Requirements)
 * and calls the same pure evaluator, so varlatchd can evaluate the same
 * tuples and compare.
 *
 * Resources are each Organization, each of its live Projects and each live
 * Environment: the evaluator takes no item, so items do not change an
 * answer. A credential that is expired or revoked, or an identity that is
 * disabled, is refused before any evaluation: one row per identity and
 * state says so, for every resource. Outcomes:
 *   allow, no-grant, requirement-failed  (the evaluator's answer)
 *   not-found          a machine identity outside its own Organization
 *   unauthenticated    an expired or revoked credential, a disabled identity
 * A request's security-control checkpoints (passkey verification) are
 * ceremonies of the request, not of the state: the controls' rows are
 * copied and compared byte for byte instead.
 */

export const ACTIONS = [
  "organization.read", "organization.manage", "project.read", "project.manage", "environment.read", "environment.manage",
  "config.metadata.read", "config.value.read", "config.value.write", "secret.reveal", "secret.use", "contract.read",
  "contract.submit", "contract.activate", "identity.read", "identity.manage", "policy.read", "policy.manage", "audit.read",
  "config.sync.manage",
] as const satisfies readonly Action[];
// Every action the evaluator knows is in ACTIONS (a compile error otherwise).
type MissingAction = Exclude<Action, (typeof ACTIONS)[number]>;
const everyAction: MissingAction extends never ? true : never = true;
void everyAction;

export type Outcome = "allow" | "no-grant" | "requirement-failed" | "not-found" | "unauthenticated";

export interface DecisionRow {
  identityId: string;
  credential: "active" | "expired" | "revoked";
  /** Absent with "unauthenticated", which holds for every resource. */
  organizationId?: string;
  projectId?: string | null;
  environmentId?: string | null;
  action?: Action;
  outcome: Outcome;
}

interface Resource {
  context: ResourceContext;
  projectId: string | null;
  environmentId: string | null;
}

/** The decision table, streamed, in a fixed order. */
export async function* decisionTable(client: Querier): AsyncIterable<DecisionRow> {
  const ctx = { db: client } as unknown as AppCtx;
  const rows = async <T>(sql: string, params: unknown[] = []) => (await client.query(sql, params)).rows as T[];
  const identities = await rows<{ id: string; kind: string; organization_id: string | null; disabled: boolean }>(
    `SELECT id, kind, organization_id, disabled FROM identities ORDER BY id COLLATE "C"`,
  );
  const orgs = await rows<{ id: string }>(`SELECT id FROM organizations WHERE deleted_at IS NULL ORDER BY id COLLATE "C"`);
  const resources = new Map<string, Resource[]>();
  const requirements = new Map<string, Awaited<ReturnType<typeof loadTailnetRequirements>>>();
  for (const org of orgs) {
    const list: Resource[] = [{ context: { organizationId: org.id }, projectId: null, environmentId: null }];
    for (const p of await rows<{ id: string }>(`SELECT id FROM projects WHERE organization_id = $1 AND deleted_at IS NULL ORDER BY id COLLATE "C"`, [org.id])) {
      list.push({ context: { organizationId: org.id, projectId: p.id }, projectId: p.id, environmentId: null });
      for (const e of await rows<{ id: string; tier: Tier; parent_environment_id: string | null }>(
        `SELECT id, tier, parent_environment_id FROM environments WHERE project_id = $1 AND deleted_at IS NULL ORDER BY id COLLATE "C"`,
        [p.id],
      )) {
        list.push({
          context: { organizationId: org.id, projectId: p.id, environment: { id: e.id, rootId: e.parent_environment_id ?? e.id, tier: e.tier } },
          projectId: p.id,
          environmentId: e.id,
        });
      }
    }
    resources.set(org.id, list);
    requirements.set(org.id, await loadTailnetRequirements(ctx, org.id));
  }

  for (const identity of identities) {
    for (const state of ["expired", "revoked"] as const) yield { identityId: identity.id, credential: state, outcome: "unauthenticated" };
    if (identity.disabled) {
      yield { identityId: identity.id, credential: "active", outcome: "unauthenticated" };
      continue;
    }
    for (const org of orgs) {
      const machineElsewhere = identity.kind !== "human" && identity.organization_id !== org.id;
      const role = identity.kind === "human" ? await getOrgRole(ctx, org.id, identity.id) : null;
      const grants = machineElsewhere ? [] : await loadGrants(ctx, org.id, identity.id);
      for (const r of resources.get(org.id)!) {
        for (const action of ACTIONS) {
          let outcome: Outcome;
          if (machineElsewhere) outcome = "not-found";
          else {
            const result = evaluate({ action, resource: r.context, orgRole: role, grants, requirements: requirements.get(org.id)!, tailnetContext: null });
            outcome = result.allowed ? "allow" : result.denial === "requirement-failed" ? "requirement-failed" : "no-grant";
          }
          yield { identityId: identity.id, credential: "active", organizationId: org.id, projectId: r.projectId, environmentId: r.environmentId, action, outcome };
        }
      }
    }
  }
}
