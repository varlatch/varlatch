// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Context } from "hono";
import type { Action, ResourceContext, TailnetContext, TailnetRequirementRecord } from "../authz/evaluate.js";
import type { IdentityRow } from "../auth/credentials.js";
import type { Querier } from "../db/migrate.js";
import type { AppCtx } from "../domain/ctx.js";
import { decide, loadTailnetRequirements, type Principal } from "../http/support.js";
import type { Tier } from "@varlatch/contract";
import type { Decision, DecisionSource, DecisionTailnet } from "./bundle.js";

/**
 * Decision 8's decision table (ADR-0059 step 7, go-step7; BUNDLE.md
 * section 4): the old evaluator's answer at the frozen point for every
 * identity × credential state × resource × action, with the tailnet
 * Requirements in force, which varlatchd evaluates again on the target
 * (CHECKS.md, "authorization").
 *
 * Each decision is the request path's own: http/support.ts decide, with
 * the Organization role, the Grants with their Groups and Roles expanded,
 * and the Requirements loaded as a request loads them, existence not
 * hidden. A denial is its error code (PERMISSION_DENIED,
 * RESOURCE_NOT_FOUND for a machine identity outside its Organization,
 * TAILNET_CONTEXT_REQUIRED, TAILNET_CONTEXT_UNAVAILABLE).
 *
 * The tuples:
 *   - an identity is named by one of its credentials (the first by id):
 *     varlatchd evaluates the credential's identity, so another credential
 *     of it adds nothing. An identity with no credential cannot act and is
 *     not named;
 *   - each credential state: `active` is decided; `expired` and `revoked`
 *     are refused before authorization, UNAUTHENTICATED;
 *   - resources: each live Organization, each of its live Projects and
 *     each live Environment. The evaluator takes no item, so items change
 *     no answer;
 *   - every action the evaluator knows;
 *   - the Tailnet Context: none, for every tuple; then, active only, on
 *     each Environment of an Organization with tailnet Requirements, one
 *     context per Requirement that satisfies its selector, and one per
 *     tailnet that satisfies none.
 * A request's security-control checkpoints (passkey verification) are
 * ceremonies of the request, not of the state: the controls' rows are
 * copied and compared byte for byte instead. Whether an identity is
 * disabled is authentication's (its own check), as in varlatchd.
 *
 * The table is streamed, in a fixed order, after its count: the state it
 * reads is small (identities, resources, Requirements) and each query is
 * asked once (the snapshot does not change under it).
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

const STATES = ["active", "expired", "revoked"] as const;

/** A node id no selector names: a context with it satisfies a Requirement only by its tags or user. */
const UNNAMED_NODE = "nMigrationCheck";

interface Resource {
  context: ResourceContext;
  project: string | null;
  environment: string | null;
}

interface Org {
  id: string;
  resources: Resource[];
  environments: Resource[];
  contexts: DecisionTailnet[];
}

/**
 * Queries asked through decide, each answered once: within the export's
 * read-only snapshot, the same query has the same answer.
 */
function memoized(client: Querier): Querier {
  const answers = new Map<string, ReturnType<Querier["query"]>>();
  return {
    query: ((sql: string, params?: unknown[]) => {
      const key = JSON.stringify([sql, params ?? []]);
      let answer = answers.get(key);
      if (!answer) {
        answer = client.query(sql, params);
        answers.set(key, answer);
      }
      return answer;
    }) as Querier["query"],
  } as Querier;
}

/** The contexts a Requirement's selector is tested with: one satisfying it, and per tailnet one satisfying none. */
function contextsFor(requirements: TailnetRequirementRecord[]): DecisionTailnet[] {
  const out: DecisionTailnet[] = [];
  const seen = new Set<string>();
  const add = (t: DecisionTailnet) => {
    const key = JSON.stringify(t);
    if (!seen.has(key)) {
      seen.add(key);
      out.push(t);
    }
  };
  const sorted = [...requirements].sort((a, b) => Buffer.compare(Buffer.from(a.id), Buffer.from(b.id)));
  for (const r of sorted) {
    const s = r.selector;
    add({ tailnet: s.tailnet, nodeId: s.nodes?.[0] ?? UNNAMED_NODE, tags: s.tags?.slice(0, 1) ?? [], userLogin: s.users?.[0] ?? null });
  }
  for (const r of sorted) add({ tailnet: r.selector.tailnet, nodeId: UNNAMED_NODE, tags: [], userLogin: null });
  return out;
}

/** The decision section at `at` (Unix microseconds): its count, then its decisions, streamed. */
export async function decisionTable(client: Querier, at: bigint): Promise<DecisionSource> {
  const db = memoized(client);
  const ctx = { db } as unknown as AppCtx;
  const rows = async <T>(sql: string, params: unknown[] = []) => (await client.query(sql, params)).rows as T[];

  const identities = await rows<{ id: string; kind: string; organization_id: string | null; credential: string | null; credential_kind: string | null }>(
    `SELECT i.id, i.kind, i.organization_id, c.id AS credential, c.kind AS credential_kind
       FROM identities i
       LEFT JOIN LATERAL (SELECT id, kind FROM credentials WHERE identity_id = i.id ORDER BY id COLLATE "C" LIMIT 1) c ON true
      ORDER BY i.id COLLATE "C"`,
  );
  const named = identities.filter((i): i is typeof i & { credential: string } => i.credential !== null);

  const orgs: Org[] = [];
  for (const { id } of await rows<{ id: string }>(`SELECT id FROM organizations WHERE deleted_at IS NULL ORDER BY id COLLATE "C"`)) {
    const resources: Resource[] = [{ context: { organizationId: id }, project: null, environment: null }];
    for (const p of await rows<{ id: string }>(`SELECT id FROM projects WHERE organization_id = $1 AND deleted_at IS NULL ORDER BY id COLLATE "C"`, [id])) {
      resources.push({ context: { organizationId: id, projectId: p.id }, project: p.id, environment: null });
      for (const e of await rows<{ id: string; tier: Tier; parent_environment_id: string | null }>(
        `SELECT id, tier, parent_environment_id FROM environments WHERE project_id = $1 AND deleted_at IS NULL ORDER BY id COLLATE "C"`,
        [p.id],
      )) {
        resources.push({
          context: { organizationId: id, projectId: p.id, environment: { id: e.id, rootId: e.parent_environment_id ?? e.id, tier: e.tier } },
          project: p.id,
          environment: e.id,
        });
      }
    }
    const environments = resources.filter((r) => r.environment !== null);
    orgs.push({ id, resources, environments, contexts: contextsFor(await loadTailnetRequirements(ctx, id)) });
  }

  const perCredential =
    STATES.length * orgs.reduce((n, o) => n + o.resources.length, 0) * ACTIONS.length +
    orgs.reduce((n, o) => n + o.contexts.length * o.environments.length, 0) * ACTIONS.length;
  const count = named.length * perCredential;

  async function* decisions(): AsyncIterable<Decision> {
    for (const identity of named) {
      const principal: Principal = {
        identity: { id: identity.id, kind: identity.kind, organization_id: identity.organization_id } as IdentityRow,
        credentialId: identity.credential,
        credentialKind: identity.credential_kind as Principal["credentialKind"],
      };
      const answer = async (r: Resource, action: Action, tailnet: DecisionTailnet | null): Promise<Pick<Decision, "allowed" | "code">> => {
        const tailnetContext: TailnetContext | null = tailnet
          ? { tailnet: tailnet.tailnet, nodeId: tailnet.nodeId, tags: tailnet.tags, ...(tailnet.userLogin !== null ? { userLogin: tailnet.userLogin } : {}) }
          : null;
        // decide reads the request's Tailnet Context and notes what it authorized: nothing else of a request.
        const request = { get: (key: string) => (key === "tailnetContext" ? tailnetContext ?? undefined : undefined), set: () => {} } as unknown as Context;
        const d = await decide(ctx, request, principal, action, r.context);
        return d.allowed ? { allowed: true, code: null } : { allowed: false, code: d.error.code };
      };
      for (const state of STATES) {
        for (const org of orgs) {
          for (const r of org.resources) {
            for (const action of ACTIONS) {
              const a = state === "active" ? await answer(r, action, null) : { allowed: false, code: "UNAUTHENTICATED" };
              yield { credential: identity.credential, state, organization: org.id, project: r.project, environment: r.environment, action, tailnet: null, ...a };
            }
          }
        }
      }
      for (const org of orgs) {
        for (const tailnet of org.contexts) {
          for (const r of org.environments) {
            for (const action of ACTIONS) {
              yield { credential: identity.credential, state: "active", organization: org.id, project: r.project, environment: r.environment, action, tailnet, ...(await answer(r, action, tailnet)) };
            }
          }
        }
      }
    }
  }
  return { count, at, decisions: decisions() };
}
