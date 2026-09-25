// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { CONFIG_ITEM_NAME_PATTERN } from "@varlatch/contract";
import { recordAuditEvent } from "../audit/events.js";
import type { Evaluation, TailnetContext } from "../authz/evaluate.js";
import { evaluate } from "../authz/evaluate.js";
import {
  destinationMatches,
  formatSelector,
  parseDestinationSelector,
  type Destination,
} from "../authz/destination.js";
import { newId } from "../db/ids.js";
import { withTx } from "../db/tx.js";
import { loadGrants, loadTailnetRequirements } from "../http/support.js";
import type { AppCtx } from "./ctx.js";
import { rootIdOf, type EnvironmentRow } from "./environments.js";
import { DomainError } from "./errors.js";
import type { OrgRow } from "./orgs.js";
import type { ProjectRow } from "./projects.js";
import {
  MAX_REFERENCE_DEPTH,
  ReferenceExpansionError,
  expandReferences,
  referencedNames,
} from "./references.js";
import { auditThenDecrypt, captureState, type CapturedState, type ResolvedItem } from "./retrieval.js";

/**
 * Capabilities (ADR-0022): a Capability narrows potential future use and
 * never expands the Agent's Grants. Exercise is the security boundary — the
 * Agent's secret.use (including Tailnet Requirements against the exercise
 * request's context) is evaluated against current state on every call, and
 * the current effective Value version is resolved then (Model B). Successful
 * exercise commits its audit event before anything is decrypted.
 */

export interface CapabilityRow {
  id: string;
  organization_id: string;
  broker_identity_id: string;
  agent_identity_id: string;
  project_id: string;
  environment_id: string;
  items: string[];
  destinations: string[];
  secret_hash: string;
  run_id: string | null;
  expires_at: string;
  revoked_at: string | null;
  created_at: string;
}

const MAX_TTL_SECONDS = 24 * 60 * 60;

function hashCapabilitySecret(secret: string): string {
  return createHash("sha256").update(secret, "utf8").digest("hex");
}

async function evaluateAgentSecretUse(
  ctx: AppCtx,
  org: OrgRow,
  agentIdentityId: string,
  resource: { projectId: string; environment: EnvironmentRow },
  tailnetContext: TailnetContext | null,
  action: "secret.use" | "config.value.read" = "secret.use",
) {
  const grants = await loadGrants(ctx, org.id, agentIdentityId);
  const requirements = await loadTailnetRequirements(ctx, org.id);
  return evaluate({
    action,
    resource: {
      organizationId: org.id,
      projectId: resource.projectId,
      environment: {
        id: resource.environment.id,
        rootId: rootIdOf(resource.environment),
        tier: resource.environment.tier,
      },
    },
    orgRole: null,
    grants,
    requirements,
    tailnetContext,
  });
}

export interface IssueCapabilityInput {
  agentIdentityId: string;
  items: string[];
  destinations: string[];
  ttlSeconds: number;
  runId?: string | undefined;
}

export interface IssuedCapability {
  id: string;
  /** Returned exactly once; only its hash is stored. */
  secret: string;
  agentIdentityId: string;
  environmentId: string;
  items: string[];
  destinations: string[];
  runId: string | null;
  expiresAt: string;
  /** Advisory current-authority preflight; exercise re-checks regardless. */
  preflight: "ok" | "agent-lacks-secret-use";
}

export async function issueCapability(
  ctx: AppCtx,
  org: OrgRow,
  project: ProjectRow,
  env: EnvironmentRow,
  brokerIdentityId: string,
  input: IssueCapabilityInput,
): Promise<IssuedCapability> {
  if (input.items.length === 0) {
    throw new DomainError("VALIDATION_FAILED", "A Capability names explicit Config Items");
  }
  for (const item of input.items) {
    if (!CONFIG_ITEM_NAME_PATTERN.test(item)) {
      throw new DomainError("VALIDATION_FAILED", `Invalid Config Item name: ${item}`);
    }
  }
  if (input.destinations.length === 0) {
    throw new DomainError("VALIDATION_FAILED", "A Capability names explicit destinations");
  }
  const selectors = input.destinations.map((raw) => {
    const sel = parseDestinationSelector(raw);
    if (!sel) throw new DomainError("VALIDATION_FAILED", `Invalid destination selector: ${raw}`);
    return formatSelector(sel);
  });
  if (input.ttlSeconds < 1 || input.ttlSeconds > MAX_TTL_SECONDS) {
    throw new DomainError("VALIDATION_FAILED", `ttlSeconds must be 1..${MAX_TTL_SECONDS}`);
  }

  const agent = (
    await ctx.db.query(
      "SELECT id, kind, disabled FROM identities WHERE id = $1 AND organization_id = $2",
      [input.agentIdentityId, org.id],
    )
  ).rows[0] as { id: string; kind: string; disabled: boolean } | undefined;
  if (!agent || agent.kind !== "agent") {
    throw new DomainError("VALIDATION_FAILED", "agentIdentityId must name an agent identity in this organization");
  }
  if (agent.disabled) {
    throw new DomainError("VALIDATION_FAILED", "Agent identity is disabled");
  }

  // Advisory only: Requirements are excluded (they depend on the exercise
  // request's Tailnet Context, unknowable now). Exercise remains authoritative.
  const preflightGrants = await loadGrants(ctx, org.id, agent.id);
  const preflightEval = evaluate({
    action: "secret.use",
    resource: {
      organizationId: org.id,
      projectId: project.id,
      environment: { id: env.id, rootId: rootIdOf(env), tier: env.tier },
    },
    orgRole: null,
    grants: preflightGrants,
    requirements: [],
    tailnetContext: null,
  });

  const id = newId("capability");
  const secret = `vlt_cap_${randomBytes(32).toString("base64url")}`;
  const expiresAt = new Date(Date.now() + input.ttlSeconds * 1000).toISOString();

  await withTx(ctx.db, async (db) => {
    await db.query(
      `INSERT INTO capabilities
         (id, organization_id, broker_identity_id, agent_identity_id, project_id,
          environment_id, items, destinations, secret_hash, run_id, expires_at, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$3)`,
      [
        id,
        org.id,
        brokerIdentityId,
        agent.id,
        project.id,
        env.id,
        input.items,
        selectors,
        hashCapabilitySecret(secret),
        input.runId ?? null,
        expiresAt,
      ],
    );
    await recordAuditEvent(db, {
      eventType: "capability.issued",
      decision: "info",
      actorIdentityId: brokerIdentityId,
      organizationId: org.id,
      action: "secret.use",
      resource: {
        capabilityId: id,
        agentIdentityId: agent.id,
        projectId: project.id,
        environmentId: env.id,
      },
      metadata: {
        items: input.items.join(","),
        destinations: selectors.join(","),
        runId: input.runId ?? null,
        expiresAt,
        preflight: preflightEval.allowed ? "ok" : "agent-lacks-secret-use",
      },
    });
  });

  return {
    id,
    secret,
    agentIdentityId: agent.id,
    environmentId: env.id,
    items: input.items,
    destinations: selectors,
    runId: input.runId ?? null,
    expiresAt,
    preflight: preflightEval.allowed ? "ok" : "agent-lacks-secret-use",
  };
}

export async function listCapabilities(
  ctx: AppCtx,
  org: OrgRow,
  env: EnvironmentRow,
  opts: { brokerIdentityId?: string | undefined },
): Promise<CapabilityRow[]> {
  const params: unknown[] = [org.id, env.id];
  let where = "organization_id = $1 AND environment_id = $2";
  if (opts.brokerIdentityId) {
    where += " AND broker_identity_id = $3";
    params.push(opts.brokerIdentityId);
  }
  const res = await ctx.db.query(
    `SELECT * FROM capabilities WHERE ${where} ORDER BY created_at DESC, id`,
    params,
  );
  return res.rows as CapabilityRow[];
}

export async function revokeCapability(
  ctx: AppCtx,
  org: OrgRow,
  capabilityId: string,
  opts: { actorIdentityId: string; brokerIdentityId?: string | undefined },
): Promise<void> {
  await withTx(ctx.db, async (db) => {
    const params: unknown[] = [capabilityId, org.id];
    let where = "id = $1 AND organization_id = $2 AND revoked_at IS NULL";
    if (opts.brokerIdentityId) {
      where += " AND broker_identity_id = $3";
      params.push(opts.brokerIdentityId);
    }
    const res = await db.query(
      `UPDATE capabilities SET revoked_at = now() WHERE ${where} RETURNING id`,
      params,
    );
    if (!res.rows[0]) throw new DomainError("RESOURCE_NOT_FOUND", "Capability not found");
    await recordAuditEvent(db, {
      eventType: "capability.revoked",
      decision: "info",
      actorIdentityId: opts.actorIdentityId,
      organizationId: org.id,
      action: "secret.use",
      resource: { capabilityId },
    });
  });
}

export interface ExerciseInput {
  capabilityId: string;
  capabilitySecret: string;
  destination: Destination;
}

export interface ExerciseResult {
  items: {
    name: string;
    versionId: string;
    value: string;
    /**
     * The previous value during a dual-phase rotation (ADR-0027), injected
     * as-is so the consumer can accept either during the overlap window.
     */
    retiring?: { versionId: string; value: string };
  }[];
  /** Named by the Capability but not currently resolvable as Secrets. */
  withheld: string[];
}

type DenyReason =
  | "not-found"
  | "wrong-broker"
  | "bad-secret"
  | "revoked"
  | "expired"
  | "destination-mismatch"
  | "authz-denied"
  | "requirement-failed"
  | "unresolved-reference";

/**
 * Everything an exercise reads, from the retrieval snapshot (ADR-0038
 * Decision 6): the Capability row, the Agent's authorization evaluated on
 * the snapshot's Grants and Requirements, and the captured values, including
 * the ciphertext of every value a reference could reach for the Agent.
 */
export interface CapturedExercise {
  state: CapturedState;
  row: CapabilityRow | undefined;
  /** The Agent's secret.use, and its config.value.read for reference expansion. */
  use: Evaluation | null;
  plainRead: Evaluation | null;
}

export async function captureExercise(
  sctx: AppCtx,
  scope: { org: OrgRow; project: ProjectRow; env: EnvironmentRow },
  now: Date,
  capabilityId: string,
  tailnetContext: TailnetContext | null,
): Promise<CapturedExercise> {
  const { org, project, env } = scope;
  const row = (
    await sctx.db.query(
      "SELECT * FROM capabilities WHERE id = $1 AND organization_id = $2 AND environment_id = $3",
      [capabilityId, org.id, env.id],
    )
  ).rows[0] as CapabilityRow | undefined;
  const resource = { projectId: project.id, environment: env };
  const use = row
    ? await evaluateAgentSecretUse(sctx, org, row.agent_identity_id, resource, tailnetContext)
    : null;
  const plainRead = row
    ? await evaluateAgentSecretUse(sctx, org, row.agent_identity_id, resource, tailnetContext, "config.value.read")
    : null;
  const state = await captureState(sctx, scope, now, (item) =>
    item.sensitive ? (row?.items.includes(item.name) ?? false) : plainRead?.allowed === true,
  );
  return { state, row, use, plainRead };
}

export async function exerciseCapability(
  ctx: AppCtx,
  captured: CapturedExercise,
  brokerIdentityId: string,
  input: ExerciseInput,
  opts: {
    tailnetContext: TailnetContext | null;
    requestId?: string | undefined;
    listener?: "ordinary" | "tailnet" | undefined;
  },
): Promise<ExerciseResult> {
  const { state, row } = captured;
  const { org, project, env } = state;

  const deny = async (
    reason: DenyReason,
    detail?: Record<string, string>,
  ): Promise<never> => {
    await recordAuditEvent(ctx.db, {
      eventType: "capability.denied",
      decision: "deny",
      actorIdentityId: brokerIdentityId,
      organizationId: org.id,
      action: "secret.use",
      resource: {
        capabilityId: input.capabilityId,
        agentIdentityId: row?.agent_identity_id ?? null,
        projectId: project.id,
        environmentId: env.id,
      },
      requestId: opts.requestId ?? null,
      listener: opts.listener ?? null,
      metadata: {
        reason,
        destination: `${input.destination.host}:${input.destination.port}`,
        ...detail,
      },
    });
    // Existence-hiding: only the bound Broker presenting the right secret
    // learns anything beyond not-found.
    if (reason === "not-found" || reason === "wrong-broker" || reason === "bad-secret") {
      throw new DomainError("RESOURCE_NOT_FOUND", "Capability not found");
    }
    if (reason === "requirement-failed") {
      throw new DomainError(
        opts.tailnetContext ? "TAILNET_CONTEXT_UNAVAILABLE" : "TAILNET_CONTEXT_REQUIRED",
        opts.tailnetContext
          ? "Tailnet Context does not satisfy the required selector"
          : "This exercise requires trusted Tailnet Context",
      );
    }
    if (reason === "unresolved-reference") {
      throw new DomainError(
        "PERMISSION_DENIED",
        `Exercised material references \${${detail?.reference}} (in ${detail?.referencedBy}), which ${
          detail?.cause === "secret-not-bound"
            ? "is a Secret this Capability does not name — bind it in the Capability's items"
            : detail?.cause === "plain-read-denied"
              ? "the Agent's Grants do not allow reading here (config.value.read)"
              : "does not exist in this environment — escape as $${NAME} if literal text is intended"
        }`,
        { reason, ...detail },
      );
    }
    throw new DomainError("PERMISSION_DENIED", "Capability cannot be exercised", {
      reason,
      ...detail,
    });
  };

  if (!row) return deny("not-found");
  if (row.broker_identity_id !== brokerIdentityId) return deny("wrong-broker");
  const presented = Buffer.from(hashCapabilitySecret(input.capabilitySecret), "hex");
  const stored = Buffer.from(row.secret_hash, "hex");
  if (presented.length !== stored.length || !timingSafeEqual(presented, stored)) {
    return deny("bad-secret");
  }
  if (row.revoked_at) return deny("revoked");
  if (new Date(row.expires_at).getTime() <= state.now.getTime()) return deny("expired");

  const selectors = row.destinations.map((raw) => parseDestinationSelector(raw));
  const matched = selectors.some((sel) => sel && destinationMatches(sel, input.destination));
  if (!matched) return deny("destination-mismatch");

  // Model B: the effective versions and the AGENT's secret.use, both as the
  // snapshot saw them.
  const secretsByName = new Map(state.items.filter((i) => i.sensitive).map((i) => [i.name, i]));
  const selected: ResolvedItem[] = [];
  const withheld: string[] = [];
  for (const name of row.items) {
    const item = secretsByName.get(name);
    if (item) selected.push(item);
    else withheld.push(name);
  }

  const evaluation = captured.use as Evaluation;
  if (!evaluation.allowed) {
    return deny(evaluation.denial === "requirement-failed" ? "requirement-failed" : "authz-denied");
  }

  // Audit commits before anything is decrypted (ADR-0016/0022 §17); records
  // the exact versions exercised and the canonical destination, never a URL.
  const plaintext = await auditThenDecrypt(
    ctx,
    state,
    [
      {
        eventType: "capability.exercised",
        decision: "allow",
        actorIdentityId: brokerIdentityId,
        organizationId: org.id,
        action: "secret.use",
        resource: {
          capabilityId: row.id,
          agentIdentityId: row.agent_identity_id,
          projectId: project.id,
          environmentId: env.id,
        },
        // Decision-time facts (ADR-0029 §6): Roles are editable and membership
        // unversioned, so the snapshot records what the evaluator actually saw.
        authz: {
          grantIds: evaluation.provenance.grantIds,
          ...(evaluation.provenance.applied ? { applied: evaluation.provenance.applied } : {}),
          requirements: evaluation.requirements,
        },
        requestId: opts.requestId ?? null,
        listener: opts.listener ?? null,
        metadata: {
          destination: `${input.destination.host}:${input.destination.port}`,
          items: selected
            .map((i) => (i.retiringVersionId ? `${i.name}@${i.versionId}+${i.retiringVersionId}` : `${i.name}@${i.versionId}`))
            .join(","),
          withheld: withheld.length,
          runId: row.run_id,
        },
      },
    ],
    selected.flatMap((i) => (i.retiringVersionId ? [i.versionId, i.retiringVersionId] : [i.versionId])),
  );

  const items: ExerciseResult["items"] = [];
  const lookup = new Map<string, string>();
  for (const item of selected) {
    const value = plaintext.get(item.versionId) as string;
    lookup.set(item.name, value);
    // Rotation: also inject the retiring version so the agent's upstream can
    // accept either during the window. References resolve to primaries only
    // (ADR-0027 §2), so the retiring copy is passed through unexpanded.
    const retiring = item.retiringVersionId
      ? { versionId: item.retiringVersionId, value: plaintext.get(item.retiringVersionId) as string }
      : undefined;
    items.push({ name: item.name, versionId: item.versionId, value, ...(retiring ? { retiring } : {}) });
  }

  // Reference expansion at exercise (ADR-0026): strict resolve-or-deny —
  // the consumer is an upstream API that cannot react to a literal ${NAME}.
  // Referenced Secrets must be bound in this Capability (already selected
  // above); non-sensitive items may be pulled in only when the Agent's
  // Grants allow config.value.read here. They are found one reference level
  // at a time, and each level's audit commits before it is decrypted.
  const plainByName = new Map(state.items.filter((i) => !i.sensitive).map((i) => [i.name, i]));
  const queued = new Set<string>();
  let frontier: { referencedBy: string; raw: string }[] = items.map((i) => ({ referencedBy: i.name, raw: i.value }));
  for (let depth = 0; frontier.length > 0 && depth < MAX_REFERENCE_DEPTH; depth++) {
    const needed: { item: ResolvedItem; referencedBy: string }[] = [];
    for (const { referencedBy, raw } of frontier) {
      for (const reference of referencedNames(raw)) {
        if (lookup.has(reference) || queued.has(reference)) continue;
        if (secretsByName.has(reference)) {
          return deny("unresolved-reference", { reference, referencedBy, cause: "secret-not-bound" });
        }
        const plain = plainByName.get(reference);
        if (!plain) {
          return deny("unresolved-reference", { reference, referencedBy, cause: "unknown-item" });
        }
        queued.add(reference);
        needed.push({ item: plain, referencedBy });
      }
    }
    if (needed.length === 0) break;
    if (!captured.plainRead?.allowed) {
      const first = needed[0]!;
      return deny("unresolved-reference", {
        reference: first.item.name,
        referencedBy: first.referencedBy,
        cause: "plain-read-denied",
      });
    }
    const decrypted = await auditThenDecrypt(
      ctx,
      state,
      [
        {
          eventType: "value.disclosed",
          decision: "allow",
          actorIdentityId: brokerIdentityId,
          organizationId: org.id,
          action: "config.value.read",
          resource: {
            capabilityId: row.id,
            agentIdentityId: row.agent_identity_id,
            projectId: project.id,
            environmentId: env.id,
          },
          requestId: opts.requestId ?? null,
          listener: opts.listener ?? null,
          metadata: {
            mode: "reference-expansion",
            items: needed.map((n) => `${n.item.name}@${n.item.versionId}`).join(","),
            runId: row.run_id,
          },
        },
      ],
      needed.map((n) => n.item.versionId),
    );
    frontier = [];
    for (const { item } of needed) {
      const value = decrypted.get(item.versionId) as string;
      lookup.set(item.name, value);
      frontier.push({ referencedBy: item.name, raw: value });
    }
  }
  for (const item of items) {
    try {
      item.value = expandReferences(item.value, (name) => lookup.get(name), true);
    } catch (error) {
      if (!(error instanceof ReferenceExpansionError)) throw error;
      return deny("unresolved-reference", { referencedBy: item.name, cause: "incomplete-or-excessive-expansion" });
    }
  }
  return { items, withheld };
}
