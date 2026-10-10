// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  semanticsFor,
  semanticsVersionOf,
  type ConfigurationContract,
} from "@varlatch/contract";
import type { AuditEventInput } from "../audit/events.js";
import { isExpired, rootIdOf } from "./environments.js";
import { DomainError } from "./errors.js";
import {
  categoryDigests,
  manifestOf,
  type CallerView,
  type StateCategory,
  type StateManifest,
} from "./manifest.js";
import { expandReferences } from "./references.js";
import { auditThenDecrypt, type CapturedState, type ResolvedItem } from "./retrieval.js";
import type { ValidationAccess, ValidationResult } from "./values.js";

/**
 * Strict retrieval (ADR-0038 Decision 6): the non-sensitive values and every
 * authorized Secret, from one snapshot, with the state manifest, the caller
 * view, and the validation of exactly the values returned, in one response.
 *
 * Each class is authorized separately: a caller without secret.reveal still
 * gets non-sensitive values, and the Secrets are reported as withheld. The
 * response is built only after every audit commit, decryption, and
 * expansion has succeeded; a failure returns an error and no values.
 */

export interface StrictItem {
  name: string;
  sensitive: boolean;
  source: "self" | "parent";
  versionId: string;
  /** The delivered value, references expanded; null when withheld. */
  value: string | null;
  /** The stored text, present only when expansion changed `value`. */
  rawValue?: string;
  /** A Secret's previous version while a rotation window is open, unexpanded. */
  retiring?: { versionId: string; value: string };
  /** True while a dual-phase rotation window is open (metadata only). */
  rotating?: true;
}

export interface StrictRetrieval {
  /** "preflight" returns no Secret values: only their verdicts, for an operator with secret.reveal. */
  mode: RetrievalMode;
  environmentId: string;
  manifest: StateManifest;
  stateDigest: `sha256:${string}`;
  /** Per-category digests, so a later precondition mismatch can name what changed. */
  stateDigests: Record<StateCategory, `sha256:${string}`>;
  /** The snapshot's active Contract, when the caller may read it. */
  contract: ConfigurationContract | null;
  items: StrictItem[];
  callerView: CallerView & { contractWithheld: boolean };
  /** Verdicts on exactly the values returned, at the revision's semantics version. */
  validation: ValidationResult;
}

export type RetrievalMode = "strict" | "preflight";

export interface StrictAccess {
  plain: ValidationAccess;
  secret: ValidationAccess;
  contract: boolean;
}

export async function strictRetrieval(
  ctx: Parameters<typeof auditThenDecrypt>[0],
  state: CapturedState,
  access: StrictAccess,
  opts: {
    mode: RetrievalMode;
    actorIdentityId: string;
    requestId?: string | undefined;
    listener?: "ordinary" | "tailnet" | undefined;
    /** What each class was allowed by, for the audit events (auditAuthz). */
    authz?: { plain?: Record<string, unknown> | undefined; secret?: Record<string, unknown> | undefined };
  },
): Promise<StrictRetrieval> {
  const preflight = opts.mode === "preflight";
  const { org, project, env, contract } = state;
  if (isExpired(env, state.now)) {
    throw new DomainError(
      "ENVIRONMENT_EXPIRED",
      "This environment has expired; retrieval and mutation are disabled until it is deleted or its expiry is changed",
    );
  }
  const delivers = (item: ResolvedItem) => (item.sensitive ? access.secret : access.plain) === "allowed";
  const plain = state.items.filter((i) => !i.sensitive && delivers(i));
  const secrets = state.items.filter((i) => i.sensitive && delivers(i));

  // One commit covers every decryption below, and precedes all of them.
  const events: AuditEventInput[] = [];
  const base = {
    decision: "allow" as const,
    actorIdentityId: opts.actorIdentityId,
    organizationId: org.id,
    resource: { projectId: project.id, environmentId: env.id },
    requestId: opts.requestId ?? null,
    listener: opts.listener,
  };
  if (plain.length > 0) {
    events.push({
      ...base,
      eventType: "value.disclosed",
      action: "config.value.read",
      ...(opts.authz?.plain ? { authz: opts.authz.plain } : {}),
      metadata: { mode: "strict-retrieval", items: plain.map((i) => `${i.name}@${i.versionId}`).join(",") },
    });
  }
  if (secrets.length > 0) {
    // A preflight decrypts Secrets only to validate them in-process: the
    // event records the attempt and purpose, never a verdict.
    events.push(
      preflight
        ? {
            ...base,
            eventType: "secret.validated",
            action: "secret.reveal",
            ...(opts.authz?.secret ? { authz: opts.authz.secret } : {}),
            metadata: { purpose: "preflight-validation", items: secrets.map((i) => `${i.name}@${i.versionId}`).join(",") },
          }
        : {
            ...base,
            eventType: "secret.disclosed",
            action: "secret.reveal",
            ...(opts.authz?.secret ? { authz: opts.authz.secret } : {}),
            metadata: {
              mode: "strict-retrieval",
              items: secrets
                .map((i) => (i.retiringVersionId ? `${i.name}@${i.versionId}+${i.retiringVersionId}` : `${i.name}@${i.versionId}`))
                .join(","),
            },
          },
    );
  }
  const plaintext = await auditThenDecrypt(
    ctx,
    state,
    events,
    [...plain, ...secrets].flatMap((i) =>
      i.sensitive && i.retiringVersionId && !preflight ? [i.versionId, i.retiringVersionId] : [i.versionId],
    ),
  );

  // Expansion follows delivery: a non-sensitive value expands from
  // non-sensitive values; a Secret from Secrets and, when the caller may read
  // them, non-sensitive values. Everything in either domain was decrypted
  // above, since all of it is being returned.
  const plainValues = new Map(plain.map((i) => [i.name, plaintext.get(i.versionId) as string]));
  const secretDomain = new Map([
    ...secrets.map((i) => [i.name, plaintext.get(i.versionId) as string] as const),
    ...plainValues,
  ]);
  const items: StrictItem[] = [];
  const unexpanded: CallerView["unexpanded"] = [];
  const withheld: CallerView["withheld"] = [];
  /** What each evaluable item delivers, expanded: the verdicts' input. */
  const evaluable = new Map<string, string>();
  const notEvaluable = new Map<string, { reason: "permission" | "requirement"; requires: "config.value.read" | "secret.reveal" }>();
  for (const item of state.items) {
    const entry: StrictItem = {
      name: item.name,
      sensitive: item.sensitive,
      source: item.source,
      versionId: item.versionId,
      value: null,
      ...(item.retiringVersionId ? { rotating: true as const } : {}),
    };
    if (!delivers(item)) {
      const decision = item.sensitive ? access.secret : access.plain;
      const denied = {
        reason: decision === "requirement" ? ("requirement" as const) : ("permission" as const),
        requires: item.sensitive ? ("secret.reveal" as const) : ("config.value.read" as const),
      };
      notEvaluable.set(item.name, denied);
      // In a preflight no Secret is delivered to the operator by design, so
      // only non-sensitive values count as withheld.
      if (!(preflight && item.sensitive)) withheld.push({ name: item.name, ...denied });
      items.push(entry);
      continue;
    }
    const raw = plaintext.get(item.versionId) as string;
    const domain = item.sensitive ? secretDomain : plainValues;
    const literal = new Set<string>();
    // Size and work limits throw: the whole retrieval fails, with no values.
    const value = expandReferences(raw, (name) => domain.get(name), false, (name) => literal.add(name));
    evaluable.set(item.name, value);
    if (literal.size > 0) unexpanded.push({ name: item.name, references: [...literal].sort() });
    if (preflight && item.sensitive) {
      // Validated in-process only; the plaintext is not returned.
      items.push(entry);
      continue;
    }
    entry.value = value;
    if (value !== raw) entry.rawValue = raw;
    if (item.sensitive && item.retiringVersionId) {
      entry.retiring = { versionId: item.retiringVersionId, value: plaintext.get(item.retiringVersionId) as string };
    }
    items.push(entry);
  }

  const validation = validateDelivered(state, evaluable, notEvaluable, unexpanded, access);
  const { manifest, stateDigest } = manifestOf(state);
  return {
    mode: opts.mode,
    environmentId: env.id,
    manifest,
    stateDigest,
    stateDigests: categoryDigests(manifest),
    contract: access.contract ? contract : null,
    items,
    callerView: { withheld, unexpanded, contractWithheld: !access.contract && contract !== null },
    validation,
  };
}

/**
 * Verdicts on the values this retrieval returns, from the same snapshot. An
 * item is judged only if it was delivered: verdicts are value-derived.
 */
function validateDelivered(
  state: CapturedState,
  evaluable: Map<string, string>,
  notEvaluable: Map<string, { reason: "permission" | "requirement"; requires: "config.value.read" | "secret.reveal" }>,
  unexpanded: CallerView["unexpanded"],
  access: StrictAccess,
): ValidationResult {
  const { contract, env, project } = state;
  const result: ValidationResult = {
    environmentId: env.id,
    contractRevisionId: project.active_contract_revision_id,
    valid: true,
    complete: true,
    missing: [],
    invalid: [],
    notEvaluated: [],
    unresolved: [],
  };
  if (!contract) return result;
  const semantics = semanticsFor(semanticsVersionOf(contract));
  const envCtx = { rootId: rootIdOf(env), tier: env.tier };
  const stored = new Map(state.items.map((i) => [i.name, i]));
  const literalByName = new Map(unexpanded.map((u) => [u.name, u.references]));
  for (const item of contract.items) {
    if (!stored.has(item.name)) {
      if (semantics.missingWhenAbsent(item, envCtx)) result.missing.push(item.name);
      continue;
    }
    const denied = notEvaluable.get(item.name);
    if (denied) {
      result.notEvaluated.push({ name: item.name, reason: denied.reason, requires: denied.requires });
      continue;
    }
    const literal = literalByName.get(item.name);
    if (literal) {
      // "authority": a Secret whose only literal references are non-sensitive
      // values this caller may not read.
      const authority =
        item.sensitive &&
        access.plain !== "allowed" &&
        literal.every((name) => stored.get(name)?.sensitive === false);
      result.unresolved.push({ name: item.name, reason: authority ? "authority" : "reference" });
      continue;
    }
    const problem = semantics.validate(item, evaluable.get(item.name) as string);
    if (problem) result.invalid.push({ name: item.name, reason: problem });
  }
  result.complete =
    result.notEvaluated.length === 0 && !result.unresolved.some((u) => u.reason === "authority");
  result.valid =
    result.complete &&
    result.missing.length === 0 &&
    result.invalid.length === 0 &&
    result.unresolved.length === 0;
  return result;
}
