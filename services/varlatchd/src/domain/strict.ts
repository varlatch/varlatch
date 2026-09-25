// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  semanticsFor,
  semanticsVersionOf,
  type ConfigurationContract,
} from "@varlatch/contract";
import type { AuditEventInput } from "../audit/events.js";
import { isExpired, rootIdOf } from "./environments.js";
import { DomainError } from "./errors.js";
import { manifestOf, type CallerView, type StateManifest } from "./manifest.js";
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
  environmentId: string;
  manifest: StateManifest;
  stateDigest: `sha256:${string}`;
  /** The snapshot's active Contract, when the caller may read it. */
  contract: ConfigurationContract | null;
  items: StrictItem[];
  callerView: CallerView & { contractWithheld: boolean };
  /** Verdicts on exactly the values returned, at the revision's semantics version. */
  validation: ValidationResult;
}

export interface StrictAccess {
  plain: ValidationAccess;
  secret: ValidationAccess;
  contract: boolean;
}

export async function strictRetrieval(
  ctx: Parameters<typeof auditThenDecrypt>[0],
  state: CapturedState,
  access: StrictAccess,
  opts: { actorIdentityId: string; requestId?: string | undefined; listener?: "ordinary" | "tailnet" | undefined },
): Promise<StrictRetrieval> {
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
    listener: opts.listener ?? null,
  };
  if (plain.length > 0) {
    events.push({
      ...base,
      eventType: "value.disclosed",
      action: "config.value.read",
      metadata: { mode: "strict-retrieval", items: plain.map((i) => `${i.name}@${i.versionId}`).join(",") },
    });
  }
  if (secrets.length > 0) {
    events.push({
      ...base,
      eventType: "secret.disclosed",
      action: "secret.reveal",
      metadata: {
        mode: "strict-retrieval",
        items: secrets
          .map((i) => (i.retiringVersionId ? `${i.name}@${i.versionId}+${i.retiringVersionId}` : `${i.name}@${i.versionId}`))
          .join(","),
      },
    });
  }
  const plaintext = await auditThenDecrypt(
    ctx,
    state,
    events,
    [...plain, ...secrets].flatMap((i) => (i.retiringVersionId && i.sensitive ? [i.versionId, i.retiringVersionId] : [i.versionId])),
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
      withheld.push({
        name: item.name,
        reason: decision === "requirement" ? "requirement" : "permission",
        requires: item.sensitive ? "secret.reveal" : "config.value.read",
      });
      items.push(entry);
      continue;
    }
    const raw = plaintext.get(item.versionId) as string;
    const domain = item.sensitive ? secretDomain : plainValues;
    const literal = new Set<string>();
    // Size and work limits throw: the whole retrieval fails, with no values.
    const value = expandReferences(raw, (name) => domain.get(name), false, (name) => literal.add(name));
    entry.value = value;
    if (value !== raw) entry.rawValue = raw;
    if (item.sensitive && item.retiringVersionId) {
      entry.retiring = { versionId: item.retiringVersionId, value: plaintext.get(item.retiringVersionId) as string };
    }
    if (literal.size > 0) unexpanded.push({ name: item.name, references: [...literal].sort() });
    items.push(entry);
  }

  const validation = validateDelivered(state, items, withheld, unexpanded, access);
  return {
    environmentId: env.id,
    ...manifestOf(state),
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
  items: StrictItem[],
  withheld: CallerView["withheld"],
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
  const byName = new Map(items.map((i) => [i.name, i]));
  const withheldByName = new Map(withheld.map((w) => [w.name, w]));
  const literalByName = new Map(unexpanded.map((u) => [u.name, u.references]));
  for (const item of contract.items) {
    const delivered = byName.get(item.name);
    if (!delivered) {
      if (semantics.missingWhenAbsent(item, envCtx)) result.missing.push(item.name);
      continue;
    }
    const denied = withheldByName.get(item.name);
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
        literal.every((name) => byName.get(name)?.sensitive === false);
      result.unresolved.push({ name: item.name, reason: authority ? "authority" : "reference" });
      continue;
    }
    const problem = semantics.validate(item, delivered.value as string);
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
