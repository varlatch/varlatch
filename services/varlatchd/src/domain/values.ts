// SPDX-License-Identifier: AGPL-3.0-or-later
import { CONFIG_ITEM_NAME_PATTERN, semanticsFor, semanticsVersionOf } from "@varlatch/contract";
import { recordAuditEvent } from "../audit/events.js";
import type { Envelope } from "../crypto/aead.js";
import { decryptValue, encryptValue } from "../crypto/hierarchy.js";
import { newId } from "../db/ids.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import {
  activeContractOf,
  MAX_ROTATION_GRACE_SECONDS,
  rotationGraceOf,
  sensitivityOf,
} from "./contracts.js";
import { isExpired, rootIdOf, type EnvironmentRow } from "./environments.js";
import { DomainError } from "./errors.js";
import { orgKekOf, type OrgRow } from "./orgs.js";
import { expandReferences, referencedNames } from "./references.js";
import type { ProjectRow } from "./projects.js";

interface ValueRow {
  id: string;
  environment_id: string;
  item_name: string;
  current_version_id: string | null;
  deleted_at: string | null;
  retiring_version_id?: string | null;
  rotation_deadline?: string | null;
}

interface VersionRow {
  id: string;
  value_id: string;
  payload: Envelope | string;
  wrapped_dek: Envelope | string;
  previous_version_id: string | null;
}

export function decryptVersion(
  ctx: AppCtx,
  org: OrgRow,
  item: { valueRowId: string; versionId: string },
): Promise<string> {
  return ctx.db
    .query("SELECT * FROM value_versions WHERE id = $1", [item.versionId])
    .then((res) => {
      const version = res.rows[0] as VersionRow | undefined;
      if (!version) throw new DomainError("INTERNAL", "Missing value version");
      return decryptValue(orgKekOf(ctx, org), org.id, item.valueRowId, item.versionId, {
        payload: envelope(version.payload),
        wrappedDek: envelope(version.wrapped_dek),
      }).toString("utf8");
    });
}

function envelope(v: Envelope | string): Envelope {
  return typeof v === "string" ? (JSON.parse(v) as Envelope) : v;
}

function assertNotExpired(env: EnvironmentRow): void {
  if (isExpired(env)) {
    throw new DomainError(
      "ENVIRONMENT_EXPIRED",
      "This environment has expired; retrieval and mutation are disabled until it is deleted or its expiry is changed",
    );
  }
}

export interface SetValueResult {
  versionId: string;
  previousVersionId: string | null;
  itemName: string;
  environmentId: string;
  sensitive: boolean;
}

export async function setValue(
  ctx: AppCtx,
  org: OrgRow,
  project: ProjectRow,
  env: EnvironmentRow,
  itemName: string,
  input: { value: string; expectedVersionId?: string | undefined },
  actorIdentityId: string,
): Promise<SetValueResult> {
  if (!CONFIG_ITEM_NAME_PATTERN.test(itemName)) {
    throw new DomainError("VALIDATION_FAILED", "Invalid Config Item name");
  }
  assertNotExpired(env);
  const orgKek = orgKekOf(ctx, org);
  const contract = await activeContractOf(ctx, project);
  const sensitive = sensitivityOf(contract, itemName);

  return withTx(ctx.db, async (db) => {
    // Serialize all mutations of this environment, including absent rows.
    // The version comparison below runs only after earlier writers commit.
    await db.query("SELECT id FROM environments WHERE id = $1 FOR UPDATE", [env.id]);
    let row = (
      await db.query(
        "SELECT * FROM env_values WHERE environment_id = $1 AND item_name = $2",
        [env.id, itemName],
      )
    ).rows[0] as ValueRow | undefined;
    if (!row) {
      const id = newId("value");
      await db.query(
        "INSERT INTO env_values (id, environment_id, item_name) VALUES ($1,$2,$3)",
        [id, env.id, itemName],
      );
      row = { id, environment_id: env.id, item_name: itemName, current_version_id: null, deleted_at: null };
    }
    if (
      input.expectedVersionId !== undefined &&
      row.current_version_id !== input.expectedVersionId
    ) {
      throw new DomainError("VERSION_CONFLICT", "The value changed since the expected version", {
        currentVersionId: row.current_version_id,
      });
    }
    const versionId = newId("version");
    const encrypted = encryptValue(
      orgKek,
      org.id,
      row.id,
      versionId,
      Buffer.from(input.value, "utf8"),
    );
    await db.query(
      `INSERT INTO value_versions (id, value_id, payload, wrapped_dek, previous_version_id, created_by)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [
        versionId,
        row.id,
        JSON.stringify(encrypted.payload),
        JSON.stringify(encrypted.wrappedDek),
        row.current_version_id,
        actorIdentityId,
      ],
    );
    // A plain write supersedes any in-flight rotation (ADR-0027 §6).
    await db.query(
      `UPDATE env_values
       SET current_version_id = $1, deleted_at = NULL,
           retiring_version_id = NULL, rotation_deadline = NULL, rotation_started_at = NULL
       WHERE id = $2`,
      [versionId, row.id],
    );
    await recordAuditEvent(db, {
      eventType: "value.written",
      decision: "info",
      actorIdentityId,
      organizationId: org.id,
      action: "config.value.write",
      resource: {
        projectId: project.id,
        environmentId: env.id,
        itemName,
        versionId,
        previousVersionId: row.current_version_id,
      },
      metadata: { sensitive },
    });
    return {
      versionId,
      previousVersionId: row.current_version_id,
      itemName,
      environmentId: env.id,
      sensitive,
    };
  });
}

export async function deleteValue(
  ctx: AppCtx,
  org: OrgRow,
  project: ProjectRow,
  env: EnvironmentRow,
  itemName: string,
  actorIdentityId: string,
): Promise<void> {
  assertNotExpired(env);
  await withTx(ctx.db, async (db) => {
    // Serialize all mutations of this environment, including absent rows.
    // The version comparison below runs only after earlier writers commit.
    await db.query("SELECT id FROM environments WHERE id = $1 FOR UPDATE", [env.id]);
    const res = await db.query(
      `UPDATE env_values
       SET deleted_at = now(), current_version_id = NULL,
           retiring_version_id = NULL, rotation_deadline = NULL, rotation_started_at = NULL
       WHERE environment_id = $1 AND item_name = $2 AND deleted_at IS NULL
       RETURNING id`,
      [env.id, itemName],
    );
    if (!res.rows[0]) {
      throw new DomainError("RESOURCE_NOT_FOUND", "Value not found");
    }
    await recordAuditEvent(db, {
      eventType: "value.deleted",
      decision: "info",
      actorIdentityId,
      organizationId: org.id,
      action: "config.value.write",
      resource: { projectId: project.id, environmentId: env.id, itemName },
    });
  });
}

export interface RotationResult {
  itemName: string;
  environmentId: string;
  primaryVersionId: string;
  retiringVersionId: string | null;
  rotationDeadline: string | null;
  sensitive: boolean;
}

/**
 * Begin a dual-phase rotation (ADR-0027): write a new primary version and pin
 * the prior primary as retiring for a bounded grace window. Fails if the item
 * has no current value, or a rotation is already in flight (complete it first).
 */
export async function beginRotation(
  ctx: AppCtx,
  org: OrgRow,
  project: ProjectRow,
  env: EnvironmentRow,
  itemName: string,
  input: { value: string; expectedVersionId?: string | undefined; graceSeconds?: number | undefined },
  actorIdentityId: string,
): Promise<RotationResult> {
  if (!CONFIG_ITEM_NAME_PATTERN.test(itemName)) {
    throw new DomainError("VALIDATION_FAILED", "Invalid Config Item name");
  }
  assertNotExpired(env);
  const orgKek = orgKekOf(ctx, org);
  const contract = await activeContractOf(ctx, project);
  const sensitive = sensitivityOf(contract, itemName);
  const grace = Math.min(
    input.graceSeconds ?? rotationGraceOf(contract, itemName),
    MAX_ROTATION_GRACE_SECONDS,
  );

  return withTx(ctx.db, async (db) => {
    // Serialize all mutations of this environment, including absent rows.
    // The version comparison below runs only after earlier writers commit.
    await db.query("SELECT id FROM environments WHERE id = $1 FOR UPDATE", [env.id]);
    const row = (
      await db.query("SELECT * FROM env_values WHERE environment_id = $1 AND item_name = $2", [
        env.id,
        itemName,
      ])
    ).rows[0] as ValueRow | undefined;
    if (!row || row.deleted_at || !row.current_version_id) {
      throw new DomainError("RESOURCE_NOT_FOUND", "No current value to rotate");
    }
    const rotating =
      row.retiring_version_id &&
      row.rotation_deadline &&
      new Date(row.rotation_deadline).getTime() > Date.now();
    if (rotating) {
      throw new DomainError(
        "ROTATION_IN_PROGRESS",
        "A rotation is already in progress for this item; complete it before starting another",
      );
    }
    if (
      input.expectedVersionId !== undefined &&
      row.current_version_id !== input.expectedVersionId
    ) {
      throw new DomainError("VERSION_CONFLICT", "The value changed since the expected version", {
        currentVersionId: row.current_version_id,
      });
    }
    const versionId = newId("version");
    const encrypted = encryptValue(orgKek, org.id, row.id, versionId, Buffer.from(input.value, "utf8"));
    await db.query(
      `INSERT INTO value_versions (id, value_id, payload, wrapped_dek, previous_version_id, created_by)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [
        versionId,
        row.id,
        JSON.stringify(encrypted.payload),
        JSON.stringify(encrypted.wrappedDek),
        row.current_version_id,
        actorIdentityId,
      ],
    );
    const deadline = new Date(Date.now() + grace * 1000).toISOString();
    await db.query(
      `UPDATE env_values
       SET current_version_id = $1, retiring_version_id = $2,
           rotation_deadline = $3, rotation_started_at = now()
       WHERE id = $4`,
      [versionId, row.current_version_id, deadline, row.id],
    );
    await recordAuditEvent(db, {
      eventType: "value.rotation_started",
      decision: "info",
      actorIdentityId,
      organizationId: org.id,
      action: "config.value.write",
      resource: {
        projectId: project.id,
        environmentId: env.id,
        itemName,
        versionId,
        previousVersionId: row.current_version_id,
      },
      metadata: { sensitive, retiring: `${itemName}@${row.current_version_id}`, deadline },
    });
    return {
      itemName,
      environmentId: env.id,
      primaryVersionId: versionId,
      retiringVersionId: row.current_version_id,
      rotationDeadline: deadline,
      sensitive,
    };
  });
}

/**
 * Complete a rotation early (ADR-0027): drop the retiring version. Idempotent
 * — completing a not-rotating item is a no-op success (an elapsed deadline
 * already retired it). Finalizes the row in place.
 */
export async function completeRotation(
  ctx: AppCtx,
  org: OrgRow,
  project: ProjectRow,
  env: EnvironmentRow,
  itemName: string,
  actorIdentityId: string,
): Promise<RotationResult> {
  assertNotExpired(env);
  return withTx(ctx.db, async (db) => {
    // Serialize all mutations of this environment, including absent rows.
    // The version comparison below runs only after earlier writers commit.
    await db.query("SELECT id FROM environments WHERE id = $1 FOR UPDATE", [env.id]);
    const row = (
      await db.query("SELECT * FROM env_values WHERE environment_id = $1 AND item_name = $2", [
        env.id,
        itemName,
      ])
    ).rows[0] as ValueRow | undefined;
    if (!row || row.deleted_at || !row.current_version_id) {
      throw new DomainError("RESOURCE_NOT_FOUND", "No value to complete rotation for");
    }
    const wasRotating = row.retiring_version_id !== null && row.retiring_version_id !== undefined;
    if (wasRotating) {
      await db.query(
        `UPDATE env_values
         SET retiring_version_id = NULL, rotation_deadline = NULL, rotation_started_at = NULL
         WHERE id = $1`,
        [row.id],
      );
      await recordAuditEvent(db, {
        eventType: "value.rotation_completed",
        decision: "info",
        actorIdentityId,
        organizationId: org.id,
        action: "config.value.write",
        resource: { projectId: project.id, environmentId: env.id, itemName, versionId: row.current_version_id },
        metadata: { retired: `${itemName}@${row.retiring_version_id}` },
      });
    }
    return {
      itemName,
      environmentId: env.id,
      primaryVersionId: row.current_version_id,
      retiringVersionId: null,
      rotationDeadline: null,
      sensitive: sensitivityOf(await activeContractOf(ctx, project), itemName),
    };
  });
}

export interface ResolvedItem {
  name: string;
  sensitive: boolean;
  source: "self" | "parent";
  valueRowId: string;
  versionId: string;
  organizationId: string;
  /**
   * Present only while a dual-phase rotation (ADR-0027) is active and its
   * deadline is still in the future: the previous version, still valid.
   */
  retiringVersionId?: string;
}

export async function resolveItems(
  ctx: AppCtx,
  org: OrgRow,
  project: ProjectRow,
  env: EnvironmentRow,
): Promise<ResolvedItem[]> {
  const contract = await activeContractOf(ctx, project);
  const byName = new Map<string, ResolvedItem>();
  const load = async (environmentId: string, source: "self" | "parent") => {
    const res = await ctx.db.query(
      `SELECT id, item_name, current_version_id, retiring_version_id, rotation_deadline
       FROM env_values
       WHERE environment_id = $1 AND deleted_at IS NULL AND current_version_id IS NOT NULL`,
      [environmentId],
    );
    for (const r of res.rows as {
      id: string;
      item_name: string;
      current_version_id: string;
      retiring_version_id: string | null;
      rotation_deadline: string | null;
    }[]) {
      if (source === "parent" && byName.has(r.item_name)) continue;
      // Lazy fail-safe expiry (ADR-0027 §4): an elapsed deadline drops the
      // retiring version from every read without a cleanup worker.
      const rotating =
        r.retiring_version_id !== null &&
        r.rotation_deadline !== null &&
        new Date(r.rotation_deadline).getTime() > Date.now();
      byName.set(r.item_name, {
        name: r.item_name,
        sensitive: sensitivityOf(contract, r.item_name),
        source,
        valueRowId: r.id,
        versionId: r.current_version_id,
        organizationId: org.id,
        ...(rotating ? { retiringVersionId: r.retiring_version_id as string } : {}),
      });
    }
  };
  await load(env.id, "self");
  if (env.parent_environment_id) await load(env.parent_environment_id, "parent");
  return [...byName.values()].sort((a, b) => (a.name < b.name ? -1 : 1));
}

export interface EffectiveItem {
  name: string;
  sensitive: boolean;
  source: "self" | "parent";
  versionId: string;
  /** Present when values were requested and authorized; null when withheld. */
  value: string | null;
  /**
   * The literal stored text, present only when ${NAME} expansion changed
   * `value` — editors must write this back, never the expanded form.
   */
  rawValue?: string;
  /** True while a dual-phase rotation (ADR-0027) is active (metadata only). */
  rotating?: boolean;
}

/**
 * Bulk Effective Configuration (ADR-0012/0017). When values are included, the
 * disclosure audit event commits before plaintext is returned (ADR-0016) and
 * records exactly which item versions were disclosed.
 */
export async function effectiveConfiguration(
  ctx: AppCtx,
  org: OrgRow,
  project: ProjectRow,
  env: EnvironmentRow,
  opts: {
    includeValues: boolean;
    /** Per-item authorization decided by the caller's evaluator results. */
    mayReadValue: (sensitive: boolean) => boolean;
    actorIdentityId: string;
    requestId?: string;
    listener?: "ordinary" | "tailnet";
  },
): Promise<EffectiveItem[]> {
  assertNotExpired(env);
  const items = await resolveItems(ctx, org, project, env);
  if (!opts.includeValues) {
    return items.map((i) => ({
      name: i.name,
      sensitive: i.sensitive,
      source: i.source,
      versionId: i.versionId,
      value: null,
      ...(i.retiringVersionId ? { rotating: true } : {}),
    }));
  }

  const disclosed = items.filter((i) => opts.mayReadValue(i.sensitive));
  // Audit commits before material leaves the process; failure fails disclosure.
  await recordAuditEvent(ctx.db, {
    eventType: "value.disclosed",
    decision: "allow",
    actorIdentityId: opts.actorIdentityId,
    organizationId: org.id,
    action: "config.value.read",
    resource: { projectId: project.id, environmentId: env.id },
    requestId: opts.requestId ?? null,
    listener: opts.listener ?? null,
    metadata: {
      items: disclosed.map((i) => `${i.name}@${i.versionId}`).join(","),
      withheld: items.length - disclosed.length,
    },
  });

  const orgKek = orgKekOf(ctx, org);
  const result: EffectiveItem[] = [];
  for (const item of items) {
    let value: string | null = null;
    if (opts.mayReadValue(item.sensitive)) {
      const res = await ctx.db.query("SELECT * FROM value_versions WHERE id = $1", [
        item.versionId,
      ]);
      const version = res.rows[0] as VersionRow | undefined;
      if (!version) throw new DomainError("INTERNAL", "Missing value version");
      value = decryptValue(orgKek, org.id, item.valueRowId, item.versionId, {
        payload: envelope(version.payload),
        wrappedDek: envelope(version.wrapped_dek),
      }).toString("utf8");
    }
    result.push({
      name: item.name,
      sensitive: item.sensitive,
      source: item.source,
      versionId: item.versionId,
      value,
      ...(item.retiringVersionId ? { rotating: true } : {}),
    });
  }
  // Reference expansion never expands authority: the lookup set is exactly
  // the plaintext this caller receives in this response; anything else
  // (withheld items, Secrets on this path) stays a literal ${NAME}.
  const readable = new Map(
    result.filter((i) => i.value !== null).map((i) => [i.name, i.value as string]),
  );
  for (const item of result) {
    if (item.value !== null) {
      const expanded = expandReferences(item.value, (name) => readable.get(name));
      if (expanded !== item.value) {
        item.rawValue = item.value;
        item.value = expanded;
      }
    }
  }
  return result;
}

/**
 * Whether the caller may learn one class of fact during validation. A
 * denial is "permission"; an unmet Tailnet Requirement is "requirement".
 */
export type ValidationAccess = "allowed" | "permission" | "requirement";

/**
 * Validation verdicts are value-derived: an enum verdict says whether a
 * value is in a list, and repeated Contract changes turn that into a guessing
 * oracle. So each verdict needs the right to read what it describes. Checks
 * are lazy: a class with nothing to evaluate is never authorized (and never
 * records a denial).
 */
export interface ValidationAccessCheck {
  /** Presence of stored values: `config.metadata.read`. */
  metadata: () => Promise<ValidationAccess>;
  /** Verdicts on non-sensitive values: `config.value.read`. */
  plain: () => Promise<ValidationAccess>;
  /** Verdicts on Secrets: `secret.reveal`, including its Requirements. */
  secret: () => Promise<ValidationAccess>;
}

export interface NotEvaluatedItem {
  name: string;
  /** Why, from authorization only; never from the value. */
  reason: "permission" | "requirement";
  requires: "config.metadata.read" | "config.value.read" | "secret.reveal";
}

export interface ValidationResult {
  environmentId: string;
  contractRevisionId: string | null;
  /** True only when every item was evaluated and none is missing or invalid. */
  valid: boolean;
  /** False when any item was not evaluated; `valid` is then false too. */
  complete: boolean;
  missing: string[];
  invalid: { name: string; reason: string }[];
  notEvaluated: NotEvaluatedItem[];
}

/**
 * Continuous validation (ADR-0013): reported, never blocking retrieval.
 *
 * Only items the caller may read are evaluated; the rest are reported as not
 * evaluated with an authorization-derived reason, and never influence
 * `valid`, `missing`, or `invalid`. Every decryption is audited before it
 * happens (autocommitted, as capability exercise does), naming the exact
 * item versions; verdicts themselves are never audited or logged.
 */
export async function validateEnvironment(
  ctx: AppCtx,
  org: OrgRow,
  project: ProjectRow,
  env: EnvironmentRow,
  opts: {
    access: ValidationAccessCheck;
    actorIdentityId: string;
    requestId?: string;
  },
): Promise<ValidationResult> {
  const contract = await activeContractOf(ctx, project);
  const result: ValidationResult = {
    environmentId: env.id,
    contractRevisionId: project.active_contract_revision_id,
    valid: true,
    complete: true,
    missing: [],
    invalid: [],
    notEvaluated: [],
  };
  if (!contract) return result;

  const metadata = await opts.access.metadata();
  if (metadata !== "allowed") {
    result.notEvaluated = contract.items.map((item) => ({
      name: item.name,
      reason: metadata,
      requires: "config.metadata.read",
    }));
    result.complete = false;
    result.valid = false;
    return result;
  }

  const items = await resolveItems(ctx, org, project, env);
  const present = new Map(items.map((i) => [i.name, i]));
  const envCtx = { rootId: rootIdOf(env), tier: env.tier };
  const semantics = semanticsFor(semanticsVersionOf(contract));

  const toCheck: { item: (typeof contract.items)[number]; resolved: ResolvedItem }[] = [];
  const access: Partial<Record<"plain" | "secret", ValidationAccess>> = {};
  for (const item of contract.items) {
    const resolved = present.get(item.name);
    if (!resolved) {
      if (semantics.missingWhenAbsent(item, envCtx)) {
        result.missing.push(item.name);
      }
      continue;
    }
    const kind = item.sensitive ? "secret" : "plain";
    access[kind] ??= await opts.access[kind]();
    const decision = access[kind];
    if (decision === "allowed") {
      toCheck.push({ item, resolved });
    } else {
      result.notEvaluated.push({
        name: item.name,
        reason: decision,
        requires: item.sensitive ? "secret.reveal" : "config.value.read",
      });
    }
  }

  // Audit before decryption: one event per authorization action, naming the
  // exact versions about to be decrypted. No verdicts are recorded.
  for (const sensitive of [true, false]) {
    const batch = toCheck.filter((c) => c.item.sensitive === sensitive);
    if (batch.length === 0) continue;
    await recordAuditEvent(ctx.db, {
      eventType: sensitive ? "secret.validated" : "value.validated",
      decision: "allow",
      actorIdentityId: opts.actorIdentityId,
      organizationId: org.id,
      action: sensitive ? "secret.reveal" : "config.value.read",
      resource: { projectId: project.id, environmentId: env.id },
      requestId: opts.requestId ?? null,
      metadata: {
        purpose: "validation",
        contractRevisionId: project.active_contract_revision_id,
        items: batch.map((c) => `${c.item.name}@${c.resolved.versionId}`).join(","),
      },
    });
  }

  const orgKek = orgKekOf(ctx, org);
  for (const { item, resolved } of toCheck) {
    // Type checks decrypt in-process; no plaintext leaves this function.
    const res = await ctx.db.query("SELECT * FROM value_versions WHERE id = $1", [
      resolved.versionId,
    ]);
    const version = res.rows[0] as VersionRow | undefined;
    if (!version) continue;
    const value = decryptValue(orgKek, org.id, resolved.valueRowId, resolved.versionId, {
      payload: envelope(version.payload),
      wrappedDek: envelope(version.wrapped_dek),
    }).toString("utf8");
    const problem = semantics.validate(item, value);
    if (problem) result.invalid.push({ name: item.name, reason: problem });
  }
  result.complete = result.notEvaluated.length === 0;
  result.valid = result.complete && result.missing.length === 0 && result.invalid.length === 0;
  return result;
}

// ---------------------------------------------------------------------------
// Atomic change sets (dashboard design R2): one reviewed save = one
// transaction. All expected-version guards (for sets AND deletes) validate
// before any mutation; any conflict rejects the whole set with entitled
// metadata only. Per-item audit events remain authoritative and share a
// changeSetId correlation (operational metadata, not a domain resource).

export type ValueChange =
  | { op: "set"; item: string; value: string; expectedVersionId?: string | undefined }
  | { op: "delete"; item: string; expectedVersionId?: string | undefined };

export interface ChangeSetResult {
  changeSetId: string;
  results: { item: string; op: "set" | "delete"; versionId: string | null }[];
}

export async function applyChangeSet(
  ctx: AppCtx,
  org: OrgRow,
  project: ProjectRow,
  env: EnvironmentRow,
  changes: ValueChange[],
  actorIdentityId: string,
  requestId?: string,
): Promise<ChangeSetResult> {
  assertNotExpired(env);
  if (changes.length === 0) {
    throw new DomainError("VALIDATION_FAILED", "Change set is empty");
  }
  const seen = new Set<string>();
  for (const change of changes) {
    if (!CONFIG_ITEM_NAME_PATTERN.test(change.item)) {
      throw new DomainError("VALIDATION_FAILED", `Invalid Config Item name: ${change.item}`);
    }
    if (seen.has(change.item)) {
      throw new DomainError("VALIDATION_FAILED", `Duplicate Config Item in change set: ${change.item}`);
    }
    seen.add(change.item);
  }
  const orgKek = orgKekOf(ctx, org);
  const contract = await activeContractOf(ctx, project);
  const changeSetId = newId("version").replace("ver_", "cs_");

  return withTx(ctx.db, async (db) => {
    // Serialize all mutations of this environment, including absent rows.
    // The version comparison below runs only after earlier writers commit.
    await db.query("SELECT id FROM environments WHERE id = $1 FOR UPDATE", [env.id]);
    // Phase 1: load current rows and validate every guard before mutating.
    const rows = new Map<string, ValueRow | undefined>();
    const conflicts: { item: string; currentVersionId: string | null }[] = [];
    for (const change of changes) {
      const row = (
        await db.query(
          "SELECT * FROM env_values WHERE environment_id = $1 AND item_name = $2",
          [env.id, change.item],
        )
      ).rows[0] as ValueRow | undefined;
      rows.set(change.item, row);
      const current = row?.deleted_at ? null : (row?.current_version_id ?? null);
      if (change.expectedVersionId !== undefined && current !== change.expectedVersionId) {
        conflicts.push({ item: change.item, currentVersionId: current });
      }
      if (change.op === "delete" && (current === null || row?.deleted_at)) {
        if (change.expectedVersionId === undefined) {
          conflicts.push({ item: change.item, currentVersionId: null });
        }
      }
    }
    if (conflicts.length > 0) {
      throw new DomainError(
        "VERSION_CONFLICT",
        "One or more values changed since they were reviewed; nothing was written",
        { conflicts },
      );
    }

    // Phase 2: apply all.
    const results: ChangeSetResult["results"] = [];
    for (const change of changes) {
      let row = rows.get(change.item);
      if (change.op === "set") {
        if (!row) {
          const id = newId("value");
          await db.query(
            "INSERT INTO env_values (id, environment_id, item_name) VALUES ($1,$2,$3)",
            [id, env.id, change.item],
          );
          row = { id, environment_id: env.id, item_name: change.item, current_version_id: null, deleted_at: null };
        }
        const versionId = newId("version");
        const encrypted = encryptValue(orgKek, org.id, row.id, versionId, Buffer.from(change.value, "utf8"));
        await db.query(
          `INSERT INTO value_versions (id, value_id, payload, wrapped_dek, previous_version_id, created_by)
           VALUES ($1,$2,$3,$4,$5,$6)`,
          [versionId, row.id, JSON.stringify(encrypted.payload), JSON.stringify(encrypted.wrappedDek), row.deleted_at ? null : row.current_version_id, actorIdentityId],
        );
        await db.query(
          `UPDATE env_values
           SET current_version_id = $1, deleted_at = NULL,
               retiring_version_id = NULL, rotation_deadline = NULL, rotation_started_at = NULL
           WHERE id = $2`,
          [versionId, row.id],
        );
        await recordAuditEvent(db, {
          eventType: "value.written",
          decision: "info",
          actorIdentityId,
          organizationId: org.id,
          action: "config.value.write",
          resource: {
            projectId: project.id,
            environmentId: env.id,
            itemName: change.item,
            versionId,
            previousVersionId: row.deleted_at ? null : row.current_version_id,
          },
          requestId: requestId ?? null,
          metadata: { sensitive: sensitivityOf(contract, change.item), changeSetId },
        });
        results.push({ item: change.item, op: "set", versionId });
      } else {
        await db.query(
          `UPDATE env_values
           SET deleted_at = now(), current_version_id = NULL,
               retiring_version_id = NULL, rotation_deadline = NULL, rotation_started_at = NULL
           WHERE id = $1`,
          [(row as ValueRow).id],
        );
        await recordAuditEvent(db, {
          eventType: "value.deleted",
          decision: "info",
          actorIdentityId,
          organizationId: org.id,
          action: "config.value.write",
          resource: { projectId: project.id, environmentId: env.id, itemName: change.item },
          requestId: requestId ?? null,
          metadata: { changeSetId },
        });
        results.push({ item: change.item, op: "delete", versionId: null });
      }
    }
    return { changeSetId, results };
  });
}

// ---------------------------------------------------------------------------
// Requested Secret disclosure (dashboard design R2): an explicit POST-class
// security operation. The caller declares items or an intentional
// all-authorized-secrets scope; one audit event enumerates exactly what was
// returned, committed before plaintext leaves the process (ADR-0016).

export interface DisclosureRequest {
  items?: string[] | undefined;
  scope?: "all-authorized-secrets" | undefined;
}

export interface DisclosureResult {
  items: {
    name: string;
    versionId: string;
    value: string;
    /**
     * The previous value during a dual-phase rotation (ADR-0027), still
     * valid — consumers accept either during the window. Absent when stable.
     */
    retiring?: { versionId: string; value: string };
  }[];
  /** Requested but not disclosed (unknown, non-sensitive, or unauthorized). */
  withheld: string[];
}

export async function discloseSecrets(
  ctx: AppCtx,
  org: OrgRow,
  project: ProjectRow,
  env: EnvironmentRow,
  request: DisclosureRequest,
  opts: {
    actorIdentityId: string;
    requestId?: string | undefined;
    listener?: "ordinary" | "tailnet" | undefined;
    /**
     * Whether the caller also holds config.value.read here: only then may
     * reference expansion pull NON-SENSITIVE values into disclosed secrets.
     */
    mayReadPlain?: boolean | undefined;
  },
): Promise<DisclosureResult> {
  assertNotExpired(env);
  if (!request.scope && (!request.items || request.items.length === 0)) {
    throw new DomainError(
      "VALIDATION_FAILED",
      'Declare requested "items" or scope "all-authorized-secrets" explicitly',
    );
  }
  const resolved = await resolveItems(ctx, org, project, env);
  const secrets = resolved.filter((i) => i.sensitive);
  const byName = new Map(secrets.map((i) => [i.name, i]));

  let selected: ResolvedItem[];
  let withheld: string[] = [];
  if (request.scope === "all-authorized-secrets") {
    selected = secrets;
  } else {
    selected = [];
    for (const name of request.items as string[]) {
      const item = byName.get(name);
      if (item) selected.push(item);
      else withheld.push(name);
    }
  }

  // Audit commits before plaintext is returned; enumerates exact versions.
  await recordAuditEvent(ctx.db, {
    eventType: "secret.disclosed",
    decision: "allow",
    actorIdentityId: opts.actorIdentityId,
    organizationId: org.id,
    action: "secret.reveal",
    resource: { projectId: project.id, environmentId: env.id },
    requestId: opts.requestId ?? null,
    listener: opts.listener ?? null,
    metadata: {
      mode: request.scope ?? "requested",
      items: selected
        .map((i) => (i.retiringVersionId ? `${i.name}@${i.versionId}+${i.retiringVersionId}` : `${i.name}@${i.versionId}`))
        .join(","),
      withheld: withheld.length,
    },
  });

  const orgKek = orgKekOf(ctx, org);
  const decryptOne = async (valueRowId: string, versionId: string): Promise<string> => {
    const res = await ctx.db.query("SELECT * FROM value_versions WHERE id = $1", [versionId]);
    const version = res.rows[0] as VersionRow | undefined;
    if (!version) throw new DomainError("INTERNAL", "Missing value version");
    return decryptValue(orgKek, org.id, valueRowId, versionId, {
      payload: envelope(version.payload),
      wrappedDek: envelope(version.wrapped_dek),
    }).toString("utf8");
  };
  const decrypt = (item: ResolvedItem): Promise<string> =>
    decryptOne(item.valueRowId, item.versionId);

  const items: DisclosureResult["items"] = [];
  const lookup = new Map<string, string>();
  for (const item of selected) {
    const value = await decrypt(item);
    lookup.set(item.name, value);
    // Rotation: expose the retiring version so consumers accept both during
    // the window. References always resolve to primaries (ADR-0027 §2), so
    // the retiring copy is returned literal (unexpanded).
    const retiring = item.retiringVersionId
      ? {
          versionId: item.retiringVersionId,
          value: await decryptOne(item.valueRowId, item.retiringVersionId),
        }
      : undefined;
    items.push({ name: item.name, versionId: item.versionId, value, ...(retiring ? { retiring } : {}) });
  }

  // Reference expansion (never authority expansion): disclosed Secrets may
  // reference each other, and — only when the caller also holds
  // config.value.read — non-sensitive items of the same environment.
  // Anything else stays a literal ${NAME}. The plain sources are resolved
  // as a closure (a referenced plain value may itself reference further
  // plain values) and audited before their plaintext is used (ADR-0016).
  if (opts.mayReadPlain) {
    const plainByName = new Map(resolved.filter((i) => !i.sensitive).map((i) => [i.name, i]));
    const needed: ResolvedItem[] = [];
    const queued = new Set<string>();
    const enqueue = (raw: string) => {
      for (const name of referencedNames(raw)) {
        const plain = plainByName.get(name);
        if (plain && !lookup.has(name) && !queued.has(name)) {
          queued.add(name);
          needed.push(plain);
        }
      }
    };
    for (const value of lookup.values()) enqueue(value);
    if (needed.length > 0) {
      const sources: { item: ResolvedItem; value: string }[] = [];
      for (let i = 0; i < needed.length; i++) {
        const item = needed[i] as ResolvedItem;
        const value = await decrypt(item);
        sources.push({ item, value });
        enqueue(value);
      }
      await recordAuditEvent(ctx.db, {
        eventType: "value.disclosed",
        decision: "allow",
        actorIdentityId: opts.actorIdentityId,
        organizationId: org.id,
        action: "config.value.read",
        resource: { projectId: project.id, environmentId: env.id },
        requestId: opts.requestId ?? null,
        listener: opts.listener ?? null,
        metadata: {
          mode: "reference-expansion",
          items: sources.map((s) => `${s.item.name}@${s.item.versionId}`).join(","),
        },
      });
      for (const s of sources) lookup.set(s.item.name, s.value);
    }
  }
  for (const item of items) {
    item.value = expandReferences(item.value, (name) => lookup.get(name));
  }
  return { items, withheld };
}
