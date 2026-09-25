// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ConfigurationContract } from "@varlatch/contract";
import { recordAuditEvent, type AuditEventInput } from "../audit/events.js";
import type { Envelope } from "../crypto/aead.js";
import { decryptValue } from "../crypto/hierarchy.js";
import { withSnapshot, withTx } from "../db/tx.js";
import { getRevision, sensitivityOf, type ContractRevisionRow } from "./contracts.js";
import type { AppCtx } from "./ctx.js";
import type { EnvironmentRow } from "./environments.js";
import { DomainError } from "./errors.js";
import { orgKekOf, type OrgRow } from "./orgs.js";
import type { ProjectRow } from "./projects.js";

/**
 * Two-phase retrieval (ADR-0038 Decision 6).
 *
 * 1. Snapshot: one read-only REPEATABLE READ transaction performs every read
 *    a retrieval depends on (scope rows, authorization inputs, the Contract
 *    Revision, values, and the ciphertext of every version it could decrypt)
 *    and evaluates authorization without writing.
 * 2. Audit and decryption: each decryption is preceded by the audit commit
 *    that names its exact version, level by level for reference-expansion
 *    inputs. A failed commit stops the request. Nothing is read again.
 *
 * Authorization is therefore effective at the snapshot boundary: a
 * revocation that commits after a request's snapshot began does not affect
 * that request, and the next request sees it.
 */

export interface ResolvedItem {
  name: string;
  sensitive: boolean;
  source: "self" | "parent";
  valueRowId: string;
  versionId: string;
  organizationId: string;
  /**
   * Present only while a dual-phase rotation (ADR-0027) is active and its
   * deadline is still in the future at the snapshot's "now".
   */
  retiringVersionId?: string;
}

interface Ciphertext {
  valueRowId: string;
  payload: Envelope;
  wrappedDek: Envelope;
}

/** Everything a retrieval read, from one snapshot. */
export interface CapturedState {
  /** The snapshot's transaction time: the request's only clock. */
  now: Date;
  org: OrgRow;
  project: ProjectRow;
  env: EnvironmentRow;
  revision: ContractRevisionRow | null;
  contract: ConfigurationContract | null;
  items: ResolvedItem[];
  /** Immutable ciphertext, by version ID, of every version the request could decrypt. */
  ciphertext: Map<string, Ciphertext>;
}

/** Run the snapshot phase with a context whose every read sees one snapshot. */
export function inSnapshot<T>(ctx: AppCtx, read: (sctx: AppCtx, now: Date) => Promise<T>): Promise<T> {
  return withSnapshot(ctx.db, (db, now) => read({ ...ctx, db }, now));
}

export function envelope(v: Envelope | string): Envelope {
  return typeof v === "string" ? (JSON.parse(v) as Envelope) : v;
}

function parseContract(row: ContractRevisionRow): ConfigurationContract {
  return typeof row.contract === "string" ? (JSON.parse(row.contract) as ConfigurationContract) : row.contract;
}

/**
 * The Environment's effective values at `now`: its own, then its parent's
 * for names it does not set. A retiring version is included only while its
 * rotation deadline is still in the future (lazy fail-safe expiry, ADR-0027 §4).
 */
export async function resolveItems(
  ctx: AppCtx,
  org: OrgRow,
  env: EnvironmentRow,
  contract: ConfigurationContract | null,
  now: Date,
): Promise<ResolvedItem[]> {
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
      rotation_deadline: string | Date | null;
    }[]) {
      if (source === "parent" && byName.has(r.item_name)) continue;
      const rotating =
        r.retiring_version_id !== null &&
        r.rotation_deadline !== null &&
        new Date(r.rotation_deadline).getTime() > now.getTime();
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

/**
 * Capture a retrieval's state inside the snapshot: the active Contract
 * Revision, the resolved items, and the ciphertext of every version of the
 * items `wants` selects (primary and, while open, retiring). Which references
 * a value contains is known only after decryption, so callers select every
 * item a reference could reach within the caller's delivery domain.
 */
export async function captureState(
  sctx: AppCtx,
  scope: { org: OrgRow; project: ProjectRow; env: EnvironmentRow },
  now: Date,
  wants: (item: ResolvedItem) => boolean,
): Promise<CapturedState> {
  const { org, project, env } = scope;
  const revision = project.active_contract_revision_id
    ? await getRevision(sctx, project.id, project.active_contract_revision_id)
    : null;
  const contract = revision ? parseContract(revision) : null;
  const items = await resolveItems(sctx, org, env, contract, now);
  const valueRowOf = new Map<string, string>();
  for (const item of items.filter(wants)) {
    valueRowOf.set(item.versionId, item.valueRowId);
    if (item.retiringVersionId) valueRowOf.set(item.retiringVersionId, item.valueRowId);
  }
  const ciphertext = new Map<string, Ciphertext>();
  if (valueRowOf.size > 0) {
    const res = await sctx.db.query(
      "SELECT id, payload, wrapped_dek FROM value_versions WHERE id = ANY($1)",
      [[...valueRowOf.keys()]],
    );
    for (const r of res.rows as { id: string; payload: Envelope | string; wrapped_dek: Envelope | string }[]) {
      ciphertext.set(r.id, {
        valueRowId: valueRowOf.get(r.id) as string,
        payload: envelope(r.payload),
        wrappedDek: envelope(r.wrapped_dek),
      });
    }
  }
  return { now, org, project, env, revision, contract, items, ciphertext };
}

/**
 * Commit `events`, then decrypt exactly `versionIds` from the captured
 * ciphertext. The events are committed together before any decryption
 * starts; if the commit fails, nothing is decrypted and the error stops the
 * request. Nothing is read from the database.
 */
export async function auditThenDecrypt(
  ctx: AppCtx,
  state: CapturedState,
  events: AuditEventInput[],
  versionIds: string[],
): Promise<Map<string, string>> {
  if (events.length > 0) {
    await withTx(ctx.db, async (db) => {
      for (const event of events) await recordAuditEvent(db, event);
    });
  }
  const orgKek = orgKekOf(ctx, state.org);
  const plaintext = new Map<string, string>();
  for (const versionId of versionIds) {
    const captured = state.ciphertext.get(versionId);
    if (!captured) throw new DomainError("INTERNAL", "A value version was not captured in the retrieval snapshot");
    plaintext.set(
      versionId,
      decryptValue(orgKek, state.org.id, captured.valueRowId, versionId, {
        payload: captured.payload,
        wrappedDek: captured.wrappedDek,
      }).toString("utf8"),
    );
  }
  return plaintext;
}
