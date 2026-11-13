// SPDX-License-Identifier: AGPL-3.0-or-later
import { lockedQuery } from "../db/locks.js";
import type { Querier } from "../db/migrate.js";
import { labelWithId, quotedList } from "./approvallabels.js";
import type { ApprovalBinding, ProtectedGate } from "./approvals.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";
import { approvalMetadata, prepareProtectedOperation } from "./protected.js";
import { resolveItems, type CapturedState, type ResolvedItem } from "./retrieval.js";

/**
 * admin-step-up for an export (ADR-0054 Decision 5, step 4.9, amendment
 * C): a Secret disclosure with `purpose: "export"`, the dashboard's `.env`
 * download.
 *
 * The binding (binding catalogue, `secret.export`): target the Project and
 * the environment; body the purpose, the selection mode, the requested
 * names (`items` mode only, sorted and without duplicates) and the exact,
 * sorted set of Secret names to be disclosed; query `{}`; no version. The
 * values are what is disclosed and are never bound. "All authorized"
 * approves that exact set, not a selector: a Secret created or a Grant
 * added after the intent changes the set, and the approval no longer
 * matches. Reference expansion and the non-sensitive values of the same
 * file are value reads: they stay exempt and outside the binding.
 *
 * An export is authorized in a read-only snapshot (retrieval.ts) and an
 * approval is consumed in a writable transaction, so an export under
 * `enforce` has two phases:
 *
 * 1. the snapshot captures the authorization, the selection and the
 *    versions, as for any disclosure, and writes nothing;
 * 2. the disclosure's audit transaction (exportGuard), before anything is
 *    decrypted, in amendment E's lock order:
 *    1. the Organization FOR KEY SHARE (a pending deletion still allows
 *       reads; an incident freeze refuses), then the control's mode;
 *    2. the requester FOR UPDATE, then the consumption (the intent, the
 *       session, the credential, which is revalidated);
 *    3. the Project FOR SHARE, then the environment and its parent FOR
 *       SHARE in id order: a value write (FOR NO KEY UPDATE on its
 *       environment) or a Contract activation (FOR NO KEY UPDATE on the
 *       Project) either committed before this point or waits until this
 *       transaction ends;
 *    4. the freshness check, against the live rows and the live clock
 *       (clock_timestamp(), read after the locks): every disclosed name
 *       resolves now exactly as it was captured (freshnessOf);
 *    5. `secret.reveal` decided again for the caller (the route's
 *       callback);
 *    6. the report count, then the disclosure's audit event, with the
 *       approval's id.
 *    It commits, then the captured ciphertext is decrypted. A stale capture
 *    answers STATE_CHANGED before the commit and before any decryption:
 *    the consumption rolls back with the rest, so the approval stays
 *    usable, and the client repeats the request with it, which makes a
 *    fresh capture.
 *
 * passkey-verification (ADR-0054 Decision 7) is decided twice on this path,
 * by design:
 * - in the snapshot, as for every disclosure (the route's checkpoint, after
 *   the existence checks and terminal Tailnet denials): it decides the
 *   request, and it is what an export without an approval (the control
 *   `off` or at `report`) is decided by, never read again;
 * - under `enforce`, again in phase 2, by prepareProtectedOperation, under
 *   the Organization lock and before the binding: phase 2 is a write (it
 *   consumes an approval, or fails into creating an intent), so Decision 2's
 *   rule for writes applies there, as for every other protected write. It
 *   gives the same answer as the snapshot unless the requester's outcome
 *   changed in between (passkey-verification turned on or tightened, the
 *   passkey's trust or the sign-in's evidence changed); then it refuses
 *   before any consumption, intent, audit or decryption. A requester it
 *   refuses never gets an approval intent.
 *
 * Without an approval the phase-2 transaction rolls back and withApproval
 * creates the intent in a transaction of its own: never inside the
 * snapshot. A machine credential is refused without one. When the snapshot
 * did not see the control at `enforce`, phase 2 is today's audit
 * transaction, unchanged: no extra locks and no freshness check (the
 * route takes this path only for a snapshot that saw `enforce`; a control
 * turned on after the snapshot began does not affect it, as for every
 * other authorization input of a retrieval, Decision 2).
 */

export interface ExportRequest {
  items?: string[] | undefined;
  scope?: "all-authorized-secrets" | undefined;
}

const sortedUnique = (names: readonly string[]) => [...new Set(names)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

/** secret.export of a capture: null when it discloses no Secret, which needs no approval. */
export function exportBinding(state: CapturedState, request: ExportRequest, selected: readonly ResolvedItem[]): ApprovalBinding | null {
  const disclosed = sortedUnique(selected.map((i) => i.name));
  if (disclosed.length === 0) return null;
  const all = request.scope === "all-authorized-secrets";
  const requested = all ? null : sortedUnique(request.items ?? []);
  const where = `${labelWithId("project", state.project.name, state.project.id)} / ${labelWithId("environment", state.env.name, state.env.id)}`;
  const count = `${disclosed.length} Secret${disclosed.length === 1 ? "" : "s"}`;
  return {
    operation: "secret.export",
    organizationId: state.org.id,
    target: { projectId: state.project.id, environmentId: state.env.id },
    body: { purpose: "export", mode: all ? "all-authorized-secrets" : "items", requested, disclosed },
    query: {},
    expectedVersion: null,
    summary: {
      title: `Export ${count} of ${where} to a file: ${quotedList(disclosed)}`,
      changes: [
        { field: "selection", from: null, to: all ? "every Secret you may reveal" : "the Secrets requested", loosens: false },
        ...(requested ? [{ field: "requested", from: null, to: quotedList(requested), loosens: false }] : []),
        { field: "disclosed", from: null, to: quotedList(disclosed), loosens: false },
      ],
    },
  };
}

/** The refusal of a stale capture: nothing committed, nothing decrypted, the approval still usable. */
export function staleCapture(approvalId: string, what: string): DomainError {
  return new DomainError(
    "STATE_CHANGED",
    `The values changed since this export read them (${what}). Nothing was disclosed, and the approval was not used: repeat the request with it`,
    { reason: "stale-capture", approvalId },
  );
}

interface LiveEnvironment {
  id: string;
  deleted_at: string | Date | null;
  expires_at: string | Date | null;
}

/**
 * Why the capture is stale now, or null when every disclosed name resolves
 * exactly as captured, under the Project and environment locks the caller
 * holds and the live clock read after them:
 *
 * - the environment and its parent are live and not expired;
 * - the Project's active Contract Revision is the captured one, so the set
 *   of Secrets is the same;
 * - per disclosed name, resolved as a capture does (resolveItems: the
 *   environment's own values, then its parent's for names it does not set):
 *   the same source environment and value row (a child override created or
 *   removed changes it), the same current version, and the same retiring
 *   version, present exactly when it was captured (one counts only while
 *   its rotation deadline is after the live clock).
 */
async function freshnessOf(ctx: AppCtx, db: Querier, state: CapturedState, selected: readonly ResolvedItem[]): Promise<string | null> {
  const now = new Date(((await db.query("SELECT clock_timestamp() AS now")).rows[0] as { now: string | Date }).now);
  const project = (await db.query("SELECT active_contract_revision_id, deleted_at FROM projects WHERE id = $1", [state.project.id]))
    .rows[0] as { active_contract_revision_id: string | null; deleted_at: string | Date | null } | undefined;
  if (!project || project.deleted_at) return "the project was deleted";
  if (project.active_contract_revision_id !== (state.revision?.id ?? null)) return "a new Contract Revision was activated";
  const envIds = [state.env.id, ...(state.env.parent_environment_id ? [state.env.parent_environment_id] : [])];
  const envs = (await db.query("SELECT id, deleted_at, expires_at FROM environments WHERE id = ANY($1)", [envIds])).rows as LiveEnvironment[];
  for (const id of envIds) {
    const live = envs.find((e) => e.id === id);
    if (!live || live.deleted_at) return "the environment was deleted";
    if (live.expires_at !== null && new Date(live.expires_at).getTime() <= now.getTime()) return "the environment expired";
  }
  const resolved = new Map((await resolveItems({ ...ctx, db }, state.org, state.env, state.contract, now)).map((i) => [i.name, i]));
  for (const captured of selected) {
    const item = resolved.get(captured.name);
    if (!item) return `${JSON.stringify(captured.name)} has no value now`;
    if (item.source !== captured.source || item.valueRowId !== captured.valueRowId) {
      return `${JSON.stringify(captured.name)} comes from another environment now`;
    }
    if (item.versionId !== captured.versionId) return `${JSON.stringify(captured.name)} has a new value`;
    if ((item.retiringVersionId ?? null) !== (captured.retiringVersionId ?? null)) {
      return `${JSON.stringify(captured.name)} started or ended a rotation`;
    }
  }
  return null;
}

/**
 * Phase 2 of an export the snapshot saw under `enforce` (see the top of
 * this file): run inside the disclosure's audit transaction, before its
 * exposure rows and audit insert. Returns what the audit event adds (the
 * approval's id), or throws: ApprovalNeeded (rolled back; withApproval
 * creates the intent), STATE_CHANGED for a stale capture, or the refusal of
 * the recheck.
 */
export function exportGuard(
  ctx: AppCtx,
  gate: ProtectedGate,
  state: CapturedState,
  request: ExportRequest,
  selected: readonly ResolvedItem[],
  reauthorize: (db: Querier) => Promise<void>,
): (db: Querier) => Promise<Record<string, string | boolean>> {
  return async (db) => {
    // Steps 1, 2, 4, 6 and 7: the Organization (a pending deletion allows
    // reads, an incident freeze refuses), the controls under it, the
    // passkey-verification checkpoint under that lock (see the top of this
    // file), the requester (FOR UPDATE when consuming), the consumption.
    const prepared = await prepareProtectedOperation(db, gate, {
      scope: { organizationId: state.org.id, allowFrozen: true, people: [gate.requester.identityId] },
      checks: [{ control: "admin-step-up", operation: "secret.export" }],
      binding: async () => exportBinding(state, request, selected),
    });
    if (prepared.approval) {
      // Steps 8 and 9: the Project, then the environment and its parent in
      // id order, FOR SHARE.
      await lockedQuery(db, { table: "projects", mode: "share", key: "$1" }, "SELECT 1 FROM projects WHERE id = $1 FOR SHARE", [state.project.id]);
      const envIds = [state.env.id, ...(state.env.parent_environment_id ? [state.env.parent_environment_id] : [])].sort();
      await lockedQuery(db, { table: "environments", mode: "share" }, "SELECT id FROM environments WHERE id = ANY($1) ORDER BY id FOR SHARE", [envIds]);
      const stale = await freshnessOf(ctx, db, state, selected);
      if (stale) throw staleCapture(prepared.approval.id, stale);
      await reauthorize(db);
    }
    await prepared.count(db);
    return approvalMetadata(prepared.approval);
  };
}

/**
 * admin-step-up's mode and version for an export, read in the retrieval
 * snapshot like every other input it decides on; null when it is off.
 */
export async function exportControl(db: Querier, organizationId: string): Promise<{ mode: "report" | "enforce"; version: number } | null> {
  const row = (await db.query(
    "SELECT mode, version FROM security_controls WHERE organization_id = $1 AND control = 'admin-step-up' AND mode <> 'off'",
    [organizationId],
  )).rows[0] as { mode: "report" | "enforce"; version: number } | undefined;
  return row ? { mode: row.mode, version: Number(row.version) } : null;
}
