// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHmac } from "node:crypto";
import { getAdapter, type NameOutcome, type SyncItem } from "@varlatch/sync";
import { recordAuditEvent } from "../audit/events.js";
import type { Envelope } from "../crypto/aead.js";
import { decryptPlatformCredential, decryptValue, syncFingerprintKey } from "../crypto/hierarchy.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { isExpired, type EnvironmentRow } from "./environments.js";
import { orgKekOf, type OrgRow } from "./orgs.js";
import type { ProjectRow } from "./projects.js";
import { ReferenceExpansionError, expandReferences } from "./references.js";
import { activeContractOf } from "./contracts.js";
import { DomainError } from "./errors.js";
import { envelope, resolveItems } from "./retrieval.js";
import {
  recordCredentialExpiry,
  describeDestination,
  matchesExclusion,
  targetRow,
  TARGET_COLUMNS,
  type SyncMapping,
  type SyncTargetRow,
} from "./sync.js";

/**
 * Sync Target reconciliation (ADR-0031 §3-7): converge each destination to
 * the Target's current effective output. Never replays deltas; diffs keyed
 * fingerprints against the per-destination ledger; intent precedes the wire;
 * per-Target leases with monotonically increasing generations fence stale
 * runs; a low-frequency repair pass force-writes (or verify-and-fixes) and
 * re-applies tombstoned deletions. Failures never throw out of the loop and
 * never block Secret Plane operations.
 */

const LEASE_TTL_SECONDS = 300; // far above the 10s per-request timeout (§4)
const BASE_BACKOFF_MS = 30_000;
const MAX_BACKOFF_MS = 3_600_000;
const FAILURE_BUDGET = 10;
const SCAN_BATCH = 500;
export const REPAIR_INTERVAL_MS = 6 * 3_600_000;

/** Connection + org facts, read AFTER lease acquisition — never from the batch. */
interface LiveConnection {
  platform: string;
  base_identity: string;
  credential_envelope: Envelope | string;
  wrapped_org_kek: Envelope | string;
  connection_revoked_at: string | null;
  /** The Connection's version this run's credential was read at. */
  connection_version: number;
  /** When the platform said, during this run, the credential expires. */
  observed_expiry?: string;
}

interface LedgerRow {
  dest_name: string;
  fingerprint: string | null;
  state: string;
  generation: string | number;
}

export interface SyncRunOptions {
  fetchImpl?: typeof fetch | undefined;
  repairIntervalMs?: number | undefined;
  /** Which adapters this Installation allows (VARLATCH_SYNC_ADAPTERS). */
  allowedAdapters?: string[] | undefined;
}

// ---------------------------------------------------------------------------
// Trigger scan: anything that changes what a Target would push (§6). The
// cursor walks audit_events excluding sync.* (delivery never triggers
// delivery); Target mutations never travel through here — their transactions
// set needs_sync directly.

export async function scanSyncTriggers(ctx: AppCtx): Promise<void> {
  await ctx.db.query(
    `INSERT INTO sync_cursor (singleton, occurred_at, event_id)
     VALUES (true, now(), '') ON CONFLICT (singleton) DO NOTHING`,
  );
  const cursor = (
    await ctx.db.query("SELECT cursor_order FROM sync_cursor WHERE singleton")
  ).rows[0] as { cursor_order: string };
  const events = await ctx.db.query(
    `SELECT id, occurred_at, event_order::text, event_type, resource FROM audit_events
     WHERE event_order > $1 AND event_type NOT LIKE 'sync.%'
     ORDER BY event_order LIMIT $2`,
    [cursor.cursor_order, SCAN_BATCH],
  );
  const rows = events.rows as { id: string; occurred_at: string; event_order: string; event_type: string; resource: unknown }[];
  if (rows.length === 0) return;

  const environmentIds = new Set<string>();
  const projectIds = new Set<string>();
  for (const row of rows) {
    const resource = (
      typeof row.resource === "string" ? JSON.parse(row.resource) : row.resource
    ) as Record<string, string | null> | null;
    if (!resource) continue;
    if (resource.environmentId) environmentIds.add(resource.environmentId);
    // Contract activation feeds defaults and sensitivity project-wide.
    else if (resource.projectId && row.event_type.startsWith("contract.")) {
      projectIds.add(resource.projectId);
    }
  }
  if (environmentIds.size > 0 || projectIds.size > 0) {
    // A write in a root parent triggers Targets of derived children (§6).
    await ctx.db.query(
      `UPDATE sync_targets SET needs_sync = true
       WHERE revoked_at IS NULL AND NOT needs_sync AND (
         environment_id = ANY($1)
         OR environment_id IN (SELECT id FROM environments WHERE parent_environment_id = ANY($1))
         OR project_id = ANY($2)
       )`,
      [[...environmentIds], [...projectIds]],
    );
  }
  const last = rows[rows.length - 1] as { id: string; occurred_at: string; event_order: string };
  await ctx.db.query(
    "UPDATE sync_cursor SET cursor_order = GREATEST(cursor_order, $1), event_id = $2 WHERE singleton",
    [last.event_order, last.id],
  );
}

// ---------------------------------------------------------------------------
// One pass over every due Target. Never throws.

export async function runSyncOnce(ctx: AppCtx, opts: SyncRunOptions = {}): Promise<void> {
  try {
    await scanSyncTriggers(ctx);
  } catch (err) {
    console.error("sync trigger scan failed:", err);
  }
  const repairIntervalMs = opts.repairIntervalMs ?? REPAIR_INTERVAL_MS;
  // The batch selects CANDIDATE ids only. Every configuration fact is read
  // at (or after) lease acquisition: acting on a batch snapshot would let a
  // mutation committed between selection and acquisition — a destination
  // change, a re-point — run under a fresh, valid generation against the
  // OLD configuration, recording old-destination successes in the new
  // destination's ledger.
  let due;
  try {
    due = await ctx.db.query(
      `SELECT t.id
       FROM sync_targets t
       JOIN organizations o ON o.id = t.organization_id
       WHERE t.revoked_at IS NULL AND t.state = 'active' AND o.deleted_at IS NULL
         AND (t.next_attempt_at IS NULL OR t.next_attempt_at <= now())
         AND (t.needs_sync OR t.last_repair_at IS NULL
              OR t.last_repair_at < now() - ($1 * interval '1 millisecond'))
       ORDER BY t.created_at, t.id`,
      [repairIntervalMs],
    );
  } catch (err) {
    console.error("sync target selection failed:", err);
    return;
  }
  for (const raw of due.rows as { id: string }[]) {
    try {
      await reconcileTarget(ctx, raw.id, opts);
    } catch (err) {
      console.error(`sync reconcile failed (${raw.id}):`, err);
    }
  }
}

/** Exported for the stale-selection regression test. */
export async function reconcileTarget(
  ctx: AppCtx,
  targetId: string,
  opts: SyncRunOptions,
): Promise<void> {
  // Lease: at most one valid reconciliation per Target (§4). The RETURNING
  // row is THE configuration snapshot this run may act on — atomically the
  // same row version the acquired generation belongs to.
  const lease = await ctx.db.query(
    `UPDATE sync_targets
     SET generation = generation + 1, lease_expires_at = now() + ($2 * interval '1 second'),
         needs_sync = false, last_attempt_at = now()
     WHERE id = $1 AND revoked_at IS NULL AND state = 'active'
       AND (lease_expires_at IS NULL OR lease_expires_at < now())
     RETURNING ${TARGET_COLUMNS}, generation`,
    [targetId, LEASE_TTL_SECONDS],
  );
  const leaseRow = lease.rows[0] as Record<string, unknown> | undefined;
  if (!leaseRow) return; // another run holds the lease, or state changed
  const target = targetRow(leaseRow);
  const generation = Number(leaseRow.generation as string | number);

  try {
    // Connection and org facts also post-lease: a re-point that raced the
    // batch changed connection_id on the row we just snapshotted.
    const connRes = await ctx.db.query(
      `SELECT c.platform, c.base_identity, c.credential_envelope, c.version AS connection_version,
              c.revoked_at AS connection_revoked_at, o.wrapped_org_kek
       FROM platform_connections c, organizations o
       WHERE c.id = $1 AND o.id = $2 AND o.deleted_at IS NULL`,
      [target.connection_id, target.organization_id],
    );
    const live = connRes.rows[0] as LiveConnection | undefined;
    if (!live || live.connection_revoked_at) {
      // Revocation disables referencing Targets in the same transaction;
      // reaching here is a narrow race — surface it, never push.
      await recordFailure(ctx, target, "connection-revoked", true, generation);
      return;
    }
    if (opts.allowedAdapters && !opts.allowedAdapters.includes(live.platform)) {
      await recordFailure(ctx, target, "adapter-not-allowed-on-installation", false, generation);
      return;
    }

    // Repair runs force-write; a triggered converge diffs against the ledger.
    const force =
      target.last_repair_at === null ||
      Date.now() - new Date(target.last_repair_at).getTime() >=
        (opts.repairIntervalMs ?? REPAIR_INTERVAL_MS);

    let outcome: Awaited<ReturnType<typeof reconcileUnderLease>>;
    try {
      outcome = await reconcileUnderLease(ctx, target, live, generation, force, opts);
    } finally {
      // Whatever the outcome, even a throw (a refused public-key fetch), the
      // platform may have said when the credential expires; recorded only if
      // the Connection still holds that credential, and never masking the
      // run's own error.
      if (live.observed_expiry) {
        await recordCredentialExpiry(ctx.db, target.connection_id, live.connection_version, live.observed_expiry).catch((e) =>
          console.error("credential expiry bookkeeping failed:", e),
        );
      }
    }
    if (outcome === LEASE_LOST) {
      // Aborting was right either way, but only a MOVED generation proves a
      // successor exists (whose mutation re-set needs_sync). A failed probe
      // aborts too — and if the generation is in fact still ours, nobody
      // else will reschedule the abandoned work: record a guarded failure
      // so backoff-and-retry owns it. The guard keeps this safe against a
      // successor appearing between the check and the update.
      let fenced = true;
      try {
        const res = await ctx.db.query(
          "SELECT generation FROM sync_targets WHERE id = $1",
          [target.id],
        );
        const row = res.rows[0] as { generation: string | number } | undefined;
        fenced = row !== undefined && Number(row.generation) !== generation;
      } catch {
        fenced = false; // cannot confirm a successor: reschedule, guarded
      }
      if (!fenced) {
        await recordFailure(ctx, target, "interrupted mid-run; retrying", true, generation).catch(
          (e) => console.error("sync interruption bookkeeping failed:", e),
        );
      }
      return;
    }
    if (outcome.ok) {
      await ctx.db.query(
        `UPDATE sync_targets
         SET failure_count = 0, next_attempt_at = NULL, last_result = $2
             ${force ? ", last_repair_at = now()" : ""}
         WHERE id = $1 AND generation = $3`,
        [target.id, outcome.result, generation],
      );
    } else {
      await recordFailure(ctx, target, outcome.result, true, generation);
    }
  } catch (err) {
    await recordFailure(
      ctx,
      target,
      err instanceof Error ? `${err.name}: ${err.message}`.slice(0, 300) : "error",
      true,
      generation,
    ).catch((e) => console.error("sync failure bookkeeping failed:", e));
  } finally {
    await ctx.db
      .query(
        "UPDATE sync_targets SET lease_expires_at = NULL WHERE id = $1 AND generation = $2",
        [target.id, generation],
      )
      .catch(() => {});
  }
}

interface RunOutcome {
  ok: boolean;
  result: string;
}

/**
 * The run was fenced before its wire phase (generation moved under it):
 * nothing was sent, nothing is recordable, and the target's bookkeeping
 * belongs to whoever bumped the generation — record no failure, no audit.
 */
const LEASE_LOST: RunOutcome = { ok: false, result: "lease-lost" };

async function reconcileUnderLease(
  ctx: AppCtx,
  target: SyncTargetRow,
  live: LiveConnection,
  generation: number,
  force: boolean,
  opts: SyncRunOptions,
): Promise<RunOutcome> {
  const adapter = getAdapter(live.platform);
  const org = {
    id: target.organization_id,
    wrapped_org_kek: live.wrapped_org_kek,
  } as OrgRow;

  // Freshly resolved state, always (§6: a missed trigger delays a push,
  // never corrupts one).
  const project = (
    await ctx.db.query("SELECT * FROM projects WHERE id = $1", [target.project_id])
  ).rows[0] as ProjectRow | undefined;
  const env = (
    await ctx.db.query("SELECT * FROM environments WHERE id = $1 AND deleted_at IS NULL", [
      target.environment_id,
    ])
  ).rows[0] as EnvironmentRow | undefined;
  if (!project || !env) return { ok: false, result: "environment-gone" };
  if (isExpired(env)) return { ok: false, result: "environment-expired" };

  // Audit before decryption, even when nothing will be pushed: the event
  // names the exact versions this reconcile is about to decrypt, and
  // commits first. Its sync.* type keeps it out of the trigger scan.
  const rendered = await renderEffectiveOutput(ctx, org, project, env, target, adapter.platform, (versions) =>
    recordAuditEvent(ctx.db, {
      eventType: "sync.values_decrypted",
      decision: "info",
      organizationId: target.organization_id,
      action: "config.sync.manage",
      resource: { targetId: target.id, environmentId: target.environment_id },
      metadata: {
        purpose: "sync-reconcile",
        items: versions.map((v) => `${v.name}@${v.versionId}`).join(","),
        generation,
      },
    }).then(() => undefined),
  );

  // Ledger read; invalidate names a lapsed run had begun writing (§4).
  const ledgerRes = await ctx.db.query(
    "SELECT dest_name, fingerprint, state, generation FROM sync_ledger WHERE target_id = $1",
    [target.id],
  );
  const ledger = new Map(
    (ledgerRes.rows as LedgerRow[]).map((r) => [r.dest_name, r]),
  );
  const ambiguous = new Set(
    [...ledger.values()]
      .filter((r) => r.state.startsWith("intent-") && Number(r.generation) < generation)
      .map((r) => r.dest_name),
  );

  const fpKey = syncFingerprintKey(orgKekOf(ctx, org), target.id);
  const desired = new Map<string, { value: string; fingerprint: string; versionId: string }>();
  for (const item of rendered.items) {
    desired.set(item.destName, {
      value: item.value,
      fingerprint: fingerprint(fpKey, item.destName, item.value),
      versionId: item.versionId,
    });
  }

  // Verify-and-fix (§6): an adapter that can read values back repairs only
  // actual drift instead of force-writing everything.
  let remote: Map<string, string> | null = null;
  if (force && adapter.supportsReadBack && adapter.readValues) {
    try {
      remote = await adapter.readValues(adapterRequest(ctx, org, target, live, opts));
    } catch {
      remote = null; // fall back to force-writes
    }
  }

  const writes: { destName: string; value: string; fingerprint: string; versionId: string }[] = [];
  // Read-back can prove a name converged without a wire write — but the
  // ledger must still record ownership, or a matching remote value from a
  // crashed run (intent never confirmed) or an out-of-band write would
  // leave the name unowned and later removal would miss it.
  const adoptions: { destName: string; fingerprint: string }[] = [];
  for (const [destName, want] of desired) {
    const entry = ledger.get(destName);
    const converged =
      entry && entry.state === "written" && entry.fingerprint === want.fingerprint;
    const needsWrite = force
      ? remote
        ? remote.get(destName) !== want.value
        : true
      : !converged || ambiguous.has(destName);
    if (needsWrite) writes.push({ destName, ...want });
    else if (force && remote && !converged) {
      adoptions.push({ destName, fingerprint: want.fingerprint });
    }
  }

  const deletes: string[] = [];
  for (const [destName, entry] of ledger) {
    if (desired.has(destName)) continue;
    if (entry.state === "tombstone") {
      // Re-apply tombstoned deletions on repair or when a stale write may
      // have resurrected the name (§3/§6).
      if (force && (!remote || remote.has(destName))) deletes.push(destName);
      else if (ambiguous.has(destName)) deletes.push(destName);
    } else if (target.remove_orphans) {
      deletes.push(destName);
    }
  }

  // A repair write whose content matches the ledger fingerprint is not a
  // change and triggers no redeploy (§5).
  const changingWrites = writes.filter((w) => ledger.get(w.destName)?.fingerprint !== w.fingerprint);

  // Nothing left the process for an adoption, so no disclosure event and no
  // redeploy — only ownership bookkeeping. A fence here still aborts: the
  // lease is gone and any wire phase below belongs to the successor.
  for (const a of adoptions) {
    if (!(await ledgerSet(ctx, target.id, generation, a.destName, "written", a.fingerprint, null))) {
      return LEASE_LOST;
    }
  }

  if (writes.length === 0 && deletes.length === 0) {
    return {
      ok: rendered.flags.length === 0,
      result: rendered.flags.length > 0 ? flagSummary(rendered.flags) : "converged",
    };
  }

  // Audit precedes disclosure (§7): if this commit fails, the push does not
  // happen. Names and versions only; destination redacted like webhook URLs.
  await recordAuditEvent(ctx.db, {
    eventType: "sync.push_attempted",
    decision: "info",
    organizationId: target.organization_id,
    action: "config.sync.manage",
    resource: { targetId: target.id, environmentId: target.environment_id },
    metadata: {
      destination: describeDestination(adapter.platform, destinationKey(target)),
      items: writes.map((w) => `${w.destName}@${w.versionId}`).join(","),
      deletes: deletes.join(","),
      generation,
      forced: force,
    },
  });

  const req = adapterRequest(ctx, org, target, live, opts, generation);
  let writeOutcomes: NameOutcome[] = [];
  if (writes.length > 0) {
    for (const w of writes) {
      if (!(await ledgerSet(ctx, target.id, generation, w.destName, "intent-write", w.fingerprint, null))) {
        return LEASE_LOST;
      }
    }
    const items: SyncItem[] = writes.map((w) => ({ name: w.destName, value: w.value }));
    writeOutcomes = await adapter.writeValues(req, items);
    for (const o of writeOutcomes) {
      const w = writes.find((x) => x.destName === o.name);
      await ledgerSet(
        ctx,
        target.id,
        generation,
        o.name,
        o.ok ? "written" : "failed-write",
        w?.fingerprint ?? null,
        o.ok ? null : (o.error ?? "failed"),
      );
    }
    // Fewer outcomes than items means shouldAbort cut the batch short:
    // stop here — no deletes, no result event, no redeploy. Confirmations
    // above were fence-rejected no-ops; the successor owns those names.
    if (writeOutcomes.length < writes.length) return LEASE_LOST;
  }

  let deleteOutcomes: NameOutcome[] = [];
  if (deletes.length > 0) {
    for (const name of deletes) {
      if (!(await ledgerSet(ctx, target.id, generation, name, "intent-delete", null, null))) {
        return LEASE_LOST;
      }
    }
    deleteOutcomes = await adapter.deleteNames(req, deletes);
    for (const o of deleteOutcomes) {
      await ledgerSet(
        ctx,
        target.id,
        generation,
        o.name,
        o.ok ? "tombstone" : "failed-delete",
        null,
        o.ok ? null : (o.error ?? "failed"),
      );
    }
    if (deleteOutcomes.length < deletes.length) return LEASE_LOST;
  }

  const failed = [
    ...writeOutcomes.filter((o) => !o.ok),
    ...deleteOutcomes.filter((o) => !o.ok),
  ];
  // Per-item failures from rendering (unresolved references, unstorable
  // names, pending re-affirmation) degrade the Target too.
  const result =
    failed.length === 0 && rendered.flags.length === 0
      ? "ok"
      : `degraded: ${[...failed.map((f) => `${f.name} (${f.error ?? "failed"})`), ...rendered.flags].join("; ")}`.slice(0, 500);

  await recordAuditEvent(ctx.db, {
    eventType: "sync.push_result",
    decision: "info",
    organizationId: target.organization_id,
    action: "config.sync.manage",
    resource: { targetId: target.id, environmentId: target.environment_id },
    metadata: {
      written: writeOutcomes.filter((o) => o.ok).length,
      deleted: deleteOutcomes.filter((o) => o.ok).length,
      failed: failed.length,
      generation,
      result: failed.length === 0 ? "ok" : "degraded",
    },
  });

  // Best-effort redeploy, only when ledger content actually changed (§5).
  // Best-effort means a failure never degrades the Target (the values did
  // land) — but it must show in last_result, or "pushed but the running
  // app never picked it up" is invisible to the operator.
  let redeployNote = "";
  if (
    target.redeploy &&
    adapter.supportsRedeploy &&
    adapter.triggerRedeploy &&
    (changingWrites.some((w) => writeOutcomes.some((o) => o.ok && o.name === w.destName)) ||
      deleteOutcomes.some((o) => o.ok))
  ) {
    // A fence during the batch's FINAL write returns a full outcome count,
    // so truncation cannot detect it — probe once more before redeploying a
    // platform this run may no longer speak for.
    if (req.shouldAbort && (await req.shouldAbort())) return LEASE_LOST;
    await adapter.triggerRedeploy(req).catch((err: unknown) => {
      redeployNote = `; redeploy failed (${err instanceof Error ? err.message : "error"})`;
    });
  }

  return {
    ok: failed.length === 0 && rendered.flags.length === 0,
    result: `${result}${redeployNote}`.slice(0, 500),
  };
}

// ---------------------------------------------------------------------------
// Effective output rendering under the Target's own standing authority (§2):
// mapped items, rotation primaries, inheritance, renames — and reference
// expansion that may draw ONLY on the disclosure set (§2: expansion never
// becomes a side door around the gate).

interface RenderedItem {
  destName: string;
  value: string;
  versionId: string;
}

/**
 * Sync delivery is a server-side convergence loop, not a caller's retrieval:
 * it decrypts to fingerprint values and decide what changed. Like every
 * retrieval it audits before it decrypts (sync.values_decrypted, committed
 * by the caller of renderEffectiveOutput), and again before any value leaves
 * the process (sync.push_attempted, ADR-0031 §7). A missed or mixed read is
 * repaired by the next reconcile.
 */
async function decryptForSync(
  ctx: AppCtx,
  org: OrgRow,
  valueRowId: string,
  versionId: string,
): Promise<string> {
  const res = await ctx.db.query("SELECT payload, wrapped_dek FROM value_versions WHERE id = $1", [versionId]);
  const version = res.rows[0] as { payload: string; wrapped_dek: string } | undefined;
  if (!version) throw new DomainError("INTERNAL", "Missing value version");
  return decryptValue(orgKekOf(ctx, org), org.id, valueRowId, versionId, {
    payload: envelope(version.payload),
    wrappedDek: envelope(version.wrapped_dek),
  }).toString("utf8");
}

export async function renderEffectiveOutput(
  ctx: AppCtx,
  org: OrgRow,
  project: ProjectRow,
  env: EnvironmentRow,
  target: Pick<SyncTargetRow, "mapping">,
  platform: string,
  /** Commits the audit event for exactly these versions; decryption follows only if it succeeds. */
  beforeDecrypt: (versions: { name: string; versionId: string }[]) => Promise<void>,
): Promise<{ items: RenderedItem[]; flags: string[] }> {
  const adapter = getAdapter(platform);
  const resolved = await resolveItems(ctx, org, env, await activeContractOf(ctx, project), new Date());
  const flags: string[] = [];

  const mapping: SyncMapping = target.mapping;
  const selected: { name: string; destName: string; sensitive: boolean; valueRowId: string; versionId: string }[] = [];
  const seenDest = new Set<string>();
  const pick = (name: string, rename: string | undefined) => {
    const item = resolved.find((i) => i.name === name);
    if (!item) return; // not in effective output: convergence handles removal
    const destName = adapter.canonicalizeName(rename ?? name);
    const problem = adapter.validateName(destName);
    if (problem) {
      flags.push(`${name}: unstorable name`);
      return;
    }
    if (seenDest.has(destName)) {
      flags.push(`${name}: destination name collision (${destName})`);
      return;
    }
    seenDest.add(destName);
    selected.push({
      name,
      destName,
      sensitive: item.sensitive,
      valueRowId: item.valueRowId,
      versionId: item.versionId,
    });
  };

  if (mapping.kind === "wildcard") {
    // Exclusions shrink the disclosure set silently — an excluded item is
    // outside the mapping, not a flagged failure (ADR-0031 amendment).
    for (const item of resolved) {
      if (matchesExclusion(mapping.exclude, item.name)) continue;
      pick(item.name, undefined);
    }
  } else {
    for (const m of mapping.items) {
      const item = resolved.find((i) => i.name === m.name);
      // An item that became a Secret leaves the disclosure set until
      // re-affirmed (§2) — its pushes stop, visibly.
      if (item?.sensitive && !m.secretAffirmed) {
        flags.push(`${m.name}: became a Secret; re-affirmation required`);
        continue;
      }
      pick(m.name, m.rename);
    }
  }

  // Decrypt the disclosure set; the reference lookup is exactly this set.
  if (selected.length > 0) await beforeDecrypt(selected.map((i) => ({ name: i.name, versionId: i.versionId })));
  const plaintext = new Map<string, string>();
  for (const item of selected) {
    plaintext.set(
      item.name,
      await decryptForSync(ctx, org, item.valueRowId, item.versionId),
    );
  }

  const items: RenderedItem[] = [];
  for (const item of selected) {
    const rawValue = plaintext.get(item.name) as string;
    try {
      items.push({
        destName: item.destName,
        value: expandReferences(rawValue, (n) => plaintext.get(n), true),
        versionId: item.versionId,
      });
    } catch (error) {
      if (!(error instanceof ReferenceExpansionError)) throw error;
      flags.push(`${item.name}: ${error.message}`);
    }
  }
  return { items, flags };
}

// ---------------------------------------------------------------------------

function fingerprint(key: Buffer, destName: string, value: string): string {
  return createHmac("sha256", key).update(`${destName} ${value}`, "utf8").digest("hex");
}

function destinationKey(target: SyncTargetRow): string {
  try {
    const parsed = JSON.parse(target.canonical_destination) as [string, string, string];
    return parsed[2];
  } catch {
    return "?";
  }
}

function adapterRequest(
  ctx: AppCtx,
  org: OrgRow,
  target: SyncTargetRow,
  live: LiveConnection,
  opts: SyncRunOptions,
  generation?: number,
) {
  const envelope =
    typeof live.credential_envelope === "string"
      ? (JSON.parse(live.credential_envelope) as Envelope)
      : live.credential_envelope;
  return {
    baseIdentity: live.base_identity,
    destination: target.destination,
    credential: decryptPlatformCredential(
      orgKekOf(ctx, org),
      target.organization_id,
      target.connection_id,
      envelope,
    ),
    ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
    onCredentialExpiry: (expiresAt: string) => {
      live.observed_expiry = expiresAt;
    },
    // Per-request cancellation for writes/deletes/redeploy (preparatory
    // reads are not gated): a batch whose intents were accepted would
    // otherwise keep sending after a mid-batch fence. This narrows the
    // stale-send residual to the final check-to-send race per gated
    // request (plus requests already on the network). If the check itself
    // fails, don't send what we can't verify — the caller distinguishes a
    // confirmed fence from a probe failure and reschedules the latter.
    ...(generation !== undefined
      ? {
          shouldAbort: async (): Promise<boolean> => {
            try {
              const res = await ctx.db.query(
                "SELECT generation FROM sync_targets WHERE id = $1",
                [target.id],
              );
              const row = res.rows[0] as { generation: string | number } | undefined;
              return !row || Number(row.generation) !== generation;
            } catch {
              return true;
            }
          },
        }
      : {}),
  };
}

/**
 * Ledger writes are conditional on the writing lease still being current:
 * a run that lost its lease can record nothing (§4). The FOR SHARE lock
 * serializes the generation check against mutations that fence a run out
 * (destination change, re-point) — those hold FOR UPDATE on the target row,
 * so a fenced run blocks here and then sees the bumped generation instead
 * of racing its stale write past the ledger reset. Returns false when
 * fenced: intent-phase callers must then STOP before the wire ("intent
 * precedes the wire" — a fenced run may not send what it cannot record);
 * confirmation-phase callers ignore it (the wire already happened and the
 * successor's ambiguity handling owns those names). Exported for tests.
 */
export async function ledgerSet(
  ctx: AppCtx,
  targetId: string,
  generation: number,
  destName: string,
  state: string,
  fp: string | null,
  lastError: string | null,
): Promise<boolean> {
  return withTx(ctx.db, async (db) => {
    const res = await db.query(
      "SELECT generation FROM sync_targets WHERE id = $1 FOR SHARE",
      [targetId],
    );
    const current = res.rows[0] as { generation: string | number } | undefined;
    if (!current || Number(current.generation) !== generation) return false;
    await db.query(
      `INSERT INTO sync_ledger (target_id, dest_name, fingerprint, state, generation, last_error)
       VALUES ($1, $2, $4, $5, $3, $6)
       ON CONFLICT (target_id, dest_name) DO UPDATE
         SET fingerprint = $4, state = $5, generation = $3, last_error = $6, updated_at = now()`,
      [targetId, destName, generation, fp, state, lastError],
    );
    return true;
  });
}

async function recordFailure(
  ctx: AppCtx,
  target: SyncTargetRow,
  result: string,
  backoff: boolean,
  generation?: number,
): Promise<void> {
  const failures = target.failure_count + 1;
  const delayMs = Math.min(BASE_BACKOFF_MS * 2 ** target.failure_count, MAX_BACKOFF_MS);
  const disable = backoff && failures >= FAILURE_BUDGET;
  // A failed run leaves pending work: needs_sync must come back on (lease
  // acquisition cleared it) or the backed-off retry would never qualify for
  // selection and the Target would wait for the next trigger or repair pass.
  const applied = await ctx.db.query(
    `UPDATE sync_targets
     SET failure_count = $2, last_result = $3, needs_sync = true,
         next_attempt_at = now() + ($4 * interval '1 millisecond'),
         state = CASE WHEN $5 THEN 'disabled' ELSE state END,
         disabled_reason = CASE WHEN $5 THEN 'failure-budget-exhausted' ELSE disabled_reason END
     WHERE id = $1 AND revoked_at IS NULL${generation !== undefined ? " AND generation = $6" : ""}
     RETURNING id`,
    generation !== undefined
      ? [target.id, failures, result.slice(0, 500), delayMs, disable, generation]
      : [target.id, failures, result.slice(0, 500), delayMs, disable],
  );
  if (disable && applied.rows.length > 0) {
    // Auto-disable is a state the UI must surface; a human resumes (§5).
    await recordAuditEvent(ctx.db, {
      eventType: "sync.target_disabled",
      decision: "info",
      organizationId: target.organization_id,
      action: "config.sync.manage",
      resource: { targetId: target.id, environmentId: target.environment_id },
      metadata: { reason: "failure-budget-exhausted", failures, lastResult: result.slice(0, 300) },
    });
  }
}

function flagSummary(flags: string[]): string {
  return `flagged: ${flags.join("; ")}`.slice(0, 500);
}

/** Periodic delivery, modeled on the webhook loop: best-effort, never throws. */
export function startSyncLoop(
  ctx: AppCtx,
  opts: SyncRunOptions & { intervalMs?: number } = {},
): () => void {
  let busy = false;
  const tick = async () => {
    if (busy) return;
    const leave = ctx.maintenance?.enter();
    if (ctx.maintenance && !leave) return;
    busy = true;
    try {
      await runSyncOnce(ctx, opts);
    } catch (err) {
      console.error("sync loop error:", err);
    } finally {
      busy = false;
      leave?.();
    }
  };
  const timer = setInterval(() => void tick(), opts.intervalMs ?? 30_000);
  timer.unref();
  void tick();
  return () => clearInterval(timer);
}
