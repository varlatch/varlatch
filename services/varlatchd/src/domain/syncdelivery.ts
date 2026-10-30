// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHmac } from "node:crypto";
import { getAdapter, type NameOutcome, type NameUsage, type SyncItem, type UsageReport } from "@varlatch/sync";
import { recordAuditEvent } from "../audit/events.js";
import type { Envelope } from "../crypto/aead.js";
import { decryptPlatformCredential, decryptValue, syncFingerprintKey } from "../crypto/hierarchy.js";
import { withTx } from "../db/tx.js";
import type { AppCtx } from "./ctx.js";
import { isExpired, type EnvironmentRow } from "./environments.js";
import { APP_REMOVED, appCredentialFrom, mintInstallationToken } from "./githubmint.js";
import { orgKekOf, type OrgRow } from "./orgs.js";
import type { ProjectRow } from "./projects.js";
import { ReferenceExpansionError, expandReferences } from "./references.js";
import { activeContractOf } from "./contracts.js";
import { DomainError } from "./errors.js";
import { envelope, resolveItems } from "./retrieval.js";
import {
  boundNotes,
  recordCredentialExpiry,
  describeDestination,
  matchesExclusion,
  targetRow,
  TARGET_COLUMNS,
  type SyncMapping,
  type SyncTargetRow,
  type TargetNote,
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
/**
 * A run's budget, under the lease TTL: after it the run's send check
 * refuses (ADR-0050 Decision 3), on the database clock, so no run outlives
 * its lease and a Target can be shown drained.
 */
const RUN_BUDGET_SECONDS = 240;
/** The send check's one query: the Target's generation, and whether the run is within its deadline. Exported for tests. */
export const SEND_CHECK_SQL =
  "SELECT t.generation, (r.deadline > now()) AS within FROM sync_targets t LEFT JOIN sync_runs r ON r.target_id = t.id AND r.generation = $2 WHERE t.id = $1";
const BASE_BACKOFF_MS = 30_000;
const MAX_BACKOFF_MS = 3_600_000;
const FAILURE_BUDGET = 10;
const SCAN_BATCH = 500;
export const REPAIR_INTERVAL_MS = 6 * 3_600_000;

/** Connection + org facts, read AFTER lease acquisition — never from the batch. */
interface LiveConnection {
  platform: string;
  base_identity: string;
  /** NULL for an App Connection, which stores no token. */
  credential_envelope: Envelope | string | null;
  wrapped_org_kek: Envelope | string;
  connection_revoked_at: string | null;
  /** The Connection's version this run's credential was read at. */
  connection_version: number;
  /** When the platform said, during this run, the credential expires. */
  observed_expiry?: string;
  credential_kind: "token" | "github-app";
  github_installation_id: string | number | null;
  /** An App Connection's App (ADR-0047): NULL for a token Connection. */
  app_row_id: string | null;
  app_github_id: string | number | null;
  app_client_id: string | null;
  app_key_envelope: Envelope | string | null;
  app_removed_at: string | null;
  /** The installation token minted for this run's pushes: never stored. */
  minted_token?: string;
}

/** Varlatch could not get a token for an App Connection's push: the run fails with GitHub's reason, as Varlatch reads it. */
class GitHubAppTokenError extends Error {
  override name = "GitHub App";
}

interface LedgerRow {
  dest_name: string;
  fingerprint: string | null;
  state: string;
  generation: string | number;
  /** When a confirmed write, deletion or read-back last proved the name (migration 32). */
  repaired_at: Date | string | null;
}

export interface SyncRunOptions {
  fetchImpl?: typeof fetch | undefined;
  repairIntervalMs?: number | undefined;
  /** Which adapters this Installation allows (VARLATCH_SYNC_ADAPTERS). */
  allowedAdapters?: string[] | undefined;
  /** A run's budget in seconds; tests shorten it (default RUN_BUDGET_SECONDS). */
  runBudgetSeconds?: number | undefined;
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
    // The Targets are locked in ascending ID order first, as every other
    // transaction locks them (ADR-0051): a bulk UPDATE would lock them in
    // physical order and could deadlock with a Project's deletion.
    await withTx(ctx.db, async (db) => {
      const due = await db.query(
        `SELECT id FROM sync_targets
         WHERE revoked_at IS NULL AND NOT needs_sync AND (
           environment_id = ANY($1)
           OR environment_id IN (SELECT id FROM environments WHERE parent_environment_id = ANY($1))
           OR project_id = ANY($2)
         )
         ORDER BY id FOR UPDATE`,
        [[...environmentIds], [...projectIds]],
      );
      const ids = (due.rows as { id: string }[]).map((r) => r.id);
      if (ids.length > 0) {
        await db.query("UPDATE sync_targets SET needs_sync = true WHERE id = ANY($1) AND revoked_at IS NULL", [ids]);
      }
    });
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
  // Rows of runs past their deadline: their send check refuses anyway, so
  // they no longer count; this only keeps the table small (ADR-0050).
  await ctx.db.query("DELETE FROM sync_runs WHERE deadline <= now()").catch((err: unknown) =>
    console.error("sync run cleanup failed:", err),
  );
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
  // The run is registered with its deadline in the same statement, so no
  // run ever holds a lease without a row (ADR-0050 Decision 5).
  const lease = await ctx.db.query(
    `WITH lease AS (
       UPDATE sync_targets
       SET generation = generation + 1, lease_expires_at = now() + ($2 * interval '1 second'),
           needs_sync = false, last_attempt_at = now()
       WHERE id = $1 AND revoked_at IS NULL AND state = 'active'
         AND (lease_expires_at IS NULL OR lease_expires_at < now())
       RETURNING ${TARGET_COLUMNS}, generation
     ), run AS (
       INSERT INTO sync_runs (target_id, generation, deadline)
       SELECT id, generation, now() + ($3 * interval '1 second') FROM lease
       RETURNING deadline
     )
     SELECT lease.*, run.deadline AS run_deadline FROM lease, run`,
    [targetId, LEASE_TTL_SECONDS, opts.runBudgetSeconds ?? RUN_BUDGET_SECONDS],
  );
  const leaseRow = lease.rows[0] as Record<string, unknown> | undefined;
  if (!leaseRow) return; // another run holds the lease, or state changed
  const target = targetRow(leaseRow);
  const generation = Number(leaseRow.generation as string | number);
  /** The Connection version this run read its credential at, once read. */
  let credentialVersion: number | undefined;
  // Kept in memory: the row may be cleaned by another process's tick before
  // this run classifies how it ended.
  const runDeadline = leaseRow.run_deadline as Date | string;
  // The notes of a completed inspection, kept for a run that throws later.
  const inspected: { notes?: TargetNote[] } = {};

  try {
    // Connection and org facts also post-lease: a re-point that raced the
    // batch changed connection_id on the row we just snapshotted.
    const connRes = await ctx.db.query(
      `SELECT c.platform, c.base_identity, c.credential_envelope, c.version AS connection_version,
              c.revoked_at AS connection_revoked_at, o.wrapped_org_kek,
              c.credential_kind, c.github_installation_id,
              a.id AS app_row_id, a.github_app_id AS app_github_id, a.client_id AS app_client_id,
              a.key_envelope AS app_key_envelope, a.removed_at AS app_removed_at
       FROM platform_connections c
       JOIN organizations o ON o.id = $2 AND o.deleted_at IS NULL
       LEFT JOIN github_apps a ON a.id = c.github_app_id
       WHERE c.id = $1`,
      [target.connection_id, target.organization_id],
    );
    const live = connRes.rows[0] as LiveConnection | undefined;
    if (live) credentialVersion = Number(live.connection_version);
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

    // A forced run works within a repair cycle (ADR-0050 Decision 4): opened
    // by the first forced run, it lets later runs skip names already
    // repaired since it opened, so a repair larger than one run's budget
    // completes over several runs instead of starting over each time.
    let cycleStart: Date | null = null;
    if (force) {
      const cycle = await ctx.db.query(
        `UPDATE sync_targets SET repair_cycle_started_at = COALESCE(repair_cycle_started_at, now())
         WHERE id = $1 AND generation = $2 RETURNING repair_cycle_started_at`,
        [target.id, generation],
      );
      const started = (cycle.rows[0] as { repair_cycle_started_at: Date | string } | undefined)?.repair_cycle_started_at;
      cycleStart = started ? new Date(started) : null;
    }

    let outcome: Awaited<ReturnType<typeof reconcileUnderLease>>;
    try {
      outcome = await reconcileUnderLease(ctx, target, live, generation, force, opts, inspected, cycleStart);
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
      let outOfBudget = false;
      try {
        // The deadline from the run's row while it exists, else the one this
        // run was given: another process's tick may have removed the row.
        const res = await ctx.db.query(
          `SELECT t.generation,
                  COALESCE((SELECT r.deadline FROM sync_runs r WHERE r.target_id = t.id AND r.generation = $3), $2::timestamptz) <= now()
                    AS expired
           FROM sync_targets t WHERE t.id = $1`,
          [target.id, runDeadline, generation],
        );
        const row = res.rows[0] as { generation: string | number; expired: boolean } | undefined;
        fenced = row !== undefined && Number(row.generation) !== generation;
        outOfBudget = row !== undefined && !fenced && row.expired === true;
      } catch {
        fenced = false; // cannot confirm a successor: reschedule, guarded
      }
      if (outOfBudget) {
        // The run used up its budget: a yield, not a failure (ADR-0050
        // Decision 4). What it confirmed stays confirmed; the Target is
        // picked up again on the next tick.
        await ctx.db
          .query("UPDATE sync_targets SET needs_sync = true WHERE id = $1 AND generation = $2", [target.id, generation])
          .catch((e) => console.error("sync yield bookkeeping failed:", e));
        return;
      }
      if (!fenced) {
        await recordFailure(ctx, target, "interrupted mid-run; retrying", true, generation, inspected.notes, credentialVersion).catch(
          (e) => console.error("sync interruption bookkeeping failed:", e),
        );
      }
      return;
    }
    // The repair cycle closes when its eligible work is done, independent of
    // the Target's health: a flag such as an unresolved reference must not
    // keep a cycle open (and its credited names unverified) for good.
    if (force && outcome.cycleComplete) {
      await ctx.db.query(
        `UPDATE sync_targets SET last_repair_at = COALESCE(repair_cycle_started_at, now()), repair_cycle_started_at = NULL
         WHERE id = $1 AND generation = $2`,
        [target.id, generation],
      );
    }
    if (outcome.ok) {
      await ctx.db.query(
        `UPDATE sync_targets
         SET failure_count = 0, next_attempt_at = NULL, last_result = $2
             ${outcome.notes !== undefined ? ", last_notes = $4" : ""}
         WHERE id = $1 AND generation = $3`,
        outcome.notes !== undefined
          ? [target.id, outcome.result, generation, JSON.stringify(outcome.notes)]
          : [target.id, outcome.result, generation],
      );
    } else {
      await recordFailure(ctx, target, outcome.result, true, generation, outcome.notes, credentialVersion);
    }
  } catch (err) {
    await recordFailure(
      ctx,
      target,
      err instanceof Error ? `${err.name}: ${err.message}`.slice(0, 300) : "error",
      true,
      generation,
      inspected.notes,
      credentialVersion,
    ).catch((e) => console.error("sync failure bookkeeping failed:", e));
  } finally {
    await ctx.db
      .query(
        "UPDATE sync_targets SET lease_expires_at = NULL WHERE id = $1 AND generation = $2",
        [target.id, generation],
      )
      .catch(() => {});
    // The run's own row, whether or not it was fenced: it describes the
    // run, not the lease.
    await ctx.db
      .query("DELETE FROM sync_runs WHERE target_id = $1 AND generation = $2", [target.id, generation])
      .catch(() => {});
  }
}

interface RunOutcome {
  ok: boolean;
  result: string;
  /**
   * Held names and usage notes, replacing the Target's (migration 31) when
   * the run reached the value check; undefined when it did not, which
   * leaves them as they are.
   */
  notes?: TargetNote[];
  /**
   * A forced run handled all its eligible repair work without a failed
   * write or deletion: the repair cycle can close, whatever rendering flags
   * say about the Target's health (ADR-0050 Decision 4).
   */
  cycleComplete?: boolean;
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
  inspected: { notes?: TargetNote[] } = {},
  cycleStart: Date | null = null,
): Promise<RunOutcome> {
  const adapter = getAdapter(live.platform);
  const org = {
    id: target.organization_id,
    wrapped_org_kek: live.wrapped_org_kek,
  } as OrgRow;

  // Freshly resolved state, always (§6: a missed trigger delays a push,
  // never corrupts one).
  const project = (
    await ctx.db.query("SELECT * FROM projects WHERE id = $1 AND deleted_at IS NULL", [target.project_id])
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
    "SELECT dest_name, fingerprint, state, generation, repaired_at FROM sync_ledger WHERE target_id = $1",
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
  // Repaired since the open cycle began: a forced run leaves these alone
  // unless ordinary reconciliation needs them (ADR-0050 Decision 4).
  const credited = (name: string): boolean => {
    const at = ledger.get(name)?.repaired_at;
    return cycleStart !== null && at !== null && at !== undefined && new Date(at) >= cycleStart && !ambiguous.has(name);
  };

  const fpKey = syncFingerprintKey(orgKekOf(ctx, org), target.id);
  const desired = new Map<string, { value: string; fingerprint: string; versionId: string }>();
  for (const item of rendered.items) {
    desired.set(item.destName, {
      value: item.value,
      fingerprint: fingerprint(fpKey, item.destName, item.value),
      versionId: item.versionId,
    });
  }

  // Usage (ADR-0031 amendment 2026-10-21): how the destination itself uses
  // the names this run may write or delete, read before the diff. A name
  // the platform sets itself is neither written nor deleted; the rest are
  // notes, which never fail the run.
  const flags = [...rendered.flags];
  // Held names, with why (ADR-0031 amendment 2026-10-22): summarized in
  // the result and listed as notes, never a failure, so they spend no
  // failure budget.
  const heldReasons = rendered.held.map((h) => `${h.name}: ${h.reason}`);
  const heldNotes: TargetNote[] = rendered.held.map((h) => ({ code: "held", name: h.name, reason: h.reason }));
  const notes: TargetNote[] = [];
  let usage: UsageReport | null = null;
  if (adapter.inspectUsage) {
    const names = [...new Set([...desired.keys(), ...ledger.keys()])];
    usage = await adapter
      .inspectUsage(await adapterRequest(ctx, org, target, live, opts), names)
      .catch(() => ({ checked: false, reason: "the destination could not be read", names: new Map<string, NameUsage>() }));
  }
  const usageOf = (name: string): NameUsage => usage?.names.get(name) ?? {};
  if (usage && !usage.checked) notes.push({ code: "usage-unchecked", reason: usage.reason ?? "unknown" });
  // Names held this run: neither written nor deleted. The platform's own,
  // and values it would not deliver as given (checked here, before the
  // diff, so a value already stored is held to the same rule).
  const held = new Set<string>();
  for (const [destName, want] of [...desired]) {
    const problem = usageOf(destName).owned
      ? "the platform sets this name itself"
      : (adapter.valueProblem?.(target.destination, destName, want.value, usage) ?? null);
    if (problem) {
      desired.delete(destName);
      held.add(destName);
      heldReasons.push(`${destName}: ${problem}`);
      const fix = usageOf(destName).owned ? null : (adapter.heldFix?.(target.destination, destName, want.value) ?? null);
      heldNotes.push({ code: "held", name: destName, reason: problem, ...(fix ? { fix } : {}) });
    } else {
      notes.push(...usageNotes(destName, usageOf(destName)));
    }
  }
  // The value check is complete: a run that throws from here on still
  // replaces the Target's notes with these, held names first.
  inspected.notes = boundNotes([...heldNotes, ...notes]);
  // A name this destination refuses (the platform's own) or that the
  // platform sets itself was never Varlatch's to delete.
  const notOurs = (name: string) =>
    usageOf(name).owned === true || adapter.validateName(name, target.destination) !== null;
  // After a confirmed delete, a repair deletes again only when it knows the
  // platform does not re-create the name: never for a name its
  // configuration may reference, nor when usage could not be read (each
  // repeat would also restart a service).
  const mayRecreate = (name: string) => usageOf(name).referenced === true || (usage !== null && !usage.checked);

  // Verify-and-fix (§6): an adapter that can read values back repairs only
  // actual drift instead of force-writing everything. A value the platform
  // withholds reads as null: it never matches, so it is rewritten.
  // A name stored in another form than the adapter writes (a Coolify
  // variable without the literal flags) is rewritten even when it matches.
  let remote: Map<string, string | null> | null = null;
  let rewrite = new Set<string>();
  if (force && adapter.supportsReadBack && (adapter.readRemote || adapter.readValues)) {
    try {
      const request = await adapterRequest(ctx, org, target, live, opts);
      if (adapter.readRemote) {
        const state = await adapter.readRemote(request);
        remote = state.values;
        rewrite = state.rewrite;
      } else {
        remote = (await adapter.readValues!(request));
      }
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
  // Names a read-back proved current: they earn repair credit without a write.
  const verified: string[] = [];
  for (const [destName, want] of desired) {
    const entry = ledger.get(destName);
    const converged =
      entry && entry.state === "written" && entry.fingerprint === want.fingerprint;
    // Ordinary work first: a credited name is skipped only when nothing
    // changed for it since its repair.
    const repaired = force && converged && credited(destName);
    const needsWrite = force && !repaired
      ? remote
        ? remote.get(destName) !== want.value || rewrite.has(destName)
        : true
      : !converged || ambiguous.has(destName);
    if (needsWrite) writes.push({ destName, ...want });
    else if (force && remote && !converged) {
      adoptions.push({ destName, fingerprint: want.fingerprint });
    } else if (force && remote && !repaired) {
      verified.push(destName);
    }
  }

  const deletes: string[] = [];
  for (const [destName, entry] of ledger) {
    if (desired.has(destName) || held.has(destName)) continue;
    if (notOurs(destName)) continue;
    if (entry.state === "tombstone") {
      if (mayRecreate(destName)) notes.push({ code: "kept-by-platform", name: destName });
      // Re-apply tombstoned deletions on repair or when a stale write may
      // have resurrected the name (§3/§6), unless the platform may
      // re-create it (above).
      if (force && !credited(destName) && (!remote || remote.has(destName)) && !mayRecreate(destName)) deletes.push(destName);
      else if (ambiguous.has(destName)) deletes.push(destName);
      // Read back as absent: verified, so it earns credit without a delete.
      else if (force && remote && !remote.has(destName) && !credited(destName) && !mayRecreate(destName)) {
        verified.push(destName);
      }
    } else if (entry.state === "intent-delete" || entry.state === "failed-delete") {
      // A deletion an earlier run decided on and did not finish (cut off
      // by a fence or its deadline, or refused): carried on, so it
      // completes even when the Target does not remove orphans.
      deletes.push(destName);
    } else if (target.remove_orphans) {
      deletes.push(destName);
    }
  }

  // Whether confirmed changes owe a redeploy: only on a Target that asks for
  // one, through an adapter that can (never Convex or GitHub Actions).
  const redeploys = target.redeploy && adapter.supportsRedeploy === true && adapter.triggerRedeploy !== undefined;

  // Every note is known now (the ledger pass added the kept names).
  const runNotes = boundNotes([...heldNotes, ...notes]);
  inspected.notes = runNotes;

  // Nothing left the process for an adoption, so no disclosure event and no
  // redeploy — only ownership bookkeeping. A fence here still aborts: the
  // lease is gone and any wire phase below belongs to the successor.
  for (const a of adoptions) {
    if (!(await ledgerSet(ctx, target.id, generation, a.destName, "written", a.fingerprint, null))) {
      return LEASE_LOST;
    }
  }
  if (verified.length > 0 && !(await creditVerified(ctx, target.id, generation, verified))) return LEASE_LOST;

  if (writes.length === 0 && deletes.length === 0) {
    // Nothing to write, but an earlier run may still owe a redeploy.
    const owedNote = redeploys
      ? await payRedeploy(ctx, adapter, target, generation, await adapterRequest(ctx, org, target, live, opts, generation))
      : "";
    if (owedNote === LEASE_LOST) return LEASE_LOST;
    return {
      ok: flags.length === 0,
      result: `${withHeld(flags.length > 0 ? flagSummary(flags) : "converged", heldReasons)}${owedNote}`.slice(0, 500),
      notes: runNotes,
      cycleComplete: force,
    };
  }

  // Drift (ADR-0050 Decision 8): on a forced run that read the destination
  // back, among the actions just selected, the names the platform changed,
  // removed or re-created since Varlatch last wrote them. Only a confirmed
  // ledger entry at the fingerprint Varlatch wants now can drift; a value
  // the platform withholds (null), a form-only rewrite, an ambiguous name
  // or a change Varlatch is making itself is not drift.
  const drift = { changed: [] as string[], removed: [] as string[], recreated: [] as string[] };
  if (force && remote) {
    for (const w of writes) {
      const entry = ledger.get(w.destName);
      if (!entry || entry.state !== "written" || entry.fingerprint !== w.fingerprint || ambiguous.has(w.destName)) continue;
      const there = remote.get(w.destName);
      if (!remote.has(w.destName)) drift.removed.push(w.destName);
      else if (typeof there === "string" && there !== w.value) drift.changed.push(w.destName);
    }
    for (const name of deletes) {
      if (ledger.get(name)?.state === "tombstone" && !ambiguous.has(name) && remote.has(name)) drift.recreated.push(name);
    }
  }
  const drifted = new Set([...drift.changed, ...drift.removed, ...drift.recreated]);
  if (drifted.size > 0) {
    const sourceOf = new Map(rendered.items.map((i) => [i.destName, i.name]));
    const items = [...new Set([...drift.changed, ...drift.removed].map((d) => sourceOf.get(d)).filter((n): n is string => !!n))];
    const recorded = await recordDrift(ctx, target, generation, [...drifted], {
      destination: describeDestination(adapter.platform, destinationKey(target)),
      items: items.join(","),
      changed: drift.changed.join(","),
      removed: drift.removed.join(","),
      recreated: drift.recreated.join(","),
      count: drifted.size,
      generation,
    });
    if (!recorded) return LEASE_LOST;
  }

  // Audit precedes disclosure (§7): if this commit fails, the push does not
  // happen. Names and versions only; destination redacted like webhook URLs.
  // A run fenced by now records nothing and sends nothing (ADR-0050).
  const attempted = await recordGuardedEvent(ctx, target.id, generation, {
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
  if (!attempted) return LEASE_LOST;

  const req = { ...(await adapterRequest(ctx, org, target, live, opts, generation)), usage };
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
        // Only a write of what the ledger already confirmed is no change and
        // owes no redeploy (ADR-0031 §5). An intent or a failed write also
        // carries the fingerprint, but nothing confirmed it landed: a retry
        // of a change still owes its redeploy.
        // Putting drift back is a change on the platform too (ADR-0050
        // Decision 10).
        o.ok &&
          redeploys &&
          (drifted.has(o.name) || !(ledger.get(o.name)?.state === "written" && ledger.get(o.name)?.fingerprint === w?.fingerprint)),
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
      if (o.ok && mayRecreate(o.name)) notes.push({ code: "kept-by-platform", name: o.name });
      await ledgerSet(
        ctx,
        target.id,
        generation,
        o.name,
        o.ok ? "tombstone" : "failed-delete",
        null,
        o.ok ? null : (o.error ?? "failed"),
        o.ok && redeploys,
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
  const result = withHeld(
    failed.length === 0 && flags.length === 0
      ? "ok"
      : `degraded: ${[...failed.map((f) => `${f.name} (${f.error ?? "failed"})`), ...flags].join("; ")}`,
    heldReasons,
  );

  const recorded = await recordGuardedEvent(ctx, target.id, generation, {
    eventType: "sync.push_result",
    decision: "info",
    organizationId: target.organization_id,
    action: "config.sync.manage",
    resource: { targetId: target.id, environmentId: target.environment_id },
    metadata: {
      written: writeOutcomes.filter((o) => o.ok).length,
      deleted: deleteOutcomes.filter((o) => o.ok).length,
      failed: failed.length,
      held: heldReasons.length,
      ...(drifted.size > 0
        ? {
            driftRepaired: [...writeOutcomes, ...deleteOutcomes].filter((o) => o.ok && drifted.has(o.name)).length,
            driftFailed: [...writeOutcomes, ...deleteOutcomes].filter((o) => !o.ok && drifted.has(o.name)).length,
          }
        : {}),
      generation,
      result: failed.length === 0 ? "ok" : "degraded",
    },
  });
  // Fenced after its last request: the result belongs to nobody now, and
  // no redeploy may follow (ADR-0050 Decision 2).
  if (!recorded) return LEASE_LOST;

  // The owed redeploy, this run's and any earlier one's (ADR-0050 Decision 4).
  const redeployNote = await payRedeploy(ctx, adapter, target, generation, req);
  if (redeployNote === LEASE_LOST) return LEASE_LOST;

  return {
    ok: failed.length === 0 && flags.length === 0,
    result: `${result}${redeployNote}`.slice(0, 500),
    notes: boundNotes([...heldNotes, ...notes]),
    cycleComplete: force && failed.length === 0,
  };
}

/** Notes for a name the run keeps managing: hints, never failures. */
function usageNotes(name: string, usage: NameUsage): TargetNote[] {
  const notes: TargetNote[] = [];
  if (usage.shadowedIn?.length) notes.push({ code: "shadowed", name, containers: usage.shadowedIn });
  if (usage.notDeliveredTo?.length) notes.push({ code: "not-delivered", name });
  if (usage.unknownIn?.length) notes.push({ code: "unknown-form", name, containers: usage.unknownIn });
  if (usage.generatedOnce) notes.push({ code: "generated-once", name });
  return notes;
}

// ---------------------------------------------------------------------------
// Effective output rendering under the Target's own standing authority (§2):
// mapped items, rotation primaries, inheritance, renames — and reference
// expansion that may draw ONLY on the disclosure set (§2: expansion never
// becomes a side door around the gate).

interface RenderedItem {
  /** The Config Item the value comes from (a mapping may rename it). */
  name: string;
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
  // An erased version (ADR-0051) is never decrypted: it fails closed as missing.
  const res = await ctx.db.query("SELECT payload, wrapped_dek FROM value_versions WHERE id = $1 AND erased_at IS NULL", [versionId]);
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
  target: Pick<SyncTargetRow, "mapping" | "destination">,
  platform: string,
  /** Commits the audit event for exactly these versions; decryption follows only if it succeeds. */
  beforeDecrypt: (versions: { name: string; versionId: string }[]) => Promise<void>,
): Promise<{ items: RenderedItem[]; flags: string[]; held: { name: string; reason: string }[] }> {
  const adapter = getAdapter(platform);
  const resolved = await resolveItems(ctx, org, env, await activeContractOf(ctx, project), new Date());
  const flags: string[] = [];
  const held: { name: string; reason: string }[] = [];

  const mapping: SyncMapping = target.mapping;
  const selected: { name: string; destName: string; sensitive: boolean; valueRowId: string; versionId: string }[] = [];
  const seenDest = new Set<string>();
  const pick = (name: string, rename: string | undefined) => {
    const item = resolved.find((i) => i.name === name);
    if (!item) return; // not in effective output: convergence handles removal
    const destName = adapter.canonicalizeName(rename ?? name);
    if (adapter.validateName(destName) !== null) {
      flags.push(`${name}: unstorable name`);
      return;
    }
    // A name this destination's platform sets itself (a Coolify service's
    // SERVICE_URL_*): held, not a failure, as a wildcard cannot exclude
    // every future one (ADR-0031 amendment 2026-10-22).
    const owned = adapter.validateName(destName, target.destination);
    if (owned) {
      held.push({ name: destName, reason: owned });
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
        name: item.name,
        destName: item.destName,
        value: expandReferences(rawValue, (n) => plaintext.get(n), true),
        versionId: item.versionId,
      });
    } catch (error) {
      if (!(error instanceof ReferenceExpansionError)) throw error;
      flags.push(`${item.name}: ${error.message}`);
    }
  }
  return { items, flags, held };
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

async function adapterRequest(
  ctx: AppCtx,
  org: OrgRow,
  target: SyncTargetRow,
  live: LiveConnection,
  opts: SyncRunOptions,
  generation?: number,
) {
  return {
    baseIdentity: live.base_identity,
    destination: target.destination,
    ...(await credentialOf(ctx, org, target, live, opts)),
    ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
    // Per-request cancellation for writes/deletes/redeploy (preparatory
    // reads are not gated): a batch whose intents were accepted would
    // otherwise keep sending after a mid-batch fence. This narrows the
    // stale-send residual to the final check-to-send race per gated
    // request (plus requests already on the network). If the check itself
    // fails, don't send what we can't verify — the caller distinguishes a
    // confirmed fence from a probe failure and reschedules the latter.
    ...(generation !== undefined
      ? {
          // The send check: the generation still holds the Target, and the
          // run's deadline has not passed, both on the database clock in one
          // query (ADR-0050 Decisions 1 and 3).
          shouldAbort: async (): Promise<boolean> => {
            try {
              const res = await ctx.db.query(SEND_CHECK_SQL, [target.id, generation]);
              const row = res.rows[0] as { generation: string | number; within: boolean | null } | undefined;
              return !row || Number(row.generation) !== generation || row.within !== true;
            } catch {
              return true;
            }
          },
        }
      : {}),
  };
}

/**
 * The run's credential. A token Connection's stored token, whose expiry the
 * platform may report. An App Connection's token is minted for this run
 * (ADR-0047 Decision 3), narrowed to the Target's repository (and
 * environment) with write on its secrets, once per run; its expiry is
 * never recorded (Decision 4). A refused mint fails the run with Varlatch's
 * reading of GitHub's answer.
 */
async function credentialOf(
  ctx: AppCtx,
  org: OrgRow,
  target: SyncTargetRow,
  live: LiveConnection,
  opts: SyncRunOptions,
): Promise<{ credential: string; credentialKind: "token" | "github-app"; onCredentialExpiry?: (expiresAt: string) => void }> {
  if (live.credential_kind === "github-app") {
    if (live.minted_token === undefined) {
      const app = appCredentialFrom(ctx, org, live);
      if (!app) throw new GitHubAppTokenError(APP_REMOVED.message);
      const minted = await mintInstallationToken(opts.fetchImpl ?? fetch, app, "push", target.destination);
      if (!minted.ok) throw new GitHubAppTokenError(minted.check.message);
      live.minted_token = minted.token;
    }
    return { credential: live.minted_token, credentialKind: "github-app" };
  }
  const envelope =
    typeof live.credential_envelope === "string"
      ? (JSON.parse(live.credential_envelope) as Envelope)
      : (live.credential_envelope as Envelope);
  return {
    credential: decryptPlatformCredential(orgKekOf(ctx, org), target.organization_id, target.connection_id, envelope),
    credentialKind: "token",
    onCredentialExpiry: (expiresAt: string) => {
      live.observed_expiry = expiresAt;
    },
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
/**
 * Records a delivery audit event only while `generation` still holds the
 * Target (ADR-0050 Decision 2). The check and the insert share one
 * transaction with the Target row locked as `ledgerSet` locks it, so a
 * pause or revoke that fenced the run leaves no event behind it; a check
 * followed by an unlocked insert would race. Returns false when fenced.
 */
async function recordGuardedEvent(
  ctx: AppCtx,
  targetId: string,
  generation: number,
  event: Parameters<typeof recordAuditEvent>[1],
): Promise<boolean> {
  return withTx(ctx.db, async (db) => {
    const res = await db.query("SELECT generation FROM sync_targets WHERE id = $1 FOR SHARE", [targetId]);
    const current = res.rows[0] as { generation: string | number } | undefined;
    if (!current || Number(current.generation) !== generation) return false;
    await recordAuditEvent(db, event);
    return true;
  });
}

export async function ledgerSet(
  ctx: AppCtx,
  targetId: string,
  generation: number,
  destName: string,
  state: string,
  fp: string | null,
  lastError: string | null,
  /** A confirmed change that owes a redeploy: recorded in the same transaction (ADR-0050 Decision 4). */
  oweRedeploy = false,
): Promise<boolean> {
  return withTx(ctx.db, async (db) => {
    const res = await db.query(
      "SELECT generation FROM sync_targets WHERE id = $1 FOR SHARE",
      [targetId],
    );
    const current = res.rows[0] as { generation: string | number } | undefined;
    if (!current || Number(current.generation) !== generation) return false;
    await db.query(
      // A confirmed write or deletion earns repair credit; an intent or a
      // failure clears it (ADR-0050 Decision 4).
      `INSERT INTO sync_ledger (target_id, dest_name, fingerprint, state, generation, last_error, repaired_at)
       VALUES ($1, $2, $4, $5, $3, $6, CASE WHEN $5 IN ('written', 'tombstone') THEN now() END)
       ON CONFLICT (target_id, dest_name) DO UPDATE
         SET fingerprint = $4, state = $5, generation = $3, last_error = $6, updated_at = now(),
             repaired_at = CASE WHEN $5 IN ('written', 'tombstone') THEN now() END`,
      [targetId, destName, generation, fp, state, lastError],
    );
    // Only while the Target still wants redeploys: turning them off settles
    // the debt and fences the run, under the same row lock.
    if (oweRedeploy) await db.query("UPDATE sync_targets SET redeploy_owed = redeploy_owed + 1 WHERE id = $1 AND redeploy", [targetId]);
    return true;
  });
}

/**
 * Records drift before it is put back (ADR-0050 Decisions 9 and 11): the
 * sync.drift_detected event and the Target's last-drift summary, in one
 * transaction under the same generation guard as the other delivery
 * events. Names only. Returns false when the run was fenced.
 */
async function recordDrift(
  ctx: AppCtx,
  target: SyncTargetRow,
  generation: number,
  names: string[],
  metadata: Record<string, string | number>,
): Promise<boolean> {
  return withTx(ctx.db, async (db) => {
    const res = await db.query("SELECT generation FROM sync_targets WHERE id = $1 FOR SHARE", [target.id]);
    const current = res.rows[0] as { generation: string | number } | undefined;
    if (!current || Number(current.generation) !== generation) return false;
    const eventId = await recordAuditEvent(db, {
      eventType: "sync.drift_detected",
      decision: "info",
      organizationId: target.organization_id,
      action: "config.sync.manage",
      resource: { targetId: target.id, environmentId: target.environment_id },
      metadata,
    });
    await db.query(
      `UPDATE sync_targets
       SET last_drift_at = now(), last_drift_count = $2, last_drift_names = $3, last_drift_event_id = $4
       WHERE id = $1`,
      [target.id, names.length, JSON.stringify(names.slice(0, 50)), eventId],
    );
    return true;
  });
}

/**
 * Pays an owed redeploy (ADR-0050 Decision 4): reads the debt under this
 * run's generation, asks the adapter, and settles only the revision it read,
 * only when the platform accepted the request. An abort (the fence or the
 * deadline) sends nothing and leaves the debt for the next run; a refusal
 * leaves it too, and shows in the result. Delivery is at least once: a
 * crash after an accepted redeploy and before settling sends another.
 */
async function payRedeploy(
  ctx: AppCtx,
  adapter: ReturnType<typeof getAdapter>,
  target: SyncTargetRow,
  generation: number,
  req: Parameters<NonNullable<ReturnType<typeof getAdapter>["triggerRedeploy"]>>[0],
): Promise<string | typeof LEASE_LOST> {
  if (!target.redeploy || !adapter.supportsRedeploy || !adapter.triggerRedeploy) return "";
  // The current setting, not the one the run started with.
  const res = await ctx.db.query(
    "SELECT redeploy, redeploy_owed, redeploy_paid FROM sync_targets WHERE id = $1 AND generation = $2",
    [target.id, generation],
  );
  const row = res.rows[0] as { redeploy: boolean; redeploy_owed: string | number; redeploy_paid: string | number } | undefined;
  if (!row) return LEASE_LOST; // fenced: the successor pays
  if (!row.redeploy) return "";
  const owed = Number(row.redeploy_owed);
  if (owed <= Number(row.redeploy_paid)) return "";
  let outcome: "sent" | "aborted";
  try {
    outcome = await adapter.triggerRedeploy(req);
  } catch (err) {
    return `; redeploy failed (${err instanceof Error ? err.message : "error"})`;
  }
  if (outcome === "aborted") return LEASE_LOST;
  await ctx.db.query(
    "UPDATE sync_targets SET redeploy_paid = GREATEST(redeploy_paid, $3) WHERE id = $1 AND generation = $2",
    [target.id, generation, owed],
  );
  return "";
}

/** Repair credit for names a read-back proved current (written and present, or deleted and absent), under the same generation guard as ledgerSet. */
async function creditVerified(ctx: AppCtx, targetId: string, generation: number, names: string[]): Promise<boolean> {
  return withTx(ctx.db, async (db) => {
    const res = await db.query("SELECT generation FROM sync_targets WHERE id = $1 FOR SHARE", [targetId]);
    const current = res.rows[0] as { generation: string | number } | undefined;
    if (!current || Number(current.generation) !== generation) return false;
    await db.query(
      "UPDATE sync_ledger SET repaired_at = now() WHERE target_id = $1 AND dest_name = ANY($2) AND state IN ('written', 'tombstone')",
      [targetId, names],
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
  notes?: TargetNote[],
  credentialVersion?: number,
): Promise<void> {
  await withTx(ctx.db, async (db) => {
    // A failure with a credential replaced since the run read it is the old
    // credential's, not this Target's (#57): the replacement reset the count
    // and resumed what the old credential stopped, so it is not counted.
    // The Connection first, then the Target (ADR-0047 Decision 5's order): a
    // replacement holds the Connection while it resets the Target, so this
    // waits for it and then sees its version.
    if (credentialVersion !== undefined) {
      const connection = await db.query("SELECT version FROM platform_connections WHERE id = $1 FOR SHARE", [target.connection_id]);
      const row = connection.rows[0] as { version: number | string } | undefined;
      if (!row || Number(row.version) !== credentialVersion) return;
    }
    const params: unknown[] = [target.id];
    const guard = generation !== undefined ? ` AND generation = $${params.push(generation)}` : "";
    // The count as it is now, not as the run's lease read it: a replacement
    // may have reset it since.
    const locked = await db.query(
      `SELECT failure_count FROM sync_targets WHERE id = $1 AND revoked_at IS NULL${guard} FOR UPDATE`,
      params,
    );
    const current = locked.rows[0] as { failure_count: number | string } | undefined;
    if (!current) return;
    const previous = Number(current.failure_count);
    const failures = previous + 1;
    const delayMs = Math.min(BASE_BACKOFF_MS * 2 ** previous, MAX_BACKOFF_MS);
    const disable = backoff && failures >= FAILURE_BUDGET;
    // A failed run leaves pending work: needs_sync must come back on (lease
    // acquisition cleared it) or the backed-off retry would never qualify for
    // selection and the Target would wait for the next trigger or repair pass.
    const update: unknown[] = [target.id, failures, result.slice(0, 500), delayMs, disable];
    const setNotes = notes !== undefined ? `, last_notes = $${update.push(JSON.stringify(notes))}` : "";
    await db.query(
      `UPDATE sync_targets
       SET failure_count = $2, last_result = $3, needs_sync = true,
           next_attempt_at = now() + ($4 * interval '1 millisecond'),
           state = CASE WHEN $5 THEN 'disabled' ELSE state END,
           disabled_reason = CASE WHEN $5 THEN 'failure-budget-exhausted' ELSE disabled_reason END${setNotes}
       WHERE id = $1`,
      update,
    );
    if (disable) {
      // Auto-disable is a state the UI must surface; a human resumes (§5).
      await recordAuditEvent(db, {
        eventType: "sync.target_disabled",
        decision: "info",
        organizationId: target.organization_id,
        action: "config.sync.manage",
        resource: { targetId: target.id, environmentId: target.environment_id },
        metadata: { reason: "failure-budget-exhausted", failures, lastResult: result.slice(0, 300) },
      });
    }
  });
}

function flagSummary(flags: string[]): string {
  return `flagged: ${flags.join("; ")}`.slice(0, 500);
}

/**
 * A run's result with the names it held appended, bounded. Held names are
 * no failure (ADR-0031 amendment 2026-10-22): a run whose only problems
 * they are succeeds, so they never spend the failure budget or schedule a
 * retry, and the result says what was held and why.
 */
function withHeld(result: string, held: string[]): string {
  return (held.length > 0 ? `${result}; held: ${held.join("; ")}` : result).slice(0, 500);
}

/** Periodic delivery, modeled on the webhook loop: best-effort, never throws. */
/**
 * For each Target, the start of its oldest run that can still send
 * (ADR-0050 Decision 5); a Target missing from the map is drained.
 */
export async function liveRunStarts(ctx: AppCtx, targetIds: string[]): Promise<Map<string, Date>> {
  if (targetIds.length === 0) return new Map();
  const res = await ctx.db.query(
    `SELECT target_id, min(started_at) AS started_at FROM sync_runs
     WHERE target_id = ANY($1) AND deadline > now() GROUP BY target_id`,
    [targetIds],
  );
  return new Map(
    res.rows.map((r) => {
      const row = r as { target_id: string; started_at: Date | string };
      return [row.target_id, new Date(row.started_at)];
    }),
  );
}

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
