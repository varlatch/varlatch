// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Writable } from "node:stream";
import type { Gate } from "@varlatch/backup";
import type { PoolQuerier } from "../db/tx.js";
import { loadManifest, writeBundle, type BundleSummary, type Digest, type FrozenPoint } from "./bundle.js";
import { decisionTable } from "./decisions.js";
import { digests } from "./digests.js";
import { preflight, type Preflight } from "./preflight.js";
import { ExportRefused } from "./refused.js";
import { pgRowSource } from "./source.js";

export { ExportRefused };

/**
 * `varlatchd admin migration export` (ADR-0059 step 7, go-step7 slice
 * 7.2b): the source bundle (bundle.ts, varlatchd's BUNDLE.md) with its
 * tables, decision 7's digests (with a run key) and decision 8's decision
 * table, all read from one snapshot, once the preflight passes.
 *
 * Where it reads:
 *   - behind the barrier (`migration`, drained), from the snapshot the
 *     barrier exported and holds in the running daemon (SET TRANSACTION
 *     SNAPSHOT), so two exports at the same frozen point are byte for byte
 *     the same;
 *   - when the barrier holds none (it ran with no daemon) and once
 *     `migrated-out`, from its own, after checking the last audit position
 *     is still the frozen one;
 *   - in a dry run (no gate), from its own consistent snapshot.
 * It writes nothing to the database. A refused preflight writes no bundle.
 *
 * The decisions are evaluated at the frozen point: their moment (`at`) is
 * the last audit event's, so it too is the same at every export.
 */

const SNAPSHOT = /^[0-9A-F]+-[0-9A-F]+-[0-9]+$/i;

/** Where an export may read from, by the gate in force, or why it may not. */
export function exportMode(gate: Gate | null, dryRun: boolean): { snapshot: string | null; position: string | null } {
  if (!gate) {
    if (!dryRun) throw new ExportRefused("no migration barrier is held: open it first (varlatchd admin migration barrier), or pass --dry-run to read a consistent snapshot of the running installation");
    return { snapshot: null, position: null };
  }
  if (dryRun) throw new ExportRefused(`a ${gate.kind} gate is open: a dry run reads a running installation only`);
  if (gate.kind === "migration" && gate.phase === "paused" && gate.frozenPosition) {
    return { snapshot: gate.frozenSnapshot ?? null, position: gate.frozenPosition };
  }
  if (gate.kind === "migrated-out" && gate.frozenPosition) return { snapshot: null, position: gate.frozenPosition };
  throw new ExportRefused(gate.kind === "migration" ? "the migration barrier has not drained yet: run varlatchd admin migration barrier again" : `a ${gate.kind} gate is open: the export reads behind the migration barrier only`);
}

export interface ExportResult {
  frozenPoint: FrozenPoint;
  preflight: Preflight;
  bundle: BundleSummary;
}

export async function exportSource(
  db: PoolQuerier,
  opts: { gate: Gate | null; dryRun: boolean; out: Writable; rootKek: Buffer | null; runKey: Buffer | null },
): Promise<ExportResult> {
  const mode = exportMode(opts.gate, opts.dryRun);
  if (opts.runKey && !opts.rootKek) throw new ExportRefused("the digests need the Root KEK");
  const manifest = loadManifest();
  const client = await db.connect();
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    let snapshot: string;
    if (mode.snapshot) {
      if (!SNAPSHOT.test(mode.snapshot)) throw new ExportRefused("the barrier's snapshot id is malformed");
      try {
        await client.query(`SET TRANSACTION SNAPSHOT '${mode.snapshot}'`);
      } catch {
        throw new ExportRefused(
          "the snapshot the barrier holds is gone (varlatchd restarted or stopped, or its transaction was ended, by idle_in_transaction_session_timeout for one): " +
            "with varlatchd running, run varlatchd admin migration barrier again, which holds a new one at the same frozen point",
        );
      }
      snapshot = mode.snapshot;
    } else {
      snapshot = ((await client.query("SELECT pg_export_snapshot() AS s")).rows[0] as { s: string }).s;
    }
    const last = (await client.query(
      `SELECT coalesce(max(event_order), 0)::text AS p,
              coalesce((SELECT (extract(epoch FROM occurred_at) * 1000000)::bigint FROM audit_events ORDER BY event_order DESC LIMIT 1), 0)::text AS at
         FROM audit_events`,
    )).rows[0] as { p: string; at: string };
    if (mode.position !== null && last.p !== mode.position) {
      throw new ExportRefused(`the installation's last audit position is ${last.p}, not the frozen ${mode.position}: something wrote after the barrier; nothing was exported`);
    }
    const frozenPoint = { auditPosition: last.p, snapshot };
    const pre = await preflight(client, manifest);
    if (!pre.ok) throw new ExportRefused(`preflight refused the export: ${pre.failures.map((f) => f.message).join("; ")}`, pre);

    const items: Digest[] = [];
    if (opts.runKey) for await (const d of digests(client, opts.rootKek!, opts.runKey)) items.push(d);
    const bundle = await writeBundle(opts.out, {
      manifest,
      frozenPoint,
      rows: pgRowSource(client),
      digests: items,
      decisions: await decisionTable(client, BigInt(last.at)),
    });
    await client.query("COMMIT");
    return { frozenPoint, preflight: pre, bundle };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}
