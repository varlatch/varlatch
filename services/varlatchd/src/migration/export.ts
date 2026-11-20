// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Writable } from "node:stream";
import type { Gate } from "@varlatch/backup";
import type { PoolQuerier } from "../db/tx.js";
import { loadManifest, writeBundle, type BundleSummary, type FrozenPoint } from "./bundle.js";
import { decisionTable } from "./decisions.js";
import { digests } from "./digests.js";
import { preflight, type Preflight } from "./preflight.js";
import { pgRowSource } from "./source.js";

/**
 * `varlatchd admin migration export` (ADR-0059 step 7, go-step7 slice
 * 7.2b): the source bundle (bundle.ts), and beside it the report: the
 * preflight, decision 7's digests (with a run key) and decision 8's
 * decision table, all read from one snapshot.
 *
 * Where it reads:
 *   - behind the barrier (`migration`, drained), from the snapshot the
 *     barrier exported and holds (SET TRANSACTION SNAPSHOT), so two
 *     exports at the same frozen point are byte for byte the same;
 *     without a held snapshot (the barrier ran with no daemon, or the
 *     daemon restarted) and once `migrated-out`, from its own, after
 *     checking the last audit position is still the frozen one;
 *   - in a dry run (no gate), from its own consistent snapshot.
 * It writes nothing to the database. A refused preflight writes no bundle.
 *
 * The report is JSON Lines too:
 *   {"report":"varlatch-migration","format":1,"direction":"forward","frozenPoint":{"auditPosition":<n>,"snapshot":"<id>"}}
 *   {"preflight":{...}}
 *   {"digest":{"class":...,"ids":{...},"hmac":"<hex>"}}         (with a run key)
 *   {"decision":{"identityId":...,"credential":...,...,"outcome":...}}
 *   {"end":{"bundle":{"tables":<n>,"rows":<n>,"sha256":"<hex>"},"digests":<n>,"decisions":<n>}}
 */

export class ExportRefused extends Error {
  override name = "ExportRefused";
  constructor(message: string, readonly preflight?: Preflight) {
    super(message);
  }
}

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
  digests: number;
  decisions: number;
}

export async function exportSource(
  db: PoolQuerier,
  opts: { gate: Gate | null; dryRun: boolean; out: Writable; report: Writable; rootKek: Buffer | null; runKey: Buffer | null },
): Promise<ExportResult> {
  const mode = exportMode(opts.gate, opts.dryRun);
  const manifest = loadManifest();
  const client = await db.connect();
  const line = (v: unknown) => writeLine(opts.report, v);
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    let snapshot: string;
    if (mode.snapshot) {
      if (!SNAPSHOT.test(mode.snapshot)) throw new ExportRefused("the barrier's snapshot id is malformed");
      try {
        await client.query(`SET TRANSACTION SNAPSHOT '${mode.snapshot}'`);
      } catch {
        throw new ExportRefused("the barrier's snapshot is no longer held (varlatchd restarted?): run varlatchd admin migration barrier again to freeze a new one");
      }
      snapshot = mode.snapshot;
    } else {
      snapshot = ((await client.query("SELECT pg_export_snapshot() AS s")).rows[0] as { s: string }).s;
    }
    const position = ((await client.query("SELECT coalesce(max(event_order), 0)::text AS p FROM audit_events")).rows[0] as { p: string }).p;
    if (mode.position !== null && position !== mode.position) {
      throw new ExportRefused(`the installation's last audit position is ${position}, not the frozen ${mode.position}: something wrote after the barrier; nothing was exported`);
    }
    const frozenPoint = { auditPosition: position, snapshot };
    await line(`{"report":"varlatch-migration","format":1,"direction":"forward","frozenPoint":{"auditPosition":${position},"snapshot":${JSON.stringify(snapshot)}}}`);
    const pre = await preflight(client, manifest);
    await line({ preflight: pre });
    if (!pre.ok) throw new ExportRefused(`preflight refused the export: ${pre.failures.map((f) => f.message).join("; ")}`, pre);

    const bundle = await writeBundle(opts.out, { manifest, frozenPoint, rows: pgRowSource(client) });
    let digestCount = 0;
    if (opts.runKey) {
      if (!opts.rootKek) throw new ExportRefused("the digests need the Root KEK");
      for await (const d of digests(client, opts.rootKek, opts.runKey)) {
        await line({ digest: d });
        digestCount++;
      }
    }
    let decisionCount = 0;
    for await (const d of decisionTable(client)) {
      await line({ decision: d });
      decisionCount++;
    }
    await line({ end: { bundle, digests: digestCount, decisions: decisionCount } });
    await client.query("COMMIT");
    return { frozenPoint, preflight: pre, bundle, digests: digestCount, decisions: decisionCount };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

async function writeLine(out: Writable, text: unknown): Promise<void> {
  const s = typeof text === "string" ? text : JSON.stringify(text);
  if (!out.write(s + "\n")) await new Promise<void>((resolve) => out.once("drain", resolve));
}
