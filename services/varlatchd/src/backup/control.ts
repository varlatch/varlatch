// SPDX-License-Identifier: AGPL-3.0-or-later
import { createServer, request } from 'node:http';
import { chmodSync, existsSync, readFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { durableJson, Maintenance, EMBEDDED_RELEASE, backupStatus, recordReleaseCheck, releaseCheckInputSchema, saveStatus, statusSchema, type Gate } from '@varlatch/backup';
import type { AppCtx } from '../domain/ctx.js';
import { getInstallation, verifyLoadedKek } from '../domain/bootstrap.js';
import { archiveMetadata } from './metadata.js';
export { archiveMetadata };
import { schemaIsCurrent } from '../db/migrate.js';
import { syncAllMirrors, type MirrorConfig } from '../mirror/publisher.js';
import { drainOperators } from "./operator-lock.js";
import type { PoolQuerier } from "../db/tx.js";
import { recordRestore } from '../domain/auditexport.js';
import { OnlineCapture, CAPTURE_EXCLUSION } from './online.js';

export const stateDir = () => process.env.VARLATCH_STATE_DIR ?? '/var/lib/varlatch';
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
/** The control commands that only read, answered even while another runs. */
const READ_ONLY_COMMANDS = new Set(['migration-status', 'gate', 'status']);
/** No TCP listener: only Infrastructure Operators with access to the container can invoke this. */
export function startBackupControl(ctx: AppCtx, maintenance: Maintenance, mirror: MirrorConfig | null): OnlineCapture {
  const socket = join(maintenance.dir, 'backup.sock');
  if (existsSync(socket)) unlinkSync(socket);
  const online = new OnlineCapture({ ...ctx, db: ctx.db as PoolQuerier });
  let operation = false;
  const server = createServer(async (req, res) => {
    try {
      let body = '';
      for await (const chunk of req) { body += String(chunk); if (body.length > 64 * 1024) throw new Error('Control request too large'); }
      const input = JSON.parse(body || '{}') as { command: string; id?: string; ttlMs?: number; drainMs?: number; status?: unknown; installationId?: string; manifestIdentity?: string; releaseCheck?: unknown };
      // The read-only commands answer beside a running operation (a drain
      // in progress included); every other command runs alone.
      const readOnly = READ_ONLY_COMMANDS.has(input.command);
      if (!readOnly && operation) throw new Error('Another control operation is running');
      if (!readOnly) operation = true;
      try {
        const getGate = () => maintenance.require(input.id ?? '');
        const drain = async () => {
          while (maintenance.busy > 0) { getGate(); await delay(50); }
          getGate();
        };
        let result: unknown;
        switch (input.command) {
          // Online capture (ADR-0036): no gate, no pause, no Application Plane.
          case 'online-capture-begin': {
            if (maintenance.gate) throw new Error('Installation maintenance is active; capture refused');
            result = await online.begin(input.ttlMs ?? 300_000); break;
          }
          case 'online-capture-finish': result = await online.finish(input.id ?? ''); break;
          case 'online-capture-abort': await online.abort(input.id ?? ''); result = { aborted: true }; break;
          // Frozen capture (ADR-0033), kept for host CLIs older than this daemon.
          case 'capture-begin': {
            if (online.running) throw new Error('An online backup capture is running');
            result = maintenance.beginCapture(input.ttlMs ?? 300_000); break;
          }
          case 'capture-pause': {
            const gate = getGate(); if (gate.kind !== 'capture') throw new Error('Not a capture');
            await drain();
            await drainOperators(ctx.db as PoolQuerier, getGate);
            const metadata = await archiveMetadata(ctx);
            if (!mirror) throw new Error('Application Plane URL is required for an installation backup');
            await syncAllMirrors(ctx, mirror);
            maintenance.phase(gate.id, 'paused');
            result = metadata; break;
          }
          case 'capture-finish': maintenance.finishCapture(getGate().id); result = { completed: true }; break;
          case 'gate': result = { gate: getGate(), busy: maintenance.busy }; break;
          case 'restore-drain': {
            if (getGate().kind !== 'restore') throw new Error('Not a restore');
            if (online.running) throw new Error('A backup capture is running; restore refused');
            await drain();
            // Existing operator processes are drained when the database exists.
            // Fresh-host restore has no operator process that could have entered it.
            try {
              await drainOperators(ctx.db as PoolQuerier, getGate);
              // No capture from another process may hold the exclusion either.
              const held = await ctx.db.query('SELECT pg_try_advisory_lock($1) AS acquired', [CAPTURE_EXCLUSION]);
              if (!(held.rows[0] as { acquired: boolean }).acquired) throw new Error('A backup capture is running; restore refused');
              await ctx.db.query('SELECT pg_advisory_unlock($1)', [CAPTURE_EXCLUSION]);
            }
            catch (e) { if ((e as { code?: string }).code !== "3D000") throw e; }
            // No DB writes: safe even on a fresh, empty host.
            result = { isolated: true }; break;
          }
          case 'restore-reconcile': {
            const gate = getGate(); if (gate.kind !== 'restore') throw new Error('Not a restore');
            const inst = await getInstallation(ctx.db);
            if (!inst || inst.id !== input.installationId || !(await verifyLoadedKek(ctx)) || !(await schemaIsCurrent(ctx.db))) throw new Error('Restored installation, schema, or canary did not verify');
            if (!mirror) throw new Error('Application Plane URL is required');
            if (!/^[0-9a-f]{64}$/.test(input.manifestIdentity ?? '')) throw new Error('Restore manifest identity is required');
            // First new audit event, before reconciliation and before admitting work.
            // Every audit export starts a new stream in the same transaction (ADR-0056 Decision 5).
            await recordRestore(ctx.db, { eventType: 'installation.restored', decision: 'info', metadata: { archiveId: gate.archiveId, manifestIdentity: input.manifestIdentity!, installationId: inst.id } });
            maintenance.phase(gate.id, 'reconciling');
            for (let i = 0; i < 120; i++) {
              try {
                const response = await fetch(`${mirror.convexUrl}/version`, { signal: AbortSignal.timeout(1000) });
                if (response.ok) break;
              } catch { /* supervisor is starting the backend */ }
              if (i === 119) throw new Error('Application Plane did not restart for reconciliation');
              await delay(500);
            }
            // The Application Plane was reset, not restored (ADR-0036 D3): it
            // has no functions until the deploy job runs after isolation
            // clears, and Mirrors are published after that.
            durableJson(join(maintenance.dir, "restore-verified.json"), { id: gate.id });
            result = { reconciled: true }; break;
          }
          case 'restore-complete': {
            const gate = getGate();
            if (gate.kind !== 'restore' || gate.phase !== 'reconciling') throw new Error('Restore has not reached reconciliation');
            const proof = JSON.parse(readFileSync(join(maintenance.dir, "restore-verified.json"), "utf8"));
            if (proof.id !== gate.id) throw new Error("Restore reconciliation has not completed");
            // Completion is separate so the host can validate both planes first.
            if (!(await verifyLoadedKek(ctx)) || !(await schemaIsCurrent(ctx.db))) throw new Error('Final restore checks failed');
            maintenance.completeRestore(gate.id); result = { completed: true }; break;
          }
          // The migration barrier (ADR-0059 step 7, go-step7 decision 6),
          // through `varlatchd admin migration`: never entered otherwise.
          case 'migration-barrier': {
            if (online.running) throw new Error('A backup capture is running; the migration barrier was not opened');
            result = await migrationBarrier(ctx, maintenance, input.drainMs ?? MIGRATION_DRAIN_MS); break;
          }
          case 'migration-status': result = { gate: maintenance.gate, busy: maintenance.busy, inFlight: maintenance.busyLabels }; break;
          case 'migration-release': maintenance.releaseMigration(input.id ?? ''); await releaseHeldSnapshot(); result = { released: true }; break;
          case 'migration-migrated-out': result = { gate: maintenance.markMigratedOut(input.id ?? '') }; await releaseHeldSnapshot(); break;
          case 'status': result = backupStatus(maintenance.dir); break;
          case 'record': saveStatus(maintenance.dir, statusSchema.parse(input.status)); result = { recorded: true }; break;
          // The host's look for a newer release (ADR-0049): display state for
          // Installation Admins, recorded as the host CLI found it.
          case 'release-check': {
            const parsed = releaseCheckInputSchema.safeParse(input.releaseCheck);
            if (!parsed.success) throw new Error('Invalid release check');
            recordReleaseCheck(maintenance.dir, parsed.data); result = { recorded: true }; break;
          }
          default: throw new Error('Unknown backup control command');
        }
        res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(result));
      } finally { if (!readOnly) operation = false; }
    } catch (error) {
      res.writeHead(409, { 'content-type': 'application/json' });
      // Our own operator diagnostics contain no credential or DB error details.
      res.end(JSON.stringify({ error: error instanceof Error && !('code' in error) ? error.message : 'Backup control operation failed' }));
    }
  });
  server.listen(socket, () => chmodSync(socket, 0o600));
  const timer = setInterval(() => { try { maintenance.cleanExpired(); } catch { /* unreadable state fails closed */ } }, 500);
  timer.unref();
  return online;
}
/** How long the barrier waits for what is in flight to finish, by default. */
export const MIGRATION_DRAIN_MS = 15 * 60_000;

/** What the barrier reports: the gate, what it waited for, and the frozen point. */
export interface MigrationBarrier {
  gate: Gate;
  drained: { ms: number; waitedFor: Record<string, number> };
  frozen: { auditPosition: string; at: string; snapshot: string | null };
}

/**
 * Opens (or, after an interruption, continues) the migration barrier and
 * drains it: in-flight requests and every background loop's pass end
 * (each counted by its label, so the report names what was waited for),
 * then the operator processes and any backup capture of another process;
 * nothing new starts. The frozen point is the last audit position. It
 * writes nothing to the database. A drain that does not finish within
 * drainMs leaves the barrier held and names what still runs.
 */
export async function migrationBarrier(ctx: AppCtx, maintenance: Maintenance, drainMs: number): Promise<MigrationBarrier> {
  const open = maintenance.gate;
  const gate = open?.kind === 'migration' ? open : maintenance.beginMigration();
  const started = Date.now();
  const waitedFor: Record<string, number> = {};
  while (maintenance.busy > 0) {
    maintenance.require(gate.id);
    for (const [label, n] of Object.entries(maintenance.busyLabels)) waitedFor[label] = Math.max(waitedFor[label] ?? 0, n);
    if (Date.now() - started > drainMs) {
      throw new Error(`The migration barrier is held, but did not drain within ${Math.round(drainMs / 1000)} s; still running: ${Object.keys(maintenance.busyLabels).join(', ')}. Run the barrier again to keep waiting, or release it.`);
    }
    await delay(50);
  }
  // Operator processes, within what is left of the drain's time.
  await drainOperators(ctx.db as PoolQuerier, () => {
    maintenance.require(gate.id);
    if (Date.now() - started > drainMs) {
      throw new Error(`The migration barrier is held, but did not drain within ${Math.round(drainMs / 1000)} s; still running: an operator process. Run the barrier again to keep waiting, or release it.`);
    }
  });
  const held = await ctx.db.query('SELECT pg_try_advisory_lock($1) AS acquired', [CAPTURE_EXCLUSION]);
  if (!(held.rows[0] as { acquired: boolean }).acquired) throw new Error('A backup capture of another process is running; the barrier is held: run it again once the capture ends');
  await ctx.db.query('SELECT pg_advisory_unlock($1)', [CAPTURE_EXCLUSION]);
  // The frozen point: a snapshot exported now and held while the barrier
  // stands, and the last audit position read in it. The export reads from
  // that snapshot, so two exports at the frozen point read the same state.
  const pinned = await holdSnapshot(ctx.db as PoolQuerier, gate.id);
  const last = pinned
    ? pinned.position
    : ((await ctx.db.query('SELECT coalesce(max(event_order), 0)::text AS p FROM audit_events')).rows[0] as { p: string } | undefined)?.p ?? '0';
  const frozen = maintenance.freezeMigration(gate.id, last, pinned?.snapshot ?? null);
  return { gate: frozen, drained: { ms: Date.now() - started, waitedFor }, frozen: { auditPosition: last, at: new Date().toISOString(), snapshot: pinned?.snapshot ?? null } };
}

/** The barrier's held snapshot: its transaction stays open while the barrier stands. */
let held: { gateId: string; client: Awaited<ReturnType<PoolQuerier['connect']>>; snapshot: string; position: string } | null = null;

/**
 * Exports a snapshot and keeps its read-only transaction open (in this
 * daemon) until the barrier is released or marked migrated out. A rerun of
 * the barrier keeps the one it holds. Null when the database cannot hold
 * one: the export then reads its own and checks the frozen position.
 */
async function holdSnapshot(db: PoolQuerier, gateId: string): Promise<{ snapshot: string; position: string } | null> {
  if (held?.gateId === gateId) return held;
  await releaseHeldSnapshot();
  let client: Awaited<ReturnType<PoolQuerier['connect']>> | null = null;
  try {
    client = await db.connect();
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const snapshot = ((await client.query('SELECT pg_export_snapshot() AS s')).rows[0] as { s: string }).s;
    const position = ((await client.query('SELECT coalesce(max(event_order), 0)::text AS p FROM audit_events')).rows[0] as { p: string }).p;
    held = { gateId, client, snapshot, position };
    return held;
  } catch {
    if (client) {
      await client.query('ROLLBACK').catch(() => {});
      client.release();
    }
    return null;
  }
}

/** Ends the held snapshot's transaction, if any. */
export async function releaseHeldSnapshot(): Promise<void> {
  const h = held;
  held = null;
  if (!h) return;
  await h.client.query('ROLLBACK').catch(() => {});
  h.client.release();
}

export async function control(input: unknown, dir = stateDir()): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const req = request({ socketPath: join(dir, 'backup.sock'), path: '/', method: 'POST' }, res => {
      let text = ''; res.on('data', c => { text += String(c); });
      res.on('end', () => { try { const value = JSON.parse(text); if (res.statusCode !== 200) reject(new Error(value.error)); else resolve(value); } catch { reject(new Error('Invalid backup control response')); } });
    });
    // Only a socket that is not there, or that nobody listens on, means no
    // daemon; any other failure (permissions, a transient error) is not.
    req.on('error', (e: NodeJS.ErrnoException) => reject(new Error(
      e.code === 'ENOENT' || e.code === 'ECONNREFUSED' ? 'Backup supervisor is not running' : `Backup control socket failed (${e.code ?? 'error'})`,
    )));
    req.end(JSON.stringify(input));
  });
}
