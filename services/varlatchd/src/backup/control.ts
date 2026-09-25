// SPDX-License-Identifier: AGPL-3.0-or-later
import { createServer, request } from 'node:http';
import { chmodSync, existsSync, readFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { durableJson, Maintenance, EMBEDDED_RELEASE, backupStatus, saveStatus, statusSchema, type Gate } from '@varlatch/backup';
import type { AppCtx } from '../domain/ctx.js';
import { getInstallation, verifyLoadedKek } from '../domain/bootstrap.js';
import { archiveMetadata } from './metadata.js';
export { archiveMetadata };
import { schemaIsCurrent } from '../db/migrate.js';
import { syncAllMirrors, type MirrorConfig } from '../mirror/publisher.js';
import { drainOperators } from "./operator-lock.js";
import type { PoolQuerier } from "../db/tx.js";
import { recordAuditEvent } from '../audit/events.js';
import { OnlineCapture, CAPTURE_EXCLUSION } from './online.js';

export const stateDir = () => process.env.VARLATCH_STATE_DIR ?? '/var/lib/varlatch';
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
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
      const input = JSON.parse(body || '{}') as { command: string; id?: string; ttlMs?: number; status?: unknown; installationId?: string; manifestIdentity?: string };
      if (operation) throw new Error('Another control operation is running');
      operation = true;
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
            await recordAuditEvent(ctx.db, { eventType: 'installation.restored', decision: 'info', metadata: { archiveId: gate.archiveId, manifestIdentity: input.manifestIdentity!, installationId: inst.id } });
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
          case 'status': result = backupStatus(maintenance.dir); break;
          case 'record': saveStatus(maintenance.dir, statusSchema.parse(input.status)); result = { recorded: true }; break;
          default: throw new Error('Unknown backup control command');
        }
        res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(result));
      } finally { operation = false; }
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
export async function control(input: unknown, dir = stateDir()): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const req = request({ socketPath: join(dir, 'backup.sock'), path: '/', method: 'POST' }, res => {
      let text = ''; res.on('data', c => { text += String(c); });
      res.on('end', () => { try { const value = JSON.parse(text); if (res.statusCode !== 200) reject(new Error(value.error)); else resolve(value); } catch { reject(new Error('Invalid backup control response')); } });
    });
    req.on('error', () => reject(new Error('Backup supervisor is not running')));
    req.end(JSON.stringify(input));
  });
}
