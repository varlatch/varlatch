// SPDX-License-Identifier: Apache-2.0
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, unlinkSync, linkSync, openSync, fsyncSync, closeSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { BackupError } from './archive.js';

/**
 * The installation's maintenance gate (ADR-0033, ADR-0036). Besides a
 * backup capture and a restore, the migration to the Go line (ADR-0059
 * step 7, internal docs/design/go-step7.md decisions 6 and 15) has two
 * kinds, opened only by `varlatchd admin migration ...`:
 *   - `migration`: the barrier. Unlike a capture it has no deadline and is
 *     never cleared when the daemon starts; only `admin migration release`
 *     ends it. `frozenPosition` is the last audit position once drained.
 *   - `migrated-out`: permanent, once the installation moved; every request
 *     is refused, reads included. Only a completed reverse migration
 *     removes it (not in this release's slice 7.2a).
 * An installation that never runs the migration never sees either.
 */
export type GateKind = 'capture' | 'restore' | 'migration' | 'migrated-out';
export interface Gate {
  id: string; kind: GateKind; phase: 'draining' | 'paused' | 'reconciling';
  expiresAt: number | null; archiveId: string | null;
  /** The migration barrier's frozen point: the last audit position (event_order), once drained. */
  frozenPosition?: string | null;
  /**
   * The PostgreSQL snapshot the barrier exported at its frozen point and
   * holds while it stands (the export reads from it); null when none is
   * held (the barrier ran with no daemon).
   */
  frozenSnapshot?: string | null;
}
const GATE_KINDS: readonly GateKind[] = ['capture', 'restore', 'migration', 'migrated-out'];
/** Whether a gate belongs to the migration: kept across a restart, never expiring. */
export function isMigrationGate(gate: Gate | null): boolean {
  return gate?.kind === 'migration' || gate?.kind === 'migrated-out';
}
export function durableJson(path: string, value: unknown, exclusive = false): void {
  const temp = `${path}.${randomUUID()}.tmp`;
  const fd = openSync(temp, 'wx', 0o644);
  try { writeFileSync(fd, JSON.stringify(value)); fsyncSync(fd); } finally { closeSync(fd); }
  try { if (exclusive) linkSync(temp, path); else renameSync(temp, path); }
  finally { if (existsSync(temp)) unlinkSync(temp); }
  const directory = openSync(join(path, '..'), 'r'); try { fsyncSync(directory); } finally { closeSync(directory); }
}
export function readGate(dir: string): Gate | null {
  try {
    const value = JSON.parse(readFileSync(join(dir, 'maintenance.json'), 'utf8')) as Gate;
    if (!value.id || !GATE_KINDS.includes(value.kind) || !['draining', 'paused', 'reconciling'].includes(value.phase) ||
        (value.kind === 'capture' && (!Number.isFinite(value.expiresAt) || (value.expiresAt as number) <= 0)) ||
        (isMigrationGate(value) && (value.expiresAt !== null || value.phase === 'reconciling')) ||
        (value.kind === 'migrated-out' && value.phase !== 'paused') ||
        (value.frozenPosition !== undefined && value.frozenPosition !== null &&
          (typeof value.frozenPosition !== 'string' || !/^[0-9]+$/.test(value.frozenPosition))) ||
        (value.frozenSnapshot !== undefined && value.frozenSnapshot !== null &&
          (typeof value.frozenSnapshot !== 'string' || !/^[0-9A-F]+-[0-9A-F]+-[0-9]+$/i.test(value.frozenSnapshot)))) throw new Error();
    return value;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw new BackupError('Maintenance state is unreadable; isolation remains active');
  }
}
export function activeGate(dir: string, now = Date.now()): Gate | null {
  const g = readGate(dir);
  return g?.kind === 'capture' && (g.expiresAt as number) <= now ? null : g;
}
/** Single-process controller; all online mutations enter through its operator-only Unix socket. */
export class Maintenance {
  private active = 0;
  /** What is in flight, by label ("request", "webhooks", ...), for a drain's report. */
  private readonly inFlight = new Map<string, number>();
  constructor(readonly dir: string, private readonly now: () => number = Date.now) { mkdirSync(dir, { recursive: true, mode: 0o755 }); }
  get gate(): Gate | null { return activeGate(this.dir, this.now()); }
  get busy(): number { return this.active; }
  /** What is in flight now, by label: a drain's report of what it still waits for. */
  get busyLabels(): Record<string, number> { return Object.fromEntries([...this.inFlight].filter(([, n]) => n > 0)); }
  /**
   * Synchronous admission ensures no task slips between gate inspection and
   * accounting. label names what enters (a background loop's name, or
   * "request"), for the drain's report.
   */
  enter(label = 'request'): (() => void) | null {
    if (this.gate) return null;
    this.active++;
    this.inFlight.set(label, (this.inFlight.get(label) ?? 0) + 1);
    let done = false;
    return () => {
      if (!done) { done = true; this.active--; this.inFlight.set(label, (this.inFlight.get(label) ?? 1) - 1); }
    };
  }
  beginCapture(ttlMs: number): Gate {
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1000 || ttlMs > 24 * 60 * 60 * 1000) throw new BackupError('Capture deadline must be between 1 second and 24 hours');
    this.cleanExpired();
    const gate: Gate = { id: randomUUID(), kind: 'capture', phase: 'draining', expiresAt: this.now() + ttlMs, archiveId: null };
    durableJson(join(this.dir, 'maintenance.json'), gate, true);
    return gate;
  }
  /**
   * What `varlatchd serve` does with a gate it finds at start: an interrupted
   * capture is cleared (its process is gone); a restore and the migration's
   * gates stay, so a restart behind the barrier stays behind it. The gate
   * left open, or null.
   */
  clearInterruptedCapture(): Gate | null {
    const gate = this.gate;
    if (gate?.kind === 'capture') { this.finishCapture(gate.id); return this.gate; }
    return gate;
  }
  cleanExpired(): void {
    const old = readGate(this.dir);
    if (old?.kind === 'capture' && (old.expiresAt as number) <= this.now()) unlinkSync(join(this.dir, 'maintenance.json'));
  }
  require(id: string): Gate {
    const gate = this.gate;
    if (!gate || gate.id !== id) throw new BackupError('Maintenance ownership lost; discard this capture');
    return gate;
  }
  phase(id: string, phase: Gate['phase']): Gate {
    const gate = this.require(id);
    const next = { ...gate, phase };
    durableJson(join(this.dir, 'maintenance.json'), next);
    return next;
  }
  finishCapture(id: string): void {
    if (this.require(id).kind !== 'capture') throw new BackupError('Restore isolation cannot expire or be released as capture');
    unlinkSync(join(this.dir, 'maintenance.json'));
  }
  /**
   * The migration barrier (go-step7 decision 6): a gate with no deadline,
   * created only when none is open (a capture or a restore refuses it).
   */
  beginMigration(): Gate {
    this.cleanExpired();
    if (readGate(this.dir)) throw new BackupError('Another maintenance operation owns this installation; the migration barrier was not opened');
    const gate: Gate = { id: randomUUID(), kind: 'migration', phase: 'draining', expiresAt: null, archiveId: null, frozenPosition: null };
    durableJson(join(this.dir, 'maintenance.json'), gate, true);
    return gate;
  }
  /** The barrier drained: paused, with its frozen point. */
  freezeMigration(id: string, frozenPosition: string, frozenSnapshot: string | null = null): Gate {
    const gate = this.require(id);
    if (gate.kind !== 'migration') throw new BackupError('Not a migration barrier');
    const next: Gate = { ...gate, phase: 'paused', frozenPosition, frozenSnapshot };
    durableJson(join(this.dir, 'maintenance.json'), next);
    return next;
  }
  /** Ends the barrier (the migration did not switch): the installation serves again. */
  releaseMigration(id: string): void {
    if (this.require(id).kind !== 'migration') throw new BackupError('Only the migration barrier can be released this way');
    unlinkSync(join(this.dir, 'maintenance.json'));
  }
  /**
   * The installation moved (go-step7 decision 15): the barrier becomes the
   * permanent migrated-out gate. Nothing in this release removes it.
   */
  markMigratedOut(id: string): Gate {
    const gate = this.require(id);
    if (gate.kind !== 'migration' || gate.phase !== 'paused') throw new BackupError('The migration barrier must be drained (paused) before the installation is marked migrated out');
    const next: Gate = { ...gate, kind: 'migrated-out', phase: 'paused' };
    durableJson(join(this.dir, 'maintenance.json'), next);
    return next;
  }
  completeRestore(id: string): void {
    if (this.require(id).kind !== 'restore') throw new BackupError('Not a restore gate');
    unlinkSync(join(this.dir, 'maintenance.json'));
    const fd = openSync(this.dir, 'r'); try { fsyncSync(fd); } finally { closeSync(fd); }
  }
}
/** Offline entry before starting services on a fresh host; an existing gate is never overwritten. */
export function prepareRestore(dir: string, archiveId: string): Gate {
  mkdirSync(dir, { recursive: true, mode: 0o755 });
  const proof = join(dir, "restore-verified.json");
  if (existsSync(proof)) unlinkSync(proof);
  const existing = readGate(dir);
  if (existing) {
    if (existing.kind !== 'restore' || existing.archiveId !== archiveId) throw new BackupError('Another maintenance operation owns this installation');
    // A retry must stop the Application Plane again, including after reconciliation failed.
    const gate = { ...existing, phase: 'paused' as const };
    durableJson(join(dir, 'maintenance.json'), gate);
    return gate;
  }
  const gate: Gate = { id: randomUUID(), kind: 'restore', phase: 'paused', expiresAt: null, archiveId };
  durableJson(join(dir, 'maintenance.json'), gate, true);
  return gate;
}
