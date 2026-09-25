// SPDX-License-Identifier: Apache-2.0
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, unlinkSync, linkSync, openSync, fsyncSync, closeSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { BackupError } from './archive.js';

export interface Gate {
  id: string; kind: 'capture' | 'restore'; phase: 'draining' | 'paused' | 'reconciling';
  expiresAt: number | null; archiveId: string | null;
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
    if (!value.id || !['capture', 'restore'].includes(value.kind) || !['draining', 'paused', 'reconciling'].includes(value.phase) ||
        (value.kind === 'capture' && (!Number.isFinite(value.expiresAt) || (value.expiresAt as number) <= 0))) throw new Error();
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
  constructor(readonly dir: string, private readonly now: () => number = Date.now) { mkdirSync(dir, { recursive: true, mode: 0o755 }); }
  get gate(): Gate | null { return activeGate(this.dir, this.now()); }
  get busy(): number { return this.active; }
  /** Synchronous admission ensures no task slips between gate inspection and accounting. */
  enter(): (() => void) | null {
    if (this.gate) return null;
    this.active++;
    let done = false;
    return () => { if (!done) { done = true; this.active--; } };
  }
  beginCapture(ttlMs: number): Gate {
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1000 || ttlMs > 24 * 60 * 60 * 1000) throw new BackupError('Capture deadline must be between 1 second and 24 hours');
    this.cleanExpired();
    const gate: Gate = { id: randomUUID(), kind: 'capture', phase: 'draining', expiresAt: this.now() + ttlMs, archiveId: null };
    durableJson(join(this.dir, 'maintenance.json'), gate, true);
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
