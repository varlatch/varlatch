// SPDX-License-Identifier: Apache-2.0
import { afterEach, expect, it } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { Maintenance, prepareRestore, backupStatus, saveStatus } from '../src/index.js';
const dirs: string[] = [];
function directory() { const dir = mkdtempSync(join(tmpdir(), 'gate-test-')); dirs.push(dir); return dir; }
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
it('blocks new work while accounting for in-flight work and expires a capture without accepting stale completion', () => {
  let now = 100; const m = new Maintenance(directory(), () => now);
  const leave = m.enter()!;
  const gate = m.beginCapture(1000);
  expect(m.enter()).toBeNull(); expect(m.busy).toBe(1);
  expect(() => m.beginCapture(1000)).toThrow();
  leave(); leave(); expect(m.busy).toBe(0);
  now += 1001;
  expect(m.gate).toBeNull(); expect(m.enter()).not.toBeNull();
  expect(() => m.finishCapture(gate.id)).toThrow('ownership lost');
  const newer = m.beginCapture(1000);
  expect(() => m.finishCapture(gate.id)).toThrow();
  expect(m.gate?.id).toBe(newer.id);
});
it('keeps restore isolated across restart and time, blocks capture release, and only retries the same archive', () => {
  const dir = directory(), archiveId = randomUUID();
  const gate = prepareRestore(dir, archiveId);
  const restarted = new Maintenance(dir, () => Number.MAX_SAFE_INTEGER);
  expect(restarted.enter()).toBeNull();
  expect(() => restarted.finishCapture(gate.id)).toThrow();
  expect(() => prepareRestore(dir, randomUUID())).toThrow();
  expect(prepareRestore(dir, archiveId).id).toBe(gate.id);
  restarted.completeRestore(gate.id);
  expect(restarted.enter()).not.toBeNull();
});
it('fails closed on corrupt durable state', () => {
  const dir = directory(); writeFileSync(join(dir, 'maintenance.json'), '{');
  expect(() => new Maintenance(dir).enter()).toThrow('isolation');
});
it('never attributes an older verification to the latest archive, or calls an upload remote verification', () => {
  const dir = directory(); const now = Date.now();
  const base = { installationId: 'inst_test', release: '0.7.0', requiredKeyVersions: [1] };
  saveStatus(dir, { ...base, archiveId: randomUUID(), createdAt: new Date(now - 1000).toISOString(), verification: { integrity: true, compatibility: true, keyMatch: true, targetRelease: '0.7.0', checkedAt: new Date(now).toISOString() } });
  const newest = randomUUID();
  saveStatus(dir, { ...base, archiveId: newest, createdAt: new Date(now).toISOString(), delivery: { destination: 'offsite', uploadedAt: new Date(now).toISOString() } });
  expect(backupStatus(dir, now).warnings).toEqual(expect.arrayContaining([expect.stringContaining(`Newest archive ${newest} has not passed`), expect.stringContaining('No remote copy has passed retrieval')]));
  expect(backupStatus(dir, now).archives[0]?.verification).toBeUndefined();
});
it('asks for remote verification only when the latest remote check failed or is overdue', () => {
  const dir = directory(); const now = Date.now(); const day = 24 * 3600_000;
  const base = { installationId: 'inst_test', release: '0.8.0', requiredKeyVersions: [1] };
  const check = (at: number, keyMatch = true) => ({ integrity: true, compatibility: true, keyMatch, targetRelease: '0.8.0', checkedAt: new Date(at).toISOString() });
  const nightly = (at: number, remoteVerification?: ReturnType<typeof check>) => {
    const archiveId = randomUUID();
    saveStatus(dir, { ...base, archiveId, createdAt: new Date(at).toISOString(), verification: check(at), delivery: { destination: 'offsite', uploadedAt: new Date(at).toISOString(), ...(remoteVerification ? { remoteVerification } : {}) } });
    return archiveId;
  };
  const remoteWarnings = () => backupStatus(dir, now).warnings.filter(w => w.includes('etrieval'));
  const older = nightly(now - 10 * day, check(now - 10 * day));
  nightly(now - day); nightly(now);
  // Newer unverified-remote archives do not re-raise a warning within 30 days.
  expect(backupStatus(dir, now).warnings).toEqual([]);
  expect(backupStatus(dir, now + 21 * day).warnings).toContain('No remote copy has passed retrieval and verification within the last 30 days');
  saveStatus(dir, { ...base, archiveId: older, createdAt: new Date(now - 10 * day).toISOString(), delivery: { destination: 'offsite', uploadedAt: new Date(now - 10 * day).toISOString(), remoteVerification: check(now, false) } });
  expect(remoteWarnings()).toEqual([`Remote copy of ${older} failed retrieval and verification`]);
});
