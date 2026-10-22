// SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RELEASE_CHECK_FILE, compareVersions, readReleaseCheck, recordReleaseCheck, releaseUrl } from '../src/index.js';

const dirs: string[] = [];
function directory() { const dir = mkdtempSync(join(tmpdir(), 'release-check-test-')); dirs.push(dir); return dir; }
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

const T1 = Date.parse('2026-10-22T03:40:00Z');
const T2 = Date.parse('2026-10-23T03:40:00Z');
const found = (version = '0.19.0') => ({ outcome: 'found', repo: 'varlatch/varlatch', latest: { version, publishedAt: '2026-10-21T12:00:00.000Z' }, releaseSet: true });

describe('release check record (ADR-0049)', () => {
  it('reads nothing before the first check', () => {
    expect(readReleaseCheck(directory())).toBeNull();
  });

  it('records a success as both the last attempt and the last success, stamped by the recorder', () => {
    const dir = directory();
    recordReleaseCheck(dir, found(), T1);
    expect(readReleaseCheck(dir)).toEqual({
      lastAttempt: { checkedAt: '2026-10-22T03:40:00.000Z', repo: 'varlatch/varlatch', failed: null },
      lastSuccess: { checkedAt: '2026-10-22T03:40:00.000Z', repo: 'varlatch/varlatch', latest: { version: '0.19.0', publishedAt: '2026-10-21T12:00:00.000Z' }, releaseSet: true },
    });
  });

  it('keeps the last success when a later attempt fails', () => {
    const dir = directory();
    recordReleaseCheck(dir, found(), T1);
    recordReleaseCheck(dir, { outcome: 'failed', repo: 'varlatch/varlatch', failed: 'unreachable' }, T2);
    const record = readReleaseCheck(dir)!;
    expect(record.lastAttempt).toEqual({ checkedAt: '2026-10-23T03:40:00.000Z', repo: 'varlatch/varlatch', failed: 'unreachable' });
    expect(record.lastSuccess?.checkedAt).toBe('2026-10-22T03:40:00.000Z');
    expect(record.lastSuccess?.latest.version).toBe('0.19.0');
  });

  it('records a failure with no earlier success', () => {
    const dir = directory();
    recordReleaseCheck(dir, { outcome: 'failed', repo: 'varlatch/varlatch', failed: 'rate-limited' }, T1);
    expect(readReleaseCheck(dir)).toEqual({ lastAttempt: { checkedAt: '2026-10-22T03:40:00.000Z', repo: 'varlatch/varlatch', failed: 'rate-limited' }, lastSuccess: null });
  });

  it('refuses anything but a release version, an owner/name repository, a known reason, and the known fields', () => {
    const dir = directory();
    const refused = [
      found('v0.19.0'),
      found('0.19'),
      found('0.19.0 <script>'),
      { ...found(), repo: 'https://evil.example/x' },
      { ...found(), repo: 'varlatch/..' },
      { ...found(), repo: 'varlatch' },
      { ...found(), url: 'https://evil.example' },
      { ...found(), latest: { version: '0.19.0', publishedAt: 'yesterday' } },
      { outcome: 'failed', repo: 'varlatch/varlatch', failed: 'GitHub said: 500 Internal Server Error' },
      { outcome: 'found', repo: 'varlatch/varlatch', latest: { version: '0.19.0', publishedAt: null } },
      {},
      null,
    ];
    for (const input of refused) expect(() => recordReleaseCheck(dir, input, T1), JSON.stringify(input)).toThrow();
    expect(readReleaseCheck(dir)).toBeNull();
  });

  it('replaces an unreadable record, and says it is unreadable until then', () => {
    const dir = directory();
    writeFileSync(join(dir, RELEASE_CHECK_FILE), '{"lastAttempt":');
    expect(() => readReleaseCheck(dir)).toThrow();
    recordReleaseCheck(dir, found(), T1);
    expect(JSON.parse(readFileSync(join(dir, RELEASE_CHECK_FILE), 'utf8')).lastSuccess.latest.version).toBe('0.19.0');
  });

  it('builds the release page only from a valid repository and version', () => {
    expect(releaseUrl('varlatch/varlatch', '0.19.0')).toBe('https://github.com/varlatch/varlatch/releases/tag/v0.19.0');
    expect(releaseUrl('acme-fork/varlatch.x', '1.0.0-rc.1')).toBe('https://github.com/acme-fork/varlatch.x/releases/tag/v1.0.0-rc.1');
    expect(() => releaseUrl('evil.example/x/y', '0.19.0')).toThrow();
    expect(() => releaseUrl('varlatch/varlatch', '0.19.0/../../x')).toThrow();
  });

  it('orders releases and prereleases as the upgrade does', () => {
    expect(compareVersions('0.19.0', '0.18.1')).toBeGreaterThan(0);
    expect(compareVersions('0.10.0', '0.9.0')).toBeGreaterThan(0);
    expect(compareVersions('0.19.0', '0.19.0')).toBe(0);
    expect(compareVersions('0.19.0-rc1', '0.19.0')).toBeLessThan(0);
  });
});
