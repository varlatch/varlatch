// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as backup from '../src/backup.js';
import { captureLegacyBackup } from '../src/legacyBackup.js';

describe('legacy capture preflight', () => {
  const dirs: string[] = [];
  afterEach(() => { vi.restoreAllMocks(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
  function inputs(version = '0.7.0') {
    const dir = mkdtempSync(join(tmpdir(), 'legacy-preflight-')); dirs.push(dir);
    const release = join(dir, 'release.json');
    writeFileSync(release, JSON.stringify({ version, apiMajor: 1, supportedPostgresMajor: 17 }));
    writeFileSync(join(dir, 'bek'), 'a'.repeat(64));
    writeFileSync(join(dir, 'kek'), 'b'.repeat(64));
    return { dir, release, args: ['--bek-file', join(dir, 'bek'), '--kek-file', join(dir, 'kek')] };
  }
  it('refuses unknown releases before executing any Docker command', async () => {
    const { dir, release, args } = inputs('0.6.0');
    const docker = vi.spyOn(backup, 'compose');
    await expect(captureLegacyBackup(args, dir, release)).rejects.toThrow(/published v0.7.0/);
    expect(docker).not.toHaveBeenCalled();
  });
  it('refuses newer schemas before stopping writers', async () => {
    const { dir, release, args } = inputs();
    const docker = vi.spyOn(backup, 'compose')
      .mockResolvedValueOnce(JSON.stringify({ services: { 'convex-backend': {} } }))
      .mockResolvedValueOnce('0.7.0').mockResolvedValueOnce('18');
    await expect(captureLegacyBackup(args, dir, release)).rejects.toThrow(/exactly migration 16/);
    expect(docker.mock.calls.some(([, command]) => command[0] === 'stop')).toBe(false);
  });
  it('refuses storage it cannot capture before stopping writers', async () => {
    const { dir, release, args } = inputs();
    const docker = vi.spyOn(backup, 'compose').mockResolvedValueOnce(JSON.stringify({ services: {
      'convex-backend': { environment: { STORAGE_DIR: '/external' } },
    } }));
    await expect(captureLegacyBackup(args, dir, release)).rejects.toThrow(/canonical Convex local storage/);
    expect(docker).toHaveBeenCalledOnce();
  });
});
