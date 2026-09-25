// SPDX-License-Identifier: Apache-2.0
import { readFileSync, existsSync } from 'node:fs';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { join, resolve, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { BackupError, describeComponents, distinctKeys, manifestSchema, parseKey, sealArchive, verifyManifest, type Manifest } from '@varlatch/backup';
import { compose, dockerCommand, loadBek, targetRelease } from './backup.js';

const option = (args: string[], name: string) => { const i = args.indexOf(name); return i < 0 ? undefined : args[i + 1]; };
/** One-time bridge for the released pre-ADR-0033 binary. This is explicitly
 * offline, not an imitation of a lease the old daemon cannot enforce. */
export async function captureLegacyBackup(args: string[], dir: string, releasePath: string): Promise<string> {
  const source = JSON.parse(readFileSync(releasePath, 'utf8')) as { version?: string; apiMajor?: number; supportedPostgresMajor?: number };
  if (source.version !== '0.7.0' || source.apiMajor !== 1 || source.supportedPostgresMajor !== 17) throw new BackupError('Offline bridge supports the published v0.7.0 release only');
  if (option(args, '--destination')) throw new BackupError('For the one-time offline bridge, create and verify the local archive first; configure scheduled S3 delivery after upgrading');
  const keyFile = option(args, '--kek-file'); if (!keyFile) throw new BackupError('Supply --kek-file');
  const bek = loadBek(args), key = parseKey(readFileSync(keyFile, 'utf8'));
  distinctKeys(bek, [key]);
  const archiveId = randomUUID(), output = resolve(option(args, '--out') ?? join(dir, 'backups', `${archiveId}.vltbak`));
  if (existsSync(output)) throw new BackupError('Output already exists');
  const scratch = await mkdtemp(join(option(args, '--scratch-dir') ?? tmpdir(), 'varlatch-legacy-capture-'));
  let stopped = false;
  try {
    // Do not print the resolved Compose configuration: it contains credentials.
    const config = JSON.parse(await compose(dir, ['config', '--format', 'json'])) as { services: Record<string, { environment?: Record<string, string> }> };
    const env = config.services['convex-backend']?.environment ?? {};
    if ((env.DATA_DIR && env.DATA_DIR !== '/convex/data') || (env.STORAGE_DIR && env.STORAGE_DIR !== '/convex/data/storage') || Object.keys(env).some(n => n.startsWith('S3_STORAGE_') && env[n])) throw new BackupError('Offline bridge requires canonical Convex local storage');
    const version = await compose(dir, ['run', '--rm', '--no-deps', '-T', '--entrypoint', 'node', 'varlatchd', '-p', 'JSON.parse(require("node:fs").readFileSync("/app/package.json","utf8")).version']);
    if (version !== '0.7.0') throw new BackupError('Source binary does not match the v0.7.0 manifest');
    const sql = async (query: string) => compose(dir, ['exec', '-T', 'postgres', 'psql', '-U', 'postgres', '-d', 'varlatch', '-At', '-v', 'ON_ERROR_STOP=1', '-c', query]);
    if (await sql('SELECT max(id) FROM varlatch_migrations') !== '16') throw new BackupError('Offline bridge requires exactly migration 16; newer installations must use ordinary capture');
    if (await sql("SELECT current_setting('server_version_num')::int / 10000") !== '17') throw new BackupError('Offline bridge requires PostgreSQL 17');
    const services = Object.keys(config.services).filter(name => name !== 'postgres');
    console.log('One-time offline capture: stopping application services. They remain stopped until the upgrade succeeds or you explicitly start the old release.');
    stopped = true; // Even a failed stop may have stopped a subset of services.
    await compose(dir, ['stop', ...services]);
    const stillRunning = (await compose(dir, ['ps', '--status', 'running', '--services'])).split('\n').filter(Boolean);
    if (stillRunning.some(name => name !== 'postgres')) throw new BackupError('Application writers did not stop');
    // Capture metadata after the last writer stopped, not from a live preflight.
    const inst = JSON.parse(await sql("SELECT json_build_object('id',id,'canary',kek_canary) FROM installation")) as { id: string; canary: unknown };
    const createdAt = new Date().toISOString();
    const base = {
      formatVersion: 1 as const, archiveId, installationId: inst.id, createdAt,
      release: { schemaVersion: 1 as const, version: '0.7.0', apiMajor: 1, migrationVersion: 16, supportedPostgresMajor: 17, supportedRestoreSources: [] },
      requiredKeyVersions: [1], canaries: [{ version: 1, envelope: inst.canary }],
    };
    const check = verifyManifest({ ...base, components: [] } as Manifest, targetRelease(args), bek, new Map([[1,key]]));
    if (!check.keyMatch || !check.compatibility) throw new BackupError('Offline capture key or target compatibility check failed');
    for (const [db, component] of [['varlatch','secret-plane.dump'],['convex_self_hosted','application-plane.dump']] as const) {
      await compose(dir, ['exec', '-T', 'postgres', 'pg_dump', '-U', 'postgres', '-Fc', db], { outputFile: join(scratch, component) });
    }
    const convex = await compose(dir, ['ps', '--all', '-q', 'convex-backend']);
    if (!convex || convex.includes('\n')) throw new BackupError('Expected exactly one stopped Convex container');
    await dockerCommand(dir, ['cp', `${convex}:/convex/data/storage/.`, '-'], { outputFile: join(scratch, 'convex-storage.tar') });
    const manifest = manifestSchema.parse({ ...base, components: await describeComponents(scratch, 1) });
    await mkdir(dirname(output), { recursive: true, mode: 0o700 });
    await sealArchive(scratch, manifest, bek, output);
    console.log(`Offline archive created: ${output} (${archiveId}). Services remain stopped.`);
    return output;
  } catch (error) {
    if (stopped) console.error('Offline capture failed; application services remain stopped. Do not migrate. Fix the error and retry, or explicitly start the original release.');
    throw error;
  } finally {
    key.fill(0); bek.material.fill(0);
    await rm(scratch, { recursive: true, force: true });
  }
}
