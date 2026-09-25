// SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, writeFile, readFile, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createCipheriv, randomBytes, randomUUID } from 'node:crypto';
import { canonicalJson } from '@varlatch/contract';
import { EMBEDDED_RELEASE, describeComponents, sealArchive, openArchive, verifyManifest, manifestSchema, distinctKeys, compatible } from '../src/index.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), 'backup-test-')); dirs.push(dir);
  const key = randomBytes(32), bek = { kind: 'key' as const, material: randomBytes(32) };
  const nonce = randomBytes(12), installationId = 'inst_test';
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(canonicalJson({ purpose: 'kek-canary', installationId })));
  const ciphertext = Buffer.concat([cipher.update(randomBytes(32)), cipher.final()]);
  for (const name of ['secret-plane.dump', 'application-plane.dump', 'convex-storage.tar']) await writeFile(join(dir, name), randomBytes(100));
  // Deliberately present: the allowlist must never archive this file.
  await writeFile(join(dir, 'root-kek'), key);
  const manifest = manifestSchema.parse({ formatVersion: 1, archiveId: randomUUID(), installationId, createdAt: new Date().toISOString(), release: EMBEDDED_RELEASE, requiredKeyVersions: [1], canaries: [{ version: 1, envelope: { formatVersion: 1, algorithm: 'aes-256-gcm', nonce: nonce.toString('base64'), ciphertext: ciphertext.toString('base64'), authTag: cipher.getAuthTag().toString('base64') } }], components: await describeComponents(dir, 1) });
  const output = join(dir, 'archive.vltbak');
  return { dir, key, bek, manifest, output };
}
describe('archive formats (ADR-0036)', () => {
  it('format 2 carries the Secret Plane only; format 1 still requires all three components', async () => {
    const f = await fixture();
    const v2 = manifestSchema.parse({ ...f.manifest, formatVersion: 2, components: await describeComponents(f.dir, 2) });
    expect(v2.components.map(c => c.name)).toEqual(['secret-plane.dump']);
    await sealArchive(f.dir, v2, f.bek, f.output);
    await openArchive(f.output, f.bek, async (manifest, dir) => {
      expect(manifest.formatVersion).toBe(2);
      expect(await readdir(dir)).toEqual(['secret-plane.dump']);
    });
    // A format-2 manifest listing Application Plane components, or a
    // format-1 manifest missing them, is not a valid archive.
    expect(() => manifestSchema.parse({ ...f.manifest, formatVersion: 2 })).toThrow();
    expect(() => manifestSchema.parse({ ...f.manifest, formatVersion: 1, components: v2.components })).toThrow();
  });
});
describe('authenticated installation archives', () => {
  it('round-trips all components, excludes unrelated key files, and verifies independently', async () => {
    const f = await fixture(); await sealArchive(f.dir, f.manifest, f.bek, f.output);
    let extracted = '';
    await openArchive(f.output, f.bek, async (manifest, dir) => {
      extracted = dir;
      expect(await readdir(dir)).toEqual(['application-plane.dump', 'convex-storage.tar', 'secret-plane.dump']);
      expect(await readFile(join(dir, 'secret-plane.dump'))).toEqual(await readFile(join(f.dir, 'secret-plane.dump')));
      expect(verifyManifest(manifest, EMBEDDED_RELEASE, f.bek, new Map([[1, f.key]]))).toMatchObject({ integrity: true, compatibility: true, keyMatch: true });
      expect(verifyManifest(manifest, EMBEDDED_RELEASE, f.bek, new Map([[1, randomBytes(32)]]))).toMatchObject({ integrity: true, compatibility: true, keyMatch: false });
    });
    await expect(readdir(extracted)).rejects.toThrow();
    expect((await readFile(f.output)).includes(f.key)).toBe(false);
  });
  it('rejects wrong BEK, header/ciphertext/tag corruption and truncation before invoking the consumer', async () => {
    const f = await fixture(); await sealArchive(f.dir, f.manifest, f.bek, f.output);
    const original = await readFile(f.output);
    await expect(openArchive(f.output, { kind: 'key', material: randomBytes(32) }, async () => { throw Error('consumer invoked'); })).rejects.toThrow('integrity');
    for (const index of [10, 45, original.length - 1]) {
      const changed = Buffer.from(original); changed[index] = changed[index]! ^ 1; await writeFile(f.output, changed);
      await expect(openArchive(f.output, f.bek, async () => { throw Error('consumer invoked'); })).rejects.toThrow('integrity');
    }
    await writeFile(f.output, original.subarray(0, -1));
    await expect(openArchive(f.output, f.bek, async () => {})).rejects.toThrow('integrity');
  });
  it('detects component checksum mismatch and refuses overwrite', async () => {
    const f = await fixture(); f.manifest.components[0]!.sha256 = '0'.repeat(64);
    await sealArchive(f.dir, f.manifest, f.bek, f.output);
    await expect(openArchive(f.output, f.bek, async () => {})).rejects.toThrow('checksum');
    await expect(sealArchive(f.dir, f.manifest, f.bek, f.output)).rejects.toThrow();
  });
  it('supports passphrases and rejects KEK reuse and missing key versions', async () => {
    const f = await fixture();
    expect(() => distinctKeys({ kind: 'key', material: f.key }, [f.key])).toThrow('independent');
    expect(() => distinctKeys({ kind: 'passphrase', material: Buffer.from(f.key.toString('hex')) }, [f.key])).toThrow('independent');
    const bek = { kind: 'passphrase' as const, material: Buffer.from('a separately held backup passphrase') };
    await sealArchive(f.dir, f.manifest, bek, f.output);
    await openArchive(f.output, bek, async manifest => { expect(verifyManifest(manifest, EMBEDDED_RELEASE, bek, new Map()).keyMatch).toBe(false); });
    expect(manifestSchema.safeParse({ ...f.manifest, requiredKeyVersions: [1, 2] }).success).toBe(false);
  });
  it('requires an explicit compatible source, rejects downgrade and PostgreSQL skew', () => {
    const source = EMBEDDED_RELEASE;
    // A hypothetical future release that does not list the current one.
    const target = { ...source, version: 'future', migrationVersion: source.migrationVersion + 1, supportedRestoreSources: [] };
    expect(compatible(source, target)).toBe(false);
    expect(compatible(source, { ...target, supportedRestoreSources: [{ version: source.version, migrationVersion: source.migrationVersion }] })).toBe(true);
    expect(compatible(source, { ...source, supportedPostgresMajor: 18 })).toBe(false);
    expect(compatible(source, { ...target, migrationVersion: source.migrationVersion - 1, supportedRestoreSources: [{ version: source.version, migrationVersion: source.migrationVersion }] })).toBe(false);
  });
});
