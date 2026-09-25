// SPDX-License-Identifier: Apache-2.0
import { createCipheriv, createDecipheriv, createHash, randomBytes, scryptSync } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { open, stat, mkdtemp, rm, link, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { canonicalJson } from '@varlatch/contract';
import { compatible, formatComponents, manifestSchema, type ArchiveFormat, type Manifest, type Release } from './manifest.js';

const MAGIC = Buffer.from('VLTBAK01');
const HEADER_BYTES = 36; // magic + scrypt salt + GCM nonce; authenticated as AAD
const MAX_BYTES = 60 * 1024 ** 3; // below the per-message AES-GCM limit
export class BackupError extends Error { override name = 'BackupError'; }
export type Bek = { kind: 'key'; material: Buffer } | { kind: 'passphrase'; material: Buffer };
function derive(bek: Bek, salt: Buffer): Buffer {
  if (bek.kind === 'key' && bek.material.length !== 32) throw new BackupError('BEK key file must contain a 32-byte key');
  if (bek.kind === 'passphrase' && bek.material.length < 12) throw new BackupError('BEK passphrase must have at least 12 bytes');
  return scryptSync(bek.material, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
}
export function distinctKeys(bek: Bek, keys: Iterable<Buffer>): void {
  for (const key of keys) if (bek.material.equals(key) || bek.material.toString().trim() === key.toString('hex') || bek.material.toString().trim() === key.toString('base64')) {
    throw new BackupError('The Backup Encryption Key must be independent of the Root KEK');
  }
}
export function parseKey(raw: string): Buffer {
  const value = raw.trim();
  if (!/^(?:[a-fA-F0-9]{64}|[A-Za-z0-9+/]{43}=)$/.test(value)) throw new BackupError('Key file must contain a 32-byte hex or base64 key');
  return Buffer.from(value, /^[a-fA-F0-9]{64}$/.test(value) ? 'hex' : 'base64');
}
export async function checksum(path: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest('hex');
}
export async function describeComponents(dir: string, format: ArchiveFormat): Promise<Manifest['components']> {
  return Promise.all(formatComponents[format].map(async name => ({ name, bytes: (await stat(join(dir, name))).size, sha256: await checksum(join(dir, name)) })));
}
/** Fixed component allowlist: arbitrary files, configuration and keys cannot enter an archive. */
export async function sealArchive(dir: string, manifest: Manifest, bek: Bek, output: string): Promise<void> {
  manifestSchema.parse(manifest);
  const json = Buffer.from(JSON.stringify(manifest));
  if (json.length > 1024 * 1024 || manifest.components.reduce((n, c) => n + c.bytes, json.length + 4) > MAX_BYTES) throw new BackupError('Archive exceeds the v1 60 GiB size limit');
  const length = Buffer.alloc(4); length.writeUInt32BE(json.length);
  const header = Buffer.concat([MAGIC, randomBytes(16), randomBytes(12)]);
  const key = derive(bek, header.subarray(8, 24));
  const cipher = createCipheriv('aes-256-gcm', key, header.subarray(24)); key.fill(0);
  cipher.setAAD(header);
  async function* plaintext() {
    yield length; yield json;
    for (const c of manifest.components) yield* createReadStream(join(dir, c.name));
  }
  const partial = `${output}.${randomBytes(8).toString('hex')}.partial`;
  try {
    const fd = await open(partial, 'wx', 0o600); await fd.write(header); await fd.close();
    await pipeline(Readable.from(plaintext()), cipher, createWriteStream(partial, { flags: 'a' }));
    const file = await open(partial, 'a');
    try { await file.write(cipher.getAuthTag()); await file.sync(); } finally { await file.close(); }
    await link(partial, output); // never overwrite an existing archive
  } finally { await rm(partial, { force: true }); }
}
export interface Verification { integrity: boolean; compatibility: boolean; keyMatch: boolean; targetRelease: string; checkedAt: string; }
export function checkKeys(manifest: Manifest, candidates: Map<number, Buffer>): boolean {
  return manifest.canaries.every(c => {
    const key = candidates.get(c.version); if (!key) return false;
    try {
      const e = c.envelope;
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(e.nonce, 'base64'));
      decipher.setAAD(Buffer.from(canonicalJson({ purpose: 'kek-canary', installationId: manifest.installationId })));
      decipher.setAuthTag(Buffer.from(e.authTag, 'base64'));
      const plaintext = Buffer.concat([decipher.update(Buffer.from(e.ciphertext, 'base64')), decipher.final()]);
      const ok = plaintext.length === 32; plaintext.fill(0); return ok;
    } catch { return false; }
  });
}
/** Authenticate the entire encrypted stream before interpreting any manifest or component. */
export async function openArchive<T>(path: string, bek: Bek, use: (manifest: Manifest, dir: string) => Promise<T>, scratch = tmpdir()): Promise<T> {
  const dir = await mkdtemp(join(scratch, 'varlatch-backup-'));
  try {
    const size = (await stat(path)).size;
    if (size < HEADER_BYTES + 20 || size > MAX_BYTES + HEADER_BYTES + 16) throw new BackupError('Invalid archive size');
    const file = await open(path, 'r');
    const header = Buffer.alloc(HEADER_BYTES), tag = Buffer.alloc(16);
    try { await file.read(header, 0, HEADER_BYTES, 0); await file.read(tag, 0, 16, size - 16); } finally { await file.close(); }
    if (!header.subarray(0, 8).equals(MAGIC)) throw new BackupError('Unsupported archive format');
    const key = derive(bek, header.subarray(8, 24));
    const decipher = createDecipheriv('aes-256-gcm', key, header.subarray(24)); key.fill(0);
    decipher.setAAD(header); decipher.setAuthTag(tag);
    const plain = join(dir, 'authenticated.pack');
    try {
      await pipeline(createReadStream(path, { start: HEADER_BYTES, end: size - 17 }), decipher, createWriteStream(plain, { flags: 'wx', mode: 0o600 }));
    } catch { throw new BackupError('Archive integrity check failed (wrong BEK, corruption, or truncation)'); }
    const pack = await open(plain, 'r');
    let manifest: Manifest, offset: number;
    try {
      const length = Buffer.alloc(4); await pack.read(length, 0, 4, 0);
      const n = length.readUInt32BE();
      if (n < 2 || n > 1024 * 1024) throw new BackupError('Invalid manifest size');
      const json = Buffer.alloc(n); if ((await pack.read(json, 0, n, 4)).bytesRead !== n) throw new BackupError('Truncated manifest');
      try { manifest = manifestSchema.parse(JSON.parse(json.toString())); } catch { throw new BackupError('Invalid archive manifest'); }
      offset = 4 + n;
    } finally { await pack.close(); }
    const plainSize = (await stat(plain)).size;
    if (manifest.components.reduce((sum, c) => sum + c.bytes, offset) !== plainSize) throw new BackupError('Component sizes do not match archive');
    for (const c of manifest.components) {
      const output = join(dir, c.name);
      if (c.bytes === 0) { const f = await open(output, 'wx', 0o600); await f.close(); }
      else await pipeline(createReadStream(plain, { start: offset, end: offset + c.bytes - 1 }), createWriteStream(output, { flags: 'wx', mode: 0o600 }));
      if (await checksum(output) !== c.sha256) throw new BackupError('Component checksum mismatch');
      offset += c.bytes;
    }
    await unlink(plain);
    return await use(manifest, dir);
  } finally { await rm(dir, { recursive: true, force: true }); }
}
export function verifyManifest(manifest: Manifest, target: Release, bek: Bek, candidates: Map<number, Buffer>): Verification {
  distinctKeys(bek, candidates.values());
  return { integrity: true, compatibility: compatible(manifest.release, target), keyMatch: checkKeys(manifest, candidates), targetRelease: target.version, checkedAt: new Date().toISOString() };
}
