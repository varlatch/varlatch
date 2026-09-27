// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { Maintenance, prepareRestore } from '@varlatch/backup';
import { archiveMetadata } from '../src/backup/control.js';
import { generateKey } from '../src/crypto/aead.js';
import { ensureInstallation } from '../src/domain/bootstrap.js';
import { issueCredential } from '../src/auth/credentials.js';
import { buildApp } from '../src/http/app.js';
import { migratedTestDb } from './helpers/pglite.js';
import type { AppCtx } from '../src/domain/ctx.js';
let ctx: AppCtx, close: () => Promise<void>, dir: string;
beforeEach(async () => {
  const db = await migratedTestDb();
  dir = mkdtempSync(join(tmpdir(), 'varlatch-maintenance-'));
  ctx = { db, rootKek: generateKey(), maintenance: new Maintenance(dir) }; close = db.close;
  await ensureInstallation(ctx);
});
afterEach(async () => { await close(); rmSync(dir, { recursive: true, force: true }); });
it('rejects ordinary reads, writes, and auth before any audit write during capture', async () => {
  const app = buildApp(ctx); const gate = ctx.maintenance!.beginCapture(10_000);
  const before = await ctx.db.query('SELECT count(*) FROM audit_events');
  for (const [method, path] of [['GET','/v1/organizations'], ['POST','/v1/organizations'], ['POST','/auth/sign-in/passkey'], ['GET','/readyz']]) {
    expect((await app.request(path!, { method })).status).toBe(503);
  }
  expect((await app.request('/healthz')).status).toBe(200);
  expect((await app.request('/.well-known/jwks.json')).status).toBe(200);
  expect(await ctx.db.query('SELECT count(*) FROM audit_events')).toEqual(before);
  ctx.maintenance!.phase(gate.id, 'paused');
  expect((await app.request('/.well-known/jwks.json')).status).toBe(503);
  ctx.maintenance!.finishCapture(gate.id);
  expect((await app.request('/readyz')).status).toBe(200);
});
it('boots into durable restore isolation even with no installation tables', async () => {
  prepareRestore(dir, randomUUID());
  await ctx.db.query('DROP TABLE installation');
  const restarted = buildApp({ ...ctx, maintenance: new Maintenance(dir) });
  expect((await restarted.request('/readyz')).status).toBe(503);
  expect((await restarted.request('/v1/meta')).status).toBe(503);
  expect((await restarted.request('/.well-known/jwks.json')).status).toBe(503);
});
it('rejects incomplete root/org rotations and mixed root wrapping versions', async () => {
  expect((await archiveMetadata(ctx)).requiredKeyVersions).toEqual([1]);
  await ctx.db.query("UPDATE installation SET key_rotation_state = 'verifying'");
  await expect(archiveMetadata(ctx)).rejects.toThrow('rotation');
  await ctx.db.query("UPDATE installation SET key_rotation_state = 'idle'");
  await ctx.db.query("INSERT INTO organizations(id, slug, name, wrapped_org_kek, root_kek_version) VALUES ('org_test','test','Test','{}',2)");
  await expect(archiveMetadata(ctx)).rejects.toThrow('unverified');
});
it('requires Installation Admin authority for backup visibility', async () => {
  await ctx.db.query("INSERT INTO identities(id, kind, name, installation_admin) VALUES ('id_admin','human','Admin',true), ('id_member','human','Member',false)");
  const admin = await issueCredential(ctx.db, { identityId: 'id_admin', kind: 'cli' });
  const member = await issueCredential(ctx.db, { identityId: 'id_member', kind: 'cli' });
  const app = buildApp(ctx);
  expect((await app.request('/v1/installation/backups')).status).toBe(401);
  expect((await app.request('/v1/installation/backups', { headers: { Authorization: `Bearer ${member.token}` } })).status).toBe(403);
  const result = await app.request('/v1/installation/backups', { headers: { Authorization: `Bearer ${admin.token}` } });
  expect(result.status).toBe(200); expect(await result.json()).toMatchObject({ archives: [] });
});
