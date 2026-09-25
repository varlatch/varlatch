// SPDX-License-Identifier: AGPL-3.0-or-later
import { EMBEDDED_RELEASE } from '@varlatch/backup';
import type { AppCtx } from '../domain/ctx.js';
import { verifyLoadedKek } from '../domain/bootstrap.js';
import { schemaIsCurrent } from '../db/migrate.js';

/**
 * Archive manifest metadata, refusing incomplete key rotations (ADR-0033
 * D3). Online capture calls it inside the snapshot transaction, so the
 * required key versions and canary describe exactly the dumped state.
 */
export async function archiveMetadata(ctx: AppCtx) {
  if (!(await schemaIsCurrent(ctx.db)) || !(await verifyLoadedKek(ctx))) throw new Error('Schema or loaded KEK check failed');
  const result = await ctx.db.query('SELECT id, kek_canary, root_kek_version, key_rotation_state FROM installation');
  const inst = result.rows[0] as { id: string; kek_canary: unknown; root_kek_version: number; key_rotation_state: string } | undefined;
  if (!inst || inst.key_rotation_state !== 'idle') throw new Error('Root KEK rotation is incomplete');
  const orgs = await ctx.db.query("SELECT DISTINCT root_kek_version, key_rotation_state FROM organizations");
  if ((orgs.rows as { root_kek_version: number; key_rotation_state: string }[]).some(o => o.root_kek_version !== inst.root_kek_version || o.key_rotation_state !== 'idle')) throw new Error('Key rotation has unverified rewraps outstanding');
  return { installationId: inst.id, release: EMBEDDED_RELEASE, requiredKeyVersions: [inst.root_kek_version], canaries: [{ version: inst.root_kek_version, envelope: typeof inst.kek_canary === 'string' ? JSON.parse(inst.kek_canary) : inst.kek_canary }] };
}
