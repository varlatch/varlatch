// SPDX-License-Identifier: Apache-2.0
import { readdirSync, readFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { durableJson } from './maintenance.js';

const verification = z.object({ integrity: z.boolean(), compatibility: z.boolean(), keyMatch: z.boolean(), targetRelease: z.string().max(100), checkedAt: z.iso.datetime() }).strict();
export const statusSchema = z.object({
  archiveId: z.uuid(), installationId: z.string().max(100), createdAt: z.iso.datetime(), release: z.string().max(100),
  requiredKeyVersions: z.array(z.number().int().positive()).max(100),
  verification: verification.optional(),
  delivery: z.object({ destination: z.string().max(100), uploadedAt: z.iso.datetime(), remoteVerification: verification.optional() }).strict().optional(),
  /**
   * How the capture ran (ADR-0036): recorded for online captures only — a
   * daemon old enough to need the frozen fallback would reject the field.
   */
  capture: z.object({
    mode: z.literal('online'),
    snapshotHeldMs: z.number().int().nonnegative(),
    dumpMs: z.number().int().nonnegative(),
    dumpBytes: z.number().int().nonnegative(),
  }).strict().optional(),
}).strict();
export type BackupStatus = z.infer<typeof statusSchema>;
export function saveStatus(dir: string, input: BackupStatus): void {
  const status = statusSchema.parse(input);
  mkdirSync(join(dir, 'backups'), { recursive: true, mode: 0o700 });
  const path = join(dir, 'backups', `${status.archiveId}.json`);
  let previous: BackupStatus | undefined;
  try { previous = statusSchema.parse(JSON.parse(readFileSync(path, 'utf8'))); }
  catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e; }
  if (previous && (previous.installationId !== status.installationId || previous.createdAt !== status.createdAt || previous.release !== status.release || JSON.stringify(previous.requiredKeyVersions) !== JSON.stringify(status.requiredKeyVersions))) throw new Error('Archive identity conflict');
  durableJson(path, { ...previous, ...status });
}
const REMOTE_VERIFICATION_MAX_AGE_MS = 30 * 24 * 3600_000;
export function backupStatus(dir: string, now = Date.now()): { archives: BackupStatus[]; warnings: string[] } {
  let names: string[];
  try { names = readdirSync(join(dir, 'backups')); } catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT') names = []; else throw e; }
  const archives = names.filter(n => /^[a-f0-9-]{36}\.json$/.test(n)).map(n => statusSchema.parse(JSON.parse(readFileSync(join(dir, 'backups', n), 'utf8')))).sort((a,b) => b.createdAt.localeCompare(a.createdAt));
  const newest = archives[0];
  const warnings: string[] = [];
  const passed = (v: z.infer<typeof verification> | undefined) => v?.integrity && v.compatibility && v.keyMatch;
  if (!newest || now - Date.parse(newest.createdAt) > 48 * 3600_000) warnings.push('No archive created within the last 48 hours');
  if (newest && !passed(newest.verification)) warnings.push(`Newest archive ${newest.archiveId} has not passed verification`);
  if (newest && !newest.delivery) warnings.push(`Newest archive ${newest.archiveId} has not been delivered to a destination`);
  // Remote verification needs read credentials the scheduled job never holds
  // (ADR-0033 Decision 8), so it is a periodic operator ritual: warn when the
  // latest remote check failed or is overdue, not about every new archive.
  const remote = archives.flatMap(a => a.delivery?.remoteVerification ? [{ archiveId: a.archiveId, check: a.delivery.remoteVerification }] : [])
    .sort((a, b) => b.check.checkedAt.localeCompare(a.check.checkedAt))[0];
  if (remote && !passed(remote.check)) warnings.push(`Remote copy of ${remote.archiveId} failed retrieval and verification`);
  else if (archives.some(a => a.delivery) && !(remote && now - Date.parse(remote.check.checkedAt) < REMOTE_VERIFICATION_MAX_AGE_MS)) warnings.push('No remote copy has passed retrieval and verification within the last 30 days');
  for (const version of new Set(archives.flatMap(a => a.requiredKeyVersions))) {
    if (!archives.some(a => a.requiredKeyVersions.includes(version) && a.verification?.keyMatch && now - Date.parse(a.verification.checkedAt) < 30 * 24 * 3600_000)) warnings.push(`Root KEK version ${version} required by recorded archives has no successful check within 30 days; retain it while those archives exist`);
  }
  return { archives, warnings };
}
