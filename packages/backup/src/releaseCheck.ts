// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import { durableJson } from './maintenance.js';

/**
 * The host's last look for a newer release (ADR-0049). `varlatch upgrade
 * --check` records it through the backup control; varlatchd only reads it,
 * for Installation Admins and the doctor. Display state, not authority: it
 * starts nothing, and nothing in it is a URL.
 */
export const RELEASE_CHECK_FILE = 'release-check.json';

/** A release version as tags name it, without the `v`. */
export const RELEASE_VERSION = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;
/** A GitHub repository, `owner/name`. */
export const RELEASE_REPO = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/(?!\.\.?$)[A-Za-z0-9._-]{1,100}$/;
export const DEFAULT_RELEASE_REPO = 'varlatch/varlatch';
/** How long a check that found no newer release is taken as current. */
export const RELEASE_CHECK_MAX_AGE_MS = 14 * 24 * 3600_000;

export const RELEASE_CHECK_FAILURES = ['unreachable', 'rate-limited', 'not-found', 'invalid-answer'] as const;
export type ReleaseCheckFailure = (typeof RELEASE_CHECK_FAILURES)[number];

const version = z.string().max(100).regex(RELEASE_VERSION);
const repo = z.string().max(140).regex(RELEASE_REPO);
const latest = z.object({ version, publishedAt: z.iso.datetime().nullable() }).strict();

/** What the CLI sends: one attempt's outcome. The control stamps the time. */
export const releaseCheckInputSchema = z.discriminatedUnion('outcome', [
  z.object({ outcome: z.literal('found'), repo, latest, releaseSet: z.boolean() }).strict(),
  z.object({ outcome: z.literal('failed'), repo, failed: z.enum(RELEASE_CHECK_FAILURES) }).strict(),
]);
export type ReleaseCheckInput = z.infer<typeof releaseCheckInputSchema>;

export const releaseCheckSchema = z.object({
  lastAttempt: z.object({ checkedAt: z.iso.datetime(), repo, failed: z.enum(RELEASE_CHECK_FAILURES).nullable() }).strict(),
  lastSuccess: z.object({ checkedAt: z.iso.datetime(), repo, latest, releaseSet: z.boolean() }).strict().nullable(),
}).strict();
export type ReleaseCheck = z.infer<typeof releaseCheckSchema>;

/** Null when no check was ever recorded; throws when the record is unreadable. */
export function readReleaseCheck(dir: string): ReleaseCheck | null {
  let text: string;
  try { text = readFileSync(join(dir, RELEASE_CHECK_FILE), 'utf8'); }
  catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null; throw e; }
  return releaseCheckSchema.parse(JSON.parse(text));
}

/**
 * Records one attempt. A failure keeps the last success: an unreachable
 * GitHub says nothing about which release is the latest.
 */
export function recordReleaseCheck(dir: string, input: unknown, now = Date.now()): ReleaseCheck {
  const attempt = releaseCheckInputSchema.parse(input);
  let previous: ReleaseCheck | null = null;
  try { previous = readReleaseCheck(dir); } catch { /* an unreadable record is replaced */ }
  const checkedAt = new Date(now).toISOString();
  const record: ReleaseCheck = attempt.outcome === 'found'
    ? { lastAttempt: { checkedAt, repo: attempt.repo, failed: null }, lastSuccess: { checkedAt, repo: attempt.repo, latest: attempt.latest, releaseSet: attempt.releaseSet } }
    : { lastAttempt: { checkedAt, repo: attempt.repo, failed: attempt.failed }, lastSuccess: previous?.lastSuccess ?? null };
  durableJson(join(dir, RELEASE_CHECK_FILE), releaseCheckSchema.parse(record));
  return record;
}

/** Semver-ish compare: negative when a < b. Prereleases sort before their
    release (0.7.0-rc1 < 0.7.0); prerelease-vs-prerelease compares lexically. */
export function compareVersions(a: string, b: string): number {
  const parse = (v: string): { nums: number[]; pre: string } => {
    const [core = '', ...pre] = v.replace(/^v/, '').split('-');
    return { nums: core.split('.').map((n) => Number(n) || 0), pre: pre.join('-') };
  };
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < Math.max(pa.nums.length, pb.nums.length); i++) {
    const d = (pa.nums[i] ?? 0) - (pb.nums[i] ?? 0);
    if (d !== 0) return d;
  }
  if (pa.pre === pb.pre) return 0;
  if (pa.pre === '') return 1;
  if (pb.pre === '') return -1;
  return pa.pre < pb.pre ? -1 : 1;
}

/** The release's page, built from validated fields only. */
export function releaseUrl(repoName: string, versionName: string): string {
  if (!RELEASE_REPO.test(repoName) || !RELEASE_VERSION.test(versionName)) throw new Error('Invalid release reference');
  return `https://github.com/${repoName}/releases/tag/v${versionName}`;
}
