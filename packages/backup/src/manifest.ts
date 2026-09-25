// SPDX-License-Identifier: Apache-2.0
import embeddedRelease from "./release.json" with { type: "json" };
import { z } from 'zod';

export const releaseSchema = z.object({
  schemaVersion: z.literal(1), version: z.string().min(1), apiMajor: z.number().int().positive(),
  migrationVersion: z.number().int().nonnegative(), supportedPostgresMajor: z.number().int().positive(),
  supportedRestoreSources: z.array(z.object({ version: z.string(), migrationVersion: z.number().int().nonnegative() })).default([]),
});
export type Release = z.infer<typeof releaseSchema>;
// Release tooling checks this against the daemon's version and migration list.
export const EMBEDDED_RELEASE: Release = releaseSchema.parse(embeddedRelease);

export const envelopeSchema = z.object({
  formatVersion: z.literal(1), algorithm: z.literal('aes-256-gcm'),
  nonce: z.string().max(32), ciphertext: z.string().max(256), authTag: z.string().max(32),
}).strict();
export const componentNames = ['secret-plane.dump', 'application-plane.dump', 'convex-storage.tar'] as const;
/**
 * The components each archive format carries, in order. Format 1 (ADR-0033)
 * archived both planes; format 2 (ADR-0036) archives the Secret Plane only —
 * the Application Plane is rebuilt on restore. `verify` still checks every
 * component a format-1 archive promises.
 */
export const formatComponents = {
  1: componentNames,
  2: ['secret-plane.dump'],
} as const satisfies Record<number, readonly (typeof componentNames)[number][]>;
export type ArchiveFormat = keyof typeof formatComponents;
export const CURRENT_FORMAT: ArchiveFormat = 2;
const componentSchema = z.object({ name: z.enum(componentNames), bytes: z.number().int().nonnegative(), sha256: z.string().regex(/^[a-f0-9]{64}$/) }).strict();
export const manifestSchema = z.object({
  formatVersion: z.union([z.literal(1), z.literal(2)]), archiveId: z.uuid(), installationId: z.string().regex(/^inst_[a-zA-Z0-9_-]+$/),
  createdAt: z.iso.datetime(), release: releaseSchema,
  requiredKeyVersions: z.array(z.number().int().positive()).min(1),
  canaries: z.array(z.object({ version: z.number().int().positive(), envelope: envelopeSchema }).strict()).min(1),
  components: z.array(componentSchema).min(1).max(componentNames.length),
}).strict().superRefine((m, ctx) => {
  const expected: readonly string[] = formatComponents[m.formatVersion];
  if (new Set(m.requiredKeyVersions).size !== m.requiredKeyVersions.length ||
      m.canaries.length !== m.requiredKeyVersions.length ||
      new Set(m.canaries.map(c => c.version)).size !== m.canaries.length ||
      m.requiredKeyVersions.some(v => !m.canaries.some(c => c.version === v)) ||
      m.components.length !== expected.length ||
      expected.some((name, i) => m.components[i]?.name !== name)) {
    ctx.addIssue({ code: 'custom', message: 'Incomplete or duplicate archive components/key versions' });
  }
});
export type Manifest = z.infer<typeof manifestSchema>;
export function compatible(source: Release, target: Release): boolean {
  return source.apiMajor === target.apiMajor && source.supportedPostgresMajor === target.supportedPostgresMajor &&
    ((source.version === target.version && source.migrationVersion === target.migrationVersion) ||
     (source.migrationVersion <= target.migrationVersion && target.supportedRestoreSources.some(s => s.version === source.version && s.migrationVersion === source.migrationVersion)));
}
