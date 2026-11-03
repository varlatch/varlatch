// SPDX-License-Identifier: Apache-2.0
import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import { Upload } from '@aws-sdk/lib-storage';
import { createReadStream, createWriteStream } from 'node:fs';
import { stat, rm } from 'node:fs/promises';
import { pipeline } from 'node:stream/promises';
import { z } from 'zod';
import { BackupError } from './archive.js';

export const destinationSchema = z.object({
  endpoint: z.url().optional(), region: z.string().min(1), bucket: z.string().min(1), prefix: z.string().default('varlatch/'),
  forcePathStyle: z.boolean().default(true),
  writeCredentialsFile: z.string().min(1),
}).strict();
export const destinationsSchema = z.record(z.string().regex(/^[a-zA-Z0-9_-]+$/), destinationSchema);
export const credentialsSchema = z.object({ accessKeyId: z.string().min(1), secretAccessKey: z.string().min(1), sessionToken: z.string().optional() }).strict();
export type Destination = z.infer<typeof destinationSchema>;
export type StorageCredentials = z.infer<typeof credentialsSchema>;
function client(destination: Destination, credentials: StorageCredentials): S3Client {
  return new S3Client({ region: destination.region, ...(destination.endpoint ? { endpoint: destination.endpoint } : {}), forcePathStyle: destination.forcePathStyle, credentials: { accessKeyId: credentials.accessKeyId, secretAccessKey: credentials.secretAccessKey, ...(credentials.sessionToken ? { sessionToken: credentials.sessionToken } : {}) }, maxAttempts: 3 });
}
function objectKey(destination: Destination, archiveId: string): string {
  if (!z.uuid().safeParse(archiveId).success) throw new BackupError('Invalid archive ID');
  return `${destination.prefix.replace(/\/?$/, '/')}${archiveId}.vltbak`;
}
// What an operator needs to tell a wrong key from a missing object or an
// unreachable endpoint: the S3 error code, the HTTP status, and a network
// error code. Never the message or response body, which the store writes and
// which may echo request details; only values that match a strict shape.
const ACCESS_CODES = new Set(['AccessDenied', 'InvalidAccessKeyId', 'SignatureDoesNotMatch', 'Unauthorized', 'Forbidden', 'ExpiredToken', 'InvalidToken']);
const MISSING_CODES = new Set(['NoSuchKey', 'NotFound', 'NoSuchBucket']);
export function storageErrorDetail(error: unknown): string {
  if (typeof error !== 'object' || error === null) return '';
  const e = error as { name?: unknown; Code?: unknown; code?: unknown; $metadata?: { httpStatusCode?: unknown } };
  const status = typeof e.$metadata?.httpStatusCode === 'number' && Number.isInteger(e.$metadata.httpStatusCode) ? e.$metadata.httpStatusCode : undefined;
  const raw = typeof e.Code === 'string' ? e.Code : typeof e.name === 'string' ? e.name : undefined;
  const code = raw && /^[A-Za-z][A-Za-z0-9]{0,63}$/.test(raw) && !['Error', 'TypeError', 'BackupError'].includes(raw) ? raw : undefined;
  const network = typeof e.code === 'string' && /^E[A-Z0-9_]{1,31}$/.test(e.code) ? e.code : undefined;
  const parts = [code && `S3 error ${code}`, status !== undefined && `HTTP ${status}`, network].filter(Boolean);
  if (!parts.length) return '';
  const hint = (code && ACCESS_CODES.has(code)) || status === 401 || status === 403
    ? ': the destination rejected the key; check its ID and secret, that it is not deleted or expired, and that it can access this bucket'
    : (code && MISSING_CODES.has(code)) || status === 404 ? ': the bucket or archive is not at the destination' : '';
  return ` (${parts.join(', ')})${hint}`;
}
export async function uploadArchive(destination: Destination, credentials: StorageCredentials, archiveId: string, path: string): Promise<void> {
  const s3 = client(destination, credentials);
  const upload = new Upload({ client: s3, params: { Bucket: destination.bucket, Key: objectKey(destination, archiveId), Body: createReadStream(path), ContentLength: (await stat(path)).size, ContentType: 'application/octet-stream' }, queueSize: 2, partSize: 16 * 1024 * 1024, leavePartsOnError: false });
  try { await upload.done(); }
  catch (error) { await upload.abort().catch(() => {}); throw new BackupError(`Destination upload failed${storageErrorDetail(error)}; local archive remains available`); }
  finally { s3.destroy(); }
}
export async function downloadArchive(destination: Destination, readCredentials: StorageCredentials, archiveId: string, output: string): Promise<void> {
  const s3 = client(destination, readCredentials);
  try {
    const result = await s3.send(new GetObjectCommand({ Bucket: destination.bucket, Key: objectKey(destination, archiveId) }));
    if (!result.Body) throw new Error('Missing object body');
    await pipeline(result.Body.transformToWebStream(), createWriteStream(output, { flags: 'wx', mode: 0o600 }));
  } catch (error) { await rm(output, { force: true }); throw new BackupError(`Remote archive retrieval failed${storageErrorDetail(error)}`); }
  finally { s3.destroy(); }
}
