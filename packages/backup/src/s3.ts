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
export async function uploadArchive(destination: Destination, credentials: StorageCredentials, archiveId: string, path: string): Promise<void> {
  const s3 = client(destination, credentials);
  const upload = new Upload({ client: s3, params: { Bucket: destination.bucket, Key: objectKey(destination, archiveId), Body: createReadStream(path), ContentLength: (await stat(path)).size, ContentType: 'application/octet-stream' }, queueSize: 2, partSize: 16 * 1024 * 1024, leavePartsOnError: false });
  try { await upload.done(); }
  catch { await upload.abort().catch(() => {}); throw new BackupError('Destination upload failed; local archive remains available'); }
  finally { s3.destroy(); }
}
export async function downloadArchive(destination: Destination, readCredentials: StorageCredentials, archiveId: string, output: string): Promise<void> {
  const s3 = client(destination, readCredentials);
  try {
    const result = await s3.send(new GetObjectCommand({ Bucket: destination.bucket, Key: objectKey(destination, archiveId) }));
    if (!result.Body) throw new Error('Missing object body');
    await pipeline(result.Body.transformToWebStream(), createWriteStream(output, { flags: 'wx', mode: 0o600 }));
  } catch { await rm(output, { force: true }); throw new BackupError('Remote archive retrieval failed'); }
  finally { s3.destroy(); }
}
