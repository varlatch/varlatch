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
// unreachable endpoint. Every word comes from the tables below: the store
// writes the error code, message and body, and any of them may echo a key ID,
// a signature or an object path, so an unrecognised value is never shown.
const KEY = 'the destination rejected the key; check its ID and secret, and that it is not deleted or expired';
const ACCESS = 'the key may not do this; check that it can access this bucket';
const S3_CODES: ReadonlyMap<string, string> = new Map([
  ['InvalidAccessKeyId', KEY], ['SignatureDoesNotMatch', KEY], ['ExpiredToken', KEY], ['InvalidToken', KEY],
  ['TokenRefreshRequired', KEY], ['Unauthorized', KEY],
  ['AccessDenied', ACCESS], ['AllAccessDisabled', ACCESS], ['AccountProblem', 'the destination account has a problem; check it with the provider'],
  ['NoSuchKey', 'the archive is not at the destination'], ['NotFound', 'the archive is not at the destination'],
  ['NoSuchBucket', 'the bucket does not exist at the destination'],
  ['RequestTimeTooSkewed', "this host's clock differs too much from the destination's; check the time on this host"],
  ['InvalidObjectState', 'the archive is in a storage class that cannot be read directly; restore it at the provider first'],
  ['InternalError', 'the destination had a temporary problem; try again later'], ['ServiceUnavailable', 'the destination had a temporary problem; try again later'],
  ['SlowDown', 'the destination is limiting requests; try again later'],
]);
const LOCAL_NAMES: ReadonlyMap<string, string> = new Map([
  ['TimeoutError', 'request timed out'], ['CredentialsProviderError', 'credentials could not be loaded'],
]);
const NETWORK_CODES: ReadonlyMap<string, string> = new Map([
  ['ENOTFOUND', 'endpoint host name not found'], ['EAI_AGAIN', 'endpoint host name lookup failed'],
  ['ECONNREFUSED', 'connection refused'], ['ECONNRESET', 'connection reset'], ['ETIMEDOUT', 'connection timed out'],
  ['EHOSTUNREACH', 'endpoint unreachable'], ['ENETUNREACH', 'network unreachable'], ['EPIPE', 'connection closed'],
  ['CERT_HAS_EXPIRED', 'endpoint TLS certificate expired'], ['ERR_TLS_CERT_ALTNAME_INVALID', 'endpoint TLS certificate does not match the host'],
  ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'endpoint TLS certificate not trusted'], ['SELF_SIGNED_CERT_IN_CHAIN', 'endpoint TLS certificate not trusted'],
  ['DEPTH_ZERO_SELF_SIGNED_CERT', 'endpoint TLS certificate not trusted'],
]);
function known(table: ReadonlyMap<string, string>, value: unknown): string | undefined {
  return typeof value === 'string' ? table.get(value) : undefined;
}
export function storageErrorDetail(error: unknown): string {
  if (typeof error !== 'object' || error === null) return '';
  const e = error as { name?: unknown; Code?: unknown; code?: unknown; $metadata?: { httpStatusCode?: unknown } };
  const raw = e.$metadata?.httpStatusCode;
  const status = typeof raw === 'number' && Number.isInteger(raw) && raw >= 100 && raw <= 599 ? raw : undefined;
  const s3Code = [e.Code, e.name].find(value => known(S3_CODES, value) !== undefined) as string | undefined;
  const local = known(LOCAL_NAMES, e.name);
  const network = known(NETWORK_CODES, e.code);
  const parts = [s3Code && `S3 error ${s3Code}`, status !== undefined && `HTTP ${status}`, local, network].filter(Boolean);
  if (!parts.length) return '';
  const hint = s3Code ? S3_CODES.get(s3Code)
    : status === 401 ? KEY
    : status === 403 ? 'the destination refused the request; check that the key can access this bucket'
    : status === 404 ? 'the bucket or archive is not at the destination' : undefined;
  return ` (${parts.join(', ')})${hint ? `: ${hint}` : ''}`;
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
