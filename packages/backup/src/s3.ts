// SPDX-License-Identifier: Apache-2.0
import { S3Client, GetObjectCommand, GetObjectRetentionCommand, HeadObjectCommand, PutObjectCommand, type ObjectLockMode, type S3ClientConfig } from '@aws-sdk/client-s3';
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
/**
 * A bucket without a credentials file: for callers whose credential comes
 * from elsewhere (the audit export keeps its key in the database, ADR-0056
 * Decision 12).
 */
export const bucketDestinationSchema = destinationSchema.omit({ writeCredentialsFile: true });
export const destinationsSchema = z.record(z.string().regex(/^[a-zA-Z0-9_-]+$/), destinationSchema);
export const credentialsSchema = z.object({ accessKeyId: z.string().min(1), secretAccessKey: z.string().min(1), sessionToken: z.string().optional() }).strict();
export type Destination = z.infer<typeof destinationSchema>;
export type BucketDestination = z.infer<typeof bucketDestinationSchema>;
export type StorageCredentials = z.infer<typeof credentialsSchema>;
export interface StorageClientOptions {
  /**
   * The request handler, or its options (agents, timeouts): a caller whose
   * requests must go through a policy (the audit export, ADR-0057) passes
   * its agents here. Absent: the SDK's default handler.
   */
  requestHandler?: S3ClientConfig['requestHandler'];
  /** Attempts per request, retries included. Default 3. */
  maxAttempts?: number;
}
/** An S3 client for one destination and key. The caller destroys it. */
export function storageClient(destination: BucketDestination, credentials: StorageCredentials, options: StorageClientOptions = {}): S3Client {
  return new S3Client({
    region: destination.region, ...(destination.endpoint ? { endpoint: destination.endpoint } : {}), forcePathStyle: destination.forcePathStyle,
    credentials: { accessKeyId: credentials.accessKeyId, secretAccessKey: credentials.secretAccessKey, ...(credentials.sessionToken ? { sessionToken: credentials.sessionToken } : {}) },
    maxAttempts: options.maxAttempts ?? 3,
    ...(options.requestHandler ? { requestHandler: options.requestHandler } : {}),
  });
}
const client = (destination: Destination, credentials: StorageCredentials): S3Client => storageClient(destination, credentials);
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
// A conditional write found the name taken (If-None-Match, ADR-0056 Decision 4).
const EXISTS = 'an object with this name already exists at the destination';
// Retention headers the bucket refused: Object Lock is off, or the key may not set retention.
const LOCK = 'the destination refused the request; if it sets retention, check that the bucket has Object Lock enabled and that the key may set retention';
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
  ['PreconditionFailed', EXISTS],
  ['InvalidRequest', LOCK], ['ObjectLockConfigurationNotFoundError', LOCK], ['NoSuchObjectLockConfiguration', LOCK],
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
    : status === 404 ? 'the bucket or archive is not at the destination'
    : status === 412 ? EXISTS : undefined;
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

export type StorageClient = S3Client;
/** One object written only if its name is free (If-None-Match: *), with its checksums and optional Object Lock retention. */
export interface ConditionalPut {
  key: string;
  body: Buffer;
  /** Hex digests of `body`. */
  sha256: string;
  md5: string;
  contentType: string;
  retention: { mode: 'compliance' | 'governance'; retainUntil: Date } | null;
}
/**
 * A conditional PutObject (ADR-0056 Decision 4): If-None-Match: *,
 * Content-MD5 (B2 needs it with Object Lock), x-amz-checksum-sha256, the
 * SHA-256 as object metadata, and the retention headers when set. A taken
 * name rejects with HTTP 412.
 */
export async function putObjectIfAbsent(s3: S3Client, bucket: string, put: ConditionalPut, abortSignal?: AbortSignal): Promise<void> {
  await s3.send(new PutObjectCommand({
    Bucket: bucket, Key: put.key, Body: put.body, ContentLength: put.body.length, ContentType: put.contentType,
    ContentMD5: Buffer.from(put.md5, 'hex').toString('base64'), ChecksumSHA256: Buffer.from(put.sha256, 'hex').toString('base64'),
    Metadata: { sha256: put.sha256 }, IfNoneMatch: '*',
    ...(put.retention ? { ObjectLockMode: put.retention.mode.toUpperCase() as ObjectLockMode, ObjectLockRetainUntilDate: put.retention.retainUntil } : {}),
  }), abortSignal ? { abortSignal } : {});
}
/** The SHA-256 metadata of an existing object (undefined when it has none). Needs a key that can read. */
export async function objectSha256(s3: S3Client, bucket: string, key: string, abortSignal?: AbortSignal): Promise<string | undefined> {
  const head = await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: key }), abortSignal ? { abortSignal } : {});
  return head.Metadata?.sha256;
}
/**
 * An object's Object Lock retention, read back (GetObjectRetention); null
 * when it has none, whether the answer says so (NoSuchObjectLockConfiguration)
 * or names no mode and date. A refusal (AccessDenied) throws: reading
 * retention is a permission of its own.
 */
export async function objectRetention(s3: S3Client, bucket: string, key: string, abortSignal?: AbortSignal): Promise<{ mode: string; retainUntil: Date } | null> {
  let got;
  try {
    got = await s3.send(new GetObjectRetentionCommand({ Bucket: bucket, Key: key }), abortSignal ? { abortSignal } : {});
  } catch (error) {
    const name = (error as { name?: unknown })?.name;
    if (name === 'NoSuchObjectLockConfiguration' || name === 'ObjectLockConfigurationNotFoundError') return null;
    throw error;
  }
  return got.Retention?.Mode && got.Retention.RetainUntilDate ? { mode: got.Retention.Mode.toLowerCase(), retainUntil: got.Retention.RetainUntilDate } : null;
}
/** An HTTP 412: the conditional write found the name taken. */
export const isPreconditionFailed = (error: unknown): boolean =>
  (error as { $metadata?: { httpStatusCode?: unknown } })?.$metadata?.httpStatusCode === 412 || (error as { name?: unknown })?.name === 'PreconditionFailed';
/** An HTTP 403 or AccessDenied: the key may not do this. */
export const isAccessDenied = (error: unknown): boolean =>
  (error as { $metadata?: { httpStatusCode?: unknown } })?.$metadata?.httpStatusCode === 403 || (error as { name?: unknown })?.name === 'AccessDenied';
