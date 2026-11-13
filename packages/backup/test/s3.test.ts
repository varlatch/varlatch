// SPDX-License-Identifier: Apache-2.0
import { createServer, type Server } from 'node:http';
import { mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GetObjectCommand } from '@aws-sdk/client-s3';
import { afterEach, describe, expect, it } from 'vitest';
import { bucketDestinationSchema, downloadArchive, storageClient, storageErrorDetail, uploadArchive, type Destination } from '../src/s3.js';

const ARCHIVE = '11111111-2222-4333-8444-555555555555';
const KEY_ID = 'TESTKEYIDVALUE0001';
const SECRET = 'TestSecretValueNeverShown0123456789';
const KEY_HINT = 'the destination rejected the key; check its ID and secret, and that it is not deleted or expired';
const REFUSED_HINT = 'the destination refused the request; check that the key can access this bucket';

describe('storageErrorDetail', () => {
  it.each([
    [{ name: 'InvalidAccessKeyId', $metadata: { httpStatusCode: 403 } }, ` (S3 error InvalidAccessKeyId, HTTP 403): ${KEY_HINT}`],
    [{ name: 'Unauthorized', $metadata: { httpStatusCode: 401 } }, ` (S3 error Unauthorized, HTTP 401): ${KEY_HINT}`],
    [{ name: 'SomethingNew', $metadata: { httpStatusCode: 401 } }, ` (HTTP 401): ${KEY_HINT}`],
    [{ name: 'AccessDenied', $metadata: { httpStatusCode: 403 } }, ' (S3 error AccessDenied, HTTP 403): the key may not do this; check that it can access this bucket'],
    [{ name: 'RequestTimeTooSkewed', $metadata: { httpStatusCode: 403 } }, " (S3 error RequestTimeTooSkewed, HTTP 403): this host's clock differs too much from the destination's; check the time on this host"],
    [{ name: 'InvalidObjectState', $metadata: { httpStatusCode: 403 } }, ' (S3 error InvalidObjectState, HTTP 403): the archive is in a storage class that cannot be read directly; restore it at the provider first'],
    [{ name: 'SomethingNew', $metadata: { httpStatusCode: 403 } }, ` (HTTP 403): ${REFUSED_HINT}`],
    [{ name: 'NoSuchKey', $metadata: { httpStatusCode: 404 } }, ' (S3 error NoSuchKey, HTTP 404): the archive is not at the destination'],
    [{ name: 'Unknown', Code: 'NoSuchBucket', $metadata: { httpStatusCode: 404 } }, ' (S3 error NoSuchBucket, HTTP 404): the bucket does not exist at the destination'],
    [{ name: 'TimeoutError' }, ' (request timed out)'],
    [{ name: 'CredentialsProviderError' }, ' (credentials could not be loaded)'],
    [Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:1'), { code: 'ECONNREFUSED' }), ' (connection refused)'],
    // The audit export's conditional writes and retention headers (ADR-0056 Decision 12).
    [{ name: 'PreconditionFailed', $metadata: { httpStatusCode: 412 } }, ' (S3 error PreconditionFailed, HTTP 412): an object with this name already exists at the destination'],
    [{ name: 'SomethingNew', $metadata: { httpStatusCode: 412 } }, ' (HTTP 412): an object with this name already exists at the destination'],
    [{ name: 'InvalidRequest', $metadata: { httpStatusCode: 400 } }, ' (S3 error InvalidRequest, HTTP 400): the destination refused the request; if it sets retention, check that the bucket has Object Lock enabled and that the key may set retention'],
    [{ name: 'ObjectLockConfigurationNotFoundError', $metadata: { httpStatusCode: 404 } }, ' (S3 error ObjectLockConfigurationNotFoundError, HTTP 404): the destination refused the request; if it sets retention, check that the bucket has Object Lock enabled and that the key may set retention'],
  ])('describes %j', (error, detail) => {
    expect(storageErrorDetail(error)).toBe(detail);
  });
  it('shows no value the store or the error supplied', () => {
    for (const value of [KEY_ID, SECRET, 'test-bucket', `E${KEY_ID}`, 'constructor', 'toString']) {
      expect(storageErrorDetail({ name: value, Code: value, code: value, $metadata: { httpStatusCode: 403 } })).toBe(` (HTTP 403): ${REFUSED_HINT}`);
      expect(storageErrorDetail({ name: value, Code: value, code: value })).toBe('');
    }
    expect(storageErrorDetail({ $metadata: { httpStatusCode: 4031 } })).toBe('');
    expect(storageErrorDetail({ $metadata: { httpStatusCode: '403' } })).toBe('');
    expect(storageErrorDetail(new Error(SECRET))).toBe('');
    expect(storageErrorDetail(SECRET)).toBe('');
    expect(storageErrorDetail(null)).toBe('');
  });
});

describe('storage failures through the SDK', () => {
  let server: Server | undefined;
  let dir: string | undefined;
  afterEach(async () => {
    await new Promise<void>(done => server ? server.close(() => done()) : done());
    if (dir) await rm(dir, { recursive: true, force: true });
    server = undefined; dir = undefined;
  });
  // A store that fails every request, echoing the key ID and secret in every
  // field of its error body, the error code included.
  async function store(status: number, code: string): Promise<Destination> {
    server = createServer((req, res) => {
      req.resume();
      req.on('end', () => {
        res.writeHead(status, { 'content-type': 'application/xml' });
        res.end(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>${code}</Code><Message>Key ${KEY_ID} with ${SECRET} refused</Message><AWSAccessKeyId>${KEY_ID}</AWSAccessKeyId><StringToSign>${SECRET}</StringToSign></Error>`);
      });
    });
    await new Promise<void>(done => server!.listen(0, '127.0.0.1', () => done()));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('no port');
    dir = await mkdtemp(join(tmpdir(), 'varlatch-s3-'));
    return { endpoint: `http://127.0.0.1:${address.port}`, region: 'us-east-1', bucket: 'test-bucket', prefix: 'varlatch/', forcePathStyle: true, writeCredentialsFile: '/unused' };
  }
  const credentials = { accessKeyId: KEY_ID, secretAccessKey: SECRET };
  function failure(promise: Promise<void>): Promise<string> {
    return promise.then(() => { throw new Error('expected a failure'); }, (error: unknown) => (error as Error).message);
  }
  const cases = [
    [403, 'InvalidAccessKeyId', `(S3 error InvalidAccessKeyId, HTTP 403): ${KEY_HINT}`],
    [401, 'Unauthorized', `(S3 error Unauthorized, HTTP 401): ${KEY_HINT}`],
    [404, 'NoSuchKey', '(S3 error NoSuchKey, HTTP 404): the archive is not at the destination'],
    [403, KEY_ID, `(HTTP 403): ${REFUSED_HINT}`],
    [403, SECRET, `(HTTP 403): ${REFUSED_HINT}`],
  ] as const;
  it.each(cases)('download: HTTP %i %s', async (status, code, detail) => {
    const destination = await store(status, code);
    const output = join(dir!, 'archive.vltbak');
    const message = await failure(downloadArchive(destination, credentials, ARCHIVE, output));
    expect(message).toBe(`Remote archive retrieval failed ${detail}`);
    expect(message).not.toContain(KEY_ID);
    expect(message).not.toContain(SECRET);
    await expect(stat(output)).rejects.toThrow();
  });
  it.each(cases)('upload: HTTP %i %s', async (status, code, detail) => {
    const destination = await store(status, code);
    const input = join(dir!, 'archive.vltbak');
    await writeFile(input, Buffer.alloc(1024, 1));
    const message = await failure(uploadArchive(destination, credentials, ARCHIVE, input));
    expect(message).toBe(`Destination upload failed ${detail}; local archive remains available`);
    expect(message).not.toContain(KEY_ID);
    expect(message).not.toContain(SECRET);
  });
});

describe('storageClient and bucketDestinationSchema (ADR-0056 Decision 12)', () => {
  it('takes a bucket without a credentials file, and refuses unknown fields', () => {
    expect(bucketDestinationSchema.parse({ endpoint: 'https://s3.example.com', region: 'us-east-1', bucket: 'b' })).toEqual({
      endpoint: 'https://s3.example.com', region: 'us-east-1', bucket: 'b', prefix: 'varlatch/', forcePathStyle: true,
    });
    expect(bucketDestinationSchema.safeParse({ region: 'r', bucket: 'b', writeCredentialsFile: '/x' }).success).toBe(false);
  });
  it('builds a client with the given attempts and request handler', async () => {
    const handled: string[] = [];
    const s3 = storageClient({ endpoint: 'http://127.0.0.1:1', region: 'r', bucket: 'b', prefix: '', forcePathStyle: true },
      { accessKeyId: KEY_ID, secretAccessKey: SECRET }, {
        maxAttempts: 1,
        requestHandler: { handle: async (request: { path: string }) => { handled.push(request.path); throw Object.assign(new Error('no'), { code: 'ECONNREFUSED' }); } } as never,
      });
    try {
      expect(await s3.config.maxAttempts()).toBe(1);
      await expect(s3.send(new GetObjectCommand({ Bucket: 'b', Key: 'k' }))).rejects.toThrow();
      expect(handled).toEqual(['/b/k']);
    } finally { s3.destroy(); }
  });
});
