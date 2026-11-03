// SPDX-License-Identifier: Apache-2.0
import { createServer, type Server } from 'node:http';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { downloadArchive, storageErrorDetail, type Destination } from '../src/s3.js';

const ARCHIVE = '11111111-2222-4333-8444-555555555555';
const KEY_ID = 'TESTKEYIDVALUE0001';
const SECRET = 'test-secret-value-never-shown';

describe('storageErrorDetail', () => {
  it('names the S3 code and HTTP status of a rejected key', () => {
    expect(storageErrorDetail({ name: 'InvalidAccessKeyId', $metadata: { httpStatusCode: 403 }, message: `bad ${KEY_ID}` }))
      .toBe(' (S3 error InvalidAccessKeyId, HTTP 403): the destination rejected the key; check its ID and secret, that it is not deleted or expired, and that it can access this bucket');
  });
  it('says when the archive is missing', () => {
    expect(storageErrorDetail({ name: 'NoSuchKey', $metadata: { httpStatusCode: 404 } })).toBe(' (S3 error NoSuchKey, HTTP 404): the bucket or archive is not at the destination');
  });
  it('names a network error code', () => {
    expect(storageErrorDetail(Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:1'), { code: 'ECONNREFUSED' }))).toBe(' (ECONNREFUSED)');
  });
  it('drops anything that is not a plain code', () => {
    expect(storageErrorDetail({ name: `AccessDenied ${KEY_ID}`, code: 'not a code', $metadata: { httpStatusCode: '403' } })).toBe('');
    expect(storageErrorDetail(new Error(SECRET))).toBe('');
    expect(storageErrorDetail(SECRET)).toBe('');
    expect(storageErrorDetail(null)).toBe('');
  });
});

describe('downloadArchive', () => {
  let server: Server | undefined;
  let dir: string | undefined;
  afterEach(async () => {
    await new Promise<void>(done => server ? server.close(() => done()) : done());
    if (dir) await rm(dir, { recursive: true, force: true });
    server = undefined; dir = undefined;
  });
  async function store(status: number, code: string): Promise<Destination> {
    server = createServer((_req, res) => {
      res.writeHead(status, { 'content-type': 'application/xml' });
      res.end(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>${code}</Code><Message>Key ${KEY_ID} with ${SECRET} refused</Message><AWSAccessKeyId>${KEY_ID}</AWSAccessKeyId></Error>`);
    });
    await new Promise<void>(done => server!.listen(0, '127.0.0.1', () => done()));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('no port');
    return { endpoint: `http://127.0.0.1:${address.port}`, region: 'us-east-1', bucket: 'test-bucket', prefix: 'varlatch/', forcePathStyle: true, writeCredentialsFile: '/unused' };
  }
  it.each([
    [403, 'InvalidAccessKeyId', 'S3 error InvalidAccessKeyId, HTTP 403'],
    [404, 'NoSuchKey', 'S3 error NoSuchKey, HTTP 404'],
  ])('reports HTTP %i %s without echoing the response', async (status, code, detail) => {
    const destination = await store(status, code);
    dir = await mkdtemp(join(tmpdir(), 'varlatch-s3-'));
    const output = join(dir, 'archive.vltbak');
    const failure = await downloadArchive(destination, { accessKeyId: KEY_ID, secretAccessKey: SECRET }, ARCHIVE, output).then(() => undefined, (error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    const message = (failure as Error).message;
    expect(message).toContain(`Remote archive retrieval failed (${detail})`);
    expect(message).not.toContain(KEY_ID);
    expect(message).not.toContain(SECRET);
    await expect(stat(output)).rejects.toThrow();
  });
});
