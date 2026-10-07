#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Isolated S3 compatibility check against a throwaway S3 server (the Versity
// S3 gateway, which enforces SigV4 authentication and supports multipart
// uploads); never accesses an operator's configured destination or existing
// container. VARLATCH_TEST_S3_IMAGE substitutes another versitygw image.
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes, randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
import { uploadArchive, downloadArchive } from '../packages/backup/dist/s3.js';
const require = createRequire(new URL('../packages/backup/package.json', import.meta.url));
const { S3Client, CreateBucketCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const image = process.env.VARLATCH_TEST_S3_IMAGE ?? 'docker.io/versity/versitygw:v1.8.0@sha256:30292fc2eeacc67a36993b01f7a7a5e3361a19cced0e80c1d71cfa2a4b0a2499';
const name = `vlt-backup-s3-${randomBytes(5).toString('hex')}`;
const dir = mkdtempSync(join(tmpdir(), name));
const credentials = { accessKeyId: 'backup-test', secretAccessKey: randomBytes(24).toString('hex') };
let s3;
try {
  // The secret goes through the environment, by name only: a failed command's
  // error repeats its arguments, and CI logs are public.
  execFileSync('docker', ['run','-d','--name',name,'-p','127.0.0.1::7070','-e',`ROOT_ACCESS_KEY=${credentials.accessKeyId}`,'-e','ROOT_SECRET_KEY',image,'posix','/tmp'], {stdio:'pipe',env:{...process.env,ROOT_SECRET_KEY:credentials.secretAccessKey}});
  const endpoint=`http://${execFileSync('docker',['port',name,'7070/tcp'],{encoding:'utf8'}).trim()}`;
  // Any HTTP answer, even an authentication error, means it is listening.
  for(let i=0;i<100;i++) { try { await fetch(endpoint); break; } catch {} await new Promise(r=>setTimeout(r,100)); }
  s3=new S3Client({endpoint,region:'us-east-1',forcePathStyle:true,credentials});
  await s3.send(new CreateBucketCommand({Bucket:'backups'}));
  const destination={endpoint,region:'us-east-1',bucket:'backups',prefix:'installation/',forcePathStyle:true,writeCredentialsFile:'unused'};
  // Crosses Upload's multipart threshold (16 MiB), exercises both protocols.
  for(const bytes of [1024,17*1024*1024]) {
    const id=randomUUID(), input=join(dir,`${id}.in`), output=join(dir,`${id}.out`), content=randomBytes(bytes);
    writeFileSync(input,content);
    await uploadArchive(destination,credentials,id,input);
    await downloadArchive(destination,credentials,id,output);
    assert.deepEqual(readFileSync(output),content);
    await s3.send(new DeleteObjectCommand({Bucket:'backups',Key:`installation/${id}.vltbak`}));
    await assert.rejects(downloadArchive(destination,credentials,id,join(dir,'missing')));
  }
  console.log('PASS: S3 single/multipart upload, retrieval, byte integrity, and missing-object failure');
} finally {
  s3?.destroy();
  try { execFileSync('docker',['rm','-fv',name],{stdio:'pipe'}); } catch {}
  rmSync(dir,{recursive:true,force:true});
}
