#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Destructive ONLY to the randomly named disposable projects created here.
// Prerequisites: Docker, workspace builds, and the candidate images
// varlatch-backup-test:local, varlatch-backup-web-test:local and
// varlatch-backup-convex-deploy-test:local (see the CI backup-recovery job);
// (docker build -t varlatch-backup-test:local -f services/varlatchd/Dockerfile .).
import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, cpSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { VarlatchClient } from '../packages/sdk/dist/index.js';
import { openArchive, sealArchive, parseKey, describeComponents } from '../packages/backup/dist/index.js';
const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const dir = mkdtempSync(join(tmpdir(), 'varlatch-backup-e2e-'));
const project = `vlt-backup-${randomBytes(5).toString('hex')}`;
const source = join(dir, 'source'), target = join(dir, 'target');
const dirs = [source, target];
function docker(where, args, input) {
  return execFileSync('docker', ['compose', '--project-directory', where, ...args], { input, encoding: 'utf8', maxBuffer: 2 * 1024 * 1024, stdio: ['pipe','pipe','pipe'] }).trim();
}
// Emulated runs (release.yml's arm64-e2e: arm64 images on an x64 host) are
// several times slower; VARLATCH_TEST_SLOWDOWN stretches every wait here.
const slowdown = Number(process.env.VARLATCH_TEST_SLOWDOWN || 1);
function cli(where, args, ok = true) {
  const result = spawnSync('node', [join(root, 'apps/cli/dist/varlatch.cjs'), 'admin', 'backup', ...args, '--dir', where, '--bek-file', join(where, 'secrets/bek'), '--kek-file', join(where, 'secrets/root')], { encoding: 'utf8', timeout: 180_000 * slowdown });
  if (ok) assert.equal(result.status, 0, result.stderr || result.stdout);
  else assert.notEqual(result.status, 0, 'Expected failure');
  return result.stdout;
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
// One connection per request. The docker and CLI calls block the event loop;
// when one outlasts varlatchd's keep-alive (5 s, as under arm64 emulation), a
// pooled connection's close goes unnoticed and the next request dies on it.
const fresh = (url, init = {}) => fetch(url, { ...init, headers: { ...Object.fromEntries(new Headers(init.headers)), connection: 'close' } });
async function status(url) { const tries = 60 * slowdown; for(let n=0;n<tries;n++) { try { return (await fresh(url)).status; } catch(e) { if(n===tries-1) throw e; await sleep(500); } } }
async function ready(url) { for(let n=0;n<120*slowdown;n++) { try { if ((await fresh(url)).ok) return; } catch {} await sleep(500); } throw Error('Service did not become ready'); }
function base(where, service, port) { return `http://${docker(where, ['port', service, String(port)])}`; }
const rootKey = randomBytes(32).toString('hex'), bek = randomBytes(32).toString('hex');
for (const [i, where] of dirs.entries()) {
  mkdirSync(join(where, 'secrets'), { recursive: true });
  writeFileSync(join(where, 'secrets/root'), rootKey); writeFileSync(join(where, 'secrets/bek'), bek);
  cpSync(join(root, 'infra/compose/postgres-init'), join(where, 'postgres-init'), { recursive: true });
  cpSync(join(root, 'infra/compose/convex-supervisor.cjs'), join(where, 'convex-supervisor.cjs'));
  let compose = readFileSync(join(root, 'infra/compose/docker-compose.yml'), 'utf8');
  compose = compose.replace('name: varlatch', `name: ${project}-${i}`)
    .replace(/build:\n\s+context: \.\.\/\.\.\n\s+dockerfile: services\/varlatchd\/Dockerfile\n/g, 'image: varlatch-backup-test:local\n')
    // Restore reconciles the Application Plane with the deploy job (ADR-0035 D4).
    .replace(/build:\n\s+context: \.\.\/\.\.\n\s+dockerfile: infra\/compose\/convex-deploy\.Dockerfile\n/g, 'image: varlatch-backup-convex-deploy-test:local\n')
    .replace(/build:\n\s+context: \.\.\/\.\.\n\s+dockerfile: apps\/web\/Dockerfile\n/g, 'image: varlatch-backup-web-test:local\n');
  if (i === 1) {
    // The target's varlatchd reports unhealthy throughout: its health check
    // fails while a restore holds it and can flap on a loaded host. Restore
    // must still start the rest of the installation, promptly.
    const before = compose;
    compose = compose.replace(`"fetch('http://127.0.0.1:8686/readyz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))",`, '"process.exit(1)",')
      .replace('retries: 6', 'retries: 1').replace('start_period: 15s', 'start_period: 0s');
    if (compose === before) throw Error('could not override the target varlatchd health check');
  }
  writeFileSync(join(where, 'docker-compose.yml'), compose);
  writeFileSync(join(where, '.env'), `POSTGRES_SUPERUSER_PASSWORD=test-superuser\nVARLATCH_MIGRATE_PASSWORD=test-migrate\nVARLATCH_RUNTIME_PASSWORD=test-runtime\nCONVEX_DB_PASSWORD=test-convex\nCONVEX_INSTANCE_SECRET=${randomBytes(32).toString('hex')}\nVARLATCHD_PORT=0\nVARLATCH_WEB_PORT=0\nCONVEX_PORT=0\nCONVEX_SITE_PORT=0\nVARLATCH_KEK_HOST_PATH=./secrets/root\nVARLATCH_PUBLIC_URL=http://varlatchd:8686\n`);

}
try {
  console.log('Starting isolated source installation');
  docker(source, ['up','-d','postgres','varlatch-migrate','varlatchd','convex-backend']);
  const apiUrl = base(source, 'varlatchd', 8686), convexUrl = base(source, 'convex-backend',3210);
  await ready(`${apiUrl}/readyz`); await ready(`${convexUrl}/version`);
  const adminKey = docker(source, ['exec','-T','convex-backend','./generate_admin_key.sh']);
  const env = { ...process.env, CONVEX_SELF_HOSTED_URL: convexUrl, CONVEX_SELF_HOSTED_ADMIN_KEY: adminKey };
  for (const [name, value] of [['VARLATCH_ISSUER','http://varlatchd:8686'],['VARLATCH_JWKS_URL','http://varlatchd:8686/.well-known/jwks.json']]) execFileSync('pnpm',['exec','convex','env','set',name,value],{cwd:join(root,'convex'),env,stdio:'pipe'});
  execFileSync('pnpm',['exec','convex','deploy','-y'],{cwd:join(root,'convex'),env,stdio:'pipe'});
  const bootstrap = docker(source, ['exec','-T','varlatchd','node','dist/cli.js','admin','bootstrap','--cli-credential']);
  const token = bootstrap.match(/vlt_cli_\S+/)?.[0]; assert(token);
  const api = new VarlatchClient({ server: apiUrl, token, fetch: fresh });
  await api.createOrganization({ slug: 'backup-test', name: 'Backup test' });
  await api.createProject('backup-test', { slug: 'app', name: 'App', contractAuthority: 'managed' });
  await api.createEnvironment('backup-test','app',{ name:'development', tier:'development' });
  const revision = await api.pushContractRevision('backup-test','app',{ contract: { schemaVersion: 1, items: [{ name:'SECRET', type:'string', sensitive:true, required:{kind:'always'} }] } });
  await api.activateContractRevision('backup-test','app',revision.id);
  await api.setValue('backup-test','app','development','SECRET',{ value:'backup-e2e-secret-value' });
  // Force a cold JWKS cache: draining Mirrors must fetch the public signing
  // keys while ordinary API traffic is already gated. Re-resolve ephemeral ports.
  docker(source, ['restart', 'convex-backend']);
  await ready(`${base(source, 'convex-backend', 3210)}/version`);
  const archive = join(dir,'good.vltbak');
  // Online capture (ADR-0036): the Secret Plane keeps serving throughout —
  // readiness, and disclosures, each of which commits an audit event.
  console.log('Capturing online while the Secret Plane keeps serving, then verifying');
  const capture = spawn('node', [join(root, 'apps/cli/dist/varlatch.cjs'), 'admin', 'backup', 'create', '--out', archive, '--dir', source, '--bek-file', join(source, 'secrets/bek'), '--kek-file', join(source, 'secrets/root')]);
  let captureOut = '', capturing = true;
  capture.stdout.on('data', d => { captureOut += d; }); capture.stderr.on('data', d => { captureOut += d; });
  const captured = new Promise(r => capture.on('exit', code => { capturing = false; r(code); }));
  const strict = new VarlatchClient({ server: apiUrl, token, maintenanceRetryMs: 0, fetch: fresh });
  const during = [];
  while (capturing) {
    during.push(await status(`${apiUrl}/readyz`));
    try { await strict.discloseSecrets('backup-test','app','development',{items:['SECRET']}); during.push('disclosed'); }
    catch (e) { during.push(`disclosure failed: ${e.code ?? e.message}`); }
    await sleep(100); // paced: each disclosure is an audit event for the Mirror publisher
  }
  assert.equal(await captured, 0, captureOut);
  assert(during.length >= 2 && during.every(s => s === 200 || s === 'disclosed'), `ordinary traffic was gated during capture: ${during.join(', ')}`);
  const format = await openArchive(archive, { kind: 'key', material: parseKey(bek) }, async m => ({ version: m.formatVersion, components: m.components.map(c => c.name) }));
  assert.deepEqual(format, { version: 2, components: ['secret-plane.dump'] }, 'format 2: the Secret Plane only');
  console.log(`PASS  online capture: ${during.length} requests during it, none gated; format-2 archive`);
  await sleep(3000 * slowdown); // let the Mirror publisher catch up before the frozen-protocol lease test
  cli(source,['verify','--in',archive,'--record']);
  const metadata = JSON.parse(cli(source,['status']));
  assert.equal(metadata.archives.length,1); assert.equal(metadata.archives[0].verification.keyMatch,true);
  const archiveId = metadata.archives[0].archiveId;
  // Lease expiry really resumes both services; stale ownership is rejected.
  console.log('Testing capture lease expiry');
  // The lease must outlast starting a CLI process in the container, which
  // takes several seconds on slow runners and far longer under emulation.
  const leaseMs = 10_000 * slowdown;
  const lease = JSON.parse(docker(source,['exec','-T','varlatchd','node','dist/cli.js','admin','backup-control','capture-begin'],JSON.stringify({ttlMs:leaseMs})));
  docker(source,['exec','-T','varlatchd','node','dist/cli.js','admin','backup-control','capture-pause'],JSON.stringify({id:lease.id}));
  assert.equal(await status(`${apiUrl}/readyz`),503);
  await sleep(leaseMs + 500); await ready(`${apiUrl}/readyz`); await ready(`${base(source, 'convex-backend', 3210)}/version`);
  assert.throws(()=>docker(source,['exec','-T','varlatchd','node','dist/cli.js','admin','backup-control','capture-finish'],JSON.stringify({id:lease.id})));
  docker(source,['stop']);
  cli(source,['verify','--in',archive]); // origin is completely offline
  console.log('Restoring on fresh volumes with regenerated Convex credentials');
  const firstRestore = cli(target,['restore','--in',archive]);
  // The Application Plane is rebuilt, not restored (ADR-0036 D3).
  assert.match(firstRestore, /Application Plane reconciled with this release/);
  assert.match(firstRestore, /Mirrors published from the restored Secret Plane/);
  // A restore leaves the whole installation running, dashboard included,
  // not only the services it needed for the restore itself.
  assert.match(firstRestore, /Remaining services started/);
  const running = docker(target, ['ps', '--status', 'running', '--services']).split('\n');
  for (const service of ['postgres', 'varlatchd', 'convex-backend', 'varlatch-web']) assert(running.includes(service), `${service} runs after restore: ${running.join(', ')}`);
  const targetApiUrl=base(target,'varlatchd',8686);
  await ready(`${targetApiUrl}/readyz`);
  const restored = new VarlatchClient({server:targetApiUrl,token,fetch:fresh});
  const disclosure=await restored.discloseSecrets('backup-test','app','development',{items:['SECRET']});
  assert.equal(disclosure.items[0].value,'backup-e2e-secret-value');
  const events=docker(target,['exec','-T','postgres','psql','-U','postgres','-d','varlatch','-Atc',"SELECT metadata->>'archiveId' FROM audit_events WHERE event_type='installation.restored' ORDER BY event_order DESC LIMIT 1"]);
  assert.equal(events,archiveId);
  const damaged=join(dir,'bad-db.vltbak');
  await openArchive(archive,{kind:'key',material:parseKey(bek)},async(manifest,scratch)=>{
    writeFileSync(join(scratch,'secret-plane.dump'),'not a pg_dump');
    manifest.components=await describeComponents(scratch, manifest.formatVersion);
    await sealArchive(scratch,manifest,{kind:'key',material:parseKey(bek)},damaged);
  });
  console.log('Injecting a restore failure and restarting both services');
  cli(target,['restore','--in',damaged],false);
  assert.equal(await status(`${targetApiUrl}/readyz`),503);
  docker(target,['restart','varlatchd','convex-backend']); await sleep(2000 * slowdown);
  // Ephemeral published ports are re-randomized by `docker restart`.
  const restartedApiUrl=base(target,'varlatchd',8686);
  assert.equal(await status(`${restartedApiUrl}/v1/meta`),503);
  assert.equal(await status(`${base(target,'convex-backend',3210)}/api/query`),503);
  assert.match(cli(target,['restore','--in',archive]),/Application Plane reconciled with this release/);
  const retriedUrl=base(target,'varlatchd',8686);
  await ready(`${retriedUrl}/readyz`);
  const retried = new VarlatchClient({server:retriedUrl,token,fetch:fresh});
  assert.equal((await retried.discloseSecrets('backup-test','app','development',{items:['SECRET']})).items[0].value,'backup-e2e-secret-value');
  console.log('PASS: capture, verification without origin, lease expiry, fresh-host restore, secret decryption, audit, failed restore isolation across restart, and idempotent retry');
} catch (error) {
  for (const where of dirs) { try { console.error(docker(where,['logs','--tail','200','varlatchd','convex-backend'])); } catch {} }
  for (const where of dirs) { try { console.error(`[${where}/backup-diagnostics.log]\n${readFileSync(join(where,'backup-diagnostics.log'),'utf8')}`); } catch {} }
  throw error;
} finally {
  for(const where of dirs) { try { docker(where,['down','-v','--remove-orphans']); } catch {} }
  rmSync(dir,{recursive:true,force:true});
}
