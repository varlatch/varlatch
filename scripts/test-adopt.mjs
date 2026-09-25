#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// `varlatch adopt` on plain Compose (ADR-0035 D13), candidate images
// (varlatch-backup-*-test:local). The installation is configured the old,
// hand-written way: every secret a variable, a hand-generated
// CONVEX_ADMIN_KEY, a separate Convex origin, and the legacy
// http://tailscale:8686 JWKS URL. Adoption must take ownership of it without
// changing what works, and every step must be verified in operation.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, appendFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseDocument } from 'yaml';
import { VarlatchClient } from '../packages/sdk/dist/index.js';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const cli = join(root, 'apps/cli/dist/varlatch.cjs');
const images = { varlatchd: 'varlatch-backup-test:local', 'varlatch-migrate': 'varlatch-backup-test:local', 'varlatch-web': 'varlatch-backup-web-test:local', 'convex-deploy': 'varlatch-backup-convex-deploy-test:local' };
const dir = mkdtempSync(join(tmpdir(), 'varlatch-adopt-e2e-'));
const results = [];
const pass = (name, detail = '') => { results.push(name); console.log(`PASS  ${name}${detail ? ` — ${detail}` : ''}`); };
const dc = (args, opts = {}) => execFileSync('docker', ['compose', ...args], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...opts }).trim();
const run = args => { const r = spawnSync('node', [cli, ...args, '--dir', dir], { encoding: 'utf8', timeout: 1_200_000, maxBuffer: 64 * 1024 * 1024 }); return { code: r.status, out: `${r.stdout}\n${r.stderr}` }; };
const freePort = () => new Promise(res => { const s = createServer(); s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => res(port)); }); });
const sha = f => createHash('sha256').update(readFileSync(f)).digest('hex');
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function healthy() {
  for (let i = 0; i < 120; i++) {
    const rows = dc(['ps', '--format', 'json']).split('\n').filter(Boolean).map(l => JSON.parse(l));
    if (rows.length >= 4 && rows.every(r => r.State === 'running' && (!r.Health || r.Health === 'healthy'))) return;
    await sleep(3000);
  }
  throw new Error('not healthy');
}

try {
  // ---- A hand-configured installation, the pre-ADR-0035 way.
  const doc = parseDocument(readFileSync(join(root, 'infra/compose/docker-compose.yml'), 'utf8'));
  doc.set('name', `vlt-adopt-${randomBytes(3).toString('hex')}`);
  for (const [service, image] of Object.entries(images)) {
    doc.deleteIn(['services', service, 'build']); doc.setIn(['services', service, 'image'], image); doc.setIn(['services', service, 'pull_policy'], 'never');
  }
  writeFileSync(join(dir, 'docker-compose.yml'), doc.toString({ lineWidth: 0 }));
  cpSync(join(root, 'infra/compose/convex-supervisor.cjs'), join(dir, 'convex-supervisor.cjs'));
  cpSync(join(root, 'infra/compose/postgres-init'), join(dir, 'postgres-init'), { recursive: true });
  mkdirSync(join(dir, 'secrets'), { mode: 0o700 }); mkdirSync(join(dir, 'backups'));
  writeFileSync(join(dir, 'secrets/varlatch-kek'), randomBytes(32).toString('hex'));
  const webPort = await freePort(), convexPort = await freePort();
  const values = {
    POSTGRES_SUPERUSER_PASSWORD: randomBytes(12).toString('hex'), VARLATCH_MIGRATE_PASSWORD: randomBytes(12).toString('hex'),
    VARLATCH_RUNTIME_PASSWORD: randomBytes(12).toString('hex'), CONVEX_DB_PASSWORD: randomBytes(12).toString('hex'),
    CONVEX_INSTANCE_SECRET: randomBytes(32).toString('hex'),
  };
  const convexOrigin = `http://localhost:${convexPort}`;
  writeFileSync(join(dir, '.env'), [
    ...Object.entries(values).map(([k, v]) => `${k}=${v}`),
    `VARLATCH_PUBLIC_URL=http://localhost:${webPort}`, 'VARLATCH_JWKS_URL=http://tailscale:8686/.well-known/jwks.json',
    'VARLATCH_CONVEX_URL=http://convex-backend:3210', `CONVEX_CLOUD_ORIGIN=${convexOrigin}`, `CONVEX_SITE_ORIGIN=${convexOrigin}`,
    `VARLATCH_WEB_PORT=${webPort}`, `CONVEX_PORT=${convexPort}`, 'VARLATCHD_PORT=0', 'VARLATCH_KEK_HOST_PATH=./secrets/varlatch-kek',
    'VARLATCH_SYNC=on', '',
  ].join('\n'), { mode: 0o600 });
  dc(['up', '-d', 'postgres', 'convex-backend']);
  for (let i = 0; i < 60 && !dc(['ps', '--format', '{{.Health}}', 'convex-backend']).includes('healthy'); i++) await sleep(3000);
  const adminKey = dc(['exec', '-T', 'convex-backend', './generate_admin_key.sh']).split('\n').pop();
  appendFileSync(join(dir, '.env'), `CONVEX_ADMIN_KEY=${adminKey}\n`);
  dc(['up', '-d']); await healthy();
  dc(['run', '--rm', 'convex-deploy']);
  const token = dc(['exec', '-T', 'varlatchd', 'node', 'dist/cli.js', 'admin', 'bootstrap', '--cli-credential']).match(/vlt_cli_\S+/)[0];
  const url = `http://${dc(['port', 'varlatchd', '8686'])}`;
  let api = new VarlatchClient({ server: url, token });
  await api.createOrganization({ slug: 'hand', name: 'Hand' });
  await api.createProject('hand', { slug: 'app', name: 'App', contractAuthority: 'managed' });
  await api.createEnvironment('hand', 'app', { name: 'production', tier: 'production' });
  const rev = await api.pushContractRevision('hand', 'app', { contract: { schemaVersion: 1, items: [{ name: 'SECRET', type: 'string', sensitive: true, required: { kind: 'always' } }] } });
  await api.activateContractRevision('hand', 'app', rev.id);
  await api.setValue('hand', 'app', 'production', 'SECRET', { value: 'hand-configured-secret' });
  pass('hand-configured installation: secrets as variables, admin key, separate Convex origin, legacy JWKS URL');

  // ---- Dry run: a plan, and nothing changes.
  const envBefore = sha(join(dir, '.env'));
  const dry = run(['adopt']);
  assert.equal(dry.code, 5, dry.out);
  for (const step of ['config', 'secret-files', 'remove-variables', 'trust', 'deploy-authority', 'custody', 'managed-env']) assert.match(dry.out, new RegExp(step));
  assert.equal(sha(join(dir, '.env')), envBefore, 'a dry run changes nothing');
  assert(!Object.values(values).some(v => dry.out.includes(v)), 'the plan names variables, never values');
  pass('dry run lists every step, prints no secret value, changes nothing');

  // ---- Apply: every step, verified in operation.
  const applied = run(['adopt', '--apply', '--escrow', 'copy', '--attest']);
  assert.equal(applied.code, 0, applied.out);
  assert.match(applied.out, /Adopted: this installation is managed/);
  assert(!Object.values(values).concat(adminKey).some(v => applied.out.includes(v)), 'no secret value printed');
  pass('adopt --apply completes every step');

  api = new VarlatchClient({ server: `http://${dc(['port', 'varlatchd', '8686'])}`, token });
  assert.equal((await api.discloseSecrets('hand', 'app', 'production', { items: ['SECRET'] })).items[0].value, 'hand-configured-secret');
  pass('same credential, same secret after adoption');
  const env = readFileSync(join(dir, '.env'), 'utf8');
  assert(env.startsWith('# Managed by `varlatch setup`'), 'managed .env');
  assert(!Object.values(values).concat(adminKey).some(v => env.includes(v)), '.env holds no secret value');
  assert.match(env, /VARLATCH_JWKS_URL=http:\/\/varlatchd:8686\/.well-known\/jwks.json/);
  assert.match(env, new RegExp(`CONVEX_CLOUD_ORIGIN=${convexOrigin}`), 'the separate Convex origin is kept');
  assert.match(env, /VARLATCH_SYNC=on/, 'operator lines kept');
  for (const service of ['postgres', 'varlatchd', 'convex-backend', 'varlatch-web']) {
    const config = execFileSync('docker', ['inspect', dc(['ps', '-q', service])], { encoding: 'utf8' });
    assert(!Object.values(values).concat(adminKey).some(v => config.includes(v)), `${service} configuration holds no secret value`);
  }
  pass('no secret value in .env or any container configuration; Convex origin and operator lines kept');
  const doctor = run(['doctor', '--json', '--wait', '30']);
  const checks = Object.fromEntries(JSON.parse(doctor.out.slice(doctor.out.indexOf('{'))).checks.map(c => [c.id, c]));
  assert.equal(doctor.code, 0, doctor.out);
  assert.equal(checks['application-plane.functions']?.status, 'pass');
  assert.equal(checks['custody.attestations']?.status, 'pass');
  pass('doctor clean after adoption, custody attested');

  // ---- Setup takes over from here and changes nothing.
  const configBefore = dc(['--profile', 'deploy', 'config', '--format', 'json']);
  const setup = run(['setup', '--no-wait']);
  assert.equal(dc(['--profile', 'deploy', 'config', '--format', 'json']), configBefore, 'setup keeps the adopted configuration');
  assert.match(setup.out, /none regenerated/);
  pass('a later `varlatch setup` keeps the adopted configuration byte-for-byte');

  // ---- Revert: only when nothing changed since.
  const revert = run(['adopt', '--revert', 'managed-env']);
  assert.equal(revert.code, 0, revert.out);
  assert(!readFileSync(join(dir, '.env'), 'utf8').startsWith('# Managed'), 'reverted to the checkpoint');
  assert.equal(run(['adopt', '--apply', '--only', 'managed-env']).code, 0);
  appendFileSync(join(dir, '.env'), '# edited by hand\n');
  const refused = run(['adopt', '--revert', 'managed-env']);
  assert.notEqual(refused.code, 0);
  assert.match(refused.out, /changed after managed-env/);
  assert.notEqual(run(['adopt', '--revert', 'trust']).code, 0, 'trust is forward only');
  pass('revert restores a checkpoint, refuses after a hand edit, and never undoes trust');

  console.log(`PASS: varlatch adopt (${results.length} checks)`);
} finally {
  try { dc(['--profile', 'deploy', 'down', '-v', '--remove-orphans']); } catch {}
  rmSync(dir, { recursive: true, force: true });
}
