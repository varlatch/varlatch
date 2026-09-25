#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Prod-shaped release transition (ADR-0035 design note: "implement everything,
// validate once"). An installation laid out like a reference production
// deployment:
//
//   - the Coolify/Tailscale Compose file (published v0.9.0 → candidate, generated)
//   - Coolify's environment: every stack variable in every service (#28)
//   - CONVEX_ADMIN_KEY in that environment; convex-deploy runs on every deploy
//   - Convex trusting varlatchd via the legacy http://tailscale:8686 JWKS URL
//
// is upgraded to the candidate the way Coolify deploys it — no adoption — and
// must keep working unchanged. Then the pre-upgrade archive is restored on a
// fresh host of the same shape, and (informational until ADR-0035 Q10 lands)
// on a fresh canonical-Compose host.
//
// CI has no tailnet: the sidecar is replaced by a stub that holds the network
// namespace and the `varlatchd` alias, exactly the parts varlatchd depends on.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { connect } from 'node:net';
import { fileURLToPath } from 'node:url';
import { parseDocument } from 'yaml';
import { VarlatchClient } from '../packages/sdk/dist/index.js';
import { openArchive, parseKey } from '../packages/backup/dist/index.js';
import { mergeInto } from '../infra/coolify/generate-compose.mjs';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const fixtures = join(root, 'scripts/fixtures/v0.9.0');
const oldManifest = JSON.parse(readFileSync(join(fixtures, 'varlatch-release.json'), 'utf8'));
const release = JSON.parse(readFileSync(join(root, 'packages/backup/src/release.json'), 'utf8'));
const LOCAL_OLD = process.env.VARLATCH_TEST_OLD_IMAGES === 'local';
const oldImages = LOCAL_OLD
  ? { varlatchd: 'varlatch-v090-varlatchd:local', 'varlatch-web': 'varlatch-v090-web:local', 'convex-deploy': 'varlatch-v090-convex-deploy:local' }
  : { varlatchd: oldManifest.images.varlatchd.digest, 'varlatch-web': oldManifest.images['varlatch-web'].digest, 'convex-deploy': oldManifest.images['convex-deploy'].digest };
const newImages = { varlatchd: 'varlatch-backup-test:local', 'varlatch-web': 'varlatch-backup-web-test:local', 'convex-deploy': 'varlatch-backup-convex-deploy-test:local' };
const IMAGE_OF = { 'varlatch-migrate': 'varlatchd', varlatchd: 'varlatchd', 'varlatch-web': 'varlatch-web', 'convex-deploy': 'convex-deploy' };
const LEGACY_JWKS = 'http://tailscale:8686/.well-known/jwks.json';

const dir = mkdtempSync(join(tmpdir(), 'varlatch-prod-shape-'));
const project = `vlt-prodshape-${randomBytes(4).toString('hex')}`;
const prod = join(dir, 'prod'), sameShape = join(dir, 'restore-same-shape'), canonical = join(dir, 'restore-canonical');
const fileBased = join(dir, 'file-based');
const secrets = {
  rootKey: randomBytes(32).toString('hex'), bek: randomBytes(32).toString('hex'),
  instance: randomBytes(32).toString('hex'), pg: randomBytes(12).toString('hex'),
};

function sh(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'], ...opts }).trim();
}
const dc = (where, args, input) => sh('docker', ['compose', '--project-directory', where, ...args], { input, timeout: 600_000 });
const sleep = ms => new Promise(r => setTimeout(r, ms));
function ps(where, service) {
  const out = dc(where, ['ps', '-a', '--format', 'json', service]);
  const rows = out.startsWith('[') ? JSON.parse(out) : out.split('\n').filter(Boolean).map(l => JSON.parse(l));
  return rows[0];
}
async function until(what, test, ms = 180_000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) { if (await test()) return; await sleep(1000); }
  throw new Error(`Timed out waiting for ${what}`);
}
async function ready(url) {
  await until(`${url}/readyz`, async () => { try { return (await fetch(`${url}/readyz`)).ok; } catch { return false; } });
}
const serviceUrl = (where, service, port) => `http://${dc(where, ['port', service, String(port)])}`;
function cli(bin, where, args) {
  const result = spawnSync('node', [bin, ...args, '--dir', where], { encoding: 'utf8', timeout: 600_000, maxBuffer: 64 * 1024 * 1024 });
  let diagnostics = '';
  try { diagnostics = readFileSync(join(where, 'backup-diagnostics.log'), 'utf8'); } catch {}
  return { ok: result.status === 0, out: `${result.stdout}\n${result.stderr}${result.status === 0 || !diagnostics ? '' : `\n[backup-diagnostics.log]\n${diagnostics}`}`.trim() };
}
const keyArgs = where => ['--bek-file', join(where, 'secrets/bek'), '--kek-file', join(where, 'secrets/root')];

/** The prod shape: a Coolify Compose file + CI stubs, with images instead of builds. */
function prodShapeCompose(source, images, name) {
  const doc = parseDocument(readFileSync(source, 'utf8'));
  mergeInto(doc.contents, parseDocument(`
services:
  tailscale:
    image: alpine:3.20
    entrypoint: !reset []
    command: ["sleep", "infinity"]
    healthcheck:
      disable: true
`).contents);
  return finish(doc, images, name, true);
}
function canonicalCompose(images, name) {
  return finish(parseDocument(readFileSync(join(root, 'infra/compose/docker-compose.yml'), 'utf8')), images, name, false);
}
function finish(doc, images, name, coolifyEnv) {
  doc.set('name', name);
  for (const service of doc.getIn(['services']).items.map(p => String(p.key.value))) {
    if (IMAGE_OF[service]) {
      doc.deleteIn(['services', service, 'build']);
      doc.setIn(['services', service, 'image'], images[IMAGE_OF[service]]);
      if (images[IMAGE_OF[service]].endsWith(':local')) doc.setIn(['services', service, 'pull_policy'], 'never');
    }
    // Coolify hands every service every stack variable (#28); reproduce it.
    if (coolifyEnv) doc.setIn(['services', service, 'env_file'], ['.env']);
  }
  return doc.toString({ lineWidth: 0 });
}

function prepare(where, compose, supervisor, initDir, extraEnv = {}) {
  mkdirSync(join(where, 'secrets'), { recursive: true });
  mkdirSync(join(where, 'backups'), { recursive: true }); // operator-owned, not Docker-created
  // varlatchd runs as uid 999 and reads the KEK through the Compose secret
  // bind mount; a host-owned 0600 file is unreadable to it. Scratch keys use
  // default permissions like the other recovery tests.
  writeFileSync(join(where, 'secrets/root'), secrets.rootKey);
  writeFileSync(join(where, 'secrets/bek'), secrets.bek, { mode: 0o600 });
  cpSync(initDir, join(where, 'postgres-init'), { recursive: true });
  cpSync(supervisor, join(where, 'convex-supervisor.cjs'));
  writeFileSync(join(where, 'docker-compose.yml'), compose);
  const env = {
    POSTGRES_SUPERUSER_PASSWORD: `su-${secrets.pg}`, VARLATCH_MIGRATE_PASSWORD: `mig-${secrets.pg}`,
    VARLATCH_RUNTIME_PASSWORD: `rt-${secrets.pg}`, CONVEX_DB_PASSWORD: `cvx-${secrets.pg}`,
    CONVEX_INSTANCE_SECRET: secrets.instance, TS_AUTHKEY: 'tskey-ci-stub', VARLATCH_TAILNET_NAME: 'ci.ts.net',
    VARLATCH_PUBLIC_URL: 'https://varlatch.prodshape.test', VARLATCH_JWKS_URL: LEGACY_JWKS,
    VARLATCH_CONVEX_URL: 'http://convex-backend:3210',
    CONVEX_CLOUD_ORIGIN: 'https://convex.prodshape.test', CONVEX_SITE_ORIGIN: 'https://convex.prodshape.test',
    VARLATCH_KEK_HOST_PATH: './secrets/root', VARLATCHD_PORT: '0', VARLATCH_WEB_PORT: '0', CONVEX_PORT: '0',
    ...extraEnv,
  };
  writeFileSync(join(where, '.env'), Object.entries(env).map(([k, v]) => `${k}=${v}`).join('\n') + '\n', { mode: 0o600 });
}
const addEnv = (where, key, value) => writeFileSync(join(where, '.env'), readFileSync(join(where, '.env'), 'utf8') + `${key}=${value}\n`);

async function coolifyDeploy(where, { recreate = false } = {}) {
  // Coolify's deploy: bring the whole file up; convex-deploy is part of it.
  // On upgrade every container is recreated so all of them run candidate
  // code — convex-backend's image is unchanged across releases and its
  // supervisor is a bind-mounted file, so without recreation the pre-upgrade
  // supervisor process would keep running.
  dc(where, ['up', '-d', '--remove-orphans', ...(recreate ? ['--force-recreate'] : [])]);
  await until('convex-deploy to finish', () => ps(where, 'convex-deploy')?.State === 'exited');
  assert.equal(ps(where, 'convex-deploy').ExitCode, 0, 'convex-deploy must succeed');
  // A deploy is judged by "running:healthy" (the Coolify baseline), not by
  // the moment `up` returns: wait until every health-checked service is healthy.
  await until('all services healthy', () => {
    const out = dc(where, ['ps', '--format', 'json']);
    const rows = out.startsWith('[') ? JSON.parse(out) : out.split('\n').filter(Boolean).map(l => JSON.parse(l));
    return rows.every(r => r.State === 'running' && (!r.Health || r.Health === 'healthy'));
  });
  const url = serviceUrl(where, 'tailscale', 8686);
  await ready(url);
  return url;
}
function convexEnv(where, name) {
  // Uses the provided admin key, or derives one inside the job container the
  // way reconcile does (restored hosts have no CONVEX_ADMIN_KEY).
  const script = '[ -n "$CONVEX_SELF_HOSTED_ADMIN_KEY" ] || CONVEX_SELF_HOSTED_ADMIN_KEY=$(convex-generate-key "${INSTANCE_NAME:-convex-self-hosted}" ' +
    '"${CONVEX_INSTANCE_SECRET:-$(cat "$CONVEX_INSTANCE_SECRET_FILE" 2>/dev/null)}" | tail -n 1); export CONVEX_SELF_HOSTED_ADMIN_KEY; ' +
    `exec node_modules/.bin/convex env get ${name}`;
  return dc(where, ['run', '--rm', '--no-deps', '-T', '--entrypoint', 'sh', 'convex-deploy', '-c', script]).split('\n').pop();
}
function envNames(where, service) {
  const id = dc(where, ['ps', '-q', service]);
  return sh('docker', ['inspect', id, '--format', '{{range .Config.Env}}{{println .}}{{end}}']).split('\n').map(l => l.split('=')[0]).filter(Boolean);
}

/** Opens a real WebSocket upgrade through the Convex supervisor, then resets
 * it (TCP RST) the way a dropped network or an exiting client does. */
function resetWebSocket(hostPort) {
  const [host, port] = hostPort.split(':');
  return new Promise((resolveReset, reject) => {
    const socket = connect({ host, port: Number(port) }, () => socket.write(
      `GET /api/1.45.0/sync HTTP/1.1\r\nHost: ${hostPort}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
      `Sec-WebSocket-Key: ${randomBytes(16).toString('base64')}\r\nSec-WebSocket-Version: 13\r\n\r\n`));
    socket.once('data', data => {
      if (!String(data).startsWith('HTTP/1.1 101')) { socket.destroy(); reject(new Error(`no upgrade: ${String(data).split('\r\n')[0]}`)); return; }
      socket.resetAndDestroy(); setTimeout(resolveReset, 300);
    });
    socket.once('error', reject);
    setTimeout(() => reject(new Error('upgrade timeout')), 10_000);
  });
}
const results = [];

const pass = (name, detail = '') => { results.push(name); console.log(`PASS  ${name}${detail ? ` — ${detail}` : ''}`); };

try {
  // ---- 1. Published v0.9.0 in the prod shape, provisioned like Coolify.
  console.log(`--- v0.9.0 prod shape (${LOCAL_OLD ? 'local tag rebuild' : 'published digests'})`);
  prepare(prod, prodShapeCompose(join(fixtures, 'docker-compose.coolify-tailscale.yml'), oldImages, `${project}-prod`),
    join(fixtures, 'convex-supervisor.cjs'), join(fixtures, 'postgres-init'));
  dc(prod, ['up', '-d', 'postgres', 'convex-backend']);
  await until('convex-backend healthy', () => ps(prod, 'convex-backend')?.Health === 'healthy');
  addEnv(prod, 'CONVEX_ADMIN_KEY', dc(prod, ['exec', '-T', 'convex-backend', './generate_admin_key.sh']).split('\n').pop());
  let url = await coolifyDeploy(prod);
  const token = dc(prod, ['exec', '-T', 'varlatchd', 'node', 'dist/cli.js', 'admin', 'bootstrap', '--cli-credential']).match(/vlt_cli_\S+/)?.[0];
  assert(token, 'bootstrap credential');
  let api = new VarlatchClient({ server: url, token });
  await api.createOrganization({ slug: 'prod', name: 'Prod' });
  await api.createProject('prod', { slug: 'app', name: 'App', contractAuthority: 'managed' });
  await api.createEnvironment('prod', 'app', { name: 'production', tier: 'production' });
  const revision = await api.pushContractRevision('prod', 'app', { contract: { schemaVersion: 1, items: [{ name: 'SECRET', type: 'string', sensitive: true, required: { kind: 'always' } }] } });
  await api.activateContractRevision('prod', 'app', revision.id);
  await api.setValue('prod', 'app', 'production', 'SECRET', { value: 'prod-shape-secret' });
  dc(prod, ['exec', '-T', 'varlatchd', 'node', 'dist/cli.js', 'admin', 'mirror-sync']);
  assert.equal(convexEnv(prod, 'VARLATCH_JWKS_URL'), LEGACY_JWKS);
  pass('v0.9.0 prod shape serves, mirrors via the legacy tailscale JWKS URL');

  // ---- 2. Pre-upgrade archive with the release's own CLI (as the host timer does).
  const oldCli = join(dir, 'varlatch-0.9.0.cjs');
  writeFileSync(oldCli, sh('docker', ['run', '--rm', '--entrypoint', 'cat', oldImages.varlatchd, '/opt/varlatch/varlatch.cjs']));
  const archive = join(dir, 'pre-upgrade.vltbak');
  const capture = cli(oldCli, prod, ['admin', 'backup', 'create', ...keyArgs(prod), '--out', archive]);
  assert(capture.ok, capture.out);
  pass('pre-upgrade archive captured with the v0.9.0 CLI');
  // The candidate CLI against the v0.9.0 daemon — what `varlatch upgrade`
  // does first: the daemon predates online capture (ADR-0036), so the CLI
  // falls back to the frozen protocol and a format-1 archive.
  const fallbackArchive = join(dir, 'pre-upgrade-candidate-cli.vltbak');
  const fallback = cli(join(root, 'apps/cli/dist/varlatch.cjs'), prod, ['admin', 'backup', 'create', ...keyArgs(prod), '--out', fallbackArchive]);
  assert(fallback.ok, fallback.out);
  assert.equal(await openArchive(fallbackArchive, { kind: 'key', material: parseKey(secrets.bek) }, async m => m.formatVersion), 1);
  pass('the candidate CLI captures the v0.9.0 daemon with the frozen protocol (format 1)');

  // ---- 3. Upgrade the Coolify way — new file + images, redeploy — no adoption.
  console.log(`--- upgrade to candidate ${release.version} (Coolify redeploy, not adopted)`);
  writeFileSync(join(prod, 'docker-compose.yml'),
    prodShapeCompose(join(root, 'infra/compose/docker-compose.coolify-tailscale.yml'), newImages, `${project}-prod`));
  cpSync(join(root, 'infra/compose/convex-supervisor.cjs'), join(prod, 'convex-supervisor.cjs'));
  url = await coolifyDeploy(prod, { recreate: true });
  api = new VarlatchClient({ server: url, token });
  assert.equal((await api.meta()).serverVersion, release.version);
  assert.equal((await api.discloseSecrets('prod', 'app', 'production', { items: ['SECRET'] })).items[0].value, 'prod-shape-secret');
  pass('upgraded without adoption: same credential, same secret', `server ${release.version}`);
  assert.equal(convexEnv(prod, 'VARLATCH_JWKS_URL'), LEGACY_JWKS, 'an upgrade without adoption must not rewrite Convex trust configuration');
  pass('Convex trust configuration untouched by the upgrade');
  const again = dc(prod, ['run', '--rm', '--no-deps', '-T', 'convex-deploy']);
  assert.match(again, /deployment authority provided/, 'an installation that still sets CONVEX_ADMIN_KEY keeps using it (D13)');
  assert.match(again, /nothing to change/, `reconcile after the upgrade must be a no-op:\n${again}`);
  pass('reconcile on the upgraded installation uses the provided key and changes nothing');
  const doctor = cli(join(root, 'apps/cli/dist/varlatch.cjs'), prod, ['doctor', '--json', '--wait', '30']);
  const checks = Object.fromEntries(JSON.parse(doctor.out.slice(doctor.out.indexOf('{'))).checks.map(c => [c.id, c]));
  for (const id of ['services.running', 'secret-plane.ready', 'mirror.catch-up', 'application-plane.deploy', 'application-plane.functions', 'release.pending-upgrade']) {
    assert.equal(checks[id]?.status, 'pass', `doctor ${id}: ${checks[id]?.detail ?? 'missing'}`);
  }
  assert(doctor.ok, 'doctor reports no mandatory failure');
  pass('doctor: no mandatory failure on the upgraded prod shape');
  const convexPort = dc(prod, ['port', 'convex-backend', '3210']);
  for (let i = 0; i < 5; i++) await resetWebSocket(convexPort);
  await sleep(2000);
  const restarted = dc(prod, ['ps', '-aq']).split('\n').filter(Boolean)
    .map(id => sh('docker', ['inspect', id, '--format', '{{.Name}} {{.RestartCount}}']))
    .filter(line => !line.endsWith(' 0'));
  assert.deepEqual(restarted, [], 'no container may crash-restart across the upgrade');
  pass('no container restarted across the upgrade, including 5 reset WebSocket clients');
  const leaked = envNames(prod, 'varlatchd').filter(n => ['CONVEX_ADMIN_KEY', 'CONVEX_INSTANCE_SECRET', 'POSTGRES_SUPERUSER_PASSWORD', 'VARLATCH_MIGRATE_PASSWORD', 'CONVEX_DB_PASSWORD', 'TS_AUTHKEY'].includes(n));
  console.log(`INFO  #28 (known, not adopted): runtime varlatchd receives ${leaked.join(', ') || 'none'}`);

  // ---- 3b. Adopt it the Coolify way (ADR-0035 D13): adopt prints the env
  // change, the operator applies it in Coolify's settings and redeploys, adopt
  // verifies — until adopted. Here the "settings" are the injected .env.
  console.log('--- adopt the upgraded Coolify-shaped installation (D13)');
  const secretValues = [`su-${secrets.pg}`, `mig-${secrets.pg}`, `rt-${secrets.pg}`, `cvx-${secrets.pg}`, secrets.instance,
    readFileSync(join(prod, '.env'), 'utf8').match(/^CONVEX_ADMIN_KEY=(.+)$/m)[1]];
  addEnv(prod, 'COOLIFY_RESOURCE_UUID', 'ci-resource');
  url = await coolifyDeploy(prod);
  const coolifySettings = (changes) => {
    let text = readFileSync(join(prod, '.env'), 'utf8');
    for (const line of changes) {
      const m = line.match(/^(add|set|delete) ([A-Z0-9_]+)(?:=(.*))?$/);
      text = text.split('\n').filter(l => !l.startsWith(`${m[2]}=`)).join('\n');
      if (m[1] !== 'delete') text = `${text.replace(/\n*$/, '\n')}${m[2]}=${m[3]}\n`;
    }
    writeFileSync(join(prod, '.env'), text);
  };
  let rounds = 0;
  for (;;) {
    const r = cli(join(root, 'apps/cli/dist/varlatch.cjs'), prod, ['adopt', '--apply', '--secrets-dir', join(prod, 'host-secrets'), '--escrow', 'copy', '--attest']);
    assert(!secretValues.some(v => r.out.includes(v)), 'adopt never prints a secret value');
    if (r.ok) break;
    const changes = r.out.split('\n').map(l => l.trim()).filter(l => /^(add|set|delete) [A-Z0-9_]+/.test(l));
    assert(changes.length, `adopt stopped without a Coolify change plan:\n${r.out}`);
    assert(++rounds <= 6, 'adoption converges');
    console.log(`  round ${rounds}: ${changes.map(c => c.split('=')[0]).join('; ')}`);
    coolifySettings(changes);
    url = await coolifyDeploy(prod, { recreate: true }); // a Coolify deploy recreates the containers
  }
  api = new VarlatchClient({ server: url, token });
  assert.equal((await api.discloseSecrets('prod', 'app', 'production', { items: ['SECRET'] })).items[0].value, 'prod-shape-secret');
  const adoptedConfig = sh('docker', ['inspect', dc(prod, ['ps', '-q', 'varlatchd'])]);
  assert.deepEqual(secretValues.filter(v => adoptedConfig.includes(v)), [], 'runtime varlatchd holds no other service\'s secret');
  assert.match(readFileSync(join(prod, '.env'), 'utf8'), /^VARLATCH_JWKS_URL=http:\/\/varlatchd:8686\/.well-known\/jwks.json$/m);
  const reconciled = dc(prod, ['run', '--rm', '--no-deps', '-T', 'convex-deploy']);
  assert.match(reconciled, /deployment authority derived/, 'CONVEX_ADMIN_KEY is gone; the job derives its key');
  assert.match(reconciled, /nothing to change/, 'Convex already trusts varlatchd at its fixed name');
  pass(`Coolify-shaped installation adopted in ${rounds} manual round(s): no secret variables, derived admin key, fixed trust (#28 resolved)`);
  dc(prod, ['stop']);

  // ---- 4a. Pre-upgrade archive → fresh host, same shape, candidate release.
  console.log('--- restore the pre-upgrade archive on a fresh prod-shaped host');
  prepare(sameShape, prodShapeCompose(join(root, 'infra/compose/docker-compose.coolify-tailscale.yml'), newImages, `${project}-same`),
    join(root, 'infra/compose/convex-supervisor.cjs'), join(root, 'infra/compose/postgres-init'));
  const candidateCli = join(root, 'apps/cli/dist/varlatch.cjs');
  const restoreSame = cli(candidateCli, sameShape, ['admin', 'backup', 'restore', '--in', archive, ...keyArgs(sameShape)]);
  assert(restoreSame.ok, `restore onto the prod shape failed:\n${restoreSame.out}`);
  const restoredUrl = serviceUrl(sameShape, 'tailscale', 8686);
  await ready(restoredUrl);
  const restored = new VarlatchClient({ server: restoredUrl, token });
  assert.equal((await restored.discloseSecrets('prod', 'app', 'production', { items: ['SECRET'] })).items[0].value, 'prod-shape-secret');
  // The archive's Application Plane is not restored (ADR-0036 D3): it is
  // rebuilt with the candidate's functions and this host's trust settings.
  assert.match(restoreSame.out, /Application Plane reconciled with this release/, restoreSame.out);
  assert.match(restoreSame.out, /reconcile: deployed functions/, 'the archive\'s functions are replaced');
  assert.equal(convexEnv(sameShape, 'VARLATCH_JWKS_URL'), LEGACY_JWKS, 'a host configured with the legacy URL keeps it');
  assert.match(dc(sameShape, ['run', '--rm', '--no-deps', '-T', 'convex-deploy']), /nothing to change/);
  pass('pre-upgrade archive restores on a fresh prod-shaped host, functions reconciled with the candidate');

  // ---- 4b. Same archive → canonical Compose, which has no sidecar. Its
  // Convex trust configuration names http://tailscale:8686 (ADR-0035 Q10),
  // but restore no longer carries it over: the Application Plane is rebuilt
  // for this host (ADR-0036 D3).
  console.log('--- restore the pre-upgrade archive on a fresh canonical-Compose host (Q10)');
  prepare(canonical, canonicalCompose(newImages, `${project}-canonical`), join(root, 'infra/compose/convex-supervisor.cjs'),
    join(root, 'infra/compose/postgres-init'), { VARLATCH_JWKS_URL: 'http://varlatchd:8686/.well-known/jwks.json' });
  const restoreCanonical = cli(candidateCli, canonical, ['admin', 'backup', 'restore', '--in', archive, ...keyArgs(canonical)]);
  assert(restoreCanonical.ok, `legacy archive onto canonical Compose:\n${restoreCanonical.out}`);
  const canonicalUrl = serviceUrl(canonical, 'varlatchd', 8686);
  await ready(canonicalUrl);
  assert.equal((await new VarlatchClient({ server: canonicalUrl, token }).discloseSecrets('prod', 'app', 'production', { items: ['SECRET'] })).items[0].value, 'prod-shape-secret');
  // The archive's Convex state is not restored (ADR-0036 D3): the rebuilt
  // Application Plane trusts this host's configured URL.
  assert.equal(convexEnv(canonical, 'VARLATCH_JWKS_URL'), 'http://varlatchd:8686/.well-known/jwks.json', 'trust configuration self-heals to this topology');
  assert.match(dc(canonical, ['run', '--rm', '--no-deps', '-T', 'convex-deploy']), /nothing to change/);
  pass('pre-upgrade Tailscale-topology archive restores on a fresh canonical-Compose host (Q10), trust configuration converged');

  // ---- 5. Fresh Coolify-shaped installation with every secret as a file (#28).
  console.log('--- fresh Coolify-shaped installation, secrets as per-service files (#28)');
  const fileSecrets = {
    'postgres-superuser-password': randomBytes(12).toString('hex'), 'varlatch-migrate-password': randomBytes(12).toString('hex'),
    'varlatch-runtime-password': randomBytes(12).toString('hex'), 'convex-db-password': randomBytes(12).toString('hex'),
    'convex-instance-secret': randomBytes(32).toString('hex'), 'tailscale-authkey': 'tskey-ci-stub',
  };
  prepare(fileBased, prodShapeCompose(join(root, 'infra/compose/docker-compose.coolify-tailscale.yml'), newImages, `${project}-files`),
    join(root, 'infra/compose/convex-supervisor.cjs'), join(root, 'infra/compose/postgres-init'));
  for (const [name, value] of Object.entries(fileSecrets)) writeFileSync(join(fileBased, 'secrets', name), value); // container users read them
  const hostPath = n => join(fileBased, 'secrets', n);
  // Coolify's env settings hold only non-secret values and file paths now.
  writeFileSync(join(fileBased, '.env'), Object.entries({
    VARLATCH_TAILNET_NAME: 'ci.ts.net', VARLATCH_PUBLIC_URL: 'https://varlatch.prodshape.test',
    VARLATCH_JWKS_URL: 'http://varlatchd:8686/.well-known/jwks.json', VARLATCH_CONVEX_URL: 'http://convex-backend:3210',
    CONVEX_CLOUD_ORIGIN: 'https://convex.prodshape.test', CONVEX_SITE_ORIGIN: 'https://convex.prodshape.test',
    VARLATCH_KEK_HOST_PATH: './secrets/root', VARLATCHD_PORT: '0', VARLATCH_WEB_PORT: '0', CONVEX_PORT: '0',
    POSTGRES_SUPERUSER_PASSWORD_HOST_PATH: hostPath('postgres-superuser-password'),
    VARLATCH_MIGRATE_PASSWORD_HOST_PATH: hostPath('varlatch-migrate-password'),
    VARLATCH_RUNTIME_PASSWORD_HOST_PATH: hostPath('varlatch-runtime-password'),
    CONVEX_DB_PASSWORD_HOST_PATH: hostPath('convex-db-password'),
    CONVEX_INSTANCE_SECRET_HOST_PATH: hostPath('convex-instance-secret'),
    TS_AUTHKEY_HOST_PATH: hostPath('tailscale-authkey'),
  }).map(([k, v]) => `${k}=${v}`).join('\n') + '\n');
  const fileUrl = await coolifyDeploy(fileBased);
  const fileToken = dc(fileBased, ['exec', '-T', 'varlatchd', 'node', 'dist/cli.js', 'admin', 'bootstrap', '--cli-credential']).match(/vlt_cli_\S+/)?.[0];
  assert(fileToken, 'bootstrap on the file-based installation');
  const fileApi = new VarlatchClient({ server: fileUrl, token: fileToken });
  await fileApi.createOrganization({ slug: 'files', name: 'Files' });
  await fileApi.createProject('files', { slug: 'app', name: 'App', contractAuthority: 'managed' });
  await fileApi.createEnvironment('files', 'app', { name: 'production', tier: 'production' });
  const fileRevision = await fileApi.pushContractRevision('files', 'app', { contract: { schemaVersion: 1, items: [{ name: 'SECRET', type: 'string', sensitive: true, required: { kind: 'always' } }] } });
  await fileApi.activateContractRevision('files', 'app', fileRevision.id);
  await fileApi.setValue('files', 'app', 'production', 'SECRET', { value: 'file-based-secret' });
  assert.equal((await fileApi.discloseSecrets('files', 'app', 'production', { items: ['SECRET'] })).items[0].value, 'file-based-secret');
  pass('file-based installation serves: no secret in any environment variable');
  const reconcileLog = dc(fileBased, ['run', '--rm', '--no-deps', '-T', 'convex-deploy']);
  assert.match(reconcileLog, /deployment authority derived/, 'the deploy job derives its key from the instance-secret file');
  assert.match(reconcileLog, /nothing to change/);
  pass('deploy job derives the admin key from the instance-secret file');
  const mounted = service => dc(fileBased, ['exec', '-T', service, 'ls', '/run/secrets']).split(/\s+/).filter(Boolean).sort();
  assert.deepEqual(mounted('varlatchd'), ['varlatch-kek', 'varlatch-runtime-password']);
  assert.deepEqual(mounted('convex-backend'), ['convex-db-password', 'convex-instance-secret']);
  const varlatchdConfig = sh('docker', ['inspect', dc(fileBased, ['ps', '-q', 'varlatchd'])]);
  const foreign = Object.entries(fileSecrets).filter(([name, value]) => name !== 'varlatch-runtime-password' && varlatchdConfig.includes(value)).map(([name]) => name);
  assert.deepEqual(foreign, [], 'runtime varlatchd must hold no other service\'s secret');
  pass('runtime varlatchd holds only its own secrets (#28), even with Coolify\'s every-variable environment');
  const fileDoctor = cli(join(root, 'apps/cli/dist/varlatch.cjs'), fileBased, ['doctor', '--json', '--wait', '30']);
  assert(fileDoctor.ok, `doctor on the file-based installation:\n${fileDoctor.out}`);
  pass('doctor: no mandatory failure on the file-based installation');

  console.log(`PASS: prod-shaped v0.9.0 → ${release.version} transition (${results.length} checks)`);
} catch (error) {
  for (const where of [prod, sameShape, canonical, fileBased]) {
    try { console.error(dc(where, ['ps', '-a', '--format', '{{.Service}} {{.State}} {{.Health}} {{.Status}}'])); } catch {}
    try {
      for (const id of dc(where, ['ps', '-aq']).split('\n').filter(Boolean)) {
        console.error(sh('docker', ['inspect', id, '--format', '{{.Name}} restarts={{.RestartCount}} started={{.State.StartedAt}} exit={{.State.ExitCode}}']));
      }
    } catch {}
    try { console.error(dc(where, ['logs', '--tail', '25', 'varlatchd', 'varlatch-migrate', 'convex-deploy', 'convex-backend'])); } catch {}
    // The Convex supervisor is Node; its own output (e.g. a crash trace) lacks
    // the backend's timestamped log prefix — print all of it, not a tail.
    try {
      const supervisor = dc(where, ['logs', '--no-log-prefix', 'convex-backend']).split('\n').filter(l => l && !/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(l));
      if (supervisor.length) console.error(`[convex supervisor output]\n${supervisor.join('\n')}`);
    } catch {}
  }
  throw error;
} finally {
  for (const where of [prod, sameShape, canonical, fileBased]) { try { dc(where, ['down', '-v', '--remove-orphans']); } catch {} }
  rmSync(dir, { recursive: true, force: true });
}
