#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Restore compatibility across the removal of the environment-name mapping
// (schema migration 21). A published 0.10.0 installation (migration 20) holds
// mapping entries, a Contract that names an environment by ID, a Secret, and
// mapping audit events. It is backed up with its own 0.10.0 CLI (the one its
// image ships), then restored on a fresh candidate installation, which
// migrates it forward. Contract revisions, audit history, and values must be
// unchanged; the mapping table and its endpoints must be gone.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, cpSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { VarlatchClient } from '../packages/sdk/dist/index.js';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const fixtures = join(root, 'scripts/fixtures/v0.10.0');
const oldRelease = JSON.parse(readFileSync(join(fixtures, 'varlatch-release.json'), 'utf8'));
// CI runs the published digest; local testing may use an exact-tag rebuild.
const oldImage = process.env.VARLATCH_TEST_V0100_IMAGE ?? oldRelease.images.varlatchd.digest;
const release = JSON.parse(readFileSync(join(root, 'packages/backup/src/release.json'), 'utf8'));
const dir = mkdtempSync(join(tmpdir(), 'varlatch-v0100-restore-'));
const source = join(dir, 'source'), target = join(dir, 'target');
const project = `vlt-v0100-${randomBytes(5).toString('hex')}`;
const rootKey = randomBytes(32).toString('hex'), bek = randomBytes(32).toString('hex');
// The candidate images CI builds; each tag can be overridden for local runs.
const imageNames = {
  'services/varlatchd/Dockerfile': process.env.VARLATCH_TEST_IMAGE_VARLATCHD ?? 'varlatch-backup-test:local',
  'apps/web/Dockerfile': process.env.VARLATCH_TEST_IMAGE_WEB ?? 'varlatch-backup-web-test:local',
  'infra/compose/convex-deploy.Dockerfile': process.env.VARLATCH_TEST_IMAGE_CONVEX_DEPLOY ?? 'varlatch-backup-convex-deploy-test:local',
};

function docker(where, args, input) {
  return execFileSync('docker', ['compose', '--project-directory', where, ...args], { input, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'] }).trim();
}
function base(where, service, port) { return `http://${docker(where, ['port', service, String(port)])}`; }
const sleep = ms => new Promise(r => setTimeout(r, ms));
const fresh = (url, init = {}) => fetch(url, { ...init, headers: { ...Object.fromEntries(new Headers(init.headers)), connection: 'close' } });
async function ready(url) { for (let n = 0; n < 120; n++) { try { if ((await fresh(url)).ok) return; } catch {} await sleep(500); } throw Error(`Readiness timeout: ${url}`); }
function backup(cliPath, where, args) {
  const result = spawnSync('node', [cliPath, 'admin', 'backup', ...args, '--dir', where, '--bek-file', join(where, 'secrets/bek'), '--kek-file', join(where, 'secrets/root')], { encoding: 'utf8', timeout: 600_000, maxBuffer: 64 * 1024 * 1024 });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  return `${result.stdout}\n${result.stderr}`;
}
function sql(where, query) { return docker(where, ['exec', '-T', 'postgres', 'psql', '-U', 'postgres', '-d', 'varlatch', '-Atc', query]); }
// Identifiers and stored JSON only: never plaintext.
const snapshot = where => ({
  revisions: sql(where, "SELECT coalesce(json_agg(r ORDER BY r.id), '[]') FROM (SELECT id, project_id, content_hash, contract FROM contract_revisions) r"),
  mappingEvents: sql(where, "SELECT coalesce(json_agg(a ORDER BY a.event_order), '[]') FROM (SELECT id, event_type, decision, action, organization_id, resource, metadata, occurred_at, event_order FROM audit_events WHERE event_type LIKE 'contract.varlock_mapping_%') a"),
  activeRevisions: sql(where, "SELECT coalesce(json_agg(p ORDER BY p.id), '[]') FROM (SELECT id, active_contract_revision_id FROM projects) p"),
});

for (const where of [source, target]) {
  mkdirSync(join(where, 'secrets'), { recursive: true });
  writeFileSync(join(where, 'secrets/root'), rootKey); writeFileSync(join(where, 'secrets/bek'), bek);
  cpSync(join(root, 'infra/compose/postgres-init'), join(where, 'postgres-init'), { recursive: true });
  cpSync(join(root, 'infra/compose/convex-supervisor.cjs'), join(where, 'convex-supervisor.cjs'));
  writeFileSync(join(where, '.env'), `POSTGRES_SUPERUSER_PASSWORD=test-superuser\nVARLATCH_MIGRATE_PASSWORD=test-migrate\nVARLATCH_RUNTIME_PASSWORD=test-runtime\nCONVEX_DB_PASSWORD=test-convex\nCONVEX_INSTANCE_SECRET=${randomBytes(32).toString('hex')}\nVARLATCHD_PORT=0\nVARLATCH_WEB_PORT=0\nCONVEX_PORT=0\nCONVEX_SITE_PORT=0\nVARLATCH_KEK_HOST_PATH=./secrets/root\nVARLATCH_PUBLIC_URL=http://varlatchd:8686\n`);
}
// Source: the published 0.10.0 release compose, daemon image pinned.
writeFileSync(join(source, 'docker-compose.yml'), readFileSync(join(fixtures, 'docker-compose.release.yml'), 'utf8')
  .replace('name: varlatch', `name: ${project}-0`)
  .replace(/image: ghcr\.io\/varlatch\/varlatchd[^\n]+/g, `image: ${oldImage}`));
cpSync(join(fixtures, 'varlatch-release.json'), join(source, 'varlatch-release.json'));
// Target: the candidate, built from this checkout.
writeFileSync(join(target, 'docker-compose.yml'), readFileSync(join(root, 'infra/compose/docker-compose.yml'), 'utf8')
  .replace('name: varlatch', `name: ${project}-1`)
  .replace(/build:\n\s+context: \.\.\/\.\.\n\s+dockerfile: (\S+)\n/g, (_, file) => `image: ${imageNames[file]}\n`));

try {
  console.log(`Starting the published 0.10.0 source (${oldImage})`);
  docker(source, ['up', '-d', 'postgres', 'varlatch-migrate', 'varlatchd', 'convex-backend']);
  const sourceUrl = base(source, 'varlatchd', 8686), convexUrl = base(source, 'convex-backend', 3210);
  await ready(`${sourceUrl}/readyz`); await ready(`${convexUrl}/version`);
  assert.equal(sql(source, 'SELECT max(id) FROM varlatch_migrations'), String(oldRelease.migrationVersion));
  const adminKey = docker(source, ['exec', '-T', 'convex-backend', './generate_admin_key.sh']);
  const env = { ...process.env, CONVEX_SELF_HOSTED_URL: convexUrl, CONVEX_SELF_HOSTED_ADMIN_KEY: adminKey };
  for (const [name, value] of [['VARLATCH_ISSUER', 'http://varlatchd:8686'], ['VARLATCH_JWKS_URL', 'http://varlatchd:8686/.well-known/jwks.json']]) execFileSync('pnpm', ['exec', 'convex', 'env', 'set', name, value], { cwd: join(root, 'convex'), env, stdio: 'pipe' });
  execFileSync('pnpm', ['exec', 'convex', 'deploy', '-y'], { cwd: join(root, 'convex'), env, stdio: 'pipe' });
  const token = docker(source, ['exec', '-T', 'varlatchd', 'node', 'dist/cli.js', 'admin', 'bootstrap', '--cli-credential']).match(/vlt_cli_\S+/)?.[0];
  assert(token);
  const api = new VarlatchClient({ server: sourceUrl, token, fetch: fresh });
  await api.createOrganization({ slug: 'mapping', name: 'Mapping' });
  await api.createProject('mapping', { slug: 'app', name: 'App', contractAuthority: 'git' });
  await api.createEnvironment('mapping', 'app', { name: 'development', tier: 'development' });
  const production = await api.createEnvironment('mapping', 'app', { name: 'production', tier: 'production' });
  const contract = { schemaVersion: 1, items: [{ name: 'SECRET', type: 'string', sensitive: true, required: { kind: 'selector', selector: { kind: 'environments', environmentIds: [production.id] } } }] };
  const revision = await api.pushContractRevision('mapping', 'app', { contract });
  await api.activateContractRevision('mapping', 'app', revision.id);
  await api.setValue('mapping', 'app', 'production', 'SECRET', { value: 'mapping-removal-secret' });
  // Mapping entries through the 0.10.0 API (this checkout's SDK no longer has them).
  const mapping = async (method, name, body) => {
    const res = await fresh(`${sourceUrl}/v1/organizations/mapping/projects/app/varlock-mapping/${name}`, { method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}) });
    assert(res.ok, `${method} mapping ${name}: ${res.status}`);
  };
  await mapping('PUT', 'prod', { environmentId: production.id });
  await mapping('PUT', 'old', { environmentId: production.id });
  await mapping('DELETE', 'old');
  assert.equal(sql(source, 'SELECT count(*) FROM varlock_env_mappings'), '1');
  const before = snapshot(source);
  assert.equal(JSON.parse(before.mappingEvents).length, 3, 'two set events and one removal');
  console.log('PASS  0.10.0 source holds a mapping entry, a Contract, a Secret, and mapping audit events');

  // Back up with the CLI the 0.10.0 image ships.
  const oldCli = join(dir, 'varlatch-0.10.0.cjs');
  writeFileSync(oldCli, execFileSync('docker', ['run', '--rm', '--entrypoint', 'cat', oldImage, '/opt/varlatch/varlatch.cjs'], { maxBuffer: 64 * 1024 * 1024 }));
  const archive = join(dir, 'v0100.vltbak');
  backup(oldCli, source, ['create', '--out', archive]);
  docker(source, ['stop']);
  const newCli = join(root, 'apps/cli/dist/varlatch.cjs');
  backup(newCli, source, ['verify', '--in', archive]);
  console.log('PASS  archive created by the 0.10.0 CLI and verified offline');

  console.log(`Restoring into a fresh candidate installation (migration ${release.migrationVersion})`);
  const restoreOut = backup(newCli, target, ['restore', '--in', archive]);
  assert.match(restoreOut, /Application Plane reconciled with this release/);
  const targetUrl = base(target, 'varlatchd', 8686); await ready(`${targetUrl}/readyz`);
  assert.equal(sql(target, 'SELECT max(id) FROM varlatch_migrations'), String(release.migrationVersion));
  assert.equal(sql(target, "SELECT coalesce(to_regclass('varlock_env_mappings')::text, 'gone')"), 'gone');
  const after = snapshot(target);
  assert.deepEqual(JSON.parse(after.revisions), JSON.parse(before.revisions), 'contract revisions unchanged');
  assert.deepEqual(JSON.parse(after.activeRevisions), JSON.parse(before.activeRevisions), 'active revisions unchanged');
  assert.deepEqual(JSON.parse(after.mappingEvents), JSON.parse(before.mappingEvents), 'mapping audit history unchanged');
  const restored = new VarlatchClient({ server: targetUrl, token, fetch: fresh });
  assert.equal((await restored.discloseSecrets('mapping', 'app', 'production', { items: ['SECRET'] })).items[0].value, 'mapping-removal-secret');
  const gone = await fresh(`${targetUrl}/v1/organizations/mapping/projects/app/varlock-mapping`, { headers: { authorization: `Bearer ${token}` } });
  assert.equal(gone.status, 404, 'the mapping endpoints are gone');
  // The environment the mapping named is now deletable once no Contract references it.
  const optional = await restored.pushContractRevision('mapping', 'app', { contract: { schemaVersion: 1, items: [{ name: 'SECRET', type: 'string', sensitive: true, required: { kind: 'never' } }] } });
  await restored.activateContractRevision('mapping', 'app', optional.id);
  await restored.deleteEnvironment('mapping', 'app', 'production');
  console.log('PASS: a 0.10.0 archive with mapping entries restores into the candidate and migrates forward; revisions, audit history, and values unchanged; mapping gone');
} catch (error) {
  for (const where of [source, target]) { try { console.error(docker(where, ['logs', '--tail', '40', 'varlatchd', 'varlatch-migrate'])); } catch {} }
  throw error;
} finally {
  for (const where of [source, target]) { try { docker(where, ['down', '-v', '--remove-orphans']); } catch {} }
  rmSync(dir, { recursive: true, force: true });
}
