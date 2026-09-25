// SPDX-License-Identifier: Apache-2.0
// Both supported deployment variants must enforce the same recovery gate.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
const env = {
  ...process.env,
  POSTGRES_SUPERUSER_PASSWORD: 'compose-test', VARLATCH_MIGRATE_PASSWORD: 'compose-test',
  VARLATCH_RUNTIME_PASSWORD: 'compose-test', CONVEX_DB_PASSWORD: 'compose-test',
  CONVEX_INSTANCE_SECRET: 'compose-test', TS_AUTHKEY: 'compose-test', VARLATCH_TAILNET_NAME: 'test.ts.net',
};
const variants = [['docker-compose.yml'], ['docker-compose.yml', 'docker-compose.tailscale.yml'], ['docker-compose.coolify-tailscale.yml']];
for (const files of variants) {
  const name = files.join(' + ');
  const args = files.flatMap(f => ['-f', fileURLToPath(new URL(`../infra/compose/${f}`, import.meta.url))]);
  const config = JSON.parse(execFileSync('docker', ['compose', ...args, '--profile', 'deploy', 'config', '--format', 'json'], { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
  if (config.services.tailscale) {
    // varlatchd shares the sidecar's network namespace: Docker refuses published
    // ports there, and web/Convex reach it only through the sidecar's alias.
    assert.equal(config.services.varlatchd.network_mode, 'service:tailscale', `${name}: varlatchd joins the sidecar`);
    assert(!config.services.varlatchd.ports?.length, `${name}: varlatchd must not publish ports`);
    assert(config.services.tailscale.networks?.default?.aliases?.includes('varlatchd'), `${name}: sidecar carries the varlatchd alias`);
  }
  for (const service of ['varlatchd', 'varlatch-migrate', 'convex-backend']) {
    assert(config.services[service].volumes.some(v => v.source === 'varlatch-state' && v.target === '/var/lib/varlatch'), `${name}: ${service} must share the durable gate`);
  }
  assert.deepEqual(config.services['convex-backend'].entrypoint, ['node', '/convex/varlatch-supervisor.cjs']);
  assert(config.services['convex-backend'].volumes.some(v => v.target === '/convex/varlatch-supervisor.cjs' && v.read_only));
  assert.equal(config.services.varlatchd.environment.VARLATCH_STATE_DIR, '/var/lib/varlatch');
  assert.equal(config.services['varlatch-backup'], undefined, 'No plaintext dump job');
  // #28: each secret file reaches only the services that need it.
  const expected = {
    postgres: ['convex-db-password', 'postgres-superuser-password', 'varlatch-migrate-password', 'varlatch-runtime-password'],
    'varlatch-migrate': ['varlatch-migrate-password'],
    varlatchd: ['varlatch-kek', 'varlatch-runtime-password'],
    'varlatch-web': [],
    'convex-backend': ['convex-db-password', 'convex-instance-secret'],
    'convex-deploy': ['convex-instance-secret'],
    ...(config.services.tailscale ? { tailscale: ['tailscale-authkey'] } : {}),
  };
  for (const [service, secrets] of Object.entries(expected)) {
    const actual = (config.services[service]?.secrets ?? []).map(s => s.source).sort();
    assert.deepEqual(actual, secrets, `${name}: ${service} secrets`);
  }
}
// The deploy image copies Convex's key tool from the backend image: both must
// be the same pinned backend (ADR-0035 D3).
const pin = (text, what) => text.match(/ghcr\.io\/get-convex\/convex-backend@sha256:[0-9a-f]{64}/)?.[0] ?? assert.fail(`${what}: no pinned convex-backend`);
const read = rel => readFileSync(fileURLToPath(new URL(`../infra/compose/${rel}`, import.meta.url)), 'utf8');
assert.equal(pin(read('convex-deploy.Dockerfile'), 'convex-deploy.Dockerfile'), pin(read('docker-compose.yml'), 'docker-compose.yml'), 'convex-deploy must take its key tool from the pinned convex-backend');
console.log('PASS: canonical, Tailscale overlay, and Coolify/Tailscale deployment contracts; convex-backend pins agree');
