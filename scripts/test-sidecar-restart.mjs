#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Tailscale topology (ADR-0014): varlatchd shares the sidecar's network
// namespace. A sidecar restart replaces that namespace; without handling,
// varlatchd is left with only loopback — "healthy" to Docker, unreachable to
// everything. Both restart paths must recover on their own:
//   - a restart Compose performs (`docker compose restart tailscale`):
//     depends_on `restart: true` restarts varlatchd with it;
//   - a restart by the container runtime (`docker restart`, a crash): the
//     varlatchd watchdog exits and its restart policy rejoins the new namespace.
// A stand-in sidecar owns the namespace; no tailnet is needed.
// Prerequisites: the candidate images varlatch-backup-test:local and
// varlatch-backup-web-test:local.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { parseDocument } from 'yaml';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const dir = mkdtempSync(join(tmpdir(), 'varlatch-sidecar-restart-'));
const dc = args => execFileSync('docker', ['compose', ...args], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const sleep = ms => new Promise(r => setTimeout(r, ms));
const readyz = async () => { try { return (await fetch(`http://${dc(['port', 'varlatch-web', '80'])}/readyz`, { signal: AbortSignal.timeout(3000) })).status; } catch { return 0; } };
async function recovers(what, ms = 90_000) {
  const start = Date.now();
  while (Date.now() - start < ms) { if (await readyz() === 200) return Date.now() - start; await sleep(1000); }
  throw new Error(`${what}: varlatchd did not become reachable again within ${ms / 1000} s`);
}
const restarts = () => Number(execFileSync('docker', ['inspect', '-f', '{{.RestartCount}}', dc(['ps', '-q', 'varlatchd'])], { encoding: 'utf8' }).trim());

try {
  cpSync(join(root, 'infra/compose/postgres-init'), join(dir, 'postgres-init'), { recursive: true });
  cpSync(join(root, 'infra/compose/convex-supervisor.cjs'), join(dir, 'convex-supervisor.cjs'));
  mkdirSync(join(dir, 'secrets'));
  writeFileSync(join(dir, 'secrets/kek'), randomBytes(32).toString('hex'));
  const base = parseDocument(readFileSync(join(root, 'infra/compose/docker-compose.yml'), 'utf8'));
  base.set('name', `vlt-sidecar-${randomBytes(3).toString('hex')}`);
  for (const [s, i] of Object.entries({ varlatchd: 'varlatch-backup-test:local', 'varlatch-migrate': 'varlatch-backup-test:local', 'varlatch-web': 'varlatch-backup-web-test:local' })) {
    base.deleteIn(['services', s, 'build']); base.setIn(['services', s, 'image'], i); base.setIn(['services', s, 'pull_policy'], 'never');
  }
  writeFileSync(join(dir, 'docker-compose.yml'), base.toString({ lineWidth: 0 }));
  const ts = parseDocument(readFileSync(join(root, 'infra/compose/docker-compose.tailscale.yml'), 'utf8'));
  ts.setIn(['services', 'tailscale', 'image'], 'alpine:3.20');
  ts.setIn(['services', 'tailscale', 'entrypoint'], ts.createNode(['sleep', 'infinity']));
  ts.setIn(['services', 'tailscale', 'healthcheck'], ts.createNode({ disable: true }));
  writeFileSync(join(dir, 'docker-compose.tailscale.yml'), ts.toString({ lineWidth: 0 }));
  writeFileSync(join(dir, '.env'), [
    'COMPOSE_FILE=docker-compose.yml:docker-compose.tailscale.yml', 'POSTGRES_SUPERUSER_PASSWORD=a', 'VARLATCH_MIGRATE_PASSWORD=b',
    'VARLATCH_RUNTIME_PASSWORD=c', 'CONVEX_DB_PASSWORD=d', `CONVEX_INSTANCE_SECRET=${randomBytes(32).toString('hex')}`,
    'VARLATCHD_PORT=0', 'VARLATCH_WEB_PORT=0', 'CONVEX_PORT=0', 'VARLATCH_KEK_HOST_PATH=./secrets/kek',
    'VARLATCH_TAILNET_NAME=example.ts.net', 'VARLATCH_PUBLIC_URL=http://localhost:8787', '',
  ].join('\n'));
  dc(['up', '-d', 'postgres', 'varlatch-migrate', 'tailscale', 'varlatchd', 'varlatch-web']);
  await recovers('initial start', 180_000);
  console.log('PASS  varlatchd reachable through the sidecar namespace');

  dc(['restart', 'tailscale']);
  console.log(`PASS  recovers after a Compose restart of the sidecar — ${((await recovers('compose restart')) / 1000).toFixed(1)} s`);

  const before = restarts();
  execFileSync('docker', ['restart', dc(['ps', '-q', 'tailscale'])], { stdio: 'ignore' });
  const took = await recovers('runtime restart');
  assert(restarts() > before, 'the watchdog restarted varlatchd');
  assert.match(dc(['logs', 'varlatchd']), /lost its network/);
  console.log(`PASS  recovers after a runtime restart of the sidecar (watchdog) — ${(took / 1000).toFixed(1)} s`);
  console.log('PASS: sidecar restarts never leave varlatchd stranded');
} finally {
  try { dc(['down', '-v', '--remove-orphans']); } catch {}
  rmSync(dir, { recursive: true, force: true });
}
