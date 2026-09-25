#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Public ingress (ADR-0035 D6) end to end: `varlatch setup --ingress public`
// with the bundled Caddy obtaining a real ACME certificate — from Pebble,
// Let's Encrypt's test CA, instead of Let's Encrypt. The Compose files and
// Caddyfile are the shipped ones; the fixture only adds the Pebble service,
// points VARLATCH_ACME_CA at it, lets Caddy trust Pebble's API, publishes
// random host ports, and gives Caddy the public host name on the Compose
// network so Pebble validates it exactly as Let's Encrypt would over the
// internet (HTTP-01 on :80 / TLS-ALPN-01 on :443).
//
// Checks: setup waits for and reports the certificate; it validates for the
// host against Pebble's root; /readyz and /v1 over HTTPS; HTTP redirects to
// HTTPS; the /convex WebSocket upgrade passes Caddy; the enrollment link
// carries the public origin; nothing else of the installation is published.
// Prerequisites: the candidate images (varlatch-backup-*-test:local).
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { createServer } from 'node:net';
import https from 'node:https';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseDocument } from 'yaml';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const cli = join(root, 'apps/cli/dist/varlatch.cjs');
const host = 'vault.varlatch.test';
const PEBBLE = 'ghcr.io/letsencrypt/pebble:2.8.0';
const images = { varlatchd: 'varlatch-backup-test:local', 'varlatch-migrate': 'varlatch-backup-test:local', 'varlatch-web': 'varlatch-backup-web-test:local', 'convex-deploy': 'varlatch-backup-convex-deploy-test:local' };
const dir = mkdtempSync(join(tmpdir(), 'varlatch-ingress-public-'));
const dc = args => execFileSync('docker', ['compose', ...args], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const results = [];
const pass = (name, detail = '') => { results.push(name); console.log(`PASS  ${name}${detail ? ` — ${detail}` : ''}`); };
const freePort = () => new Promise(res => { const s = createServer(); s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => res(port)); }); });

/** One HTTPS request to Caddy's published port, as a browser would send it for `host`. */
function request(port, path, { ca, headers = {}, upgrade = false } = {}) {
  return new Promise((res, rej) => {
    const req = https.request({ host: '127.0.0.1', port, servername: host, path, ca, headers: { Host: host, ...headers }, timeout: 15000 }, r => {
      const cert = r.socket?.getPeerCertificate?.(); // before the socket is released
      let body = ''; r.on('data', c => { body += c; }); r.on('end', () => res({ status: r.statusCode, headers: r.headers, body, cert }));
    });
    if (upgrade) req.on('upgrade', (r, socket) => { socket.destroy(); res({ status: r.statusCode, headers: r.headers }); });
    req.on('error', rej); req.end();
  });
}

try {
  // ---- The shipped Compose files, candidate images.
  const doc = parseDocument(readFileSync(join(root, 'infra/compose/docker-compose.yml'), 'utf8'));
  doc.set('name', `vlt-ingress-${randomBytes(3).toString('hex')}`);
  for (const [s, i] of Object.entries(images)) { doc.deleteIn(['services', s, 'build']); doc.setIn(['services', s, 'image'], i); doc.setIn(['services', s, 'pull_policy'], 'never'); }
  writeFileSync(join(dir, 'docker-compose.yml'), doc.toString({ lineWidth: 0 }));
  for (const f of ['convex-supervisor.cjs', 'postgres-init', 'Caddyfile']) cpSync(join(root, 'infra/compose', f), join(dir, f), { recursive: true });

  // ---- Fixture: Pebble instead of Let's Encrypt.
  const peek = execFileSync('docker', ['create', PEBBLE], { encoding: 'utf8' }).trim();
  try {
    execFileSync('docker', ['cp', `${peek}:/test/certs/pebble.minica.pem`, join(dir, 'pebble-api-root.pem')]);
    execFileSync('docker', ['cp', `${peek}:/test/config/pebble-config.json`, join(dir, 'pebble-config.json')]);
  } finally { execFileSync('docker', ['rm', peek], { stdio: 'ignore' }); }
  const pebbleConfig = JSON.parse(readFileSync(join(dir, 'pebble-config.json'), 'utf8'));
  Object.assign(pebbleConfig.pebble, { httpPort: 80, tlsPort: 443 }); // validate like Let's Encrypt does
  writeFileSync(join(dir, 'pebble-config.json'), JSON.stringify(pebbleConfig));
  const caddy = parseDocument(readFileSync(join(root, 'infra/compose/docker-compose.caddy.yml'), 'utf8'));
  caddy.setIn(['services', 'caddy', 'ports'], caddy.createNode(['0:80', '0:443']));
  caddy.setIn(['services', 'caddy', 'environment', 'VARLATCH_ACME_CA'], 'https://pebble:14000/dir');
  caddy.setIn(['services', 'caddy', 'environment', 'SSL_CERT_FILE'], '/pebble-api-root.pem');
  caddy.getIn(['services', 'caddy', 'volumes']).add('./pebble-api-root.pem:/pebble-api-root.pem:ro');
  caddy.setIn(['services', 'caddy', 'networks'], caddy.createNode({ default: { aliases: [host] } }));
  caddy.getIn(['services', 'caddy', 'depends_on']).add('pebble');
  caddy.setIn(['services', 'pebble'], caddy.createNode({
    image: PEBBLE, command: ['-config', '/pebble-config.json'],
    environment: { PEBBLE_VA_NOSLEEP: '1', PEBBLE_WFE_NONCEREJECT: '0' },
    volumes: ['./pebble-config.json:/pebble-config.json:ro'],
  }));
  writeFileSync(join(dir, 'docker-compose.caddy.yml'), caddy.toString({ lineWidth: 0 }));

  // ---- Setup, as an operator would run it.
  const run = spawnSync('node', [cli, 'setup', '--dir', dir, '--ingress', 'public', '--public-url', `https://${host}`, '--port', String(await freePort()), '--no-wait'],
    { encoding: 'utf8', timeout: 900_000, maxBuffer: 64 * 1024 * 1024 });
  const out = `${run.stdout}\n${run.stderr}`;
  assert.equal(run.status, 3, out); // 3: waiting for the passkey enrollment
  assert.match(out, new RegExp(`HTTPS certificate for ${host.replace(/\./g, '\\.')}`));
  const link = out.match(/https:\/\/\S+\/enroll#\S+/)?.[0];
  assert(link?.startsWith(`https://${host}/enroll#`), `enrollment link on the public origin: ${link}`);
  const env = readFileSync(join(dir, '.env'), 'utf8');
  assert.match(env, /^COMPOSE_FILE=docker-compose\.yml:docker-compose\.caddy\.yml$/m);
  assert.match(env, new RegExp(`^VARLATCH_PUBLIC_HOST=${host.replace(/\./g, '\\.')}$`, 'm'));
  pass('setup --ingress public: certificate obtained, enrollment link on the public origin');

  // ---- The certificate chains to Pebble's root for the host.
  const root0 = execFileSync('docker', ['compose', 'exec', '-T', 'caddy', 'wget', '-q', '-O', '-', 'https://pebble:15000/roots/0'], { cwd: dir, encoding: 'utf8' });
  const port = Number(dc(['port', 'caddy', '443']).split(':').pop());
  const ready = await request(port, '/readyz', { ca: root0 });
  assert.equal(ready.status, 200);
  assert.equal(ready.cert?.subjectaltname, `DNS:${host}`);
  pass('HTTPS verifies against the CA for the public host', ready.cert.issuer?.CN);

  const token = dc(['exec', '-T', 'varlatchd', 'node', 'dist/cli.js', 'admin', 'bootstrap', '--cli-credential']).match(/vlt_cli_\S+/)?.[0];
  const meta = await request(port, '/v1/meta', { ca: root0, headers: { Authorization: `Bearer ${token}` } });
  assert.equal(meta.status, 200, meta.body);
  pass('/v1 through Caddy', JSON.parse(meta.body).serverVersion);

  const plain = await new Promise((res, rej) => http.get({ host: '127.0.0.1', port: Number(dc(['port', 'caddy', '80']).split(':').pop()), path: '/', headers: { Host: host } }, r => res(r)).on('error', rej));
  assert.equal(plain.statusCode, 308);
  assert.equal(plain.headers.location, `https://${host}/`);
  pass('HTTP redirects to HTTPS');

  const ws = await request(port, '/convex/api/1.45.0/sync', {
    ca: root0, upgrade: true,
    headers: { Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': randomBytes(16).toString('base64') },
  });
  assert.equal(ws.status, 101);
  pass('/convex WebSocket upgrade through Caddy');

  // Only Caddy is reachable from outside; the dashboard stays on loopback.
  const published = dc(['ps', '--format', '{{.Service}} {{.Ports}}']).split('\n').filter(l => /0\.0\.0\.0|\[::\]/.test(l)).map(l => l.split(' ')[0]);
  assert.deepEqual([...new Set(published)], ['caddy'], `published on all interfaces: ${published.join(', ')}`);
  pass('only Caddy listens on all interfaces');

  console.log(`PASS: public ingress (${results.length} checks)`);
} finally {
  try { dc(['down', '-v', '--remove-orphans']); } catch {}
  rmSync(dir, { recursive: true, force: true });
}
