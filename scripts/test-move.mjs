#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Moving an installation to another public URL (issue #103), end to end:
// the rehearsal of docs/operations/move-installation.md on a real stack.
//
// An installation set up with the public ingress at vault.varlatch.test
// (certificates from Pebble, Let's Encrypt's test CA, as in
// test-ingress-public.mjs) gets an Installation Admin and a member with
// passkeys, then `varlatch move` takes it to vault2.varlatch.test. A
// browser with a virtual authenticator reaches both names through a CONNECT
// proxy, so the origins are the real https://<host> ones WebAuthn checks.
//
// Checks: the move archives and verifies first; the new address gets its
// certificate and Convex the new issuer (setup's health check passes,
// Mirror catch-up included); the old passkeys are gone and the old address
// is not served; one re-enrollment link per person; the admin and the member
// enroll new passkeys on their existing identities; a CLI credential issued
// before the move works at the new address; nothing of the move is left open.
// Prerequisites: the candidate images (varlatch-backup-*-test:local), the
// CLI bundle (apps/cli/dist), and Playwright's Chromium.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { createRequire } from 'node:module';
import net, { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import tls from 'node:tls';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseDocument } from 'yaml';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const cli = join(root, 'apps/cli/dist/varlatch.cjs');
const playwright = await import(pathToFileURL(createRequire(join(root, 'services/varlatchd/package.json')).resolve('playwright')).href);
const chromium = playwright.chromium ?? playwright.default.chromium; // CommonJS module
const OLD = 'vault.varlatch.test';
const NEW = 'vault2.varlatch.test';
const PEBBLE = 'ghcr.io/letsencrypt/pebble:2.8.0';
const images = { varlatchd: 'varlatch-backup-test:local', 'varlatch-migrate': 'varlatch-backup-test:local', 'varlatch-web': 'varlatch-backup-web-test:local', 'convex-deploy': 'varlatch-backup-convex-deploy-test:local' };
const dir = mkdtempSync(join(tmpdir(), 'varlatch-move-'));
const dc = args => execFileSync('docker', ['compose', ...args], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const varlatchd = args => dc(['exec', '-T', 'varlatchd', 'node', 'dist/cli.js', ...args]);
const results = [];
const pass = (name, detail = '') => { results.push(name); console.log(`PASS  ${name}${detail ? ` — ${detail}` : ''}`); };
const freePort = () => new Promise(res => { const s = createServer(); s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => res(port)); }); });
const caddyPort = () => Number(dc(['port', 'caddy', '443']).split(':').pop());

/** Runs a CLI command; resolves `lines` as output arrives, and `exit` with code and output. */
function run(args) {
  let out = '';
  const listeners = [];
  const child = spawn('node', [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  const onData = d => { out += d; for (const l of listeners) l(out); };
  child.stdout.on('data', onData); child.stderr.on('data', onData);
  const exit = new Promise(r => child.on('close', code => r({ code, out })));
  /** Resolves once the output matches `re` (all matches), or null at exit. */
  const when = re => new Promise(res => {
    const check = text => { const m = [...text.matchAll(re)]; if (m.length) res(m); };
    listeners.push(check); check(out);
    exit.then(() => res(null));
  });
  return { when, exit };
}

/** A CONNECT proxy that sends both names to Caddy's published HTTPS port. */
function startProxy() {
  const server = http.createServer((_req, res) => { res.writeHead(405); res.end(); });
  server.on('connect', (req, socket, head) => {
    const [host] = req.url.split(':');
    if (![OLD, NEW].includes(host)) { socket.end('HTTP/1.1 403 Forbidden\r\n\r\n'); return; }
    const upstream = net.connect(caddyPort(), '127.0.0.1', () => {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      upstream.write(head); upstream.pipe(socket); socket.pipe(upstream);
    });
    upstream.on('error', () => socket.destroy()); socket.on('error', () => upstream.destroy());
  });
  return new Promise(res => server.listen(0, '127.0.0.1', () => res(server)));
}

/** The base64 SHA-256 of the certificate's public key Caddy serves for `host` (Chrome's SPKI allowlist). */
function spkiHash(host) {
  return new Promise((res, rej) => {
    const socket = tls.connect({ host: '127.0.0.1', port: caddyPort(), servername: host, rejectUnauthorized: false }, () => {
      const der = socket.getPeerCertificate(true).raw;
      socket.end();
      res(createHash('sha256').update(new X509Certificate(der).publicKey.export({ type: 'spki', format: 'der' })).digest('base64'));
    });
    socket.on('error', rej);
  });
}

/** Opens an enrollment link in a fresh browser with a virtual authenticator and enrolls a passkey. */
async function enroll(link, proxyPort, hosts) {
  const spki = await Promise.all(hosts.map(spkiHash));
  const browser = await chromium.launch({
    proxy: { server: `http://127.0.0.1:${proxyPort}` },
    args: [`--ignore-certificate-errors-spki-list=${spki.join(',')}`],
  });
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
    await page.goto(link);
    await page.click('#enroll');
    await page.waitForFunction(() => /API credential|failed/.test(document.getElementById('status').textContent), null, { timeout: 30000 });
    assert.match(await page.textContent('#status'), /API credential/, `passkey enrollment at ${new URL(link).host}`);
  } finally { await browser.close(); }
}

/** One HTTPS request to Caddy as `host`, verified against Pebble's root. */
function request(host, path, { ca, token } = {}) {
  return new Promise((res, rej) => {
    const req = https.request({ host: '127.0.0.1', port: caddyPort(), servername: host, path, ca, headers: { Host: host, ...(token ? { Authorization: `Bearer ${token}` } : {}) }, timeout: 15000 }, r => {
      let body = ''; r.on('data', c => { body += c; }); r.on('end', () => res({ status: r.statusCode, body }));
    });
    req.on('error', rej); req.end();
  });
}
async function api(method, path, token, body) {
  const ca = execFileSync('docker', ['compose', 'exec', '-T', 'caddy', 'wget', '-q', '-O', '-', 'https://pebble:15000/roots/0'], { cwd: dir, encoding: 'utf8' });
  return new Promise((res, rej) => {
    const data = body ? JSON.stringify(body) : undefined;
    const req = https.request({ host: '127.0.0.1', port: caddyPort(), servername: OLD, path, method, ca, headers: { Host: OLD, Authorization: `Bearer ${token}`, ...(data ? { 'content-type': 'application/json' } : {}) }, timeout: 15000 }, r => {
      let text = ''; r.on('data', c => { text += c; }); r.on('end', () => res({ status: r.statusCode, body: text ? JSON.parse(text) : null }));
    });
    req.on('error', rej); if (data) req.write(data); req.end();
  });
}

let proxy;
try {
  // ---- The shipped Compose files, candidate images, Pebble for both names.
  const doc = parseDocument(readFileSync(join(root, 'infra/compose/docker-compose.yml'), 'utf8'));
  doc.set('name', `vlt-move-${randomBytes(3).toString('hex')}`);
  for (const [s, i] of Object.entries(images)) { doc.deleteIn(['services', s, 'build']); doc.setIn(['services', s, 'image'], i); doc.setIn(['services', s, 'pull_policy'], 'never'); }
  writeFileSync(join(dir, 'docker-compose.yml'), doc.toString({ lineWidth: 0 }));
  for (const f of ['convex-supervisor.cjs', 'postgres-init', 'Caddyfile']) cpSync(join(root, 'infra/compose', f), join(dir, f), { recursive: true });
  const peek = execFileSync('docker', ['create', PEBBLE], { encoding: 'utf8' }).trim();
  try {
    execFileSync('docker', ['cp', `${peek}:/test/certs/pebble.minica.pem`, join(dir, 'pebble-api-root.pem')]);
    execFileSync('docker', ['cp', `${peek}:/test/config/pebble-config.json`, join(dir, 'pebble-config.json')]);
  } finally { execFileSync('docker', ['rm', peek], { stdio: 'ignore' }); }
  const pebbleConfig = JSON.parse(readFileSync(join(dir, 'pebble-config.json'), 'utf8'));
  Object.assign(pebbleConfig.pebble, { httpPort: 80, tlsPort: 443 });
  writeFileSync(join(dir, 'pebble-config.json'), JSON.stringify(pebbleConfig));
  const caddy = parseDocument(readFileSync(join(root, 'infra/compose/docker-compose.caddy.yml'), 'utf8'));
  caddy.setIn(['services', 'caddy', 'ports'], caddy.createNode(['127.0.0.1:0:80', '127.0.0.1:0:443']));
  caddy.setIn(['services', 'caddy', 'environment', 'VARLATCH_ACME_CA'], 'https://pebble:14000/dir');
  caddy.setIn(['services', 'caddy', 'environment', 'SSL_CERT_FILE'], '/pebble-api-root.pem');
  caddy.getIn(['services', 'caddy', 'volumes']).add('./pebble-api-root.pem:/pebble-api-root.pem:ro');
  caddy.setIn(['services', 'caddy', 'networks'], caddy.createNode({ default: { aliases: [OLD, NEW] } }));
  caddy.getIn(['services', 'caddy', 'depends_on']).add('pebble');
  caddy.setIn(['services', 'pebble'], caddy.createNode({
    image: PEBBLE, command: ['-config', '/pebble-config.json'],
    environment: { PEBBLE_VA_NOSLEEP: '1', PEBBLE_WFE_NONCEREJECT: '0' },
    volumes: ['./pebble-config.json:/pebble-config.json:ro'],
  }));
  writeFileSync(join(dir, 'docker-compose.caddy.yml'), caddy.toString({ lineWidth: 0 }));
  proxy = await startProxy();
  const proxyPort = proxy.address().port;

  // ---- An installation at the old address: an Installation Admin and a member with passkeys.
  const passphrase = join(dir, 'escrow-passphrase');
  writeFileSync(passphrase, 'correct horse battery staple\n', { mode: 0o600 });
  const setup = run(['setup', '--dir', dir, '--ingress', 'public', '--public-url', `https://${OLD}`, '--port', String(await freePort()),
    '--enroll-timeout', '600', '--escrow', 'passphrase', '--escrow-passphrase-file', passphrase, '--attest']);
  const bootLink = (await setup.when(/https:\/\/\S+\/enroll#vlt_setup_\S+/g))?.[0]?.[0];
  if (!bootLink) assert.fail(`setup printed no enrollment link:\n${(await setup.exit).out}`);
  await enroll(bootLink, proxyPort, [OLD]);
  const setupDone = await setup.exit;
  assert.equal(setupDone.code, 0, setupDone.out);
  const adminId = JSON.parse(varlatchd(['admin', 'bootstrap-status'])).admins[0].id;
  const adminToken = varlatchd(['admin', 'recover', '--identity', adminId, '--cli-credential']).match(/vlt_cli_\S+/)?.[0];
  assert(adminToken, 'a CLI credential for the admin');
  assert.equal((await api('POST', '/v1/organizations', adminToken, { name: 'Acme', slug: 'acme' })).status, 201);
  const invite = await api('POST', '/v1/organizations/acme/invitations', adminToken, { name: 'Sam', role: 'member' });
  assert.equal(invite.status, 201);
  await enroll(`https://${OLD}/enroll#${invite.body.token}`, proxyPort, [OLD]);
  const before = JSON.parse(varlatchd(['admin', 'move-facts']));
  assert.deepEqual([before.publicUrl, before.people, before.passkeys], [`https://${OLD}`, 2, 2]);
  pass('installation at the old address: an Installation Admin and a member, each with a passkey', OLD);

  // ---- The move, as the procedure page describes it.
  const move = run(['move', '--dir', dir, '--public-url', `https://${NEW}`, '--ingress', 'public', '--yes', '--enroll-timeout', '600',
    '--bek-file', join(dir, 'secrets/backup-key'), '--kek-file', join(dir, 'secrets/varlatch-kek')]);
  const links = await move.when(/https:\/\/vault2\.varlatch\.test\/enroll#vlt_reenroll_\S+/g);
  if (!links) assert.fail(`move printed no re-enrollment links:\n${(await move.exit).out}`);
  await move.when(/Waiting for an Installation Admin to enroll/g);
  assert.equal(links.length, 2, 'one link per person');
  const during = JSON.parse(varlatchd(['admin', 'move-facts']));
  assert.deepEqual([during.publicUrl, during.people, during.passkeys, during.sessions], [`https://${NEW}`, 2, 0, 0]);
  pass('the old passkeys are gone and every session ended before anyone re-enrolls');
  await enroll(links[0][0], proxyPort, [NEW]); // Installation Admins first
  const moved = await move.exit;
  assert.equal(moved.code, 0, moved.out);
  const out = moved.out;
  assert.match(out, /archive .+ verified/);
  assert.match(out, new RegExp(`HTTPS certificate for ${NEW.replace(/\./g, '\\.')}`));
  assert.match(out, /2 passkey\(s\) for https:\/\/vault\.varlatch\.test removed/);
  assert.match(out, /Moved: https:\/\/vault\.varlatch\.test → https:\/\/vault2\.varlatch\.test/);
  assert(!existsSync(join(dir, 'varlatch-move.json')), 'no move left open');
  assert.equal(JSON.parse(readFileSync(join(dir, 'varlatch-install.json'), 'utf8')).publicUrl, `https://${NEW}`);
  pass('varlatch move: archive verified, new certificate, Convex trusts the new issuer (health checks pass), admin re-enrolled', NEW);

  // ---- After the move.
  await enroll(links[1][0], proxyPort, [NEW]);
  const after = JSON.parse(varlatchd(['admin', 'move-facts']));
  assert.deepEqual([after.people, after.passkeys], [2, 2]);
  pass('the member re-enrolled on the same identity with their link');

  const ca = dc(['exec', '-T', 'caddy', 'wget', '-q', '-O', '-', 'https://pebble:15000/roots/0']);
  const meta = await request(NEW, '/v1/meta', { ca, token: adminToken });
  assert.equal(meta.status, 200, meta.body);
  pass('a CLI credential issued before the move works at the new address');

  const old = await request(OLD, '/readyz', { ca }).then(r => r.status, e => e.code ?? e.message);
  assert.notEqual(old, 200, 'the old address is no longer served');
  pass('the old address is no longer served', String(old));

  console.log(`PASS: move to another public URL (${results.length} checks)`);
} finally {
  proxy?.close();
  try { dc(['--profile', 'deploy', 'down', '-v', '--remove-orphans']); } catch {}
  rmSync(dir, { recursive: true, force: true });
}
