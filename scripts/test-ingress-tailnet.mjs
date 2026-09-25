#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Tailnet ingress through `varlatch setup` (ADR-0035 D6, Q6 option B) on a
// REAL tailnet — manual, like scripts/spike-tsnet.mjs, which covers the
// mechanism's acceptance criteria. This one covers setup's own flow:
//   1. `setup --ingress tailnet` joins the node, discovers its actual name
//      and tailnet, and prints an enrollment link on https://<name>.<tailnet>.ts.net
//   2. a passkey enrolled at that link over the tailnet
//   3. the rerun (escrow + attestation) completes with a clean doctor
//   4. the managed .env and install config carry the discovered values
//
// Run on a tailnet member with MagicDNS and HTTPS certificates enabled:
//   SPIKE_TS_AUTHKEY_FILE=~/.config/varlatch-spike/ts-authkey node scripts/test-ingress-tailnet.mjs
// The node logs out and every container and volume is removed at the end.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createServer } from 'node:net';
import { homedir, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseDocument } from 'yaml';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const { chromium } = createRequire(join(root, 'apps/web/package.json'))('playwright');
const cli = join(root, 'apps/cli/dist/varlatch.cjs');
const keyFile = (process.env.SPIKE_TS_AUTHKEY_FILE ?? '').replace(/^~/, homedir());
if (!keyFile) { console.error('Set SPIKE_TS_AUTHKEY_FILE to a file holding a tailnet auth key.'); process.exit(1); }
const machine = process.env.SPIKE_HOSTNAME ?? 'varlatch-setup';
const images = { varlatchd: 'varlatch-backup-test:local', 'varlatch-migrate': 'varlatch-backup-test:local', 'varlatch-web': 'varlatch-backup-web-test:local', 'convex-deploy': 'varlatch-backup-convex-deploy-test:local' };
const dir = mkdtempSync(join(tmpdir(), 'varlatch-ingress-tailnet-'));
const results = [];
const pass = (name, detail = '') => { results.push(name); console.log(`PASS  ${name}${detail ? ` — ${detail}` : ''}`); };
const dc = args => execFileSync('docker', ['compose', ...args], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const freePort = () => new Promise(res => { const s = createServer(); s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => res(port)); }); });
const setup = args => { const r = spawnSync('node', [cli, 'setup', '--dir', dir, ...args], { encoding: 'utf8', timeout: 900_000, maxBuffer: 64 * 1024 * 1024 }); return { code: r.status, out: `${r.stdout}\n${r.stderr}` }; };

let browser;
try {
  const doc = parseDocument(readFileSync(join(root, 'infra/compose/docker-compose.yml'), 'utf8'));
  doc.set('name', `vlt-tailnet-${randomBytes(3).toString('hex')}`);
  for (const [s, i] of Object.entries(images)) { doc.deleteIn(['services', s, 'build']); doc.setIn(['services', s, 'image'], i); doc.setIn(['services', s, 'pull_policy'], 'never'); }
  writeFileSync(join(dir, 'docker-compose.yml'), doc.toString({ lineWidth: 0 }));
  for (const f of ['convex-supervisor.cjs', 'postgres-init', 'docker-compose.tailscale.yml', 'docker-compose.tailnet-https.yml', 'tailscale-serve.json']) {
    cpSync(join(root, 'infra/compose', f), join(dir, f), { recursive: true });
  }
  const port = String(await freePort());

  // ---- 1. First run: join, discover, link.
  const first = setup(['--ingress', 'tailnet', '--tailnet-machine', machine, '--tailscale-auth-key-file', keyFile, '--port', port, '--no-wait']);
  assert.equal(first.code, 3, first.out); // waiting for the passkey
  const joined = first.out.match(/tailnet node joined: (https:\/\/\S+)/)?.[1];
  assert(joined?.endsWith('.ts.net'), first.out);
  const link = first.out.match(/https:\/\/\S+\/enroll#\S+/)?.[0];
  assert(link?.startsWith(`${joined}/enroll#`), `enrollment link on the discovered origin: ${link}`);
  pass('setup joins the tailnet and issues the link on the discovered name', joined);

  const config = JSON.parse(readFileSync(join(dir, 'varlatch-install.json'), 'utf8'));
  const env = readFileSync(join(dir, '.env'), 'utf8');
  assert.equal(config.publicUrl, joined);
  assert.equal(config.ingress, 'tailnet');
  assert.match(env, new RegExp(`^VARLATCH_PUBLIC_URL=${joined.replace(/\./g, '\\.')}$`, 'm'));
  assert.match(env, new RegExp(`^VARLATCH_TAILNET_NAME=${config.tailnetName.replace(/\./g, '\\.')}$`, 'm'));
  assert.doesNotMatch(env, /tskey-/);
  pass('install config and .env carry the discovered URL and tailnet, never the auth key');

  // ---- 2. Enroll a passkey at the link, over the tailnet.
  browser = await chromium.launch();
  const context = await browser.newContext();
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await page.goto(link);
  await page.click('#enroll');
  await page.waitForFunction(() => /API credential|failed/.test(document.getElementById('status').textContent), null, { timeout: 30000 });
  assert.match(await page.textContent('#status'), /API credential/);
  pass('passkey enrolled at the tailnet link');

  // ---- 3. Rerun: nothing repeated, escrow recorded, doctor clean.
  const second = setup(['--escrow', 'copy', '--attest', '--port', port]);
  assert.equal(second.code, 0, second.out);
  assert.match(second.out, /Setup complete: https:\/\/\S+\.ts\.net/);
  assert.doesNotMatch(second.out, /\/enroll#/);
  pass('rerun completes with a clean doctor; no new link');
  console.log(`PASS: tailnet ingress through setup (${results.length} checks)`);
} finally {
  await browser?.close();
  try { dc(['exec', '-T', 'tailscale', 'tailscale', 'logout']); } catch {}
  try { dc(['down', '-v', '--remove-orphans']); } catch {}
  rmSync(dir, { recursive: true, force: true });
}
