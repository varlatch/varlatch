#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Q6 spike (ADR-0035 design note, "Private installations", option B): a
// tailnet-only installation at https://<machine>.<tailnet>.ts.net, with HTTPS
// terminated by the Tailscale sidecar (containerboot TS_SERVE_CONFIG). Checks
// the six acceptance criteria against a REAL tailnet:
//   1. HTTPS on the ts.net name; /convex WebSockets (live updates) through it
//   2. passkey enrollment, a later sign-in, host-authorized recovery; the
//      machine name is discovered before any enrollment link is issued
//   3. restarts and container recreation keep node identity and URL
//   4. reachable from the tailnet, not resolvable from public DNS
//   5. Funnel disabled
//   6. proxied (serve) requests never get Tailnet Context: a production secret
//      under a Tailnet Constraint is refused through the ts.net URL — even with
//      the Tailscale-User-* headers Serve adds — and allowed via the tailnet
//      listener (:8687)
//
// Run on a machine that is itself on the tailnet, with MagicDNS and HTTPS
// certificates enabled for the tailnet:
//   SPIKE_TS_AUTHKEY_FILE=~/.config/varlatch-spike/ts-authkey node scripts/spike-tsnet.mjs
// The auth key is mounted as a file and never printed. The node logs out and
// every container and volume is removed at the end.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { parseDocument } from 'yaml';
import { createRequire } from 'node:module';
import { VarlatchClient } from '../packages/sdk/dist/index.js';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
// Playwright is a dependency of the dashboard package.
const { chromium } = createRequire(join(root, 'apps/web/package.json'))('playwright');
const keyFile = (process.env.SPIKE_TS_AUTHKEY_FILE ?? '').replace(/^~/, homedir());
if (!keyFile) { console.error('Set SPIKE_TS_AUTHKEY_FILE to a file holding a tailnet auth key.'); process.exit(1); }
const machine = process.env.SPIKE_HOSTNAME ?? 'varlatch-spike';
const local = JSON.parse(execFileSync('tailscale', ['status', '--json'], { encoding: 'utf8' }));
const tailnet = local.MagicDNSSuffix;
const localNode = local.Self.ID;
const images = { varlatchd: 'varlatch-backup-test:local', 'varlatch-migrate': 'varlatch-backup-test:local', 'varlatch-web': 'varlatch-backup-web-test:local', 'convex-deploy': 'varlatch-backup-convex-deploy-test:local' };
const dir = mkdtempSync(join(tmpdir(), 'varlatch-tsnet-spike-'));
const results = [];
const check = (n, name, ok, detail = '') => { results.push({ n, name, ok }); console.log(`${ok ? 'PASS' : 'FAIL'}  [${n}] ${name}${detail ? ` — ${detail}` : ''}`); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const dc = (args, opts = {}) => execFileSync('docker', ['compose', ...args], { cwd: dir, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'], ...opts }).trim();
const tsStatus = () => JSON.parse(dc(['exec', '-T', 'tailscale', 'tailscale', 'status', '--json']));
const dnsName = () => tsStatus().Self?.DNSName?.replace(/\.$/, '') ?? '';
async function until(what, test, ms = 180_000) { const end = Date.now() + ms; while (Date.now() < end) { try { const v = await test(); if (v) return v; } catch {} await sleep(2000); } throw new Error(`timed out: ${what}`); }

// ---- The installation: canonical + Tailscale overlay + Serve config.
cpSync(join(root, 'infra/compose/postgres-init'), join(dir, 'postgres-init'), { recursive: true });
cpSync(join(root, 'infra/compose/convex-supervisor.cjs'), join(dir, 'convex-supervisor.cjs'));
mkdirSync(join(dir, 'secrets')); mkdirSync(join(dir, 'backups')); mkdirSync(join(dir, 'serve'));
writeFileSync(join(dir, 'secrets/kek'), randomBytes(32).toString('hex'));
writeFileSync(join(dir, 'serve/serve.json'), JSON.stringify({
  TCP: { 443: { HTTPS: true } },
  Web: { '${TS_CERT_DOMAIN}:443': { Handlers: { '/': { Proxy: 'http://varlatch-web:80' } } } },
}));
for (const [file, out] of [['docker-compose.yml', 'docker-compose.yml'], ['docker-compose.tailscale.yml', 'docker-compose.tailscale.yml']]) {
  const doc = parseDocument(readFileSync(join(root, 'infra/compose', file), 'utf8'));
  if (file === 'docker-compose.yml') {
    doc.set('name', `vlt-tsnet-${randomBytes(3).toString('hex')}`);
    for (const [service, image] of Object.entries(images)) {
      doc.deleteIn(['services', service, 'build']); doc.setIn(['services', service, 'image'], image); doc.setIn(['services', service, 'pull_policy'], 'never');
    }
  } else {
    doc.setIn(['services', 'tailscale', 'hostname'], machine);
    doc.setIn(['services', 'tailscale', 'environment', 'TS_SERVE_CONFIG'], '/serve/serve.json');
    const volumes = doc.getIn(['services', 'tailscale', 'volumes']);
    volumes.add('./serve:/serve:ro');
  }
  writeFileSync(join(dir, out), doc.toString({ lineWidth: 0 }));
}
const baseEnv = [
  'COMPOSE_FILE=docker-compose.yml:docker-compose.tailscale.yml',
  'POSTGRES_SUPERUSER_PASSWORD=spike-su', 'VARLATCH_MIGRATE_PASSWORD=spike-mig', 'VARLATCH_RUNTIME_PASSWORD=spike-rt', 'CONVEX_DB_PASSWORD=spike-cvx',
  `CONVEX_INSTANCE_SECRET=${randomBytes(32).toString('hex')}`, 'VARLATCHD_PORT=0', 'VARLATCH_WEB_PORT=0', 'CONVEX_PORT=0',
  'VARLATCH_KEK_HOST_PATH=./secrets/kek', `TS_AUTHKEY_HOST_PATH=${keyFile}`, `VARLATCH_TAILNET_NAME=${tailnet}`,
];
writeFileSync(join(dir, '.env'), baseEnv.join('\n') + '\n');

let browser;
try {
  // ---- The node first: its real name decides the public URL (criterion 2).
  dc(['up', '-d', 'tailscale']);
  const name = await until('the node to join the tailnet', () => dnsName());
  const url = `https://${name}`;
  check(2, 'machine name discovered before any enrollment link', name.endsWith(`.${tailnet}`), name);
  writeFileSync(join(dir, '.env'), [...baseEnv, `VARLATCH_PUBLIC_URL=${url}`, `CONVEX_CLOUD_ORIGIN=${url}/convex`, `CONVEX_SITE_ORIGIN=${url}/convex`].join('\n') + '\n');
  dc(['up', '-d']);
  await until('varlatchd ready', async () => (await fetch(`${url}/readyz`)).ok, 300_000);
  dc(['run', '--rm', 'convex-deploy']);
  check(1, 'HTTPS with a valid certificate on the ts.net name', (await fetch(`${url}/`)).ok, url);

  // ---- Passkeys on the ts.net origin (criterion 2).
  const token = dc(['exec', '-T', 'varlatchd', 'node', 'dist/cli.js', 'admin', 'bootstrap', '--cli-credential']).match(/vlt_cli_\S+/)[0];
  const api = new VarlatchClient({ server: url, token });
  await api.createOrganization({ slug: 'spike', name: 'Spike' });
  await api.createProject('spike', { slug: 'app', name: 'App', contractAuthority: 'managed' });
  await api.createEnvironment('spike', 'app', { name: 'production', tier: 'production' });
  const rev = await api.pushContractRevision('spike', 'app', { contract: { schemaVersion: 1, items: [{ name: 'SECRET', type: 'string', sensitive: true, required: { kind: 'always' } }] } });
  await api.activateContractRevision('spike', 'app', rev.id);
  await api.setValue('spike', 'app', 'production', 'SECRET', { value: 'tsnet-spike-secret' });
  const adminId = (await api.meWhoami?.().catch(() => null))?.identityId
    ?? dc(['exec', '-T', 'postgres', 'psql', '-U', 'postgres', '-d', 'varlatch', '-Atc', 'SELECT id FROM identities WHERE installation_admin LIMIT 1']);
  browser = await chromium.launch();
  const passkeyContext = async () => {
    const context = await browser.newContext();
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
    return { context, page };
  };
  const enroll = async (page, link) => {
    await page.goto(link);
    await page.click('#enroll');
    await page.waitForFunction(() => /API credential|failed/.test(document.getElementById('status').textContent), null, { timeout: 30000 });
    return /API credential/.test(await page.textContent('#status'));
  };
  const link = () => dc(['exec', '-T', 'varlatchd', 'node', 'dist/cli.js', 'admin', 'recover', '--identity', adminId]).match(/https:\/\/\S+enroll#\S+/)?.[0];
  const first = await passkeyContext();
  const firstLink = link();
  check(2, 'enrollment link carries the ts.net origin', firstLink?.startsWith(`${url}/enroll#`), firstLink?.split('#')[0]);
  check(2, 'passkey enrollment on the ts.net origin', await enroll(first.page, firstLink));
  await first.page.goto(`${url}/o/spike/projects`);
  await first.page.waitForSelector('[data-testid="project-card"]', { timeout: 30000 });
  // Live updates through Serve → nginx /convex → convex-backend (criterion 1).
  await sleep(6000);
  check(1, 'live updates connected (/convex WebSocket through Serve)', (await first.page.locator('[data-testid="live-updates-status"]').count()) === 0);
  await api.createProject('spike', { slug: 'live', name: 'Live', contractAuthority: 'git' });
  await first.page.waitForSelector('[data-testid="project-card"][data-slug="live"]', { timeout: 20000 });
  check(1, 'a change arrives by live signal over wss', true);
  // A later sign-in: clear the session, sign in with the same passkey.
  await first.context.clearCookies();
  await first.page.goto(`${url}/o/spike/projects`);
  await first.page.getByText('Sign in with passkey').click();
  await first.page.waitForSelector('[data-testid="project-card"]', { timeout: 30000 });
  check(2, 'later sign-in with the enrolled passkey', true);
  // Host-authorized recovery onto a new authenticator.
  const second = await passkeyContext();
  check(2, 'host-authorized recovery enrolls a new passkey', await enroll(second.page, link()));

  // ---- Restarts keep identity and URL (criterion 3).
  const nodeBefore = tsStatus().Self.ID;
  dc(['restart', 'tailscale']);
  await until('HTTPS after restart', async () => (await fetch(`${url}/readyz`)).ok);
  dc(['up', '-d', '--force-recreate', 'tailscale', 'varlatchd']);
  await until('HTTPS after recreation', async () => (await fetch(`${url}/readyz`)).ok, 300_000);
  check(3, 'restart and recreation keep node identity and URL', tsStatus().Self.ID === nodeBefore && dnsName() === name, nodeBefore);

  // ---- Access and Funnel (criteria 4, 5).
  const publicDns = execFileSync('dig', ['+short', '@1.1.1.1', name, 'A'], { encoding: 'utf8' }).trim();
  check(4, 'not resolvable in public DNS', publicDns === '', publicDns || 'no public record');
  check(4, 'reachable from this tailnet node', (await fetch(`${url}/readyz`)).ok);
  const serve = JSON.parse(dc(['exec', '-T', 'tailscale', 'tailscale', 'serve', 'status', '--json']) || '{}');
  check(5, 'Funnel disabled', !serve.AllowFunnel || Object.values(serve.AllowFunnel).every(v => !v), JSON.stringify(serve.AllowFunnel ?? {}));

  // ---- Tailnet Context never through Serve (criterion 6).
  await api.createTailnetRequirement('spike', { target: { kind: 'tier', tier: 'production' }, selector: { tailnet, nodes: [localNode] } });
  const disclose = (base, headers = {}) => fetch(`${base}/v1/organizations/spike/projects/app/environments/production/disclosures`, {
    method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...headers }, body: JSON.stringify({ scope: 'all-authorized-secrets' }),
  });
  const viaServe = await disclose(url);
  check(6, 'refused through the ts.net URL (Serve → ordinary listener)', viaServe.status === 403 && (await viaServe.json()).error?.code === 'TAILNET_CONTEXT_REQUIRED', String(viaServe.status));
  const forged = await disclose(url, { 'Tailscale-User-Login': local.User?.[local.Self.UserID]?.LoginName ?? 'x@y', 'Tailscale-User-Name': 'x', 'X-Forwarded-For': local.Self.TailscaleIPs[0] });
  check(6, '…still refused with forged Tailscale-User-* / X-Forwarded-For headers', forged.status === 403, String(forged.status));
  const viaListener = await disclose(`http://${name}:8687`);
  const listenerBody = await viaListener.json().catch(() => ({}));
  check(6, 'allowed through the tailnet listener with true peer identity', viaListener.status === 200 && listenerBody.items?.[0]?.value === 'tsnet-spike-secret', String(viaListener.status));
} catch (err) {
  check(0, 'spike', false, String(err).slice(0, 400));
} finally {
  await browser?.close();
  try { dc(['exec', '-T', 'tailscale', 'tailscale', 'logout']); } catch {}
  try { dc(['down', '-v', '--remove-orphans']); } catch {}
  rmSync(dir, { recursive: true, force: true });
}
const failed = results.filter(r => !r.ok);
console.log(failed.length ? `\n${failed.length} check(s) failed` : `\nPASS: all ${results.length} checks`);
process.exit(failed.length ? 1 : 0);
