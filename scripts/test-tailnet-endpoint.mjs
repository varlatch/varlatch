#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// The tailnet browser endpoint (ADR-0046) on a REAL tailnet, through
// `varlatch setup --tailnet-endpoint`. Manual, like test-ingress-tailnet.mjs.
// It builds a disposable installation with the tailnet ingress and the
// endpoint, then runs the ADR's real-tailnet cases from this machine:
//
//   setup   the endpoint's settings, the printed access rule, doctor's
//           tailnet checks passing
//   case 1  an approved device (this machine, named by a node Requirement):
//           a page on the dashboard's origin, in Chromium, reads the device
//           check and a disclosure through the endpoint; audit records the
//           tailnet listener and this device
//   case 2  the same device once the Requirement names another node:
//           403 TAILNET_CONTEXT_UNAVAILABLE, readable by the page
//   case 4  the ordinary ingress (the dashboard's address): the disclosure
//           is TAILNET_CONTEXT_REQUIRED, no CORS, no device route
//   case 5  spoofed identity at the endpoint: forwarding and Tailscale
//           headers change nothing, a foreign Host is refused, a PROXY
//           preamble gets no HTTP answer
//   case 7  the LocalAPI unavailable (its socket moved away for a moment):
//           constrained reads refused as resolver-unavailable, metadata
//           still served
//   peer    a container on the Compose network: no route to the endpoint
//           (bound to loopback), and no device on the plain listener
//
// Run on a tailnet member whose access rules let it reach the test node on
// tcp:8688 (in a tailnet where members may reach every device, no change is
// needed), with MagicDNS and HTTPS certificates enabled:
//   SPIKE_TS_AUTHKEY_FILE=~/.config/varlatch-spike/ts-authkey node scripts/test-tailnet-endpoint.mjs
// It never changes access rules. The node logs out and every container and
// volume is removed at the end. Any failure, including a prerequisite that
// is missing (no route to tcp:8688, no certificate), fails the run.
import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { request as httpsRequest } from 'node:https';
import { createServer, connect as tcpConnect } from 'node:net';
import { homedir, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseDocument } from 'yaml';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const { chromium } = createRequire(join(root, 'apps/web/package.json'))('playwright');
const cli = join(root, 'apps/cli/dist/varlatch.cjs');
const keyFile = (process.env.SPIKE_TS_AUTHKEY_FILE ?? '').replace(/^~/, homedir());
if (!keyFile) { console.error('Set SPIKE_TS_AUTHKEY_FILE to a file holding a tailnet auth key.'); process.exit(1); }
const machine = process.env.SPIKE_HOSTNAME ?? 'varlatch-endpoint';
const images = { varlatchd: 'varlatch-backup-test:local', 'varlatch-migrate': 'varlatch-backup-test:local', 'varlatch-web': 'varlatch-backup-web-test:local', 'convex-deploy': 'varlatch-backup-convex-deploy-test:local' };
const project = `vlt-endpoint-${randomBytes(3).toString('hex')}`;
const dir = mkdtempSync(join(tmpdir(), 'varlatch-tailnet-endpoint-'));

let failed = false;
const pass = (name, detail = '') => console.log(`PASS  ${name}${detail ? `: ${detail}` : ''}`);
const fail = (name, detail = '') => { failed = true; console.log(`FAIL  ${name}${detail ? `: ${detail}` : ''}`); };
const check = (name, ok, detail = '') => (ok ? pass(name, detail) : fail(name, detail));

const dc = (args, input) => execFileSync('docker', ['compose', ...args], { cwd: dir, encoding: 'utf8', input, stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'] }).trim();
const freePort = () => new Promise((res) => { const s = createServer(); s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => res(port)); }); });
const setup = (args) => { const r = spawnSync('node', [cli, 'setup', '--dir', dir, ...args], { encoding: 'utf8', timeout: 900_000, maxBuffer: 64 * 1024 * 1024 }); return { code: r.status, out: `${r.stdout}\n${r.stderr}` }; };
const sql = (query) => dc(['exec', '-T', 'postgres', 'psql', '-U', 'postgres', '-d', 'varlatch', '-Atc', query]);

let browser;
try {
  const doc = parseDocument(readFileSync(join(root, 'infra/compose/docker-compose.yml'), 'utf8'));
  doc.set('name', project);
  for (const [s, i] of Object.entries(images)) { doc.deleteIn(['services', s, 'build']); doc.setIn(['services', s, 'image'], i); doc.setIn(['services', s, 'pull_policy'], 'never'); }
  writeFileSync(join(dir, 'docker-compose.yml'), doc.toString({ lineWidth: 0 }));
  for (const f of ['convex-supervisor.cjs', 'postgres-init', 'docker-compose.tailscale.yml', 'docker-compose.tailnet-https.yml', 'tailscale-serve.json']) {
    cpSync(join(root, 'infra/compose', f), join(dir, f), { recursive: true });
  }
  const port = String(await freePort());

  // ---- Setup with the endpoint: join, enroll, finish.
  const first = setup(['--ingress', 'tailnet', '--tailnet-endpoint', '--tailnet-machine', machine, '--tailscale-auth-key-file', keyFile, '--port', port, '--no-wait']);
  const publicUrl = first.out.match(/tailnet node joined: (https:\/\/\S+)/)?.[1];
  const link = first.out.match(/https:\/\/\S+\/enroll#\S+/)?.[0];
  if (first.code !== 3 || !publicUrl || !link) throw new Error(`setup did not reach enrollment:\n${first.out}`);
  const host = new URL(publicUrl).hostname;
  const endpoint = `https://${host}:8688`;
  const env = readFileSync(join(dir, '.env'), 'utf8');
  check('setup writes the endpoint settings for varlatchd, the dashboard and the sidecar',
    env.includes('VARLATCH_TAILNET_HTTPS_PORT=8688\n') && env.includes(`VARLATCH_TAILNET_ENDPOINT=${endpoint}\n`) && env.includes('VARLATCH_TAILNET_CERT_UID=999\n'));

  browser = await chromium.launch();
  const context = await browser.newContext();
  // Chromium asks before a page reaches a local-network address; this stands for the person clicking Allow (spike S5).
  await context.grantPermissions(['local-network-access']);
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await page.goto(link);
  await page.click('#enroll');
  await page.waitForFunction(() => /API credential|failed/.test(document.getElementById('status').textContent), null, { timeout: 30000 });

  const second = setup(['--escrow', 'copy', '--attest', '--port', port]);
  check('setup completes and prints the access rule for the endpoint, without editing the policy',
    second.code === 0 && second.out.includes(`Tailnet browser endpoint: ${endpoint}`) && /"ip":\["tcp:8688"\]/.test(second.out), second.code === 0 ? '' : second.out.slice(-800));
  check('doctor: the tailnet listener and the endpoint pass; reachability stays unknown',
    /✓ Tailnet listener/.test(second.out) && /✓ Tailnet browser endpoint\n/.test(second.out) && /\? Tailnet browser endpoint reachable from browsers/.test(second.out));

  // ---- Data: a production secret behind a Requirement naming this machine.
  const adminId = sql("SELECT id FROM identities WHERE installation_admin LIMIT 1");
  const token = dc(['exec', '-T', 'varlatchd', 'node', 'dist/cli.js', 'admin', 'recover', '--identity', adminId, '--cli-credential']).split('\n').pop();
  const api = (path, init = {}) => fetch(`${publicUrl}${path}`, { ...init, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...init.headers } });
  await api('/v1/organizations', { method: 'POST', body: JSON.stringify({ name: 'Acme', slug: 'acme' }) });
  await api('/v1/organizations/acme/projects', { method: 'POST', body: JSON.stringify({ name: 'API', slug: 'api', contractAuthority: 'managed' }) });
  await api('/v1/organizations/acme/projects/api/environments', { method: 'POST', body: JSON.stringify({ name: 'production', tier: 'production' }) });
  await api('/v1/organizations/acme/projects/api/environments/production/values/SECRET_A', { method: 'PUT', body: JSON.stringify({ value: 'endpoint-s3cr3t' }) });
  const self = JSON.parse(execFileSync('tailscale', ['status', '--json', '--peers=false'], { encoding: 'utf8' })).Self;
  const tailnet = host.split('.').slice(1).join('.');
  const requirement = async (nodes) => {
    const r = await api('/v1/organizations/acme/requirements', { method: 'POST', body: JSON.stringify({ kind: 'tailnet', target: { kind: 'tier', tier: 'production' }, selector: { tailnet, nodes } }) });
    return (await r.json()).id;
  };
  let reqId = await requirement([self.ID]);
  const PATH = '/v1/organizations/acme/projects/api/environments/production';

  // A page on the dashboard's origin (served by the test, not the dashboard), reading cross-origin as the dashboard does.
  await page.route(`${publicUrl}/__endpoint-test`, (route) => route.fulfill({ contentType: 'text/html', body: '<!doctype html><title>endpoint test</title>' }));
  await page.goto(`${publicUrl}/__endpoint-test`);
  const fromPage = (path, method = 'GET', body) => page.evaluate(async ({ url, method, body, token }) => {
    try {
      const res = await fetch(url, { method, credentials: 'omit', headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(8000) });
      return { status: res.status, body: await res.json().catch(() => null) };
    } catch (err) { return { error: String(err) }; }
  }, { url: `${endpoint}${path}`, method, body, token });

  // ---- Case 1: approved device.
  const device = await fromPage('/v1/tailnet/context');
  check('case 1: the endpoint recognizes this machine, from a page on the dashboard\'s origin', device.body?.recognized === true && device.body?.nodeId === self.ID, JSON.stringify(device));
  const disclosed = await fromPage(`${PATH}/disclosures`, 'POST', { scope: 'all-authorized-secrets' });
  check('case 1: the disclosure through the endpoint returns the value', disclosed.status === 200 && disclosed.body?.items?.[0]?.value === 'endpoint-s3cr3t', JSON.stringify(disclosed).slice(0, 300));
  const audit = sql("SELECT listener || ' ' || (tailnet->>'nodeId') FROM audit_events WHERE event_type = 'secret.disclosed' ORDER BY event_order DESC LIMIT 1");
  check('case 1: audit records the tailnet listener and this device', audit === `tailnet ${self.ID}`, audit);

  // ---- Case 2: the same device, no longer named.
  await api(`/v1/organizations/acme/requirements/${reqId}`, { method: 'DELETE' });
  reqId = await requirement(['nSOMEONEELSE']);
  const mismatch = await fromPage(`${PATH}/disclosures`, 'POST', { scope: 'all-authorized-secrets' });
  check('case 2: a device the Requirement does not name is refused, and the page can read why', mismatch.status === 403 && mismatch.body?.error?.code === 'TAILNET_CONTEXT_UNAVAILABLE', JSON.stringify(mismatch));
  await api(`/v1/organizations/acme/requirements/${reqId}`, { method: 'DELETE' });
  reqId = await requirement([self.ID]);

  // ---- Case 4: the ordinary ingress.
  const ordinary = await api(`${PATH}/disclosures`, { method: 'POST', body: JSON.stringify({ scope: 'all-authorized-secrets' }) });
  check('case 4: the dashboard\'s address never satisfies the Requirement', ordinary.status === 403 && (await ordinary.json()).error?.code === 'TAILNET_CONTEXT_REQUIRED');
  const preflight = await fetch(`${publicUrl}${PATH}/disclosures`, { method: 'OPTIONS', headers: { Origin: publicUrl, 'Access-Control-Request-Method': 'POST' } });
  check('case 4: no CORS on the ordinary ingress', preflight.headers.get('access-control-allow-origin') === null);
  check('case 4: no device route on the ordinary ingress', (await api('/v1/tailnet/context')).status === 404);

  // ---- Case 5: spoofed identity at the endpoint, from this machine (not the named node now).
  await api(`/v1/organizations/acme/requirements/${reqId}`, { method: 'DELETE' });
  reqId = await requirement(['nSOMEONEELSE']);
  const spoofed = await fetch(`${endpoint}${PATH}/disclosures`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'X-Forwarded-For': '100.64.0.7', Forwarded: 'for=100.64.0.7', 'X-Real-IP': '100.64.0.7', 'Tailscale-User-Login': 'admin@example.com', 'Tailscale-App-Capabilities': '{}' },
    body: JSON.stringify({ scope: 'all-authorized-secrets' }),
  });
  check('case 5: forwarding and Tailscale headers change nothing', spoofed.status === 403 && (await spoofed.json()).error?.code === 'TAILNET_CONTEXT_UNAVAILABLE');
  const recorded = sql("SELECT tailnet->>'nodeId' FROM audit_events WHERE event_type = 'authorization.denied' ORDER BY event_order DESC LIMIT 1");
  check('case 5: the denial records this machine, not what the headers said', recorded === self.ID, recorded);
  const foreignHost = await new Promise((res) => {
    const req = httpsRequest({ host, port: 8688, servername: host, path: '/v1/tailnet/context', headers: { Authorization: `Bearer ${token}`, Host: 'evil.example.com' } }, (r) => { r.resume(); res(r.statusCode); });
    req.on('error', (e) => res(String(e)));
    req.end();
  });
  check('case 5: a foreign Host is refused', foreignHost === 403, String(foreignHost));
  const preamble = await new Promise((res) => {
    const s = tcpConnect(8688, host, () => s.write('PROXY TCP4 100.64.0.7 127.0.0.1 51000 8688\r\nGET /v1/tailnet/context HTTP/1.1\r\nHost: x\r\n\r\n'));
    let got = '';
    s.on('data', (d) => (got += d.toString('latin1')));
    s.on('error', () => {});
    s.on('close', () => res(got));
    setTimeout(() => s.destroy(), 8000);
  });
  check('case 5: a PROXY preamble gets no HTTP answer', !preamble.includes('HTTP/1.1'));
  await api(`/v1/organizations/acme/requirements/${reqId}`, { method: 'DELETE' });
  reqId = await requirement([self.ID]);

  // ---- Case 7: the LocalAPI unavailable for a moment.
  const sock = '/var/run/tailscale/tailscaled.sock';
  try {
    dc(['exec', '-T', 'tailscale', 'mv', sock, `${sock}.away`]);
    const refused = await fromPage(`${PATH}/disclosures`, 'POST', { scope: 'all-authorized-secrets' });
    check('case 7: without the LocalAPI, constrained reads are refused', refused.status === 403 && refused.body?.error?.code === 'TAILNET_CONTEXT_REQUIRED', JSON.stringify(refused));
    const reason = sql("SELECT tailnet->>'refused' FROM audit_events WHERE event_type = 'authorization.denied' ORDER BY event_order DESC LIMIT 1");
    check('case 7: and recorded as resolver-unavailable', reason === 'resolver-unavailable', reason);
    const metadata = await fromPage(`${PATH}/effective-configuration`);
    check('case 7: metadata is still served', metadata.status === 200, JSON.stringify(metadata).slice(0, 200));
  } finally {
    dc(['exec', '-T', 'tailscale', 'mv', `${sock}.away`, sock]);
  }

  // ---- A peer on the Compose network.
  const net = `${project}_default`;
  const peer = (code) => spawnSync('docker', ['run', '--rm', '--network', net, '--entrypoint', 'node', images.varlatchd, '-e', code], { encoding: 'utf8', timeout: 60_000 });
  const tls = peer(`require('https').get({host:'varlatchd',port:8688,path:'/v1/tailnet/context',rejectUnauthorized:false},r=>console.log('answered',r.statusCode)).on('error',e=>console.log('error',e.code))`);
  check('peer: the endpoint is not reachable from the Compose network (bound to loopback)', /error (ECONNREFUSED|ECONNRESET)/.test(tls.stdout), tls.stdout + tls.stderr);
  const plain = peer(`fetch('http://varlatchd:8687${PATH}/disclosures',{method:'POST',headers:{Authorization:'Bearer ${token}','Content-Type':'application/json'},body:JSON.stringify({scope:'all-authorized-secrets'})}).then(async r=>console.log(r.status,(await r.json()).error?.code)).catch(e=>console.log('error',e.cause?.code))`);
  check('peer: on the plain listener it has no device', /403 TAILNET_CONTEXT_REQUIRED|error ECONNREFUSED/.test(plain.stdout), plain.stdout + plain.stderr);
} catch (err) {
  fail('real-tailnet endpoint test', String(err?.stack ?? err).slice(0, 1200));
} finally {
  await browser?.close();
  try { dc(['exec', '-T', 'tailscale', 'tailscale', 'logout']); } catch {}
  try { dc(['down', '-v', '--remove-orphans']); } catch {}
  rmSync(dir, { recursive: true, force: true });
}
if (failed) { console.log('FAILED'); process.exit(1); }
console.log('PASS: tailnet browser endpoint on a real tailnet');
