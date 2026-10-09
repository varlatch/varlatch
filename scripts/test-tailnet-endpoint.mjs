#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// The tailnet browser endpoint (ADR-0046) on a REAL tailnet, through
// `varlatch setup --tailnet-endpoint`. Manual, like test-ingress-tailnet.mjs.
// It builds the images of THIS checkout (clean, one commit, under tags no
// other run uses, labeled with the commit and checked before use), sets up
// a disposable installation with the tailnet ingress and the endpoint, and
// runs the ADR's real-tailnet cases from this machine, the browser ones in
// the real dashboard under its Content-Security-Policy:
//
//   setup   the endpoint's settings, the printed access rule, doctor's
//           tailnet checks passing
//   case 1  an approved device (this machine, named by a node Requirement):
//           in the dashboard, Connect to tailnet, Reveal all and an export
//           with secrets read through the endpoint, and nothing protected
//           is asked of the dashboard's own address; audit records the
//           tailnet listener and this device
//   case 2  the same device once the Requirement names another node: the
//           dashboard says this device does not meet the requirements
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
//   csp     no Content-Security-Policy violation anywhere in the run, and
//           the policy names the endpoint
//
// Run from a clean checkout of the revision under review (the dashboard side,
// #27, included), on a tailnet member whose access rules let it reach the
// test node on tcp:8688 (in a tailnet where members may reach every device,
// no change is needed), with MagicDNS and HTTPS certificates enabled:
//   SPIKE_TS_AUTHKEY_FILE=~/.config/varlatch-spike/ts-authkey \
//   VARLATCH_TEST_REVISION=<the reviewed commit> node scripts/test-tailnet-endpoint.mjs
// VARLATCH_TEST_REVISION, when set, must be the checkout's HEAD.
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
const git = (...args) => execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' }).trim();
// One revision, exactly: what is built is what was committed and reviewed.
if (git('status', '--porcelain')) { console.error('The checkout has uncommitted changes: commit or stash them, so the run tests exactly one revision.'); process.exit(1); }
const revision = git('rev-parse', 'HEAD');
if (process.env.VARLATCH_TEST_REVISION && !revision.startsWith(process.env.VARLATCH_TEST_REVISION)) {
  console.error(`HEAD is ${revision}, not ${process.env.VARLATCH_TEST_REVISION}: check out the reviewed revision.`); process.exit(1);
}
if (spawnSync('git', ['-C', root, 'cat-file', '-e', `${revision}:apps/web/src/lib/tailnetConnection.tsx`]).status !== 0) {
  console.error(`${revision} has no dashboard side of the endpoint (#27): run on a revision that has both.`); process.exit(1);
}
const runId = randomBytes(3).toString('hex');
const project = `vlt-endpoint-${runId}`;
const tag = (name) => `varlatch-endpoint-test/${name}:${revision.slice(0, 12)}-${runId}`;
const images = { varlatchd: tag('varlatchd'), 'varlatch-migrate': tag('varlatchd'), 'varlatch-web': tag('web'), 'convex-deploy': tag('convex-deploy') };
const dockerfiles = { [tag('varlatchd')]: 'services/varlatchd/Dockerfile', [tag('web')]: 'apps/web/Dockerfile', [tag('convex-deploy')]: 'infra/compose/convex-deploy.Dockerfile' };
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
  for (const [image, dockerfile] of Object.entries(dockerfiles)) {
    console.log(`building ${image} from ${revision.slice(0, 12)} ...`);
    execFileSync('docker', ['build', '-q', '-f', join(root, dockerfile), '-t', image, '--label', `org.varlatch.test.revision=${revision}`, root], { stdio: ['ignore', 'ignore', 'inherit'] });
    const label = execFileSync('docker', ['image', 'inspect', '-f', '{{index .Config.Labels "org.varlatch.test.revision"}} {{.Id}}', image], { encoding: 'utf8' }).trim();
    if (!label.startsWith(`${revision} `)) throw new Error(`${image} is not the image just built from ${revision}: ${label}`);
    console.log(`  ${image} = ${label.split(' ')[1]}`);
  }
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
  const context = await browser.newContext({ acceptDownloads: true });
  const cspViolations = [];
  const watchCsp = (p) => p.on('console', (m) => { if (/Content Security Policy/i.test(m.text())) cspViolations.push(m.text().slice(0, 240)); });
  context.on('page', watchCsp);
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

  // Every request the browser makes, to tell the endpoint from the dashboard's own address.
  const requests = [];
  context.on('request', (r) => requests.push({ url: r.url(), method: r.method() }));
  const protectedOnOrdinary = () =>
    requests.filter((r) => r.url.startsWith(`${publicUrl}${PATH}/`) && (/\/disclosures$/.test(r.url) || /include=values/.test(r.url)));
  const onEndpoint = (suffix, method) => requests.filter((r) => r.url.startsWith(`${endpoint}${PATH}${suffix}`) && r.method === method);

  // ---- Case 1, in the dashboard: Connect, Reveal all, export.
  const shell = await page.goto(`${publicUrl}/o/acme/p/api/e/production`);
  const policy = (await shell.allHeaders())['content-security-policy'] ?? '';
  check('csp: the dashboard\'s policy lets it connect to the endpoint, and nothing inline', policy.includes(endpoint) && !/unsafe-inline|unsafe-eval/.test(policy), policy);
  await page.waitForSelector('[data-testid="tailnet-connect"]', { timeout: 30000 });
  check('case 1: no request to the endpoint before Connect', requests.every((r) => !r.url.startsWith(endpoint)));
  await page.click('[data-testid="tailnet-connect"]');
  await page.waitForSelector('[data-testid="tailnet-read-note"]', { timeout: 30000 });
  check('case 1: Connect checks this device; the values are read through the endpoint', onEndpoint('/effective-configuration?include=values', 'GET').length > 0);
  await page.click('[data-testid="reveal-all"]');
  await page.waitForFunction(() => document.querySelector('[data-row="SECRET_A"]')?.textContent?.includes('endpoint-s3cr3t'), null, { timeout: 30000 });
  check('case 1: Reveal all shows the secret, disclosed through the endpoint', onEndpoint('/disclosures', 'POST').length === 1);
  const audit = sql("SELECT listener || ' ' || (tailnet->>'nodeId') FROM audit_events WHERE event_type = 'secret.disclosed' ORDER BY event_order DESC LIMIT 1");
  check('case 1: audit records the tailnet listener and this device', audit === `tailnet ${self.ID}`, audit);

  // A new page load starts unconnected: the grid offers Connect again.
  await page.goto(`${publicUrl}/o/acme/p/api`);
  await page.waitForSelector('[data-testid="tailnet-connect-prompt"] [data-testid="tailnet-connect"]', { timeout: 30000 });
  await page.click('[data-testid="tailnet-connect-prompt"] [data-testid="tailnet-connect"]');
  await page.waitForSelector('[data-testid="tailnet-connect-prompt"]', { state: 'detached', timeout: 30000 });
  await page.click('[data-testid="export-menu"]');
  await page.click('[data-testid="export-production"]');
  await page.waitForSelector('[data-testid="export-include-secrets"]', { timeout: 30000 });
  await page.click('[data-testid="export-include-secrets"]');
  const [download] = await Promise.all([page.waitForEvent('download'), page.click('[data-testid="export-download"]')]);
  const exported = readFileSync(await download.path(), 'utf8');
  check('case 1: the export with secrets reads through the endpoint', exported.includes('SECRET_A=endpoint-s3cr3t') && onEndpoint('/disclosures', 'POST').length === 2, exported.split('\n').slice(0, 3).join(' | '));
  check('case 1: nothing protected was asked of the dashboard\'s own address', protectedOnOrdinary().length === 0, JSON.stringify(protectedOnOrdinary()));

  // ---- Case 2, in the dashboard: the Requirement names another node.
  await api(`/v1/organizations/acme/requirements/${reqId}`, { method: 'DELETE' });
  reqId = await requirement(['nSOMEONEELSE']);
  await page.goto(`${publicUrl}/o/acme/p/api/e/production`);
  await page.waitForSelector('[data-testid="tailnet-connect"]', { timeout: 30000 });
  await page.click('[data-testid="tailnet-connect"]');
  const refused = await page.waitForSelector('[data-testid="tailnet-connect-status"][data-status="refused"]', { timeout: 30000 }).then(() => true, () => false);
  check('case 2: the dashboard says this device does not meet the requirements here', refused, await page.textContent('[data-testid="tailnet-only-notice"]').catch(() => ''));
  check('case 2: and still asks nothing protected of its own address', protectedOnOrdinary().length === 0);
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
    const res = await fetch(`${endpoint}${PATH}/disclosures`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ scope: 'all-authorized-secrets' }) });
    const refused = { status: res.status, body: await res.json().catch(() => null) };
    check('case 7: without the LocalAPI, constrained reads are refused', refused.status === 403 && refused.body?.error?.code === 'TAILNET_CONTEXT_REQUIRED', JSON.stringify(refused));
    const reason = sql("SELECT tailnet->>'refused' FROM audit_events WHERE event_type = 'authorization.denied' ORDER BY event_order DESC LIMIT 1");
    check('case 7: and recorded as resolver-unavailable', reason === 'resolver-unavailable', reason);
    const metadata = await fetch(`${endpoint}${PATH}/effective-configuration`, { headers: { Authorization: `Bearer ${token}` } });
    check('case 7: metadata is still served', metadata.status === 200, String(metadata.status));
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
  check('csp: no Content-Security-Policy violation anywhere in the run', cspViolations.length === 0, cspViolations.slice(0, 3).join(' | '));
} catch (err) {
  fail('real-tailnet endpoint test', String(err?.stack ?? err).slice(0, 1200));
} finally {
  await browser?.close();
  try { dc(['exec', '-T', 'tailscale', 'tailscale', 'logout']); } catch {}
  try { dc(['down', '-v', '--remove-orphans']); } catch {}
  rmSync(dir, { recursive: true, force: true });
  spawnSync('docker', ['image', 'rm', ...new Set(Object.values(images))], { stdio: 'ignore' });
}
if (failed) { console.log('FAILED'); process.exit(1); }
console.log('PASS: tailnet browser endpoint on a real tailnet');
