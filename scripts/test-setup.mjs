#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// `varlatch setup` end to end (ADR-0035 D7) on the canonical Compose file with
// the candidate images (varlatch-backup-*-test:local, as in the recovery job):
//
//   A. fresh directory → one command → enroll a passkey from the printed link
//      → setup completes with a clean doctor; no secret value in .env or in
//      varlatchd's configuration; a rerun regenerates nothing, prints no
//      link, and the Application Plane reconcile is a no-op
//   B. an admin that never enrolled a passkey (interrupted / headless) → the
//      rerun issues a recovery link and completes once it is used
//   C. a hand-written .env is refused (existing installations adopt instead)
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseDocument } from 'yaml';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const cli = join(root, 'apps/cli/dist/varlatch.cjs');
const playwright = await import(pathToFileURL(createRequire(join(root, 'services/varlatchd/package.json')).resolve('playwright')).href);
const chromium = playwright.chromium ?? playwright.default.chromium; // CommonJS module
const images = { varlatchd: 'varlatch-backup-test:local', 'varlatch-migrate': 'varlatch-backup-test:local', 'varlatch-web': 'varlatch-backup-web-test:local', 'convex-deploy': 'varlatch-backup-convex-deploy-test:local' };
const work = mkdtempSync(join(tmpdir(), 'varlatch-setup-e2e-'));
const dirs = [];
const results = [];
const pass = (name, detail = '') => { results.push(name); console.log(`PASS  ${name}${detail ? ` — ${detail}` : ''}`); };

const freePort = () => new Promise(res => { const s = createServer(); s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => res(port)); }); });
const dc = (dir, args) => execFileSync('docker', ['compose', ...args], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();

function composeDir(name) {
  const dir = join(work, name);
  mkdirSync(dir);
  const doc = parseDocument(readFileSync(join(root, 'infra/compose/docker-compose.yml'), 'utf8'));
  doc.set('name', `vlt-setup-${randomBytes(3).toString('hex')}-${name}`);
  for (const [service, image] of Object.entries(images)) {
    doc.deleteIn(['services', service, 'build']);
    doc.setIn(['services', service, 'image'], image);
    doc.setIn(['services', service, 'pull_policy'], 'never');
  }
  writeFileSync(join(dir, 'docker-compose.yml'), doc.toString({ lineWidth: 0 }));
  cpSync(join(root, 'infra/compose/convex-supervisor.cjs'), join(dir, 'convex-supervisor.cjs'));
  cpSync(join(root, 'infra/compose/postgres-init'), join(dir, 'postgres-init'), { recursive: true });
  dirs.push(dir);
  return dir;
}

/** Runs setup; resolves with the enroll link when one is printed, and with the exit. */
function setup(dir, args) {
  let out = '';
  const child = spawn('node', [cli, 'setup', '--dir', dir, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let linkResolve;
  const link = new Promise(r => { linkResolve = r; });
  const onData = d => { out += d; const m = out.match(/https?:\/\/\S+\/enroll#\S+/); if (m) linkResolve(m[0]); };
  child.stdout.on('data', onData); child.stderr.on('data', onData);
  const exit = new Promise(r => child.on('close', code => { linkResolve(null); r({ code, out }); }));
  return { link, exit };
}

async function enroll(url) {
  const browser = await chromium.launch();
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
    await page.goto(url);
    await page.click('#enroll');
    await page.waitForFunction(() => /API credential|failed/.test(document.getElementById('status').textContent), null, { timeout: 30000 });
    assert.match(await page.textContent('#status'), /API credential/, 'passkey enrollment');
  } finally { await browser.close(); }
}

const secretsDigest = dir => createHash('sha256').update(readdirSync(join(dir, 'secrets')).sort().map(f => f + readFileSync(join(dir, 'secrets', f))).join()).digest('hex');

try {
  // ---- C. A hand-configured installation is not taken over.
  const hand = composeDir('hand');
  writeFileSync(join(hand, '.env'), 'POSTGRES_SUPERUSER_PASSWORD=x\n');
  const refused = await setup(hand, ['--public-url', 'http://localhost:1']).exit;
  assert.notEqual(refused.code, 0);
  assert.match(refused.out, /hand-configured installation/);
  pass('a hand-written .env is refused, not taken over');

  // ---- A. Fresh directory, one command.
  const fresh = composeDir('fresh');
  const port = await freePort();
  const url = `http://localhost:${port}`;
  const passphraseFile = join(work, 'escrow-passphrase');
  writeFileSync(passphraseFile, 'correct horse battery staple\n', { mode: 0o600 });
  const run = setup(fresh, ['--public-url', url, '--port', String(port), '--enroll-timeout', '600',
    '--escrow', 'passphrase', '--escrow-passphrase-file', passphraseFile, '--attest']);
  const link = await run.link;
  // Not assert(link, `…${await run.exit}`): the message would be evaluated
  // first, waiting for setup to exit before enrollment could even start.
  if (!link) assert.fail(`setup printed no enrollment link:\n${(await run.exit).out}`);
  assert(link.startsWith(`${url}/enroll#`), `the link uses the public URL: ${link}`);
  await enroll(link);
  const first = await run.exit;
  assert.equal(first.code, 0, first.out);
  assert.match(first.out, /Setup complete/);
  pass('fresh directory → running, bootstrapped installation with one command', url);
  const env = readFileSync(join(fresh, '.env'), 'utf8');
  const secretValues = readdirSync(join(fresh, 'secrets')).map(f => readFileSync(join(fresh, 'secrets', f), 'utf8').trim());
  assert(!secretValues.some(v => env.includes(v)), '.env must hold no secret value');
  const varlatchdConfig = execFileSync('docker', ['inspect', dc(fresh, ['ps', '-q', 'varlatchd'])], { encoding: 'utf8' });
  const runtimePassword = readFileSync(join(fresh, 'secrets/varlatch-runtime-password'), 'utf8').trim();
  assert(!secretValues.filter(v => v !== runtimePassword).some(v => varlatchdConfig.includes(v)), 'varlatchd holds only its own secrets');
  assert(!varlatchdConfig.includes(runtimePassword), 'even its own password arrives as a file, not configuration');
  pass('no secret value in .env or in varlatchd\'s configuration');
  assert.match(first.out, /deployment authority derived/, 'no admin key anywhere');
  pass('Application Plane deployed with a derived key');
  // The escrow blob must actually restore this installation's Root KEK.
  const [blob] = readdirSync(join(fresh, 'recovery'));
  assert(blob?.startsWith('varlatch-kek-escrow-'), 'escrow blob written');
  // Passphrase on the first stdin line, the blob after it: nothing in files
  // the container user cannot read, nothing on a command line.
  const restoredKek = execFileSync('docker', ['compose', 'exec', '-T', 'varlatchd', 'sh', '-c',
    'IFS= read -r VARLATCH_KEK_PASSPHRASE; export VARLATCH_KEK_PASSPHRASE; cat > /tmp/escrow.json; exec node dist/cli.js admin kek restore --in /tmp/escrow.json --out /tmp/restored-kek'],
    { cwd: fresh, input: `correct horse battery staple\n${readFileSync(join(fresh, 'recovery', blob), 'utf8')}`, encoding: 'utf8' });
  assert.match(restoredKek, /KEK written/, 'the escrow blob restores a KEK verified against the installation canary');
  assert.match(first.out, /✓ recorded as your attestation/);
  assert.match(first.out, /✓ Off-host recovery key copies \(operator attestation\)/, 'doctor shows the attestation');
  pass('passphrase escrow restores the Root KEK; custody recorded as an attestation');

  const before = secretsDigest(fresh);
  const rerun = await setup(fresh, ['--public-url', url]).exit;
  assert.equal(rerun.code, 0, rerun.out);
  assert.equal(secretsDigest(fresh), before, 'secrets unchanged');
  assert.match(rerun.out, /none regenerated/);
  assert.doesNotMatch(rerun.out, /\/enroll#/, 'no new enrollment link');
  assert.match(rerun.out, /nothing to change/, 'reconcile is a no-op');
  assert.match(rerun.out, /✓ attested: Root KEK/, 'escrow is not repeated');
  assert.equal(readdirSync(join(fresh, 'recovery')).length, 1, 'no second escrow blob');
  pass('rerun changes nothing: no secrets regenerated, no link, reconcile no-op, escrow kept');
  const other = await setup(fresh, ['--public-url', 'https://other.example.com']).exit;
  assert.notEqual(other.code, 0);
  assert.match(other.out, /re-enrollment event/);
  pass('a different public URL is refused (hostname change is its own procedure)');

  // ---- B. An admin without a passkey (interrupted enrollment / headless bootstrap).
  const pending = composeDir('pending');
  const portB = await freePort();
  const urlB = `http://localhost:${portB}`;
  const noWait = await setup(pending, ['--public-url', urlB, '--port', String(portB), '--no-wait']).exit;
  assert.equal(noWait.code, 3, noWait.out);
  dc(pending, ['exec', '-T', 'varlatchd', 'node', 'dist/cli.js', 'admin', 'bootstrap', '--cli-credential']);
  const resume = setup(pending, ['--enroll-timeout', '600', '--escrow', 'copy']);
  const recoveryLink = await resume.link;
  assert(recoveryLink?.includes('/enroll#vlt_recover_'), `a recovery link for the pending admin: ${recoveryLink}`);
  await enroll(recoveryLink);
  const resumed = await resume.exit;
  assert.equal(resumed.code, 4, `without confirmation escrow stays pending:\n${resumed.out}`);
  assert.match(resumed.out, /never finished enrolling/);
  assert.match(resumed.out, /escrow is pending/);
  pass('an admin without a passkey gets a recovery link; unconfirmed escrow stays pending (exit 4)');
  const confirmed = await setup(pending, ['--escrow', 'copy', '--attest']).exit;
  assert.equal(confirmed.code, 0, confirmed.out);
  assert.match(confirmed.out, /Setup complete/);
  pass('confirming custody completes setup');

  console.log(`PASS: varlatch setup (${results.length} checks)`);
} finally {
  for (const dir of dirs) { try { dc(dir, ['down', '-v', '--remove-orphans']); } catch {} }
  rmSync(work, { recursive: true, force: true });
}
