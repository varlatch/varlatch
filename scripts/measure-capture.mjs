#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Measures online capture (ADR-0036) at realistic audit-history sizes on a
// resource-limited stack: database and dump size, dump duration, disclosure
// latency during the capture against a baseline, and restore duration
// (including the Application Plane rebuild). Prints one markdown table.
//
// Prerequisites: Docker, workspace builds, and the candidate images
// varlatch-backup-test:local, varlatch-backup-web-test:local and
// varlatch-backup-convex-deploy-test:local (see the CI backup-recovery job).
//
// Environment (defaults in brackets):
//   MEASURE_SIZES        audit events per run      [100000,1000000,10000000]
//   MEASURE_PG_CPUS      postgres CPU limit        [2]
//   MEASURE_PG_MEMORY    postgres memory limit     [4g]
//   MEASURE_WORKERS      concurrent disclosers     [2]
//   MEASURE_PACE_MS      pause between requests    [250]
// The defaults stay under varlatchd's per-client limit of 600 requests a
// minute, so every error reported is something other than rate limiting.
//   MEASURE_BASELINE_S   baseline load duration    [20]
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { parseDocument } from 'yaml';
import { VarlatchClient } from '../packages/sdk/dist/index.js';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const cliPath = join(root, 'apps/cli/dist/varlatch.cjs');
const env = (name, fallback) => process.env[name] ?? fallback;
const sizes = env('MEASURE_SIZES', '100000,1000000,10000000').split(',').map(Number);
const pgCpus = env('MEASURE_PG_CPUS', '2'), pgMemory = env('MEASURE_PG_MEMORY', '4g');
const workers = Number(env('MEASURE_WORKERS', '2')), paceMs = Number(env('MEASURE_PACE_MS', '250'));
const baselineS = Number(env('MEASURE_BASELINE_S', '20'));
const images = { varlatchd: 'varlatch-backup-test:local', 'varlatch-migrate': 'varlatch-backup-test:local', 'varlatch-web': 'varlatch-backup-web-test:local', 'convex-deploy': 'varlatch-backup-convex-deploy-test:local' };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const rootKey = randomBytes(32).toString('hex'), bek = randomBytes(32).toString('hex');

function stack(name) {
  const where = mkdtempSync(join(tmpdir(), `varlatch-measure-${name}-`));
  mkdirSync(join(where, 'secrets')); mkdirSync(join(where, 'backups'));
  writeFileSync(join(where, 'secrets/root'), rootKey); writeFileSync(join(where, 'secrets/bek'), bek);
  cpSync(join(root, 'infra/compose/postgres-init'), join(where, 'postgres-init'), { recursive: true });
  cpSync(join(root, 'infra/compose/convex-supervisor.cjs'), join(where, 'convex-supervisor.cjs'));
  const doc = parseDocument(readFileSync(join(root, 'infra/compose/docker-compose.yml'), 'utf8'));
  doc.set('name', `vlt-measure-${name}-${randomBytes(3).toString('hex')}`);
  for (const [service, image] of Object.entries(images)) {
    doc.deleteIn(['services', service, 'build']); doc.setIn(['services', service, 'image'], image); doc.setIn(['services', service, 'pull_policy'], 'never');
  }
  // A small host: the database (and the dump, which runs in its container)
  // share one CPU/memory budget; varlatchd gets one CPU.
  doc.setIn(['services', 'postgres', 'deploy'], doc.createNode({ resources: { limits: { cpus: pgCpus, memory: pgMemory } } }));
  doc.setIn(['services', 'varlatchd', 'deploy'], doc.createNode({ resources: { limits: { cpus: '1', memory: '1g' } } }));
  writeFileSync(join(where, 'docker-compose.yml'), doc.toString({ lineWidth: 0 }));
  writeFileSync(join(where, '.env'), [
    'POSTGRES_SUPERUSER_PASSWORD=measure-superuser', 'VARLATCH_MIGRATE_PASSWORD=measure-migrate', 'VARLATCH_RUNTIME_PASSWORD=measure-runtime',
    'CONVEX_DB_PASSWORD=measure-convex', `CONVEX_INSTANCE_SECRET=${randomBytes(32).toString('hex')}`,
    'VARLATCHD_PORT=0', 'CONVEX_PORT=0', 'CONVEX_SITE_PORT=0', 'VARLATCH_WEB_PORT=0', 'VARLATCH_KEK_HOST_PATH=./secrets/root',
    'VARLATCH_PUBLIC_URL=http://localhost:8686', '',
  ].join('\n'));
  const dc = (args, opts = {}) => execFileSync('docker', ['compose', ...args], { cwd: where, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'], ...opts }).trim();
  const psql = sql => dc(['exec', '-T', 'postgres', 'psql', '-U', 'postgres', '-d', 'varlatch', '-v', 'ON_ERROR_STOP=1', '-Atc', sql]);
  return { where, dc, psql, url: () => `http://${dc(['port', 'varlatchd', '8686'])}` };
}
async function ready(url) { for (let i = 0; i < 600; i++) { try { if ((await fetch(`${url}/readyz`)).ok) return; } catch {} await sleep(500); } throw new Error('not ready'); }
function cli(where, args) {
  return new Promise(res => {
    const t = performance.now();
    const child = spawn('node', [cliPath, ...args, '--dir', where, '--bek-file', join(where, 'secrets/bek'), '--kek-file', join(where, 'secrets/root')]);
    let out = ''; child.stdout.on('data', d => { out += d; }); child.stderr.on('data', d => { out += d; });
    child.on('exit', code => res({ code, out, ms: performance.now() - t }));
  });
}
/** Paced disclosure load: every request commits an audit event, like real use. */
function load(api) {
  const latencies = []; const errors = {}; let stop = false;
  const done = Promise.all(Array.from({ length: workers }, async () => {
    while (!stop) {
      const t = performance.now();
      try { await api.discloseSecrets('measure', 'app', 'production', { items: ['DATABASE_URL', 'STRIPE_KEY', 'PORT'] }); latencies.push(performance.now() - t); }
      catch (e) { const code = e.code ?? e.name ?? 'error'; errors[code] = (errors[code] ?? 0) + 1; }
      await sleep(paceMs);
    }
  }));
  return { stop: async () => { stop = true; await done; return summarize(latencies, errors); } };
}
function summarize(latencies, errors) {
  const s = [...latencies].sort((a, b) => a - b);
  const p = q => (s.length ? s[Math.min(s.length - 1, Math.floor(q * s.length))] : NaN);
  const failed = Object.values(errors).reduce((a, b) => a + b, 0);
  return { requests: s.length + failed, errors: failed, errorCodes: errors, p50: p(0.5), p95: p(0.95), p99: p(0.99) };
}
const ms = x => (Number.isFinite(x) ? `${Math.round(x)} ms` : '—');
const secs = x => `${(x / 1000).toFixed(1)} s`;

async function measure(size) {
  const source = stack('src'), target = stack('dst');
  try {
    console.log(`--- ${size.toLocaleString('en')} audit events`);
    source.dc(['up', '-d', 'postgres', 'varlatch-migrate', 'varlatchd', 'convex-backend']);
    await ready(source.url());
    source.dc(['run', '--rm', 'convex-deploy']);
    const token = source.dc(['exec', '-T', 'varlatchd', 'node', 'dist/cli.js', 'admin', 'bootstrap', '--cli-credential']).match(/vlt_cli_\S+/)[0];
    let api = new VarlatchClient({ server: source.url(), token, maintenanceRetryMs: 0 });
    await api.createOrganization({ slug: 'measure', name: 'Measure' });
    await api.createProject('measure', { slug: 'app', name: 'App', contractAuthority: 'managed' });
    await api.createEnvironment('measure', 'app', { name: 'production', tier: 'production' });
    const items = ['DATABASE_URL', 'STRIPE_KEY', 'PORT'].map(name => ({ name, type: 'string', sensitive: name !== 'PORT', required: { kind: 'always' } }));
    const rev = await api.pushContractRevision('measure', 'app', { contract: { schemaVersion: 1, items } });
    await api.activateContractRevision('measure', 'app', rev.id);
    for (const [name, value] of [['DATABASE_URL', 'postgres://db.internal/app'], ['STRIPE_KEY', `sk_live_${randomBytes(16).toString('hex')}`], ['PORT', '3000']]) {
      await api.setValue('measure', 'app', 'production', name, { value });
    }

    // Seed audit history shaped like real disclosures, with varlatchd stopped
    // so the Mirror publisher starts from the end of it.
    source.dc(['stop', 'varlatchd']);
    const ids = JSON.parse(source.psql(`SELECT json_build_object('org', o.id, 'project', p.id, 'env', e.id, 'actor', (SELECT id FROM identities LIMIT 1))
      FROM organizations o JOIN projects p ON p.organization_id = o.id JOIN environments e ON e.project_id = p.id LIMIT 1`));
    const seedStart = performance.now();
    source.psql(`
      ALTER TABLE audit_events DISABLE TRIGGER audit_position_insert;
      INSERT INTO audit_events (id, event_type, occurred_at, actor_identity_id, organization_id, action, resource, decision, authz, listener, request_id, metadata, event_order)
      SELECT 'aud_seed_' || g, 'secret.disclosed', now() - (${size} - g) * interval '100 milliseconds', '${ids.actor}', '${ids.org}', 'secret.reveal',
        jsonb_build_object('projectId', '${ids.project}', 'environmentId', '${ids.env}'), 'allow',
        jsonb_build_object('grants', jsonb_build_array('grt_' || md5(g::text)), 'requirements', '[]'::jsonb, 'orgRole', 'member'),
        'ordinary', 'req_' || md5(g::text),
        jsonb_build_object('mode', 'requested', 'items', 'DATABASE_URL@val_' || left(md5('a' || g), 20) || ',STRIPE_KEY@val_' || left(md5('b' || g), 20) || ',PORT@val_' || left(md5('c' || g), 20), 'withheld', 0),
        (SELECT coalesce(max(event_order), 0) FROM audit_events) + g
      FROM generate_series(1, ${size}) g;
      UPDATE audit_position SET value = (SELECT max(event_order) FROM audit_events);
      ALTER TABLE audit_events ENABLE TRIGGER audit_position_insert;`);
    // Settle the bulk load now, so autovacuum does not run during the baseline.
    source.psql('VACUUM (ANALYZE) audit_events');
    const seedMs = performance.now() - seedStart;
    const dbBytes = Number(source.psql("SELECT pg_database_size('varlatch')"));
    source.dc(['start', 'varlatchd']);
    await ready(source.url());
    api = new VarlatchClient({ server: source.url(), token, maintenanceRetryMs: 0 });

    const warmup = load(api); // discarded: caches and connections
    await sleep(10_000);
    await warmup.stop();
    const baselineLoad = load(api);
    await sleep(baselineS * 1000);
    const baseline = await baselineLoad.stop();

    // The operator tooling alone, no capture: three control calls through
    // `docker compose exec`, as `backup create` makes them — isolates their cost.
    const toolingLoad = load(api);
    await sleep(1000);
    for (let i = 0; i < 3; i++) source.dc(['exec', '-T', 'varlatchd', 'node', 'dist/control-entry.js', 'status'], { input: '{}' });
    await sleep(1000);
    const tooling = await toolingLoad.stop();

    const archive = join(source.where, 'backups', 'measure.vltbak');
    const captureLoad = load(api);
    const capture = await cli(source.where, ['admin', 'backup', 'create', '--out', archive, '--timeout-seconds', '7200']);
    const during = await captureLoad.stop();
    assert.equal(capture.code, 0, capture.out);
    const held = capture.out.match(/snapshot held ([\d.]+) s \(dump ([\d.]+) s, ([\d.]+) MiB\)/);
    assert(held, capture.out);

    const restore = await cli(target.where, ['admin', 'backup', 'restore', '--in', archive]);
    assert.equal(restore.code, 0, restore.out);
    await ready(target.url());
    const restored = new VarlatchClient({ server: target.url(), token });
    assert.match((await restored.discloseSecrets('measure', 'app', 'production', { items: ['STRIPE_KEY'] })).items[0].value, /^sk_live_/);

    const result = {
      size, dbBytes, seedMs, archiveBytes: statSync(archive).size,
      snapshotHeldS: Number(held[1]), dumpS: Number(held[2]), dumpMiB: Number(held[3]), captureCommandMs: capture.ms,
      baseline, tooling, during, restoreMs: restore.ms,
    };
    console.log(JSON.stringify(result));
    return result;
  } finally {
    for (const s of [source, target]) { try { s.dc(['down', '-v', '--remove-orphans']); } catch {} rmSync(s.where, { recursive: true, force: true }); }
  }
}

const results = [];
for (const size of sizes) results.push(await measure(size));
console.log(`\nPostgres limited to ${pgCpus} CPU / ${pgMemory} (the dump runs in its container), varlatchd to 1 CPU / 1 GB;`);
console.log(`${workers} paced disclosers (${paceMs} ms pause), each disclosure committing an audit event.`);
console.log(`Errors by code: ${results.map(r => `${r.size}: ${JSON.stringify({ baseline: r.baseline.errorCodes, tooling: r.tooling.errorCodes, during: r.during.errorCodes })}`).join('; ')}\n`);
console.log('| Audit events | Database | Dump | Snapshot held (dump) | Disclosure p50 / p95 / p99: baseline | tooling only | during `backup create` | Errors during | Restore (incl. rebuild) |');
console.log('|---|---|---|---|---|---|---|---|---|');
const lat = l => `${ms(l.p50)} / ${ms(l.p95)} / ${ms(l.p99)}`;
for (const r of results) {
  console.log(`| ${r.size.toLocaleString('en')} | ${(r.dbBytes / 1024 ** 3).toFixed(2)} GiB | ${r.dumpMiB.toFixed(0)} MiB | ${r.snapshotHeldS.toFixed(1)} s (${r.dumpS.toFixed(1)} s) | ${lat(r.baseline)} | ${lat(r.tooling)} | ${lat(r.during)} | ${r.during.errors} of ${r.during.requests} | ${secs(r.restoreMs)} |`);
}
