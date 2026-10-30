#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Measures deleting an Organization (ADR-0051 Decision 6) on a
// resource-limited PostgreSQL: how long the finalization transaction takes
// at realistic sizes, and how long another Organization's audited writes
// take meanwhile, against a baseline. Prints one markdown table.
//
// varlatchd's own code runs in this process against a throwaway PostgreSQL
// container, which is removed at the end. Nothing else is contacted.
//
// Prerequisites: Docker, and the workspace build (pnpm build).
//
// Environment (defaults in brackets):
//   MEASURE_VERSIONS     value versions in the deleted Organization, per run  [100000,1000000]
//   MEASURE_PG_CPUS      postgres CPU limit                                   [2]
//   MEASURE_PG_MEMORY    postgres memory limit                                [4g]
//   MEASURE_PACE_MS      pause after each of the probe's writes (one client) [250]
//   MEASURE_BASELINE_S   probe duration before the deletion                   [10]
//
// The deleted Organization: 20 projects of 5 environments, every item with 5
// versions, 25 people (one admin) with 3 Grants each, 10 machine identities,
// 10 integrations and 2 webhooks. Its values are copies of one real
// encrypted value; finalization never decrypts them.
//
// Percentiles are the sorted sample at index floor(p × n), the maximum for
// p = 100. Lock waits are sampled from pg_stat_activity every 20 ms during
// finalization: a wait shorter than that can go unseen.
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { issueCredential } from '../services/varlatchd/dist/auth/credentials.js';
import { runMigrations } from '../services/varlatchd/dist/db/migrate.js';
import { createPgQuerier } from '../services/varlatchd/dist/db/pg.js';
import { consumeSetupGrant, ensureInstallation, issueBootstrapGrant, issueInviteGrant } from '../services/varlatchd/dist/domain/bootstrap.js';
import { finalizeDeletion } from '../services/varlatchd/dist/domain/orgdeletion.js';
import { buildApp } from '../services/varlatchd/dist/http/app.js';

const env = (name, fallback) => process.env[name] ?? fallback;
const sizes = env('MEASURE_VERSIONS', '100000,1000000').split(',').map(Number);
const pgCpus = env('MEASURE_PG_CPUS', '2'), pgMemory = env('MEASURE_PG_MEMORY', '4g');
const paceMs = Number(env('MEASURE_PACE_MS', '250'));
const baselineS = Number(env('MEASURE_BASELINE_S', '10'));
const PROJECTS = 20, ENVIRONMENTS = 5, VERSIONS = 5, PEOPLE = 25, MACHINES = 10, TARGETS = 10;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const docker = args => execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();

/** Starts the container; the caller removes it, whatever happens after this. */
function startPostgres() {
  const name = `varlatch-measure-deletion-${randomBytes(3).toString('hex')}`;
  docker(['run', '-d', '--rm', '--name', name, '--cpus', pgCpus, '--memory', pgMemory, '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-p', '127.0.0.1::5432', 'postgres:17.6']);
  return name;
}

/** Waits until the container accepts connections, every check bounded in time. */
async function readyPostgres(name) {
  for (let i = 0; i < 120; i++) {
    try {
      execFileSync('docker', ['exec', name, 'pg_isready', '-U', 'postgres', '-h', '127.0.0.1', '-t', '2'], { stdio: 'ignore', timeout: 5000 });
      const port = docker(['port', name, '5432']).split(':').pop();
      return `postgres://postgres@127.0.0.1:${port}/postgres`;
    } catch {
      await sleep(500);
    }
  }
  throw new Error('PostgreSQL did not start');
}

function percentiles(latencies) {
  const sorted = [...latencies].sort((a, b) => a - b);
  const at = p => sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))] ?? NaN;
  return `${at(50).toFixed(0)} / ${at(95).toFixed(0)} / ${(sorted[sorted.length - 1] ?? NaN).toFixed(0)} ms`;
}

async function measure(versions) {
  const items = Math.max(1, Math.round(versions / (PROJECTS * ENVIRONMENTS * VERSIONS)));
  const name = startPostgres();
  let db = null;
  // The probe and the lock sampler run beside the measurement: their
  // failures are kept and rethrown, and both are stopped and settled
  // before the pool closes and the container goes.
  const background = { stop: false, failures: [], tasks: [] };
  const beside = (task) => background.tasks.push(task().catch((err) => background.failures.push(err)));
  try {
    db = createPgQuerier(await readyPostgres(name));
    const connection = await db.connect();
    try {
      await runMigrations(connection);
    } finally {
      connection.release();
    }
    const ctx = { db, rootKek: randomBytes(32) };
    await ensureInstallation(ctx);
    const adminId = (await consumeSetupGrant(ctx, (await issueBootstrapGrant(ctx)).token, {})).identityId;
    const token = (await issueCredential(db, { identityId: adminId, kind: 'cli' })).token;
    // Seeding and the probe count as separate clients for the per-client
    // request limit (600 a minute), as two machines would.
    const app = buildApp(ctx, { clientAddress: c => c.req.header('x-measure-client') ?? 'seed' });
    const call = async (method, path, body) => {
      const res = await app.request(path, {
        method,
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      const json = await res.json().catch(() => null);
      if (res.status >= 300) throw new Error(`${method} ${path}: ${res.status} ${JSON.stringify(json)}`);
      return json;
    };
    const contract = { schemaVersion: 1, items: [{ name: 'TOKEN', required: { kind: 'never' }, sensitive: true, type: 'string' }] };
    const project = async (org, slug) => {
      await call('POST', `/v1/organizations/${org}/projects`, { slug, name: slug, contractAuthority: 'managed' });
      const revision = await call('POST', `/v1/organizations/${org}/projects/${slug}/contract/revisions`, { contract });
      await call('POST', `/v1/organizations/${org}/projects/${slug}/contract/revisions/${revision.id}/activate`, {});
    };

    // The probe's Organization: one environment, one item, written again and again.
    await call('POST', '/v1/organizations', { slug: 'other', name: 'Other' });
    await project('other', 'api');
    await call('POST', '/v1/organizations/other/projects/api/environments', { name: 'development', tier: 'development' });
    const PROBE = '/v1/organizations/other/projects/api/environments/development/values/TOKEN';

    // The deleted Organization.
    const big = await call('POST', '/v1/organizations', { slug: 'big', name: 'Big' });
    const environmentIds = [];
    for (let p = 0; p < PROJECTS; p++) {
      await project('big', `p${p}`);
      for (let e = 0; e < ENVIRONMENTS; e++) {
        environmentIds.push((await call('POST', `/v1/organizations/big/projects/p${p}/environments`, { name: `env${e}`, tier: e === 0 ? 'production' : 'development' })).id);
      }
    }
    await call('PUT', '/v1/organizations/big/projects/p0/environments/env0/values/TOKEN', { value: randomBytes(24).toString('base64url') });
    const template = (await db.query('SELECT payload, wrapped_dek FROM value_versions ORDER BY created_at LIMIT 1')).rows[0];
    await db.query(
      `INSERT INTO env_values (id, environment_id, item_name)
       SELECT 'val_m' || e.n || '_' || g, e.id, 'ITEM_' || g
       FROM unnest($1::text[]) WITH ORDINALITY AS e(id, n), generate_series(1, $2) g`,
      [environmentIds, items],
    );
    await db.query(
      `INSERT INTO value_versions (id, value_id, payload, wrapped_dek, created_by)
       SELECT v.id || '_' || n, v.id, $1, $2, $3 FROM env_values v, generate_series(1, $4) n WHERE v.id LIKE 'val_m%'`,
      [JSON.stringify(template.payload), JSON.stringify(template.wrapped_dek), adminId, VERSIONS],
    );
    await db.query(`UPDATE env_values SET current_version_id = id || '_' || $1 WHERE id LIKE 'val_m%'`, [VERSIONS]);
    const projects = (await call('GET', '/v1/organizations/big/projects')).items;
    for (let i = 0; i < PEOPLE - 1; i++) {
      const invite = await issueInviteGrant(ctx, { organizationId: big.id, role: 'member', name: `Person ${i}` }, adminId);
      const person = (await consumeSetupGrant(ctx, invite.token, {})).identityId;
      for (let g = 0; g < 3; g++) {
        const scope = { kind: 'project', projectId: projects[(i + g) % projects.length].id };
        await call('POST', '/v1/organizations/big/grants', { subjectIdentityId: person, scope, actions: ['environment.read', 'secret.reveal'] });
      }
    }
    for (let m = 0; m < MACHINES; m++) await call('POST', '/v1/organizations/big/identities', { name: `machine-${m}`, kind: 'service' });
    const connectionId = (await call('POST', '/v1/organizations/big/platform-connections', { platform: 'coolify', baseIdentity: 'https://coolify.example.com', name: 'c', credential: 'token-c' })).id;
    for (let t = 0; t < TARGETS; t++) {
      await call('POST', `/v1/organizations/big/projects/p${t}/environments/env1/sync-targets`, { connectionId, destination: { applicationUuid: `app${t}` }, mapping: { kind: 'wildcard' } });
    }
    for (let w = 0; w < 2; w++) await call('POST', '/v1/organizations/big/webhooks', { url: `https://sink.example/hooks/${w}` });
    const dbSize = (await db.query('SELECT pg_size_pretty(pg_database_size(current_database())) AS size')).rows[0].size;
    const seeded = (await db.query("SELECT count(*)::int AS n FROM value_versions v JOIN env_values e ON e.id = v.value_id JOIN environments n ON n.id = e.environment_id JOIN projects p ON p.id = n.project_id WHERE p.organization_id = $1", [big.id])).rows[0].n;
    await db.query('VACUUM ANALYZE');

    // Probe: one client, one audited write at a time, paced.
    const probe = { samples: [], errors: 0 };
    beside(async () => {
      while (!background.stop) {
        const started = performance.now();
        const res = await app.request(PROBE, { method: 'PUT', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'x-measure-client': 'probe' }, body: JSON.stringify({ value: randomBytes(24).toString('base64url') }) });
        await res.arrayBuffer();
        const ended = performance.now();
        if (res.status !== 200) probe.errors += 1;
        probe.samples.push({ started, ended, ms: ended - started });
        await sleep(paceMs);
      }
    });
    await sleep(baselineS * 1000);
    const baselineEnd = performance.now();

    const scheduleStart = performance.now();
    const scheduled = await call('POST', '/v1/organizations/big/deletion', {});
    const scheduleMs = performance.now() - scheduleStart;
    await db.query("UPDATE organization_deletions SET scheduled_at = now() - interval '8 days', run_after = now() - interval '1 minute' WHERE id = $1", [scheduled.id]);
    await sleep(1000);
    // Lock waits of any session while finalization runs, sampled every 20 ms:
    // the probe may wait on disk, but should never wait on a lock.
    let lockWaits = 0;
    let sampling = true;
    beside(async () => {
      while (sampling && !background.stop) {
        lockWaits += (await db.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE wait_event_type = 'Lock'")).rows[0].n;
        await sleep(20);
      }
    });
    const finalizeStart = performance.now();
    const outcome = await finalizeDeletion(ctx, scheduled.id, big.id);
    const finalizeEnd = performance.now();
    sampling = false;
    if (!outcome) throw new Error('finalization did not run');
    await sleep(2000);
    background.stop = true;
    await Promise.all(background.tasks);
    if (background.failures.length > 0) throw background.failures[0];

    const baseline = probe.samples.filter(s => s.ended <= baselineEnd).map(s => s.ms);
    const during = probe.samples.filter(s => s.ended >= finalizeStart && s.started <= finalizeEnd).map(s => s.ms);
    const erased = (await db.query('SELECT count(*)::int AS n FROM value_versions WHERE erased_at IS NOT NULL')).rows[0].n;
    if (erased !== seeded) throw new Error(`erased ${erased} of ${seeded} versions`);
    return {
      versions: seeded,
      dbSize,
      scheduleMs,
      finalizeMs: finalizeEnd - finalizeStart,
      baseline: percentiles(baseline),
      during: percentiles(during),
      duringCount: during.length,
      errors: probe.errors,
      lockWaits,
    };
  } finally {
    background.stop = true;
    await Promise.allSettled(background.tasks);
    await db?.end().catch(() => {});
    try {
      docker(['rm', '-f', name]);
    } catch {}
  }
}

const rows = [];
for (const size of sizes) {
  console.error(`measuring ${size} value versions…`);
  rows.push(await measure(size));
}
console.log(`PostgreSQL limited to ${pgCpus} CPUs / ${pgMemory}; one probe client in another Organization, pausing ${paceMs} ms after each write.\n`);
console.log('| Value versions | Database | Scheduling | Finalization | Probe p50 / p95 / max, baseline | … during finalization (writes) | Failed probe writes | Lock waits sampled |');
console.log('|---|---|---|---|---|---|---|---|');
for (const r of rows) {
  console.log(`| ${r.versions.toLocaleString('en-US')} | ${r.dbSize} | ${(r.scheduleMs / 1000).toFixed(1)} s | ${(r.finalizeMs / 1000).toFixed(1)} s | ${r.baseline} | ${r.during} (${r.duringCount}) | ${r.errors} | ${r.lockWaits} |`);
}
