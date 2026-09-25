// SPDX-License-Identifier: Apache-2.0
import { AsyncLocalStorage } from 'node:async_hooks';
import { spawn } from 'node:child_process';
import { createReadStream, createWriteStream, readFileSync, existsSync, writeFileSync } from 'node:fs';
import { mkdir, mkdtemp, rm, stat } from 'node:fs/promises';
import { join, resolve, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash, randomUUID } from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import {
  BackupError, EMBEDDED_RELEASE, releaseSchema, manifestSchema, describeComponents, sealArchive, CURRENT_FORMAT,
  openArchive, verifyManifest, parseKey, distinctKeys, type ArchiveFormat, type Bek, type Gate, type Manifest, type Release, type BackupStatus,
} from '@varlatch/backup';
import { destinationsSchema, credentialsSchema, uploadArchive, downloadArchive } from '@varlatch/backup/s3';

const operationContext = new AsyncLocalStorage<{ lost: boolean; children: Set<ReturnType<typeof spawn>> }>();
/** Kernel lock on the shared state volume, released on operator death. The
 * restore gate is deliberately separate and remains after this lock is lost. */
export async function withOperatorLock<T>(dir: string, run: () => Promise<T>, legacy = false): Promise<T> {
  if (!legacy) await ensureNamespaceOwner(dir);
  const state = { lost: false, children: new Set<ReturnType<typeof spawn>>() };
  const lockArgs = legacy
    ? ['compose', 'exec', '-T', 'postgres', 'flock', '-n', '/var/lib/postgresql/data/varlatch-backup-bridge.lock', 'sh', '-c', 'printf "locked\\n"; cat >/dev/null']
    : ['compose', 'run', '--rm', '--no-deps', '-T', '--entrypoint', 'flock', 'varlatchd', '-n', '/var/lib/varlatch/backup-operation.lock', 'node', '-e', 'process.stdin.resume(); process.stdin.on("end",()=>process.exit(0)); console.log("locked")'];
  const holder = spawn('docker', lockArgs, { cwd: dir, stdio: ['pipe', 'pipe', 'pipe'] });
  let holderErr = '';
  holder.stderr.on('data', (chunk: Buffer) => { holderErr = (holderErr + chunk.toString()).slice(-8192); });
  holder.stdin.on('error', () => {});
  let finished = false;
  const abort = () => { if (!finished) { state.lost = true; for (const child of state.children) child.kill('SIGTERM'); } };
  holder.on('close', abort); holder.on('error', abort);
  process.on('SIGINT', abort); process.on('SIGTERM', abort);
  try {
    await new Promise<void>((resolveLocked, reject) => {
      const timer = setTimeout(() => { holder.kill(); reject(new BackupError('Timed out acquiring the operator lock')); }, 30_000);
      holder.stdout.once('data', data => { clearTimeout(timer); if (String(data).trim() === 'locked') resolveLocked(); else reject(new BackupError('Invalid operator lock response')); });
      holder.once('close', () => { clearTimeout(timer); reject(new BackupError(`Could not acquire the operator lock: another backup/restore may own this installation, or Compose failed. ${recordDiagnostics(dir, lockArgs, holderErr)}`)); });
      holder.once('error', () => { clearTimeout(timer); reject(new BackupError('Docker Compose is unavailable')); });
    });
    return await operationContext.run(state, run);
  } finally {
    finished = true; holder.stdin.end();
    process.off('SIGINT', abort); process.off('SIGTERM', abort);
  }
}
/** Bounded child stderr goes to an operator-only file, never to output: it can
 * contain connection strings. Returns the pointer sentence for the error. */
function recordDiagnostics(dir: string, args: string[], stderrTail: string): string {
  const path = join(dir, 'backup-diagnostics.log');
  try {
    writeFileSync(path, `# ${new Date().toISOString()} docker ${args.join(' ')}\n${stderrTail || '(no stderr captured)'}\n`, { mode: 0o600 });
    return `Diagnostics: ${path}`;
  } catch { return 'Diagnostics could not be written; inspect service logs.'; }
}
const option = (args: string[], name: string) => { const i = args.indexOf(name); return i < 0 ? undefined : args[i + 1]; };
function required(args: string[], name: string): string {
  const value = option(args, name); if (!value || value.startsWith('--')) throw new BackupError(`Supply ${name}`); return value;
}
export interface ProcessOptions { input?: string; inputFile?: string; outputFile?: string; timeoutMs?: number; operatorJsonErrors?: boolean; }
/** No shell interpolation and no child stderr/connection strings in operator output. */
export async function compose(dir: string, args: string[], options: ProcessOptions = {}): Promise<string> {
  return dockerCommand(dir, ['compose', ...args], options);
}
export async function dockerCommand(dir: string, args: string[], options: ProcessOptions = {}): Promise<string> {
  const operation = operationContext.getStore();
  if (operation?.lost) throw new BackupError('Operator execution interrupted or lock lost; restore remains isolated');
  const child = spawn('docker', args, { cwd: dir, stdio: ['pipe', 'pipe', 'pipe'] });
  operation?.children.add(child);
  const timer = setTimeout(() => child.kill('SIGTERM'), options.timeoutMs ?? 30 * 60_000);
  let text = ''; let oversized = false;
  // stderr may carry connection strings/credentials: never in operator output,
  // but a bounded tail goes to an operator-only diagnostics file on failure —
  // a generic error with no trail costs hours of blind debugging.
  let errTail = '';
  child.stderr.on('data', (chunk: Buffer) => { errTail = (errTail + chunk.toString()).slice(-8192); });
  const ended = new Promise<void>((resolveDone, reject) => {
    child.once('error', () => reject(new BackupError('Docker Compose could not be started')));
    child.once('close', code => code === 0 && !oversized ? resolveDone() : reject(new BackupError(`Compose ${args[1] ?? args[0]} failed; installation may remain isolated. ${recordDiagnostics(dir, args, errTail)}`)));
  });
  const streams: Promise<unknown>[] = [ended];
  if (options.outputFile) streams.push(pipeline(child.stdout, createWriteStream(options.outputFile, { flags: 'wx', mode: 0o600 })));
  else child.stdout.on('data', (chunk: Buffer) => { text += chunk.toString(); if (text.length > 1024 * 1024) { oversized = true; child.kill(); } });
  if (options.inputFile) streams.push(pipeline(createReadStream(options.inputFile), child.stdin));
  else { child.stdin.on('error', () => {}); child.stdin.end(options.input ?? ''); }
  try { await Promise.all(streams); return text.trim(); }
  catch (e) {
    child.kill();
    if (options.operatorJsonErrors) {
      let diagnostic: unknown;
      try { diagnostic = JSON.parse(text).error; } catch { /* use generic process failure */ }
      if (typeof diagnostic === 'string') throw new BackupError(diagnostic);
    }
    throw e;
  }
  finally { clearTimeout(timer); operation?.children.delete(child); }
}
/**
 * In the Tailscale topology (ADR-0014) varlatchd has no network of its own: it
 * joins the sidecar's namespace (`network_mode: service:<sidecar>`). Compose
 * cannot create a `--no-deps` varlatchd container — the operator lock, offline
 * restore control, the restore bring-up — while that sidecar container is
 * missing, which made fresh-host restores into this topology fail. Returns
 * the sidecar's service name, or null for the canonical topology.
 */
async function namespaceOwner(dir: string): Promise<string | null> {
  let config: { services?: Record<string, { network_mode?: string }> };
  try { config = JSON.parse(await compose(dir, ['config', '--format', 'json'])); } catch { return null; }
  return config.services?.varlatchd?.network_mode?.match(/^service:(.+)$/)?.[1] ?? null;
}
/** Create/start the sidecar if needed. Never recreates a running one: that
 * would cut an already-running varlatchd off from its network namespace. */
async function ensureNamespaceOwner(dir: string): Promise<string | null> {
  const owner = await namespaceOwner(dir);
  if (owner) await compose(dir, ['up', '-d', '--no-deps', '--no-recreate', owner]);
  return owner;
}
/** Whether the running image has the light control entry (per Compose directory). */
const lightControl = new Map<string, boolean>();
async function control<T>(dir: string, command: string, input: unknown = {}, offline = false): Promise<T> {
  // A running daemon is reached through the minimal control client: the full
  // CLI costs ~0.8 s of CPU to load, taken from the daemon's requests. Older
  // images only have the full CLI.
  if (!offline && !lightControl.has(dir)) {
    lightControl.set(dir, await compose(dir, ['exec', '-T', 'varlatchd', 'test', '-f', 'dist/control-entry.js']).then(() => true, () => false));
  }
  const args = offline
    ? ['run', '--rm', '--no-deps', '-T', 'varlatchd', 'admin', 'backup-control', command]
    : lightControl.get(dir)
      ? ['exec', '-T', 'varlatchd', 'node', 'dist/control-entry.js', command]
      : ['exec', '-T', 'varlatchd', 'node', 'dist/cli.js', 'admin', 'backup-control', command];
  return JSON.parse(await compose(dir, args, { input: JSON.stringify(input), operatorJsonErrors: true })) as T;
}
async function waitFor(test: () => Promise<boolean>, deadline: number): Promise<void> {
  while (Date.now() < deadline) { if (await test()) return; await new Promise(r => setTimeout(r, 200)); }
  throw new BackupError('Maintenance deadline exceeded; capture is invalid or restore remains isolated');
}
async function convexStopped(dir: string, id: string, deadline: number): Promise<void> {
  await waitFor(async () => {
    const state = await control<{ gate: Gate }>(dir, 'gate', { id });
    if (state.gate.id !== id) throw new BackupError('Capture ownership lost');
    try {
      const ack = JSON.parse(await compose(dir, ['exec', '-T', 'convex-backend', 'cat', '/var/lib/varlatch/convex-ack.json']));
      return ack.id === id && ack.stopped === true;
    } catch { return false; }
  }, deadline);
}
export function loadBek(args: string[]): Bek {
  const key = option(args, '--bek-file'), passphrase = option(args, '--bek-passphrase-file');
  if (!!key === !!passphrase) throw new BackupError('Supply exactly one of --bek-file or --bek-passphrase-file');
  return key ? { kind: 'key', material: parseKey(readFileSync(key, 'utf8')) } : { kind: 'passphrase', material: Buffer.from(readFileSync(passphrase!, 'utf8').replace(/\r?\n$/, '')) };
}
function candidateKeys(args: string[], versions: number[]): Map<number, Buffer> {
  const file = required(args, '--kek-file');
  // v1 capture deliberately permits exactly one required Root KEK version.
  if (versions.length !== 1) throw new BackupError('This verifier requires per-version candidate support for mixed-key archives');
  return new Map([[versions[0]!, parseKey(readFileSync(file === '-' ? 0 : file, 'utf8'))]]);
}
export function targetRelease(args: string[]): Release {
  const path = option(args, '--target-release');
  try { return path ? releaseSchema.parse(JSON.parse(readFileSync(path, 'utf8'))) : EMBEDDED_RELEASE; }
  catch { throw new BackupError('Target release manifest lacks supported compatibility metadata'); }
}
function statusOf(manifest: Manifest): BackupStatus {
  return { archiveId: manifest.archiveId, installationId: manifest.installationId, createdAt: manifest.createdAt, release: manifest.release.version, requiredKeyVersions: manifest.requiredKeyVersions };
}
function destination(args: string[], dir: string) {
  const name = required(args, '--destination');
  const config = option(args, '--destinations-file') ?? join(dir, 'backup-destinations.json');
  const all = destinationsSchema.parse(JSON.parse(readFileSync(config, 'utf8')));
  const dest = all[name]; if (!dest) throw new BackupError('Unknown backup destination');
  return { name, dest, configDir: dirname(resolve(config)) };
}
function credentials(path: string) { return credentialsSchema.parse(JSON.parse(readFileSync(path, 'utf8'))); }
export async function createBackup(args: string[], dir: string): Promise<string> {
  const legacy = option(args, '--legacy-release');
  if (legacy) {
    const { captureLegacyBackup } = await import('./legacyBackup.js');
    return withOperatorLock(dir, () => captureLegacyBackup(args, dir, legacy), true);
  }
  return withOperatorLock(dir, () => captureBackup(args, dir));
}
type CaptureMetadata = Omit<Manifest, 'formatVersion' | 'archiveId' | 'createdAt' | 'components'>;
interface Captured { format: ArchiveFormat; metadata: CaptureMetadata; createdAt: string; metrics?: NonNullable<BackupStatus['capture']> }
interface OnlineStarted { id: string; snapshot: string; role: string; application: string; createdAt: string; expiresAt: number; metadata: CaptureMetadata }

/** The supplied custody copy must match before any dump is taken. */
function checkCandidateKey(metadata: CaptureMetadata, bek: Bek, key: Buffer): void {
  const check = verifyManifest({ ...metadata, formatVersion: CURRENT_FORMAT, archiveId: randomUUID(), createdAt: new Date().toISOString(), components: [{ name: 'secret-plane.dump', bytes: 0, sha256: '0'.repeat(64) }] }, metadata.release, bek, new Map([[metadata.requiredKeyVersions[0]!, key]]));
  if (!check.keyMatch) throw new BackupError('Candidate Root KEK does not match the installation');
}

/**
 * Online capture (ADR-0036): one exported snapshot of the Secret Plane,
 * dumped while the installation keeps serving. Returns null when the
 * running daemon predates it (the caller then uses the frozen capture).
 */
async function captureOnline(dir: string, scratch: string, timeoutMs: number, bek: Bek, key: Buffer): Promise<Captured | null> {
  let capture: OnlineStarted | undefined;
  try {
    capture = await control<OnlineStarted>(dir, 'online-capture-begin', { ttlMs: timeoutMs });
  } catch (e) {
    if (e instanceof BackupError && /Unknown backup control command/.test(e.message)) return null;
    throw e;
  }
  const held = Date.now();
  try {
    checkCandidateKey(capture.metadata, bek, key);
    // As the daemon's own role (so it can stop the dump when the lease
    // expires) and under the capture's application_name.
    const conninfo = `dbname=varlatch user=${capture.role} application_name=${capture.application}`;
    const dumpStart = Date.now();
    await compose(dir, ['exec', '-T', 'postgres', 'pg_dump', '-Fc', '--snapshot', capture.snapshot, '-d', conninfo],
      { outputFile: join(scratch, 'secret-plane.dump'), timeoutMs: Math.max(1, capture.expiresAt - Date.now()) });
    const dumpMs = Date.now() - dumpStart;
    // Positive confirmation: still valid, exclusion still held. Otherwise discard.
    await control(dir, 'online-capture-finish', { id: capture.id });
    const done = capture; capture = undefined;
    const metrics = { mode: 'online' as const, snapshotHeldMs: Date.now() - held, dumpMs, dumpBytes: (await stat(join(scratch, 'secret-plane.dump'))).size };
    console.log(`Captured online: snapshot held ${(metrics.snapshotHeldMs / 1000).toFixed(1)} s (dump ${(dumpMs / 1000).toFixed(1)} s, ${(metrics.dumpBytes / 1024 ** 2).toFixed(1)} MiB); the installation kept serving.`);
    return { format: 2, metadata: done.metadata, createdAt: done.createdAt, metrics };
  } finally {
    if (capture) await control(dir, 'online-capture-abort', { id: capture.id }).catch(() => {});
  }
}

/** Frozen capture (ADR-0033): for daemons older than online capture, e.g. the release an upgrade starts from. */
async function captureFrozen(dir: string, scratch: string, timeoutMs: number, bek: Bek, key: Buffer): Promise<Captured> {
  let gate: Gate | undefined;
  try {
    gate = await control<Gate>(dir, 'capture-begin', { ttlMs: timeoutMs });
    const metadata = await control<CaptureMetadata>(dir, 'capture-pause', { id: gate.id });
    checkCandidateKey(metadata, bek, key);
    await convexStopped(dir, gate.id, gate.expiresAt!);
    const createdAt = new Date().toISOString();
    for (const [database, name] of [['varlatch', 'secret-plane.dump'], ['convex_self_hosted', 'application-plane.dump']] as const) {
      await control(dir, 'gate', { id: gate.id });
      await compose(dir, ['exec', '-T', 'postgres', 'pg_dump', '-U', 'postgres', '-Fc', database], { outputFile: join(scratch, name), timeoutMs: Math.max(1, gate.expiresAt! - Date.now()) });
    }
    // Convex's module/file storage must be captured at the same stopped checkpoint.
    await compose(dir, ['exec', '-T', 'convex-backend', 'tar', '-C', '/convex/data/storage', '-cf', '-', '.'], { outputFile: join(scratch, 'convex-storage.tar'), timeoutMs: Math.max(1, gate.expiresAt! - Date.now()) });
    await control(dir, 'capture-finish', { id: gate.id }); gate = undefined;
    return { format: 1, metadata, createdAt };
  } finally {
    if (gate) await control(dir, 'capture-finish', { id: gate.id }).catch(() => {});
  }
}

async function captureBackup(args: string[], dir: string): Promise<string> {
  const bek = loadBek(args);
  const key = parseKey(readFileSync(required(args, '--kek-file'), 'utf8'));
  distinctKeys(bek, [key]);
  const archiveId = randomUUID();
  const output = resolve(option(args, '--out') ?? join(dir, 'backups', `${archiveId}.vltbak`));
  if (existsSync(output)) throw new BackupError('Output already exists');
  await mkdir(dirname(output), { recursive: true, mode: 0o700 });
  const scratch = await mkdtemp(join(option(args, '--scratch-dir') ?? tmpdir(), 'varlatch-capture-'));
  const timeoutMs = Number(option(args, '--timeout-seconds') ?? '300') * 1000;
  try {
    const captured = await captureOnline(dir, scratch, timeoutMs, bek, key)
      ?? await captureFrozen(dir, scratch, timeoutMs, bek, key);
    const manifest = manifestSchema.parse({ ...captured.metadata, formatVersion: captured.format, archiveId, createdAt: captured.createdAt, components: await describeComponents(scratch, captured.format) });
    await sealArchive(scratch, manifest, bek, output);
    const status: BackupStatus = { ...statusOf(manifest), ...(captured.metrics ? { capture: captured.metrics } : {}) };
    await control(dir, 'record', { status });
    console.log(`Archive created: ${output} (${archiveId})`);
    if (option(args, '--destination')) {
      const { name, dest, configDir } = destination(args, dir);
      await uploadArchive(dest, credentials(resolve(configDir, dest.writeCredentialsFile)), archiveId, output);
      status.delivery = { destination: name, uploadedAt: new Date().toISOString() };
      await control(dir, 'record', { status });
      console.log(`Upload completed to ${name}; remote retrieval has not been verified.`);
    }
    return output;
  } finally {
    key.fill(0); bek.material.fill(0);
    await rm(scratch, { recursive: true, force: true });
  }
}
export async function verifyBackup(args: string[], dir: string, target = targetRelease(args)): Promise<Manifest> {
  const bek = loadBek(args);
  const remote = option(args, '--destination');
  const scratch = await mkdtemp(join(option(args, '--scratch-dir') ?? tmpdir(), 'varlatch-verify-'));
  try {
    let path: string;
    if (remote) {
      const { dest } = destination(args, dir);
      path = join(scratch, 'remote.vltbak');
      await downloadArchive(dest, credentials(required(args, '--read-credentials-file')), required(args, '--archive'), path);
    } else path = required(args, '--in');
    return await openArchive(path, bek, async manifest => {
      if (remote && manifest.archiveId !== required(args, '--archive')) throw new BackupError('Remote object has a different archive identity');
      const keys = candidateKeys(args, manifest.requiredKeyVersions);
      let result;
      try { result = verifyManifest(manifest, target, bek, keys); } finally { for (const key of keys.values()) key.fill(0); }
      console.log(JSON.stringify({ archiveId: manifest.archiveId, ...result, message: Object.values({ integrity: result.integrity, compatibility: result.compatibility, keyMatch: result.keyMatch }).every(Boolean) ? 'checks passed' : 'checks failed' }));
      if (args.includes('--record')) {
        const status = { ...statusOf(manifest), verification: result };
        if (remote) {
          // Retrieval does not assert a prior upload timestamp that we never observed.
          const stored = await control<{ archives: BackupStatus[] }>(dir, 'status');
          const existing = stored.archives.find(a => a.archiveId === manifest.archiveId);
          if (!existing?.delivery || existing.delivery.destination !== remote) throw new BackupError('No matching recorded delivery; verification succeeded but remote status cannot be attached');
          await control(dir, 'record', { status: { ...status, delivery: { ...existing.delivery, remoteVerification: result } } });
        } else await control(dir, 'record', { status });
      }
      if (!result.integrity || !result.compatibility || !result.keyMatch) throw new BackupError('Backup verification checks failed');
      return manifest;
    }, option(args, '--scratch-dir'));
  } finally { bek.material.fill(0); await rm(scratch, { recursive: true, force: true }); }
}
async function existingInstallation(dir: string): Promise<string | null> {
  const database = await compose(dir, ['exec', '-T', 'postgres', 'psql', '-U', 'postgres', '-d', 'postgres', '-Atc', "SELECT 1 FROM pg_database WHERE datname = 'varlatch'"]);
  if (database !== '1') return null;
  const present = await compose(dir, ['exec', '-T', 'postgres', 'psql', '-U', 'postgres', '-d', 'varlatch', '-Atc', "SELECT to_regclass('public.installation') IS NOT NULL"]);
  if (present !== 't') return null;
  return (await compose(dir, ['exec', '-T', 'postgres', 'psql', '-U', 'postgres', '-d', 'varlatch', '-Atc', 'SELECT id FROM installation LIMIT 1'])) || null;
}
export async function restoreBackup(args: string[], dir: string): Promise<void> {
  return withOperatorLock(dir, () => restoreInstallation(args, dir));
}
async function restoreInstallation(args: string[], dir: string): Promise<void> {
  const bek = loadBek(args), target = targetRelease(args);
  try {
    await openArchive(required(args, '--in'), bek, async (manifest, scratch) => {
      const keys = candidateKeys(args, manifest.requiredKeyVersions);
      try {
        const result = verifyManifest(manifest, target, bek, keys);
        if (!result.compatibility || !result.keyMatch) throw new BackupError('Restore preflight checks failed');
      } finally { for (const key of keys.values()) key.fill(0); }
      const gate = await control<Gate>(dir, 'prepare-restore', { archiveId: manifest.archiveId }, true);
      // Bypass normal migrate dependencies: restore owns the database until it is complete.
      const owner = await ensureNamespaceOwner(dir);
      await compose(dir, ['up', '-d', '--no-deps', ...(owner ? [owner] : []), 'postgres', 'varlatchd', 'convex-backend']);
      await waitFor(async () => { try { await control(dir, 'restore-drain', { id: gate.id }); return true; } catch { return false; } }, Date.now() + 60_000);
      await convexStopped(dir, gate.id, Date.now() + 60_000);
      const existing = await existingInstallation(dir);
      if (existing && existing !== manifest.installationId) throw new BackupError('Refusing to replace an initialized installation with a different Installation ID; restore remains isolated');
      // The Secret Plane is restored; the Application Plane is reset and
      // rebuilt after isolation clears (ADR-0036 D3) — for format-1 archives
      // too, whose Application Plane components are ignored here (verify
      // still checks them).
      for (const [database, owner, dump] of [['varlatch', 'varlatchd_migrate', 'secret-plane.dump'], ['convex_self_hosted', 'convex', null]] as const) {
        for (const sql of [`DROP DATABASE ${database} WITH (FORCE)`, `CREATE DATABASE ${database} OWNER ${owner}`]) {
          await compose(dir, ['exec', '-T', 'postgres', 'psql', '-U', 'postgres', '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c', sql]);
        }
        if (dump) await compose(dir, ['exec', '-T', 'postgres', 'pg_restore', '-U', 'postgres', '--exit-on-error', '--no-owner', '--role', owner, '-d', database], { inputFile: join(scratch, dump) });
      }
      await compose(dir, ['exec', '-T', 'convex-backend', 'sh', '-c', 'rm -rf /convex/data/storage && mkdir -p /convex/data/storage']);
      if (manifest.release.migrationVersion !== target.migrationVersion) await compose(dir, ['run', '--rm', '--no-deps', '-T', 'varlatch-migrate', 'migrate', '--restore-gate', gate.id]);
      await control(dir, 'restore-reconcile', { id: gate.id, installationId: manifest.installationId, manifestIdentity: createHash('sha256').update(JSON.stringify(manifest)).digest('hex') });
      await control(dir, 'restore-complete', { id: gate.id });
      console.log(`Restore completed for ${manifest.installationId}: Secret Plane restored and its canary verified; rebuilding the Application Plane.`);
      await reconcileApplicationPlane(dir);
    }, option(args, '--scratch-dir'));
  } finally { bek.material.fill(0); }
}
/**
 * The archive brings the Application Plane functions and trust configuration
 * of the release that captured it. Converge both on this installation's
 * release and configuration (ADR-0035 D4) once the restore gate is lifted —
 * during it the supervisor admits only Mirror traffic.
 */
async function reconcileApplicationPlane(dir: string): Promise<void> {
  const services = (await compose(dir, ['--profile', 'deploy', 'config', '--services']).catch(() => '')).split('\n');
  if (!services.includes('convex-deploy')) {
    console.log('This Compose project has no convex-deploy service: deploy this release\'s Application Plane functions yourself, then run `varlatch doctor`.');
    return;
  }
  let out: string;
  try {
    out = await compose(dir, ['run', '--rm', '--no-deps', '-T', 'convex-deploy'], { timeoutMs: 15 * 60_000 });
  } catch (e) {
    throw new BackupError(
      `The data is restored, but the Application Plane was not reconciled with this release: Convex may still serve the archive's functions. ` +
        `Run \`docker compose run --rm convex-deploy\`, then \`varlatch doctor\`. (${(e as Error).message})`,
    );
  }
  for (const line of out.split('\n').filter(l => l.startsWith('reconcile:'))) console.log(`  ${line}`);
  console.log('Application Plane reconciled with this release.');
  // Mirrors now, rather than at the publisher's next full sync.
  try {
    await compose(dir, ['exec', '-T', 'varlatchd', 'node', 'dist/cli.js', 'admin', 'mirror-sync']);
    console.log('Mirrors published from the restored Secret Plane.');
  } catch {
    console.log('Mirrors not published yet; varlatchd republishes them within a minute (non-authoritative: the dashboard reads /v1 meanwhile).');
  }
}
export async function backupCommand(args: string[]): Promise<void> {
  const dir = resolve(option(args, '--dir') ?? process.cwd());
  switch (args[0]) {
    case 'create': await createBackup(args, dir); break;
    case 'verify': await verifyBackup(args, dir); break;
    case 'restore': await restoreBackup(args, dir); break;
    case 'status': console.log(JSON.stringify(await control(dir, 'status'), null, 2)); break;
    default: throw new BackupError('Usage: varlatch admin backup create|verify|restore|status --dir <compose-directory> (see docs/operations/backup.md)');
  }
}
