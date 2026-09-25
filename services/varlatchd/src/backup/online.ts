// SPDX-License-Identifier: AGPL-3.0-or-later
import { randomUUID } from 'node:crypto';
import type { Querier } from '../db/migrate.js';
import type { PoolQuerier } from '../db/tx.js';
import type { AppCtx } from '../domain/ctx.js';
import { archiveMetadata } from './metadata.js';

/**
 * Online capture (ADR-0036): the Secret Plane is dumped from one exported
 * REPEATABLE READ snapshot while varlatchd keeps admitting all traffic.
 *
 * The capture exclusion is a session-level advisory lock that rotation
 * start, `migrate`, and restore take too (ADR-0036 D5). It is acquired
 * BEFORE the snapshot exists: a REPEATABLE READ snapshot is taken at the
 * transaction's first statement, so a lock taken by that statement could
 * follow a snapshot that predates a rotation committed while it waited.
 *
 * Holding it on the connection that exports the snapshot ties both to one
 * backend. If that connection is lost the lock is released at once, and the
 * capture is invalid: `finish` demands positive confirmation that this very
 * connection still holds the exclusion before an archive may be published.
 */

export const CAPTURE_EXCLUSION = 7330034;

type Client = Querier & { release: (destroy?: boolean) => void };

/** Waits (bounded) for the capture exclusion on `client`; the caller releases it. */
export async function acquireCaptureExclusion(client: Querier, waitMs: number, onWait?: () => void): Promise<void> {
  const deadline = Date.now() + waitMs;
  let announced = false;
  for (;;) {
    const r = await client.query('SELECT pg_try_advisory_lock($1) AS acquired', [CAPTURE_EXCLUSION]);
    if ((r.rows[0] as { acquired: boolean }).acquired) return;
    if (Date.now() >= deadline) throw new Error('A backup capture holds the installation; try again when it has finished');
    if (!announced) { announced = true; onWait?.(); }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
}
export async function releaseCaptureExclusion(client: Querier): Promise<void> {
  await client.query('SELECT pg_advisory_unlock($1)', [CAPTURE_EXCLUSION]);
}

/** For operations that must never overlap a capture: migrate, restore, and (when built) key rotation start. */
export async function withCaptureExclusion<T>(db: PoolQuerier, waitMs: number, fn: () => Promise<T>, onWait?: () => void): Promise<T> {
  const client = await db.connect();
  try {
    await acquireCaptureExclusion(client, waitMs, onWait);
    try { return await fn(); } finally { await releaseCaptureExclusion(client).catch(() => {}); }
  } finally { client.release(); }
}

export interface CaptureStarted {
  id: string;
  /** For `pg_dump --snapshot`. */
  snapshot: string;
  /** The dump must connect as this role (so varlatchd may terminate it) and with this application_name. */
  role: string;
  application: string;
  createdAt: string;
  expiresAt: number;
  metadata: Awaited<ReturnType<typeof archiveMetadata>>;
}

export interface OnlineCaptureOptions {
  /** How long a capture waits for the exclusion (e.g. behind a migration). */
  exclusionWaitMs?: number;
  /** Confirmed termination of this capture's dump backends; returns true once none remain. */
  terminate?: (application: string) => Promise<boolean>;
  /** Observes the expiry sequence (tests). */
  onStep?: (step: 'invalidated' | 'terminated' | 'snapshot-closed' | 'released' | 'termination-unconfirmed') => void;
}

interface Active {
  started: CaptureStarted;
  client: Client;
  state: 'active' | 'invalid';
  timer: NodeJS.Timeout;
  expiring?: Promise<void>;
}

export class OnlineCapture {
  private active: Active | null = null;
  constructor(private readonly ctx: AppCtx & { db: PoolQuerier }, private readonly opts: OnlineCaptureOptions = {}) {}

  get running(): boolean { return this.active !== null; }

  async begin(ttlMs: number): Promise<CaptureStarted> {
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1000 || ttlMs > 24 * 60 * 60 * 1000) throw new Error('Capture deadline must be between 1 second and 24 hours');
    if (this.active) throw new Error('Another backup capture is running');
    const client = await this.ctx.db.connect();
    let locked = false;
    try {
      // 1. The exclusion, before any snapshot exists.
      await acquireCaptureExclusion(client, this.opts.exclusionWaitMs ?? 30_000);
      locked = true;
      // 2. The snapshot: established by the first statement after BEGIN,
      //    i.e. after the exclusion — so it sees every rotation committed
      //    before the exclusion was granted, and none can start after.
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      const metadata = await archiveMetadata({ ...this.ctx, db: client });
      const snapshot = (await client.query('SELECT pg_export_snapshot() AS id, current_user AS role')).rows[0] as { id: string; role: string };
      const id = randomUUID();
      const started: CaptureStarted = {
        id, snapshot: snapshot.id, role: snapshot.role, application: `varlatch-capture-${id}`,
        createdAt: new Date().toISOString(), expiresAt: Date.now() + ttlMs, metadata,
      };
      const timer = setTimeout(() => { void this.expire(id); }, ttlMs);
      timer.unref();
      this.active = { started, client, state: 'active', timer };
      return started;
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      if (locked) await releaseCaptureExclusion(client).catch(() => {});
      client.release();
      throw e;
    }
  }

  /**
   * Positive confirmation (ADR-0036 D5): the capture is still valid, its
   * lease has not expired, and its own connection still holds the exclusion.
   * Only then may the caller publish the archive.
   */
  async finish(id: string): Promise<{ valid: true }> {
    const active = this.require(id);
    if (active.state !== 'active' || Date.now() >= active.started.expiresAt) {
      await this.expire(id);
      throw new Error('Capture lease expired; discard this capture');
    }
    let held = false;
    try {
      const r = await active.client.query(
        "SELECT count(*)::int AS n FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted AND objsubid = 1 AND ((classid::bigint << 32) | objid::bigint) = $1",
        [CAPTURE_EXCLUSION],
      );
      held = (r.rows[0] as { n: number }).n === 1;
    } catch { held = false; }
    if (!held) {
      await this.expire(id);
      throw new Error('Capture lost its exclusion; discard this capture');
    }
    // The lease may have fired while we awaited the check.
    if (active.expiring || active.state !== 'active') {
      await active.expiring;
      throw new Error('Capture lease expired; discard this capture');
    }
    clearTimeout(active.timer);
    this.active = null;
    try {
      await active.client.query('COMMIT');
      await releaseCaptureExclusion(active.client);
    } finally { active.client.release(); }
    return { valid: true };
  }

  /** Operator abort (e.g. the dump failed): same ordering as lease expiry. */
  async abort(id: string): Promise<void> {
    this.require(id);
    await this.expire(id);
  }

  /**
   * Invalidate → stop the dump, confirmed → close the snapshot → stop any
   * late importer, confirmed → release the exclusion. If termination cannot
   * be confirmed the exclusion stays held and termination is retried: no
   * incompatible operation may overlap a dump that is still running.
   */
  private expire(id: string): Promise<void> {
    const active = this.active;
    if (!active || active.started.id !== id) return Promise.resolve();
    active.expiring ??= (async () => {
      active.state = 'invalid';
      clearTimeout(active.timer);
      this.opts.onStep?.('invalidated');
      // Through the pool, not the capture connection: that one may be the
      // thing that failed.
      const terminate = this.opts.terminate ?? ((app: string) => this.terminateDumps(app));
      const confirm = async () => {
        for (;;) {
          if (await terminate(active.started.application).catch(() => false)) return;
          this.opts.onStep?.('termination-unconfirmed');
          console.error(`backup capture ${id}: dump termination not confirmed; keeping the capture exclusion and retrying`);
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      };
      let connected = true;
      try {
        await confirm();
        this.opts.onStep?.('terminated');
        try { await active.client.query('ROLLBACK'); } catch { connected = false; }
        this.opts.onStep?.('snapshot-closed');
        // A dump that imported the snapshot just before it closed.
        await confirm();
        // A lost capture connection already released its lock with it; the
        // capture is invalid either way and nothing is published.
        if (connected) await releaseCaptureExclusion(active.client).catch(() => { connected = false; });
        this.opts.onStep?.('released');
      } finally {
        active.client.release(!connected);
        if (this.active === active) this.active = null;
      }
    })();
    return active.expiring;
  }

  private require(id: string): Active {
    if (!this.active || this.active.started.id !== id) throw new Error('Unknown or lost capture; discard it');
    return this.active;
  }

  /** Terminates this capture's dump backends and confirms none remain. */
  private async terminateDumps(application: string): Promise<boolean> {
    const client = this.ctx.db;
    const pids = (await client.query(
      'SELECT pid FROM pg_stat_activity WHERE application_name = $1', [application],
    )).rows as { pid: number }[];
    for (const { pid } of pids) {
      // A positive timeout makes PostgreSQL wait for the backend to exit;
      // with the default 0 it only reports that the signal was sent.
      await client.query('SELECT pg_terminate_backend($1, 5000)', [pid]);
    }
    const left = await client.query('SELECT count(*)::int AS n FROM pg_stat_activity WHERE application_name = $1', [application]);
    return (left.rows[0] as { n: number }).n === 0;
  }
}
