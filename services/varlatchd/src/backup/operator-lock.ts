// SPDX-License-Identifier: AGPL-3.0-or-later
import type { PoolQuerier } from '../db/tx.js';

// Host-exec admin and migration writers participate in maintenance draining,
// even though their processes are not counted by the daemon's HTTP admission.
// Every writer acquires shared BEFORE checking the filesystem gate. Once the
// gate exists, an exclusive barrier proves all previously admitted work ended.
export const OPERATOR_LOCK = 7330033;
export async function operatorLease(db: PoolQuerier): Promise<() => Promise<void>> {
  const connection = await db.connect();
  try { await connection.query('SELECT pg_advisory_lock_shared($1)', [OPERATOR_LOCK]); }
  catch (e) { connection.release(); throw e; }
  return async () => {
    try { await connection.query('SELECT pg_advisory_unlock_shared($1)', [OPERATOR_LOCK]); }
    finally { connection.release(); }
  };
}
export async function drainOperators(db: PoolQuerier, stillOwned: () => unknown): Promise<void> {
  const connection = await db.connect();
  try {
    for (;;) {
      stillOwned();
      const result = await connection.query('SELECT pg_try_advisory_lock($1) AS acquired', [OPERATOR_LOCK]);
      if ((result.rows[0] as { acquired: boolean }).acquired) {
        await connection.query('SELECT pg_advisory_unlock($1)', [OPERATOR_LOCK]);
        return;
      }
      await new Promise(r => setTimeout(r, 50));
    }
  } finally { connection.release(); }
}
