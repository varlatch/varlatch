// SPDX-License-Identifier: AGPL-3.0-or-later
import { MIGRATIONS, type Migration } from "./migrations/index.js";

/**
 * Forward-only migration runner (ADR-0019): numbered, append-only migrations
 * applied in order inside transactions. No down migrations — rollback is
 * restore-from-backup. The runtime process never runs this; the one-shot
 * migrate entrypoint does, under the elevated database role.
 */

/** Minimal querying surface satisfied by pg.Pool/Client and pglite. */
export interface Querier {
  query: (text: string, params?: unknown[]) => Promise<{ rows: unknown[] }>;
  /** Multi-statement execution; falls back to query() when absent. */
  exec?: (text: string) => Promise<unknown>;
}

async function execSql(db: Querier, sql: string): Promise<void> {
  if (db.exec) await db.exec(sql);
  else await db.query(sql);
}

export interface MigrationStatus {
  appliedIds: number[];
  pending: Migration[];
  /** Applied IDs this binary does not know: schema is newer than the binary. */
  unknownApplied: number[];
}

/**
 * Read-only: safe under the runtime role (which has no DDL). Only
 * runMigrations() — the migrate entrypoint under the elevated role — creates
 * the bookkeeping table.
 */
export async function migrationStatus(db: Querier): Promise<MigrationStatus> {
  const existsRes = await db.query(
    "SELECT to_regclass('varlatch_migrations') IS NOT NULL AS present",
  );
  if (!(existsRes.rows[0] as { present: boolean }).present) {
    return { appliedIds: [], pending: [...MIGRATIONS], unknownApplied: [] };
  }
  const res = await db.query("SELECT id FROM varlatch_migrations ORDER BY id");
  const appliedIds = (res.rows as { id: number }[]).map((r) => r.id);
  const known = new Set(MIGRATIONS.map((m) => m.id));
  const appliedSet = new Set(appliedIds);
  return {
    appliedIds,
    pending: MIGRATIONS.filter((m) => !appliedSet.has(m.id)),
    unknownApplied: appliedIds.filter((id) => !known.has(id)),
  };
}

export async function runMigrations(db: Querier): Promise<{ applied: Migration[] }> {
  const ids = MIGRATIONS.map((m) => m.id);
  const sorted = [...ids].sort((a, b) => a - b);
  if (ids.some((id, i) => id !== sorted[i]) || new Set(ids).size !== ids.length) {
    throw new Error("Migration list must be strictly ordered and unique");
  }
  await execSql(
    db,
    `CREATE TABLE IF NOT EXISTS varlatch_migrations (
       id integer PRIMARY KEY,
       name text NOT NULL,
       applied_at timestamptz NOT NULL DEFAULT now()
     )`,
  );
  const status = await migrationStatus(db);
  if (status.unknownApplied.length > 0) {
    throw new Error(
      `Database schema is newer than this binary (unknown migrations: ${status.unknownApplied.join(", ")}). ` +
        "Refusing to run; use a matching or newer release.",
    );
  }
  const applied: Migration[] = [];
  for (const migration of status.pending) {
    await execSql(db, "BEGIN");
    try {
      await execSql(db, migration.sql);
      await db.query(
        "INSERT INTO varlatch_migrations (id, name) VALUES ($1, $2)",
        [migration.id, migration.name],
      );
      await execSql(db, "COMMIT");
    } catch (err) {
      await execSql(db, "ROLLBACK");
      throw new Error(
        `Migration ${migration.id} (${migration.name}) failed: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
    applied.push(migration);
  }
  return { applied };
}

/** Readiness check (ADR-0019): schema must exactly match the binary. */
export async function schemaIsCurrent(db: Querier): Promise<boolean> {
  const status = await migrationStatus(db);
  return status.pending.length === 0 && status.unknownApplied.length === 0;
}
