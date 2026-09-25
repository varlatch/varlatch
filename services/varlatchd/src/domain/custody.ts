// SPDX-License-Identifier: AGPL-3.0-or-later
import { recordAuditEvent } from "../audit/events.js";
import type { Querier } from "../db/migrate.js";
import { DomainError } from "./errors.js";

/**
 * Custody Attestations (ADR-0035 D9): an Infrastructure Operator's dated
 * statement that a separately held copy of a recovery key exists. The
 * installation can verify that a key *works*; it can never verify that a copy
 * exists elsewhere — so this is recorded as a claim, shown as a claim, and
 * aged, never merged into a verified check.
 *
 * Recorded as Security Audit Events: append-only, dated, and carried by
 * backups (after a restore, which keys are held off-host still matters). The
 * Root KEK attestation names the key version it covers, so replacing the key
 * voids it. No key material or value-derived hash is recorded (ADR-0016).
 */

export const CUSTODY_KEYS = ["root-kek", "backup-key"] as const;
export type CustodyKey = (typeof CUSTODY_KEYS)[number];
export const CUSTODY_METHODS = ["passphrase-escrow", "shamir-split", "copy"] as const;
export type CustodyMethod = (typeof CUSTODY_METHODS)[number];

export interface Attestation {
  key: CustodyKey;
  method: CustodyMethod;
  at: string;
  keyVersion: number | null;
}

export interface CustodyStatus {
  rootKekVersion: number;
  /** Latest attestation per key; for the Root KEK, only for its current version. */
  attestations: Record<CustodyKey, Attestation | null>;
}

const EVENT = "installation.custody_attested";

async function currentKekVersion(db: Querier): Promise<number> {
  const res = await db.query("SELECT root_kek_version FROM installation LIMIT 1");
  const row = res.rows[0] as { root_kek_version: number } | undefined;
  if (!row) throw new DomainError("VALIDATION_FAILED", "Installation is not initialized");
  return row.root_kek_version;
}

export async function attestCustody(
  db: Querier,
  input: { key: string; method: string },
): Promise<Attestation> {
  if (!(CUSTODY_KEYS as readonly string[]).includes(input.key)) {
    throw new DomainError("VALIDATION_FAILED", `key must be one of ${CUSTODY_KEYS.join(", ")}`);
  }
  if (!(CUSTODY_METHODS as readonly string[]).includes(input.method)) {
    throw new DomainError("VALIDATION_FAILED", `method must be one of ${CUSTODY_METHODS.join(", ")}`);
  }
  const key = input.key as CustodyKey;
  const keyVersion = key === "root-kek" ? await currentKekVersion(db) : null;
  await recordAuditEvent(db, {
    eventType: EVENT,
    decision: "info",
    metadata: { key, method: input.method, ...(keyVersion !== null ? { keyVersion } : {}) },
  });
  return { key, method: input.method as CustodyMethod, at: new Date().toISOString(), keyVersion };
}

export async function custodyStatus(db: Querier): Promise<CustodyStatus> {
  const rootKekVersion = await currentKekVersion(db);
  const res = await db.query(
    `SELECT metadata, occurred_at FROM audit_events WHERE event_type = $1 ORDER BY event_order DESC`,
    [EVENT],
  );
  const attestations: Record<CustodyKey, Attestation | null> = { "root-kek": null, "backup-key": null };
  for (const row of res.rows as { metadata: Record<string, unknown> | string; occurred_at: string | Date }[]) {
    const meta = (typeof row.metadata === "string" ? JSON.parse(row.metadata) : row.metadata) as Record<string, unknown>;
    const key = meta.key as CustodyKey;
    if (!(CUSTODY_KEYS as readonly string[]).includes(key) || attestations[key]) continue;
    const keyVersion = typeof meta.keyVersion === "number" ? meta.keyVersion : null;
    if (key === "root-kek" && keyVersion !== rootKekVersion) continue;
    attestations[key] = {
      key,
      method: meta.method as CustodyMethod,
      at: new Date(row.occurred_at).toISOString(),
      keyVersion,
    };
  }
  return { rootKekVersion, attestations };
}
