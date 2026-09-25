// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Querier } from "../../src/db/migrate.js";

/**
 * Records every statement a Querier runs, interleaved with decryptions
 * reported through {@link TraceLog.decrypt}, so a test can check the order
 * of reads, audit commits, and decryptions within one request.
 */
export type TraceEntry =
  | { kind: "sql"; text: string; params: unknown[] }
  | { kind: "decrypt"; versionId: string };

export interface TraceLog {
  entries: TraceEntry[];
  decrypt(versionId: string): void;
  /** When set, an audit insert whose event type it accepts fails. */
  failAudit: ((eventType: string, metadata: string) => boolean) | null;
  reset(): void;
}

export function traceLog(): TraceLog {
  const log: TraceLog = {
    entries: [],
    decrypt: (versionId) => log.entries.push({ kind: "decrypt", versionId }),
    failAudit: null,
    reset: () => {
      log.entries = [];
      log.failAudit = null;
    },
  };
  return log;
}

export function traced<Q extends Querier>(db: Q, log: TraceLog): Q {
  return {
    ...db,
    query: async (text: string, params?: unknown[]) => {
      log.entries.push({ kind: "sql", text, params: params ?? [] });
      if (log.failAudit && /INSERT INTO audit_events/.test(text)) {
        const eventType = String(params?.[1] ?? "");
        const metadata = String(params?.[13] ?? "");
        if (log.failAudit(eventType, metadata)) throw new Error(`injected audit commit failure (${eventType})`);
      }
      return db.query(text, params);
    },
  };
}

const SNAPSHOT_BEGIN = /^BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY/;
/** Tables a retrieval may read only inside its snapshot. */
const SNAPSHOT_ONLY =
  /\b(env_values|value_versions|capabilities|grants|roles|groups|group_members|team_projects|requirements|org_members|contract_revisions|projects|environments|organizations)\b/;

function versionsNamed(metadata: string): string[] {
  let items: string;
  try {
    items = String((JSON.parse(metadata) as { items?: unknown }).items ?? "");
  } catch {
    return [];
  }
  return items
    .split(",")
    .filter(Boolean)
    .flatMap((entry) => (entry.split("@")[1] ?? "").split("+"))
    .filter(Boolean);
}

/**
 * Check the two-phase retrieval invariants over one request's trace:
 * - exactly one read-only snapshot, and after it no statement touches a
 *   table the retrieval reads;
 * - every decryption is preceded by a committed audit insert naming its
 *   version;
 * - the versions named by the request's audit events are exactly the
 *   versions decrypted.
 */
export function checkAuditBeforeDecryption(log: TraceLog): { decrypted: string[]; audited: string[] } {
  const entries = log.entries;
  const starts = entries.flatMap((e, i) => (e.kind === "sql" && SNAPSHOT_BEGIN.test(e.text) ? [i] : []));
  if (starts.length !== 1) throw new Error(`expected one retrieval snapshot, found ${starts.length}`);
  const start = starts[0] as number;
  const end = entries.findIndex((e, i) => i > start && e.kind === "sql" && /^(COMMIT|ROLLBACK)/.test(e.text));
  if (end < 0) throw new Error("the snapshot never ended");
  for (const e of entries.slice(start + 1, end)) {
    if (e.kind === "decrypt") throw new Error(`decrypted ${e.versionId} inside the snapshot`);
    if (/^\s*(INSERT|UPDATE|DELETE)/i.test(e.text)) throw new Error(`wrote inside the snapshot: ${e.text}`);
  }

  const committed = new Set<string>();
  let pending: string[] | null = null;
  const decrypted: string[] = [];
  for (const e of entries.slice(end + 1)) {
    if (e.kind === "decrypt") {
      if (!committed.has(e.versionId)) throw new Error(`decrypted ${e.versionId} before an audit commit named it`);
      decrypted.push(e.versionId);
      continue;
    }
    if (SNAPSHOT_ONLY.test(e.text) && !/INSERT INTO audit_events/.test(e.text)) {
      throw new Error(`read after the snapshot: ${e.text.slice(0, 120)}`);
    }
    if (/^BEGIN/.test(e.text)) pending = [];
    else if (/^COMMIT/.test(e.text)) {
      for (const v of pending ?? []) committed.add(v);
      pending = null;
    } else if (/^ROLLBACK/.test(e.text)) pending = null;
    else if (/INSERT INTO audit_events/.test(e.text)) {
      const named = versionsNamed(String(e.params[13] ?? ""));
      if (pending) pending.push(...named);
      else for (const v of named) committed.add(v);
    }
  }
  return { decrypted: [...new Set(decrypted)].sort(), audited: [...committed].sort() };
}
