// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { durableJson } from "@varlatch/backup";

/**
 * Mirror publication status (ADR-0035 Decision 8). The publisher's cursor
 * lives in the running daemon's memory; this file in the state volume is how
 * a separate, read-only `admin doctor` process observes it. It carries
 * positions, times, and a truncated error message — never mirror payloads.
 */

export interface MirrorStatus {
  /** Highest audit event_order the incremental publisher has pushed. */
  cursorOrder: string | null;
  lastIncrementalAt: string | null;
  lastFullSyncAt: string | null;
  lastError: { at: string; message: string } | null;
  updatedAt: string;
}

export const MIRROR_STATUS_FILE = "mirror-status.json";

export function readMirrorStatus(dir: string): MirrorStatus | null {
  try {
    return JSON.parse(readFileSync(join(dir, MIRROR_STATUS_FILE), "utf8")) as MirrorStatus;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw e;
  }
}

/**
 * Records outcomes and persists only on change (cursor moved, error state
 * changed, full sync completed), so an idle installation does not rewrite
 * the file every incremental tick.
 */
export class MirrorStatusReporter {
  private status: MirrorStatus = {
    cursorOrder: null,
    lastIncrementalAt: null,
    lastFullSyncAt: null,
    lastError: null,
    updatedAt: new Date(0).toISOString(),
  };

  constructor(
    private readonly dir: string,
    private readonly write: (path: string, value: unknown) => void = durableJson,
  ) {}

  incremental(cursorOrder: string, now = new Date()): void {
    const changed = cursorOrder !== this.status.cursorOrder || this.status.lastError !== null;
    this.status.cursorOrder = cursorOrder;
    this.status.lastIncrementalAt = now.toISOString();
    this.status.lastError = null;
    if (changed) this.persist(now);
  }

  fullSync(now = new Date()): void {
    this.status.lastFullSyncAt = now.toISOString();
    this.status.lastError = null;
    this.persist(now);
  }

  failure(err: unknown, now = new Date()): void {
    const message = (err instanceof Error ? err.message : String(err)).slice(0, 300);
    if (this.status.lastError?.message === message) return;
    this.status.lastError = { at: now.toISOString(), message };
    this.persist(now);
  }

  private persist(now: Date): void {
    this.status.updatedAt = now.toISOString();
    try {
      this.write(join(this.dir, MIRROR_STATUS_FILE), this.status);
    } catch (err) {
      // Status reporting must never break publication.
      console.error(`mirror status not written: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}

export type MirrorVerdict =
  | { state: "caught-up" }
  | { state: "behind"; cursorOrder: string | null; watermark: string }
  | { state: "rejected"; message: string }
  | { state: "failing"; message: string }
  | { state: "unknown"; reason: string };

/**
 * Has publication reached `watermark` (the newest audit event_order when the
 * check started)? A trailing 401/403 from Convex is classified separately:
 * it means Convex no longer trusts varlatchd's mirror token (issuer/JWKS).
 */
export function evaluateMirror(status: MirrorStatus | null, watermark: string): MirrorVerdict {
  if (!status) return { state: "unknown", reason: "no publication status recorded yet" };
  if (status.lastError) {
    const rejected = /HTTP 40[13]\b|unauthori[sz]ed|Unauthenticated/i.test(status.lastError.message);
    return rejected
      ? { state: "rejected", message: status.lastError.message }
      : { state: "failing", message: status.lastError.message };
  }
  if (status.cursorOrder !== null && BigInt(status.cursorOrder) >= BigInt(watermark)) {
    return { state: "caught-up" };
  }
  return { state: "behind", cursorOrder: status.cursorOrder, watermark };
}
