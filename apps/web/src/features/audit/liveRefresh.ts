// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useRef } from "react";
import { hashKey, useQueryClient, type QueryKey } from "@tanstack/react-query";
import { VarlatchApiError } from "@varlatch/sdk";
import { useMeSignal, useMirrorSignal } from "../../lib/realtime";

/** True when the server refused a read for lack of permission. */
export function isPermissionDenied(err: unknown): boolean {
  return err instanceof VarlatchApiError && (err.status === 403 || err.code === "PERMISSION_DENIED");
}

/** How long after a failed audit read the next automatic read waits. */
export const AUDIT_BACKOFF_MS = 30_000;

type Failure = { at: number; error: unknown };

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(signal.reason);
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal.reason);
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * The single gate every audit read goes through, whatever asked for it: a
 * change signal, the reconnect catch-up that invalidates every query,
 * degraded polling, window focus, or a retry.
 *
 * A refused read is itself an audit event, which moves the change signal,
 * so a page that cannot read the log would otherwise ask again forever.
 * After any failed read (refused, not found, a server or network error) the
 * next read waits until AUDIT_BACKOFF_MS after that failure. Triggers in that
 * window join the one waiting read, so an open page makes at most one failed
 * read per AUDIT_BACKOFF_MS, and access granted by any route (a grant, a
 * team) shows within that time. Reads that succeed are not delayed.
 *
 * "Try again" and a change of the person's membership or role skip the wait:
 * they cancel the read in flight first, so a read sent before a promotion
 * cannot answer for the one after it.
 *
 * The last failure is kept for display: a waiting or running read resets
 * the query to pending, and the page keeps showing the refusal instead of
 * a skeleton.
 */
export function useAuditReads(org: string) {
  const qc = useQueryClient();
  const failures = useRef(new Map<string, Failure>()).current;

  const read = useCallback(
    async <T,>(queryKey: QueryKey, signal: AbortSignal, fetch: () => Promise<T>): Promise<T> => {
      const key = hashKey(queryKey);
      const last = failures.get(key);
      const wait = last ? last.at + AUDIT_BACKOFF_MS - Date.now() : 0;
      if (wait > 0) await sleep(wait, signal);
      try {
        const result = await fetch();
        if (!signal.aborted) failures.delete(key);
        return result;
      } catch (err) {
        if (!signal.aborted) failures.set(key, { at: Date.now(), error: err });
        throw err;
      }
    },
    [failures],
  );

  const lastFailure = (queryKey: QueryKey): unknown => failures.get(hashKey(queryKey))?.error;

  const refreshNow = useCallback(async () => {
    for (const failure of failures.values()) failure.at = Number.NEGATIVE_INFINITY;
    await qc.cancelQueries({ queryKey: ["audit", org] });
    await qc.refetchQueries({ queryKey: ["audit", org], type: "active" });
  }, [failures, qc, org]);

  // A new role changes what may be read; the shell's membership watcher
  // refetches every query too, and joins this read.
  useMeSignal(["membership"], () => void refreshNow().catch(() => undefined));

  return { read, lastFailure, refreshNow };
}

/**
 * Live updates for the Audit page: every change signal refetches the log at
 * once, except that a signal arriving while a read is in flight waits for
 * that read to settle and then asks once more (the event may have landed
 * after the read). Several signals during one read collapse into one. After
 * a failure the read is held back by useAuditReads, which every read goes
 * through.
 */
export function useAuditLiveRefresh(orgId: string | undefined, org: string): void {
  const qc = useQueryClient();
  const held = useRef(new Set<string>());

  useMirrorSignal(orgId, "*", () => {
    for (const query of qc.getQueryCache().findAll({ queryKey: ["audit", org] })) {
      if (query.state.fetchStatus === "fetching") {
        held.current.add(query.queryHash);
        continue;
      }
      void qc.invalidateQueries({ queryKey: query.queryKey, exact: true });
    }
  });

  useEffect(() => {
    const pending = held.current;
    const unsubscribe = qc.getQueryCache().subscribe((event) => {
      if (event.type !== "updated") return;
      const query = event.query;
      if (!pending.has(query.queryHash) || query.state.fetchStatus !== "idle") return;
      pending.delete(query.queryHash);
      queueMicrotask(() => void qc.invalidateQueries({ queryKey: query.queryKey, exact: true }));
    });
    return () => {
      unsubscribe();
      pending.clear();
    };
  }, [qc]);
}
