// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { VarlatchApiError } from "@varlatch/sdk";
import { useMirrorSignal } from "../../lib/realtime";

/** True when the server refused a read for lack of permission. */
export function isPermissionDenied(err: unknown): boolean {
  return err instanceof VarlatchApiError && (err.status === 403 || err.code === "PERMISSION_DENIED");
}

/**
 * Live updates for the audit log, without feeding on its own refusals.
 *
 * Every audit event moves the org's changeSignal, and a refused read of the
 * audit log is itself an audit event. Refetching on every signal would turn
 * one refusal into an endless stream of reads and new denial events. So:
 *
 * - a query whose last read was refused is left alone: the page shows the
 *   refusal until the person retries, or until their access changes (the
 *   membership watcher refetches every query then) or the identity or
 *   organization changes (a different query);
 * - a signal that arrives while a read is in flight is held until that read
 *   settles: when it succeeded, the log is read once more (the event may
 *   have landed after the read); when it was refused, the signal was most
 *   likely that refusal and is dropped.
 */
export function useAuditLiveRefresh(orgId: string | undefined, org: string): void {
  const qc = useQueryClient();
  const held = useRef(new Set<string>());

  useMirrorSignal(orgId, "*", () => {
    for (const query of qc.getQueryCache().findAll({ queryKey: ["audit", org] })) {
      if (isPermissionDenied(query.state.error)) continue;
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
      if (query.state.status !== "success") return;
      queueMicrotask(() => void qc.invalidateQueries({ queryKey: query.queryKey, exact: true }));
    });
    return () => {
      unsubscribe();
      pending.clear();
    };
  }, [qc]);
}
