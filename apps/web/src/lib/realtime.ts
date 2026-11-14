// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef } from "react";
import { useConvexConnectionState, useQuery as useConvexQuery } from "convex/react";
import { anyApi } from "convex/server";
import { useQuery, useQueryClient, type QueryKey } from "@tanstack/react-query";
import { useSession } from "./session";
import { backend } from "./backend";
import { useSseConnected, useSseMeDocs, useSseOrgDocs } from "./sseProvider";

/**
 * Reactive invalidation over live-update signals: the server sends a
 * per-org changeSignal whenever audit events are recorded, carrying the
 * event-type domains touched ("grant", "project", …), and a per-identity
 * identitySignal for events outside any organization. Pages subscribe to the
 * signal for their domains and refetch their authoritative /v1 queries when
 * it moves. The signal never carries authoritative data, it only says
 * "something changed"; a stale or lost signal degrades to polling
 * (LiveUpdatesStatus).
 *
 * The transport is chosen once, when this module loads, after /v1/meta was
 * read (lib/backend.ts), so a component calls the same hooks on every
 * render:
 *
 * - "convex": the TypeScript server's Convex mirror (ADR-0005), whose
 *   subscriptions are scoped by the Convex token's claims;
 * - "sse": the Go server's server-sent events (lib/sse.ts, ADR-0059
 *   Decision 4), scoped by the browser session on the server;
 * - "none": no live updates; a signal never arrives (undefined, as before
 *   the first snapshot), and the pages' queries refresh by polling.
 */

const mirrorList = (anyApi as Record<string, Record<string, unknown>>).mirror!
  .list as Parameters<typeof useConvexQuery>[0];
const mirrorListMine = (anyApi as Record<string, Record<string, unknown>>).mirror!
  .listMine as Parameters<typeof useConvexQuery>[0];

type Docs = { data?: ChangeSignal }[] | undefined;

const transport = backend().realtime;

/** An Organization's changeSignal documents. */
const useOrgDocs: (orgId: string | undefined) => Docs =
  transport === "convex"
    ? (orgId) => useConvexQuery(mirrorList, (orgId ? { kind: "changeSignal", organizationId: orgId } : "skip") as never) as Docs
    : transport === "sse"
      ? useSseOrgDocs
      : () => undefined;

/** The signed-in person's identitySignal documents. */
const useMeDocs: () => Docs =
  transport === "convex"
    ? () => useConvexQuery(mirrorListMine, { kind: "identitySignal" } as never) as Docs
    : transport === "sse"
      ? useSseMeDocs
      : () => undefined;

/** Whether the live-updates connection is up; always false without live updates. */
export const useRealtimeConnected: () => boolean =
  transport === "convex"
    ? () => useConvexConnectionState().isWebSocketConnected
    : transport === "sse"
      ? useSseConnected
      : () => false;

interface ChangeSignal {
  lastEventId?: string;
  domains?: string[];
}

/**
 * Invalidate `queryKeys` when the org's changeSignal reports a change in any
 * of `domains` (event-type prefixes; "*" matches every change). The signal
 * observed on mount is treated as already-seen: React Query fetched fresh
 * data at that point.
 */
export function useMirrorInvalidation(
  orgId: string | undefined,
  domains: "*" | string[],
  queryKeys: QueryKey[],
): void {
  useSignalInvalidation(useOrgDocs(orgId), domains, queryKeys);
}

/**
 * Me-scoped counterpart: org-less events (credential lifecycle on /v1/me)
 * signal the acting identity instead of an org. The subscription is scoped
 * server-side to the signed-in identity (the Convex token's subject, or the
 * stream's session); no id is passed here.
 */
export function useMeRealtime(domains: "*" | string[], queryKeys: QueryKey[]): void {
  useSignalInvalidation(useMeDocs(), domains, queryKeys);
}

/**
 * Me-scoped, with a callback instead of query keys: `onChange` runs when the
 * caller's identitySignal reports a change in any of `domains` (for
 * instance "membership": removed from an organization, or a new role).
 */
export function useMeSignal(domains: "*" | string[], onChange: () => void): void {
  useSignal(useMeDocs(), domains, onChange);
}

function useSignalInvalidation(
  docs: { data?: ChangeSignal }[] | undefined,
  domains: "*" | string[],
  queryKeys: QueryKey[],
): void {
  const qc = useQueryClient();
  const keys = useRef(queryKeys);
  keys.current = queryKeys;
  useSignal(docs, domains, () => {
    for (const key of keys.current) void qc.invalidateQueries({ queryKey: key });
  });
}

function useSignal(docs: { data?: ChangeSignal }[] | undefined, domains: "*" | string[], onChange: () => void): void {
  const signal = docs?.[0]?.data;
  // undefined = subscription not loaded yet; null = loaded, no signal doc.
  const lastEventId = docs === undefined ? undefined : (signal?.lastEventId ?? null);

  // Latest args live in refs so the effect can depend on the signal alone —
  // callers pass fresh array literals and callbacks every render.
  const args = useRef({ domains, onChange, touched: signal?.domains });
  args.current = { domains, onChange, touched: signal?.domains };
  const seen = useRef<string | null | undefined>(undefined);

  useEffect(() => {
    if (lastEventId === undefined) return;
    if (seen.current === undefined) {
      // First loaded snapshot is the baseline: REST data is fresh at mount.
      seen.current = lastEventId;
      return;
    }
    if (!lastEventId || seen.current === lastEventId) return;
    seen.current = lastEventId;
    const { domains: watch, onChange: run, touched } = args.current;
    if (watch !== "*" && !(touched ?? []).some((d) => watch.includes(d))) return;
    run();
  }, [lastEventId]);
}

/**
 * Page-level convenience: routes carry the org slug, the changeSignal is
 * keyed by org id — resolve it through the shared ["org", slug] query and
 * subscribe. Keys are matched by React Query prefix, so ["grants", org]
 * covers every narrower key under it.
 */
export function useOrgRealtime(
  orgSlug: string | undefined,
  domains: "*" | string[],
  queryKeys: QueryKey[],
): void {
  const { api } = useSession();
  const org = useQuery({
    queryKey: ["org", orgSlug],
    queryFn: () => api.getOrganization(orgSlug as string),
    enabled: Boolean(orgSlug),
  });
  useMirrorInvalidation((org.data as { id: string } | undefined)?.id, domains, queryKeys);
}
