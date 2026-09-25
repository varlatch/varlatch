// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef } from "react";
import { useQuery as useConvexQuery } from "convex/react";
import { anyApi } from "convex/server";
import { useQuery, useQueryClient, type QueryKey } from "@tanstack/react-query";
import { useSession } from "./session";

/**
 * Reactive invalidation over the Convex mirror (ADR-0005): varlatchd pushes a
 * per-org changeSignal whenever audit events are recorded, carrying the
 * event-type domains touched ("grant", "project", …). Pages subscribe to the
 * signal for their domains and refetch their authoritative /v1 queries when
 * it moves. Convex never serves authoritative data here — it only says
 * "something changed"; a stale or lost signal degrades to today's behavior.
 */

const mirrorList = (anyApi as Record<string, Record<string, unknown>>).mirror!
  .list as Parameters<typeof useConvexQuery>[0];
const mirrorListMine = (anyApi as Record<string, Record<string, unknown>>).mirror!
  .listMine as Parameters<typeof useConvexQuery>[0];

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
  const docs = useConvexQuery(
    mirrorList,
    orgId ? { kind: "changeSignal", organizationId: orgId } : "skip",
  ) as { data?: ChangeSignal }[] | undefined;
  useSignalInvalidation(docs, domains, queryKeys);
}

/**
 * Me-scoped counterpart: org-less events (credential lifecycle on /v1/me)
 * signal the acting identity instead of an org. The subscription is scoped
 * server-side to the Convex token's subject — no id is passed here.
 */
export function useMeRealtime(domains: "*" | string[], queryKeys: QueryKey[]): void {
  const docs = useConvexQuery(mirrorListMine, { kind: "identitySignal" }) as
    | { data?: ChangeSignal }[]
    | undefined;
  useSignalInvalidation(docs, domains, queryKeys);
}

function useSignalInvalidation(
  docs: { data?: ChangeSignal }[] | undefined,
  domains: "*" | string[],
  queryKeys: QueryKey[],
): void {
  const qc = useQueryClient();
  const signal = docs?.[0]?.data;
  // undefined = subscription not loaded yet; null = loaded, no signal doc.
  const lastEventId = docs === undefined ? undefined : (signal?.lastEventId ?? null);

  // Latest args live in refs so the effect can depend on the signal alone —
  // callers pass fresh array literals every render.
  const args = useRef({ domains, queryKeys, touched: signal?.domains });
  args.current = { domains, queryKeys, touched: signal?.domains };
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
    const { domains: watch, queryKeys: keys, touched } = args.current;
    if (watch !== "*" && !(touched ?? []).some((d) => watch.includes(d))) return;
    for (const key of keys) void qc.invalidateQueries({ queryKey: key });
  }, [lastEventId, qc]);
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
