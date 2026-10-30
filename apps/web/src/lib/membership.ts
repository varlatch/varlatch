// SPDX-License-Identifier: AGPL-3.0-or-later
import { useRef } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useQueryClient, type QueryClient, type QueryKey } from "@tanstack/react-query";
import { useToast } from "../components/Toast";
import { useMeSignal } from "./realtime";
import { useSession } from "./session";

/**
 * When the signed-in person's membership changes (ADR-0052 Decision 9:
 * removed from an organization, or given another role), varlatchd signals
 * them, not only the organization. Their dashboard then refreshes its
 * organization list and realtime token, cancels and drops everything cached
 * for an organization it lost, revealed values included, and leaves that
 * organization's pages. A realtime token minted before the removal keeps
 * its claim for up to ten minutes; it carries change signals only.
 */

export interface OrgSummary {
  id: string;
  slug: string;
  name: string;
}

/** The organizations in `before` that `after` no longer lists. */
export function lostOrganizations(before: OrgSummary[], after: OrgSummary[]): OrgSummary[] {
  const kept = new Set(after.map((o) => o.id));
  return before.filter((o) => !kept.has(o.id));
}

/** Whether a query key belongs to `org`: it names its slug or its ID. */
export function mentionsOrganization(queryKey: QueryKey, org: Pick<OrgSummary, "id" | "slug">): boolean {
  const key = JSON.stringify(queryKey);
  return key.includes(JSON.stringify(org.slug)) || key.includes(JSON.stringify(org.id));
}

/**
 * Re-read the organization list (a new request, never one already in
 * flight), then cancel and drop every query of an organization no longer
 * in it. Returns the organizations lost.
 */
export async function dropLostOrganizations(
  qc: QueryClient,
  listOrganizations: () => Promise<{ items: OrgSummary[] }>,
  current?: string,
): Promise<OrgSummary[]> {
  const before = qc.getQueryData<{ items: OrgSummary[] }>(["orgs"])?.items ?? [];
  // A read already in flight may have started before the change: cancel it
  // and read again, never join it.
  await qc.cancelQueries({ queryKey: ["orgs"], exact: true });
  const after = await listOrganizations();
  qc.setQueryData(["orgs"], after);
  const lost = lostOrganizations(before, after.items);
  // The page's own organization counts as lost when the list no longer has
  // it, even if the list was never loaded before.
  if (current && !after.items.some((o) => o.slug === current) && !lost.some((o) => o.slug === current)) {
    lost.push({ id: current, slug: current, name: current });
  }
  for (const org of lost) {
    const predicate = (q: { queryKey: QueryKey }) => mentionsOrganization(q.queryKey, org);
    await qc.cancelQueries({ predicate });
    qc.removeQueries({ predicate });
  }
  return lost;
}

/** Mounted once in the shell: acts on the signed-in person's membership signal. */
export function useMembershipWatcher(): void {
  const qc = useQueryClient();
  const { api, accessChanged } = useSession();
  const navigate = useNavigate();
  const toast = useToast();
  const { org } = useParams();
  const current = useRef(org);
  current.current = org;
  useMeSignal(["membership"], () => {
    // Revealed values are masked and the realtime token minted again first.
    accessChanged();
    void (async () => {
      const here = current.current;
      const lost = await dropLostOrganizations(qc, () => api.listOrganizations(), here);
      const left = lost.find((o) => o.slug === here);
      if (left) {
        navigate("/", { replace: true });
        toast.error(`You no longer have access to ${left.name}`, {
          description: "An admin removed you from this organization, or you left it.",
        });
      }
      // Another role changes what every remaining page may show.
      await qc.invalidateQueries();
    })().catch(() => undefined);
  });
}
