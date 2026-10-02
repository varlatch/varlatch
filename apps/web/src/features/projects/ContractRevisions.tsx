// SPDX-License-Identifier: AGPL-3.0-or-later
import { useQuery } from "@tanstack/react-query";
import { MoreHorizontal } from "lucide-react";
import type { ContractRevision } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { timeAgo, useNow } from "../../lib/time";
import { Badge, Menu, cn } from "../../components/ui";
import { useToast } from "../../components/Toast";
import { useCapability } from "./hooks";
import { revisionSemanticsVersion } from "./semanticsMove";

type RevisionEntry = {
  id: string;
  pushedAt: string;
  actorIdentityId: string | null;
  semanticsVersion: number | undefined;
  itemCount: number | undefined;
};

/** "rev_ljyxtq…mzgq": enough to tell revisions apart, short enough to scan. */
export function shortRevision(id: string): string {
  return id.length > 14 ? `${id.slice(0, 8)}…${id.slice(-4)}` : id;
}

/**
 * Revision history. The API serves the active revision only, so older
 * revisions, and who pushed each one, come from the audit log when this
 * server filters it and the viewer may read it; otherwise the card shows
 * the active revision alone.
 */
export function ContractRevisions({
  org,
  projectId,
  active,
  className,
}: {
  org: string;
  projectId: string;
  active: ContractRevision;
  className?: string;
}) {
  const { api } = useSession();
  const toast = useToast();
  const now = useNow();
  const filters = useCapability("audit.filters");
  const history = useQuery({
    queryKey: ["audit", org, "contract-revisions", projectId],
    queryFn: () => api.listAuditEvents(org, { projectId, eventType: "contract.*", limit: 50 }),
    enabled: filters,
    retry: false,
    staleTime: 30_000,
  });
  const identities = useQuery({
    queryKey: ["identities", org],
    queryFn: () => api.listIdentities(org),
    enabled: filters,
    retry: false,
    staleTime: 60_000,
  });
  const nameOf = (id: string | null) => (id ? identities.data?.items.find((i) => i.id === id)?.name : undefined);

  const entries: RevisionEntry[] = [];
  for (const e of history.data?.items ?? []) {
    if (e.eventType !== "contract.revision_pushed") continue;
    const id = (e.resource as { contractRevisionId?: string } | undefined)?.contractRevisionId;
    if (!id || entries.some((x) => x.id === id)) continue;
    const meta = (e.metadata ?? {}) as { semanticsVersion?: number; itemCount?: number };
    entries.push({
      id,
      pushedAt: e.occurredAt as string,
      actorIdentityId: (e.actorIdentityId as string | null) ?? null,
      semanticsVersion: meta.semanticsVersion,
      itemCount: meta.itemCount,
    });
  }
  if (!entries.some((x) => x.id === active.id)) {
    entries.unshift({
      id: active.id,
      pushedAt: active.createdAt,
      actorIdentityId: null,
      semanticsVersion: revisionSemanticsVersion(active),
      itemCount: ((active.contract as { items?: unknown[] } | undefined)?.items ?? []).length,
    });
  }
  const shown = entries.slice(0, 5);
  const copy = (id: string) =>
    void navigator.clipboard.writeText(id).then(
      () => toast.success("Revision ID copied"),
      () => undefined,
    );

  return (
    <section className={cn("rounded-xl border border-bd bg-raised", className)} data-testid="contract-revisions">
      <h2 className="border-b border-bd px-5 py-3.5 text-[15px] font-semibold">Revisions</h2>
      <ol className="relative px-5 py-4">
        {shown.map((r, i) => {
          const isActive = r.id === active.id;
          const by = nameOf(r.actorIdentityId);
          return (
            <li key={r.id} className="relative flex gap-3 pb-4 last:pb-0" data-revision={r.id}>
              {i < shown.length - 1 && <span aria-hidden="true" className="absolute left-[7px] top-5 h-[calc(100%-0.75rem)] w-px bg-bd" />}
              <span
                aria-hidden="true"
                className={cn(
                  "relative mt-1 flex size-[15px] shrink-0 items-center justify-center rounded-full",
                  isActive ? "bg-accent/25 ring-1 ring-accent" : "bg-transparent",
                )}
              >
                <span className={cn("size-2 rounded-full", isActive ? "bg-accent" : "bg-subtle")} />
              </span>
              <div className="min-w-0 flex-1">
                <p className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[13px] font-medium text-fg" title={r.id}>
                    {shortRevision(r.id)}
                  </span>
                  {isActive && <Badge tone="accent">active</Badge>}
                </p>
                <p className="mt-0.5 text-xs text-muted" title={new Date(r.pushedAt).toLocaleString()}>
                  pushed {timeAgo(r.pushedAt, now)}
                  {by && (
                    <>
                      {" "}
                      by <span className="text-fg/90">{by}</span>
                    </>
                  )}
                </p>
                <p className="text-xs text-muted">
                  {r.semanticsVersion !== undefined && `rules v${r.semanticsVersion}`}
                  {r.itemCount !== undefined && ` · ${r.itemCount} item${r.itemCount === 1 ? "" : "s"}`}
                </p>
              </div>
              <Menu
                label={`Actions for revision ${shortRevision(r.id)}`}
                buttonClassName="size-7 justify-center border border-bd"
                items={[{ label: "Copy revision ID", onSelect: () => copy(r.id) }]}
              >
                <MoreHorizontal size={15} />
              </Menu>
            </li>
          );
        })}
      </ol>
      {entries.length > shown.length && (
        <p className="border-t border-bd px-5 py-2.5 text-xs text-muted">
          {entries.length - shown.length} older revision{entries.length - shown.length === 1 ? "" : "s"} in the audit log
        </p>
      )}
    </section>
  );
}
