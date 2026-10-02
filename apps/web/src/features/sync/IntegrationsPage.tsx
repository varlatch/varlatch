// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import { useParams } from "react-router-dom";
import { useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { Info, Plus, Upload } from "lucide-react";
import type { SyncPlatform, SyncTarget } from "@varlatch/protocol";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { Button, Callout, EmptyState, Mono, Skeleton, cn } from "../../components/ui";
import { keys, useEnvironmentContext, useMeta } from "../projects/hooks";
import { connectionsKey } from "./keys";
import { AddIntegrationDialog } from "./AddIntegrationDialog";
import { TargetCard } from "./TargetCard";
import { targetDestination } from "./status";
import { syncTargetItemStatus } from "./syncStatus";

// Moved to ./syncStatus; re-exported for existing importers.
export { syncTargetItemStatus } from "./syncStatus";

/**
 * Environment integrations: each sync target is a standing, audited
 * disclosure of this environment's values to one destination. Creating one
 * goes through a review that names exactly what leaves and where.
 */


/**
 * Per-target synced/pending/failed for one rotating item: the operator
 * completes a rotation on evidence, not hope.
 */
export function RotationSyncStatus({ item }: { item: string }) {
  const { org, project, env: envParam } = useParams() as { org: string; project: string; env: string };
  const env = decodeURIComponent(envParam);
  const { api } = useSession();
  const targets = useQuery({
    queryKey: keys.syncTargets(org, project, env),
    queryFn: () => api.listSyncTargets(org, project, env),
  });
  const details = useQueries({
    queries: (targets.data?.items ?? []).map((t) => ({
      queryKey: ["sync-target", org, project, env, t.id],
      queryFn: () => api.getSyncTarget(org, project, env, t.id),
    })),
  });
  const items = targets.data?.items ?? [];
  if (items.length === 0) return null;
  return (
    <span className="ml-2 inline-flex gap-2 text-[10px]" data-testid={`rotation-sync-${item}`}>
      {items.map((t, i) => {
        const status = syncTargetItemStatus(t, details[i]?.data?.names, item);
        const label = targetDestination(t).primary;
        return (
          <span
            key={t.id}
            className={cn(
              status === "synced" && "text-allow",
              status === "pending" && "text-muted",
              status === "failed" && "text-deny",
            )}
            title={`Integration ${label}: new value ${status}`}
          >
            {label}: {status}
          </span>
        );
      })}
    </span>
  );
}

export function IntegrationsPage() {
  const { org, project, environment } = useEnvironmentContext();
  const envName = environment.name;
  const { api } = useSession();
  const qc = useQueryClient();
  useOrgRealtime(org, ["sync"], [keys.syncTargets(org, project.slug, envName), connectionsKey(org)]);

  const meta = useMeta();
  const syncEnabled = (meta.data?.capabilities ?? []).includes("sync.targets");
  const adapters = (meta.data?.syncAdapters ?? []) as SyncPlatform[];
  const targets = useQuery({
    queryKey: keys.syncTargets(org, project.slug, envName),
    queryFn: () => api.listSyncTargets(org, project.slug, envName),
  });
  const connections = useQuery({ queryKey: connectionsKey(org), queryFn: () => api.listPlatformConnections(org) });
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: keys.syncTargets(org, project.slug, envName) });
    void qc.invalidateQueries({ queryKey: keys.orgSyncTargets(org) });
    void qc.invalidateQueries({ queryKey: connectionsKey(org) });
  };
  const [adding, setAdding] = useState(false);
  const items = targets.data?.items ?? [];
  const byId = new Map((connections.data?.items ?? []).map((c) => [c.id, c]));

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Callout tone="neutral" icon={<Info size={16} />} className="min-w-0 flex-1 py-2.5">
          Each integration is a standing, audited disclosure of this environment's values to one destination.
        </Callout>
        {syncEnabled && (
          <Button variant="primary" size="lg" data-testid="add-integration" icon={<Plus size={16} />} onClick={() => setAdding(true)}>
            Add integration
          </Button>
        )}
      </div>

      {!syncEnabled && meta.data && (
        <Callout tone="warn" data-testid="sync-disabled-notice" title="Outbound sync is off on this installation">
          Values can still reach other platforms from your own CI with <Mono className="text-fg">varlatch sync push</Mono>.
        </Callout>
      )}

      {targets.isLoading ? (
        <div className="space-y-3">
          <Skeleton className="h-28 w-full rounded-xl" />
          <Skeleton className="h-28 w-full rounded-xl" />
        </div>
      ) : items.length === 0 ? (
        <div className="rounded-xl border border-dashed border-bd">
          <EmptyState
            data-testid="integrations-empty"
            icon={<Upload size={20} />}
            title="Nothing leaves this environment"
            description="Add an integration to push its values to GitHub Actions, Coolify or Convex. You review exactly what leaves before it is created."
            actions={
              syncEnabled ? (
                <Button onClick={() => setAdding(true)} icon={<Plus size={14} />}>
                  Add integration
                </Button>
              ) : undefined
            }
          />
        </div>
      ) : (
        <div className="space-y-3">
          {items.map((t) => (
            <TargetCard
              key={t.id}
              org={org}
              project={project.slug}
              envName={envName}
              target={t}
              connection={byId.get(t.connectionId)}
              onChanged={refresh}
            />
          ))}
        </div>
      )}

      {adding && (
        <AddIntegrationDialog
          open
          onClose={() => setAdding(false)}
          onCreated={() => {
            setAdding(false);
            refresh();
          }}
          org={org}
          project={project.slug}
          envName={envName}
          adapters={adapters}
          connections={connections.data?.items ?? []}
        />
      )}
    </div>
  );
}
