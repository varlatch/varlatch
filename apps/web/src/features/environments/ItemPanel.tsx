// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { useQueries, useQuery } from "@tanstack/react-query";
import { Braces, CircleAlert, CircleCheck, CircleDashed, Eye, EyeOff, Lock, Pencil, RefreshCw, Trash2, Undo2 } from "lucide-react";
import type { Environment, PlatformConnection, SyncTarget } from "@varlatch/protocol";
import type { Page } from "@varlatch/sdk";
import { useSession } from "../../lib/session";
import { shortId } from "../../lib/identity";
import { timeAgo, timeUntil, useNow } from "../../lib/time";
import { PanelSection } from "../../components/Drawer";
import { CopyButton } from "../../components/CodeBlock";
import { PlatformLogo } from "../../components/brand-logos";
import { Avatar, Badge, Button, Skeleton, cn } from "../../components/ui";
import { useCapability } from "../projects/hooks";
import {
  draftKind,
  requirednessLabel,
  type CellState,
  type ContractItemMeta,
  type Draft,
  type ServerItem,
} from "../values/model";
import type { Disclosed } from "../values/useDisclosure";
import { DraftMarker, SecretMask } from "../values/bits";
import { itemLedgerEntry, syncTargetItemStatus, targetLabel, targetPlatform } from "../sync/syncStatus";

export type PanelActions = {
  reveal: () => void;
  hide: () => void;
  edit: () => void;
  revert: () => void;
  remove: () => void;
  rotate: () => void;
  finishRotation: () => void;
};

/**
 * The selected item: what the contract says, the value (reveal is audited,
 * copy only after reveal for Secrets), rotation, where it syncs to, and its
 * history when the server can filter the audit log by item.
 */
export function ItemPanelBody({
  org,
  project,
  env,
  name,
  server,
  contract,
  sensitive,
  state,
  draft,
  disclosed,
  withheld,
  rotationDeadline,
  targets,
  connections,
  busy,
  actions,
}: {
  org: string;
  project: string;
  env: Environment;
  name: string;
  server: ServerItem | undefined;
  contract: ContractItemMeta | undefined;
  sensitive: boolean;
  state: CellState;
  draft: Draft | undefined;
  disclosed: Disclosed | undefined;
  withheld: boolean;
  /** Known only when the rotation was started from this page. */
  rotationDeadline: string | undefined;
  targets: SyncTarget[];
  connections: PlatformConnection[] | undefined;
  busy: { reveal?: boolean; finish?: boolean };
  actions: PanelActions;
}) {
  const now = useNow(30_000);
  const kind = draftKind(draft, server);
  const own = server?.source === "self";
  return (
    <>
      {contract?.description ? (
        <p className="-mt-2 text-[13px] text-muted">{contract.description}</p>
      ) : !contract ? (
        <p className="-mt-2 text-[13px] text-muted">Not in the contract. Values outside the contract are treated as secrets.</p>
      ) : null}

      <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5 text-[13px]">
        <dt className="text-muted">Type</dt>
        <dd className="font-mono text-[12.5px]">
          {contract?.type ?? "string"}
          {contract?.enumValues?.length ? <span className="text-muted"> · {contract.enumValues.join(", ")}</span> : null}
        </dd>
        <dt className="text-muted">Required</dt>
        <dd>{requirednessLabel(contract, env)}</dd>
        {contract?.defaultValue !== undefined && (
          <>
            <dt className="text-muted">Default</dt>
            <dd className="font-mono text-[12.5px]">{contract.defaultValue}</dd>
          </>
        )}
        {server?.source === "parent" && (
          <>
            <dt className="text-muted">Source</dt>
            <dd>Inherited from the parent environment</dd>
          </>
        )}
      </dl>

      <PanelSection
        title="Value"
        actions={kind ? <DraftMarker kind={kind} /> : undefined}
      >
        <div className="flex items-stretch gap-2">
          <div
            className={cn(
              "flex min-h-10 min-w-0 flex-1 items-center rounded-lg border border-bd bg-inset px-3 py-2",
              kind === "deleted" && "line-through decoration-deny/70",
            )}
            data-testid="panel-value"
          >
            <ValueText
              server={server}
              state={state}
              sensitive={sensitive}
              draft={draft}
              disclosed={disclosed}
              withheld={withheld}
              contract={contract}
            />
          </div>
          {sensitive && server && !draft && (
            <Button
              className="h-auto min-h-10 flex-col gap-0 px-3 py-1 leading-tight"
              data-testid="panel-reveal"
              loading={busy.reveal}
              onClick={disclosed ? actions.hide : actions.reveal}
            >
              <span className="flex items-center gap-1.5">
                {disclosed ? <EyeOff size={14} /> : <Eye size={14} />}
                {disclosed ? "Hide" : "Reveal"}
              </span>
              {!disclosed && <span className="text-[10.5px] font-normal text-muted">audited</span>}
            </Button>
          )}
          {(() => {
            const copy = sensitive ? disclosed?.value : !withheld ? server?.value : undefined;
            if (draft || !server) return null;
            return copy !== undefined && copy !== null ? (
              <CopyButton value={copy} className="h-auto min-h-10" data-testid="panel-copy">
                Copy
              </CopyButton>
            ) : sensitive ? (
              <Button className="h-auto min-h-10" disabled title="Reveal first to copy a secret">
                Copy
              </Button>
            ) : null;
          })()}
        </div>
        {server?.rawValue !== undefined && !draft && (
          <p className="mt-2 text-xs text-muted">
            Stored with a reference: <span className="font-mono text-fg/90">{server.rawValue}</span>
            {server.value != null && (
              <>
                {" "}
                expands to <span className="font-mono text-fg/90">{server.value}</span>
              </>
            )}
          </p>
        )}
        <div className="mt-3 flex flex-wrap gap-2">
          {kind !== "deleted" && (
            <Button size="sm" icon={<Pencil size={13} />} onClick={actions.edit} data-testid="panel-edit">
              {sensitive && server ? "Overwrite…" : server || draft ? "Edit" : "Set value"}
            </Button>
          )}
          {draft && (
            <Button size="sm" variant="ghost" icon={<Undo2 size={13} />} onClick={actions.revert}>
              Revert change
            </Button>
          )}
          {own && draft?.op !== "delete" && (
            <Button
              size="sm"
              variant="ghost"
              className="text-muted hover:text-deny"
              icon={<Trash2 size={13} />}
              onClick={actions.remove}
              data-testid={`delete-${name}`}
            >
              Delete value
            </Button>
          )}
        </div>
      </PanelSection>

      {own && (
        <PanelSection title="Rotation">
          {server?.rotating ? (
            <div className="space-y-3" data-testid="panel-rotation">
              <div className="flex items-center gap-2" aria-hidden="true">
                <span className="size-2.5 rounded-full bg-accent" />
                <span className="h-1 flex-1 overflow-hidden rounded-full bg-hover">
                  <span className="block h-full w-1/2 rounded-full bg-accent/80" />
                </span>
                <span className="size-2.5 rounded-full border-2 border-bd-strong" />
              </div>
              <div className="flex justify-between text-xs text-muted">
                <span>New value live</span>
                <span>{rotationDeadline ? `Grace ends ${timeUntil(rotationDeadline, now)}` : "Grace window open"}</span>
              </div>
              <p className="text-[13px] text-fg/90">Old and new values both work until you finish or the grace window ends.</p>
              {disclosed?.retiring !== undefined && (
                <p className="text-xs text-muted">
                  Previous value: <span className="font-mono text-fg/90">{disclosed.retiring}</span>
                </p>
              )}
              <Button
                variant="primary"
                size="sm"
                data-testid={`complete-rotation-${name}`}
                loading={busy.finish}
                onClick={actions.finishRotation}
              >
                Finish rotation
              </Button>
            </div>
          ) : (
            <div className="flex items-center justify-between gap-3">
              <p className="text-[13px] text-muted">Replace the value with an overlap window so consumers switch without an outage.</p>
              <Button
                size="sm"
                icon={<RefreshCw size={13} />}
                data-testid={`rotate-${name}`}
                disabled={Boolean(draft)}
                title={draft ? "Save or revert the change first" : undefined}
                onClick={actions.rotate}
              >
                Rotate…
              </Button>
            </div>
          )}
        </PanelSection>
      )}

      <SyncedTo org={org} project={project} env={env} name={name} targets={targets} connections={connections} />
      <History org={org} env={env} name={name} />
    </>
  );
}

function ValueText({
  server,
  state,
  sensitive,
  draft,
  disclosed,
  withheld,
  contract,
}: {
  server: ServerItem | undefined;
  state: CellState;
  sensitive: boolean;
  draft: Draft | undefined;
  disclosed: Disclosed | undefined;
  withheld: boolean;
  contract: ContractItemMeta | undefined;
}) {
  const mono = "min-w-0 break-all font-mono text-[13px]";
  if (draft?.op === "set") {
    return sensitive ? <SecretMask className="text-fg/80" /> : <span className={mono}>{draft.value || <em className="text-muted">(empty)</em>}</span>;
  }
  if (draft?.op === "delete") return sensitive ? <SecretMask /> : <span className={cn(mono, "text-muted")}>{server?.rawValue ?? server?.value}</span>;
  if (state === "missing_required") return <span className="text-[13px] font-medium text-deny">missing · required</span>;
  if (state === "covered_by_default") {
    return <span className="font-mono text-[13px] italic text-muted">default {contract?.defaultValue}</span>;
  }
  if (!server) return <span className="text-[13px] text-muted">Not set</span>;
  if (sensitive) return disclosed ? <span className={mono}>{disclosed.value}</span> : <SecretMask />;
  if (withheld) return <span className="text-[13px] text-muted">Set; your access does not include reading it</span>;
  return <span className={mono}>{server.value === "" ? <em className="text-muted">(empty)</em> : server.value}</span>;
}

function SyncedTo({
  org,
  project,
  env,
  name,
  targets,
  connections,
}: {
  org: string;
  project: string;
  env: Environment;
  name: string;
  targets: SyncTarget[];
  connections: PlatformConnection[] | undefined;
}) {
  const { api } = useSession();
  const now = useNow(60_000);
  const details = useQueries({
    queries: targets.map((t) => ({
      queryKey: ["sync-target", org, project, env.name, t.id],
      queryFn: () => api.getSyncTarget(org, project, env.name, t.id),
      retry: false,
    })),
  });
  return (
    <PanelSection title="Synced to">
      {targets.length === 0 ? (
        <p className="text-[13px] text-muted">No integration pushes this item.</p>
      ) : (
        <ul className="divide-y divide-bd overflow-hidden rounded-lg border border-bd" data-testid="panel-sync">
          {targets.map((t, i) => {
            const names = details[i]?.data?.names;
            const status = t.state !== "active" ? t.state : syncTargetItemStatus(t, names, name);
            const entry = itemLedgerEntry(t, names, name);
            const icon =
              status === "synced" ? (
                <CircleCheck size={15} className="text-allow" />
              ) : status === "failed" || status === "disabled" ? (
                <CircleAlert size={15} className="text-deny" />
              ) : (
                <CircleDashed size={15} className="text-muted" />
              );
            return (
              <li key={t.id} className="flex items-center gap-2.5 px-3 py-2.5 text-[13px]" data-sync-target={t.id}>
                <PlatformLogo platform={targetPlatform(t, connections)} size={16} className="shrink-0" />
                <span className="min-w-0 flex-1 truncate">{targetLabel(t, connections)}</span>
                {details[i]?.isLoading ? (
                  <Skeleton className="h-3.5 w-20" />
                ) : (
                  <span
                    className={cn(
                      "flex shrink-0 items-center gap-1.5 text-xs",
                      status === "synced" ? "text-muted" : status === "failed" || status === "disabled" ? "text-deny" : "text-muted",
                    )}
                    title={entry?.error ?? undefined}
                  >
                    {icon}
                    {status === "synced" && entry ? `synced ${timeAgo(entry.updatedAt, now)}` : status}
                  </span>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </PanelSection>
  );
}

const EVENT_LABEL: Record<string, string> = {
  "value.written": "set the value",
  "value.deleted": "deleted the value",
  "value.rotation_started": "started a rotation",
  "value.rotation_completed": "finished the rotation",
  "secret.disclosed": "revealed it",
  "value.disclosed": "read it",
  "secret.validated": "validated it",
  "value.validated": "validated it",
};

type AuditEvent = {
  eventId: string;
  eventType: string;
  occurredAt: string;
  actorIdentityId?: string | null;
  resource?: { environmentId?: string; itemName?: string } | null;
  metadata?: { items?: string } | null;
};

type FilteredAuditList = (
  org: string,
  opts: { item?: string; environmentId?: string; limit?: number },
) => Promise<Page<Record<string, unknown>>>;

/** Item history: only on servers that can filter the audit log by item. */
function History({ org, env, name }: { org: string; env: Environment; name: string }) {
  const supported = useCapability("audit.filters");
  const { api } = useSession();
  const now = useNow(60_000);
  const events = useQuery({
    queryKey: ["audit-item", org, env.id, name],
    enabled: supported,
    retry: false,
    queryFn: async () => {
      const list = api.listAuditEvents.bind(api) as unknown as FilteredAuditList;
      const page = await list(org, { item: name, environmentId: env.id, limit: 10 });
      // Defensive: keep only this item's events even if a filter was ignored.
      return (page.items as AuditEvent[]).filter(
        (e) =>
          e.resource?.environmentId === env.id &&
          (e.resource.itemName === name || (e.metadata?.items ?? "").split(",").some((s) => s.startsWith(`${name}@`))),
      );
    },
  });
  const identities = useQuery({
    queryKey: ["identities", org],
    queryFn: () => api.listIdentities(org),
    enabled: supported,
    retry: false,
  });
  if (!supported) return null;
  const who = (id: string | null | undefined) =>
    (id && identities.data?.items.find((i) => i.id === id)?.name) || (id ? shortId(id) : "Varlatch");
  return (
    <PanelSection title="History">
      {events.isLoading ? (
        <Skeleton className="h-16 w-full" />
      ) : (events.data ?? []).length === 0 ? (
        <p className="text-[13px] text-muted">No recorded activity for this item yet.</p>
      ) : (
        <ul className="divide-y divide-bd overflow-hidden rounded-lg border border-bd" data-testid="panel-history">
          {events.data!.map((e) => (
            <li key={e.eventId} className="flex items-center gap-2.5 px-3 py-2 text-[13px]">
              <Avatar name={who(e.actorIdentityId)} size="sm" />
              <span className="min-w-0 flex-1 truncate">
                <span className="text-fg">{who(e.actorIdentityId)}</span>{" "}
                <span className="text-muted">{EVENT_LABEL[e.eventType] ?? e.eventType}</span>
              </span>
              <span className="shrink-0 text-xs text-muted" title={e.occurredAt}>
                {timeAgo(e.occurredAt, now)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </PanelSection>
  );
}

/** Header badges and icon for the panel title. */
export function panelHeading(sensitive: boolean, type: string | undefined): { icon: React.ReactNode; badges: React.ReactNode } {
  return {
    icon: sensitive ? <Lock size={16} /> : <Braces size={16} />,
    badges: (
      <>
        {sensitive && <Badge tone="mono">secret</Badge>}
        <Badge tone="mono">{type ?? "string"}</Badge>
      </>
    ),
  };
}
