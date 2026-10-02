// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, MoreHorizontal, Plug, Plus, ShieldAlert, Trash2 } from "lucide-react";
import type { PlatformConnection, SyncPlatform, SyncTarget, Tier } from "@varlatch/protocol";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { timeAgo, useNow } from "../../lib/time";
import { Button, Callout, Count, EmptyState, Field, Input, Menu, Mono, Skeleton, Status, TierDot, cn } from "../../components/ui";
import { PageHeader } from "../../components/PageHeader";
import { Dialog, useConfirm } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { keys, useMeta, useOrgName } from "../projects/hooks";
import { connectionsKey } from "./keys";
import { platformMeta } from "./platform-meta";
import { connectionHealth, targetDestination } from "./status";
import { PlatformTile } from "./TargetCard";
import { useOrgEnvironments, type EnvironmentRef } from "./useOrgEnvironments";

/**
 * Platform connections: one credential per platform account or instance.
 * A connection discloses nothing by itself; the environments' integrations
 * that use it do. Replacing a credential re-authorizes every integration
 * that uses it at once, so the dependents are listed before it happens.
 */
export function ConnectionsPage() {
  const { org } = useParams() as { org: string };
  const { api } = useSession();
  const qc = useQueryClient();
  const orgName = useOrgName(org);
  useOrgRealtime(org, ["sync"], [connectionsKey(org), keys.orgSyncTargets(org)]);
  const meta = useMeta();
  const syncEnabled = (meta.data?.capabilities ?? []).includes("sync.targets");
  const adapters = (meta.data?.syncAdapters ?? []) as SyncPlatform[];
  const connections = useQuery({ queryKey: connectionsKey(org), queryFn: () => api.listPlatformConnections(org) });
  const targets = useQuery({ queryKey: keys.orgSyncTargets(org), queryFn: () => api.listOrgSyncTargets(org) });
  const envs = useOrgEnvironments(org);
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: connectionsKey(org) });
    void qc.invalidateQueries({ queryKey: keys.orgSyncTargets(org) });
    void qc.invalidateQueries({ queryKey: ["sync-targets", org] });
  };

  const [params, setParams] = useSearchParams();
  const [creating, setCreating] = useState<SyncPlatform | "pick" | null>(null);
  const [replacing, setReplacing] = useState<string | null>(null);
  // Integrations link here with ?replace=<connection> to fix a rejected credential.
  useEffect(() => {
    const id = params.get("replace");
    if (id && connections.data?.items.some((c) => c.id === id)) {
      setReplacing(id);
      params.delete("replace");
      setParams(params, { replace: true });
    }
  }, [params, setParams, connections.data]);

  const list = connections.data?.items ?? [];
  const allTargets = targets.data?.items ?? [];
  const replacingConnection = list.find((c) => c.id === replacing);

  return (
    <>
      <PageHeader
        breadcrumbs={[{ label: orgName, to: `/o/${org}/projects` }, { label: "Connections" }]}
        title="Connections"
        badges={list.length > 0 ? <Count className="h-6 min-w-6 text-xs">{list.length}</Count> : undefined}
        subtitle="Credentials for the platforms your environments push to. Stored encrypted, never shown again."
        actions={
          syncEnabled && (
            <Button variant="primary" size="lg" data-testid="new-connection" icon={<Plus size={16} />} onClick={() => setCreating("pick")}>
              New connection
            </Button>
          )
        }
      />

      {!syncEnabled && meta.data && (
        <Callout tone="warn" className="mb-4" title="Outbound sync is off on this installation">
          Connections can be listed and revoked, but no integration pushes values until an operator enables sync.
        </Callout>
      )}

      {connections.isLoading ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-64 rounded-xl" />
          ))}
        </div>
      ) : list.length === 0 ? (
        <div className="rounded-xl border border-dashed border-bd">
          <EmptyState
            icon={<Plug size={20} />}
            title={<span data-testid="connections-empty">No connections yet</span>}
            description={
              syncEnabled
                ? "Connect GitHub, Coolify or Convex so environments can push their values there."
                : "Outbound sync is disabled on this installation."
            }
            actions={
              syncEnabled ? (
                <div className="flex gap-2">
                  {adapters.map((a) => (
                    <button
                      key={a}
                      type="button"
                      onClick={() => setCreating(a)}
                      className="cursor-pointer rounded-lg transition-transform hover:scale-105"
                      aria-label={`Connect ${platformMeta(a).shortLabel}`}
                    >
                      <PlatformTile platform={a} size="lg" />
                    </button>
                  ))}
                </div>
              ) : undefined
            }
          />
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {list.map((c) => (
            <ConnectionCard
              key={c.id}
              org={org}
              connection={c}
              targets={allTargets.filter((t) => t.connectionId === c.id)}
              envs={envs.byId}
              onReplace={() => setReplacing(c.id)}
              onChanged={refresh}
            />
          ))}
          {syncEnabled && (
            <button
              type="button"
              onClick={() => setCreating("pick")}
              className="group flex min-h-48 cursor-pointer flex-col items-center justify-center gap-4 rounded-xl border border-dashed border-bd p-6 text-center transition-colors hover:border-accent/50 hover:bg-raised md:col-span-2 xl:col-span-3"
            >
              <span className="text-[15px] font-semibold text-fg">Connect another platform</span>
              <span className="flex gap-3">
                {adapters.map((a) => (
                  <PlatformTile key={a} platform={a} size="lg" className="transition-colors group-hover:border-bd-strong" />
                ))}
              </span>
              <span className="text-[13px] text-muted">More platforms coming</span>
            </button>
          )}
        </div>
      )}

      {creating && (
        <NewConnectionDialog
          org={org}
          adapters={adapters}
          initial={creating === "pick" ? null : creating}
          onClose={() => setCreating(null)}
          onCreated={() => {
            setCreating(null);
            refresh();
          }}
        />
      )}
      {replacingConnection && (
        <ReplaceCredentialDialog
          org={org}
          connection={replacingConnection}
          targets={allTargets.filter((t) => t.connectionId === replacingConnection.id)}
          envs={envs.byId}
          onClose={() => setReplacing(null)}
          onReplaced={() => {
            setReplacing(null);
            refresh();
          }}
        />
      )}
    </>
  );
}

/** Credential age in days: "today", "3d ago", "92d ago". */
function age(iso: string, now: number): string {
  const days = Math.floor((now - Date.parse(iso)) / 86_400_000);
  if (days < 1) return timeAgo(iso, now);
  return `${days}d ago`;
}

function targetEnv(t: SyncTarget, envs: Map<string, EnvironmentRef>) {
  return envs.get(t.environmentId);
}

/** "api / production" chip with the tier dot, linking to that environment's integrations. */
function EnvChip({ org, target, envs }: { org: string; target: SyncTarget; envs: Map<string, EnvironmentRef> }) {
  const ref = targetEnv(target, envs);
  const failing = target.state === "disabled" || target.failureCount > 0;
  const inner = (
    <>
      {ref ? <TierDot tier={ref.environment.tier as Tier} /> : <span className="size-2 rounded-full bg-subtle" />}
      <span className="truncate font-mono text-xs">
        {ref ? `${ref.project.slug} / ${ref.environment.name}` : "an environment"}
      </span>
      {failing && <span className="ml-auto shrink-0 text-[11px] text-deny">failing</span>}
      {target.state === "paused" && <span className="ml-auto shrink-0 text-[11px] text-muted">paused</span>}
    </>
  );
  const cls = "flex min-w-0 items-center gap-2 rounded-md border border-bd bg-inset px-2.5 py-1.5";
  return ref ? (
    <Link
      to={`/o/${org}/p/${ref.project.slug}/e/${encodeURIComponent(ref.environment.name)}/integrations`}
      className={cn(cls, "hover:border-bd-strong hover:bg-hover")}
      title={targetDestination(target).primary}
    >
      {inner}
    </Link>
  ) : (
    <span className={cls}>{inner}</span>
  );
}

function ConnectionCard({
  org,
  connection,
  targets,
  envs,
  onReplace,
  onChanged,
}: {
  org: string;
  connection: PlatformConnection;
  targets: SyncTarget[];
  envs: Map<string, EnvironmentRef>;
  onReplace: () => void;
  onChanged: () => void;
}) {
  const { api } = useSession();
  const confirm = useConfirm();
  const toast = useToast();
  const now = useNow();
  const meta = platformMeta(connection.platform);
  const health = connectionHealth(targets);
  const revoke = useMutation({
    mutationFn: () => api.revokePlatformConnection(org, connection.id),
    onSuccess: () => {
      onChanged();
      toast.success("Connection revoked", { description: `${targets.length} integration${targets.length === 1 ? "" : "s"} stopped.` });
    },
    onError: (err) => toast.error("Could not revoke the connection", { description: err instanceof Error ? err.message : String(err) }),
  });

  const askRevoke = async () => {
    const ok = await confirm({
      title: `Revoke ${connection.name}?`,
      tone: "danger",
      confirmLabel: "Revoke connection",
      description: "Varlatch deletes the stored credential. Values already pushed stay on the platform.",
      consequences:
        targets.length === 0
          ? [{ text: "No integration uses this connection." }]
          : [
              { text: `${targets.length} integration${targets.length === 1 ? "" : "s"} stop pushing until pointed at another connection:` },
              ...targets.map((t) => {
                const ref = targetEnv(t, envs);
                return {
                  icon: ref ? <TierDot tier={ref.environment.tier as Tier} className="mt-1" /> : undefined,
                  text: (
                    <span className="font-mono text-xs">
                      {ref ? `${ref.project.slug} / ${ref.environment.name}` : "an environment"} → {targetDestination(t, connection).primary}
                    </span>
                  ),
                };
              }),
            ],
    });
    if (ok) revoke.mutate();
  };

  return (
    <article data-connection={connection.id} className="flex flex-col rounded-xl border border-bd bg-raised">
      <div className="flex items-start gap-3.5 px-5 pt-5">
        <span title={meta.label}>
          <PlatformTile platform={connection.platform} size="lg" />
        </span>
        <div className="min-w-0 flex-1">
          <h2 className="truncate text-[17px] font-semibold text-fg">{connection.name}</h2>
          <p className="mt-0.5 truncate font-mono text-[13px] text-muted" title={connection.baseIdentity}>
            {connection.platform === "coolify" || connection.platform === "convex" ? connection.baseIdentity.replace(/^https?:\/\//, "") : connection.baseIdentity}
          </p>
        </div>
        <Menu
          data-testid={`connection-menu-${connection.id}`}
          label={`Actions for ${connection.name}`}
          buttonClassName="size-8 justify-center border border-bd"
          items={[
            {
              label: "Replace credential",
              icon: <KeyRound size={14} />,
              "data-testid": `replace-credential-${connection.id}`,
              onSelect: onReplace,
            },
            {
              label: "Revoke connection",
              danger: true,
              separatorBefore: true,
              icon: <Trash2 size={14} />,
              "data-testid": `revoke-connection-${connection.id}`,
              onSelect: () => void askRevoke(),
            },
          ]}
        >
          <MoreHorizontal size={16} />
        </Menu>
      </div>
      <div className="space-y-2.5 px-5 pb-4 pt-3.5">
        <Status tone={health.tone} className="text-sm">
          {health.label}
          {health.at && health.tone === "error" && <span className="text-deny/80">· {timeAgo(health.at, now)}</span>}
        </Status>
        {health.credentialRejected && (
          <div>
            <Button variant="danger" size="sm" onClick={onReplace} data-testid={`fix-connection-${connection.id}`}>
              Replace credential
            </Button>
          </div>
        )}
      </div>
      <div className="flex-1 border-t border-bd px-5 py-4">
        <p className="mb-2 text-[13px] text-muted">
          {targets.length === 0 ? "Not used by any integration" : `Used by ${targets.length} target${targets.length === 1 ? "" : "s"}`}
        </p>
        <div className="space-y-1.5" data-testid={`connection-targets-${connection.id}`}>
          {targets.map((t) => (
            <EnvChip key={t.id} org={org} target={t} envs={envs} />
          ))}
        </div>
      </div>
      <p className="border-t border-bd px-5 py-3 text-xs text-muted" title={new Date(connection.updatedAt ?? connection.createdAt).toLocaleString()}>
        {connection.updatedAt ? "Credential replaced" : "Credential set"} {age(connection.updatedAt ?? connection.createdAt, now)}
      </p>
    </article>
  );
}

function NewConnectionDialog({
  org,
  adapters,
  initial,
  onClose,
  onCreated,
}: {
  org: string;
  adapters: SyncPlatform[];
  initial: SyncPlatform | null;
  onClose: () => void;
  onCreated: () => void;
}) {
  const { api } = useSession();
  const toast = useToast();
  const [platform, setPlatform] = useState<SyncPlatform | null>(initial);
  const [baseIdentity, setBaseIdentity] = useState("");
  const [name, setName] = useState("");
  const [credential, setCredential] = useState("");
  const meta = platform ? platformMeta(platform) : null;
  const create = useMutation({
    mutationFn: () =>
      api.createPlatformConnection(org, { platform: platform as SyncPlatform, baseIdentity: baseIdentity.trim(), name: name.trim(), credential }),
    onSuccess: (c) => {
      toast.success("Connection created", { description: `${c.name} is ready for integrations.` });
      onCreated();
    },
    onError: (err) => toast.error("Could not create the connection", { description: err instanceof Error ? err.message : String(err) }),
  });
  const ready = Boolean(platform && baseIdentity.trim() && name.trim() && credential);

  return (
    <Dialog
      open
      onClose={onClose}
      title="New connection"
      description="Pick the platform, then the account or instance and a credential for it."
      size="md"
      data-testid="create-connection-form"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" data-testid="save-connection" disabled={!ready} loading={create.isPending} onClick={() => create.mutate()}>
            Create connection
          </Button>
        </>
      }
    >
      <div className="space-y-5">
        <div className="grid grid-cols-3 gap-2" role="radiogroup" aria-label="Platform" data-testid="connection-platform">
          {adapters.map((a) => {
            const m = platformMeta(a);
            return (
              <button
                key={a}
                type="button"
                role="radio"
                aria-checked={platform === a}
                data-testid={`platform-card-${a}`}
                onClick={() => setPlatform(a)}
                className={cn(
                  "flex cursor-pointer flex-col items-center gap-2 rounded-xl border bg-inset/40 px-3 py-4 text-center transition-colors",
                  platform === a ? "border-accent bg-accent/[0.06] ring-2 ring-accent/20" : "border-bd hover:border-bd-strong",
                )}
              >
                <PlatformTile platform={a} />
                <span className="text-sm font-medium text-fg">{m.shortLabel}</span>
              </button>
            );
          })}
        </div>
        {meta && <p className="-mt-2 text-[13px] text-muted">{meta.description}</p>}
        {meta && (
          <div className="space-y-4">
            <Field label={meta.identityLabel} hint={`Fixed once created: another ${meta.identityNoun} is another connection.`}>
              <Input
                data-testid="connection-base-identity"
                mono
                className="w-full"
                placeholder={meta.identityPlaceholder}
                value={baseIdentity}
                onChange={(e) => setBaseIdentity(e.target.value)}
              />
            </Field>
            <Field label="Name">
              <Input
                data-testid="connection-display-name"
                className="w-full"
                placeholder={`${meta.shortLabel} production`}
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </Field>
            <Field label={meta.credentialLabel} hint={meta.credentialHelp}>
              <Input
                data-testid="connection-new-credential"
                mono
                type="password"
                autoComplete="off"
                className="w-full"
                placeholder={meta.credentialPlaceholder}
                value={credential}
                onChange={(e) => setCredential(e.target.value)}
              />
            </Field>
          </div>
        )}
      </div>
    </Dialog>
  );
}

function ReplaceCredentialDialog({
  org,
  connection,
  targets,
  envs,
  onClose,
  onReplaced,
}: {
  org: string;
  connection: PlatformConnection;
  targets: SyncTarget[];
  envs: Map<string, EnvironmentRef>;
  onClose: () => void;
  onReplaced: () => void;
}) {
  const { api } = useSession();
  const toast = useToast();
  const [credential, setCredential] = useState("");
  const meta = platformMeta(connection.platform);
  const replace = useMutation({
    mutationFn: () => api.replacePlatformCredential(org, connection.id, { credential, expectedVersion: connection.version }),
    onSuccess: () => {
      toast.success("Credential replaced", { description: "Failing integrations retry with it now." });
      onReplaced();
    },
    onError: (err) => toast.error("The credential was not replaced", { description: err instanceof Error ? err.message : String(err) }),
  });
  return (
    <Dialog
      open
      onClose={onClose}
      title={`Replace the credential of ${connection.name}`}
      description={
        <>
          {meta.label} · <Mono>{connection.baseIdentity}</Mono>
        </>
      }
      size="md"
      data-testid={`replace-credential-dialog-${connection.id}`}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            data-testid={`confirm-credential-${connection.id}`}
            disabled={!credential}
            loading={replace.isPending}
            onClick={() => replace.mutate()}
          >
            Replace credential
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {targets.length > 0 && (
          <Callout tone="warn" icon={<ShieldAlert size={16} />} title={`This re-authorizes all ${targets.length} integration${targets.length === 1 ? "" : "s"} at once`}>
            You need integration authority over every one of them, otherwise nothing changes.
            <span className="mt-2 grid gap-1.5">
              {targets.map((t) => (
                <EnvChip key={t.id} org={org} target={t} envs={envs} />
              ))}
            </span>
          </Callout>
        )}
        <Field label={`New ${meta.credentialLabel.toLowerCase()}`} hint={meta.credentialHelp}>
          <Input
            data-testid={`new-credential-${connection.id}`}
            mono
            type="password"
            autoComplete="off"
            className="w-full"
            placeholder={meta.credentialPlaceholder}
            value={credential}
            onChange={(e) => setCredential(e.target.value)}
          />
        </Field>
      </div>
    </Dialog>
  );
}

