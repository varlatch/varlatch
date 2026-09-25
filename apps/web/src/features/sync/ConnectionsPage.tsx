// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, MoreHorizontal, TriangleAlert } from "lucide-react";
import type { PlatformConnection, SyncPlatform, SyncTarget } from "@varlatch/protocol";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { Button, Card, Input, Menu, Mono, cn } from "../../components/ui";
import { PlatformLogo } from "../../components/brand-logos";
import { platformMeta } from "./platform-meta";

/**
 * Organization-level Platform Connections (ADR-0031 §9). Replacing a
 * credential re-authorizes EVERY referencing Sync Target atomically, so the
 * full dependency list is shown before the operation — an actor managing
 * only development Targets learns here, not from a failure, that this
 * Connection also feeds production.
 */

export function ConnectionsPage() {
  const { org } = useParams() as { org: string };
  const { api } = useSession();
  const qc = useQueryClient();
  useOrgRealtime(org, ["sync"], [["platform-connections", org], ["org-sync-targets", org]]);

  const meta = useQuery({ queryKey: ["meta"], queryFn: () => api.meta() });
  const syncEnabled = (meta.data?.capabilities ?? []).includes("sync.targets");
  const adapters = (meta.data as { syncAdapters?: SyncPlatform[] } | undefined)?.syncAdapters ?? [];
  const connections = useQuery({
    queryKey: ["platform-connections", org],
    queryFn: () => api.listPlatformConnections(org),
  });
  const targets = useQuery({
    queryKey: ["org-sync-targets", org],
    queryFn: () => api.listOrgSyncTargets(org),
  });
  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["platform-connections", org] });
    void qc.invalidateQueries({ queryKey: ["org-sync-targets", org] });
  };
  const [creating, setCreating] = useState(false);

  return (
    <div className="space-y-4 pb-10">
      <div className="flex items-center gap-3">
        <h1 className="text-lg font-semibold">Connections</h1>
        <div className="flex-1" />
        {syncEnabled && (
          <Button data-testid="new-connection" onClick={() => setCreating((v) => !v)}>
            {creating ? "Cancel" : "New connection"}
          </Button>
        )}
      </div>
      <p className="text-sm text-muted">
        A Platform Connection authenticates one external platform account or instance — a GitHub
        owner, a Coolify instance, a Convex deployment. It discloses nothing by itself:
        disclosure authority lives on the Sync Targets that attach to it per environment (each
        environment's Integrations tab), and each Target pushes that environment's values to one
        destination (ADR-0031). A connection's base identity is immutable and its credential is
        stored encrypted, never redisplayed.
      </p>
      {creating && syncEnabled && (
        <CreateConnection
          org={org}
          adapters={adapters}
          onDone={() => {
            setCreating(false);
            invalidate();
          }}
        />
      )}
      {connections.data?.items.length === 0 && !creating && (
        <Card className="text-center py-8">
          <p className="text-sm font-medium mb-1" data-testid="connections-empty">
            No connections yet.
          </p>
          <p className="text-sm text-muted">
            {syncEnabled
              ? "Create one to let environments sync values to an external platform."
              : "Outbound sync is disabled on this installation."}
          </p>
        </Card>
      )}
      {(connections.data?.items ?? []).map((c) => (
        <ConnectionCard
          key={c.id}
          org={org}
          connection={c}
          targets={(targets.data?.items ?? []).filter((t) => t.connectionId === c.id)}
          onChanged={invalidate}
        />
      ))}
    </div>
  );
}

function CreateConnection({
  org,
  adapters,
  onDone,
}: {
  org: string;
  adapters: SyncPlatform[];
  onDone: () => void;
}) {
  const { api } = useSession();
  const [platform, setPlatform] = useState<SyncPlatform | null>(null);
  const [baseIdentity, setBaseIdentity] = useState("");
  const [name, setName] = useState("");
  const [credential, setCredential] = useState("");
  const [error, setError] = useState("");
  const create = useMutation({
    mutationFn: () => {
      setError("");
      return api.createPlatformConnection(org, {
        platform: platform as SyncPlatform,
        baseIdentity,
        name,
        credential,
      });
    },
    onSuccess: onDone,
    onError: (err) => setError(String(err)),
  });
  const meta = platform ? platformMeta(platform) : null;

  return (
    <Card data-testid="create-connection-form">
      <h2 className="font-medium mb-1">New connection</h2>
      <p className="text-sm text-muted mb-3">Pick the platform this connection authenticates to.</p>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3" data-testid="connection-platform">
        {adapters.map((a) => {
          const m = platformMeta(a);
          const active = platform === a;
          return (
            <button
              key={a}
              type="button"
              data-testid={`platform-card-${a}`}
              aria-pressed={active}
              onClick={() => setPlatform(a)}
              className={cn(
                "cursor-pointer rounded-lg border p-3 text-left transition-colors",
                active
                  ? "border-accent bg-accent-dim/40"
                  : "border-bd bg-inset hover:border-accent/50",
              )}
            >
              <span className="flex items-center gap-2 font-medium">
                <PlatformLogo platform={a} size={18} />
                {m.label}
              </span>
              <span className="mt-1 block text-xs text-muted">{m.description}</span>
            </button>
          );
        })}
      </div>
      {platform && meta && (
        <div className="mt-4 space-y-2 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <label className="text-muted w-28">{meta.identityLabel}</label>
            <Input
              data-testid="connection-base-identity"
              className="w-80"
              placeholder={meta.identityPlaceholder}
              value={baseIdentity}
              onChange={(e) => setBaseIdentity(e.target.value)}
            />
            <span className="text-xs text-muted">
              Immutable: a different {meta.identityNoun} is a new connection.
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <label className="text-muted w-28">Name</label>
            <Input
              data-testid="connection-display-name"
              className="w-64"
              placeholder={platform === "coolify" ? "prod coolify" : `prod ${meta.label}`}
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <label className="text-muted w-28">Credential</label>
            <Input
              data-testid="connection-new-credential"
              className="w-80"
              type="password"
              placeholder={meta.credentialPlaceholder}
              value={credential}
              onChange={(e) => setCredential(e.target.value)}
            />
            <span className="text-xs text-muted">{meta.credentialHelp}</span>
          </div>
          <div>
            <Button
              data-testid="save-connection"
              disabled={!baseIdentity || !name || !credential || create.isPending}
              onClick={() => create.mutate()}
            >
              Create connection
            </Button>
          </div>
        </div>
      )}
      {error && <p className="text-deny text-sm mt-2">{error}</p>}
    </Card>
  );
}

function ConnectionCard({
  org,
  connection,
  targets,
  onChanged,
}: {
  org: string;
  connection: PlatformConnection;
  targets: SyncTarget[];
  onChanged: () => void;
}) {
  const { api } = useSession();
  const [replacing, setReplacing] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [credential, setCredential] = useState("");
  const [error, setError] = useState("");
  const meta = platformMeta(connection.platform);

  const replace = useMutation({
    mutationFn: () => {
      setError("");
      return api.replacePlatformCredential(org, connection.id, {
        credential,
        expectedVersion: connection.version,
      });
    },
    onSuccess: () => {
      setReplacing(false);
      setCredential("");
      onChanged();
    },
    onError: (err) => setError(String(err)),
  });
  const revoke = useMutation({
    mutationFn: () => api.revokePlatformConnection(org, connection.id),
    onSuccess: onChanged,
    onError: (err) => setError(String(err)),
  });

  return (
    <Card data-connection={connection.id}>
      <div className="flex items-center gap-3">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-bd bg-inset text-fg">
          <PlatformLogo platform={connection.platform} size={18} />
        </span>
        <div className="min-w-0 flex-1">
          <p className="flex items-center gap-2 font-medium">
            <span className="truncate">{connection.name}</span>
            <span className="rounded-full border border-bd px-2 py-0.5 text-xs font-normal text-muted">
              {targets.length} target{targets.length === 1 ? "" : "s"}
            </span>
          </p>
          <p className="truncate text-sm text-muted">
            {meta.label} · <Mono>{connection.baseIdentity}</Mono>
          </p>
        </div>
        {/* Actions live in the menu; the former inline buttons' testids moved
            onto the menu items unchanged. */}
        <Menu
          data-testid={`connection-menu-${connection.id}`}
          label={`Actions for ${connection.name}`}
          items={[
            {
              label: replacing ? "Cancel replacement" : "Replace credential",
              "data-testid": `replace-credential-${connection.id}`,
              onSelect: () => setReplacing((v) => !v),
            },
            {
              label: "Revoke",
              danger: true,
              "data-testid": `revoke-connection-${connection.id}`,
              onSelect: () => revoke.mutate(),
            },
          ]}
        >
          <MoreHorizontal size={16} />
        </Menu>
      </div>
      {targets.length > 0 && (
        <div className="mt-2">
          <button
            type="button"
            className="inline-flex cursor-pointer items-center gap-1 text-xs text-muted hover:text-fg"
            aria-expanded={expanded}
            onClick={() => setExpanded((v) => !v)}
          >
            {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
            {expanded ? "Hide" : "Show"} target details
          </button>
          {expanded && (
            <div
              className="mt-1.5 space-y-0.5 rounded border border-bd bg-inset/40 p-2 text-xs text-muted"
              data-testid={`connection-targets-${connection.id}`}
            >
              {targets.map((t) => (
                <div key={t.id} className="flex items-center gap-2">
                  <Mono>{t.environmentId}</Mono>
                  <span>→</span>
                  <Mono>
                    {t.destination.repo
                      ? `${t.destination.repo}${t.destination.environment ? `#${t.destination.environment}` : ""}`
                      : (t.destination.applicationUuid ?? "deployment")}
                  </Mono>
                  <span className={cn(t.state === "disabled" && "text-deny")}>{t.state}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      {replacing && (
        <div className="mt-3 rounded border border-bd bg-inset/40 p-2 text-sm space-y-2">
          <p className="flex items-start gap-1.5">
            <TriangleAlert size={14} className="mt-0.5 shrink-0 text-tier-staging" />
            <span>
              Replacing this credential is a new disclosure grant for{" "}
              <strong>all {targets.length} referencing target(s) at once</strong>. You must hold
              disclosure authority for every one of them; otherwise the whole replacement is
              refused.
            </span>
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <Input
              data-testid={`new-credential-${connection.id}`}
              className="w-80"
              type="password"
              placeholder="New platform credential"
              value={credential}
              onChange={(e) => setCredential(e.target.value)}
            />
            <Button
              data-testid={`confirm-credential-${connection.id}`}
              disabled={!credential || replace.isPending}
              onClick={() => replace.mutate()}
            >
              Replace
            </Button>
          </div>
        </div>
      )}
      {error && <p className="text-deny text-sm mt-2">{error}</p>}
    </Card>
  );
}
