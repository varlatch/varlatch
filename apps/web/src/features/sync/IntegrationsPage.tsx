// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient, useQueries } from "@tanstack/react-query";
import { ArrowLeft, Check, CircleDashed, Pause, Play, RefreshCw, TriangleAlert } from "lucide-react";
import type { PlatformConnection, SyncMappingInput, SyncPlatform, SyncTarget } from "@varlatch/protocol";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { Button, Card, Input, Mono, Select, cn } from "../../components/ui";
import { PlatformLogo } from "../../components/brand-logos";
import { platformMeta } from "./platform-meta";

/**
 * Environment integrations (ADR-0031 §9): the UI face of Sync Targets.
 * Creating one is an explicit standing disclosure — the review step says
 * exactly what will leave Varlatch and where; nothing is on by default.
 */

const STATE_LABEL: Record<string, { label: string; className: string; icon: typeof Check }> = {
  active: { label: "active", className: "text-allow", icon: Check },
  paused: { label: "paused", className: "text-muted", icon: Pause },
  disabled: { label: "disabled", className: "text-deny", icon: TriangleAlert },
};

export function syncTargetItemStatus(
  target: SyncTarget,
  names: { name: string; state: string }[] | undefined,
  itemName: string,
): "synced" | "pending" | "failed" {
  const destName =
    target.mapping.kind === "explicit"
      ? (target.mapping.items.find((i) => i.name === itemName)?.rename ?? itemName)
      : itemName;
  const entry = names?.find((n) => n.name.toLowerCase() === destName.toLowerCase());
  if (entry?.state.startsWith("failed")) return "failed";
  if (entry?.state === "written" && !target.needsSync) return "synced";
  return "pending";
}

/**
 * Per-target synced/pending/failed for one rotating item (ADR-0031 §5):
 * the operator completes rotation on evidence, not hope.
 */
export function RotationSyncStatus({ item }: { item: string }) {
  const { org, project, env: envParam } = useParams() as { org: string; project: string; env: string };
  const env = decodeURIComponent(envParam);
  const { api } = useSession();
  const targets = useQuery({
    queryKey: ["sync-targets", org, project, env],
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
        return (
          <span
            key={t.id}
            className={cn(
              status === "synced" && "text-allow",
              status === "pending" && "text-muted",
              status === "failed" && "text-deny",
            )}
            title={`Sync Target ${destinationLabel(t)}: new value ${status}`}
          >
            {destinationLabel(t)}: {status}
          </span>
        );
      })}
    </span>
  );
}

function destinationLabel(t: SyncTarget): string {
  // convex targets have an empty destination: the Connection's deployment
  // URL is the destination.
  return t.destination.repo
    ? `${t.destination.repo}${t.destination.environment ? `#${t.destination.environment}` : ""}`
    : (t.destination.applicationUuid ?? "deployment");
}

function mappingLabel(t: SyncTarget): string {
  if (t.mapping.kind === "wildcard" && t.mapping.exclude?.length) {
    return `all items except ${t.mapping.exclude.join(", ")}`;
  }
  return t.mapping.kind === "wildcard"
    ? "all items (incl. future)"
    : t.mapping.items.map((i) => (i.rename ? `${i.name}→${i.rename}` : i.name)).join(", ");
}

export function IntegrationsPage() {
  const { org, project, env } = useParams() as { org: string; project: string; env: string };
  const envName = decodeURIComponent(env);
  const { api } = useSession();
  const qc = useQueryClient();
  useOrgRealtime(
    org,
    ["sync"],
    [
      ["sync-targets", org, project, envName],
      ["platform-connections", org],
    ],
  );

  const meta = useQuery({ queryKey: ["meta"], queryFn: () => api.meta() });
  const syncEnabled = (meta.data?.capabilities ?? []).includes("sync.targets");
  const adapters = (meta.data as { syncAdapters?: SyncPlatform[] } | undefined)?.syncAdapters ?? [];

  const targets = useQuery({
    queryKey: ["sync-targets", org, project, envName],
    queryFn: () => api.listSyncTargets(org, project, envName),
  });
  const connections = useQuery({
    queryKey: ["platform-connections", org],
    queryFn: () => api.listPlatformConnections(org),
  });

  const invalidate = () =>
    void qc.invalidateQueries({ queryKey: ["sync-targets", org, project, envName] });

  const [adding, setAdding] = useState(false);

  return (
    <div className="space-y-4 pb-10">
      <div className="flex items-center gap-3 flex-wrap">
        <Link
          to={`/o/${org}/p/${project}/e/${env}`}
          className="text-muted hover:text-fg inline-flex items-center gap-1 text-sm"
          data-testid="back-to-editor"
        >
          <ArrowLeft size={14} /> <Mono>{envName}</Mono>
        </Link>
        <h1 className="text-lg font-semibold">Integrations</h1>
        <div className="flex-1" />
        {syncEnabled && (
          <Button data-testid="add-integration" onClick={() => setAdding((v) => !v)}>
            {adding ? "Cancel" : "Add integration"}
          </Button>
        )}
      </div>
      <p className="text-sm text-muted">
        A Sync Target pushes this environment's rendered configuration to one external
        destination — an explicit, audited standing disclosure (ADR-0031). Once pushed, a
        value's protection is the destination platform's; Varlatch never claims running
        workloads adopted it.
      </p>

      {!syncEnabled && meta.data && (
        <Card data-testid="sync-disabled-notice">
          <p className="text-sm">
            Outbound sync is disabled on this installation. Values can still be pushed from
            your own CI with <Mono>varlatch sync push</Mono>.
          </p>
        </Card>
      )}

      {adding && syncEnabled && (
        <AddIntegration
          org={org}
          project={project}
          envName={envName}
          adapters={adapters}
          connections={connections.data?.items ?? []}
          onDone={() => {
            setAdding(false);
            invalidate();
            void qc.invalidateQueries({ queryKey: ["platform-connections", org] });
          }}
        />
      )}

      {targets.data?.items.length === 0 && !adding && (
        <p className="text-muted text-sm" data-testid="integrations-empty">
          No integrations — nothing leaves this environment.
        </p>
      )}
      {(targets.data?.items ?? []).map((t) => (
        <TargetRow
          key={t.id}
          org={org}
          project={project}
          envName={envName}
          target={t}
          connections={connections.data?.items ?? []}
          onChanged={invalidate}
        />
      ))}
    </div>
  );
}

function TargetRow({
  org,
  project,
  envName,
  target,
  connections,
  onChanged,
}: {
  org: string;
  project: string;
  envName: string;
  target: SyncTarget;
  connections: PlatformConnection[];
  onChanged: () => void;
}) {
  const { api } = useSession();
  const detail = useQuery({
    queryKey: ["sync-target", org, project, envName, target.id, target.version],
    queryFn: () => api.getSyncTarget(org, project, envName, target.id),
  });
  const connection = connections.find((c) => c.id === target.connectionId);
  const state = STATE_LABEL[target.state] ?? STATE_LABEL.active!;
  const StateIcon = state.icon;
  const [error, setError] = useState("");
  const act = useMutation({
    mutationFn: async (action: "push" | "pause" | "resume" | "revoke" | "reaffirm") => {
      setError("");
      if (action === "push") return api.pushSyncTarget(org, project, envName, target.id);
      if (action === "pause") return api.pauseSyncTarget(org, project, envName, target.id);
      if (action === "resume") return api.resumeSyncTarget(org, project, envName, target.id);
      if (action === "reaffirm") {
        // Re-affirmation is a widening: resubmitting the mapping under an
        // actor holding secret.reveal restores pushes of items that became
        // Secrets (ADR-0031 §2).
        if (target.mapping.kind !== "explicit") return;
        return api.updateSyncTarget(org, project, envName, target.id, {
          expectedVersion: target.version,
          mapping: {
            kind: "explicit",
            items: target.mapping.items.map((i) => ({
              name: i.name,
              ...(i.rename ? { rename: i.rename } : {}),
            })),
          },
        });
      }
      return api.revokeSyncTarget(org, project, envName, target.id);
    },
    onSuccess: onChanged,
    onError: (err) => setError(String(err)),
  });

  const needsReaffirm = (target.lastResult ?? "").includes("re-affirmation required");

  return (
    <Card data-sync-target={target.id}>
      <div className="flex items-center gap-3 flex-wrap">
        <span className={cn("inline-flex items-center gap-1 text-sm", state.className)}>
          <StateIcon size={14} /> {state.label}
          {target.disabledReason ? ` (${target.disabledReason})` : ""}
        </span>
        {connection && (
          <span className="inline-flex items-center gap-1.5 text-sm text-muted">
            <PlatformLogo platform={connection.platform} size={14} />
            {platformMeta(connection.platform).label} · <Mono>{connection.baseIdentity}</Mono>
          </span>
        )}
        <Mono className="text-sm">{destinationLabel(target)}</Mono>
        <span className="text-xs text-muted">{mappingLabel(target)}</span>
        <div className="flex-1" />
        <Button
          variant="ghost"
          data-testid={`push-now-${target.id}`}
          disabled={act.isPending || target.state !== "active"}
          onClick={() => act.mutate("push")}
        >
          <RefreshCw size={13} className="inline mr-1" />
          Push now
        </Button>
        {target.state === "active" ? (
          <Button variant="ghost" data-testid={`pause-${target.id}`} onClick={() => act.mutate("pause")}>
            <Pause size={13} className="inline mr-1" /> Pause
          </Button>
        ) : (
          <Button variant="ghost" data-testid={`resume-${target.id}`} onClick={() => act.mutate("resume")}>
            <Play size={13} className="inline mr-1" /> Resume
          </Button>
        )}
        <Button variant="danger" data-testid={`revoke-target-${target.id}`} onClick={() => act.mutate("revoke")}>
          Revoke
        </Button>
      </div>
      <div className="mt-1 text-xs text-muted">
        {target.lastAttemptAt ? (
          <>
            last {target.lastResult ?? "?"} · {new Date(target.lastAttemptAt).toLocaleString()}
            {target.failureCount > 0 && <span className="text-deny"> · {target.failureCount} failing</span>}
            {target.needsSync && <span> · converge pending</span>}
          </>
        ) : (
          "no pushes yet"
        )}
        {target.removeOrphans && " · removes orphaned names"}
        {target.redeploy &&
          (target.destination.deployAction === "restart"
            ? " · restarts on change"
            : " · redeploys on change")}
        {target.destination.buildTime === "true" && " · build-time keys"}
        {target.destination.buildTime === "false" && " · runtime-only keys"}
      </div>
      {needsReaffirm && target.mapping.kind === "explicit" && (
        <div className="mt-2 text-sm">
          <span className="text-deny">
            A mapped item became a Secret and left the disclosure set.
          </span>{" "}
          <Button
            variant="ghost"
            data-testid={`reaffirm-${target.id}`}
            onClick={() => act.mutate("reaffirm")}
          >
            Re-affirm mapping (requires secret reveal authority)
          </Button>
        </div>
      )}
      {(detail.data?.names ?? []).length > 0 && (
        <div className="mt-2 flex flex-wrap gap-2 text-[11px]">
          {detail.data!.names.map((n) => (
            <span
              key={n.name}
              data-sync-name={n.name}
              className={cn(
                "inline-flex items-center gap-1 rounded border border-bd px-1.5 py-0.5",
                n.state === "written" && "text-allow",
                n.state.startsWith("failed") && "text-deny",
                n.state === "tombstone" && "text-muted line-through",
                n.state.startsWith("intent") && "text-muted",
              )}
              title={`${n.state}${n.error ? ` — ${n.error}` : ""} · ${new Date(n.updatedAt).toLocaleString()}`}
            >
              {n.state.startsWith("failed") ? <TriangleAlert size={11} /> : n.state === "written" ? <Check size={11} /> : <CircleDashed size={11} />}
              <Mono>{n.name}</Mono>
            </span>
          ))}
        </div>
      )}
      {error && <p className="text-deny text-sm mt-2">{error}</p>}
    </Card>
  );
}

function AddIntegration({
  org,
  project,
  envName,
  adapters,
  connections,
  onDone,
}: {
  org: string;
  project: string;
  envName: string;
  adapters: SyncPlatform[];
  connections: PlatformConnection[];
  onDone: () => void;
}) {
  const { api } = useSession();
  const [connectionId, setConnectionId] = useState("");
  const [newConnection, setNewConnection] = useState(false);
  const [platform, setPlatform] = useState<SyncPlatform>(adapters[0] ?? "github-actions");
  const [baseIdentity, setBaseIdentity] = useState("");
  const [connectionName, setConnectionName] = useState("");
  const [credential, setCredential] = useState("");
  const [repo, setRepo] = useState("");
  const [ghEnvironment, setGhEnvironment] = useState("");
  const [appUuid, setAppUuid] = useState("");
  // Coolify per-target options (adapter-owned, never part of the identity).
  const [buildTime, setBuildTime] = useState<"" | "true" | "false">("");
  const [deployAction, setDeployAction] = useState<"deploy" | "restart">("deploy");
  const [mappingMode, setMappingMode] = useState<"wildcard" | "explicit">("wildcard");
  const [mappingText, setMappingText] = useState("");
  const [excludeText, setExcludeText] = useState("");
  const [removeOrphans, setRemoveOrphans] = useState(false);
  const [redeploy, setRedeploy] = useState(false);
  const [reviewing, setReviewing] = useState(false);
  const [error, setError] = useState("");

  const selected = connections.find((c) => c.id === connectionId);
  const effectivePlatform = newConnection ? platform : (selected?.platform ?? platform);

  const mapping: SyncMappingInput = useMemo(() => {
    if (mappingMode === "wildcard") {
      const exclude = excludeText
        .split(/[\n,]/)
        .map((e) => e.trim())
        .filter(Boolean);
      return { kind: "wildcard", ...(exclude.length ? { exclude } : {}) };
    }
    const items = mappingText
      .split(/[\n,]/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const [name, rename] = line.split("=", 2) as [string, string?];
        return { name: name.trim(), ...(rename ? { rename: rename.trim() } : {}) };
      });
    return { kind: "explicit", items };
  }, [mappingMode, mappingText, excludeText]);

  const destination =
    effectivePlatform === "github-actions"
      ? { repo, ...(ghEnvironment ? { environment: ghEnvironment } : {}) }
      : effectivePlatform === "coolify"
        ? {
            applicationUuid: appUuid,
            ...(buildTime ? { buildTime } : {}),
            ...(redeploy && deployAction === "restart" ? { deployAction } : {}),
          }
        : // convex: the Connection's deployment URL is the destination.
          {};

  const destinationReady =
    effectivePlatform === "github-actions"
      ? Boolean(repo)
      : effectivePlatform === "coolify"
        ? Boolean(appUuid)
        : true;
  const ready =
    (newConnection ? baseIdentity && connectionName && credential : connectionId) &&
    destinationReady &&
    (mappingMode === "wildcard" || (mapping.kind === "explicit" && mapping.items.length > 0));

  const create = useMutation({
    mutationFn: async () => {
      setError("");
      let cid = connectionId;
      if (newConnection) {
        const created = await api.createPlatformConnection(org, {
          platform,
          baseIdentity,
          name: connectionName,
          credential,
        });
        cid = created.id;
      }
      await api.createSyncTarget(org, project, envName, {
        connectionId: cid,
        destination,
        mapping,
        removeOrphans,
        // No redeploy concept on convex: a stale toggle from a previously
        // selected platform must not travel.
        redeploy: effectivePlatform === "convex" ? false : redeploy,
      });
    },
    onSuccess: onDone,
    onError: (err) => {
      setReviewing(false);
      setError(String(err));
    },
  });

  return (
    <Card data-testid="add-integration-form">
      <h2 className="font-medium mb-2">Add integration</h2>
      <div className="space-y-3 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <label className="text-muted w-28">Connection</label>
          <Select
            data-testid="connection-select"
            value={newConnection ? "__new" : connectionId}
            onChange={(v) => {
              if (v === "__new") setNewConnection(true);
              else {
                setNewConnection(false);
                setConnectionId(v);
              }
            }}
            options={[
              { value: "", label: "Choose…" },
              ...connections.map((c) => ({
                value: c.id,
                label: `${c.name} (${platformMeta(c.platform).label} · ${c.baseIdentity})`,
                icon: <PlatformLogo platform={c.platform} size={14} />,
              })),
              { value: "__new", label: "New connection…" },
            ]}
          />
        </div>
        {newConnection && (
          <div className="space-y-2 rounded border border-bd bg-inset/40 p-2">
            <div className="flex flex-wrap items-center gap-2">
              <label className="text-muted w-28">Platform</label>
              <Select
                data-testid="platform-select"
                value={platform}
                onChange={(v) => setPlatform(v as SyncPlatform)}
                options={adapters.map((a) => {
                  const m = platformMeta(a);
                  return {
                    value: a,
                    label: m.label,
                    description: m.description,
                    icon: <PlatformLogo platform={a} size={14} />,
                  };
                })}
              />
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <label className="text-muted w-28">{platformMeta(platform).identityLabel}</label>
              <Input
                data-testid="base-identity"
                className="w-80"
                placeholder={platformMeta(platform).identityPlaceholder}
                value={baseIdentity}
                onChange={(e) => setBaseIdentity(e.target.value)}
              />
              <span className="text-xs text-muted">
                Immutable: a different {platformMeta(platform).identityNoun} is a new connection.
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <label className="text-muted w-28">Name</label>
              <Input
                data-testid="connection-name"
                className="w-64"
                placeholder="prod GitHub"
                value={connectionName}
                onChange={(e) => setConnectionName(e.target.value)}
              />
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <label className="text-muted w-28">Credential</label>
              <Input
                data-testid="connection-credential"
                className="w-80"
                type="password"
                placeholder={platformMeta(platform).credentialPlaceholder}
                value={credential}
                onChange={(e) => setCredential(e.target.value)}
              />
              <span className="text-xs text-muted">{platformMeta(platform).credentialHelp}</span>
            </div>
          </div>
        )}
        <div className="flex flex-wrap items-center gap-2">
          <label className="text-muted w-28">Destination</label>
          {effectivePlatform === "github-actions" ? (
            <>
              <Input
                data-testid="dest-repo"
                className="w-56"
                placeholder="repository"
                value={repo}
                onChange={(e) => setRepo(e.target.value)}
              />
              <Input
                data-testid="dest-gh-environment"
                className="w-48"
                placeholder="environment (optional)"
                value={ghEnvironment}
                onChange={(e) => setGhEnvironment(e.target.value)}
              />
            </>
          ) : effectivePlatform === "coolify" ? (
            <Input
              data-testid="dest-app"
              className="w-72"
              placeholder="application UUID"
              value={appUuid}
              onChange={(e) => setAppUuid(e.target.value)}
            />
          ) : (
            <span className="text-xs text-muted" data-testid="dest-convex">
              The connection's deployment URL is the destination — nothing to configure.
            </span>
          )}
        </div>
        {effectivePlatform === "coolify" && (
          <div className="flex flex-wrap items-center gap-2">
            <label className="text-muted w-28">Build time</label>
            <Select
              data-testid="dest-build-time"
              value={buildTime}
              onChange={(v) => setBuildTime(v as "" | "true" | "false")}
              options={[
                { value: "", label: "Coolify default" },
                { value: "true", label: "Available at build time" },
                { value: "false", label: "Runtime only" },
              ]}
            />
            <span className="text-xs text-muted">
              Values baked into a build (VITE_*, NEXT_PUBLIC_*) are invisible to it unless marked.
              Build-time values end up in image layers.
            </span>
          </div>
        )}
        <div className="flex flex-wrap items-start gap-2">
          <label className="text-muted w-28 pt-1.5">Items</label>
          <div className="space-y-1">
            <Select
              data-testid="mapping-mode"
              value={mappingMode}
              onChange={(v) => setMappingMode(v as "wildcard" | "explicit")}
              options={[
                { value: "wildcard", label: "All items — including future ones" },
                { value: "explicit", label: "Explicit list" },
              ]}
            />
            {mappingMode === "wildcard" && (
              <input
                data-testid="mapping-exclude"
                className="w-96 rounded-md border border-bd bg-inset px-2 py-1 font-mono text-xs"
                placeholder="Exclude (optional): CONVEX_*, INTERNAL_KEY"
                value={excludeText}
                onChange={(e) => setExcludeText(e.target.value)}
                title="Exact names or trailing-* prefixes, comma-separated. Excluded items never push; everything else — including future items — does."
              />
            )}
            {mappingMode === "explicit" && (
              <textarea
                data-testid="mapping-items"
                className="w-96 h-24 rounded-md border border-bd bg-inset px-2 py-1 font-mono text-xs"
                placeholder={"DATABASE_URL\nPORT=APP_PORT"}
                value={mappingText}
                onChange={(e) => setMappingText(e.target.value)}
              />
            )}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-4">
          <label className="inline-flex items-center gap-1.5">
            <input
              type="checkbox"
              data-testid="remove-orphans"
              checked={removeOrphans}
              onChange={(e) => setRemoveOrphans(e.target.checked)}
            />
            Remove destination names that leave this environment
          </label>
          {effectivePlatform === "convex" ? (
            <span className="text-xs text-muted">
              Convex functions pick up env changes immediately — no redeploy exists.
            </span>
          ) : (
            <label className="inline-flex items-center gap-1.5">
              <input
                type="checkbox"
                data-testid="redeploy"
                checked={redeploy}
                onChange={(e) => setRedeploy(e.target.checked)}
              />
              Trigger redeploy after changes (where supported)
            </label>
          )}
          {effectivePlatform === "coolify" && redeploy && (
            <Select
              data-testid="dest-deploy-action"
              value={deployAction}
              onChange={(v) => setDeployAction(v as "deploy" | "restart")}
              options={[
                { value: "deploy", label: "Deploy: forced rebuild (re-bakes build-time values)" },
                { value: "restart", label: "Restart only (runtime env, no rebuild)" },
              ]}
            />
          )}
        </div>
        <div>
          <Button data-testid="review-integration" disabled={!ready} onClick={() => setReviewing(true)}>
            Review…
          </Button>
        </div>
        {error && <p className="text-deny">{error}</p>}
      </div>

      {reviewing && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/50 p-4">
          <Card className="max-w-lg w-full" data-testid="integration-review">
            <h3 className="font-medium mb-2">Review disclosure</h3>
            <p className="text-sm mb-2">
              This creates standing authority for varlatchd to push{" "}
              <strong>
                {mapping.kind === "wildcard"
                  ? "every current and future item of this environment — Secrets included"
                  : `${mapping.items.length} mapped item(s)`}
              </strong>{" "}
              in plaintext to{" "}
              <Mono>
                {effectivePlatform}:
                {effectivePlatform === "github-actions"
                  ? `${repo}${ghEnvironment ? `#${ghEnvironment}` : ""}`
                  : effectivePlatform === "coolify"
                    ? appUuid
                    : (selected?.baseIdentity ?? baseIdentity)}
              </Mono>
              . Every push is audited before values leave. Once pushed, protection is the
              destination platform's — revoking here never reaches back.
            </p>
            <div className="flex gap-2 justify-end">
              <Button variant="ghost" data-testid="cancel-review" onClick={() => setReviewing(false)}>
                Back
              </Button>
              <Button
                data-testid="confirm-integration"
                disabled={create.isPending}
                onClick={() => create.mutate()}
              >
                Create integration
              </Button>
            </div>
          </Card>
        </div>
      )}
    </Card>
  );
}
