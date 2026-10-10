// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  Check,
  ChevronDown,
  CircleCheck,
  CircleDashed,
  CirclePause,
  FileText,
  KeyRound,
  MoreHorizontal,
  Pause,
  Play,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import type { PlatformConnection, SyncTarget } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { formatDate, timeAgo, useNow } from "../../lib/time";
import { Button, Menu, Mono, Spinner, cn } from "../../components/ui";
import { PlatformLogo } from "../../components/brand-logos";
import { useConfirm } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { credentialExpiry, expiryText } from "./credentialExpiry";
import { platformMeta } from "./platform-meta";
import { mappingSummary, targetDestination, targetOptions, targetStatus, type TargetStatus } from "./status";

/** Square logo tile used on integration and connection cards. */
export function PlatformTile({ platform, size = "md", className }: { platform: string; size?: "sm" | "md" | "lg"; className?: string }) {
  const box = size === "lg" ? "size-12 rounded-xl" : size === "sm" ? "size-8 rounded-lg" : "size-10 rounded-lg";
  const icon = size === "lg" ? 24 : size === "sm" ? 16 : 20;
  return (
    <span className={cn("flex shrink-0 items-center justify-center border border-bd bg-inset text-fg", box, className)}>
      <PlatformLogo platform={platform} size={icon} />
    </span>
  );
}

const STATUS_ICON: Record<TargetStatus["tone"], React.ReactNode> = {
  ok: <CircleCheck size={16} className="text-allow" />,
  error: <AlertTriangle size={16} className="text-deny" />,
  warn: <AlertTriangle size={16} className="text-warn" />,
  muted: <CirclePause size={16} className="text-muted" />,
  live: <RefreshCw size={14} className="animate-spin text-accent [animation-duration:2.4s]" />,
};

const STATUS_TEXT: Record<TargetStatus["tone"], string> = {
  ok: "text-allow",
  error: "text-deny",
  warn: "text-warn",
  muted: "text-muted",
  live: "text-accent",
};

export function TargetStatusLine({ status, className }: { status: TargetStatus; className?: string }) {
  const now = useNow();
  const parts: string[] = [];
  if (status.tone === "ok" && status.at) parts.push(`pushed ${timeAgo(status.at, now)}`);
  if (status.tone === "muted" && status.at) parts.push(timeAgo(status.at, now));
  if (status.detail) parts.push(status.detail);
  if (status.tone === "live" && status.at) parts.push(`last push ${timeAgo(status.at, now)}`);
  return (
    <span className={cn("flex min-w-0 items-center gap-2 text-[13px]", className)} data-status={status.label}>
      {STATUS_ICON[status.tone]}
      <span className={cn("shrink-0 font-medium", STATUS_TEXT[status.tone])}>{status.label}</span>
      {parts.map((p) => (
        <React.Fragment key={p}>
          <span className="text-subtle">·</span>
          <span className="shrink-0 text-muted">{p}</span>
        </React.Fragment>
      ))}
      {status.error && (
        <>
          <span className="text-subtle">·</span>
          <span className="truncate text-muted" title={status.error}>
            {status.error}
          </span>
        </>
      )}
    </span>
  );
}

/**
 * One sync target: destination, connection, health with its fix, mapping
 * summary, and the actions (sync now, pause or resume, revoke, re-affirm).
 */
export function TargetCard({
  org,
  project,
  envName,
  target,
  connection,
  onChanged,
  compact = false,
  envLabel,
}: {
  org: string;
  project: string;
  envName: string;
  target: SyncTarget;
  connection: PlatformConnection | undefined;
  onChanged: () => void;
  compact?: boolean | undefined;
  /** Shown before the destination on the project overview. */
  envLabel?: React.ReactNode | undefined;
}) {
  const { api } = useSession();
  const confirm = useConfirm();
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const detail = useQuery({
    queryKey: ["sync-target", org, project, envName, target.id, target.version, target.lastAttemptAt],
    queryFn: () => api.getSyncTarget(org, project, envName, target.id),
    staleTime: 30_000,
  });
  const status = targetStatus(target);
  const now = useNow();
  // Warned here too: the integration stops when its connection's token expires.
  const expiry = credentialExpiry(connection?.credentialExpiresAt, now);
  const dest = targetDestination(target, connection);
  const mapping = mappingSummary(target);
  const options = targetOptions(target);
  const platform = connection ? platformMeta(connection.platform) : undefined;
  const names = (detail.data?.names ?? []).filter((n) => n.state !== "tombstone" && !n.state.endsWith("delete"));

  const act = useMutation({
    mutationFn: async (action: "push" | "pause" | "resume" | "revoke" | "reaffirm") => {
      if (action === "push") return api.pushSyncTarget(org, project, envName, target.id);
      if (action === "pause") return api.pauseSyncTarget(org, project, envName, target.id);
      if (action === "resume") return api.resumeSyncTarget(org, project, envName, target.id);
      if (action === "reaffirm") {
        // Re-affirming resubmits the mapping as someone allowed to reveal
        // secrets, which restores pushes of items that became secrets.
        if (target.mapping.kind !== "explicit") return;
        return api.updateSyncTarget(org, project, envName, target.id, {
          expectedVersion: target.version,
          mapping: {
            kind: "explicit",
            items: target.mapping.items.map((i) => ({ name: i.name, ...(i.rename ? { rename: i.rename } : {}) })),
          },
        });
      }
      return api.revokeSyncTarget(org, project, envName, target.id);
    },
    onSuccess: (_r, action) => {
      onChanged();
      if (action === "push") toast.success("Sync scheduled", { description: `${dest.primary} will be updated in a moment.` });
      if (action === "revoke") toast.success("Integration revoked", { description: "Values already pushed stay at the destination." });
      if (action === "reaffirm") toast.success("Mapping re-affirmed");
    },
    onError: (err) => toast.error("That did not work", { description: err instanceof Error ? err.message : String(err) }),
  });

  const revoke = async () => {
    const ok = await confirm({
      title: "Revoke this integration?",
      tone: "danger",
      confirmLabel: "Revoke integration",
      description: (
        <>
          Varlatch stops pushing <span className="font-mono text-fg">{envName}</span> to{" "}
          <span className="font-mono text-fg">{dest.primary}</span>.
        </>
      ),
      consequences: [
        { text: "Future changes no longer reach the destination." },
        { text: "Values already pushed stay there; remove them on the platform if they must go." },
      ],
    });
    if (ok) act.mutate("revoke");
  };

  const busy = act.isPending;
  const fixButton =
    status.fix === "replace-credential" ? (
      <Link
        to={`/o/${org}/connections?replace=${encodeURIComponent(target.connectionId)}`}
        className="inline-flex h-8 items-center gap-1.5 rounded-md border border-deny/50 px-3 text-sm font-medium text-deny hover:bg-deny/10"
        data-testid={`fix-credential-${target.id}`}
      >
        <KeyRound size={14} /> {connection?.credentialKind === "github-app" ? "Rotate the App's key" : "Replace credential"}
      </Link>
    ) : status.fix === "reaffirm" && target.mapping.kind === "explicit" ? (
      <Button variant="secondary" data-testid={`reaffirm-${target.id}`} disabled={busy} onClick={() => act.mutate("reaffirm")} icon={<ShieldCheck size={14} />}>
        Re-affirm mapping
      </Button>
    ) : status.fix === "reconnect" ? (
      <Link
        to={`/o/${org}/connections`}
        className="inline-flex h-8 items-center gap-1.5 rounded-md border border-bd bg-raised px-3 text-sm text-fg hover:bg-hover"
      >
        Choose a connection
      </Link>
    ) : null;

  return (
    <article
      data-sync-target={target.id}
      className={cn("overflow-hidden rounded-xl border bg-raised", status.tone === "error" ? "border-deny/30" : "border-bd")}
    >
      <div className={cn("flex flex-wrap items-center gap-x-4 gap-y-3", compact ? "px-4 py-3" : "px-5 py-4")}>
        <PlatformTile platform={connection?.platform ?? ""} size={compact ? "sm" : "md"} />
        <div className="min-w-0 flex-[1_1_14rem]">
          <p className="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-0.5">
            {envLabel}
            <Mono className={cn("truncate font-semibold text-fg", compact ? "text-[13px]" : "text-[15px]")}>{dest.primary}</Mono>
            {dest.qualifier && (
              <span className="text-[13px] text-muted">
                · {dest.qualifier.split(" ")[0]}{" "}
                <Mono className="text-fg">{dest.qualifier.split(" ").slice(1).join(" ")}</Mono>
              </span>
            )}
          </p>
          <p className="mt-0.5 truncate text-[13px] text-muted">
            via {platform?.shortLabel ?? "a revoked connection"}
            {connection && <span> ({connection.name}{connection.credentialKind === "github-app" ? ", GitHub App" : ""})</span>}
          </p>
          {expiry && expiry.state !== "later" && (
            <p
              className={cn("mt-0.5 flex items-center gap-1.5 text-[13px]", expiry.state === "expired" ? "text-deny" : "text-warn")}
              data-testid={`credential-expiry-${target.id}`}
            >
              <KeyRound size={12} aria-hidden="true" />
              {expiryText(expiry, formatDate(expiry.expiresAt))}
              {" · "}
              <Link className="underline underline-offset-2" to={`/o/${org}/connections?replace=${encodeURIComponent(target.connectionId)}`}>
                Replace it
              </Link>
            </p>
          )}
        </div>
        <TargetStatusLine status={status} className="min-w-0 flex-[1_1_16rem]" />
        <div className="ml-auto flex shrink-0 items-center gap-2">
          {fixButton}
          {target.state === "active" && !fixButton && (
            <Button
              size={compact ? "sm" : "md"}
              data-testid={`push-now-${target.id}`}
              disabled={busy}
              onClick={() => act.mutate("push")}
              icon={<RefreshCw size={13} />}
            >
              Sync now
            </Button>
          )}
          {target.state === "active" ? (
            <button
              type="button"
              aria-label="Pause pushes"
              title="Pause pushes"
              data-testid={`pause-${target.id}`}
              disabled={busy}
              onClick={() => act.mutate("pause")}
              className={cn(
                "inline-flex shrink-0 cursor-pointer items-center justify-center rounded-md border border-bd bg-raised text-muted transition-colors hover:border-bd-strong hover:bg-hover hover:text-fg disabled:cursor-not-allowed disabled:opacity-45",
                compact ? "size-7" : "size-8",
              )}
            >
              <Pause size={14} />
            </button>
          ) : (
            target.disabledReason !== "connection-revoked" && (
              <Button size={compact ? "sm" : "md"} data-testid={`resume-${target.id}`} disabled={busy} onClick={() => act.mutate("resume")} icon={<Play size={13} />}>
                Resume
              </Button>
            )
          )}
          <Menu
            label={`More actions for ${dest.primary}`}
            data-testid={`target-menu-${target.id}`}
            buttonClassName={cn("justify-center border border-bd", compact ? "size-7" : "size-8")}
            items={[
              ...(target.state === "active" && fixButton
                ? [{ label: "Sync now", icon: <RefreshCw size={14} />, onSelect: () => act.mutate("push") }]
                : []),
              {
                label: open ? "Hide pushed names" : "Show pushed names",
                icon: <FileText size={14} />,
                onSelect: () => setOpen((v) => !v),
              },
              {
                label: "Revoke integration",
                danger: true,
                separatorBefore: true,
                icon: <Trash2 size={14} />,
                "data-testid": `revoke-target-${target.id}`,
                onSelect: () => void revoke(),
              },
            ]}
          >
            <MoreHorizontal size={16} />
          </Menu>
        </div>
      </div>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className={cn(
          "flex w-full cursor-pointer flex-wrap items-center gap-x-2 gap-y-1 border-t border-bd text-left text-[13px] text-muted hover:bg-hover/50",
          compact ? "px-4 py-2" : "px-5 py-2.5",
        )}
      >
        <FileText size={14} className="shrink-0" />
        <span className="text-fg/90">{mapping.label}</span>
        {mapping.excluded?.map((e) => (
          <Mono key={e} className="font-semibold text-fg">
            {e}
          </Mono>
        ))}
        {mapping.renames > 0 && <span>· {mapping.renames} renamed</span>}
        {names.length > 0 && <span>· {names.length} value{names.length === 1 ? "" : "s"}</span>}
        {options.map((o) => (
          <span key={o}>· {o}</span>
        ))}
        <ChevronDown size={14} className={cn("ml-auto shrink-0 transition-transform", open && "rotate-180")} />
      </button>
      {open && (
        <div className={cn("border-t border-bd bg-inset/40", compact ? "px-4 py-3" : "px-5 py-3")}>
          {detail.isLoading ? (
            <Spinner />
          ) : (detail.data?.names ?? []).length === 0 ? (
            <p className="text-[13px] text-muted">Nothing pushed yet.</p>
          ) : (
            <ul className="flex flex-wrap gap-1.5">
              {detail.data!.names.map((n) => (
                <li
                  key={n.name}
                  data-sync-name={n.name}
                  title={`${n.state}${n.error ? `: ${n.error}` : ""} · ${new Date(n.updatedAt).toLocaleString()}`}
                  className={cn(
                    "inline-flex items-center gap-1 rounded-md border border-bd bg-raised px-1.5 py-0.5 font-mono text-[11.5px]",
                    n.state === "written" && "text-fg",
                    n.state.startsWith("failed") && "border-deny/40 text-deny",
                    (n.state === "tombstone" || n.state.startsWith("intent")) && "text-muted",
                    n.state === "tombstone" && "line-through",
                  )}
                >
                  {n.state.startsWith("failed") ? (
                    <AlertTriangle size={11} />
                  ) : n.state === "written" ? (
                    <Check size={11} className="text-allow" />
                  ) : (
                    <CircleDashed size={11} />
                  )}
                  {n.name}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </article>
  );
}
