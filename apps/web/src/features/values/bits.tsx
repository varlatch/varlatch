// SPDX-License-Identifier: AGPL-3.0-or-later
import { EyeOff, Link2, RefreshCw, ShieldCheck } from "lucide-react";
import { Badge, Button, Kbd, cn } from "../../components/ui";
import { modKey } from "../../lib/hotkeys";
import { listNames, plural } from "./model";

/** Small visual pieces shared by the values grid and the environment page. */

export function TypeBadge({ type, className }: { type: string | undefined; className?: string }) {
  if (!type) return null;
  return (
    <Badge tone="mono" className={cn("px-1.5 text-[10.5px] font-normal", className)}>
      {type}
    </Badge>
  );
}

export function SecretMask({ className }: { className?: string }) {
  return (
    <span aria-label="Masked secret" className={cn("select-none font-mono text-[13px] tracking-[0.18em] text-muted", className)}>
      ••••••••••
    </span>
  );
}

export function DraftMarker({ kind, className }: { kind: "edited" | "new" | "deleted" | null; className?: string }) {
  if (!kind) return null;
  const tone = kind === "edited" ? "text-warn" : kind === "new" ? "text-accent" : "text-deny";
  const dot = kind === "edited" ? "bg-warn" : kind === "new" ? "bg-accent" : "bg-deny";
  return (
    <span className={cn("inline-flex shrink-0 items-center gap-1.5 text-[11.5px] font-medium", tone, className)}>
      <span aria-hidden="true" className={cn("size-1.5 rounded-full", dot)} />
      {kind}
    </span>
  );
}

export function RotatingMarker({ item, label = "rotating", testId }: { item: string; label?: string; testId?: string }) {
  return (
    <span
      data-testid={testId ?? `rotating-${item}`}
      title="Rotating: the previous value stays valid until the grace window closes or the rotation is finished"
      className="inline-flex shrink-0 items-center gap-1 rounded-md border border-warn/40 bg-warn/10 px-1.5 py-px text-[11px] font-medium text-warn"
    >
      <RefreshCw size={11} />
      {label}
    </span>
  );
}

export function RefHint({
  item,
  expanded,
  testId,
}: {
  item: string;
  expanded: string | null | undefined;
  testId?: string;
}) {
  return (
    <span
      data-testid={testId ?? `ref-${item}`}
      title={
        expanded != null
          ? `Stored with a reference; expands to ${expanded}`
          : "Stored with a reference; ${NAME} expands when the value is read"
      }
      className="inline-flex shrink-0 cursor-help items-center gap-0.5 rounded border border-info/35 px-1 text-[10.5px] font-medium text-info"
    >
      <Link2 size={10} />
      ref
    </span>
  );
}

/** Floating save bar (sticky at the bottom of the page). */
export function SaveBar({
  count,
  envs,
  onDiscard,
  onReview,
}: {
  count: number;
  envs: string[];
  onDiscard: () => void;
  onReview: () => void;
}) {
  if (count === 0) return null;
  const mod = modKey();
  return (
    <div className="pointer-events-none sticky bottom-5 z-30 mt-6 flex justify-center">
      <div
        role="region"
        aria-label="Unsaved changes"
        className="pointer-events-auto flex animate-pop-in items-center gap-3 rounded-full border border-bd bg-raised py-1.5 pl-5 pr-1.5 shadow-pop"
      >
        <span aria-hidden="true" className="size-2 rounded-full bg-warn" />
        <span className="text-[13px] text-fg" data-testid="dirty-count">
          {plural(count, "unsaved change")} in <span className="font-mono">{envs.join(", ")}</span>
        </span>
        <span aria-hidden="true" className="h-5 w-px bg-bd" />
        <Button variant="ghost" onClick={onDiscard} data-testid="discard-drafts">
          Discard
        </Button>
        <Button variant="primary" className="rounded-full pr-2" data-testid="review-save" onClick={onReview}>
          Review &amp; save
          <Kbd className="border-accent-fg/20 bg-accent-fg/10 text-accent-fg/80">{mod === "⌘" ? "⌘S" : "Ctrl S"}</Kbd>
        </Button>
      </div>
    </div>
  );
}

/** After an audited reveal: what happened and how to hide it again. */
export function DisclosureNotice({ envs, onMaskAll }: { envs: string[]; onMaskAll: () => void }) {
  if (envs.length === 0) return null;
  return (
    <div
      data-testid="disclosure-notice"
      role="status"
      className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-lg border border-warn/35 bg-warn/[0.07] px-4 py-2.5 text-[13px]"
    >
      <ShieldCheck size={15} className="shrink-0 text-warn" />
      <span className="min-w-0 flex-1 text-fg/90">
        Secrets revealed in <span className="font-mono">{listNames(envs)}</span>. This was recorded in the audit log;
        re-masking hides them from the screen, it is not revocation. They re-mask in 5 minutes.
      </span>
      <Button size="sm" variant="secondary" icon={<EyeOff size={13} />} onClick={onMaskAll} data-testid="mask-all">
        Mask all
      </Button>
    </div>
  );
}
