// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from "react";
import { ArrowRight, Lock, RefreshCw } from "lucide-react";
import type { Environment, Tier } from "@varlatch/protocol";
import { Dialog } from "../../components/Dialog";
import { Badge, Button, Checkbox, Kbd, TierChip, TierDot, cn } from "../../components/ui";
import { modKey } from "../../lib/hotkeys";
import { listNames, plural } from "./model";

/**
 * The review is a safety boundary: per environment, what changes, old ->
 * new for values that may be shown, "hidden" for Secrets. It never triggers
 * a disclosure. Production-tier saves need an explicit acknowledgement.
 */

export type ReviewRow = {
  name: string;
  op: "change" | "add" | "delete";
  sensitive: boolean;
  /** Stored text before the change, when it may be shown. */
  oldText: string | null;
  newText?: string | undefined;
};

export type ReviewGroup = { env: Environment; rows: ReviewRow[]; targets: string[] };

const OP: Record<ReviewRow["op"], { label: string; tone: "warn" | "accent" | "danger" }> = {
  change: { label: "CHANGE", tone: "warn" },
  add: { label: "ADD", tone: "accent" },
  delete: { label: "DELETE", tone: "danger" },
};

export function ReviewDialog({
  open,
  groups,
  saving,
  onClose,
  onSave,
}: {
  open: boolean;
  groups: ReviewGroup[];
  saving: boolean;
  onClose: () => void;
  onSave: () => void;
}) {
  const production = groups.filter((g) => g.env.tier === "production");
  const [acknowledged, setAcknowledged] = useState(false);
  useEffect(() => {
    if (open) setAcknowledged(false);
  }, [open]);
  const total = groups.reduce((n, g) => n + g.rows.length, 0);
  const single = groups.length === 1 ? groups[0] : undefined;
  const ready = total > 0 && (production.length === 0 || acknowledged) && !saving;
  const mod = modKey();

  const title = single ? (
    <span className="inline-flex flex-wrap items-center gap-x-3 gap-y-1">
      Review {plural(total, "change")} to <span className="font-mono">{single.env.name}</span>
      <TierChip tier={single.env.tier as Tier} className="text-[12px]" />
    </span>
  ) : (
    `Review ${plural(total, "change")} in ${plural(groups.length, "environment")}`
  );

  return (
    <Dialog
      open={open}
      onClose={() => !saving && onClose()}
      size="lg"
      data-testid="review-dialog"
      title={title}
      description={
        single
          ? "Saved together as one atomic change set."
          : "Each environment is saved as its own atomic change set, in the order shown."
      }
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={saving}>
            Back to editing
          </Button>
          <Button
            variant="primary"
            data-testid="commit-changes"
            disabled={!ready}
            loading={saving}
            onClick={onSave}
          >
            {production.length > 0 && groups.length === 1 ? `Save to ${single?.env.name}` : "Save changes"}
            <Kbd className="border-accent-fg/20 bg-accent-fg/10 text-accent-fg/80">{mod === "⌘" ? "⌘↵" : "Ctrl ↵"}</Kbd>
          </Button>
        </>
      }
    >
      <div
        className="space-y-5"
        onKeyDown={(e) => {
          if (e.key === "Enter" && (e.metaKey || e.ctrlKey) && ready) {
            e.preventDefault();
            onSave();
          }
        }}
      >
        {groups.map((g) => (
          <section key={g.env.id} data-review-env={g.env.name} className="space-y-3">
            {!single && (
              <h3 className="flex items-center gap-2 text-[13px] font-semibold">
                <TierDot tier={g.env.tier as Tier} />
                <span className="font-mono">{g.env.name}</span>
                <span className="font-normal text-muted">{plural(g.rows.length, "change")}</span>
              </h3>
            )}
            <ul className="divide-y divide-bd overflow-hidden rounded-lg border border-bd bg-inset/40">
              {g.rows.map((r) => (
                <li key={r.name} data-review-item={r.name} className="flex min-h-12 items-center gap-3 px-4 py-2.5">
                  <Badge tone={OP[r.op].tone} className="w-[68px] justify-center font-mono tracking-wide">
                    {OP[r.op].label}
                  </Badge>
                  <span className="flex w-5 shrink-0 justify-center text-muted">
                    {r.sensitive && <Lock size={13} aria-label="Secret" />}
                  </span>
                  <span className="w-48 shrink-0 truncate font-mono text-[13px] text-fg" title={r.name}>
                    {r.name}
                  </span>
                  <span className="min-w-0 flex-1">
                    <ChangeText row={r} />
                  </span>
                </li>
              ))}
            </ul>
            {g.targets.length > 0 && (
              <div
                className="flex items-start gap-3 rounded-lg border border-bd bg-inset/40 px-4 py-3 text-[13px]"
                data-testid="review-sync-callout"
              >
                <RefreshCw size={15} className="mt-0.5 shrink-0 text-muted" />
                <p className="text-muted">
                  <span className="font-medium text-fg">{plural(g.targets.length, "integration")}</span> will push
                  {single ? " these changes" : ` the ${g.env.name} changes`}:{" "}
                  <span className="font-mono text-[12.5px] text-fg/90">{listNames(g.targets)}</span>
                </p>
              </div>
            )}
          </section>
        ))}
        {production.length > 0 && (
          <div className="rounded-lg border border-tier-production/35 bg-tier-production/[0.06] px-4 py-3">
            <Checkbox
              data-testid="production-confirm"
              checked={acknowledged}
              onChange={setAcknowledged}
              label={
                <>
                  I am changing <span className="font-medium text-tier-production">production</span>-tier configuration
                  {production.length === 1 && groups.length > 1 && (
                    <>
                      {" "}
                      in <span className="font-mono">{production[0]!.env.name}</span>
                    </>
                  )}
                  .
                </>
              }
              description="Consumers of these environments receive the new values on their next start or sync."
            />
          </div>
        )}
      </div>
    </Dialog>
  );
}

function ChangeText({ row }: { row: ReviewRow }) {
  const muted = "font-mono text-[12.5px] italic text-muted";
  if (row.sensitive) {
    const text =
      row.op === "delete" ? "secret removed" : row.op === "add" ? "secret value set · hidden" : "secret value changed · hidden";
    return <span className={muted}>{text}</span>;
  }
  if (row.op === "delete") {
    return row.oldText !== null ? <Value text={row.oldText} className="text-deny line-through decoration-deny/70" /> : <span className={muted}>value removed</span>;
  }
  if (row.op === "add") return <Value text={row.newText ?? ""} className="rounded bg-accent/10 px-1.5 py-0.5 text-accent" />;
  return (
    <span className="flex min-w-0 items-center gap-2">
      {row.oldText !== null ? (
        <Value text={row.oldText} className="text-deny line-through decoration-deny/70" />
      ) : (
        <span className={muted}>value hidden</span>
      )}
      <ArrowRight size={13} className="shrink-0 text-muted" />
      <Value text={row.newText ?? ""} className="text-accent" />
    </span>
  );
}

function Value({ text, className }: { text: string; className?: string }) {
  return (
    <span title={text} className={cn("inline-block max-w-full truncate align-middle font-mono text-[13px]", className)}>
      {text === "" ? <span className="italic text-muted">(empty)</span> : text}
    </span>
  );
}

