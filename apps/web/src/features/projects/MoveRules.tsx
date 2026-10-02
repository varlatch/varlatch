// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { ArrowRight, CircleCheck, Sparkles } from "lucide-react";
import type { ContractRevision } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { Dialog } from "../../components/Dialog";
import { Button, Callout, InfoTip, Mono, cn } from "../../components/ui";
import { useToast } from "../../components/Toast";
import { canMoveRules, movedContract, moveConsequences, reviewMove, revisionSemanticsVersion, semanticsSteps } from "./semanticsMove";

/** Plain text with `backticked` commands rendered as code. */
function WithCode({ text }: { text: string }) {
  return <>{text.split("`").map((part, i) => (i % 2 === 1 ? <Mono key={i}>{part}</Mono> : part))}</>;
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * The contract's validation rules (semantics version). When newer rules
 * exist, moving pushes the active contract unchanged except for its version,
 * shows what the server stored, and activates only on an explicit
 * confirmation. Available for git and managed projects alike.
 */
export function RulesCard({
  org,
  project,
  active,
  newest,
  authority,
  onActivated,
  className,
}: {
  org: string;
  project: string;
  active: ContractRevision;
  newest: number;
  authority: "git" | "managed";
  /** Resolves once the page shows the newly active revision. */
  onActivated: () => Promise<unknown>;
  className?: string;
}) {
  const { api } = useSession();
  const toast = useToast();
  const [review, setReview] = useState<{ base: ContractRevision; pushed: ContractRevision } | null>(null);
  const [cancelled, setCancelled] = useState<string | null>(null);
  const from = revisionSemanticsVersion(active);
  const movable = canMoveRules(from, newest);

  const push = useMutation({
    mutationFn: () => api.pushContractRevision(org, project, { contract: movedContract(active.contract, newest) }),
    onSuccess: (pushed) => {
      setCancelled(null);
      setReview({ base: active, pushed });
    },
    onError: (err) => toast.error("Could not push the revision", { description: errorText(err) }),
  });
  const activate = useMutation({
    mutationFn: async (revisionId: string) => {
      await api.activateContractRevision(org, project, revisionId);
      await onActivated();
    },
    onSuccess: () => {
      setReview(null);
      toast.success(`Version ${newest} rules are active`);
    },
  });

  const result = review ? reviewMove(review.base, review.pushed, newest) : null;
  const stale = review !== null && review.base.id !== active.id;
  const cancel = () => {
    if (review) setCancelled(review.pushed.id);
    setReview(null);
    activate.reset();
  };

  return (
    <section className={cn("rounded-xl border border-bd bg-raised px-5 py-4", className)} data-testid="contract-rules">
      <div className="flex items-start gap-3.5">
        <span
          className={cn(
            "flex size-9 shrink-0 items-center justify-center rounded-full",
            movable ? "bg-info/12 text-info" : "bg-accent/15 text-accent",
          )}
        >
          {movable ? <Sparkles size={17} /> : <CircleCheck size={18} />}
        </span>
        <div className="min-w-0 flex-1">
          <p className="flex flex-wrap items-center gap-x-2 text-[15px] font-semibold" data-testid="semantics-version" data-version={from}>
            Rules version {from}
            <span className={cn("text-[13px] font-medium", movable ? "text-info" : "text-accent")}>
              · {movable ? `version ${newest} available` : "newest"}
            </span>
            <InfoTip text="The validation rules this contract is evaluated with. Edits keep the version; to change it, move to the newest rules here or push with --semantics latest." />
          </p>
          <p className="mt-0.5 text-[13px] text-muted">
            {movable
              ? "Moving changes the version and nothing else. You review the stored revision before it becomes active."
              : `Validated with the newest rules this server supports.`}
          </p>
          {movable && (
            <Button
              className="mt-3"
              data-testid="move-rules"
              loading={push.isPending}
              onClick={() => push.mutate()}
              icon={<ArrowRight size={14} />}
            >
              Move to the newest rules (version {newest})
            </Button>
          )}
          {cancelled && (
            <p className="mt-2 text-xs text-muted">
              Cancelled. Revision <Mono>{cancelled}</Mono> stays stored but inactive; nothing changed.
            </p>
          )}
        </div>
      </div>

      {review && result && (
        <Dialog
          open
          onClose={cancel}
          size="md"
          data-testid="move-rules-review"
          title={`Move to version ${newest} rules`}
          description={
            <>
              Pushed revision <Mono className="text-fg">{review.pushed.id}</Mono>. It is not active yet.
            </>
          }
          footer={
            <>
              <span className="mr-auto text-xs text-muted">Cancel leaves the pushed revision stored but inactive.</span>
              <Button variant="secondary" onClick={cancel}>
                Cancel
              </Button>
              <Button
                variant="primary"
                data-testid="move-rules-activate"
                disabled={!result.activatable || stale}
                loading={activate.isPending}
                onClick={() => activate.mutate(review.pushed.id)}
              >
                Activate version {newest} rules
              </Button>
            </>
          }
        >
          <div className="space-y-4 text-[13px]">
            <div>
              <h3 className="mb-1.5 font-semibold">Changes</h3>
              <ul className="space-y-1" data-testid="move-rules-diff">
                {result.versionChange && (
                  <li className="flex items-center gap-2 rounded-md border border-bd bg-inset px-2.5 py-1.5 font-mono text-xs">
                    Semantics version {result.versionChange.from} → {result.versionChange.to}
                  </li>
                )}
                {result.otherChanges.map((c) => (
                  <li key={c} className="rounded-md border border-deny/40 bg-deny/[0.06] px-2.5 py-1.5 text-deny">
                    {c}
                  </li>
                ))}
              </ul>
            </div>
            {!result.activatable && (
              <Callout tone="danger" data-testid="move-rules-refused">
                The stored revision differs from the active contract in more than the semantics version, so it cannot be activated from here.
              </Callout>
            )}
            <div>
              <h3 className="mb-1.5 font-semibold">What the newer rules change</h3>
              <ul className="list-disc space-y-1 pl-5 text-fg/90">
                {semanticsSteps(from, newest).map((s) => (
                  <li key={s.version}>
                    Version {s.version}: {s.change}
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <h3 className="mb-1.5 font-semibold">After activation</h3>
              <ul className="list-disc space-y-1 pl-5 text-fg/90">
                {moveConsequences(from, newest, authority).map((c) => (
                  <li key={c}>
                    <WithCode text={c} />
                  </li>
                ))}
              </ul>
            </div>
            {stale && <Callout tone="danger">The active revision changed since this review. Cancel and start again.</Callout>}
            {activate.error && <Callout tone="danger">Could not activate the revision: {errorText(activate.error)}</Callout>}
          </div>
        </Dialog>
      )}
    </section>
  );
}
