// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useCallback, useEffect, useRef, useState } from "react";
import { startAuthentication, type PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/browser";
import { Clock, Fingerprint, ShieldAlert, ShieldCheck, ShieldX, TriangleAlert } from "lucide-react";
import { VarlatchApiError, type Approval, type ApprovalChange, type VarlatchClient } from "@varlatch/sdk";
import { useSession } from "../../lib/session";
import { countdown, formatDateTime, formatTime, useNow } from "../../lib/time";
import { Badge, Button, Callout, cn } from "../../components/ui";
import { Dialog } from "../../components/Dialog";

/**
 * Step-up approvals (ADR-0054 Decision 3): one person's approval, with a
 * trusted passkey and user verification, for one exact operation the
 * server described. The same content serves the approval page (a CLI's
 * request, `/approve/:id`) and the inline dialog for a change made here in
 * the dashboard. Only the person who asked can see an approval; approving
 * never extends its expiry, and approving does not run the operation: the
 * client that asked repeats it.
 */

/** Words for a field the server's summary names. */
const FIELD_LABELS: Record<string, string> = {
  mode: "Mode",
  config: "Lifetimes",
  defaultTtlSeconds: "Default lifetime",
  maxTtlSeconds: "Maximum lifetime",
  passkey: "Passkey",
};

/** 86400 -> "1 day", 5400 -> "90 minutes": a lifetime in seconds, in words. */
export function durationWords(seconds: number): string {
  const unit = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;
  if (seconds % 86_400 === 0) return unit(seconds / 86_400, "day");
  if (seconds % 3_600 === 0) return unit(seconds / 3_600, "hour");
  if (seconds % 60 === 0) return unit(seconds / 60, "minute");
  return unit(seconds, "second");
}

/** One value of a summary change, readable: lifetimes in words, nothing as "none". */
export function changeValue(field: string, value: string | null): string {
  if (value === null || value === "") return "none";
  if (/TtlSeconds$/.test(field) && /^\d+$/.test(value)) return durationWords(Number(value));
  return value;
}

export function fieldLabel(field: string): string {
  return FIELD_LABELS[field] ?? field;
}

/** What went wrong, for the person, from an approval route's error. */
export function approvalProblem(err: unknown): string {
  if (err instanceof VarlatchApiError) {
    const reason = typeof err.details?.reason === "string" ? err.details.reason : null;
    switch (err.code) {
      case "RESOURCE_NOT_FOUND":
        return "This approval was not found, or it is not yours. Only the person who asked can see and approve it.";
      case "APPROVAL_INVALID":
        return invalidReason(reason);
      case "RATE_LIMITED": {
        const retryAt = typeof err.details?.retryAt === "string" ? err.details.retryAt : null;
        return `Too many approval attempts. Try again${retryAt ? ` after ${formatTime(retryAt)}` : " in a few minutes"}.`;
      }
      case "PERMISSION_DENIED":
        switch (reason) {
          case "no-trusted-passkey":
            return NO_TRUSTED_PASSKEY;
          case "user-verification-required":
            return "Your passkey did not verify you with a PIN, fingerprint or face. Approve with a passkey that does. Nothing was approved.";
          case "unknown-passkey":
            return "That passkey is not one of your trusted passkeys. Use a trusted one, or confirm this one under Account, Security first. Nothing was approved.";
          case "challenge":
            return "This approval attempt was already used or expired. Try again. Nothing was approved.";
          case "invalid-assertion":
            return "The passkey response could not be verified. Try again. Nothing was approved.";
          default:
            return err.message;
        }
    }
    return err.message;
  }
  return err instanceof Error ? err.message : String(err);
}

const NO_TRUSTED_PASSKEY =
  "You have no trusted passkey, and only a trusted passkey can approve. Under Account, Security, confirm a passkey with a trusted one. " +
  "If none of your passkeys is trusted, ask whoever runs this Varlatch server for a link that enrolls a trusted one (varlatch admin reenroll).";

/** An APPROVAL_INVALID reason, for the person. */
export function invalidReason(reason: string | null): string {
  switch (reason) {
    case "expired":
      return "This approval expired. Start the change again to get a new one.";
    case "consumed":
      return "This approval was already used. Start the change again if you want to make it once more.";
    case "closed":
      return "This approval was cancelled or closed. Start the change again to get a new one.";
    case "approved":
      return "This approval is already approved. Go back to where you started it.";
    case "pending":
      return "This approval is still waiting for you to approve it.";
    case "mismatch":
      return "This approval was given for a different change. Start the change again to get a new approval.";
    case "stale":
      return "What this approval was for has changed since. Start the change again to get a new approval.";
    case "not-found":
      return "This approval was not found, or it is not yours.";
    default:
      return "This approval cannot be used any more. Start the change again to get a new one.";
  }
}

/**
 * The message for a change whose approval did not go through: a step-up the
 * person did not give (the dialog was closed or denied), or an approval the
 * server refused when the change was repeated. Null for any other error.
 */
export function approvalOutcomeMessage(err: unknown): string | null {
  if (!(err instanceof VarlatchApiError)) return null;
  if (err.code === "STEP_UP_REQUIRED") return "Nothing changed: this needs your approval with a trusted passkey, and it was not given.";
  if (err.code === "APPROVAL_INVALID") {
    return `Nothing changed. ${invalidReason(typeof err.details?.reason === "string" ? err.details.reason : null)}`;
  }
  return null;
}

/** The approval's state, with a pending one past its expiry counted as expired. */
export function effectiveState(approval: Approval, now: number): Approval["state"] {
  return approval.state === "pending" && Date.parse(approval.expiresAt) <= now ? "expired" : approval.state;
}

/** Why an approval can no longer be approved, in words; null while it can. */
export function finishedText(approval: Approval, now: number): string | null {
  switch (effectiveState(approval, now)) {
    case "pending":
      return null;
    case "approved":
      return "Approved. Go back to where you started it: the CLI continues by itself.";
    case "consumed":
      return "This approval was already used. Nothing more to do here.";
    case "expired":
      return "This approval expired before it was approved. Nothing was changed. Start the change again to get a new one.";
    case "closed":
      return approval.closeReason === "reset"
        ? "This approval was closed when whoever runs this server reset the organization's security controls. Nothing was changed."
        : approval.closeReason === "organization-deleted"
          ? "This approval was closed because its organization was deleted. Nothing was changed."
          : "This approval was cancelled. Nothing was changed.";
  }
}

function requesterText(approval: Approval): string {
  const client = approval.requestedBy.client;
  if (approval.requestedBy.credentialKind === "cli") return `You asked from the CLI${client ? ` (${client})` : ""}.`;
  return `You asked from the dashboard${client ? ` (${client})` : ""}.`;
}

function ChangeRow({ change }: { change: ApprovalChange }) {
  return (
    <li
      className={cn("flex flex-wrap items-baseline gap-x-2 gap-y-0.5", change.loosens && "text-warn")}
      data-testid="approval-change"
      data-loosens={change.loosens ? "true" : "false"}
    >
      <span className="w-36 shrink-0 text-muted">{fieldLabel(change.field)}</span>
      <span className="font-mono text-[12.5px]">
        {changeValue(change.field, change.from)} {"→"} {changeValue(change.field, change.to)}
      </span>
      {change.loosens && (
        <Badge tone="warn" className="ml-1">
          weakens
        </Badge>
      )}
    </li>
  );
}

/** What is approved: the server's summary, where, who asked, and the time left. */
export function ApprovalSummary({ approval, now }: { approval: Approval; now: number }) {
  const state = effectiveState(approval, now);
  return (
    <div data-testid="approval-summary" data-state={state}>
      <p className="text-[15px] font-medium leading-snug" data-testid="approval-title">
        {approval.summary.title}
      </p>
      <dl className="mt-3 space-y-1.5 rounded-lg border border-bd bg-inset px-4 py-3 text-[13px]">
        {approval.organization && (
          <div className="flex gap-3">
            <dt className="w-28 shrink-0 text-muted">Organization</dt>
            <dd data-testid="approval-organization">
              {approval.organization.name} <span className="font-mono text-[12px] text-muted">({approval.organization.slug})</span>
            </dd>
          </div>
        )}
        <div className="flex gap-3">
          <dt className="w-28 shrink-0 text-muted">Asked</dt>
          <dd data-testid="approval-requester">
            {requesterText(approval)} {formatDateTime(approval.createdAt)}
          </dd>
        </div>
        {state === "pending" && (
          <div className="flex gap-3">
            <dt className="w-28 shrink-0 text-muted">Expires in</dt>
            <dd className="inline-flex items-center gap-1.5 font-mono" data-testid="approval-countdown">
              <Clock size={13} aria-hidden="true" />
              {countdown(approval.expiresAt, now)}
            </dd>
          </div>
        )}
      </dl>
      {approval.summary.changes.length > 0 && (
        <ul className="mt-3 space-y-1 text-[13px]" data-testid="approval-changes">
          {approval.summary.changes.map((c, i) => (
            <ChangeRow key={`${c.field}-${i}`} change={c} />
          ))}
        </ul>
      )}
      {approval.summary.changes.some((c) => c.loosens) && (
        <p className="mt-3 text-[13px] text-muted">The highlighted parts weaken a protection. Approve only a change you made yourself.</p>
      )}
    </div>
  );
}

export type ApprovalFlow = {
  approval: Approval | null;
  error: string | null;
  busy: "approve" | "deny" | null;
  /** The browser passkey prompt or the server refused: nothing was approved, and the person may try again. */
  approve: () => Promise<boolean>;
  deny: () => Promise<void>;
};

/**
 * Approve or deny one approval: a fresh challenge from the server for
 * each attempt (a refused one is used up), the browser's passkey prompt,
 * then the assertion. `onSettled` hears the outcome once.
 */
export function useApprovalFlow(
  api: Pick<VarlatchClient, "startApproval" | "approveApproval" | "cancelApproval">,
  initial: Approval | null,
): ApprovalFlow {
  const [approval, setApproval] = useState<Approval | null>(initial);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null);
  useEffect(() => setApproval(initial), [initial]);

  const approve = useCallback(async () => {
    const target = approval ?? initial;
    if (!target) return false;
    setBusy("approve");
    setError(null);
    try {
      const { publicKey } = await api.startApproval(target.id);
      let assertion: unknown;
      try {
        assertion = await startAuthentication({ optionsJSON: publicKey as unknown as PublicKeyCredentialRequestOptionsJSON });
      } catch (err) {
        // Cancelled or timed out in the browser: nothing was sent.
        setError(`The passkey prompt did not complete (${err instanceof Error ? err.name : "cancelled"}). Nothing was approved.`);
        return false;
      }
      const approved = await api.approveApproval(target.id, assertion);
      setApproval(approved);
      return approved.state === "approved";
    } catch (err) {
      setError(approvalProblem(err));
      return false;
    } finally {
      setBusy(null);
    }
  }, [api, approval, initial]);

  const deny = useCallback(async () => {
    const target = approval ?? initial;
    if (!target) return;
    setBusy("deny");
    setError(null);
    try {
      setApproval(await api.cancelApproval(target.id));
    } catch (err) {
      setError(approvalProblem(err));
    } finally {
      setBusy(null);
    }
  }, [api, approval, initial]);

  // Until the effect adopts a newly loaded approval, show that one.
  return { approval: approval ?? initial, error, busy, approve, deny };
}

/** The buttons and messages under a summary, shared by the page and the dialog. */
export function ApprovalActions({
  flow,
  now,
  onApproved,
  onDenied,
  denyLabel = "Deny",
}: {
  flow: ApprovalFlow;
  now: number;
  onApproved?: (() => void) | undefined;
  onDenied?: (() => void) | undefined;
  denyLabel?: string | undefined;
}) {
  const { approval, error, busy } = flow;
  if (!approval) return null;
  const finished = finishedText(approval, now);
  const noTrusted = error === NO_TRUSTED_PASSKEY;
  return (
    <div className="mt-4 space-y-3">
      {finished && (
        <Callout
          tone={approval.state === "approved" ? "success" : "neutral"}
          icon={approval.state === "approved" ? <ShieldCheck size={16} /> : approval.state === "closed" ? <ShieldX size={16} /> : <Clock size={16} />}
          data-testid="approval-finished"
          data-state={effectiveState(approval, now)}
        >
          {finished}
        </Callout>
      )}
      {error && (
        <Callout
          tone={noTrusted ? "warn" : "danger"}
          icon={noTrusted ? <ShieldAlert size={16} /> : <TriangleAlert size={16} />}
          role="alert"
          data-testid="approval-error"
        >
          {error}
        </Callout>
      )}
      {!finished && (
        <>
          <p className="text-[13px] font-medium">Approve only a change you started yourself, with a trusted passkey and its PIN, fingerprint or face.</p>
          <div className="flex gap-2">
            <Button
              variant="primary"
              size="lg"
              className="flex-1"
              icon={<Fingerprint size={18} />}
              loading={busy === "approve"}
              disabled={busy !== null}
              data-testid="approval-approve"
              onClick={() => void flow.approve().then((ok) => ok && onApproved?.())}
            >
              Approve with passkey
            </Button>
            <Button
              variant="danger"
              size="lg"
              loading={busy === "deny"}
              disabled={busy !== null}
              data-testid="approval-deny"
              onClick={() => void flow.deny().then(() => onDenied?.())}
            >
              {denyLabel}
            </Button>
          </div>
        </>
      )}
    </div>
  );
}

type Pending = { approval: Approval; resolve: (approved: boolean) => void };

/**
 * The inline approval for a change made here in the dashboard: the session's
 * client hands every STEP_UP_REQUIRED to this provider, which shows the
 * approval in a dialog and resolves true once approved (the client then
 * repeats the change once, with the approval). Closing, denying or letting
 * it expire resolves false and cancels the approval on the server, best
 * effort. Several requests queue: one dialog at a time.
 */
export function ApprovalDialogProvider({ children }: { children: React.ReactNode }) {
  const { setStepUpHandler } = useSession();
  const [queue, setQueue] = useState<Pending[]>([]);
  useEffect(() => {
    setStepUpHandler((approval) => new Promise<boolean>((resolve) => setQueue((q) => [...q, { approval, resolve }])));
    return () => setStepUpHandler(null);
  }, [setStepUpHandler]);
  const current = queue[0];
  const done = useCallback(
    (approved: boolean) => {
      if (!current) return;
      current.resolve(approved);
      setQueue((q) => q.slice(1));
    },
    [current],
  );
  return (
    <>
      {children}
      {current && <ApprovalDialog key={current.approval.id} approval={current.approval} onDone={done} />}
    </>
  );
}

/** The dialog itself: the summary, a countdown, approve or cancel. */
export function ApprovalDialog({ approval, onDone }: { approval: Approval; onDone: (approved: boolean) => void }) {
  const { api } = useSession();
  const now = useNow(1000);
  const flow = useApprovalFlow(api, approval);
  const settled = useRef(false);
  const finish = useCallback(
    (approved: boolean) => {
      if (settled.current) return;
      settled.current = true;
      onDone(approved);
    },
    [onDone],
  );
  const close = () => {
    const current = flow.approval;
    // Still usable on the server: cancel it so nothing can use it later.
    if (current && (current.state === "pending" || current.state === "approved")) void api.cancelApproval(current.id).catch(() => undefined);
    finish(false);
  };
  const current = flow.approval ?? approval;
  return (
    <Dialog
      open
      onClose={close}
      size="sm"
      data-testid="approval-dialog"
      icon={
        <span className="flex size-9 items-center justify-center rounded-full bg-warn/12 text-warn">
          <ShieldAlert size={18} />
        </span>
      }
      title="Approve this change"
      description="This change needs your approval with a trusted passkey. It is applied right after you approve."
    >
      <ApprovalSummary approval={current} now={now} />
      <ApprovalActions flow={flow} now={now} onApproved={() => finish(true)} onDenied={() => finish(false)} denyLabel="Cancel" />
      {finishedText(current, now) && current.state !== "approved" && (
        <div className="mt-3 flex justify-end">
          <Button data-testid="approval-close" onClick={() => finish(false)}>
            Close
          </Button>
        </div>
      )}
    </Dialog>
  );
}
