// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowUpRight, CheckCircle2, Circle, Fingerprint, Loader2, TriangleAlert, XCircle } from "lucide-react";
import type { InstallationRelease, UpgradeRequestState } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { useCapability } from "../projects/hooks";
import { Button, Callout, cn } from "../../components/ui";
import { Dialog } from "../../components/Dialog";
import { CodeBlock } from "../../components/CodeBlock";
import { errorMessage } from "../../shell/Shell";
import { approvalOutcomeMessage } from "../security-controls/approval";
import {
  DOCS_WEB_UPGRADE_URL,
  POLL_MS,
  STEPS,
  failedStep,
  isOver,
  newRequestId,
  offeredAfter,
  oneClickVersion,
  opened,
  outcomeText,
  pollEvery,
  stepOf,
} from "./webUpgradeStatus";

/** A request that ended this long ago is no longer shown. */
const SHOW_ENDED_MS = 60 * 60_000;

/**
 * The one-click upgrade (ADR-0065 phase 2), on a server that lists
 * installation.upgrade: the request's progress when there is one, else the
 * button when every pre-flight line passes. Null otherwise: the card shows
 * the commands.
 */
export function WebUpgrade({ release }: { release: InstallationRelease }) {
  const supported = useCapability("installation.upgrade");
  const { api } = useSession();
  const qc = useQueryClient();
  const offered = oneClickVersion(release);
  const state = useQuery({
    queryKey: ["installation-upgrade-request"],
    queryFn: () => api.getUpgradeRequest(),
    enabled: supported,
    retry: false,
    refetchInterval: (q) => pollEvery(q.state.data, offered),
  });
  // The release this page loaded with: the reload below brings the one
  // that opened, whichever answer (the request's, or /v1/meta's) comes
  // first. After the reload it is the new one, so it does not reload again.
  const [loadedWith] = useState(release.running);
  const st = state.data;
  useReloadWhenOpen(loadedWith, !!st?.request && RESTARTED.includes(st.state) && st.request.version !== loadedWith);
  // A request that ended may change the pre-flight (an undone version is
  // not offered again): the tab's release is asked again.
  const ended = st ? isOver(st.state) : true;
  const wasEnded = useRef(ended);
  useEffect(() => {
    if (ended && !wasEnded.current) void qc.invalidateQueries({ queryKey: ["installation-release"] });
    wasEnded.current = ended;
  }, [ended, qc]);
  if (!supported || !st) return null;
  const again = offeredAfter(offered, st);
  const recent = st.request && Date.now() - Date.parse(st.updatedAt ?? st.request.requestedAt) < SHOW_ENDED_MS;
  if (st.request && (!isOver(st.state) || recent)) {
    return <UpgradeProgress state={st} running={release.running} offered={again} />;
  }
  if (st.unreadable?.includes("last.json") && !isOver(st.state)) {
    return <UnreadableRequest state={st} />;
  }
  return again ? <UpgradeButton version={again} running={release.running} /> : null;
}

/** The states of a request from the stop on: the page reloads once the new release answers. */
const RESTARTED: UpgradeRequestState["state"][] = ["restarting", "checking", "done"];

/**
 * A request whose record cannot be read, while the host has one waiting or
 * running: no button until it ends, and nothing to cancel by its id.
 */
function UnreadableRequest({ state }: { state: UpgradeRequestState }) {
  return (
    <Callout tone="warn" icon={<TriangleAlert size={16} />} data-testid="web-upgrade-unreadable" title="The upgrade request's record cannot be read">
      The host has a request {state.state === "waiting" ? "waiting" : "under way"}, but which one is not known. It ends by itself (a waiting request
      expires after 10 minutes); then a new request replaces the record.
    </Callout>
  );
}

/** "Upgrade to 0.52.0", the confirmation, then the passkey prompt (the session's step-up dialog). */
export function UpgradeButton({ version, running, label }: { version: string; running: string; label?: string | undefined }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const ask = useMutation({
    mutationFn: () => api.requestUpgrade(version, newRequestId()),
    onSuccess: (st) => {
      qc.setQueryData(["installation-upgrade-request"], st);
      setConfirming(false);
    },
  });
  const problem = ask.error ? (approvalOutcomeMessage(ask.error) ?? errorMessage(ask.error)) : null;
  return (
    <div className="space-y-2" data-testid="web-upgrade">
      <Button variant="primary" size="lg" data-testid="web-upgrade-button" onClick={() => (ask.reset(), setConfirming(true))}>
        {label ?? `Upgrade to ${version}`}
      </Button>
      <p className="text-muted">The host verifies the release again, backs up off the host, and upgrades. You approve with a trusted passkey.</p>
      <Dialog
        open={confirming}
        onClose={() => !ask.isPending && setConfirming(false)}
        title={`Upgrade Varlatch to ${version}?`}
        description={`From ${running}. The host does it; this page follows.`}
        data-testid="web-upgrade-confirm"
        footer={
          <>
            <Button onClick={() => setConfirming(false)} disabled={ask.isPending}>
              Cancel
            </Button>
            <Button variant="primary" icon={<Fingerprint size={16} />} loading={ask.isPending} data-testid="web-upgrade-confirm-button" onClick={() => ask.mutate()}>
              Approve with a passkey and upgrade
            </Button>
          </>
        }
      >
        <ol className="list-decimal space-y-1.5 pl-5 text-[13px]" data-testid="web-upgrade-confirm-steps">
          <li>The host finds {version} again and verifies its signature and files.</li>
          <li>It takes an encrypted snapshot, delivers it to your backup destination and checks the delivered copy. If that fails, nothing stops.</li>
          <li>It stops Varlatch, updates a copy of the database, and starts {version}.</li>
          <li>When {version}'s health checks pass it opens; when one fails, {running} serves again, with every change kept.</li>
        </ol>
        <Callout tone="warn" icon={<TriangleAlert size={16} />} className="mt-3" data-testid="web-upgrade-downtime">
          Varlatch is unavailable for about a minute while it restarts. CLI commands, Brokers and syncs that run then fail or wait; webhooks and syncs catch
          up after.
        </Callout>
        {problem && (
          <Callout tone="danger" icon={<TriangleAlert size={16} />} className="mt-3" role="alert" data-testid="web-upgrade-error">
            {problem}
          </Callout>
        )}
      </Dialog>
    </div>
  );
}

/** The request's steps, its outcome, and the cancel while the host has not taken it. */
export function UpgradeProgress({ state, running, offered }: { state: UpgradeRequestState; running: string; offered: string | null }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const [tooLate, setTooLate] = useState(false);
  const cancel = useMutation({
    mutationFn: () => api.cancelUpgradeRequest(state.request!.id),
    onSuccess: (st) => {
      setTooLate(st.cancelled === false);
      qc.setQueryData(["installation-upgrade-request"], st);
    },
  });
  const at = stepOf(state.state);
  const failAt = failedStep(state);
  const outcome = outcomeText(state, tooLate);
  const over = isOver(state.state);
  const version = state.request?.version ?? "";
  return (
    <div className="space-y-3 rounded-lg border border-bd px-4 py-3" data-testid="web-upgrade-progress" data-state={state.state}>
      <p className="font-medium">Upgrade to {version}</p>
      <ol className="space-y-1.5" aria-live="polite" aria-label="The host's steps" data-testid="web-upgrade-steps">
        {STEPS.map((step, i) => {
          const done = state.state === "done" || (failAt >= 0 ? i < failAt : at > i);
          const current = at === i && !over;
          const failedHere = failAt === i;
          return (
            <li key={step.label} className={cn("flex items-center gap-2", !done && !current && "text-muted")} data-testid={`web-upgrade-step-${i}`} data-done={done}>
              {done ? (
                <CheckCircle2 size={15} className="text-ok" aria-hidden="true" />
              ) : current ? (
                <Loader2 size={15} className="animate-spin" aria-hidden="true" />
              ) : failedHere ? (
                <XCircle size={15} className="text-danger" aria-hidden="true" />
              ) : (
                <Circle size={15} aria-hidden="true" />
              )}
              {step.label}
            </li>
          );
        })}
      </ol>
      {state.noAnswer && !over && (
        <Callout tone="warn" icon={<TriangleAlert size={16} />} data-testid="web-upgrade-no-answer" title="The host helper did not answer">
          Nothing happened on the host for 2 minutes. See whether its units run, on the host:
          <CodeBlock lines={["sudo systemctl status varlatch-upgrade.path varlatch-upgrade.service", "sudo journalctl -u varlatch-upgrade.service"]} />
        </Callout>
      )}
      {outcome && (
        <Callout
          tone={outcome.tone === "ok" ? "success" : outcome.tone}
          role={outcome.tone === "danger" || outcome.tone === "warn" ? "alert" : "status"}
          data-testid="web-upgrade-outcome"
          data-reason={state.reason ?? ""}
        >
          {outcome.text}
        </Callout>
      )}
      <div className="flex flex-wrap items-center gap-3">
        {state.state === "waiting" && !tooLate && (
          <Button variant="danger" loading={cancel.isPending} data-testid="web-upgrade-cancel" onClick={() => cancel.mutate()}>
            Cancel the request
          </Button>
        )}
        {over && offered && <UpgradeButton version={offered} running={running} label={offered === version ? `Upgrade to ${offered} again` : undefined} />}
        <a href={DOCS_WEB_UPGRADE_URL} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-accent hover:underline">
          Upgrading from the web app
          <ArrowUpRight size={13} />
        </a>
      </div>
      {cancel.error && (
        <Callout tone="danger" icon={<TriangleAlert size={16} />} role="alert">
          {errorMessage(cancel.error)}
        </Callout>
      )}
    </div>
  );
}

/**
 * Through the restart: polls /v1/meta (it answers without a session), at
 * once and then every POLL_MS, and reloads the page once, when another
 * release than `loadedWith` answers: the new one open (Decision 8). Armed
 * from the stop through done, so a request that says done before /v1/meta
 * is asked still reloads. A failed health check keeps `loadedWith`, and the
 * tab's state says undone.
 */
function useReloadWhenOpen(loadedWith: string, active: boolean) {
  const reloaded = useRef(false);
  useEffect(() => {
    if (!active) return;
    let stopped = false;
    const look = () =>
      void fetch("/v1/meta", { cache: "no-store" })
        .then((r) => (r.ok ? (r.json() as Promise<{ serverVersion?: string }>) : null))
        .then((m) => {
          if (stopped || reloaded.current || !m || !opened(loadedWith, m.serverVersion)) return;
          reloaded.current = true;
          window.location.reload();
        })
        .catch(() => undefined);
    look();
    const timer = window.setInterval(look, POLL_MS);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [loadedWith, active]);
}
