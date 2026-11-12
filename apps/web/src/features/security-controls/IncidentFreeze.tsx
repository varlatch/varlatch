// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { OctagonX, Snowflake } from "lucide-react";
import type { IncidentFreeze } from "@varlatch/sdk";
import { useSession } from "../../lib/session";
import { formatDateTime } from "../../lib/time";
import { Button, Callout, Input, SectionCard } from "../../components/ui";
import { useConfirm } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";
import { useCapability } from "../projects/hooks";

/**
 * The incident freeze in the dashboard (ADR-0055 Decision 11). "Freeze
 * Organization" on the Security page says what stops and asks for the slug
 * and a reason. While frozen, every Organization page shows a banner;
 * pages outside the exceptions show only the banner; the Security page
 * shows who froze it, when and why, with "Lift freeze", which asks for the
 * person's approval with a trusted passkey through the session's approval
 * dialog. Everything here is read from varlatchd: the Convex token leaves
 * a frozen Organization out.
 */

export const incidentFreezeKey = (org: string) => ["incident-freeze", org] as const;

/** The open freeze, the Sync Targets that resume on the lift, and the last freezes; every member may read it. */
export function useIncidentFreeze(org: string | undefined) {
  const { api } = useSession();
  const supported = useCapability("organizations.incident-freeze");
  return useQuery({
    queryKey: incidentFreezeKey(org ?? ""),
    queryFn: () => api.incidentFreeze(org as string),
    enabled: supported && Boolean(org),
    refetchInterval: 30_000,
    retry: false,
  });
}

/** What freezing stops, and what keeps working. Said before freezing. */
export const FREEZE_CONSEQUENCES = [
  "Every read and write of its members and machines is refused at once, values included: varlatch run, CI jobs and deploys that fetch from it fail.",
  "Still possible: reading members, machines, credentials, grants, requirements and the audit log; revoking credentials, grants and capabilities; removing members; pausing Sync Targets; changing security controls.",
  "Sync Targets stop pushing until the freeze is lifted. Webhooks keep delivering the audit log.",
  "Every open approval of this organization is closed.",
  "Lifting it needs an admin's approval with a trusted passkey, or whoever runs this server (varlatchd admin unfreeze).",
  "If your deploy or rollback credentials come from this organization, keep a break-glass credential outside Varlatch first.",
];

/**
 * The organization pages that work while frozen: their reads and actions
 * are inspection, audit or recovery. Connections shows its frozen view
 * (the lists and revocation, without the GitHub App and the changes the
 * freeze refuses); the GitHub App's registration callback below it does
 * not work. Every other page shows only the banner.
 */
const PAGES_WHILE_FROZEN = ["security", "access", "audit", "settings"];
const EXACT_PAGES_WHILE_FROZEN = ["connections"];

export function pageWorksWhileFrozen(pathname: string, org: string): boolean {
  const prefix = `/o/${org}`;
  if (!pathname.startsWith(prefix)) return false;
  const rest = pathname.slice(prefix.length).replace(/^\/+|\/+$/g, "");
  return PAGES_WHILE_FROZEN.includes(rest.split("/")[0] ?? "") || EXACT_PAGES_WHILE_FROZEN.includes(rest);
}

/** Whether the organization is frozen for an incident now (false while unknown). */
export function useFrozen(org: string | undefined): boolean {
  return Boolean(useIncidentFreeze(org).data?.freeze);
}

function FreezeBanner({ org, freeze, onlyBanner }: { org: string; freeze: IncidentFreeze; onlyBanner: boolean }) {
  return (
    <Callout
      tone="danger"
      icon={<Snowflake size={16} />}
      title="This organization is frozen for an incident"
      className="mb-4"
      role="status"
      data-testid="incident-freeze-banner"
      actions={
        <Link to={`/o/${org}/security#security-freeze`} className="text-[13px] font-medium underline-offset-2 hover:underline" data-testid="incident-freeze-review">
          Review
        </Link>
      }
    >
      <p>
        Frozen since {formatDateTime(freeze.frozenAt)} by {freeze.frozenBy.name ?? freeze.frozenBy.id}: {freeze.reason}
      </p>
      <p className="text-muted">
        {onlyBanner
          ? "This page is not available while the organization is frozen. Members, machines, access and the audit log stay readable."
          : "Reads and changes are refused, apart from reviewing access, revoking it and reading the audit log."}
      </p>
    </Callout>
  );
}

/** The banner on every page of a frozen organization; the page itself only where it can work. */
export function FreezeGate({ org, children }: { org: string | undefined; children: React.ReactNode }) {
  const state = useIncidentFreeze(org);
  const { pathname } = useLocation();
  const freeze = state.data?.freeze ?? null;
  if (!org || !freeze) return <>{children}</>;
  const works = pageWorksWhileFrozen(pathname, org);
  return (
    <>
      <FreezeBanner org={org} freeze={freeze} onlyBanner={!works} />
      {works ? children : null}
    </>
  );
}

/** The Security page's section: freeze, or the open freeze with "Lift freeze". */
export function IncidentFreezeCard({ org, admin }: { org: string; admin: boolean }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const supported = useCapability("organizations.incident-freeze");
  const state = useIncidentFreeze(org);
  const [reason, setReason] = useState("");
  const trimmed = reason.trim();
  const done = async (title: string, description?: string) => {
    // Everything the freeze refused or allowed changes: read it all again.
    await qc.invalidateQueries();
    toast.success(title, description ? { description } : undefined);
  };
  const freezeIt = useMutation({
    mutationFn: (why: string) => api.freezeOrganization(org, why),
    onSuccess: () => {
      setReason("");
      return done("Organization frozen", "Lift it here with your approval when the incident is handled.");
    },
    onError: (err) => toast.error("Could not freeze the organization", { description: errorMessage(err) }),
  });
  const lift = useMutation({
    mutationFn: (freezeId: string) => api.liftIncidentFreeze(org, freezeId),
    onSuccess: (r) => done("Freeze lifted", r.resumingTargets && r.resumingTargets.length > 0 ? `${r.resumingTargets.length} Sync Targets resume pushing.` : undefined),
    onError: (err) => toast.error("Could not lift the freeze", { description: errorMessage(err) }),
  });
  if (!supported) return null;
  const freeze = state.data?.freeze ?? null;
  // null: the caller may not read the Sync Targets (config.sync.manage).
  const targets = state.data?.resumingTargets ?? null;

  const askFreeze = async () => {
    if (!trimmed || trimmed.length > 200) return;
    const ok = await confirm({
      title: `Freeze organization ${org}?`,
      description: "This stops all access to it at once, until an admin lifts the freeze with a passkey approval.",
      consequences: FREEZE_CONSEQUENCES.map((text) => ({ text })),
      confirmLabel: "Freeze organization",
      tone: "danger",
      typeToConfirm: org,
    });
    if (ok) freezeIt.mutate(trimmed);
  };
  const askLift = async (f: IncidentFreeze) => {
    const ok = await confirm({
      title: `Lift the freeze of ${org}?`,
      description: "Lifting undoes nothing done during the freeze: revoked credentials and grants stay revoked. It needs your approval with a trusted passkey.",
      consequences:
        targets === null
          ? [{ text: "Sync Targets that were not paused or revoked resume pushing." }]
          : targets.length === 0
            ? [{ text: "No Sync Target resumes pushing." }]
            : targets.map((t) => ({ text: `Sync Target ${t.projectSlug}/${t.environmentName} (${t.platform}, ${t.destination}) resumes pushing.` })),
      confirmLabel: "Lift freeze",
    });
    if (ok) lift.mutate(f.id);
  };

  return (
    <SectionCard
      id="security-freeze"
      title="Incident freeze"
      description="One action that stops all access to this organization during an incident, reads included, while the audit log keeps flowing."
      className="scroll-mt-6 border-deny/40"
      data-testid="incident-freeze"
    >
      <div className="space-y-4 px-5 py-4">
        {state.error ? (
          <p className="text-[13px] text-deny" role="alert">
            {errorMessage(state.error)}
          </p>
        ) : freeze ? (
          <Callout
            tone="danger"
            icon={<OctagonX size={16} />}
            title={`Frozen by ${freeze.frozenBy.name ?? freeze.frozenBy.id} on ${formatDateTime(freeze.frozenAt)}`}
            data-testid="incident-freeze-open"
            actions={
              admin ? (
                <Button variant="secondary" loading={lift.isPending} onClick={() => void askLift(freeze)} data-testid="lift-freeze">
                  Lift freeze…
                </Button>
              ) : undefined
            }
          >
            <p>Reason: {freeze.reason}</p>
            <p className="text-muted">
              {targets === null
                ? "Sync Targets that were not paused or revoked resume pushing when it is lifted."
                : targets.length === 0
                  ? "No Sync Target resumes pushing when it is lifted."
                  : `${targets.length} Sync Targets resume pushing when it is lifted.`}
            </p>
            <p className="text-muted">Freeze {freeze.id}</p>
          </Callout>
        ) : (
          <>
            <ul className="list-disc space-y-1.5 pl-5 text-[13px] text-fg/90">
              {FREEZE_CONSEQUENCES.map((text) => (
                <li key={text}>{text}</li>
              ))}
            </ul>
            {admin ? (
              <form
                className="flex flex-wrap items-end gap-3"
                onSubmit={(e) => {
                  e.preventDefault();
                  void askFreeze();
                }}
              >
                <label className="min-w-[260px] flex-1 space-y-1.5 text-[13px]">
                  <span className="block text-muted">Reason, shown to members (up to 200 characters)</span>
                  <Input value={reason} maxLength={200} onChange={(e) => setReason(e.target.value)} data-testid="freeze-reason" />
                </label>
                <Button type="submit" variant="danger" disabled={!trimmed} loading={freezeIt.isPending} data-testid="freeze-org">
                  Freeze organization…
                </Button>
              </form>
            ) : (
              <p className="text-[13px] text-muted">Only an admin of this organization can freeze it.</p>
            )}
          </>
        )}
      </div>
    </SectionCard>
  );
}
