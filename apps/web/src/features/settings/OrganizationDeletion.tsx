// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { TriangleAlert } from "lucide-react";
import type { OrganizationDeletion } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { formatDateTime, timeUntil, useNow } from "../../lib/time";
import { Button, Callout, Input, SectionCard } from "../../components/ui";
import { useConfirm } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";
import { useCapability } from "../projects/hooks";
import { useIdentities } from "../access/shared";

/**
 * Deleting an Organization (ADR-0051 Decisions 4, 5 and 11): a request
 * that freezes it, a waiting period, another admin's approval when there
 * were several, and a cancel until it runs.
 */

export const deletionKey = (org: string) => ["org-deletion", org] as const;

/** The open deletion request, or null; every member may read it. */
export function useOrganizationDeletion(org: string | undefined) {
  const { api } = useSession();
  const supported = useCapability("organizations.delete");
  return useQuery({
    queryKey: deletionKey(org ?? ""),
    queryFn: () => api.organizationDeletion(org as string),
    enabled: supported && Boolean(org),
    refetchInterval: 60_000,
    retry: false,
  });
}

/** What scheduling, and the deletion it leads to, do and do not reach (Decision 10). */
export function organizationDeletionConsequences(approvalNeeded: boolean): string[] {
  return [
    "Now: the organization freezes. Changes are refused and reads still work, so a last copy can be made. Machine identities and webhooks are suspended, Sync Targets paused, and pending invitations revoked.",
    `After the waiting period${approvalNeeded ? ", and another admin's approval" : ""}: every membership ends, machines are retired, values are erased and the organization's key is destroyed. There is no undo.`,
    "Any admin can cancel until then. A cancel brings back the suspended machines and webhooks; Sync Targets stay paused, and invitations must be issued again.",
    "Whoever can read the audit log then can still export it afterwards.",
    "Values pushed to platforms, copies people revealed or downloaded, and backups taken before the deletion completes are not reached: rotate values at their provider.",
    "A GitHub App stays installed on GitHub: uninstall or delete it there, and revoke copies of its private key.",
  ];
}

/** The request's state in words, for the card and the banner. */
export function deletionState(deletion: OrganizationDeletion, name: (id: string) => string, now: number): { runs: string; approval: string | null } {
  const runs = `It may run from ${formatDateTime(deletion.runAfter)}${Date.parse(deletion.runAfter) > now ? ` (${timeUntil(deletion.runAfter, now)})` : ""}.`;
  if (!deletion.approvalRequired) return { runs, approval: null };
  if (deletion.approvedBy) return { runs, approval: `Approved by ${name(deletion.approvedBy)}.` };
  const overdue = Date.parse(deletion.runAfter) <= now;
  return { runs, approval: `It waits for another admin's approval${overdue ? " and never runs without it" : ""}.` };
}

function useMembership(org: string) {
  const { identityId: me } = useSession();
  const identities = useIdentities(org);
  const people = (identities.data?.items ?? []).filter((i) => i.kind === "human" && !i.removedAt);
  const names = new Map((identities.data?.items ?? []).map((i) => [i.id, i.name] as const));
  return {
    me,
    admin: people.find((p) => p.id === me)?.orgRole === "admin",
    admins: people.filter((p) => p.orgRole === "admin").length,
    name: (id: string) => (id === me ? "you" : (names.get(id) ?? id)),
  };
}

/** The Settings section: schedule, or the open request with approve and cancel. */
export function OrganizationDeletionCard({ org, slug, id }: { org: string; slug: string | undefined; id: string | undefined }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const now = useNow();
  const deletion = useOrganizationDeletion(org);
  const { me, admin, admins, name } = useMembership(org);
  const [days, setDays] = useState("7");
  const afterDays = /^\d+$/.test(days) && Number(days) >= 1 && Number(days) <= 30 ? Number(days) : null;
  const done = async (title: string, description?: string) => {
    await Promise.all([qc.invalidateQueries({ queryKey: deletionKey(org) }), qc.invalidateQueries({ queryKey: ["identities", org] })]);
    toast.success(title, description ? { description } : undefined);
  };
  const schedule = useMutation({
    mutationFn: (after: number) => api.scheduleOrganizationDeletion(org, { afterDays: after }),
    onSuccess: (d) => done("Deletion scheduled", `It may run from ${formatDateTime(d.runAfter)}.`),
    onError: (err) => toast.error("Could not schedule the deletion", { description: errorMessage(err) }),
  });
  const approve = useMutation({
    mutationFn: (deletionId: string) => api.approveOrganizationDeletion(org, deletionId),
    onSuccess: () => done("Deletion approved"),
    onError: (err) => toast.error("Could not approve the deletion", { description: errorMessage(err) }),
  });
  const cancel = useMutation({
    mutationFn: (deletionId: string) => api.cancelOrganizationDeletion(org, deletionId),
    onSuccess: () => done("Deletion cancelled", "Suspended machines and webhooks are back; Sync Targets stay paused."),
    onError: (err) => toast.error("Could not cancel the deletion", { description: errorMessage(err) }),
  });
  if (!slug) return null;
  const open = deletion.data ?? null;

  const askSchedule = async () => {
    if (afterDays === null) return;
    const ok = await confirm({
      title: `Delete organization ${slug}?`,
      description: `It freezes now and is deleted no earlier than ${afterDays} ${afterDays === 1 ? "day" : "days"} from now.`,
      consequences: organizationDeletionConsequences(admins > 1).map((text) => ({ text })),
      confirmLabel: "Schedule deletion",
      tone: "danger",
      typeToConfirm: slug,
    });
    if (ok) schedule.mutate(afterDays);
  };
  const askApprove = async (d: OrganizationDeletion) => {
    const ok = await confirm({
      title: `Approve the deletion of ${slug}?`,
      description: `${deletionState(d, name, now).runs} Then every membership ends, machines are retired, values are erased and the organization's key is destroyed. There is no undo.`,
      confirmLabel: "Approve deletion",
      tone: "danger",
      typeToConfirm: slug,
    });
    if (ok) approve.mutate(d.id);
  };
  const askCancel = async (d: OrganizationDeletion) => {
    const ok = await confirm({
      title: `Cancel the deletion of ${slug}?`,
      consequences: [
        { text: "The organization is no longer frozen." },
        { text: "Machine identities and webhooks the request suspended are back." },
        { text: "Sync Targets stay paused: resume them when you choose. Revoked invitations must be issued again." },
      ],
      confirmLabel: "Cancel deletion",
      cancelLabel: "Keep it scheduled",
    });
    if (ok) cancel.mutate(d.id);
  };

  return (
    <SectionCard
      id="settings-danger"
      title="Delete organization"
      description="Deleting is a request: the organization freezes at once and is deleted after a waiting period."
      className="scroll-mt-6 border-deny/40"
      data-testid="settings-danger"
    >
      <div className="space-y-4 px-5 py-4">
        {open ? (
          <Callout
            tone="danger"
            icon={<TriangleAlert size={16} />}
            title={`Scheduled by ${name(open.requestedBy)} on ${formatDateTime(open.scheduledAt)}`}
            data-testid="org-deletion-request"
            actions={
              admin ? (
                <>
                  {open.approvalRequired && !open.approvedBy && open.requestedBy !== me && (
                    <Button variant="danger" loading={approve.isPending} onClick={() => void askApprove(open)} data-testid="approve-org-deletion">
                      Approve…
                    </Button>
                  )}
                  <Button variant="secondary" loading={cancel.isPending} onClick={() => void askCancel(open)} data-testid="cancel-org-deletion">
                    Cancel deletion…
                  </Button>
                </>
              ) : undefined
            }
          >
            <p>{deletionState(open, name, now).runs}</p>
            {deletionState(open, name, now).approval && <p>{deletionState(open, name, now).approval}</p>}
            <p className="text-muted">Request {open.id}</p>
          </Callout>
        ) : (
          <>
            <ul className="list-disc space-y-1.5 pl-5 text-[13px] text-fg/90">
              {organizationDeletionConsequences(admins > 1).map((text) => (
                <li key={text}>{text}</li>
              ))}
            </ul>
            {id && (
              <p className="text-[13px] text-muted">
                Afterwards, the audit log is exported with <code className="rounded bg-inset px-1 font-mono">varlatch audit export --deleted-org {id}</code>.
              </p>
            )}
            {admin ? (
              <form
                className="flex flex-wrap items-end gap-3"
                onSubmit={(e) => {
                  e.preventDefault();
                  void askSchedule();
                }}
              >
                <label className="space-y-1.5 text-[13px]">
                  <span className="block text-muted">Waiting period (1 to 30 days)</span>
                  <Input
                    type="number"
                    min={1}
                    max={30}
                    className="w-28"
                    value={days}
                    onChange={(e) => setDays(e.target.value)}
                    data-testid="org-deletion-days"
                  />
                </label>
                <Button type="submit" variant="danger" disabled={afterDays === null} loading={schedule.isPending} data-testid="delete-org">
                  Delete organization…
                </Button>
              </form>
            ) : (
              <p className="text-[13px] text-muted">Only an admin of this organization can delete it.</p>
            )}
          </>
        )}
      </div>
    </SectionCard>
  );
}

/** Shown on every page of a frozen organization, with when it may be deleted. */
export function DeletionBanner({ org }: { org: string | undefined }) {
  const deletion = useOrganizationDeletion(org);
  const now = useNow();
  const open = deletion.data;
  if (!org || !open) return null;
  const state = deletionState(open, (id) => id, now);
  return (
    <Callout
      tone="danger"
      icon={<TriangleAlert size={16} />}
      title="This organization is being deleted"
      className="mb-4"
      role="status"
      data-testid="org-deletion-banner"
      actions={
        <Link to={`/o/${org}/settings#settings-danger`} className="text-[13px] font-medium underline-offset-2 hover:underline" data-testid="org-deletion-review">
          Review
        </Link>
      }
    >
      {state.runs} Until then changes are refused; reads still work, so a last copy can be made.
      {state.approval ? ` ${state.approval}` : ""}
    </Callout>
  );
}
