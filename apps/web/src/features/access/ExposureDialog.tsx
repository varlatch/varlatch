// SPDX-License-Identifier: AGPL-3.0-or-later
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ExposureReport } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { Badge, Button, Callout } from "../../components/ui";
import { Dialog, useConfirm } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";
import { envPath } from "../values/model";
import { ReviewList, reviewCount, type MemberRef } from "./MemberDialogs";
import type { Names } from "./model";

/**
 * The exposure report as a checklist (ADR-0052 Decisions 6 and 7): what the
 * person received, observed in audit; what they could reach when removed;
 * what is not covered; and what they set up. Each version still served
 * links to its value to rotate it; an operator confirms a revocation at the
 * provider, version by version. Nothing is ever marked done on its own.
 */

type Received = ExposureReport["received"][number];

const WAY_WORDS: Record<string, string> = {
  revealed: "revealed",
  delivered: "delivered to a process",
  export: "read for export",
  written: "written by them",
};

/** A version's state, as a badge and its words. */
export function versionState(v: Received): { tone: "danger" | "warn" | "mono" | "accent"; label: string; detail: string } {
  if (v.confirmation) {
    return { tone: "accent", label: "revoked at provider", detail: v.served ? "Confirmed, though Varlatch still serves this version." : "Confirmed." };
  }
  if (v.servedAs === "current") return { tone: "danger", label: "still served", detail: "The current version." };
  if (v.servedAs === "retiring") {
    return { tone: "danger", label: "still served", detail: `Retiring: served until ${v.retiringUntil ? new Date(v.retiringUntil).toLocaleString() : "its deadline"}.` };
  }
  const why = { replaced: "A newer version replaced it.", "value-deleted": "The value was deleted.", "environment-deleted": "Its environment was deleted.", unknown: "Unknown here." }[
    v.notServedBecause ?? "unknown"
  ];
  return { tone: "warn", label: "no longer served", detail: `${why} Not safe until it is revoked at its provider.` };
}

type Requirement = NonNullable<ExposureReport["authorityAtRemoval"]>["requirements"][number];

/** A Requirement as it was defined at removal: a later edit does not change it. */
export function requirementWords(r: Requirement, envLabel: (id: string) => string): string {
  const selector = (r.selector ?? {}) as { tailnet?: string; tags?: string[]; users?: string[]; nodes?: string[] };
  const by = [
    selector.tags?.length ? `tags ${selector.tags.join(", ")}` : null,
    selector.users?.length ? `users ${selector.users.join(", ")}` : null,
    selector.nodes?.length ? `nodes ${selector.nodes.join(", ")}` : null,
  ].filter(Boolean);
  const target = r.target as { kind?: string; tier?: string; environmentIds?: string[] } | null;
  const on = target?.kind === "tier" ? `the ${target.tier} tier` : target?.kind === "environments" ? (target.environmentIds ?? []).map(envLabel).join(", ") : "its target";
  return `a device in ${selector.tailnet ?? "a tailnet"}${by.length ? ` with ${by.join(" or ")}` : ""} (Requirement on ${on}, as defined at removal)`;
}

/** When a version was first received, through any environment and in any way. */
export function firstReceived(v: Received): string {
  const first = v.receipts.map((r) => r.firstAt).sort()[0];
  return first ? new Date(first).toLocaleString() : "at an unknown time";
}

/** The open items: versions not yet confirmed revoked at their provider. */
export function openItems(report: ExposureReport): Received[] {
  return report.received.filter((v) => !v.confirmation);
}

export function ExposureDialog({
  org,
  person,
  names,
  onClose,
}: {
  org: string;
  person: MemberRef | null;
  names: Names;
  onClose: () => void;
}) {
  const { api } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const toast = useToast();
  const key = ["member-exposure", org, person?.id];
  const report = useQuery({
    queryKey: key,
    queryFn: () => api.memberExposure(org, person!.id),
    enabled: person !== null,
    staleTime: 0,
  });
  const confirmRevocation = useMutation({
    mutationFn: (versionId: string) => api.confirmExposureRevocation(org, person!.id, versionId),
    onSuccess: () => void qc.invalidateQueries({ queryKey: key }),
    onError: (err) => toast.error("Could not record the confirmation", { description: errorMessage(err) }),
  });
  const revokeCredential = useMutation({
    mutationFn: (c: { identityId: string; id: string }) => api.revokeIdentityCredential(org, c.identityId, c.id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: key }),
    onError: (err) => toast.error("Could not revoke the credential", { description: errorMessage(err) }),
  });
  const envLabel = (id: string | null) => {
    const env = id ? names.environment(id) : undefined;
    const project = env ? names.project(env.projectId) : undefined;
    // A deleted environment is no longer listed: its ID keeps it apart from others.
    return env && project ? `${project.slug} / ${env.name}` : (id ?? "an unknown environment");
  };
  const data = report.data;
  const open = data ? openItems(data) : [];
  return (
    <Dialog
      open={person !== null}
      onClose={onClose}
      size="lg"
      data-testid="exposure-dialog"
      title={`What ${person?.name ?? ""} received`}
      description="From the audit log and the record taken at removal. It never shows a value."
      footer={
        <Button variant="secondary" onClick={onClose}>
          Close
        </Button>
      }
    >
      <div className="space-y-5">
        {report.isLoading && <p className="text-[13px] text-muted">Reading the report…</p>}
        {report.error && (
          <p className="text-[13px] text-deny" data-testid="exposure-error">
            {errorMessage(report.error)}
          </p>
        )}
        {data && !data.coverage.complete && (
          <Callout tone="warn" title="Older history is still being indexed" data-testid="exposure-coverage">
            Events from {data.coverage.from ? new Date(data.coverage.from).toLocaleString() : "the start"} to{" "}
            {data.coverage.to ? new Date(data.coverage.to).toLocaleString() : "the upgrade"} are not covered yet.
          </Callout>
        )}
        {data && (
          <section>
            <h3 className="text-[13px] font-medium">
              Received <span className="font-normal text-muted">· {open.length} to review of {data.received.length}</span>
            </h3>
            <p className="text-xs text-muted">A delivery shows a response was sent, not that a copy was kept.</p>
            {data.received.length === 0 && <p className="mt-2 text-[13px] text-muted">Nothing in the audit log.</p>}
            <ul className="mt-2 space-y-3" data-testid="exposure-received">
              {data.received.map((v) => {
                const state = versionState(v);
                const env = v.owningEnvironmentId ? names.environment(v.owningEnvironmentId) : undefined;
                const project = env ? names.project(env.projectId) : undefined;
                return (
                  <li key={v.versionId} data-version={v.versionId} className="rounded-md border border-bd px-3 py-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-[13px] font-medium">{v.itemName}</span>
                      <span className="font-mono text-xs text-muted" data-testid="version-id" title="Version">
                        {v.versionId}
                      </span>
                      <span className="text-xs text-muted">in {envLabel(v.owningEnvironmentId)}</span>
                      <Badge tone={state.tone} data-testid="version-state">
                        {state.label}
                      </Badge>
                      <span className="ml-auto flex gap-2">
                        {v.served && project && env && (
                          <Link className="text-[13px] text-accent" to={envPath(org, project.slug, env.name, v.itemName)} data-testid="rotate-link">
                            Rotate…
                          </Link>
                        )}
                        {!v.confirmation && (
                          <Button
                            size="sm"
                            variant="secondary"
                            data-testid="confirm-revoked"
                            loading={confirmRevocation.isPending && confirmRevocation.variables === v.versionId}
                            onClick={async () => {
                              const ok = await confirm({
                                title: `Confirm ${v.itemName} version ${v.versionId} was revoked at its provider?`,
                                description: `This version, first received ${firstReceived(v)}, in ${envLabel(v.owningEnvironmentId)}. Confirm only after this credential stopped working at its provider. Changing the value in Varlatch does not revoke the old one there.`,
                                confirmLabel: "It was revoked",
                              });
                              if (ok) confirmRevocation.mutate(v.versionId);
                            }}
                          >
                            Revoked at provider…
                          </Button>
                        )}
                      </span>
                    </div>
                    <p className="mt-1 text-xs text-muted">{state.detail}</p>
                    <ul className="mt-1 text-xs text-muted">
                      {v.receipts.map((r) => (
                        <li key={`${r.environmentId}-${r.way}`}>
                          {WAY_WORDS[r.way] ?? r.way}
                          {r.environmentId !== v.owningEnvironmentId ? ` through ${envLabel(r.environmentId)}` : ""},{" "}
                          {r.firstAt === r.lastAt
                            ? new Date(r.firstAt).toLocaleString()
                            : `${new Date(r.firstAt).toLocaleString()} to ${new Date(r.lastAt).toLocaleString()}`}
                        </li>
                      ))}
                    </ul>
                    {v.rotationHint && v.served && <p className="mt-1 text-xs">To rotate: {v.rotationHint}</p>}
                  </li>
                );
              })}
            </ul>
          </section>
        )}
        {data?.authorityAtRemoval && (
          <section data-testid="exposure-authority">
            <h3 className="text-[13px] font-medium">Could reach when removed</h3>
            <p className="text-xs text-muted">
              Recorded at removal. They could have read more than they received; a Requirement is decided per device, so access is
              either unconditional or conditional on it.
            </p>
            <ul className="mt-2 space-y-1">
              {data.authorityAtRemoval.environments.map((e) => (
                <li key={e.environmentId} data-authority={e.environmentId} className="text-[13px]">
                  {envLabel(e.environmentId)}: {e.actions.map((a) => a.action).join(", ")}{" "}
                  <Badge tone={e.conditionalOn.length ? "mono" : "warn"}>{e.conditionalOn.length ? "conditional" : "unconditional"}</Badge>
                  {e.conditionalOn.length > 0 && (
                    <ul className="ml-4 text-xs text-muted" data-testid="authority-conditions">
                      {e.conditionalOn.map((id) => {
                        const r = data.authorityAtRemoval!.requirements.find((x) => x.requirementId === id);
                        return <li key={id}>reading values needed {r ? requirementWords(r, envLabel) : `Requirement ${id}`}</li>;
                      })}
                    </ul>
                  )}
                </li>
              ))}
            </ul>
          </section>
        )}
        {data && (
          <section>
            <h3 className="text-[13px] font-medium">Not covered</h3>
            <p className="text-xs text-muted">
              What they could reach before removal and no longer could then, and values that reached a broker, an agent or a platform. Those
              paths are listed below.
            </p>
          </section>
        )}
        {data && (
          <section data-testid="exposure-indirect">
            <h3 className="text-[13px] font-medium">What they set up</h3>
            <p className="text-xs text-muted">Indirect paths: not evidence that they held a value.</p>
            {reviewCount(data.indirect) === 0 ? (
              <p className="mt-2 text-[13px] text-muted">Nothing.</p>
            ) : (
              <div className="mt-2">
                <ReviewList review={data.indirect} names={names} />
              </div>
            )}
            {data.indirect.credentials.some((c) => c.state === "valid") && (
              <ul className="mt-2 space-y-1">
                {data.indirect.credentials
                  .filter((c) => c.state === "valid")
                  .map((c) => (
                    <li key={c.id} className="flex items-center gap-2 text-[13px]">
                      <span>
                        {c.name ?? "A credential"} for {c.identityName} still works
                      </span>
                      <Button
                        size="sm"
                        variant="danger"
                        data-testid={`revoke-credential-${c.id}`}
                        loading={revokeCredential.isPending && revokeCredential.variables?.id === c.id}
                        onClick={async () => {
                          const ok = await confirm({
                            title: `Revoke ${c.name ?? "this credential"} for ${c.identityName}?`,
                            description: "Whatever uses it stops working. Issue another one for whoever should keep it.",
                            confirmLabel: "Revoke",
                            tone: "danger",
                          });
                          if (ok) revokeCredential.mutate({ identityId: c.identityId, id: c.id });
                        }}
                      >
                        Revoke
                      </Button>
                    </li>
                  ))}
              </ul>
            )}
          </section>
        )}
      </div>
    </Dialog>
  );
}
