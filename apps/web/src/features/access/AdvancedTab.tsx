// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Filter, Monitor, MoreHorizontal, Plus, Sparkles, Tag, User, Wifi } from "lucide-react";
import type { Requirement, Tier } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { countdown, timeAgo, useNow } from "../../lib/time";
import {
  Badge,
  Button,
  Callout,
  EmptyState,
  Field,
  InfoTip,
  Input,
  Menu,
  SectionCard,
  Select,
  StatusDot,
  TierDot,
  cn,
} from "../../components/ui";
import { useConfirm } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";
import { TIERS, useIdentities } from "./shared";
import { useAccessNames } from "./useAccessNames";
import {
  formEditBlocker,
  matchParts,
  parseTags,
  requirementCreate,
  requirementSentence,
  requirementUpdate,
  targetParts,
  type MatchPart,
  type TargetPart,
} from "./requirements";

/**
 * Advanced: mechanisms that never grant. Network requirements narrow where
 * secrets may be read from; agent capabilities are short-lived receipts a
 * broker issues for one run, shown here for oversight and revocation.
 */
export function AdvancedTab({ org }: { org: string }) {
  return (
    <div className="space-y-6">
      <Callout tone="info" icon={<Filter size={17} />}>
        Nothing here grants access. These rules only narrow or observe it: grants stay the single source of
        permission.
      </Callout>
      <RequirementsSection org={org} />
      <CapabilitiesSection org={org} />
    </div>
  );
}

function RequirementsSection({ org }: { org: string }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const toast = useToast();
  const { names } = useAccessNames(org);
  const reqs = useQuery({ queryKey: ["requirements", org], queryFn: () => api.listRequirements(org) });
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);
  const invalidate = () => void qc.invalidateQueries({ queryKey: ["requirements", org] });
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteRequirement(org, id),
    onSuccess: invalidate,
    onError: (err) => toast.error("Could not remove the requirement", { description: errorMessage(err) }),
  });
  const items = reqs.data?.items ?? [];
  return (
    <SectionCard
      title="Network requirements"
      description="Secrets a requirement covers can only be read from verified devices on your tailnet. A device passes a requirement by matching any one of its devices, tags or users. When several requirements cover the same secret, every one must pass. Restrictive only: a requirement can take access away, never add it."
      data-testid="requirements-section"
      actions={
        !adding && (
          <Button size="sm" variant="secondary" icon={<Plus size={13} />} data-testid="add-requirement" onClick={() => setAdding(true)}>
            Add requirement
          </Button>
        )
      }
    >
      {items.length === 0 && !adding && (
        <EmptyState
          icon={<Wifi size={20} />}
          title="No network requirements"
          description="Secret retrieval is governed by grants alone. Add one to require, for example, that production secrets are only read from devices tagged tag:prod."
          className="py-8"
        />
      )}
      <ul>
        {items.map((req) => {
          const blocker = formEditBlocker(req);
          return editing === req.id && !blocker ? (
            <li key={req.id} data-requirement={req.id} className="border-b border-bd px-5 py-4 last:border-b-0">
              <RequirementForm
                org={org}
                initial={req}
                onDone={() => {
                  setEditing(null);
                  invalidate();
                }}
                onCancel={() => setEditing(null)}
              />
            </li>
          ) : (
            <li
              key={req.id}
              data-requirement={req.id}
              title={requirementSentence(req, names)}
              className="group border-b border-bd px-5 py-3.5 text-[14px] last:border-b-0"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-muted">Secrets in</span>
                {targetParts(req.target, names).map((part) => (
                  <TargetChip key={part.kind === "tier" ? part.tier : part.id} part={part} />
                ))}
                <span className="text-muted">can only be read on</span>
                <Chip mono>{req.selector.tailnet}</Chip>
                <span className="flex-1" />
                {blocker ? (
                  <span className="inline-flex items-center gap-1.5">
                    <Button size="sm" variant="ghost" disabled data-testid={`edit-requirement-${req.id}`} data-edit-blocked="">
                      Edit
                    </Button>
                    <InfoTip text={blocker} />
                  </span>
                ) : (
                  <Button size="sm" variant="ghost" data-testid={`edit-requirement-${req.id}`} onClick={() => setEditing(req.id)}>
                    Edit
                  </Button>
                )}
                <Menu
                  label="Requirement actions"
                  items={[
                    {
                      label: "Remove…",
                      danger: true,
                      "data-testid": `delete-requirement-${req.id}`,
                      onSelect: async () => {
                        const ok = await confirm({
                          title: "Remove this requirement?",
                          description:
                            "This loosens access: the secrets it covers can then be read from anywhere a grant allows, unless another requirement still covers them. The change is audited.",
                          confirmLabel: "Remove requirement",
                          tone: "danger",
                        });
                        if (ok) remove.mutate(req.id);
                      },
                    },
                  ]}
                >
                  <MoreHorizontal size={16} />
                </Menu>
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-2" data-testid={`requirement-matches-${req.id}`}>
                <span className="text-muted">by a device that matches any of</span>
                {matchParts(req.selector).map((m) => (
                  <Chip key={`${m.kind}:${m.value}`} mono data-match={m.kind}>
                    <MatchIcon kind={m.kind} />
                    {m.value}
                  </Chip>
                ))}
              </div>
            </li>
          );
        })}
      </ul>
      {adding && (
        <div className="border-t border-bd px-5 py-4">
          <RequirementForm
            org={org}
            onDone={() => {
              setAdding(false);
              invalidate();
            }}
            onCancel={() => setAdding(false)}
          />
        </div>
      )}
    </SectionCard>
  );
}

function Chip({ children, mono, ...props }: React.ComponentProps<"span"> & { mono?: boolean }) {
  return (
    <span
      className={cn("inline-flex items-center gap-1.5 rounded-md border border-bd bg-inset px-2 py-0.5 text-[13px]", mono && "font-mono text-[12.5px]")}
      {...props}
    >
      {children}
    </span>
  );
}

function TargetChip({ part }: { part: TargetPart }) {
  if (part.kind === "tier") {
    return (
      <Chip>
        <TierDot tier={part.tier} />
        {part.tier}
      </Chip>
    );
  }
  if (!part.name) {
    // Not visible to this viewer or deleted: the ID is all there is.
    return (
      <Chip mono data-target-environment={part.id}>
        {part.id}
      </Chip>
    );
  }
  return (
    <>
      <Chip mono data-target-environment={part.id}>
        {part.tier && <TierDot tier={part.tier} />}
        {part.project ? `${part.project} / ${part.name}` : part.name}
      </Chip>
      {part.includesDerived && <span className="text-[13px] text-muted">and environments derived from it</span>}
    </>
  );
}

function MatchIcon({ kind }: { kind: MatchPart["kind"] }) {
  const Icon = kind === "device" ? Monitor : kind === "tag" ? Tag : User;
  return <Icon size={12} aria-label={kind} className="text-muted" />;
}

function RequirementForm({
  org,
  initial,
  onDone,
  onCancel,
}: {
  org: string;
  initial?: Requirement;
  onDone: () => void;
  onCancel: () => void;
}) {
  const { api } = useSession();
  const [tier, setTier] = useState<Tier>(initial?.target.kind === "tier" ? initial.target.tier : "production");
  const [tailnet, setTailnet] = useState(initial?.selector.tailnet ?? "");
  const [tags, setTags] = useState((initial?.selector.tags ?? []).join(","));
  const tagList = parseTags(tags);
  const save = useMutation({
    mutationFn: async () => {
      const form = { tier, tailnet, tags: tagList };
      // requirementUpdate refuses requirements this form cannot represent.
      if (initial) await api.updateRequirement(org, initial.id, requirementUpdate(initial, form));
      else await api.createTailnetRequirement(org, requirementCreate(form));
    },
    onSuccess: onDone,
  });
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        if (tailnet.trim() && tagList.length > 0) save.mutate();
      }}
    >
      <div className="grid gap-3 sm:grid-cols-[180px_1fr_1fr]">
        <Field label="Tier">
          <Select
            className="w-full"
            value={tier}
            onChange={(v) => setTier(v as Tier)}
            aria-label="Tier"
            options={TIERS.map((t) => ({ value: t, label: t, icon: <TierDot tier={t} /> }))}
          />
        </Field>
        <Field label="Tailnet">
          <Input data-testid="req-tailnet" mono className="w-full" placeholder="example.ts.net" value={tailnet} onChange={(e) => setTailnet(e.target.value)} />
        </Field>
        <Field label="Device tags" hint="Comma-separated, e.g. tag:prod,tag:deploy">
          <Input data-testid="req-tags" mono className="w-full" placeholder="tag:prod" value={tags} onChange={(e) => setTags(e.target.value)} />
        </Field>
      </div>
      {initial && <p className="text-xs text-muted">Edited in place. Loosening is audited exactly like tightening.</p>}
      {save.error && <p className="text-sm text-deny">{errorMessage(save.error)}</p>}
      <div className="flex justify-end gap-2">
        <Button size="sm" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button
          size="sm"
          variant="primary"
          type="submit"
          data-testid={initial ? `save-requirement-${initial.id}` : "create-requirement"}
          loading={save.isPending}
          disabled={!tailnet.trim() || tagList.length === 0}
        >
          {initial ? "Save" : "Add requirement"}
        </Button>
      </div>
    </form>
  );
}

function CapabilitiesSection({ org }: { org: string }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const identities = useIdentities(org);
  const now = useNow(1000);
  const projects = useQuery({ queryKey: ["projects", org], queryFn: () => api.listProjects(org) });
  const [projectSlug, setProjectSlug] = useState("");
  const envs = useQuery({
    queryKey: ["environments", org, projectSlug],
    queryFn: () => api.listEnvironments(org, projectSlug),
    enabled: projectSlug !== "",
  });
  const [envName, setEnvName] = useState("");
  const key = ["capabilities", org, projectSlug, envName];
  const capabilities = useQuery({
    queryKey: key,
    queryFn: () => api.listCapabilities(org, projectSlug, envName),
    enabled: projectSlug !== "" && envName !== "",
    refetchInterval: 15_000,
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.revokeCapability(org, projectSlug, envName, id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: key }),
  });
  const nameOf = (id: string) => identities.data?.items.find((i) => i.id === id)?.name ?? id;
  const items = capabilities.data?.items ?? [];
  const active = items.filter((c) => !c.revokedAt && new Date(c.expiresAt).getTime() > now);
  return (
    <SectionCard
      title={
        <span className="inline-flex items-center gap-2.5">
          Agent capabilities
          {envName && (
            <span className="inline-flex items-center gap-1.5 text-[13px] font-normal text-accent">
              <StatusDot tone="live" /> live
            </span>
          )}
        </span>
      }
      description="Short-lived receipts brokers issue so AI agents can use secrets without seeing them. The agent's own grant is re-checked on every use."
      data-testid="capabilities-section"
      actions={
        <div className="flex items-center gap-2">
          <Select
            data-testid="capability-project"
            className="min-w-36"
            value={projectSlug}
            onChange={(v) => {
              setProjectSlug(v);
              setEnvName("");
            }}
            placeholder="Project…"
            aria-label="Project"
            options={(projects.data?.items ?? []).map((p) => ({ value: p.slug, label: p.slug }))}
          />
          <Select
            data-testid="capability-environment"
            className="min-w-40"
            value={envName}
            onChange={setEnvName}
            disabled={projectSlug === ""}
            placeholder="Environment…"
            aria-label="Environment"
            options={(envs.data?.items ?? []).map((env) => ({ value: env.name, label: env.name, icon: <TierDot tier={env.tier as Tier} /> }))}
          />
        </div>
      }
    >
      {envName === "" ? (
        <EmptyState icon={<Sparkles size={20} />} title="Pick a project and environment" description="Capabilities exist only while a broker-mediated agent run is in flight." className="py-8" />
      ) : items.length === 0 ? (
        <p className="px-5 py-6 text-center text-[13px] text-muted" data-testid="capabilities-empty">
          No capabilities issued for this environment. That's the normal state: they appear only while a broker-mediated agent run is in flight.
        </p>
      ) : (
        <ul>
          {items.map((c) => {
            const revoked = Boolean(c.revokedAt);
            const expired = !revoked && new Date(c.expiresAt).getTime() <= now;
            const live = !revoked && !expired;
            return (
              <li
                key={c.id}
                data-capability={c.id}
                className={cn("flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-bd px-5 py-3 last:border-b-0", !live && "opacity-55")}
              >
                <span className="flex min-w-48 items-center gap-2.5">
                  <Sparkles size={16} className={live ? "text-info" : "text-muted"} />
                  <span>
                    <span className={cn("font-medium", revoked && "line-through")}>{nameOf(c.agentIdentityId)}</span>
                    <span className="block text-xs text-muted">
                      via {nameOf(c.brokerIdentityId)} · run <span className="font-mono">{c.runId ?? "none"}</span>
                    </span>
                  </span>
                </span>
                <span className="flex flex-wrap gap-1.5">
                  {c.items.map((i) => (
                    <Badge key={i} className="font-mono">
                      {i}
                    </Badge>
                  ))}
                </span>
                <span className="font-mono text-[12.5px] text-muted">→ {c.destinations.join(", ")}</span>
                <span className="flex-1" />
                {live ? (
                  <>
                    <span className="rounded-md border border-bd bg-inset px-2 py-0.5 font-mono text-xs tabular-nums text-fg" title={new Date(c.expiresAt).toLocaleString()}>
                      expires in {countdown(c.expiresAt, now)}
                    </span>
                    <Button
                      size="sm"
                      variant="danger"
                      data-testid={`revoke-capability-${c.id}`}
                      onClick={async () => {
                        const ok = await confirm({
                          title: "Revoke this capability?",
                          description: `${nameOf(c.agentIdentityId)} can no longer use ${c.items.join(", ")} in this run. Its very next use is denied.`,
                          confirmLabel: "Revoke capability",
                          tone: "danger",
                        });
                        if (ok) revoke.mutate(c.id);
                      }}
                    >
                      Revoke
                    </Button>
                  </>
                ) : (
                  <span className="text-xs text-muted">{revoked ? `revoked ${timeAgo(c.revokedAt, now)}` : "expired"}</span>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {envName !== "" && items.length > 0 && (
        <p className="border-t border-bd px-5 py-2.5 text-xs text-muted">
          {active.length} active · refreshes every 15 seconds
        </p>
      )}
    </SectionCard>
  );
}
