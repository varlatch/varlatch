// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { Tier } from "@varlatch/protocol";
import { Button, Card, InfoTip, Input, Mono, Select, TierChip, cn } from "../../components/ui";
import { useSession } from "../../lib/session";
import { TIERS, useIdentities } from "./shared";

/**
 * Advanced: mechanisms that never grant. Broker capabilities (ADR-0022) are
 * run-scoped oversight artifacts; tailnet requirements (ADR-0014) narrow
 * where secret retrieval may happen.
 */
export function AdvancedTab({ org }: { org: string }) {
  return (
    <div className="space-y-4">
      <p className="text-muted text-sm max-w-3xl">
        Neither mechanism here ever adds access. <b>Broker capabilities</b>
        <InfoTip className="mx-1" text="Short-lived receipts a broker issues so an AI agent can use specific secrets for one run, toward specific destinations, without ever seeing plaintext. The agent's own grant is re-checked on every exercise." />
        are short-lived, run-scoped artifacts you can observe and revoke, and{" "}
        <b>tailnet requirements</b>
        <InfoTip className="mx-1" text="A requirement is restrictive-only: it demands that secret retrieval for a tier come from a verified device on your tailnet (matching tags). It sits on top of Grants and can only take access away." />
        restrict where secret retrieval may happen. Grants stay the only source of permission.
      </p>
      <CapabilitiesSection org={org} />
      <RequirementsSection org={org} />
    </div>
  );
}

/**
 * Broker Capabilities (ADR-0022): read-only oversight plus revocation. These
 * are ephemeral run-scoped artifacts issued by Brokers; nothing here grants —
 * revoking one denies its very next exercise.
 */
function CapabilitiesSection({ org }: { org: string }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const identities = useIdentities(org);
  const projects = useQuery({ queryKey: ["projects", org], queryFn: () => api.listProjects(org) });
  const [projectSlug, setProjectSlug] = useState("");
  const envs = useQuery({
    queryKey: ["environments", org, projectSlug],
    queryFn: () => api.listEnvironments(org, projectSlug),
    enabled: projectSlug !== "",
  });
  const [envName, setEnvName] = useState("");
  const capabilities = useQuery({
    queryKey: ["capabilities", org, projectSlug, envName],
    queryFn: () => api.listCapabilities(org, projectSlug, envName),
    enabled: projectSlug !== "" && envName !== "",
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.revokeCapability(org, projectSlug, envName, id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["capabilities", org, projectSlug, envName] }),
  });
  const nameOf = (id: string) => identities.data?.items.find((i) => i.id === id)?.name ?? id;
  const statusOf = (c: { revokedAt: string | null; expiresAt: string }) =>
    c.revokedAt ? "revoked" : new Date(c.expiresAt).getTime() <= Date.now() ? "expired" : "active";

  return (
    <Card data-testid="capabilities-section">
      <h2 className="font-medium mb-1 flex items-center gap-1.5">
        Broker capabilities
        <InfoTip text="Issued by broker identities at run time, never from this page. This view is oversight: see what agents may currently exercise, and revoke anything suspicious — the revocation denies the very next exercise." />
      </h2>
      <p className="text-muted text-sm mb-3">
        Run-scoped artifacts brokers issue for agent-safe runs. A capability never grants — the
        agent's <Mono>secret.use</Mono> is re-checked on every exercise. Revoking one takes effect
        on its next exercise.
      </p>
      <div className="flex flex-wrap gap-2 items-center mb-3">
        <Select
          data-testid="capability-project"
          value={projectSlug}
          onChange={(v) => {
            setProjectSlug(v);
            setEnvName("");
          }}
          options={[
            { value: "", label: "Choose project…" },
            ...(projects.data?.items.map((p) => ({ value: p.slug, label: p.slug })) ?? []),
          ]}
        />
        {projectSlug !== "" && (
          <Select
            data-testid="capability-environment"
            value={envName}
            onChange={(v) => setEnvName(v)}
            options={[
              { value: "", label: "Choose environment…" },
              ...(envs.data?.items.map((env) => ({
                value: env.name,
                label: `${env.name} (${env.tier})`,
              })) ?? []),
            ]}
          />
        )}
      </div>
      {envName === "" && <p className="text-muted text-sm">Pick a project and environment to inspect.</p>}
      {envName !== "" && capabilities.data?.items.length === 0 && (
        <p className="text-muted text-sm" data-testid="capabilities-empty">
          No capabilities issued for this environment. That's the normal state — they appear only
          while a broker-mediated agent run is in flight.
        </p>
      )}
      {(capabilities.data?.items ?? []).length > 0 && (
        <table className="w-full text-sm">
          <tbody>
            {capabilities.data!.items.map((c) => {
              const status = statusOf(c);
              return (
                <tr key={c.id} data-capability={c.id} className="border-t border-bd align-top">
                  <td className="py-1.5 whitespace-nowrap">
                    {nameOf(c.agentIdentityId)}
                    <span className="text-muted"> via {nameOf(c.brokerIdentityId)}</span>
                  </td>
                  <td className="text-muted px-2">
                    <Mono className="text-xs">{c.items.join(", ")}</Mono>
                    <span className="mx-1">→</span>
                    <Mono className="text-xs">{c.destinations.join(", ")}</Mono>
                  </td>
                  <td className="text-muted whitespace-nowrap px-2">
                    {c.runId ?? "—"} · expires {new Date(c.expiresAt).toLocaleTimeString()}
                  </td>
                  <td className="text-right whitespace-nowrap">
                    {status === "active" ? (
                      <Button
                        variant="danger"
                        data-testid={`revoke-capability-${c.id}`}
                        onClick={() => revoke.mutate(c.id)}
                      >
                        Revoke
                      </Button>
                    ) : (
                      <span className={cn("text-xs", status === "revoked" ? "text-deny" : "text-muted")}>
                        {status}
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {revoke.error && <p className="text-deny text-sm mt-2">{String(revoke.error)}</p>}
    </Card>
  );
}

function RequirementsSection({ org }: { org: string }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const reqs = useQuery({ queryKey: ["requirements", org], queryFn: () => api.listRequirements(org) });
  const [tier, setTier] = useState<Tier>("production");
  const [tailnet, setTailnet] = useState("");
  const [tags, setTags] = useState("");
  const create = useMutation({
    mutationFn: () =>
      api.createTailnetRequirement(org, {
        target: { kind: "tier", tier },
        selector: { tailnet, tags: tags.split(",").map((t) => t.trim()).filter(Boolean) },
      }),
    onSuccess: () => {
      setTailnet("");
      setTags("");
      void qc.invalidateQueries({ queryKey: ["requirements", org] });
    },
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteRequirement(org, id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["requirements", org] }),
  });
  // In-place edit (ADR-0029): tier and selector are editable; loosening is
  // exactly as audited as tightening.
  const [editing, setEditing] = useState<string | null>(null);
  const [editTier, setEditTier] = useState<Tier>("production");
  const [editTailnet, setEditTailnet] = useState("");
  const [editTags, setEditTags] = useState("");
  const update = useMutation({
    mutationFn: (req: { id: string; version: number }) =>
      api.updateRequirement(org, req.id, {
        expectedVersion: req.version,
        target: { kind: "tier", tier: editTier },
        selector: { tailnet: editTailnet, tags: editTags.split(",").map((t) => t.trim()).filter(Boolean) },
      }),
    onSuccess: () => {
      setEditing(null);
      void qc.invalidateQueries({ queryKey: ["requirements", org] });
    },
  });

  return (
    <Card data-testid="requirements-section">
      <h2 className="font-medium mb-1 flex items-center gap-1.5">
        Tailnet requirements
        <InfoTip text="Requirements narrow where a request may come from — e.g. production secrets only from a device on your tailnet carrying certain tags. They never add access on top of Grants." />
      </h2>
      <p className="text-muted text-sm mb-3">
        Restrictive, never permissive: a requirement narrows where secret retrieval may happen (a
        verified tailnet peer), on top of Grants — it can only take access away.
      </p>
      <div className="flex flex-wrap gap-2 items-center mb-2">
        <span className="text-sm text-muted">Require tailnet for tier</span>
        <Select
          value={tier}
          onChange={(v) => setTier(v as Tier)}
          aria-label="Tier the requirement applies to"
          options={TIERS.map((t) => ({ value: t, label: t }))}
        />
        <Input
          data-testid="req-tailnet"
          placeholder="example.ts.net"
          value={tailnet}
          onChange={(e) => setTailnet(e.target.value)}
        />
        <Input
          data-testid="req-tags"
          placeholder="tag:prod,tag:deploy"
          value={tags}
          onChange={(e) => setTags(e.target.value)}
        />
        <Button
          data-testid="create-requirement"
          disabled={!tailnet || !tags.trim() || create.isPending}
          onClick={() => create.mutate()}
        >
          Add requirement
        </Button>
      </div>
      {create.error && <p className="text-deny text-sm mb-2">{String(create.error)}</p>}
      {reqs.data?.items.length === 0 && <p className="text-muted text-sm">None — retrieval is governed by Grants alone.</p>}
      {(reqs.data?.items ?? []).map((r) => {
        const req = r as {
          id: string;
          version: number;
          target: { kind: string; tier?: Tier };
          selector: { tailnet: string; tags?: string[] };
        };
        return (
          <div key={req.id} data-requirement={req.id} className="border-t border-bd py-1.5 text-sm">
            <div className="flex items-center gap-2">
              {req.target.tier ? <TierChip tier={req.target.tier} /> : <span>{req.target.kind}</span>}
              <Mono>{req.selector.tailnet}</Mono>
              <span className="text-muted">{(req.selector.tags ?? []).join(", ")}</span>
              <span className="flex-1" />
              <Button
                variant="ghost"
                data-testid={`edit-requirement-${req.id}`}
                onClick={() => {
                  setEditing(editing === req.id ? null : req.id);
                  setEditTier(req.target.tier ?? "production");
                  setEditTailnet(req.selector.tailnet);
                  setEditTags((req.selector.tags ?? []).join(","));
                }}
              >
                {editing === req.id ? "Cancel" : "Edit"}
              </Button>
              <Button variant="danger" onClick={() => remove.mutate(req.id)}>
                Remove
              </Button>
            </div>
            {editing === req.id && (
              <div className="mt-2 flex flex-wrap gap-2 items-center">
                <Select
                  value={editTier}
                  onChange={(v) => setEditTier(v as Tier)}
                  aria-label="Edited tier"
                  options={TIERS.map((t) => ({ value: t, label: t }))}
                />
                <Input value={editTailnet} onChange={(e) => setEditTailnet(e.target.value)} />
                <Input value={editTags} onChange={(e) => setEditTags(e.target.value)} />
                <Button
                  data-testid={`save-requirement-${req.id}`}
                  disabled={!editTailnet || !editTags.trim() || update.isPending}
                  onClick={() => update.mutate({ id: req.id, version: req.version })}
                >
                  Save
                </Button>
                {update.error && <p className="text-deny text-sm">{String(update.error)}</p>}
              </div>
            )}
          </div>
        );
      })}
    </Card>
  );
}
