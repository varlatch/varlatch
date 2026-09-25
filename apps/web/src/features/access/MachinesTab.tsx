// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { MoreHorizontal } from "lucide-react";
import type { OidcBinding } from "@varlatch/protocol";
import type { IdentityCredential, OrgIdentity } from "@varlatch/sdk";
import { Button, Card, InfoTip, Input, Menu, Mono, Select, cn } from "../../components/ui";
import { useSession } from "../../lib/session";
import { useIdentities } from "./shared";

/**
 * Machines: non-human identities (services, workloads, CI, brokers, agents)
 * plus their OIDC federation bindings. Kinds that carry a static credential
 * show it exactly once at creation (ADR-0007); ci federates; agents receive
 * secret material only through broker-mediated use (ADR-0023).
 */
export function MachinesTab({ org }: { org: string }) {
  return (
    <div className="space-y-4">
      <p className="text-muted text-sm max-w-3xl">
        Machine identities are the non-human actors — CI jobs, servers, credential brokers, AI
        agents. Instead of a passkey they authenticate with a one-time-shown token, or with no
        stored secret at all via OIDC federation. Like people, they start with zero access until a
        Grant says otherwise.
        <InfoTip
          className="ml-1"
          text="Kinds: service/workload hold a token; broker mediates secret use for agents; ci has no token and federates via OIDC; agent has no token and receives secret material only through a broker."
        />
      </p>
      <MachinesSection org={org} />
      <OidcBindingsSection org={org} />
    </div>
  );
}

const KIND_LABELS: Record<Exclude<OrgIdentity["kind"], "human">, string> = {
  service: "long-lived token",
  workload: "long-lived token",
  ci: "federated, no token",
  broker: "credential mediator",
  agent: "secrets via broker only",
};

function KindBadge({ kind }: { kind: OrgIdentity["kind"] }) {
  if (kind === "human") return null;
  return (
    <span
      title={KIND_LABELS[kind]}
      className="inline-flex items-center rounded-full border border-bd px-2 py-0.5 text-xs text-muted"
    >
      {kind}
    </span>
  );
}

/**
 * Friendly relative rendering of ADR-0034's ~60s-granularity last-seen
 * signal; "never" when the identity has not authenticated since the
 * lifecycle migration.
 */
function timeAgo(iso: string | null | undefined): string {
  if (!iso) return "never";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 90) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 60) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}

function MachinesSection({ org }: { org: string }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const identities = useIdentities(org);
  const meta = useQuery({ queryKey: ["meta"], queryFn: () => api.meta() });
  // ADR-0034 §7: feature-detect via capability rather than probing routes.
  const lifecycle = (meta.data?.capabilities ?? []).includes("identity.lifecycle");
  const [showRetired, setShowRetired] = useState(false);
  const allMachines = identities.data?.items.filter((i) => i.kind !== "human") ?? [];
  const retiredCount = allMachines.filter((i) => i.disabled).length;
  const machines = showRetired ? allMachines : allMachines.filter((i) => !i.disabled);
  const [credsFor, setCredsFor] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<"service" | "workload" | "ci" | "broker" | "agent">("service");
  const [ttlSeconds, setTtlSeconds] = useState("");
  const [maxUses, setMaxUses] = useState("");
  const [oneTime, setOneTime] = useState<{
    name: string;
    credential: string;
    expiresAt: string | null;
    maxUses: number | null;
  } | null>(null);
  // Only these kinds receive a static credential at creation; ci federates,
  // agents get material solely through broker-mediated exercises.
  const issuesCredential = kind === "service" || kind === "workload" || kind === "broker";
  const ttlValid = ttlSeconds === "" || /^[1-9][0-9]*$/.test(ttlSeconds);
  const maxUsesValid = maxUses === "" || /^[1-9][0-9]*$/.test(maxUses);
  const create = useMutation({
    mutationFn: () =>
      api.createIdentity(org, {
        name,
        kind,
        ...(issuesCredential && ttlSeconds !== "" ? { credentialTtlSeconds: Number(ttlSeconds) } : {}),
        ...(issuesCredential && maxUses !== "" ? { credentialMaxUses: Number(maxUses) } : {}),
      }),
    onSuccess: (r) => {
      if (r.credential) {
        setOneTime({
          name: r.name,
          credential: r.credential,
          expiresAt: r.credentialExpiresAt ?? null,
          maxUses: issuesCredential && maxUses !== "" ? Number(maxUses) : null,
        });
      }
      setName("");
      setTtlSeconds("");
      setMaxUses("");
      void qc.invalidateQueries({ queryKey: ["identities", org] });
    },
  });
  const invalidate = () => void qc.invalidateQueries({ queryKey: ["identities", org] });
  const onLifecycleError = (err: unknown) =>
    window.alert(err instanceof Error ? err.message : String(err));
  const rename = useMutation({
    mutationFn: ({ id, next }: { id: string; next: string }) => api.renameIdentity(org, id, next),
    onSuccess: invalidate,
    onError: onLifecycleError,
  });
  const retire = useMutation({
    mutationFn: (id: string) => api.retireIdentity(org, id),
    onSuccess: invalidate,
    onError: onLifecycleError,
  });
  const reactivate = useMutation({
    mutationFn: (id: string) => api.reactivateIdentity(org, id),
    onSuccess: invalidate,
    onError: onLifecycleError,
  });
  const promptRename = (i: OrgIdentity) => {
    const next = window.prompt(`Rename ${i.name} to:`, i.name)?.trim();
    if (!next || next === i.name) return;
    rename.mutate({ id: i.id, next });
  };
  const confirmRetire = (i: OrgIdentity) => {
    // ADR-0034 §3/§7: retiring disables the identity AND revokes every
    // credential — irreversible for the credentials, so re-type the name
    // (same guard as production env deletion, ADR-0025).
    const typed = window.prompt(
      `Retiring ${i.name} disables it and revokes ALL of its credentials. Reactivation will not restore them. Type the identity name to retire it:`,
    );
    if (typed !== i.name) return;
    retire.mutate(i.id);
  };

  return (
    <Card data-testid="machines-section">
      <div className="flex items-center justify-between mb-3">
        <h2 className="font-medium flex items-center gap-1.5">
          Machines
          <InfoTip text="Non-human identities (CI jobs, servers, agents) that authenticate with a token or OIDC federation instead of a passkey. Like people, they can only do what Grants allow." />
        </h2>
        <div className="flex gap-2 items-center">
          <Input
            data-testid="machine-name"
            placeholder="ci-deployer"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <Select
            value={kind}
            onChange={(v) => setKind(v as typeof kind)}
            aria-label="Machine identity kind"
            options={[
              { value: "service", label: "service" },
              { value: "workload", label: "workload" },
              { value: "ci", label: "ci (federated, no token)" },
              { value: "broker", label: "broker (credential mediator)" },
              { value: "agent", label: "agent (no token; secrets via broker)" },
            ]}
          />
          {issuesCredential && (
            <>
              <Input
                data-testid="machine-ttl"
                className={cn("w-24", !ttlValid && "border-deny")}
                placeholder="TTL (s)"
                title="Optional credential lifetime in seconds; empty means no expiry (revocation only)"
                value={ttlSeconds}
                onChange={(e) => setTtlSeconds(e.target.value.trim())}
              />
              <Input
                data-testid="machine-max-uses"
                className={cn("w-24", !maxUsesValid && "border-deny")}
                placeholder="max uses"
                title="Optional use budget; each authenticated request spends one use. 1 yields a one-shot token; empty means unlimited"
                value={maxUses}
                onChange={(e) => setMaxUses(e.target.value.trim())}
              />
            </>
          )}
          <Button
            data-testid="create-machine"
            disabled={!name || !ttlValid || !maxUsesValid || create.isPending}
            onClick={() => create.mutate()}
          >
            Create identity
          </Button>
        </div>
      </div>
      {create.error && <p className="text-deny text-sm mb-2">{String(create.error)}</p>}
      {oneTime && (
        <div
          data-testid="one-time-credential"
          className="mb-3 rounded-md border border-tier-production/50 bg-inset p-3 text-sm"
        >
          <p className="mb-1 font-medium">
            Credential for {oneTime.name} — shown once, never retrievable again.
          </p>
          <Mono className="break-all" data-testid="one-time-credential-token">
            {oneTime.credential}
          </Mono>
          {(oneTime.expiresAt || oneTime.maxUses) && (
            <p className="mt-1 text-muted" data-testid="one-time-credential-limits">
              {oneTime.expiresAt && <>Expires {new Date(oneTime.expiresAt).toLocaleString()}. </>}
              {oneTime.maxUses && (
                <>Use budget: {oneTime.maxUses} request{oneTime.maxUses === 1 ? "" : "s"}.</>
              )}
            </p>
          )}
          <div className="mt-2">
            <Button data-testid="dismiss-credential" variant="ghost" onClick={() => setOneTime(null)}>
              I stored it — dismiss
            </Button>
          </div>
        </div>
      )}
      <div className="flex items-center justify-between mb-2">
        <p className="text-muted text-sm">
          New identities start with zero access; add a Grant (Grants tab) before they can read
          anything.
        </p>
        {retiredCount > 0 && (
          <label className="flex items-center gap-1.5 text-sm text-muted whitespace-nowrap">
            <input
              data-testid="show-retired"
              type="checkbox"
              checked={showRetired}
              onChange={(e) => setShowRetired(e.target.checked)}
            />
            Show retired ({retiredCount})
          </label>
        )}
      </div>
      {allMachines.length === 0 ? (
        <p className="text-muted text-sm">
          No machine identities yet. Create one above — a service or workload gets a token shown
          exactly once; ci and agent kinds never hold a stored secret.
        </p>
      ) : machines.length === 0 ? (
        <p className="text-muted text-sm">
          All machine identities here are retired; use “Show retired” to see them.
        </p>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-muted">
              <th className="font-normal py-1">Name</th>
              <th className="font-normal">Kind</th>
              <th className="font-normal">Last seen</th>
              <th className="font-normal text-right">Identity</th>
              {lifecycle && <th className="w-8" aria-label="Actions" />}
            </tr>
          </thead>
          <tbody>
            {machines.map((i) => (
              <MachineRow
                key={i.id}
                identity={i}
                lifecycle={lifecycle}
                credsOpen={credsFor === i.id}
                onToggleCreds={() => setCredsFor((cur) => (cur === i.id ? null : i.id))}
                onRename={() => promptRename(i)}
                onRetire={() => confirmRetire(i)}
                onReactivate={() => reactivate.mutate(i.id)}
                org={org}
              />
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

function MachineRow({
  org,
  identity: i,
  lifecycle,
  credsOpen,
  onToggleCreds,
  onRename,
  onRetire,
  onReactivate,
}: {
  org: string;
  identity: OrgIdentity;
  lifecycle: boolean;
  credsOpen: boolean;
  onToggleCreds: () => void;
  onRename: () => void;
  onRetire: () => void;
  onReactivate: () => void;
}) {
  return (
    <>
      <tr key={i.id} data-identity={i.name} className="border-t border-bd">
        <td className="py-1.5">
          {i.name}
          {i.disabled && (
            <span
              title="Retired: authentication rejected, all credentials revoked (ADR-0034)"
              className="ml-2 inline-flex items-center rounded-full border border-deny/50 px-2 py-0.5 text-xs text-deny"
            >
              retired
            </span>
          )}
        </td>
        <td className="text-muted">
          <KindBadge kind={i.kind} />
        </td>
        <td
          className="text-muted"
          title={i.lastSeenAt ? new Date(i.lastSeenAt).toLocaleString() : "Never authenticated"}
        >
          {timeAgo(i.lastSeenAt)}
        </td>
        <td className="text-right">
          <Mono className="text-muted">{i.id}</Mono>
        </td>
        {lifecycle && (
          <td className="text-right pl-2">
            <Menu
              data-testid={`machine-menu-${i.id}`}
              label={`Actions for ${i.name}`}
              items={[
                {
                  label: credsOpen ? "Hide credentials" : "View credentials",
                  "data-testid": `machine-credentials-${i.id}`,
                  onSelect: onToggleCreds,
                },
                {
                  label: "Rename",
                  "data-testid": `machine-rename-${i.id}`,
                  onSelect: onRename,
                },
                i.disabled
                  ? {
                      label: "Reactivate",
                      "data-testid": `machine-reactivate-${i.id}`,
                      onSelect: onReactivate,
                    }
                  : {
                      label: "Retire",
                      danger: true,
                      "data-testid": `machine-retire-${i.id}`,
                      onSelect: onRetire,
                    },
              ]}
            >
              <MoreHorizontal size={16} />
            </Menu>
          </td>
        )}
      </tr>
      {lifecycle && credsOpen && (
        <tr className="border-t border-bd">
          <td colSpan={5} className="py-2">
            <CredentialsPanel org={org} identity={i} />
          </td>
        </tr>
      )}
    </>
  );
}

/**
 * Credential metadata for one machine identity (ADR-0034 §2): never token
 * material; revoke offered only for unrevoked service/oidc kinds — agent-run
 * stays Broker-only, cli/browser belong to humans.
 */
function CredentialsPanel({ org, identity }: { org: string; identity: OrgIdentity }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const creds = useQuery({
    queryKey: ["identity-credentials", org, identity.id],
    queryFn: () => api.listIdentityCredentials(org, identity.id),
  });
  const revoke = useMutation({
    mutationFn: (credentialId: string) => api.revokeIdentityCredential(org, identity.id, credentialId),
    onSuccess: () =>
      void qc.invalidateQueries({ queryKey: ["identity-credentials", org, identity.id] }),
  });
  const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "—");
  if (creds.isLoading) return <p className="text-muted text-sm">Loading credentials…</p>;
  if (creds.error) return <p className="text-deny text-sm">{String(creds.error)}</p>;
  const items = creds.data?.items ?? [];
  if (items.length === 0)
    return <p className="text-muted text-sm">No credentials for {identity.name}.</p>;
  return (
    <div data-testid={`credentials-panel-${identity.id}`} className="rounded-md bg-inset p-2">
      {revoke.error && <p className="text-deny text-sm mb-1">{String(revoke.error)}</p>}
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs text-muted">
            <th className="font-normal py-1">Kind</th>
            <th className="font-normal">Name</th>
            <th className="font-normal">Created</th>
            <th className="font-normal">Expires</th>
            <th className="font-normal">Last used</th>
            <th className="font-normal text-right">Status</th>
          </tr>
        </thead>
        <tbody>
          {items.map((c: IdentityCredential) => (
            <tr key={c.id} data-credential={c.id} className="border-t border-bd">
              <td className="py-1.5 text-muted">{c.kind}</td>
              <td>{c.name ?? <span className="text-muted">—</span>}</td>
              <td className="text-muted">{fmt(c.createdAt)}</td>
              <td className="text-muted">{fmt(c.expiresAt)}</td>
              <td className="text-muted" title={c.lastUsedAt ?? "Never used"}>
                {timeAgo(c.lastUsedAt)}
              </td>
              <td className="text-right">
                {c.revokedAt ? (
                  <span className="text-deny" title={`Revoked ${fmt(c.revokedAt)}`}>
                    revoked
                  </span>
                ) : c.kind === "service" || c.kind === "oidc" ? (
                  <Button
                    data-testid={`revoke-credential-${c.id}`}
                    variant="danger"
                    disabled={revoke.isPending}
                    onClick={() => revoke.mutate(c.id)}
                  >
                    Revoke
                  </Button>
                ) : (
                  <span className="text-muted" title="Not revocable here: agent-run credentials are Broker-managed; cli/browser sessions live under the owner's Credentials page.">
                    active
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function OidcBindingsSection({ org }: { org: string }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const identities = useIdentities(org);
  const machines = identities.data?.items.filter((i) => i.kind !== "human") ?? [];
  const [identityId, setIdentityId] = useState("");
  const [issuer, setIssuer] = useState("");
  const [audience, setAudience] = useState("");
  const [subject, setSubject] = useState("");

  const bindings = useQuery({
    queryKey: ["oidc-bindings", org, identityId],
    queryFn: () => api.listOidcBindings(org, identityId),
    enabled: identityId !== "",
  });
  const create = useMutation({
    mutationFn: () => api.createOidcBinding(org, identityId, { issuer, audience, subject }),
    onSuccess: () => {
      setIssuer("");
      setAudience("");
      setSubject("");
      void qc.invalidateQueries({ queryKey: ["oidc-bindings", org, identityId] });
    },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.revokeOidcBinding(org, identityId, id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["oidc-bindings", org, identityId] }),
  });

  return (
    <Card data-testid="oidc-section">
      <h2 className="font-medium mb-1 flex items-center gap-1.5">
        OIDC federation
        <InfoTip text="An OIDC binding lets a workload prove who it is with its platform's identity token (e.g. a GitHub Actions run) instead of a stored secret. It establishes identity only — access still comes from Grants." />
      </h2>
      <p className="text-muted text-sm mb-3">
        Bind an external OIDC issuer, audience, and subject to a machine identity; the workload
        then exchanges its platform token for a short-lived credential — no stored secret at all.
        A binding establishes identity only; access still comes from Grants. Subjects match
        exactly, or by prefix when they end with <Mono>*</Mono> (e.g.{" "}
        <Mono>repo:acme/api:*</Mono> for GitHub Actions).
      </p>
      <div className="flex flex-wrap gap-2 items-center mb-2">
        <Select
          data-testid="oidc-identity"
          value={identityId}
          onChange={(v) => setIdentityId(v)}
          aria-label="Machine identity to bind"
          options={[
            { value: "", label: "Choose machine identity…" },
            ...machines.map((i) => ({ value: i.id, label: `${i.name} (${i.kind})` })),
          ]}
        />
        <Input
          data-testid="oidc-issuer"
          placeholder="https://token.actions.githubusercontent.com"
          value={issuer}
          onChange={(e) => setIssuer(e.target.value)}
        />
        <Input
          data-testid="oidc-audience"
          placeholder="Audience"
          value={audience}
          onChange={(e) => setAudience(e.target.value)}
        />
        <Input
          data-testid="oidc-subject"
          placeholder="repo:acme/api:*"
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
        />
        <Button
          data-testid="create-oidc-binding"
          disabled={!identityId || !issuer || !audience || !subject || create.isPending}
          onClick={() => create.mutate()}
        >
          Bind
        </Button>
      </div>
      {create.error && <p className="text-deny text-sm mb-2">{String(create.error)}</p>}
      {revoke.error && <p className="text-deny text-sm mb-2">{String(revoke.error)}</p>}
      {identityId === "" ? (
        <p className="text-muted text-sm">Choose an identity to see its bindings.</p>
      ) : (bindings.data?.items.length ?? 0) === 0 ? (
        <p className="text-muted text-sm">No bindings yet.</p>
      ) : (
        <table className="w-full text-sm">
          <tbody>
            {bindings.data?.items.map((b: OidcBinding) => (
              <tr key={b.id} data-oidc-binding={b.subject} className="border-t border-bd">
                <td className="py-1.5">
                  <Mono className="break-all">{b.issuer}</Mono>
                </td>
                <td className="text-muted">
                  <Mono>{b.audience}</Mono>
                </td>
                <td>
                  <Mono className="break-all">{b.subject}</Mono>
                </td>
                <td className="text-right">
                  <Button
                    data-testid={`revoke-oidc-${b.id}`}
                    variant="danger"
                    onClick={() => revoke.mutate(b.id)}
                  >
                    Revoke
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}
