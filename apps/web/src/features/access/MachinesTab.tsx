// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ChevronRight,
  Clock,
  Eye,
  EyeOff,
  Gauge,
  MoreHorizontal,
  Plus,
  ShieldCheck,
  ShieldOff,
  TriangleAlert,
} from "lucide-react";
import type { IssuedMachineCredential, OidcBinding } from "@varlatch/protocol";
import type { IdentityCredential, OrgIdentity } from "@varlatch/sdk";
import { useSession } from "../../lib/session";
import { timeAgo, timeUntil, useNow } from "../../lib/time";
import {
  Badge,
  Button,
  Callout,
  EmptyState,
  Field,
  IconButton,
  Input,
  Menu,
  SectionCard,
  Select,
  Spinner,
  StatusDot,
  Switch,
  table,
  cn,
} from "../../components/ui";
import { CodeBlock, CopyButton } from "../../components/CodeBlock";
import { Dialog, useConfirm, usePrompt } from "../../components/Dialog";
import { FilterInput, Highlight, matchesFilter } from "../../components/FilterInput";
import { Tabs } from "../../components/PageHeader";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";
import { useCapability } from "../projects/hooks";
import { useIdentities } from "./shared";
import { KIND_AUTH, KIND_HELP, KindIcon } from "./model";

/**
 * Machines: non-human identities and how each signs in. Token kinds show
 * their token exactly once at creation; ci federates through OIDC with no
 * stored secret; agents use secrets only through a broker. Like people, a
 * machine starts with zero access until a grant says otherwise.
 */

type MachineKind = Exclude<OrgIdentity["kind"], "human">;
const MACHINE_KINDS: MachineKind[] = ["service", "workload", "ci", "broker", "agent"];
const TOKEN_KINDS: MachineKind[] = ["service", "workload", "broker"];

type OneTime = { name: string; kind: MachineKind; credential: string; expiresAt: string | null; maxUses: number | null; id: string };

export function MachinesTab({ org, onGrant }: { org: string; onGrant: (identityId: string) => void }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const prompt = usePrompt();
  const toast = useToast();
  const lifecycle = useCapability("identity.lifecycle");
  const identities = useIdentities(org);
  const grants = useQuery({ queryKey: ["grants", org], queryFn: () => api.listGrants(org) });
  const [filter, setFilter] = useState("");
  const [showRetired, setShowRetired] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [oneTime, setOneTime] = useState<OneTime | null>(null);
  const now = useNow();

  const all = (identities.data?.items ?? []).filter((i) => i.kind !== "human");
  const retiredCount = all.filter((i) => i.disabled).length;
  const visible = all.filter((i) => (showRetired || !i.disabled) && matchesFilter(filter, i.name, i.kind));
  const grantCount = useMemo(() => {
    const m = new Map<string, number>();
    for (const g of grants.data?.items ?? []) if (g.subjectIdentityId) m.set(g.subjectIdentityId, (m.get(g.subjectIdentityId) ?? 0) + 1);
    return m;
  }, [grants.data]);

  const invalidate = () => void qc.invalidateQueries({ queryKey: ["identities", org] });
  const lifecycleError = (err: unknown) => toast.error("That did not work", { description: errorMessage(err) });
  const rename = useMutation({
    mutationFn: ({ id, next }: { id: string; next: string }) => api.renameIdentity(org, id, next),
    onSuccess: invalidate,
    onError: lifecycleError,
  });
  const retire = useMutation({ mutationFn: (id: string) => api.retireIdentity(org, id), onSuccess: invalidate, onError: lifecycleError });
  const reactivate = useMutation({ mutationFn: (id: string) => api.reactivateIdentity(org, id), onSuccess: invalidate, onError: lifecycleError });

  const askRename = async (i: OrgIdentity) => {
    const next = await prompt({ title: `Rename ${i.name}`, label: "Name", initialValue: i.name, confirmLabel: "Rename" });
    if (next && next !== i.name) rename.mutate({ id: i.id, next });
  };
  const askRetire = async (i: OrgIdentity) => {
    const ok = await confirm({
      title: `Retire ${i.name}?`,
      description: "Retiring disables the machine and revokes every credential it holds. Reactivating later does not bring the credentials back.",
      consequences: [
        { icon: <ShieldOff size={15} />, text: "It can no longer sign in, starting with its next request." },
        { icon: <TriangleAlert size={15} />, text: "All of its tokens and OIDC sessions are revoked." },
        { text: "Its grants stay in place but match nothing until it is reactivated." },
      ],
      confirmLabel: "Retire machine",
      tone: "danger",
      typeToConfirm: i.name,
    });
    if (ok) retire.mutate(i.id);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <FilterInput
          className="min-w-64 flex-1"
          value={filter}
          onChange={setFilter}
          placeholder="Filter machines…"
          shown={visible.length}
          total={all.filter((i) => showRetired || !i.disabled).length}
          noun="machine"
          aria-label="Filter machines"
        />
        {retiredCount > 0 && (
          <label className="flex items-center gap-2 text-[13px] text-muted">
            <Switch checked={showRetired} onChange={setShowRetired} label="Show retired machines" data-testid="show-retired" />
            Show retired ({retiredCount})
          </label>
        )}
        <Button variant="primary" icon={<Plus size={15} />} data-testid="new-machine" onClick={() => setCreating(true)}>
          New machine
        </Button>
      </div>

      <SectionCard
        title="Machines"
        description="CI jobs, servers, brokers and AI agents. New machines start with zero access: add a grant before they can read anything."
        data-testid="machines-section"
        bodyClassName={table.wrap}
      >
        {all.length === 0 ? (
          <EmptyState
            title="No machines yet"
            description="Create one for a CI pipeline, a server or an AI agent. Token kinds get a token shown exactly once; ci and agent kinds never hold a stored secret."
            actions={
              <Button variant="primary" icon={<Plus size={15} />} onClick={() => setCreating(true)}>
                New machine
              </Button>
            }
          />
        ) : (
          <table className={table.table}>
            <thead>
              <tr>
                <th className={cn(table.th, "w-10")} aria-label="Expand" />
                <th className={table.th}>Machine</th>
                <th className={table.th}>Kind</th>
                <th className={table.th}>Signs in with</th>
                <th className={cn(table.th, "text-right")}>Grants</th>
                <th className={table.th}>Last seen</th>
                <th className={cn(table.th, "w-12")} aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {visible.map((i) => {
                const open = expanded === i.id;
                return (
                  <React.Fragment key={i.id}>
                    <tr
                      data-identity={i.name}
                      data-identity-id={i.id}
                      className={cn(table.tr, table.trHover, "cursor-pointer", open && "border-b-0 bg-hover/40", i.disabled && "opacity-60")}
                      onClick={() => setExpanded(open ? null : i.id)}
                    >
                      <td className={cn(table.td, "pr-0")}>
                        <ChevronRight
                          size={15}
                          className={cn("text-muted transition-transform", open && "rotate-90")}
                          data-testid={`machine-expand-${i.id}`}
                        />
                      </td>
                      <td className={table.td}>
                        <span className="flex items-center gap-3">
                          <KindIcon kind={i.kind} className="shrink-0 text-muted" />
                          <span className="font-medium">
                            <Highlight text={i.name} needle={filter} />
                          </span>
                          {i.disabled && <Badge tone="danger">retired</Badge>}
                        </span>
                      </td>
                      <td className={table.td}>
                        <Badge className="font-mono">{i.kind}</Badge>
                      </td>
                      <td className={cn(table.td, "text-[13px]")}>
                        <SignsInWith org={org} identity={i as OrgIdentity & { kind: MachineKind }} now={now} />
                      </td>
                      <td className={cn(table.td, "text-right tabular-nums")}>{grantCount.get(i.id) ?? 0}</td>
                      <td className={cn(table.td, "whitespace-nowrap text-muted")} title={i.lastSeenAt ? new Date(i.lastSeenAt).toLocaleString() : "Never authenticated"}>
                        <span className="inline-flex items-center gap-2">
                          <StatusDot tone={i.lastSeenAt && now - new Date(i.lastSeenAt).getTime() < 60 * 60_000 ? "ok" : "muted"} />
                          {timeAgo(i.lastSeenAt, now)}
                        </span>
                      </td>
                      <td className={cn(table.td, "text-right")} onClick={(e) => e.stopPropagation()}>
                        <Menu
                          data-testid={`machine-menu-${i.id}`}
                          label={`Actions for ${i.name}`}
                          items={[
                            { label: "Add a grant…", onSelect: () => onGrant(i.id), "data-testid": `machine-grant-${i.id}` },
                            { label: open ? "Hide details" : "Credentials and sign-in", onSelect: () => setExpanded(open ? null : i.id), "data-testid": `machine-credentials-${i.id}` },
                            ...(lifecycle
                              ? [
                                  { label: "Rename…", onSelect: () => void askRename(i), "data-testid": `machine-rename-${i.id}` },
                                  i.disabled
                                    ? { label: "Reactivate", onSelect: () => reactivate.mutate(i.id), "data-testid": `machine-reactivate-${i.id}` }
                                    : { label: "Retire…", danger: true, separatorBefore: true, onSelect: () => void askRetire(i), "data-testid": `machine-retire-${i.id}` },
                                ]
                              : []),
                          ]}
                        >
                          <MoreHorizontal size={16} />
                        </Menu>
                      </td>
                    </tr>
                    {open && (
                      <tr className={table.tr}>
                        <td colSpan={7} className="bg-hover/40 px-4 pb-4 pt-0">
                          <MachineDetails org={org} identity={i} lifecycle={lifecycle} />
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
              {visible.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-6 text-center text-[13px] text-muted">
                    {filter ? `No machine matches “${filter}”.` : "All machines here are retired; switch on “Show retired” to see them."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </SectionCard>

      <NewMachineDialog
        org={org}
        open={creating}
        onClose={() => setCreating(false)}
        onCreated={(created) => {
          setCreating(false);
          invalidate();
          if (created) setOneTime(created);
        }}
      />
      {oneTime && (
        <MachineTokenDialog
          oneTime={oneTime}
          onClose={() => setOneTime(null)}
          onGrant={() => {
            const id = oneTime.id;
            setOneTime(null);
            onGrant(id);
          }}
        />
      )}
    </div>
  );
}

function SignsInWith({ org, identity, now }: { org: string; identity: OrgIdentity & { kind: MachineKind }; now: number }) {
  const { api } = useSession();
  const tokenKind = TOKEN_KINDS.includes(identity.kind);
  const creds = useQuery({
    queryKey: ["identity-credentials", org, identity.id],
    queryFn: () => api.listIdentityCredentials(org, identity.id),
    enabled: tokenKind && !identity.disabled,
    retry: false,
  });
  const bindings = useQuery({
    queryKey: ["oidc-bindings", org, identity.id],
    queryFn: () => api.listOidcBindings(org, identity.id),
    enabled: identity.kind === "ci",
    retry: false,
  });
  if (identity.disabled) return <span className="text-muted">Nothing: retired</span>;
  if (identity.kind === "ci") {
    const n = bindings.data?.items.length;
    return (
      <span className="inline-flex items-center gap-2">
        <ShieldCheck size={15} className="text-accent" />
        OIDC federation
        <span className="text-muted">· {n === undefined ? "no stored secret" : n === 0 ? "no binding yet" : `${n} binding${n === 1 ? "" : "s"}`}</span>
      </span>
    );
  }
  if (identity.kind === "agent") return <span className="text-muted">{KIND_AUTH.agent}</span>;
  const active = (creds.data?.items ?? []).filter((c) => !c.revokedAt && c.kind === "service");
  if (creds.isLoading) return <span className="text-muted">Token</span>;
  if (active.length === 0) return <span className="text-muted">No active token</span>;
  const expiries = active.map((c) => c.expiresAt).filter(Boolean) as string[];
  const soonest = expiries.sort()[0];
  const soon = soonest && new Date(soonest).getTime() - now < 7 * 86_400_000;
  return (
    <span className="inline-flex items-center gap-2">
      {soon && <StatusDot tone="warn" />}
      Token
      <span className="text-muted">· {soonest ? `expires ${timeUntil(soonest, now)}` : "no expiry"}</span>
    </span>
  );
}

function MachineDetails({ org, identity, lifecycle }: { org: string; identity: OrgIdentity; lifecycle: boolean }) {
  return (
    <div className="grid gap-4 pt-1 lg:grid-cols-2">
      <OidcBindings org={org} identity={identity} />
      {lifecycle && <CredentialsList org={org} identity={identity} />}
    </div>
  );
}

function OidcBindings({ org, identity }: { org: string; identity: OrgIdentity }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const toast = useToast();
  const [issuer, setIssuer] = useState(identity.kind === "ci" ? "https://token.actions.githubusercontent.com" : "");
  const [audience, setAudience] = useState("varlatch");
  const [subject, setSubject] = useState("");
  const [adding, setAdding] = useState(false);
  const key = ["oidc-bindings", org, identity.id];
  const bindings = useQuery({ queryKey: key, queryFn: () => api.listOidcBindings(org, identity.id) });
  const create = useMutation({
    mutationFn: () => api.createOidcBinding(org, identity.id, { issuer, audience, subject }),
    onSuccess: () => {
      setSubject("");
      setAdding(false);
      void qc.invalidateQueries({ queryKey: key });
    },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.revokeOidcBinding(org, identity.id, id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: key }),
    onError: (err) => toast.error("Could not remove the binding", { description: errorMessage(err) }),
  });
  const items = bindings.data?.items ?? [];
  return (
    <div className="rounded-lg border border-bd bg-raised" data-testid="oidc-section">
      <div className="flex items-center justify-between gap-3 border-b border-bd px-4 py-2.5">
        <div>
          <p className="text-[13px] font-semibold">OIDC bindings</p>
          <p className="text-xs text-muted">Sign in with a platform's identity token instead of a stored secret.</p>
        </div>
        {!adding && (
          <Button size="sm" variant="secondary" icon={<Plus size={13} />} data-testid="add-oidc-binding" onClick={() => setAdding(true)}>
            Add binding
          </Button>
        )}
      </div>
      {items.length === 0 && !adding && (
        <p className="px-4 py-3 text-[13px] text-muted">
          {identity.kind === "ci" ? "No binding yet. Add one so this pipeline can sign in." : "None. This machine signs in with a token."}
        </p>
      )}
      {items.length > 0 && (
        <ul>
          {items.map((b: OidcBinding) => (
            <li key={b.id} data-oidc-binding={b.subject} className="grid grid-cols-[1fr_auto] items-center gap-2 border-b border-bd px-4 py-2.5 last:border-b-0">
              <div className="min-w-0 space-y-0.5 text-[12.5px]">
                <MonoRow label="Issuer" value={b.issuer} />
                <MonoRow label="Audience" value={b.audience} />
                <MonoRow label="Subject" value={b.subject} />
              </div>
              <Button
                size="sm"
                variant="danger"
                data-testid={`revoke-oidc-${b.id}`}
                onClick={async () => {
                  const ok = await confirm({
                    title: "Remove this OIDC binding?",
                    description: `Workloads matching ${b.subject} can no longer sign in as ${identity.name}.`,
                    confirmLabel: "Remove binding",
                    tone: "danger",
                  });
                  if (ok) revoke.mutate(b.id);
                }}
              >
                Remove
              </Button>
            </li>
          ))}
        </ul>
      )}
      {adding && (
        <form
          className="space-y-3 border-t border-bd px-4 py-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (issuer && audience && subject) create.mutate();
          }}
        >
          <div className="grid gap-3 sm:grid-cols-3">
            <Field label="Issuer">
              <Input data-testid="oidc-issuer" mono className="w-full" value={issuer} placeholder="https://token.actions.githubusercontent.com" onChange={(e) => setIssuer(e.target.value)} />
            </Field>
            <Field label="Audience">
              <Input data-testid="oidc-audience" mono className="w-full" value={audience} onChange={(e) => setAudience(e.target.value)} />
            </Field>
            <Field label="Subject" hint="Exact, or a prefix ending in *">
              <Input data-autofocus data-testid="oidc-subject" mono className="w-full" value={subject} placeholder="repo:acme/api:*" onChange={(e) => setSubject(e.target.value)} />
            </Field>
          </div>
          {create.error && <p className="text-sm text-deny">{errorMessage(create.error)}</p>}
          <div className="flex justify-end gap-2">
            <Button size="sm" variant="ghost" onClick={() => setAdding(false)}>
              Cancel
            </Button>
            <Button size="sm" variant="primary" type="submit" data-testid="create-oidc-binding" loading={create.isPending} disabled={!issuer || !audience || !subject}>
              Add binding
            </Button>
          </div>
        </form>
      )}
    </div>
  );
}

function MonoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex min-w-0 items-center gap-2">
      <span className="w-16 shrink-0 text-muted">{label}</span>
      <span className="truncate font-mono text-fg">{value}</span>
      <CopyButton value={value} label={`Copy ${label.toLowerCase()}`} className="size-6" />
    </div>
  );
}

/** Credential metadata only: never token material, except once, right after issuing. */
function CredentialsList({ org, identity }: { org: string; identity: OrgIdentity }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const now = useNow();
  // Another token for a token kind (capability identity.credentials.issue);
  // ci and agent identities never hold one, and a retired one gets none.
  const canIssue =
    useCapability("identity.credentials.issue") && TOKEN_KINDS.includes(identity.kind as MachineKind) && !identity.disabled;
  const [issuing, setIssuing] = useState(false);
  const [issued, setIssued] = useState<IssuedMachineCredential | null>(null);
  const key = ["identity-credentials", org, identity.id];
  const creds = useQuery({ queryKey: key, queryFn: () => api.listIdentityCredentials(org, identity.id) });
  const revoke = useMutation({
    mutationFn: (credentialId: string) => api.revokeIdentityCredential(org, identity.id, credentialId),
    onSuccess: () => void qc.invalidateQueries({ queryKey: key }),
  });
  const items = (creds.data?.items ?? []) as (IdentityCredential & { client?: string | null })[];
  return (
    <div className="rounded-lg border border-bd bg-raised" data-testid={`credentials-panel-${identity.id}`}>
      <div className="flex items-center justify-between gap-3 border-b border-bd px-4 py-2.5">
        <div>
          <p className="text-[13px] font-semibold">Credentials</p>
          <p className="text-xs text-muted">Metadata only. Tokens are shown once, when they are issued.</p>
        </div>
        {canIssue && (
          <Button size="sm" variant="secondary" icon={<Plus size={13} />} data-testid={`issue-credential-${identity.id}`} onClick={() => setIssuing(true)}>
            Issue credential
          </Button>
        )}
      </div>
      {creds.isLoading ? (
        <div className="px-4 py-3">
          <Spinner />
        </div>
      ) : items.length === 0 ? (
        <p className="px-4 py-3 text-[13px] text-muted">No credentials.</p>
      ) : (
        <ul>
          {items.map((c) => (
            <li key={c.id} data-credential={c.id} className="flex items-center gap-3 border-b border-bd px-4 py-2.5 text-[13px] last:border-b-0">
              <Badge className="font-mono">{c.kind}</Badge>
              <span className="min-w-0 flex-1">
                <span className="block truncate">{c.name ?? c.client ?? "Unnamed"}</span>
                <span className="block text-xs text-muted">
                  issued {timeAgo(c.createdAt, now)} · used {timeAgo(c.lastUsedAt, now)}
                  {c.expiresAt && ` · expires ${timeUntil(c.expiresAt, now)}`}
                </span>
              </span>
              {c.revokedAt ? (
                <Badge tone="danger">revoked</Badge>
              ) : c.kind === "service" || c.kind === "oidc" ? (
                <Button
                  size="sm"
                  variant="danger"
                  data-testid={`revoke-credential-${c.id}`}
                  onClick={async () => {
                    const ok = await confirm({
                      title: "Revoke this credential?",
                      description: `${identity.name} can no longer authenticate with it, starting with its next request.`,
                      confirmLabel: "Revoke credential",
                      tone: "danger",
                    });
                    if (ok) revoke.mutate(c.id);
                  }}
                >
                  Revoke
                </Button>
              ) : (
                <span className="text-xs text-muted" title="Agent-run credentials are managed by the broker; CLI and browser sessions belong to their owner's account page.">
                  active
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
      <IssueCredentialDialog
        org={org}
        identity={identity}
        open={issuing}
        onClose={() => setIssuing(false)}
        onIssued={(credential) => {
          setIssuing(false);
          setIssued(credential);
          void qc.invalidateQueries({ queryKey: key });
        }}
      />
      {issued && <IssuedCredentialDialog identity={identity} issued={issued} onClose={() => setIssued(null)} />}
    </div>
  );
}

/** Another token for a machine, with its grants and its own name, revocable on its own. */
function IssueCredentialDialog({
  org,
  identity,
  open,
  onClose,
  onIssued,
}: {
  org: string;
  identity: OrgIdentity;
  open: boolean;
  onClose: () => void;
  onIssued: (issued: IssuedMachineCredential) => void;
}) {
  const { api } = useSession();
  const [name, setName] = useState("");
  const [ttlSeconds, setTtlSeconds] = useState("");
  const ttlValid = ttlSeconds === "" || /^[1-9][0-9]*$/.test(ttlSeconds);
  const issue = useMutation({
    mutationFn: () =>
      api.issueMachineCredential(org, identity.id, { name: name.trim(), ...(ttlSeconds ? { ttlSeconds: Number(ttlSeconds) } : {}) }),
    onSuccess: (issued) => {
      setName("");
      setTtlSeconds("");
      onIssued(issued);
    },
  });
  const ready = name.trim() !== "" && ttlValid;
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`Issue a credential for ${identity.name}`}
      description="A new token with this machine's grants. Name it after the program that uses it, so you can revoke it on its own."
      data-testid="issue-credential-dialog"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" data-testid="issue-credential-submit" loading={issue.isPending} disabled={!ready} onClick={() => issue.mutate()}>
            Issue credential
          </Button>
        </>
      }
    >
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          if (ready) issue.mutate();
        }}
      >
        <Field label="Name">
          <Input data-autofocus data-testid="issue-credential-name" className="w-full" maxLength={200} placeholder="backup job" value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Token lifetime (seconds)" hint="Empty: no expiry, revocation only." error={!ttlValid ? "Whole seconds, at least 1." : undefined}>
          <Input data-testid="issue-credential-ttl" mono className="w-full" placeholder="7776000" value={ttlSeconds} invalid={!ttlValid} onChange={(e) => setTtlSeconds(e.target.value.trim())} />
        </Field>
        {issue.error && <p className="text-sm text-deny">{errorMessage(issue.error)}</p>}
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}

function IssuedCredentialDialog({ identity, issued, onClose }: { identity: OrgIdentity; issued: IssuedMachineCredential; onClose: () => void }) {
  return (
    <Dialog
      open
      onClose={onClose}
      dismissable={false}
      title={`Credential issued for ${identity.name}`}
      description={issued.name}
      icon={
        <span className="flex size-9 items-center justify-center rounded-full border border-accent/50 text-accent">
          <ShieldCheck size={18} />
        </span>
      }
      data-testid="issued-credential"
      footer={
        <Button variant="primary" data-testid="dismiss-issued-credential" onClick={onClose}>
          Done
        </Button>
      }
    >
      <div className="space-y-5">
        <OneTimeToken token={issued.token} tokenTestId="issued-credential-token" copyTestId="copy-issued-credential" />
        <div className="flex flex-wrap gap-x-6 gap-y-2 text-[13px] text-muted" data-testid="issued-credential-limits">
          <span className="inline-flex items-center gap-2">
            <Clock size={15} />
            {issued.expiresAt ? `Expires ${new Date(issued.expiresAt).toLocaleString()}` : "No expiry: revoke it when done"}
          </span>
          <span className="inline-flex items-center gap-2">
            <ShieldCheck size={15} />
            The grants of {identity.name}, no more
          </span>
        </div>
      </div>
    </Dialog>
  );
}

/** A token shown once: blurred until revealed, with a copy button and the warning. */
function OneTimeToken({ token, tokenTestId, copyTestId }: { token: string; tokenTestId: string; copyTestId: string }) {
  const [revealed, setRevealed] = useState(false);
  return (
    <Callout tone="warn" icon={<TriangleAlert size={17} />} title="Copy this token now. It will never be shown again.">
      <div className="mt-2 flex items-center gap-2">
        <span
          data-testid={tokenTestId}
          className={cn(
            "min-w-0 flex-1 truncate rounded-md border border-bd bg-inset px-3 py-2 font-mono text-[13px] text-fg transition-[filter]",
            !revealed && "select-none blur-[5px]",
          )}
        >
          {token}
        </span>
        <IconButton label={revealed ? "Hide token" : "Show token"} onClick={() => setRevealed((v) => !v)}>
          {revealed ? <EyeOff size={15} /> : <Eye size={15} />}
        </IconButton>
        <CopyButton value={token} data-testid={copyTestId}>
          Copy
        </CopyButton>
      </div>
    </Callout>
  );
}

function NewMachineDialog({
  org,
  open,
  onClose,
  onCreated,
}: {
  org: string;
  open: boolean;
  onClose: () => void;
  onCreated: (oneTime: OneTime | null) => void;
}) {
  const { api } = useSession();
  const [name, setName] = useState("");
  const [kind, setKind] = useState<MachineKind>("service");
  const [ttlSeconds, setTtlSeconds] = useState("");
  const [maxUses, setMaxUses] = useState("");
  const issues = TOKEN_KINDS.includes(kind);
  const ttlValid = ttlSeconds === "" || /^[1-9][0-9]*$/.test(ttlSeconds);
  const usesValid = maxUses === "" || /^[1-9][0-9]*$/.test(maxUses);
  const create = useMutation({
    mutationFn: () =>
      api.createIdentity(org, {
        name: name.trim(),
        kind,
        ...(issues && ttlSeconds ? { credentialTtlSeconds: Number(ttlSeconds) } : {}),
        ...(issues && maxUses ? { credentialMaxUses: Number(maxUses) } : {}),
      }),
    onSuccess: (r) => {
      const created: OneTime | null = r.credential
        ? {
            id: r.id,
            name: r.name,
            kind,
            credential: r.credential,
            expiresAt: r.credentialExpiresAt ?? null,
            maxUses: issues && maxUses ? Number(maxUses) : null,
          }
        : null;
      setName("");
      setTtlSeconds("");
      setMaxUses("");
      onCreated(created);
    },
  });
  const ready = name.trim() !== "" && ttlValid && usesValid;
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="New machine"
      description="Machines start with zero access. You add a grant after creating it."
      data-testid="new-machine-dialog"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" data-testid="create-machine" loading={create.isPending} disabled={!ready} onClick={() => create.mutate()}>
            Create machine
          </Button>
        </>
      }
    >
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          if (ready) create.mutate();
        }}
      >
        <Field label="Name">
          <Input data-autofocus data-testid="machine-name" mono className="w-full" placeholder="deploy-bot" value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Kind">
          <div className="grid gap-2 sm:grid-cols-2" role="radiogroup" aria-label="Machine kind">
            {MACHINE_KINDS.map((k) => (
              <button
                key={k}
                type="button"
                role="radio"
                aria-checked={kind === k}
                data-machine-kind={k}
                onClick={() => setKind(k)}
                className={cn(
                  "flex cursor-pointer items-start gap-3 rounded-lg border px-3 py-2.5 text-left transition-colors",
                  kind === k ? "border-accent bg-accent/[0.06] ring-1 ring-accent/30" : "border-bd hover:border-bd-strong hover:bg-hover",
                )}
              >
                <KindIcon kind={k} size={17} className={cn("mt-0.5 shrink-0", kind === k ? "text-accent" : "text-muted")} />
                <span>
                  <span className="block font-mono text-[13px] font-medium">{k}</span>
                  <span className="block text-xs leading-snug text-muted">{KIND_HELP[k]}</span>
                </span>
              </button>
            ))}
          </div>
          <Select
            data-testid="machine-kind"
            className="sr-only"
            value={kind}
            onChange={(v) => setKind(v as MachineKind)}
            aria-label="Machine kind"
            options={MACHINE_KINDS.map((k) => ({ value: k, label: k }))}
          />
        </Field>
        {issues && (
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Token lifetime (seconds)" hint="Empty: no expiry, revocation only." error={!ttlValid ? "Whole seconds, at least 1." : undefined}>
              <Input data-testid="machine-ttl" mono className="w-full" placeholder="7776000" value={ttlSeconds} invalid={!ttlValid} onChange={(e) => setTtlSeconds(e.target.value.trim())} />
            </Field>
            <Field label="Use budget (requests)" hint="Empty: unlimited. 1 makes a one-shot token." error={!usesValid ? "A whole number, at least 1." : undefined}>
              <Input data-testid="machine-max-uses" mono className="w-full" placeholder="unlimited" value={maxUses} invalid={!usesValid} onChange={(e) => setMaxUses(e.target.value.trim())} />
            </Field>
          </div>
        )}
        {create.error && <p className="text-sm text-deny">{errorMessage(create.error)}</p>}
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}

function MachineTokenDialog({ oneTime, onClose, onGrant }: { oneTime: OneTime; onClose: () => void; onGrant: () => void }) {
  const [tab, setTab] = useState("shell");
  const origin = window.location.origin;
  const snippets: Record<string, string[]> = {
    shell: [`export VARLATCH_SERVER=${origin}`, "export VARLATCH_TOKEN=<paste the token>", "varlatch run -- node server.js"],
    github: [
      "env:",
      `  VARLATCH_SERVER: ${origin}`,
      "  VARLATCH_TOKEN: ${{ secrets.VARLATCH_TOKEN }}",
      "run: varlatch run -- npm start",
    ],
    docker: [`docker run -e VARLATCH_SERVER=${origin} -e VARLATCH_TOKEN your-image \\`, "  varlatch run -- node server.js"],
  };
  return (
    <Dialog
      open
      onClose={onClose}
      dismissable={false}
      title={`${oneTime.name} is ready`}
      description={`${oneTime.kind} · created just now`}
      icon={
        <span className="flex size-9 items-center justify-center rounded-full border border-accent/50 text-accent">
          <ShieldCheck size={18} />
        </span>
      }
      data-testid="one-time-credential"
      footer={
        <>
          <Button variant="secondary" data-testid="dismiss-credential" onClick={onClose}>
            Done
          </Button>
          <Button variant="primary" onClick={onGrant}>
            Add a grant for {oneTime.name} →
          </Button>
        </>
      }
    >
      <div className="space-y-5">
        <OneTimeToken token={oneTime.credential} tokenTestId="one-time-credential-token" copyTestId="copy-credential" />
        <div className="flex flex-wrap gap-x-6 gap-y-2 text-[13px] text-muted" data-testid="one-time-credential-limits">
          <span className="inline-flex items-center gap-2">
            <Clock size={15} />
            {oneTime.expiresAt ? `Expires ${new Date(oneTime.expiresAt).toLocaleString()}` : "No expiry: revoke it when done"}
          </span>
          <span className="inline-flex items-center gap-2">
            <Gauge size={15} />
            {oneTime.maxUses ? `Use budget: ${oneTime.maxUses} request${oneTime.maxUses === 1 ? "" : "s"}` : "Unlimited uses"}
          </span>
          <span className="inline-flex items-center gap-2">
            <ShieldOff size={15} />
            0 grants: it can't read anything yet
          </span>
        </div>
        <div>
          <p className="mb-1 text-[13px] font-semibold">Use it</p>
          <Tabs
            className="mb-3"
            active={tab}
            onSelect={setTab}
            items={[
              { key: "shell", label: "Shell" },
              { key: "github", label: "GitHub Actions" },
              { key: "docker", label: "Docker" },
            ]}
          />
          <CodeBlock lines={snippets[tab] ?? []} />
        </div>
      </div>
    </Dialog>
  );
}
