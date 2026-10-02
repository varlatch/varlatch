// SPDX-License-Identifier: AGPL-3.0-or-later
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleCheck, Mail, MoreHorizontal, RefreshCw, UserPlus } from "lucide-react";
import type { Grant } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { displayEmail } from "../../lib/identity";
import { timeAgo, timeUntil, useNow } from "../../lib/time";
import {
  Avatar,
  Badge,
  Button,
  Callout,
  EmptyState,
  Field,
  Input,
  Menu,
  SectionCard,
  Segmented,
  StatusDot,
  table,
  cn,
} from "../../components/ui";
import { CopyButton } from "../../components/CodeBlock";
import { Dialog, useConfirm } from "../../components/Dialog";
import { FilterInput, Highlight, matchesFilter } from "../../components/FilterInput";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";
import { useCapability } from "../projects/hooks";
import { useIdentities } from "./shared";
import { permissionPhrase, scopeParts, type Names } from "./model";
import { useAccessNames } from "./useAccessNames";

/**
 * People: every human in the organization and the invite flow. Enrollment is
 * passkey-only: an invite is a one-time link, never an email with a secret.
 * The Access column sums up the built-in grants of each person's role plus their explicit grants.
 */
export function MembersTab({ org, onGrant }: { org: string; onGrant: (identityId: string) => void }) {
  const { api, identityId: me } = useSession();
  const identities = useIdentities(org);
  const grants = useQuery({ queryKey: ["grants", org], queryFn: () => api.listGrants(org) });
  const { names, roleName } = useAccessNames(org);
  const [filter, setFilter] = useState("");
  const [inviting, setInviting] = useState(false);
  const [freshLink, setFreshLink] = useState<{ name: string; url: string } | null>(null);
  const now = useNow();

  const people = (identities.data?.items ?? []).filter((i) => i.kind === "human");
  const shown = people.filter((p) => matchesFilter(filter, p.name, displayEmail(p.email), p.orgRole));
  const grantsBySubject = useMemo(() => {
    const map = new Map<string, Grant[]>();
    for (const g of grants.data?.items ?? []) {
      if (!g.subjectIdentityId) continue;
      map.set(g.subjectIdentityId, [...(map.get(g.subjectIdentityId) ?? []), g]);
    }
    return map;
  }, [grants.data]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <FilterInput
          className="min-w-64 flex-1"
          value={filter}
          onChange={setFilter}
          placeholder="Filter people…"
          shown={shown.length}
          total={people.length}
          noun="person"
          aria-label="Filter people"
        />
        <Button variant="primary" icon={<UserPlus size={15} />} data-testid="open-invite" onClick={() => setInviting(true)}>
          Invite
        </Button>
      </div>

      <SectionCard title="Members" data-testid="people-section" bodyClassName={table.wrap}>
        {people.length === 0 ? (
          <EmptyState
            title="No members yet"
            description="Invite the first person: they open a one-time link on their own device and enroll a passkey."
          />
        ) : (
          <table className={table.table}>
            <thead>
              <tr>
                <th className={table.th}>Member</th>
                <th className={table.th}>Org role</th>
                <th className={table.th}>Access</th>
                <th className={table.th}>Last seen</th>
                <th className={cn(table.th, "w-12")} aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {shown.map((p) => {
                const own = grantsBySubject.get(p.id) ?? [];
                return (
                  <tr key={p.id} data-identity={p.name} data-identity-id={p.id} className={cn(table.tr, table.trHover)}>
                    <td className={table.td}>
                      <span className="flex items-center gap-3">
                        <Avatar name={p.name} image={p.image ?? null} size="md" />
                        <span className="min-w-0">
                          <span className="flex items-center gap-2 font-medium">
                            <Highlight text={p.name} needle={filter} />
                            {p.id === me && <Badge tone="accent">you</Badge>}
                            {p.disabled && <Badge tone="danger">retired</Badge>}
                          </span>
                          {displayEmail(p.email) && (
                            <span className="block truncate text-xs text-muted">
                              <Highlight text={displayEmail(p.email)!} needle={filter} />
                            </span>
                          )}
                        </span>
                      </span>
                    </td>
                    <td className={table.td}>
                      {p.orgRole ? <Badge tone={p.orgRole === "admin" ? "accent" : "mono"} className="font-mono">{p.orgRole}</Badge> : <span className="text-subtle">—</span>}
                    </td>
                    <td className={table.td}>
                      <AccessSummary orgRole={p.orgRole} grants={own} names={names} roleName={roleName} onGrant={() => onGrant(p.id)} />
                    </td>
                    <td className={cn(table.td, "whitespace-nowrap text-muted")} title={p.lastSeenAt ? new Date(p.lastSeenAt).toLocaleString() : "Never signed in"}>
                      <span className="inline-flex items-center gap-2">
                        <StatusDot tone={p.lastSeenAt && now - new Date(p.lastSeenAt).getTime() < 10 * 60_000 ? "ok" : "muted"} />
                        {timeAgo(p.lastSeenAt, now)}
                      </span>
                    </td>
                    <td className={cn(table.td, "text-right")}>
                      <Menu
                        label={`Actions for ${p.name}`}
                        items={[{ label: "Add a grant…", onSelect: () => onGrant(p.id) }]}
                      >
                        <MoreHorizontal size={16} />
                      </Menu>
                    </td>
                  </tr>
                );
              })}
              {shown.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-[13px] text-muted">
                    Nobody matches “{filter}”.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </SectionCard>

      <PendingInvitations org={org} freshLink={freshLink} onDismissFresh={() => setFreshLink(null)} onReissued={setFreshLink} />

      <InviteDialog
        org={org}
        open={inviting}
        onClose={() => setInviting(false)}
        onCreated={(link) => {
          setInviting(false);
          setFreshLink(link);
        }}
      />
    </div>
  );
}

/** Built-in grants of the two organization roles, in words. */
export const ROLE_ACCESS = {
  admin: { short: "Everything in the organization", long: "Admins can do every organization action, but network requirements still apply." },
  member: {
    short: "Member defaults",
    long: "Development: read, write and reveal. Staging: read and reveal. Production: item names only; anything more needs a grant.",
  },
} as const;

function AccessSummary({
  orgRole,
  grants,
  names,
  roleName,
  onGrant,
}: {
  orgRole: "admin" | "member" | null;
  grants: Grant[];
  names: Names;
  roleName: (id: string | null | undefined) => string | null;
  onGrant: () => void;
}) {
  const g = grants[0];
  const base = orgRole ? ROLE_ACCESS[orgRole] : null;
  return (
    <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1 text-[13px]">
      {base && (
        <span className="rounded-md border border-bd bg-inset px-2 py-0.5" title={base.long}>
          {base.short}
        </span>
      )}
      {g && (
        <span title={`${grants.length} explicit grant${grants.length === 1 ? "" : "s"}`}>
          {base && <span className="text-muted">+ </span>}
          {permissionPhrase(g.actions, roleName(g.roleId))}
          <span className="text-muted"> on </span>
          {scopeParts(g.scope, names).map((p) => p.label).join(" · ")}
          {grants.length > 1 && <span className="text-muted"> +{grants.length - 1} more</span>}
        </span>
      )}
      {!g && !base && <span className="text-deny">No access yet</span>}
      {!g && orgRole !== "admin" && (
        <Button size="sm" variant="ghost" onClick={onGrant}>
          Grant…
        </Button>
      )}
    </span>
  );
}

function InviteDialog({
  org,
  open,
  onClose,
  onCreated,
}: {
  org: string;
  open: boolean;
  onClose: () => void;
  onCreated: (link: { name: string; url: string }) => void;
}) {
  const { api } = useSession();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [role, setRole] = useState<"member" | "admin">("member");
  const invite = useMutation({
    mutationFn: () => api.createInvitation(org, { name: name.trim(), role }),
    onSuccess: (r) => {
      onCreated({ name: name.trim(), url: `${window.location.origin}/enroll#${r.token}` });
      setName("");
      setRole("member");
      void qc.invalidateQueries({ queryKey: ["invitations", org] });
    },
  });
  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="sm"
      title="Invite a person"
      description="Varlatch sends no email. You get a one-time link to share through a channel you trust; they enroll a passkey on their own device."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" data-testid="create-invite" loading={invite.isPending} disabled={!name.trim()} onClick={() => invite.mutate()}>
            Create invite link
          </Button>
        </>
      }
    >
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim()) invite.mutate();
        }}
      >
        <Field label="Name">
          <Input data-autofocus data-testid="invite-name" className="w-full" placeholder="Mia Verhoeven" value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Organization role" hint={role === "admin" ? ROLE_ACCESS.admin.long : `${ROLE_ACCESS.member.long} You can add grants later.`}>
          <Segmented
            value={role}
            onChange={setRole}
            aria-label="Organization role"
            options={[
              { value: "member", label: "Member" },
              { value: "admin", label: "Admin" },
            ]}
          />
        </Field>
        {invite.error && <p className="text-sm text-deny">{errorMessage(invite.error)}</p>}
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}

function PendingInvitations({
  org,
  freshLink,
  onDismissFresh,
  onReissued,
}: {
  org: string;
  freshLink: { name: string; url: string } | null;
  onDismissFresh: () => void;
  onReissued: (link: { name: string; url: string }) => void;
}) {
  const { api } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const toast = useToast();
  const manage = useCapability("invitations.manage");
  const { nameOf } = useAccessNames(org);
  const now = useNow();
  const invitations = useQuery({
    queryKey: ["invitations", org],
    queryFn: () => api.listInvitations(org, { status: "pending" }),
    enabled: manage,
  });
  const invalidate = () => qc.invalidateQueries({ queryKey: ["invitations", org] });
  const revoke = useMutation({
    mutationFn: (id: string) => api.revokeInvitation(org, id),
    onSuccess: () => void invalidate(),
    onError: (err) => toast.error("Could not revoke the invitation", { description: errorMessage(err) }),
  });
  const reissue = useMutation({
    mutationFn: async (inv: { id: string; name: string; orgRole: "admin" | "member" }) => {
      const created = await api.createInvitation(org, { name: inv.name, role: inv.orgRole });
      await api.revokeInvitation(org, inv.id);
      return { name: inv.name, url: `${window.location.origin}/enroll#${created.token}` };
    },
    onSuccess: (link) => {
      onReissued(link);
      void invalidate();
    },
    onError: (err) => toast.error("Could not create a new link", { description: errorMessage(err) }),
  });

  const pending = invitations.data?.items ?? [];
  if (!freshLink && (!manage || pending.length === 0)) return null;

  return (
    <SectionCard
      title={
        <span>
          Pending invitations{manage && <span className="font-normal text-muted"> · {pending.length}</span>}
        </span>
      }
      data-testid="invitations-section"
    >
      {freshLink && (
        <div className="border-b border-bd p-4">
          <Callout
            tone="success"
            icon={<CircleCheck size={18} />}
            data-testid="invite-url"
            title={`Invite link for ${freshLink.name} is ready`}
            actions={
              <>
                <CopyButton value={freshLink.url} data-testid="copy-invite">
                  Copy
                </CopyButton>
                <Button size="sm" variant="ghost" onClick={onDismissFresh}>
                  Done
                </Button>
              </>
            }
          >
            <p>Shown once. Share it over a channel you trust; it expires if unused.</p>
            <p className="mt-1.5 truncate font-mono text-[12.5px] text-fg">{freshLink.url}</p>
          </Callout>
        </div>
      )}
      {manage && pending.length > 0 && (
        <ul>
          {pending.map((inv) => (
            <li key={inv.id} data-invitation={inv.name} className="flex flex-wrap items-center gap-4 border-b border-bd px-5 py-3 last:border-b-0">
              <span className="flex size-9 items-center justify-center rounded-lg border border-bd bg-inset text-muted">
                <Mail size={16} />
              </span>
              <span className="min-w-0 flex-1">
                <span className="font-medium">{inv.name}</span>
                <span className="font-mono text-xs text-muted"> · {inv.orgRole}</span>
                <span className="block text-xs text-muted">
                  {inv.createdByIdentityId ? `invited by ${nameOf(inv.createdByIdentityId)} · ` : ""}
                  expires {timeUntil(inv.expiresAt, now)}
                </span>
              </span>
              <Button
                size="sm"
                variant="secondary"
                icon={<RefreshCw size={13} />}
                loading={reissue.isPending && reissue.variables?.id === inv.id}
                onClick={() => reissue.mutate(inv)}
              >
                New link
              </Button>
              <Button
                size="sm"
                variant="danger"
                data-testid={`revoke-invitation-${inv.id}`}
                onClick={async () => {
                  const ok = await confirm({
                    title: `Revoke the invitation for ${inv.name}?`,
                    description: "The link stops working immediately. You can invite them again later.",
                    confirmLabel: "Revoke invitation",
                    tone: "danger",
                  });
                  if (ok) revoke.mutate(inv.id);
                }}
              >
                Revoke
              </Button>
            </li>
          ))}
        </ul>
      )}
    </SectionCard>
  );
}
