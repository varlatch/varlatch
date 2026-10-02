// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, FolderClosed, MoreHorizontal, Plus, X } from "lucide-react";
import { useSession } from "../../lib/session";
import { Avatar, Badge, Button, Field, IconButton, Input, Menu, Select, Spinner, cn } from "../../components/ui";
import { Dialog, useConfirm, usePrompt } from "../../components/Dialog";
import { Drawer } from "../../components/Drawer";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";
import { useIdentities } from "./shared";
import { ActionPicker } from "./GrantsTab";
import { KIND_LABEL, actionLabel } from "./model";

/**
 * Roles & teams: the reuse layer. Roles bundle actions, groups bundle
 * identities, teams are groups that also own projects. None of them grants
 * anything by itself; they keep the Grants list short.
 */
export function RolesTab({ org }: { org: string }) {
  return (
    <div className="grid gap-5 lg:grid-cols-3">
      <RolesColumn org={org} />
      <GroupsColumn org={org} kind="group" />
      <GroupsColumn org={org} kind="team" />
    </div>
  );
}

function Column({
  title,
  description,
  onNew,
  newTestId,
  children,
  testId,
}: {
  title: string;
  description: string;
  onNew: () => void;
  newTestId: string;
  children: React.ReactNode;
  testId: string;
}) {
  return (
    <section data-testid={testId} className="flex flex-col rounded-xl border border-bd bg-raised">
      <header className="flex items-start justify-between gap-3 border-b border-bd px-4 py-3.5">
        <div>
          <h2 className="text-[15px] font-semibold">{title}</h2>
          <p className="mt-0.5 text-[13px] text-muted">{description}</p>
        </div>
        <Button size="sm" variant="secondary" icon={<Plus size={13} />} data-testid={newTestId} onClick={onNew}>
          New
        </Button>
      </header>
      <div className="flex-1 space-y-3 p-3">{children}</div>
    </section>
  );
}

function RolesColumn({ org }: { org: string }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const toast = useToast();
  const roles = useQuery({ queryKey: ["roles", org], queryFn: () => api.listRoles(org) });
  const grants = useQuery({ queryKey: ["grants", org], queryFn: () => api.listGrants(org) });
  const [editing, setEditing] = useState<{ id: string | null } | null>(null);
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteRole(org, id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["roles", org] }),
    onError: (err) => toast.error("Could not delete the role", { description: errorMessage(err) }),
  });
  const items = roles.data?.items ?? [];
  const usedBy = (id: string) => (grants.data?.items ?? []).filter((g) => g.roleId === id).length;
  return (
    <Column
      title="Roles"
      description="Named bundles of actions."
      onNew={() => setEditing({ id: null })}
      newTestId="new-role"
      testId="roles-section"
    >
      {roles.isLoading && <Spinner />}
      {items.length === 0 && !roles.isLoading && (
        <p className="px-1 py-2 text-[13px] text-muted">No roles yet. A role names a set of actions, so grants can cite it instead of listing them.</p>
      )}
      {items.map((r) => {
        const n = usedBy(r.id);
        return (
          <div key={r.id} data-role={r.name} className="rounded-lg border border-bd bg-raised p-3.5 transition-colors hover:border-bd-strong">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-[14px] font-semibold">{r.name}</span>
              <Menu
                label={`Actions for ${r.name}`}
                items={[
                  { label: "Edit…", onSelect: () => setEditing({ id: r.id }), "data-testid": `edit-role-${r.id}` },
                  {
                    label: "Delete…",
                    danger: true,
                    separatorBefore: true,
                    "data-testid": `delete-role-${r.id}`,
                    onSelect: async () => {
                      const ok = await confirm({
                        title: `Delete the role ${r.name}?`,
                        description: n > 0 ? `${n} grant${n === 1 ? "" : "s"} cite this role. Deleting may fail until they are changed.` : "No grant cites it.",
                        confirmLabel: "Delete role",
                        tone: "danger",
                      });
                      if (ok) remove.mutate(r.id);
                    },
                  },
                ]}
              >
                <MoreHorizontal size={16} />
              </Menu>
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {r.actions.slice(0, 6).map((a) => (
                <span key={a} className="rounded-md border border-bd bg-inset px-1.5 py-0.5 text-xs text-fg/90" title={a}>
                  {actionLabel(a)}
                </span>
              ))}
              {r.actions.length > 6 && <span className="px-1 text-xs text-muted">+{r.actions.length - 6}</span>}
              <span className="sr-only">{r.actions.join(", ")}</span>
            </div>
            <p className="mt-2.5 text-xs text-muted">
              used by {n} grant{n === 1 ? "" : "s"}
              <button
                type="button"
                data-testid={`open-role-${r.id}`}
                className="ml-2 cursor-pointer text-accent hover:underline"
                onClick={() => setEditing({ id: r.id })}
              >
                Edit
              </button>
            </p>
          </div>
        );
      })}
      {editing && (
        <RoleDrawer
          org={org}
          role={editing.id ? (items.find((r) => r.id === editing.id) ?? null) : null}
          grantCount={editing.id ? usedBy(editing.id) : 0}
          onClose={() => setEditing(null)}
        />
      )}
    </Column>
  );
}

function RoleDrawer({
  org,
  role,
  grantCount,
  onClose,
}: {
  org: string;
  role: { id: string; name: string; actions: string[]; version: number } | null;
  grantCount: number;
  onClose: () => void;
}) {
  const { api } = useSession();
  const qc = useQueryClient();
  const [name, setName] = useState(role?.name ?? "");
  const [actions, setActions] = useState<string[]>(role?.actions ?? []);
  const save = useMutation({
    mutationFn: () =>
      role
        ? api.updateRole(org, role.id, { expectedVersion: role.version, name, actions })
        : api.createRole(org, { name, actions }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["roles", org] });
      onClose();
    },
  });
  return (
    <Drawer
      open
      onClose={onClose}
      width="w-[560px]"
      data-testid="role-drawer"
      title={role ? `Edit role · ${role.name}` : "New role"}
      subtitle="A role is a named, reusable bundle of actions. Grants cite it; editing it updates every grant that does, on the next request."
      footer={
        <>
          {role && (
            <span className="mr-auto text-[13px] text-muted">
              {grantCount} grant{grantCount === 1 ? "" : "s"} follow this role
            </span>
          )}
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            data-testid={role ? `save-role-${role.id}` : "create-role"}
            loading={save.isPending}
            disabled={!name.trim() || actions.length === 0}
            onClick={() => save.mutate()}
          >
            {role ? "Save role" : "Create role"}
          </Button>
        </>
      }
    >
      <div className="space-y-5">
        <Field label="Name">
          <Input data-autofocus data-testid="role-name" mono className="w-full" placeholder="deployer" value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <div>
          <p className="text-[13px] font-medium">Permissions</p>
          <ActionPicker dataAttr={role ? "edit-action" : "role-action"} value={actions} onChange={setActions} />
        </div>
        {save.error && <p className="text-sm text-deny">{errorMessage(save.error)}</p>}
      </div>
    </Drawer>
  );
}

function GroupsColumn({ org, kind }: { org: string; kind: "group" | "team" }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const prompt = usePrompt();
  const toast = useToast();
  const isTeam = kind === "team";
  const key = [isTeam ? "teams" : "groups", org];
  const list = useQuery({ queryKey: key, queryFn: () => (isTeam ? api.listTeams(org) : api.listGroups(org)) });
  const grants = useQuery({ queryKey: ["grants", org], queryFn: () => api.listGrants(org) });
  const [creating, setCreating] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const invalidate = () => void qc.invalidateQueries({ queryKey: key });
  const rename = useMutation({
    mutationFn: ({ id, version, name }: { id: string; version: number; name: string }) =>
      isTeam ? api.updateTeam(org, id, { expectedVersion: version, name }) : api.updateGroup(org, id, { expectedVersion: version, name }),
    onSuccess: invalidate,
    onError: (err) => toast.error("Could not rename", { description: errorMessage(err) }),
  });
  const remove = useMutation({
    mutationFn: (id: string) => (isTeam ? api.deleteTeam(org, id) : api.deleteGroup(org, id)),
    onSuccess: invalidate,
    onError: (err) => toast.error(`Could not delete the ${kind}`, { description: errorMessage(err) }),
  });
  const items = list.data?.items ?? [];
  const grantsFor = (id: string) => (grants.data?.items ?? []).filter((g) => g.subjectGroupId === id).length;

  return (
    <Column
      title={isTeam ? "Teams" : "Groups"}
      description={isTeam ? "Groups that also own projects." : "Grant once, cover every member."}
      onNew={() => setCreating(true)}
      newTestId={`new-${kind}`}
      testId={isTeam ? "teams-section" : "groups-section"}
    >
      {items.length === 0 && !list.isLoading && (
        <p className="px-1 py-2 text-[13px] text-muted">
          {isTeam
            ? "No teams yet. A team owns projects, so one grant can cover everything it owns, now and later."
            : "No groups yet. Grant a group and every member inherits it; membership changes never touch grants."}
        </p>
      )}
      {items.map((g) => {
        const open = expanded === g.id;
        const n = grantsFor(g.id);
        return (
          <div key={g.id} {...{ [`data-${kind}`]: g.name }} className={cn("rounded-lg border bg-raised transition-colors", open ? "border-bd-strong" : "border-bd hover:border-bd-strong")}>
            <div className="p-3.5">
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-[14px] font-semibold">{g.name}</span>
                <Menu
                  label={`Actions for ${g.name}`}
                  items={[
                    {
                      label: "Rename…",
                      "data-testid": `rename-${kind}-${g.id}`,
                      onSelect: async () => {
                        const next = await prompt({ title: `Rename ${g.name}`, label: "Name", initialValue: g.name, confirmLabel: "Rename", mono: true });
                        if (next && next !== g.name) rename.mutate({ id: g.id, version: g.version, name: next });
                      },
                    },
                    {
                      label: "Delete…",
                      danger: true,
                      separatorBefore: true,
                      "data-testid": `delete-${kind}-${g.id}`,
                      onSelect: async () => {
                        const ok = await confirm({
                          title: `Delete the ${kind} ${g.name}?`,
                          description: n > 0 ? `${n} grant${n === 1 ? "" : "s"} name this ${kind}; its members lose what those grants give them.` : `Its members keep their own grants.`,
                          confirmLabel: `Delete ${kind}`,
                          tone: "danger",
                        });
                        if (ok) remove.mutate(g.id);
                      },
                    },
                  ]}
                >
                  <MoreHorizontal size={16} />
                </Menu>
              </div>
              <MembersPreview org={org} groupId={g.id} />
              {isTeam && <OwnedProjectsPreview org={org} teamId={g.id} />}
              <div className="mt-2.5 flex items-center justify-between text-xs text-muted">
                <span>
                  {n} grant{n === 1 ? "" : "s"}
                </span>
                <button
                  type="button"
                  data-testid={`expand-${kind}-${g.id}`}
                  onClick={() => setExpanded(open ? null : g.id)}
                  className="inline-flex cursor-pointer items-center gap-1 text-accent hover:underline"
                >
                  {open ? "Done" : isTeam ? "Members and projects" : "Members"}
                  <ChevronDown size={12} className={cn("transition-transform", open && "rotate-180")} />
                </button>
              </div>
            </div>
            {open && (
              <div className="space-y-4 border-t border-bd p-3.5">
                <MembersEditor org={org} groupId={g.id} isTeam={isTeam} />
                {isTeam && <TeamProjectsEditor org={org} teamId={g.id} />}
              </div>
            )}
          </div>
        );
      })}
      <NewGroupDialog org={org} kind={kind} open={creating} onClose={() => setCreating(false)} onCreated={invalidate} />
    </Column>
  );
}

function NewGroupDialog({
  org,
  kind,
  open,
  onClose,
  onCreated,
}: {
  org: string;
  kind: "group" | "team";
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}) {
  const { api } = useSession();
  const [name, setName] = useState("");
  const create = useMutation({
    mutationFn: () => (kind === "team" ? api.createTeam(org, { name: name.trim() }) : api.createGroup(org, { name: name.trim() })),
    onSuccess: () => {
      setName("");
      onCreated();
      onClose();
    },
  });
  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="sm"
      title={kind === "team" ? "New team" : "New group"}
      description={kind === "team" ? "A team is a group that also owns projects." : "Grant a group and every member inherits it."}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" data-testid={`create-${kind}`} loading={create.isPending} disabled={!name.trim()} onClick={() => create.mutate()}>
            Create {kind}
          </Button>
        </>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim()) create.mutate();
        }}
      >
        <Field label="Name">
          <Input data-autofocus data-testid={`${kind}-name`} mono className="w-full" placeholder={kind === "team" ? "backend" : "oncall"} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        {create.error && <p className="mt-2 text-sm text-deny">{errorMessage(create.error)}</p>}
      </form>
    </Dialog>
  );
}

function MembersPreview({ org, groupId }: { org: string; groupId: string }) {
  const { api } = useSession();
  const identities = useIdentities(org);
  const members = useQuery({ queryKey: ["group-members", org, groupId], queryFn: () => api.listGroupMembers(org, groupId) });
  const list = members.data?.items ?? [];
  const named = list.map((m) => identities.data?.items.find((i) => i.id === m.identityId)).filter(Boolean) as { id: string; name: string; image?: string | null }[];
  return (
    <div className="mt-2.5 flex items-center gap-2.5">
      {named.length > 0 ? (
        <span className="flex -space-x-1.5">
          {named.slice(0, 5).map((i) => (
            <Avatar key={i.id} name={i.name} image={i.image ?? null} size="sm" className="ring-2 ring-raised" />
          ))}
        </span>
      ) : null}
      <span className="text-xs text-muted">
        {list.length} member{list.length === 1 ? "" : "s"}
      </span>
    </div>
  );
}

function OwnedProjectsPreview({ org, teamId }: { org: string; teamId: string }) {
  const { api } = useSession();
  const projects = useQuery({ queryKey: ["projects", org], queryFn: () => api.listProjects(org) });
  const owned = useQuery({ queryKey: ["team-projects", org, teamId], queryFn: () => api.listTeamProjects(org, teamId) });
  const slugs = (owned.data?.items ?? []).map((p) => projects.data?.items.find((x) => x.id === p.projectId)?.slug).filter(Boolean) as string[];
  if (slugs.length === 0) return null;
  return (
    <div className="mt-2 flex flex-wrap gap-1.5">
      {slugs.map((s) => (
        <Badge key={s} className="font-mono">
          {s}
        </Badge>
      ))}
    </div>
  );
}

function MembersEditor({ org, groupId, isTeam }: { org: string; groupId: string; isTeam: boolean }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const identities = useIdentities(org);
  const key = ["group-members", org, groupId];
  const members = useQuery({ queryKey: key, queryFn: () => api.listGroupMembers(org, groupId) });
  const [identityId, setIdentityId] = useState("");
  const invalidate = () => void qc.invalidateQueries({ queryKey: key });
  const add = useMutation({
    mutationFn: () => (isTeam ? api.addTeamMember(org, groupId, identityId) : api.addGroupMember(org, groupId, identityId)),
    onSuccess: () => {
      setIdentityId("");
      invalidate();
    },
  });
  const remove = useMutation({
    mutationFn: (id: string) => (isTeam ? api.removeTeamMember(org, groupId, id) : api.removeGroupMember(org, groupId, id)),
    onSuccess: invalidate,
  });
  const memberIds = new Set((members.data?.items ?? []).map((m) => m.identityId));
  const nameOf = (id: string) => identities.data?.items.find((i) => i.id === id)?.name ?? id;
  const candidates = (identities.data?.items ?? []).filter((i) => !i.disabled && !memberIds.has(i.id));
  return (
    <div data-testid={`members-${groupId}`}>
      <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-subtle">Members</p>
      <ul className="mb-2 space-y-1">
        {(members.data?.items ?? []).map((m) => (
          <li key={m.identityId} data-member={nameOf(m.identityId)} className="flex items-center gap-2 text-[13px]">
            <Avatar name={nameOf(m.identityId)} size="xs" />
            <span className="flex-1 truncate">{nameOf(m.identityId)}</span>
            <IconButton size="sm" label={`Remove ${nameOf(m.identityId)}`} onClick={() => remove.mutate(m.identityId)}>
              <X size={13} />
            </IconButton>
          </li>
        ))}
        {memberIds.size === 0 && <li className="text-[13px] text-muted">Nobody yet.</li>}
      </ul>
      <div className="flex items-center gap-2">
        <Select
          data-testid={`member-select-${groupId}`}
          className="min-w-0 flex-1"
          size="sm"
          value={identityId}
          onChange={setIdentityId}
          placeholder="Add a member…"
          aria-label="Add a member"
          options={candidates.map((i) => ({ value: i.id, label: i.name, description: KIND_LABEL[i.kind] }))}
        />
        <Button size="sm" variant="secondary" data-testid={`add-member-${groupId}`} disabled={!identityId} loading={add.isPending} onClick={() => add.mutate()}>
          Add
        </Button>
      </div>
    </div>
  );
}

function TeamProjectsEditor({ org, teamId }: { org: string; teamId: string }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const projects = useQuery({ queryKey: ["projects", org], queryFn: () => api.listProjects(org) });
  const key = ["team-projects", org, teamId];
  const owned = useQuery({ queryKey: key, queryFn: () => api.listTeamProjects(org, teamId) });
  const [projectId, setProjectId] = useState("");
  const invalidate = () => void qc.invalidateQueries({ queryKey: key });
  const add = useMutation({
    mutationFn: () => api.addTeamProject(org, teamId, projectId),
    onSuccess: () => {
      setProjectId("");
      invalidate();
    },
  });
  const remove = useMutation({ mutationFn: (id: string) => api.removeTeamProject(org, teamId, id), onSuccess: invalidate });
  const ownedIds = new Set((owned.data?.items ?? []).map((p) => p.projectId));
  const slugOf = (id: string) => projects.data?.items.find((p) => p.id === id)?.slug ?? id;
  return (
    <div data-testid={`team-projects-${teamId}`}>
      <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-subtle">Owned projects</p>
      <ul className="mb-2 space-y-1">
        {(owned.data?.items ?? []).map((p) => (
          <li key={p.projectId} data-owned-project={slugOf(p.projectId)} className="flex items-center gap-2 text-[13px]">
            <FolderClosed size={14} className="text-muted" />
            <span className="flex-1 truncate font-mono">{slugOf(p.projectId)}</span>
            <IconButton size="sm" label={`Remove ${slugOf(p.projectId)}`} onClick={() => remove.mutate(p.projectId)}>
              <X size={13} />
            </IconButton>
          </li>
        ))}
        {ownedIds.size === 0 && <li className="text-[13px] text-muted">No projects yet.</li>}
      </ul>
      <div className="flex items-center gap-2">
        <Select
          data-testid={`project-select-${teamId}`}
          className="min-w-0 flex-1"
          size="sm"
          value={projectId}
          onChange={setProjectId}
          placeholder="Add a project…"
          aria-label="Add a project"
          options={(projects.data?.items ?? []).filter((p) => !ownedIds.has(p.id)).map((p) => ({ value: p.id, label: p.slug }))}
        />
        <Button size="sm" variant="secondary" data-testid={`add-project-${teamId}`} disabled={!projectId} loading={add.isPending} onClick={() => add.mutate()}>
          Add
        </Button>
      </div>
    </div>
  );
}
