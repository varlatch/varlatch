// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { OrgIdentity } from "@varlatch/sdk";
import { Button, Card, InfoTip, Input, Mono, Select, cn } from "../../components/ui";
import { useSession } from "../../lib/session";
import { ALL_ACTIONS, useIdentities } from "./shared";

/**
 * Roles & teams (ADR-0028): the reuse layer. Roles bundle actions, groups
 * bundle identities, teams are groups that own projects. None of these grant
 * anything by themselves — they exist so Grants stay few and readable.
 */
export function RolesTab({ org }: { org: string }) {
  return (
    <div className="space-y-4">
      <p className="text-muted text-sm max-w-3xl">
        Nothing on this tab grants access by itself — these are building blocks that keep the
        Grants tab short. A <b>role</b> is a named bundle of actions
        <InfoTip className="mx-1" text="Example: a 'deployer' role bundling config.value.read + secret.use. Grant the role instead of listing actions; edit the role once and every grant citing it follows." />
        , a <b>group</b> is a set of identities you can grant all at once
        <InfoTip className="mx-1" text="Grant a group and every member inherits it. Add or remove members later without touching any grant." />
        , and a <b>team</b> is a group that also owns projects
        <InfoTip className="mx-1" text="A team enables the 'team's projects' grant scope: one grant covering everything the team owns, including projects it acquires later." />
        , enabling one grant to cover everything the team owns.
      </p>
      <RolesSection org={org} />
      <GroupsSection org={org} />
      <TeamsSection org={org} />
    </div>
  );
}

/** Custom Roles (ADR-0028): named, reusable Action bundles a Grant may cite. */
function RolesSection({ org }: { org: string }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const roles = useQuery({ queryKey: ["roles", org], queryFn: () => api.listRoles(org) });
  const [name, setName] = useState("");
  const [actions, setActions] = useState<string[]>([]);
  const invalidate = () => void qc.invalidateQueries({ queryKey: ["roles", org] });
  const create = useMutation({
    mutationFn: () => api.createRole(org, { name, actions }),
    onSuccess: () => {
      setName("");
      setActions([]);
      invalidate();
    },
  });
  const remove = useMutation({ mutationFn: (id: string) => api.deleteRole(org, id), onSuccess: invalidate });
  // In-place edit (ADR-0029): re-points every grant citing the role on the
  // next authorization decision — no revoke window, no grant churn.
  const [editing, setEditing] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const [editActions, setEditActions] = useState<string[]>([]);
  const update = useMutation({
    mutationFn: (role: { id: string; version: number }) =>
      api.updateRole(org, role.id, { expectedVersion: role.version, name: editName, actions: editActions }),
    onSuccess: () => {
      setEditing(null);
      invalidate();
    },
  });

  return (
    <Card data-testid="roles-section">
      <h2 className="font-medium mb-1 flex items-center gap-1.5">
        Roles
        <InfoTip text="A reusable, named list of actions. Grants can cite a role instead of listing actions; editing the role updates every grant that cites it, effective on the next authorization decision." />
      </h2>
      <p className="text-muted text-sm mb-3">
        A role is a named, reusable bundle of actions. Grants can cite a role instead of listing
        actions — editing the role re-points every grant that uses it.
      </p>
      <div className="flex flex-wrap gap-2 items-center mb-2">
        <Input data-testid="role-name" placeholder="deployer" value={name} onChange={(e) => setName(e.target.value)} />
        <Button
          data-testid="create-role"
          disabled={!name || actions.length === 0 || create.isPending}
          onClick={() => create.mutate()}
        >
          Create role
        </Button>
      </div>
      <div className="mb-2 flex flex-wrap gap-1.5">
        {ALL_ACTIONS.map((a) => (
          <button
            key={a}
            type="button"
            data-role-action={a}
            onClick={() => setActions((prev) => (prev.includes(a) ? prev.filter((x) => x !== a) : [...prev, a]))}
            className={cn(
              "rounded-full border px-2 py-0.5 text-xs font-mono cursor-pointer",
              actions.includes(a) ? "border-accent text-accent bg-accent-dim/40" : "border-bd text-muted",
            )}
          >
            {a}
          </button>
        ))}
      </div>
      {create.error && <p className="text-deny text-sm mb-2">{String(create.error)}</p>}
      {roles.data?.items.length === 0 && (
        <p className="text-muted text-sm">
          No roles yet. Name one above and pick its actions — then grant the role on the Grants
          tab instead of repeating the same action list.
        </p>
      )}
      {(roles.data?.items ?? []).map((r) => (
        <div key={r.id} data-role={r.name} className="border-t border-bd py-1.5 text-sm">
          <div className="flex items-center gap-2">
            <span className="w-40">{r.name}</span>
            <Mono className="text-xs text-muted flex-1">{r.actions.join(", ")}</Mono>
            <Button
              variant="ghost"
              data-testid={`edit-role-${r.id}`}
              onClick={() => {
                setEditing(editing === r.id ? null : r.id);
                setEditName(r.name);
                setEditActions(r.actions);
              }}
            >
              {editing === r.id ? "Cancel" : "Edit"}
            </Button>
            <Button variant="danger" data-testid={`delete-role-${r.id}`} onClick={() => remove.mutate(r.id)}>
              Delete
            </Button>
          </div>
          {editing === r.id && (
            <div className="mt-2 space-y-2" data-testid={`role-editor-${r.id}`}>
              <div className="flex flex-wrap gap-2 items-center">
                <Input value={editName} onChange={(e) => setEditName(e.target.value)} />
                <Button
                  data-testid={`save-role-${r.id}`}
                  disabled={!editName || editActions.length === 0 || update.isPending}
                  onClick={() => update.mutate({ id: r.id, version: r.version })}
                >
                  Save
                </Button>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {ALL_ACTIONS.map((a) => (
                  <button
                    key={a}
                    type="button"
                    data-edit-action={a}
                    onClick={() =>
                      setEditActions((prev) => (prev.includes(a) ? prev.filter((x) => x !== a) : [...prev, a]))
                    }
                    className={cn(
                      "rounded-full border px-2 py-0.5 text-xs font-mono cursor-pointer",
                      editActions.includes(a) ? "border-accent text-accent bg-accent-dim/40" : "border-bd text-muted",
                    )}
                  >
                    {a}
                  </button>
                ))}
              </div>
              <p className="text-muted text-xs">
                Saving re-points every grant citing this role — the change applies on the next
                authorization decision.
              </p>
              {update.error && <p className="text-deny text-sm">{String(update.error)}</p>}
            </div>
          )}
        </div>
      ))}
    </Card>
  );
}

/** Groups (ADR-0028): identity sets usable as a Grant subject via fan-out. */
function GroupsSection({ org }: { org: string }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const identities = useIdentities(org);
  const groups = useQuery({ queryKey: ["groups", org], queryFn: () => api.listGroups(org) });
  const [name, setName] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const invalidate = () => void qc.invalidateQueries({ queryKey: ["groups", org] });
  const create = useMutation({
    mutationFn: () => api.createGroup(org, { name }),
    onSuccess: () => {
      setName("");
      invalidate();
    },
  });
  const remove = useMutation({ mutationFn: (id: string) => api.deleteGroup(org, id), onSuccess: invalidate });
  const [renaming, setRenaming] = useState<string | null>(null);
  const [renameTo, setRenameTo] = useState("");
  const rename = useMutation({
    mutationFn: (gr: { id: string; version: number }) =>
      api.updateGroup(org, gr.id, { expectedVersion: gr.version, name: renameTo }),
    onSuccess: () => {
      setRenaming(null);
      invalidate();
    },
  });

  return (
    <Card data-testid="groups-section">
      <h2 className="font-medium mb-1 flex items-center gap-1.5">
        Groups
        <InfoTip text="A set of identities. Use a group as the subject of a grant and every member inherits it — membership changes never require editing grants." />
      </h2>
      <p className="text-muted text-sm mb-3">
        A group collects identities. Grant a group and every member inherits it; add or remove
        people without touching grants.
      </p>
      <div className="flex flex-wrap gap-2 items-center mb-2">
        <Input data-testid="group-name" placeholder="deployers" value={name} onChange={(e) => setName(e.target.value)} />
        <Button data-testid="create-group" disabled={!name || create.isPending} onClick={() => create.mutate()}>
          Create group
        </Button>
      </div>
      {create.error && <p className="text-deny text-sm mb-2">{String(create.error)}</p>}
      {groups.data?.items.length === 0 && (
        <p className="text-muted text-sm">
          No groups yet. Create one, add members, then grant the whole group at once on the
          Grants tab.
        </p>
      )}
      {(groups.data?.items ?? []).map((gr) => (
        <div key={gr.id} data-group={gr.name} className="border-t border-bd py-1.5 text-sm">
          <div className="flex items-center gap-2">
            <button className="w-40 text-left hover:text-accent cursor-pointer" onClick={() => setExpanded(expanded === gr.id ? null : gr.id)}>
              {gr.name}
            </button>
            <span className="flex-1" />
            <Button
              variant="ghost"
              data-testid={`rename-group-${gr.id}`}
              onClick={() => {
                setRenaming(renaming === gr.id ? null : gr.id);
                setRenameTo(gr.name);
              }}
            >
              {renaming === gr.id ? "Cancel" : "Rename"}
            </Button>
            <Button variant="danger" data-testid={`delete-group-${gr.id}`} onClick={() => remove.mutate(gr.id)}>
              Delete
            </Button>
          </div>
          {renaming === gr.id && (
            <div className="mt-2 flex flex-wrap gap-2 items-center">
              <Input value={renameTo} onChange={(e) => setRenameTo(e.target.value)} />
              <Button
                data-testid={`save-group-${gr.id}`}
                disabled={!renameTo || rename.isPending}
                onClick={() => rename.mutate({ id: gr.id, version: gr.version })}
              >
                Save
              </Button>
              {rename.error && <p className="text-deny text-sm">{String(rename.error)}</p>}
            </div>
          )}
          {expanded === gr.id && (
            <MembersEditor org={org} groupId={gr.id} isTeam={false} identities={identities.data?.items ?? []} />
          )}
        </div>
      ))}
    </Card>
  );
}

/** Teams (ADR-0028): groups that own projects; a team scope targets them. */
function TeamsSection({ org }: { org: string }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const identities = useIdentities(org);
  const teams = useQuery({ queryKey: ["teams", org], queryFn: () => api.listTeams(org) });
  const projects = useQuery({ queryKey: ["projects", org], queryFn: () => api.listProjects(org) });
  const [name, setName] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const invalidate = () => void qc.invalidateQueries({ queryKey: ["teams", org] });
  const create = useMutation({
    mutationFn: () => api.createTeam(org, { name }),
    onSuccess: () => {
      setName("");
      invalidate();
    },
  });
  const remove = useMutation({ mutationFn: (id: string) => api.deleteTeam(org, id), onSuccess: invalidate });
  const [renaming, setRenaming] = useState<string | null>(null);
  const [renameTo, setRenameTo] = useState("");
  const rename = useMutation({
    mutationFn: (t: { id: string; version: number }) =>
      api.updateTeam(org, t.id, { expectedVersion: t.version, name: renameTo }),
    onSuccess: () => {
      setRenaming(null);
      invalidate();
    },
  });

  return (
    <Card data-testid="teams-section">
      <h2 className="font-medium mb-1 flex items-center gap-1.5">
        Teams
        <InfoTip text="A group that also owns projects. Granting with the 'team's projects' scope covers everything the team owns — including projects it acquires later." />
      </h2>
      <p className="text-muted text-sm mb-3">
        A team is a group that also owns projects. Grant a team with a "team's projects" scope to
        cover everything it owns in one grant.
      </p>
      <div className="flex flex-wrap gap-2 items-center mb-2">
        <Input data-testid="team-name" placeholder="backend" value={name} onChange={(e) => setName(e.target.value)} />
        <Button data-testid="create-team" disabled={!name || create.isPending} onClick={() => create.mutate()}>
          Create team
        </Button>
      </div>
      {create.error && <p className="text-deny text-sm mb-2">{String(create.error)}</p>}
      {teams.data?.items.length === 0 && (
        <p className="text-muted text-sm">
          No teams yet. Create one, add members and the projects it owns — then one grant can
          cover the team's whole surface.
        </p>
      )}
      {(teams.data?.items ?? []).map((t) => (
        <div key={t.id} data-team={t.name} className="border-t border-bd py-1.5 text-sm">
          <div className="flex items-center gap-2">
            <button className="w-40 text-left hover:text-accent cursor-pointer" onClick={() => setExpanded(expanded === t.id ? null : t.id)}>
              {t.name}
            </button>
            <span className="flex-1" />
            <Button
              variant="ghost"
              data-testid={`rename-team-${t.id}`}
              onClick={() => {
                setRenaming(renaming === t.id ? null : t.id);
                setRenameTo(t.name);
              }}
            >
              {renaming === t.id ? "Cancel" : "Rename"}
            </Button>
            <Button variant="danger" data-testid={`delete-team-${t.id}`} onClick={() => remove.mutate(t.id)}>
              Delete
            </Button>
          </div>
          {renaming === t.id && (
            <div className="mt-2 flex flex-wrap gap-2 items-center">
              <Input value={renameTo} onChange={(e) => setRenameTo(e.target.value)} />
              <Button
                data-testid={`save-team-${t.id}`}
                disabled={!renameTo || rename.isPending}
                onClick={() => rename.mutate({ id: t.id, version: t.version })}
              >
                Save
              </Button>
              {rename.error && <p className="text-deny text-sm">{String(rename.error)}</p>}
            </div>
          )}
          {expanded === t.id && (
            <>
              <MembersEditor org={org} groupId={t.id} isTeam identities={identities.data?.items ?? []} />
              <TeamProjectsEditor org={org} teamId={t.id} projects={projects.data?.items ?? []} />
            </>
          )}
        </div>
      ))}
    </Card>
  );
}

function MembersEditor({
  org,
  groupId,
  isTeam,
  identities,
}: {
  org: string;
  groupId: string;
  isTeam: boolean;
  identities: OrgIdentity[];
}) {
  const { api } = useSession();
  const qc = useQueryClient();
  const key = ["group-members", org, groupId];
  const members = useQuery({ queryKey: key, queryFn: () => api.listGroupMembers(org, groupId) });
  const invalidate = () => void qc.invalidateQueries({ queryKey: key });
  const [identityId, setIdentityId] = useState("");
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
  const nameOf = (id: string) => identities.find((i) => i.id === id)?.name ?? id;

  return (
    <div className="mt-2 ml-4 pl-3 border-l border-bd" data-testid={`members-${groupId}`}>
      <div className="flex gap-2 items-center mb-1">
        <span className="text-xs text-muted">Members</span>
        <Select
          value={identityId}
          onChange={(v) => setIdentityId(v)}
          data-testid={`member-select-${groupId}`}
          options={[
            { value: "", label: "Add identity…" },
            ...identities.map((i) => ({ value: i.id, label: `${i.name} (${i.kind})` })),
          ]}
        />
        <Button data-testid={`add-member-${groupId}`} disabled={!identityId || add.isPending} onClick={() => add.mutate()}>
          Add
        </Button>
      </div>
      {members.data?.items.length === 0 && <p className="text-muted text-xs">No members.</p>}
      {members.data?.items.map((m) => (
        <div key={m.identityId} data-member={nameOf(m.identityId)} className="flex items-center gap-2 py-0.5 text-xs">
          <span className="flex-1">{nameOf(m.identityId)}</span>
          <button className="text-deny hover:brightness-125 cursor-pointer" onClick={() => remove.mutate(m.identityId)}>
            remove
          </button>
        </div>
      ))}
    </div>
  );
}

function TeamProjectsEditor({
  org,
  teamId,
  projects,
}: {
  org: string;
  teamId: string;
  projects: { id: string; slug: string }[];
}) {
  const { api } = useSession();
  const qc = useQueryClient();
  const key = ["team-projects", org, teamId];
  const owned = useQuery({ queryKey: key, queryFn: () => api.listTeamProjects(org, teamId) });
  const invalidate = () => void qc.invalidateQueries({ queryKey: key });
  const [projectId, setProjectId] = useState("");
  const add = useMutation({
    mutationFn: () => api.addTeamProject(org, teamId, projectId),
    onSuccess: () => {
      setProjectId("");
      invalidate();
    },
  });
  const remove = useMutation({ mutationFn: (id: string) => api.removeTeamProject(org, teamId, id), onSuccess: invalidate });
  const slugOf = (id: string) => projects.find((p) => p.id === id)?.slug ?? id;

  return (
    <div className="mt-2 ml-4 pl-3 border-l border-bd" data-testid={`team-projects-${teamId}`}>
      <div className="flex gap-2 items-center mb-1">
        <span className="text-xs text-muted">Owned projects</span>
        <Select
          value={projectId}
          onChange={(v) => setProjectId(v)}
          data-testid={`project-select-${teamId}`}
          options={[
            { value: "", label: "Add project…" },
            ...projects.map((p) => ({ value: p.id, label: p.slug })),
          ]}
        />
        <Button data-testid={`add-project-${teamId}`} disabled={!projectId || add.isPending} onClick={() => add.mutate()}>
          Add
        </Button>
      </div>
      {owned.data?.items.length === 0 && <p className="text-muted text-xs">No projects owned.</p>}
      {owned.data?.items.map((p) => (
        <div key={p.projectId} data-owned-project={slugOf(p.projectId)} className="flex items-center gap-2 py-0.5 text-xs">
          <span className="flex-1">{slugOf(p.projectId)}</span>
          <button className="text-deny hover:brightness-125 cursor-pointer" onClick={() => remove.mutate(p.projectId)}>
            remove
          </button>
        </div>
      ))}
    </div>
  );
}
