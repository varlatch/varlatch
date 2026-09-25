// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { Grant, GrantScope, Tier } from "@varlatch/protocol";
import { Button, Card, InfoTip, Mono, Select, cn } from "../../components/ui";
import { useSession } from "../../lib/session";
import { ALL_ACTIONS, PRESETS, TIERS, useIdentities } from "./shared";

/**
 * Grants: the single source of permission (ADR-0015). Presets compile to
 * plain Grants; "editing" a grant is an atomic revoke-and-replace (ADR-0029).
 */

function describeScope(scope: GrantScope): string {
  if (scope.kind === "organization") return "whole organization";
  if (scope.kind === "project") return `project ${scope.projectId}`;
  if (scope.kind === "team") return `team ${scope.teamId}'s projects`;
  return scope.selector.kind === "tier"
    ? `tier ${scope.selector.tier} in ${scope.projectId}`
    : `${scope.selector.environmentIds.length} environment(s) in ${scope.projectId}`;
}

export function GrantsTab({ org }: { org: string }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const identities = useIdentities(org);
  const grants = useQuery({ queryKey: ["grants", org], queryFn: () => api.listGrants(org) });
  const projects = useQuery({ queryKey: ["projects", org], queryFn: () => api.listProjects(org) });
  const roles = useQuery({ queryKey: ["roles", org], queryFn: () => api.listRoles(org) });
  const groups = useQuery({ queryKey: ["groups", org], queryFn: () => api.listGroups(org) });
  const teams = useQuery({ queryKey: ["teams", org], queryFn: () => api.listTeams(org) });

  // Subject is encoded as "idn:<id>" or "grp:<id>" so one select covers both.
  const [subject, setSubject] = useState("");
  const [presetKey, setPresetKey] = useState(PRESETS[0]!.key);
  const [advanced, setAdvanced] = useState(false);
  const [actions, setActions] = useState<string[]>(PRESETS[0]!.actions);
  // Permission source: a preset/advanced action list, or a custom Role.
  const [roleId, setRoleId] = useState("");
  const [scopeKind, setScopeKind] = useState<
    "organization" | "project" | "tier" | "environments" | "team"
  >("organization");
  const [projectId, setProjectId] = useState("");
  const [teamId, setTeamId] = useState("");
  const [tier, setTier] = useState<Tier>("development");
  const [envIds, setEnvIds] = useState<string[]>([]);

  const selectedProject = projects.data?.items.find((p) => p.id === projectId);
  const envs = useQuery({
    queryKey: ["environments", org, selectedProject?.slug],
    queryFn: () => api.listEnvironments(org, (selectedProject as { slug: string }).slug),
    enabled: scopeKind === "environments" && selectedProject !== undefined,
  });

  const effectiveActions = useMemo(
    () => (advanced ? actions : PRESETS.find((p) => p.key === presetKey)!.actions),
    [advanced, actions, presetKey],
  );
  const scope: GrantScope =
    scopeKind === "organization"
      ? { kind: "organization" }
      : scopeKind === "project"
        ? { kind: "project", projectId }
        : scopeKind === "team"
          ? { kind: "team", teamId }
          : scopeKind === "tier"
            ? { kind: "environments", projectId, selector: { kind: "tier", tier } }
            : { kind: "environments", projectId, selector: { kind: "environments", environmentIds: envIds } };

  const create = useMutation({
    mutationFn: () => {
      const id = subject.slice(4);
      const subj = subject.startsWith("grp:")
        ? { subjectGroupId: id }
        : { subjectIdentityId: id };
      const perm = roleId ? { roleId } : { actions: effectiveActions };
      return api.createGrant(org, { ...subj, scope, ...perm });
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["grants", org] }),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.deleteGrant(org, id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["grants", org] }),
  });
  // "Editing" a grant is an atomic revoke-and-replace (ADR-0029): the
  // declaration is immutable, so the server swaps it for a successor in one
  // transaction with linked audit events. Subject and scope are kept; the
  // permission (actions or role) is what changes.
  const [editingGrant, setEditingGrant] = useState<string | null>(null);
  const [editGrantRoleId, setEditGrantRoleId] = useState("");
  const [editGrantActions, setEditGrantActions] = useState<string[]>([]);
  const replace = useMutation({
    mutationFn: (g: Grant) =>
      api.replaceGrant(org, g.id, {
        ...(g.subjectIdentityId ? { subjectIdentityId: g.subjectIdentityId } : {}),
        ...(g.subjectGroupId ? { subjectGroupId: g.subjectGroupId } : {}),
        scope: g.scope,
        ...(editGrantRoleId ? { roleId: editGrantRoleId } : { actions: editGrantActions }),
      }),
    onSuccess: () => {
      setEditingGrant(null);
      void qc.invalidateQueries({ queryKey: ["grants", org] });
    },
  });
  const nameOf = (id: string | null | undefined) =>
    !id
      ? "—"
      : identities.data?.items.find((i) => i.id === id)?.name ??
        groups.data?.items.find((gr) => gr.id === id)?.name ??
        teams.data?.items.find((t) => t.id === id)?.name ??
        id;
  const roleName = (id: string | null | undefined) =>
    id ? (roles.data?.items.find((r) => r.id === id)?.name ?? id) : null;
  const scopeReady =
    scopeKind === "organization" ||
    (scopeKind === "team" ? teamId !== "" : projectId !== "" && (scopeKind !== "environments" || envIds.length > 0));

  return (
    <div className="space-y-4">
      <p className="text-muted text-sm max-w-3xl">
        Grants are the heart of access. Each grant is one readable sentence: a{" "}
        <b>subject</b>
        <InfoTip className="mx-1" text="Who the grant is for — a single identity (person or machine), or a group/team so every member inherits it." />
        may perform a set of <b>actions</b>
        <InfoTip className="mx-1" text="Fine-grained verbs like config.value.read or secret.use. Presets are shortcuts that compile to ordinary action lists; a role is a reusable named list. Advanced lets you pick actions one by one." />
        within a <b>scope</b>
        <InfoTip className="mx-1" text="Where the grant applies: the whole organization, one project, one tier (e.g. only production), specific environments, or all projects a team owns." />
        . Everything is default-deny and additive — no grant, no access; revoking takes effect on
        the next request.
      </p>
      <Card data-testid="grants-section">
        <h2 className="font-medium mb-1 flex items-center gap-1.5">
          Grants
          <InfoTip text="The complete list of who may do what. Presets and roles are conveniences; every entry here is an ordinary grant the evaluator reads directly." />
        </h2>
        <p className="text-muted text-sm mb-3">
          Access is default-deny and additive: an identity can do exactly what its Grants say, nothing
          more. Presets are shortcuts that create ordinary Grants.
        </p>
        <div className="flex flex-wrap gap-2 items-center mb-2">
          <Select
            data-testid="grant-subject"
            value={subject}
            onChange={(v) => setSubject(v)}
            aria-label="Grant subject"
            options={[
              { value: "", label: "Choose subject…" },
              ...(identities.data?.items.map((i) => ({
                value: `idn:${i.id}`,
                label: `${i.name} (${i.kind})`,
              })) ?? []),
              ...(groups.data?.items.map((gr) => ({
                value: `grp:${gr.id}`,
                label: `${gr.name} (group)`,
              })) ?? []),
              ...(teams.data?.items.map((t) => ({
                value: `grp:${t.id}`,
                label: `${t.name} (team)`,
              })) ?? []),
            ]}
          />
          <Select
            data-testid="grant-role"
            value={roleId}
            onChange={(v) => setRoleId(v)}
            aria-label="Grant a reusable custom Role instead of picking actions"
            options={[
              { value: "", label: "Preset / actions…" },
              ...(roles.data?.items.map((r) => ({ value: r.id, label: `role: ${r.name}` })) ?? []),
            ]}
          />
          {!advanced && !roleId && (
            <Select
              data-testid="grant-preset"
              value={presetKey}
              onChange={(v) => {
                setPresetKey(v);
                setActions(PRESETS.find((p) => p.key === v)!.actions);
              }}
              aria-label="Permission preset"
              options={PRESETS.map((p) => ({ value: p.key, label: p.label }))}
            />
          )}
          <Select
            data-testid="grant-scope-kind"
            value={scopeKind}
            onChange={(v) => {
              setScopeKind(v as typeof scopeKind);
              setEnvIds([]);
            }}
            aria-label="Grant scope"
            options={[
              { value: "organization", label: "whole organization" },
              { value: "project", label: "one project" },
              { value: "tier", label: "one tier of a project" },
              { value: "environments", label: "specific environments" },
              ...((teams.data?.items.length ?? 0) > 0
                ? [{ value: "team", label: "a team's projects" }]
                : []),
            ]}
          />
          {scopeKind === "team" && (
            <Select
              data-testid="grant-team"
              value={teamId}
              onChange={(v) => setTeamId(v)}
              options={[
                { value: "", label: "Choose team…" },
                ...(teams.data?.items.map((t) => ({ value: t.id, label: t.name })) ?? []),
              ]}
            />
          )}
          {scopeKind !== "organization" && scopeKind !== "team" && (
            <Select
              data-testid="grant-project"
              value={projectId}
              onChange={(v) => {
                setProjectId(v);
                setEnvIds([]);
              }}
              options={[
                { value: "", label: "Choose project…" },
                ...(projects.data?.items.map((p) => ({ value: p.id, label: p.slug })) ?? []),
              ]}
            />
          )}
          {scopeKind === "tier" && (
            <Select
              value={tier}
              onChange={(v) => setTier(v as Tier)}
              aria-label="Tier"
              options={TIERS.map((t) => ({ value: t, label: t }))}
            />
          )}
          <Button
            data-testid="create-grant"
            disabled={
              !subject ||
              !scopeReady ||
              (!roleId && effectiveActions.length === 0) ||
              create.isPending
            }
            onClick={() => create.mutate()}
          >
            Grant
          </Button>
          {!roleId && (
            <Button variant="ghost" data-testid="toggle-advanced" onClick={() => setAdvanced((v) => !v)}>
              {advanced ? "Presets" : "Advanced"}
            </Button>
          )}
        </div>
        {scopeKind === "environments" && selectedProject && (
          <div data-testid="grant-environments" className="mb-2 flex flex-wrap items-center gap-1.5">
            {(envs.data?.items ?? []).map((env) => (
              <button
                key={env.id}
                type="button"
                data-env={env.name}
                onClick={() =>
                  setEnvIds((prev) =>
                    prev.includes(env.id) ? prev.filter((x) => x !== env.id) : [...prev, env.id],
                  )
                }
                className={cn(
                  "rounded-full border px-2 py-0.5 text-xs font-mono cursor-pointer",
                  envIds.includes(env.id)
                    ? "border-accent text-accent bg-accent-dim/40"
                    : "border-bd text-muted",
                )}
              >
                {env.name} <span className="opacity-70">({env.tier})</span>
              </button>
            ))}
            {envs.data?.items.length === 0 && (
              <span className="text-muted text-xs">This project has no environments yet.</span>
            )}
          </div>
        )}
        {roleId && (
          <p className="text-muted text-xs mb-2">
            Grants the reusable role <Mono>{roleName(roleId)}</Mono>:{" "}
            <Mono>{roles.data?.items.find((r) => r.id === roleId)?.actions.join(", ")}</Mono>
          </p>
        )}
        {!advanced && !roleId && (
          <p className="text-muted text-xs mb-2">
            {PRESETS.find((p) => p.key === presetKey)!.hint} — compiles to{" "}
            <Mono>{PRESETS.find((p) => p.key === presetKey)!.actions.join(", ")}</Mono>
          </p>
        )}
        {advanced && !roleId && (
          <div data-testid="advanced-actions" className="mb-2 flex flex-wrap gap-1.5">
            {ALL_ACTIONS.map((a) => (
              <button
                key={a}
                type="button"
                data-action={a}
                onClick={() =>
                  setActions((prev) => (prev.includes(a) ? prev.filter((x) => x !== a) : [...prev, a]))
                }
                className={cn(
                  "rounded-full border px-2 py-0.5 text-xs font-mono cursor-pointer",
                  actions.includes(a) ? "border-accent text-accent bg-accent-dim/40" : "border-bd text-muted",
                )}
              >
                {a}
              </button>
            ))}
          </div>
        )}
        {create.error && <p className="text-deny text-sm mb-2">{String(create.error)}</p>}
        {grants.data?.items.length === 0 && (
          <p className="text-muted text-sm">
            No grants yet — everything is denied. Pick a subject, a permission, and a scope above
            to open the first door.
          </p>
        )}
        {(grants.data?.items ?? []).length > 0 && (
          <table className="w-full text-sm">
            <tbody>
              {(grants.data?.items as Grant[]).map((g) => {
                const subjectName = nameOf(g.subjectIdentityId ?? g.subjectGroupId);
                return (
                <React.Fragment key={g.id}>
                <tr data-grant-subject={subjectName} className="border-t border-bd align-top">
                  <td className="py-1.5 whitespace-nowrap">
                    {subjectName}
                    {g.subjectGroupId && <span className="ml-1 text-[10px] uppercase text-muted">group</span>}
                  </td>
                  <td className="text-muted px-2">{describeScope(g.scope)}</td>
                  <td>
                    {g.roleId ? (
                      <span className="text-xs">
                        role <Mono>{roleName(g.roleId)}</Mono>
                      </span>
                    ) : (
                      <Mono className="text-xs">{(g.actions ?? []).join(", ")}</Mono>
                    )}
                  </td>
                  <td className="text-right whitespace-nowrap">
                    <Button
                      variant="ghost"
                      data-testid={`edit-grant-${g.id}`}
                      onClick={() => {
                        setEditingGrant(editingGrant === g.id ? null : g.id);
                        setEditGrantRoleId(g.roleId ?? "");
                        setEditGrantActions(g.actions ?? []);
                      }}
                    >
                      {editingGrant === g.id ? "Cancel" : "Edit"}
                    </Button>{" "}
                    <Button variant="danger" data-testid={`revoke-grant-${g.id}`} onClick={() => revoke.mutate(g.id)}>
                      Revoke
                    </Button>
                  </td>
                </tr>
                {editingGrant === g.id && (
                  <tr data-testid={`grant-editor-${g.id}`}>
                    <td colSpan={4} className="pb-2">
                      <div className="space-y-2 rounded border border-bd bg-inset/40 p-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-xs text-muted">
                            Keeps subject and scope; replaces the grant atomically (revoke + create,
                            linked in the audit log).
                          </span>
                          <span className="flex-1" />
                          <Select
                            data-testid={`edit-grant-role-${g.id}`}
                            value={editGrantRoleId}
                            onChange={(v) => setEditGrantRoleId(v)}
                            options={[
                              { value: "", label: "Explicit actions…" },
                              ...(roles.data?.items.map((r) => ({
                                value: r.id,
                                label: `role: ${r.name}`,
                              })) ?? []),
                            ]}
                          />
                          <Button
                            data-testid={`save-grant-${g.id}`}
                            disabled={(!editGrantRoleId && editGrantActions.length === 0) || replace.isPending}
                            onClick={() => replace.mutate(g)}
                          >
                            Replace grant
                          </Button>
                        </div>
                        {!editGrantRoleId && (
                          <div className="flex flex-wrap gap-1.5">
                            {ALL_ACTIONS.map((a) => (
                              <button
                                key={a}
                                type="button"
                                data-edit-grant-action={a}
                                onClick={() =>
                                  setEditGrantActions((prev) =>
                                    prev.includes(a) ? prev.filter((x) => x !== a) : [...prev, a],
                                  )
                                }
                                className={cn(
                                  "rounded-full border px-2 py-0.5 text-xs font-mono cursor-pointer",
                                  editGrantActions.includes(a)
                                    ? "border-accent text-accent bg-accent-dim/40"
                                    : "border-bd text-muted",
                                )}
                              >
                                {a}
                              </button>
                            ))}
                          </div>
                        )}
                        {replace.error && <p className="text-deny text-sm">{String(replace.error)}</p>}
                      </div>
                    </td>
                  </tr>
                )}
                </React.Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
