// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, ChevronDown, KeyRound, Pencil, Trash2 } from "lucide-react";
import type { Grant, GrantScope, Tier } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { timeAgo, useNow } from "../../lib/time";
import {
  Avatar,
  Badge,
  Button,
  EmptyState,
  IconButton,
  SectionCard,
  Select,
  TierDot,
  cn,
} from "../../components/ui";
import { useConfirm } from "../../components/Dialog";
import { FilterInput, matchesFilter } from "../../components/FilterInput";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";
import { ALL_ACTIONS, PRESETS, TIERS, useIdentities } from "./shared";
import {
  ACTION_GROUPS,
  ACTION_INFO,
  KIND_LABEL,
  KindIcon,
  actionLabel,
  grantSentence,
  permissionPhrase,
  scopeParts,
  type SubjectKind,
} from "./model";
import { useAccessNames } from "./useAccessNames";

/**
 * Grants: the single source of permission. The builder reads as one
 * sentence (subject can permission on scope in environments); presets and
 * roles are conveniences that compile to an ordinary grant. Editing a grant
 * is an atomic replace that keeps subject and scope.
 */

type Permission = { kind: "preset"; key: string } | { kind: "role"; id: string } | { kind: "custom" };

export function GrantsTab({ org }: { org: string }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const [searchParams] = useSearchParams();
  const identities = useIdentities(org);
  const grants = useQuery({ queryKey: ["grants", org], queryFn: () => api.listGrants(org) });
  const roles = useQuery({ queryKey: ["roles", org], queryFn: () => api.listRoles(org) });
  const groups = useQuery({ queryKey: ["groups", org], queryFn: () => api.listGroups(org) });
  const teams = useQuery({ queryKey: ["teams", org], queryFn: () => api.listTeams(org) });
  const { names, nameOf, roleName, projects, environments } = useAccessNames(org);
  const [filter, setFilter] = useState("");

  // Builder state.
  const [subject, setSubject] = useState("");
  const [permission, setPermission] = useState<Permission>({ kind: "preset", key: PRESETS[0]!.key });
  const [customActions, setCustomActions] = useState<string[]>(PRESETS[0]!.actions);
  const [scope, setScope] = useState("org"); // org | project:<id> | team:<id>
  const [envScope, setEnvScope] = useState("all"); // all | tier:<tier> | pick
  const [envIds, setEnvIds] = useState<string[]>([]);
  const [showActions, setShowActions] = useState(false);

  useEffect(() => {
    const s = searchParams.get("subject");
    if (s) setSubject(s.startsWith("grp_") || s.startsWith("tem_") ? `grp:${s}` : `idn:${s}`);
    const p = searchParams.get("project");
    if (p) setScope(`project:${p}`);
  }, [searchParams]);

  const subjectOptions = [
    ...(identities.data?.items ?? [])
      .filter((i) => !i.disabled)
      .map((i) => ({ value: `idn:${i.id}`, label: i.name, description: KIND_LABEL[i.kind], icon: <KindIcon kind={i.kind} size={15} /> })),
    ...(groups.data?.items ?? []).map((g) => ({ value: `grp:${g.id}`, label: g.name, description: "group", icon: <KindIcon kind="group" size={15} /> })),
    ...(teams.data?.items ?? []).map((t) => ({ value: `grp:${t.id}`, label: t.name, description: "team", icon: <KindIcon kind="team" size={15} /> })),
  ];
  const permValue = permission.kind === "preset" ? `preset:${permission.key}` : permission.kind === "role" ? `role:${permission.id}` : "custom";
  const effectiveActions =
    permission.kind === "preset"
      ? PRESETS.find((p) => p.key === permission.key)!.actions
      : permission.kind === "role"
        ? (roles.data?.items.find((r) => r.id === permission.id)?.actions ?? [])
        : customActions;
  const projectId = scope.startsWith("project:") ? scope.slice(8) : "";
  const projectEnvs = environments.filter((e) => e.projectId === projectId);

  const grantScope: GrantScope | null = (() => {
    if (scope === "org") return { kind: "organization" };
    if (scope.startsWith("team:")) return { kind: "team", teamId: scope.slice(5) };
    if (!projectId) return null;
    if (envScope === "all") return { kind: "project", projectId };
    if (envScope.startsWith("tier:")) return { kind: "environments", projectId, selector: { kind: "tier", tier: envScope.slice(5) as Tier } };
    if (envIds.length === 0) return null;
    return { kind: "environments", projectId, selector: { kind: "environments", environmentIds: envIds } };
  })();

  const create = useMutation({
    mutationFn: () => {
      const id = subject.slice(4);
      const subj = subject.startsWith("grp:") ? { subjectGroupId: id } : { subjectIdentityId: id };
      const perm = permission.kind === "role" ? { roleId: permission.id } : { actions: effectiveActions };
      return api.createGrant(org, { ...subj, scope: grantScope!, ...perm });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["grants", org] });
      toast.success("Access granted", { description: `${subjectOptions.find((o) => o.value === subject)?.label ?? "Subject"} · ${permissionPhrase(effectiveActions, permission.kind === "role" ? roleName(permission.id) : null)}` });
    },
    onError: (err) => toast.error("Could not create the grant", { description: errorMessage(err) }),
  });
  const ready = subject !== "" && grantScope !== null && effectiveActions.length > 0;

  const all = (grants.data?.items ?? []) as Grant[];
  const grouped = useMemo(() => {
    const map = new Map<string, Grant[]>();
    for (const g of all) {
      const key = g.subjectIdentityId ?? g.subjectGroupId ?? "unknown";
      map.set(key, [...(map.get(key) ?? []), g]);
    }
    return [...map.entries()];
  }, [all]);
  const visible = grouped
    .map(([key, list]) => [key, list.filter((g) => matchesFilter(filter, nameOf(key), permissionPhrase(g.actions, roleName(g.roleId)), scopeParts(g.scope, names).map((p) => p.label).join(" ")))] as const)
    .filter(([, list]) => list.length > 0);

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-bd bg-raised p-5" data-testid="grants-section">
        <div className="flex flex-wrap items-center gap-x-2.5 gap-y-2.5 text-[15px]">
          <SubjectIcon value={subject} identities={identities.data?.items ?? []} />
          <Select
            data-testid="grant-subject"
            aria-label="Who"
            className="min-w-52"
            value={subject}
            onChange={setSubject}
            placeholder="Choose who…"
            options={subjectOptions}
          />
          <span className="text-muted">can</span>
          <Select
            data-testid="grant-permission"
            aria-label="Permission"
            className="min-w-60"
            value={permValue}
            onChange={(v) => {
              if (v.startsWith("preset:")) {
                const key = v.slice(7);
                setPermission({ kind: "preset", key });
                setCustomActions(PRESETS.find((p) => p.key === key)!.actions);
              } else if (v.startsWith("role:")) setPermission({ kind: "role", id: v.slice(5) });
              else {
                setPermission({ kind: "custom" });
                setShowActions(true);
              }
            }}
            options={[
              ...PRESETS.map((p) => ({ value: `preset:${p.key}`, label: p.label, description: p.hint })),
              ...(roles.data?.items ?? []).map((r) => ({ value: `role:${r.id}`, label: r.name, description: `Role · ${r.actions.length} actions` })),
              { value: "custom", label: "Custom actions…", description: "Pick actions one by one" },
            ]}
          />
          <span className="text-muted">on</span>
          <Select
            data-testid="grant-scope"
            aria-label="Scope"
            className="min-w-44"
            value={scope}
            onChange={(v) => {
              setScope(v);
              setEnvScope("all");
              setEnvIds([]);
            }}
            options={[
              { value: "org", label: "the whole organization" },
              ...projects.map((p) => (p.name !== p.slug ? { value: `project:${p.id}`, label: p.slug, description: p.name } : { value: `project:${p.id}`, label: p.slug })),
              ...(teams.data?.items ?? []).map((t) => ({ value: `team:${t.id}`, label: `${t.name}'s projects`, description: "Every project the team owns, now and later" })),
            ]}
          />
          {projectId && (
            <>
              <span className="text-muted">in</span>
              <Select
                data-testid="grant-env-scope"
                aria-label="Environments"
                className="min-w-44"
                value={envScope}
                onChange={(v) => {
                  setEnvScope(v);
                  setEnvIds([]);
                }}
                options={[
                  { value: "all", label: "all environments" },
                  ...TIERS.map((t) => ({ value: `tier:${t}`, label: `${t} tier`, icon: <TierDot tier={t} /> })),
                  { value: "pick", label: "specific environments…" },
                ]}
              />
            </>
          )}
          <span className="flex-1" />
          <Button variant="primary" data-testid="create-grant" disabled={!ready} loading={create.isPending} onClick={() => create.mutate()}>
            Grant access
          </Button>
        </div>
        {projectId && envScope === "pick" && (
          <div data-testid="grant-environments" className="mt-3 flex flex-wrap items-center gap-2">
            {projectEnvs.map((env) => {
              const on = envIds.includes(env.id);
              return (
                <button
                  key={env.id}
                  type="button"
                  data-env={env.name}
                  aria-pressed={on}
                  onClick={() => setEnvIds((prev) => (on ? prev.filter((x) => x !== env.id) : [...prev, env.id]))}
                  className={cn(
                    "inline-flex cursor-pointer items-center gap-2 rounded-md border px-2.5 py-1 font-mono text-[12.5px] transition-colors",
                    on ? "border-accent bg-accent/10 text-fg" : "border-bd text-muted hover:border-bd-strong hover:text-fg",
                  )}
                >
                  {on ? <Check size={13} className="text-accent" /> : <TierDot tier={env.tier as Tier} />}
                  {env.name}
                </button>
              );
            })}
            {projectEnvs.length === 0 && <span className="text-[13px] text-muted">This project has no environments yet.</span>}
          </div>
        )}
        <div className="mt-3 flex flex-wrap items-center gap-2 text-[13px] text-muted">
          <span>
            Compiles to {effectiveActions.length} action{effectiveActions.length === 1 ? "" : "s"}
            {permission.kind === "role" && " through the role; editing the role later updates this grant"}
          </span>
          <button
            type="button"
            data-testid="toggle-advanced"
            onClick={() => setShowActions((v) => !v)}
            className="inline-flex cursor-pointer items-center gap-1 rounded-md border border-bd px-2 py-0.5 text-xs text-fg hover:bg-hover"
          >
            {showActions ? "Hide actions" : "Show actions"}
            <ChevronDown size={12} className={cn("transition-transform", showActions && "rotate-180")} />
          </button>
        </div>
        {showActions && (
          <ActionPicker
            testId="advanced-actions"
            dataAttr="action"
            value={effectiveActions}
            readOnly={permission.kind !== "custom"}
            onChange={(next) => {
              setPermission({ kind: "custom" });
              setCustomActions(next);
            }}
          />
        )}
      </section>

      <SectionCard
        title="Active grants"
        description="Explicit grants. People also get the built-in grants of their organization role: Admins can do everything; Members get development read, write and reveal, staging read and reveal, and production item names only."
        actions={
          <FilterInput
            className="w-72"
            value={filter}
            onChange={setFilter}
            placeholder="Filter grants…"
            aria-label="Filter grants"
          />
        }
      >
        {all.length === 0 ? (
          <EmptyState
            icon={<KeyRound size={20} />}
            title="No grants yet"
            description="Everything is denied. Build the first sentence above to open the first door."
          />
        ) : visible.length === 0 ? (
          <p className="px-5 py-6 text-center text-[13px] text-muted">No grant matches “{filter}”.</p>
        ) : (
          <div>
            {visible.map(([subjectId, list]) => (
              <SubjectGroup key={subjectId} org={org} subjectId={subjectId} grants={list} />
            ))}
          </div>
        )}
      </SectionCard>
    </div>
  );
}

function SubjectIcon({ value, identities }: { value: string; identities: { id: string; kind: SubjectKind }[] }) {
  const id = value.slice(4);
  const kind: SubjectKind | null = value.startsWith("idn:")
    ? (identities.find((i) => i.id === id)?.kind ?? null)
    : value.startsWith("grp:")
      ? "group"
      : null;
  return (
    <span className="flex size-9 items-center justify-center rounded-lg border border-bd bg-inset text-muted">
      {kind ? <KindIcon kind={kind} size={18} /> : <KeyRound size={17} />}
    </span>
  );
}

function SubjectGroup({ org, subjectId, grants }: { org: string; subjectId: string; grants: Grant[] }) {
  const identities = useIdentities(org);
  const { api } = useSession();
  const teams = useQuery({ queryKey: ["teams", org], queryFn: () => api.listTeams(org) });
  const { nameOf } = useAccessNames(org);
  const now = useNow();
  const identity = identities.data?.items.find((i) => i.id === subjectId);
  const isTeam = teams.data?.items.some((t) => t.id === subjectId);
  const kind: SubjectKind = identity?.kind ?? (isTeam ? "team" : "group");
  const name = nameOf(subjectId);
  return (
    <div data-grant-subject={name} className="border-b border-bd last:border-b-0">
      <div className="flex items-center gap-3 px-5 pb-1 pt-3.5">
        {identity?.kind === "human" ? (
          <Avatar name={identity.name} image={identity.image ?? null} size="sm" />
        ) : (
          <KindIcon kind={kind} size={17} className="text-muted" />
        )}
        <span className="font-semibold">{name}</span>
        <Badge className="font-mono">{KIND_LABEL[kind]}</Badge>
        {identity && (
          <span className="text-xs text-muted" title="The subject's last activity; grants do not record usage.">
            {identity.lastSeenAt ? `active ${timeAgo(identity.lastSeenAt, now)}` : "never active"}
          </span>
        )}
      </div>
      <ul className="pb-2">
        {grants.map((g) => (
          <GrantRow key={g.id} org={org} grant={g} subjectName={name} />
        ))}
      </ul>
    </div>
  );
}

function GrantRow({ org, grant: g, subjectName }: { org: string; grant: Grant; subjectName: string }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const toast = useToast();
  const roles = useQuery({ queryKey: ["roles", org], queryFn: () => api.listRoles(org) });
  const { names, roleName } = useAccessNames(org);
  const [editing, setEditing] = useState(false);
  const [editRoleId, setEditRoleId] = useState(g.roleId ?? "");
  const [editActions, setEditActions] = useState<string[]>(g.actions ?? []);
  const phrase = permissionPhrase(g.actions, roleName(g.roleId));
  const parts = scopeParts(g.scope, names);
  const revoke = useMutation({
    mutationFn: () => api.deleteGrant(org, g.id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["grants", org] }),
    onError: (err) => toast.error("Could not revoke the grant", { description: errorMessage(err) }),
  });
  const replace = useMutation({
    mutationFn: () =>
      api.replaceGrant(org, g.id, {
        ...(g.subjectIdentityId ? { subjectIdentityId: g.subjectIdentityId } : {}),
        ...(g.subjectGroupId ? { subjectGroupId: g.subjectGroupId } : {}),
        scope: g.scope,
        ...(editRoleId ? { roleId: editRoleId } : { actions: editActions }),
      }),
    onSuccess: () => {
      setEditing(false);
      void qc.invalidateQueries({ queryKey: ["grants", org] });
    },
  });
  const sentence = grantSentence(g, subjectName, phrase, names);
  return (
    <li className="group px-5">
      <div className="flex flex-wrap items-center gap-2 rounded-lg px-2 py-2 -mx-2 hover:bg-hover/60" title={sentence}>
        <span className="text-[13px] text-muted">can</span>
        <span className="rounded-md border border-bd bg-inset px-2 py-0.5 text-[13px] font-medium text-fg" title={(g.actions ?? []).join(", ")}>
          {phrase}
          {g.roleId && <span className="ml-1.5 text-xs font-normal text-muted">role</span>}
        </span>
        <span className="text-[13px] text-muted">on</span>
        {parts.map((p, i) => (
          <React.Fragment key={i}>
            {i === 1 && g.scope.kind !== "organization" && g.scope.kind !== "team" && <span className="text-[13px] text-muted">in</span>}
            <span className={cn("inline-flex items-center gap-1.5 rounded-md border border-bd bg-inset px-2 py-0.5 text-[13px]", p.mono && "font-mono text-[12.5px]")}>
              {p.tier && <TierDot tier={p.tier} />}
              {p.label}
            </span>
          </React.Fragment>
        ))}
        <span className="sr-only">{(g.actions ?? []).join(", ")}</span>
        <span className="flex-1" />
        <span className="flex items-center gap-1 opacity-60 transition-opacity group-hover:opacity-100 focus-within:opacity-100">
          <IconButton size="sm" label="Edit grant" data-testid={`edit-grant-${g.id}`} onClick={() => setEditing((v) => !v)}>
            <Pencil size={14} />
          </IconButton>
          <IconButton
            size="sm"
            tone="danger"
            label="Revoke grant"
            data-testid={`revoke-grant-${g.id}`}
            onClick={async () => {
              const ok = await confirm({
                title: "Revoke this grant?",
                description: sentence,
                consequences: [{ text: "It stops applying on the next request. Other grants of this subject stay in place." }],
                confirmLabel: "Revoke grant",
                tone: "danger",
              });
              if (ok) revoke.mutate();
            }}
          >
            <Trash2 size={14} />
          </IconButton>
        </span>
      </div>
      {editing && (
        <div data-testid={`grant-editor-${g.id}`} className="mb-3 space-y-3 rounded-lg border border-bd bg-inset p-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[13px] text-muted">Keep who and where; change what:</span>
            <Select
              data-testid={`edit-grant-role-${g.id}`}
              className="min-w-52"
              value={editRoleId}
              onChange={setEditRoleId}
              aria-label="Permission"
              options={[
                { value: "", label: "Explicit actions" },
                ...(roles.data?.items ?? []).map((r) => ({ value: r.id, label: r.name, description: "role" })),
              ]}
            />
            <span className="flex-1" />
            <Button size="sm" variant="ghost" onClick={() => setEditing(false)}>
              Cancel
            </Button>
            <Button
              size="sm"
              variant="primary"
              data-testid={`save-grant-${g.id}`}
              loading={replace.isPending}
              disabled={!editRoleId && editActions.length === 0}
              onClick={() => replace.mutate()}
            >
              Replace grant
            </Button>
          </div>
          {!editRoleId && <ActionPicker dataAttr="edit-grant-action" value={editActions} onChange={setEditActions} />}
          <p className="text-xs text-muted">Replacing is atomic: the old grant is revoked and the new one created in one step, linked in the audit log.</p>
          {replace.error && <p className="text-sm text-deny">{errorMessage(replace.error)}</p>}
        </div>
      )}
    </li>
  );
}

/** Actions grouped by area, labelled in plain English with the action name underneath. */
export function ActionPicker({
  value,
  onChange,
  readOnly = false,
  dataAttr,
  testId,
}: {
  value: string[];
  onChange: (next: string[]) => void;
  readOnly?: boolean;
  dataAttr: string;
  testId?: string;
}) {
  return (
    <div data-testid={testId} className="mt-3 grid gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-3">
      {ACTION_GROUPS.map((group) => {
        const actions = ALL_ACTIONS.filter((a) => ACTION_INFO[a]?.group === group);
        if (actions.length === 0) return null;
        return (
          <div key={group}>
            <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-subtle">{group}</p>
            <div className="space-y-1">
              {actions.map((a) => {
                const on = value.includes(a);
                return (
                  <button
                    key={a}
                    type="button"
                    {...{ [`data-${dataAttr}`]: a }}
                    aria-pressed={on}
                    disabled={readOnly}
                    title={ACTION_INFO[a]?.description}
                    onClick={() => onChange(on ? value.filter((x) => x !== a) : [...value, a])}
                    className={cn(
                      "flex w-full cursor-pointer items-start gap-2.5 rounded-md px-2 py-1.5 text-left transition-colors disabled:cursor-default",
                      on ? "bg-accent/[0.08]" : "hover:bg-hover",
                    )}
                  >
                    <span
                      className={cn(
                        "mt-0.5 flex size-4 shrink-0 items-center justify-center rounded border",
                        on ? "border-accent bg-accent text-accent-fg" : "border-bd-strong",
                      )}
                    >
                      {on && <Check size={11} strokeWidth={3} />}
                    </span>
                    <span className="min-w-0">
                      <span className="block text-[13px] text-fg">{actionLabel(a)}</span>
                      <span className="block font-mono text-[11px] text-muted">{a}</span>
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}
