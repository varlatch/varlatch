// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { MoreHorizontal, Search } from "lucide-react";
import type { Environment, Project, Tier, ValidationReport } from "@varlatch/protocol";
import { validationSummary } from "./validationSummary";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { Button, Card, InfoTip, Input, Menu, Mono, Select, TierChip } from "../../components/ui";
import { OnboardingChecklist } from "./Onboarding";

/**
 * P1 Projects landing: list + create + per-project environments with
 * validation. P2 replaces the per-project block with the config matrix.
 */
export function ProjectsPage() {
  const { org } = useParams();
  useOrgRealtime(org, ["project", "environment"], [["projects", org], ["environments", org]]);
  const { api } = useSession();
  const qc = useQueryClient();
  const projects = useQuery({
    queryKey: ["projects", org],
    queryFn: () => api.listProjects(org as string),
  });
  const [slug, setSlug] = useState("");
  const [authority, setAuthority] = useState<"git" | "managed">("git");
  const [filter, setFilter] = useState("");
  const create = useMutation({
    mutationFn: () =>
      api.createProject(org as string, { slug, name: slug, contractAuthority: authority }),
    onSuccess: () => {
      setSlug("");
      void qc.invalidateQueries({ queryKey: ["projects", org] });
    },
  });

  const all = projects.data?.items ?? [];
  /** Client-side filter over name + slug only — same posture as the palette:
      no server-side search surface, never any value or secret content. */
  const matches = useMemo(() => {
    const sorted = [...all].sort((a, b) =>
      a.name.localeCompare(b.name) || a.slug.localeCompare(b.slug),
    );
    const needle = filter.trim().toLowerCase();
    if (!needle) return sorted;
    return sorted.filter(
      (p) =>
        p.name.toLowerCase().includes(needle) || p.slug.toLowerCase().includes(needle),
    );
  }, [all, filter]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <h1 className="text-lg font-semibold">Projects</h1>
        <div className="flex gap-2 items-center">
          <Input
            data-testid="new-project-slug"
            placeholder="project-slug"
            value={slug}
            onChange={(e) => setSlug(e.target.value.toLowerCase())}
          />
          <Select
            aria-label="Contract authority"
            value={authority}
            onChange={(v) => setAuthority(v as "git" | "managed")}
            options={[
              {
                value: "git",
                label: "git contract",
                description:
                  "Git: the schema lives in your repo as .env.schema, pushed with `varlatch contract push` — the repo is the source of truth.",
              },
              {
                value: "managed",
                label: "managed contract",
                description:
                  "Managed: edit and publish the contract in this dashboard — Varlatch is the source of truth.",
              },
            ]}
          />
          <InfoTip text="Each project has exactly one contract authority; there is never bidirectional sync between them. Pick git when the schema should live and be reviewed next to code; pick managed when the dashboard is the authoring surface." />
          <Button data-testid="create-project" disabled={!slug || create.isPending} onClick={() => create.mutate()}>
            Create project
          </Button>
        </div>
      </div>
      {create.error && <p className="text-deny text-sm">{String(create.error)}</p>}
      {projects.data && <OnboardingChecklist org={org as string} projects={all} />}
      {all.length > 0 && (
        <ProjectFilter value={filter} onChange={setFilter} shown={matches.length} total={all.length} />
      )}
      {projects.data?.items.length === 0 && (
        <Card>
          <p className="font-medium mb-2">No projects yet</p>
          <p className="text-muted text-sm">
            Create one above, then connect a repository:{" "}
            <Mono className="text-accent">varlatch init --org {org} --project &lt;slug&gt;</Mono>
          </p>
        </Card>
      )}
      {all.length > 0 && matches.length === 0 && (
        <Card>
          <p className="text-muted text-sm">
            No project matches <Mono className="text-fg">{filter}</Mono>.{" "}
            <button className="text-accent hover:underline cursor-pointer" onClick={() => setFilter("")}>
              Clear filter
            </button>
          </p>
        </Card>
      )}
      {matches.map((p) => (
        <ProjectCard key={p.id} org={org as string} project={p} highlight={filter.trim()} />
      ))}
    </div>
  );
}

/** Filter box for the project list. "/" focuses it from anywhere on the page,
    matching the Cmd+K palette's keyboard-first posture (design R2). */
function ProjectFilter({
  value,
  onChange,
  shown,
  total,
}: {
  value: string;
  onChange: (v: string) => void;
  shown: number;
  total: number;
}) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey) return;
      const el = e.target as HTMLElement | null;
      const tag = el?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el?.isContentEditable) return;
      e.preventDefault();
      ref.current?.focus();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="flex items-center gap-2">
      <div className="relative flex-1">
        <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted pointer-events-none" />
        <Input
          ref={ref}
          data-testid="project-filter"
          aria-label="Filter projects"
          className="w-full pl-8"
          placeholder="Filter projects by name or slug…   /"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape") {
              onChange("");
              e.currentTarget.blur();
            }
          }}
        />
      </div>
      <span className="text-xs text-muted tabular-nums shrink-0" data-testid="project-filter-count">
        {value.trim() ? `${shown} of ${total}` : `${total} project${total === 1 ? "" : "s"}`}
      </span>
    </div>
  );
}

/** Renders `text` with every case-insensitive occurrence of `needle` marked. */
function Highlight({ text, needle }: { text: string; needle: string }) {
  if (!needle) return <>{text}</>;
  const parts: React.ReactNode[] = [];
  const hay = text.toLowerCase();
  const find = needle.toLowerCase();
  let at = 0;
  for (let i = hay.indexOf(find); i >= 0; i = hay.indexOf(find, at)) {
    if (i > at) parts.push(text.slice(at, i));
    parts.push(
      <mark key={i} className="bg-accent-dim text-fg rounded-sm px-0.5">
        {text.slice(i, i + needle.length)}
      </mark>,
    );
    at = i + needle.length;
  }
  parts.push(text.slice(at));
  return <>{parts}</>;
}

function ProjectCard({
  org,
  project,
  highlight,
}: {
  org: string;
  project: Project;
  highlight: string;
}) {
  const { api } = useSession();
  const qc = useQueryClient();
  const envs = useQuery({
    queryKey: ["environments", org, project.slug],
    queryFn: () => api.listEnvironments(org, project.slug),
  });
  const [reports, setReports] = useState<Record<string, ValidationReport>>({});
  const [envName, setEnvName] = useState("");
  const [tier, setTier] = useState<Tier>("development");
  const [addingEnv, setAddingEnv] = useState(false);
  const createEnv = useMutation({
    mutationFn: () => api.createEnvironment(org, project.slug, { name: envName, tier }),
    onSuccess: () => {
      setEnvName("");
      setAddingEnv(false);
      void qc.invalidateQueries({ queryKey: ["environments", org, project.slug] });
    },
  });
  const validate = async (env: Environment) => {
    const report = await api.validateEnvironment(org, project.slug, env.name);
    setReports((r) => ({ ...r, [env.id]: report }));
  };
  const deleteEnv = useMutation({
    mutationFn: (env: Environment) => api.deleteEnvironment(org, project.slug, env.name),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["environments", org, project.slug] }),
    onError: (err) => window.alert(err instanceof Error ? err.message : String(err)),
  });
  const confirmDelete = (env: Environment) => {
    // ADR-0025: production-tier roots require re-typing the name; everything
    // else gets a plain confirm. Deletion is final — no undelete.
    if (env.tier === "production" && !env.parentEnvironmentId) {
      const typed = window.prompt(
        `${env.name} is production-tier. Type the environment name to delete it permanently:`,
      );
      if (typed !== env.name) return;
    } else if (!window.confirm(`Delete environment ${env.name}? This cannot be undone.`)) {
      return;
    }
    deleteEnv.mutate(env);
  };

  const envCount = envs.data?.items.length;

  return (
    <Card data-testid="project-card" data-slug={project.slug}>
      <div className="flex items-baseline gap-2 flex-wrap mb-3">
        {/* The slug is the identity the CLI, URLs and contracts all use, so it
            leads; the display name follows only when it adds something. */}
        <h2 className="text-base font-semibold font-mono">
          <Link className="hover:text-accent" to={`/o/${org}/p/${project.slug}`}>
            <Highlight text={project.slug} needle={highlight} />
          </Link>
        </h2>
        {project.name !== project.slug && (
          <span className="text-sm text-muted">
            <Highlight text={project.name} needle={highlight} />
          </span>
        )}
        <span className="text-xs text-muted border border-bd rounded-full px-2 py-0.5">
          {project.contractAuthority}
        </span>
        {envCount !== undefined && (
          <span className="text-xs text-muted ml-auto">
            {envCount} environment{envCount === 1 ? "" : "s"}
          </span>
        )}
        <Menu
          data-testid="project-menu"
          label={`Actions for ${project.slug}`}
          className="self-center"
          items={[
            {
              label: "Add environment",
              "data-testid": "menu-add-environment",
              onSelect: () => setAddingEnv(true),
            },
          ]}
        >
          <MoreHorizontal size={16} />
        </Menu>
      </div>
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-muted border-b border-bd">
            <th className="py-1.5 font-medium">Environment</th>
            <th className="py-1.5 font-medium">Tier</th>
            <th className="py-1.5 font-medium">Kind</th>
            <th className="py-1.5 font-medium">Contract</th>
            <th className="py-1.5" />
          </tr>
        </thead>
        <tbody>
          {envs.data?.items.map((env) => {
            const report = reports[env.id];
            return (
              <tr key={env.id} className="border-b border-bd/50">
                <td className="py-1.5">
                  <Link className="font-mono text-[13px] hover:text-accent" to={`/o/${org}/p/${project.slug}/e/${encodeURIComponent(env.name)}`}>
                    {env.name}
                  </Link>
                </td>
                <td className="py-1.5"><TierChip tier={env.tier as Tier} /></td>
                <td className="py-1.5 text-muted">{env.kind}</td>
                <td className="py-1.5">
                  {report ? (
                    <ValidationCell report={report} />
                  ) : (
                    <Button variant="ghost" onClick={() => void validate(env)}>validate</Button>
                  )}
                </td>
                <td className="py-1.5 text-right">
                  <Button variant="ghost" disabled={deleteEnv.isPending} onClick={() => confirmDelete(env)}>
                    delete
                  </Button>
                </td>
              </tr>
            );
          })}
          {addingEnv && (
            <tr>
              <td className="py-2">
                <Input
                  autoFocus
                  placeholder="environment name"
                  value={envName}
                  onChange={(e) => setEnvName(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Escape") setAddingEnv(false);
                  }}
                />
              </td>
              <td className="py-2">
                <Select
                  aria-label="Environment tier"
                  value={tier}
                  onChange={(v) => setTier(v as Tier)}
                  options={[
                    { value: "development", label: "development" },
                    { value: "staging", label: "staging" },
                    { value: "production", label: "production" },
                  ]}
                />
              </td>
              <td colSpan={3} className="py-2">
                <Button variant="ghost" disabled={!envName || createEnv.isPending} onClick={() => createEnv.mutate()}>
                  add environment
                </Button>
                <Button variant="ghost" className="ml-1" onClick={() => setAddingEnv(false)}>
                  cancel
                </Button>
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </Card>
  );
}

function ValidationCell({ report }: { report: ValidationReport }) {
  const summary = validationSummary(report);
  if (summary.state === "valid") return <span className="allow text-allow">valid</span>;
  const notEvaluated =
    summary.notEvaluated.length > 0 ? (
      <span
        className="text-muted"
        title="Your access does not cover these values (Secrets need secret.reveal), so they were not checked."
      >
        {" "}
        · not evaluated: {summary.notEvaluated.join(", ")}
      </span>
    ) : null;
  if (summary.state === "invalid") {
    return (
      <span>
        <span className="deny text-deny">invalid: {summary.failing.join(", ")}</span>
        {notEvaluated}
      </span>
    );
  }
  return (
    <span>
      <span className="text-muted">incomplete</span>
      {notEvaluated}
    </span>
  );
}
