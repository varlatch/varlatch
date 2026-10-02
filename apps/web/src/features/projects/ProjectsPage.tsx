// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowUpRight, Check, MoreHorizontal, Pencil, Plus, TriangleAlert } from "lucide-react";
import type { Project, Tier } from "@varlatch/protocol";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { timeAgo, formatDateTime, useNow } from "../../lib/time";
import { Avatar, Badge, Button, Callout, Count, Kbd, Menu, Skeleton, TierDot, cn } from "../../components/ui";
import { usePrompt } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { PageHeader } from "../../components/PageHeader";
import { FilterInput, Highlight, isTypingTarget, matchesFilter, useListNavigation } from "../../components/FilterInput";
import { errorMessage } from "../../shell/Shell";
import { keys, useCapability, useOrgName, useProjects } from "./hooks";
import type { EnvHealth } from "./health";
import { useProjectSummary, useSeen } from "./projectSummary";
import { useAuditFilters, useIdentityNames, useProjectLastChange } from "./lastChange";
import { NewProjectDialog } from "./NewProjectDialog";
import { NewEnvironmentDialog } from "./NewEnvironmentDialog";
import { Onboarding, useOnboarding } from "./Onboarding";

/**
 * Projects landing: one compact row per project with environment health
 * from metadata, and the house filter as the way in ("/" focuses, ↑↓ select,
 * ↵ opens). A new organization sees the getting-started steps instead.
 */
export function ProjectsPage() {
  const { org } = useParams() as { org: string };
  useOrgRealtime(org, ["project", "environment", "contract", "value"], [
    keys.projects(org),
    ["environments", org],
    ["contract", org],
    ["effective-meta", org],
    ["project-last-change", org],
  ]);
  const orgName = useOrgName(org);
  const projects = useProjects(org);
  const all = useMemo(() => projects.data?.items ?? [], [projects.data]);
  const onboarding = useOnboarding(org, projects.data ? all : undefined);
  // Create from the header opens the new project; from the getting-started
  // steps it stays here so the next step is in view.
  const [creating, setCreating] = useState<null | "open" | "stay">(null);

  const breadcrumbs = [{ label: orgName ?? org, to: `/o/${org}/projects` }, { label: "Projects" }];
  const newButton = (
    <Button
      variant="primary"
      icon={<Plus size={15} />}
      data-testid="new-project"
      aria-label="New project"
      title="New project"
      onClick={() => setCreating("open")}
    >
      <span className="max-lg:sr-only">New project</span>
    </Button>
  );
  const dialog = (
    <NewProjectDialog
      org={org}
      open={creating !== null}
      onClose={() => setCreating(null)}
      onCreated={creating === "stay" ? () => undefined : undefined}
    />
  );

  if (projects.isPending || (!onboarding.ready && all.length <= 1)) {
    return (
      <>
        <PageHeader breadcrumbs={breadcrumbs} title="Projects" />
        <ListSkeleton />
        {dialog}
      </>
    );
  }
  if (projects.isError) {
    return (
      <>
        <PageHeader breadcrumbs={breadcrumbs} title="Projects" />
        <Callout tone="danger" title="Projects could not be loaded">
          {errorMessage(projects.error)}
        </Callout>
      </>
    );
  }

  // A new organization gets the steps as its page; an established one with
  // an unfinished loop keeps its list and shows the steps above it.
  if (onboarding.visible && all.length <= 1) {
    return (
      <>
        <PageHeader
          breadcrumbs={breadcrumbs}
          title={`Welcome to ${orgName ?? org}`}
          subtitle="Four steps to your first secret-free deploy."
          actions={all.length > 0 ? newButton : undefined}
        />
        <Onboarding org={org} state={onboarding} variant="page" onNewProject={() => setCreating("stay")} />
        {all.length > 0 && (
          <section className="mt-10">
            <h2 className="mb-3 flex items-center gap-2 text-[15px] font-semibold">
              Projects <Count>{all.length}</Count>
            </h2>
            <ProjectList org={org} projects={all} />
          </section>
        )}
        {dialog}
      </>
    );
  }

  return (
    <>
      <PageHeader
        breadcrumbs={breadcrumbs}
        title="Projects"
        badges={<Count className="h-6 min-w-6 px-2 text-xs">{all.length}</Count>}
        actions={newButton}
      />
      {onboarding.visible && (
        <Onboarding org={org} state={onboarding} variant="card" onNewProject={() => setCreating("stay")} />
      )}
      <ProjectList org={org} projects={all} />
      {dialog}
    </>
  );
}

/** The filter, the rows and the keyboard hints. */
function ProjectList({ org, projects }: { org: string; projects: Project[] }) {
  const navigate = useNavigate();
  const now = useNow(60_000);
  const canRename = useCapability("projects.rename");
  const showUpdated = useAuditFilters();
  const names = useIdentityNames(org, showUpdated);
  const [filter, setFilter] = useState("");
  const [focused, setFocused] = useState(false);
  const [keyboard, setKeyboard] = useState(false);

  const sorted = useMemo(() => [...projects].sort((a, b) => a.slug.localeCompare(b.slug)), [projects]);
  const matches = useMemo(() => sorted.filter((p) => matchesFilter(filter, p.slug, p.name)), [sorted, filter]);
  const open = useCallback(
    (p: Project, { newTab }: { newTab: boolean }) => {
      const to = `/o/${org}/p/${p.slug}`;
      if (newTab) window.open(to, "_blank", "noopener");
      else navigate(to);
    },
    [org, navigate],
  );
  const nav = useListNavigation(matches, open);
  const keyboardRef = useRef(false);

  // ↑↓↵ also work while nothing in particular has focus.
  const { onKeyDown } = nav;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!["ArrowDown", "ArrowUp", "Enter"].includes(e.key)) return;
      if (isTypingTarget(e.target) || (document.activeElement && document.activeElement !== document.body)) return;
      if (document.querySelector('[role="dialog"][aria-modal="true"]')) return;
      if (!keyboardRef.current) {
        // The first arrow shows the selection where it is; Enter needs a shown selection.
        if (e.key === "Enter") return;
        e.preventDefault();
        setKeyboard(true);
        keyboardRef.current = true;
        return;
      }
      onKeyDown(e as unknown as React.KeyboardEvent);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onKeyDown]);

  const selecting = focused || keyboard;
  const grid = showUpdated
    ? "@min-[860px]:grid-cols-[auto_minmax(0,max-content)_auto_minmax(0,1fr)_auto_auto_auto]"
    : "@min-[860px]:grid-cols-[auto_minmax(0,max-content)_auto_minmax(0,1fr)_auto_auto]";

  return (
    <div>
      <div
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        onMouseDown={() => {
          setKeyboard(false);
          keyboardRef.current = false;
        }}
      >
        <FilterInput
          size="lg"
          value={filter}
          onChange={setFilter}
          shown={matches.length}
          total={projects.length}
          noun="project"
          placeholder="Filter projects…"
          aria-label="Filter projects"
          data-testid="project-filter"
          countTestId="project-filter-count"
          onKeyDown={nav.onKeyDown}
        />
      </div>
      <div className="@container mt-4 overflow-hidden rounded-xl border border-bd bg-raised">
        {matches.length === 0 ? (
          <div className="px-5 py-10 text-center text-[13px] text-muted" data-testid="project-filter-empty">
            No project matches <span className="font-mono text-fg">{filter.trim()}</span>.{" "}
            <button type="button" className="link cursor-pointer" onClick={() => setFilter("")}>
              Clear the filter
            </button>
          </div>
        ) : (
          <ul
            ref={(el) => {
              nav.listRef.current = el;
            }}
            aria-label="Projects"
            className={cn("@min-[860px]:grid", grid)}
          >
            {matches.map((p, i) => (
              <ProjectRow
                key={p.id}
                org={org}
                project={p}
                filter={filter}
                active={selecting && i === nav.active}
                navProps={nav.itemProps(i)}
                canRename={canRename}
                showUpdated={showUpdated}
                names={names}
                now={now}
              />
            ))}
          </ul>
        )}
      </div>
      <p className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-2 text-xs text-muted" aria-hidden="true">
        <span className="inline-flex items-center gap-1.5">
          <Kbd>↑</Kbd>
          <Kbd>↓</Kbd> select
        </span>
        <span className="inline-flex items-center gap-1.5">
          <Kbd>↵</Kbd> open
        </span>
        <span className="inline-flex items-center gap-1.5">
          <Kbd>esc</Kbd> clear
        </span>
      </p>
    </div>
  );
}

function ProjectRow({
  org,
  project,
  filter,
  active,
  navProps,
  canRename,
  showUpdated,
  names,
  now,
}: {
  org: string;
  project: Project;
  filter: string;
  active: boolean;
  navProps: { "data-nav-index": number; "data-active": true | undefined; onMouseMove: () => void };
  canRename: boolean;
  showUpdated: boolean;
  names: Map<string, string> | null;
  now: number;
}) {
  const [seenRef, seen] = useSeen<HTMLLIElement>();
  const summary = useProjectSummary(org, project, seen);
  const last = useProjectLastChange(org, project, seen);
  const [addingEnv, setAddingEnv] = useState(false);
  const prompt = usePrompt();
  const toast = useToast();
  const { api } = useSession();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const to = `/o/${org}/p/${project.slug}`;

  const rename = useMutation({
    mutationFn: (name: string) => api.renameProject(org, project.slug, name),
    onSuccess: async (p) => {
      await qc.invalidateQueries({ queryKey: keys.projects(org) });
      toast.success(`Renamed to ${p.name}`, { description: `The slug stays ${project.slug}.` });
    },
    onError: (err) => toast.error("Could not rename the project", { description: errorMessage(err) }),
  });
  const promptRename = async () => {
    const next = await prompt({
      title: `Rename ${project.slug}`,
      description: `This changes the display name only. The slug stays ${project.slug} in URLs, the CLI and contracts.`,
      label: "Display name",
      initialValue: project.name,
      confirmLabel: "Rename",
    });
    if (next && next !== project.name) rename.mutate(next);
  };

  const actor = last.data?.actorIdentityId ? (names?.get(last.data.actorIdentityId) ?? null) : null;
  const cell = "@min-[860px]:flex @min-[860px]:items-center";

  return (
    <li
      ref={seenRef}
      {...navProps}
      data-testid="project-row"
      data-slug={project.slug}
      className={cn(
        "group relative flex items-start gap-2 border-b border-bd px-4 py-3.5 transition-colors last:border-b-0",
        "@min-[860px]:col-span-full @min-[860px]:grid @min-[860px]:grid-cols-subgrid @min-[860px]:items-center @min-[860px]:gap-x-5 @min-[860px]:py-3",
        active ? "bg-hover" : "hover:bg-hover/50",
      )}
    >
      {active && <span aria-hidden="true" className="absolute inset-y-0 left-0 w-0.5 bg-accent" />}
      <Link
        to={to}
        data-testid="project-link"
        className={cn(
          "flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-2.5 rounded-md",
          "@min-[860px]:col-[1/-2] @min-[860px]:grid @min-[860px]:grid-cols-subgrid @min-[860px]:gap-x-5",
        )}
      >
        <span className="min-w-0 max-w-64 truncate font-mono text-[15px] font-semibold text-fg">
          <Highlight text={project.slug} needle={filter} />
        </span>
        <span className={cn("min-w-0 truncate text-[13.5px] text-muted", project.name === project.slug && "@max-[859px]:hidden")}>
          {project.name !== project.slug && <Highlight text={project.name} needle={filter} />}
        </span>
        <span className={cell}>
          <Badge className="h-[22px] px-2 text-xs" title={project.contractAuthority === "git" ? "The contract lives in git" : "The contract is edited in Varlatch"}>
            {project.contractAuthority}
          </Badge>
        </span>
        <span className="order-2 flex basis-full flex-wrap items-center gap-2 @min-[860px]:order-none @min-[860px]:basis-auto">
          <EnvironmentPills summary={summary} />
        </span>
        <span className="order-1 ml-auto text-[13px] tabular-nums text-muted @min-[860px]:order-none @min-[860px]:ml-0 @min-[860px]:text-right">
          {summary.items === undefined ? (
            <Skeleton className="inline-block h-3.5 w-14 align-middle" />
          ) : summary.items === 0 && summary.contract === "none" ? (
            "no contract"
          ) : (
            `${summary.items} item${summary.items === 1 ? "" : "s"}`
          )}
        </span>
        {showUpdated && (
          <span className="order-1 hidden min-w-0 items-center gap-2 text-[13px] text-muted @min-[600px]:flex @min-[860px]:order-none">
            {last.data ? (
              <span className="inline-flex items-center gap-2" title={`${formatDateTime(last.data.at)}${actor ? ` by ${actor}` : ""}`}>
                {actor && <Avatar name={actor} size="xs" />}
                updated {timeAgo(last.data.at, now)}
              </span>
            ) : last.isPending && seen ? (
              <Skeleton className="h-3.5 w-24" />
            ) : null}
          </span>
        )}
      </Link>
      <div className="flex shrink-0 items-center justify-end gap-2 @min-[860px]:col-[-2/-1]">
        {/* Always laid out so selecting a row never shifts the columns. */}
        <span
          aria-hidden="true"
          className={cn(
            "hidden items-center gap-1 rounded-md border border-bd bg-inset px-1.5 py-0.5 text-[11px] text-muted @min-[860px]:inline-flex",
            !active && "invisible",
          )}
        >
          ↵ open
        </span>
        <Menu
          data-testid="project-menu"
          label={`Actions for ${project.slug}`}
          width="w-52"
          buttonClassName="size-8 justify-center border border-bd bg-raised hover:border-bd-strong"
          items={[
            {
              label: "Open",
              icon: <ArrowUpRight size={15} />,
              "data-testid": "menu-open-project",
              onSelect: () => navigate(to),
            },
            {
              label: "New environment…",
              icon: <Plus size={15} />,
              "data-testid": "menu-new-environment",
              disabled: summary.envsLoading,
              onSelect: () => setAddingEnv(true),
            },
            ...(canRename
              ? [
                  {
                    label: "Rename…",
                    icon: <Pencil size={14} />,
                    "data-testid": "menu-rename-project",
                    onSelect: () => void promptRename(),
                  },
                ]
              : []),
          ]}
        >
          <MoreHorizontal size={16} />
        </Menu>
      </div>
      {addingEnv && (
        <NewEnvironmentDialog
          org={org}
          project={project.slug}
          environments={summary.environments}
          open
          onClose={() => setAddingEnv(false)}
        />
      )}
    </li>
  );
}

function EnvironmentPills({ summary }: { summary: ReturnType<typeof useProjectSummary> }) {
  if (summary.envsLoading) {
    return (
      <>
        <Skeleton className="h-7 w-28" />
        <Skeleton className="h-7 w-24" />
      </>
    );
  }
  if (summary.envsError) return <span className="text-[13px] text-subtle">Environments unavailable</span>;
  if (summary.roots.length === 0) return <span className="text-[13px] text-subtle">No environments</span>;
  return (
    <>
      {summary.health.map(({ env, health }) => (
        <EnvPill key={env.id} name={env.name} tier={env.tier as Tier} health={health} />
      ))}
      {summary.derived > 0 && (
        <span
          className="text-xs text-muted"
          title={`${summary.derived} personal or preview environment${summary.derived === 1 ? "" : "s"}`}
        >
          +{summary.derived}
        </span>
      )}
    </>
  );
}

function EnvPill({ name, tier, health }: { name: string; tier: Tier; health: EnvHealth }) {
  const title =
    health.state === "ok"
      ? `${name}: every required item has a value`
      : health.state === "missing"
        ? `${name}: no value for ${health.items.join(", ")}`
        : health.state === "no-contract"
          ? `${name}: no active contract yet`
          : `${name} (${tier})`;
  return (
    <span
      title={title}
      data-env={name}
      data-health={health.state}
      className="inline-flex h-7 max-w-full items-center gap-2 rounded-md border border-bd bg-inset/50 px-2.5 text-[12.5px] text-fg"
    >
      <TierDot tier={tier} />
      <span className="truncate">{name}</span>
      {health.state === "ok" && (
        <>
          <Check size={14} className="shrink-0 text-allow" aria-hidden="true" />
          <span className="sr-only">ready</span>
        </>
      )}
      {health.state === "missing" && (
        <span className="inline-flex shrink-0 items-center gap-1 text-deny">
          <TriangleAlert size={13} aria-hidden="true" />
          {health.items.length} missing
        </span>
      )}
      {health.state === "loading" && <Skeleton className="h-3 w-3 rounded-full" />}
    </span>
  );
}

function ListSkeleton() {
  return (
    <div aria-busy="true" aria-label="Loading projects">
      <Skeleton className="h-11 w-full rounded-lg" />
      <div className="mt-4 overflow-hidden rounded-xl border border-bd bg-raised">
        {[0, 1, 2].map((i) => (
          <div key={i} className="flex items-center gap-5 border-b border-bd px-4 py-4 last:border-b-0">
            <Skeleton className="h-4 w-28" />
            <Skeleton className="h-4 w-20" />
            <Skeleton className="h-6 w-14" />
            <Skeleton className="h-7 w-28" />
            <Skeleton className="h-7 w-24" />
          </div>
        ))}
      </div>
    </div>
  );
}
