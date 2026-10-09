// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useLocation, useNavigate } from "react-router-dom";
import { useQueries, useQuery } from "@tanstack/react-query";
import {
  Eye,
  FileText,
  FolderClosed,
  History,
  Keyboard,
  Lock,
  Moon,
  Plug,
  Plus,
  ScrollText,
  Search,
  Settings,
  Sun,
  UserRound,
  Users,
} from "lucide-react";
import type { Tier } from "@varlatch/protocol";
import { useOrgRealtime } from "../lib/realtime";
import { useSession } from "../lib/session";
import { applyTheme } from "../lib/theme";
import { modKey } from "../lib/hotkeys";
import { keys, useCapability, useEnvironments } from "../features/projects/hooks";
import { isTailnetOnly } from "../lib/tailnet";
import { NewProjectDialog } from "../features/projects/NewProjectDialog";
import { NewEnvironmentDialog } from "../features/projects/NewEnvironmentDialog";
import { Highlight, matchesFilter } from "./FilterInput";
import { Kbd, Spinner, TierDot, cn } from "./ui";

/**
 * Cmd/Ctrl+K palette (design R2): grouped, keyboard-first search over
 * metadata the caller may already list (pages, projects, environments) and,
 * on servers with `search.items`, server-side Config Item name search. Names
 * only, never values. Also runs a few actions. Recent entries are kept in
 * localStorage as path and label only.
 */

/** Best-effort platform detection for keycap shortcut hints. */
export function isMacPlatform(): boolean {
  return modKey() === "⌘";
}

type Group = "recent" | "environments" | "projects" | "items" | "pages" | "actions";
const GROUP_TITLES: Record<Group, string> = {
  recent: "Recent",
  environments: "Environments",
  projects: "Projects",
  items: "Config items",
  pages: "Pages",
  actions: "Actions",
};

type Entry = {
  /** Stable id, exposed as data-palette-entry. */
  id: string;
  group: Group;
  label: string;
  mono?: boolean;
  icon: React.ReactNode;
  hint?: string | undefined;
  hintMono?: boolean;
  keys?: string[];
  /** Extra text the filter matches but does not show. */
  search?: string;
  to?: string;
  run?: () => void;
};

const RECENT_KEY = "varlatch:palette-recent";
type Recent = { path: string; label: string };

function readRecent(): Recent[] {
  try {
    const raw = JSON.parse(localStorage.getItem(RECENT_KEY) ?? "[]") as unknown;
    return Array.isArray(raw)
      ? raw.filter((r): r is Recent => typeof r?.path === "string" && typeof r?.label === "string")
      : [];
  } catch {
    return [];
  }
}

/** Remembers a project or environment page by path and label only. */
export function rememberRecent(path: string, label: string): void {
  const next = [{ path, label }, ...readRecent().filter((r) => r.path !== path)].slice(0, 20);
  localStorage.setItem(RECENT_KEY, JSON.stringify(next));
}

/** Project and environment pages, normalized to their landing path. */
function recentFor(pathname: string): Recent | null {
  const m = /^\/o\/([^/]+)\/p\/([^/]+)(?:\/e\/([^/]+))?/.exec(pathname);
  if (!m) return null;
  const [, org, project, env] = m as unknown as [string, string, string, string | undefined];
  if (env) {
    return { path: `/o/${org}/p/${project}/e/${env}`, label: `${project} / ${decodeURIComponent(env)}` };
  }
  return { path: `/o/${org}/p/${project}`, label: project };
}

const PAGES = [
  { key: "projects", label: "Projects", icon: FolderClosed, keys: ["G", "P"] },
  { key: "access", label: "Access", icon: Users, keys: ["G", "A"] },
  { key: "connections", label: "Connections", icon: Plug, keys: ["G", "C"] },
  { key: "audit", label: "Audit log", icon: ScrollText, keys: ["G", "L"] },
  { key: "settings", label: "Settings", icon: Settings, keys: ["G", "S"] },
] as const;

/** Lower is better: exact, prefix, word start, anywhere. */
function score(e: Entry, needle: string): number {
  const label = e.label.toLowerCase();
  const n = needle.trim().toLowerCase();
  if (label === n) return 0;
  if (label.startsWith(n)) return 1;
  if (new RegExp(`(^|[\\s/·:_.-])${n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`).test(label)) return 2;
  return 3;
}

export function CommandPalette() {
  const location = useLocation();
  const navigate = useNavigate();
  const { api } = useSession();
  const route = /^\/o\/([^/]+)(?:\/p\/([^/]+)(?:\/e\/([^/]+))?)?/.exec(location.pathname);
  const org = route?.[1];
  const routeProject = route?.[2];
  const routeEnv = route?.[3] ? decodeURIComponent(route[3]) : undefined;
  useOrgRealtime(org, ["project", "environment"], [["projects", org], ["environments", org]]);

  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [cursor, setCursor] = useState(0);
  const [dialog, setDialog] = useState<null | { kind: "project" } | { kind: "environment"; project: string }>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const restoreRef = useRef<HTMLElement | null>(null);
  const listId = useId();

  // Visits to project and environment pages feed "Recent".
  useEffect(() => {
    const r = recentFor(location.pathname);
    if (r) rememberRecent(r.path, r.label);
  }, [location.pathname]);

  const show = useCallback(() => {
    restoreRef.current = document.activeElement as HTMLElement | null;
    setText("");
    setCursor(0);
    setOpen(true);
  }, []);
  const close = useCallback(() => {
    setOpen(false);
    restoreRef.current?.focus?.();
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && !e.altKey && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (open) close();
        else show();
      }
    };
    window.addEventListener("keydown", onKey);
    window.addEventListener("varlatch:open-palette", show);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("varlatch:open-palette", show);
    };
  }, [open, show, close]);
  useEffect(() => {
    if (open) inputRef.current?.focus();
  }, [open]);

  const projects = useQuery({
    queryKey: keys.projects(org ?? ""),
    queryFn: () => api.listProjects(org as string),
    enabled: open && Boolean(org),
  });
  const projectList = useMemo(
    () => [...(projects.data?.items ?? [])].sort((a, b) => a.slug.localeCompare(b.slug)),
    [projects.data],
  );
  // Lazy and bounded: environments of each project, from the shared cache.
  const envQueries = useQueries({
    queries: projectList.map((p) => ({
      queryKey: keys.environments(org ?? "", p.slug),
      queryFn: () => api.listEnvironments(org as string, p.slug),
      enabled: open && Boolean(org),
    })),
  });
  const routeProjectId = projectList.find((p) => p.slug === routeProject)?.id;
  const routeTailnetOnly = isTailnetOnly(
    envQueries.flatMap((q) => q.data?.items ?? []).find((e) => e.projectId === routeProjectId && e.name === routeEnv),
  );
  // Feature-detect rather than probe: servers without search.items keep
  // the client-side search above.
  const canSearchItems = useCapability("search.items");
  const query = text.trim();
  const itemSearch = useQuery({
    queryKey: ["item-search", org, query],
    queryFn: () => api.searchConfigItems(org as string, { q: query, limit: 8 }),
    enabled: open && canSearchItems && Boolean(org) && query.length >= 2,
    placeholderData: (prev) => prev,
    staleTime: 30_000,
  });

  const theme = typeof document !== "undefined" && document.documentElement.dataset.theme === "light" ? "light" : "dark";

  const groups = ((): { group: Group; entries: Entry[] }[] => {
    if (!open) return [];
    const base = org ? `/o/${org}` : "";
    const pages: Entry[] = [
      ...(org
        ? PAGES.map((p) => ({
            id: `page:${p.key}`,
            group: "pages" as const,
            label: p.label,
            icon: <p.icon size={16} />,
            keys: [...p.keys],
            to: `${base}/${p.key}`,
          }))
        : []),
      { id: "page:account", group: "pages", label: "My account", icon: <UserRound size={16} />, keys: ["G", "M"], to: "/account" },
    ];
    const projectEntries: Entry[] = projectList.map((p) => ({
      id: p.slug,
      group: "projects",
      label: p.slug,
      mono: true,
      icon: <FolderClosed size={16} />,
      hint: p.name !== p.slug ? p.name : undefined,
      to: `${base}/p/${p.slug}`,
    }));
    const envEntries: Entry[] = projectList.flatMap((p, i) =>
      (envQueries[i]?.data?.items ?? []).map((env) => ({
        id: `${p.slug}/${env.name}`,
        group: "environments" as const,
        label: `${p.slug} / ${env.name}`,
        mono: true,
        icon: <TierDot tier={env.tier as Tier} className="mx-1" />,
        hint: `${env.tier} tier`,
        hintMono: true,
        to: `${base}/p/${p.slug}/e/${encodeURIComponent(env.name)}`,
      })),
    );
    // Server-side item hits (metadata only): open the first authorized
    // environment with the item filter filled in.
    const itemEntries: Entry[] =
      query.length >= 2
        ? (itemSearch.data?.items ?? []).flatMap((hit) => {
            const env = hit.environments[0];
            // Previous results stay on screen while the next search runs; keep only those that still match.
            if (!env || !hit.name.toLowerCase().includes(query.toLowerCase())) return [];
            const where = hit.environments.length > 1 ? `in ${hit.environments.length} environments` : `in ${env.name}`;
            return [
              {
                id: `${hit.project.slug}:${hit.name}`,
                group: "items" as const,
                label: `${hit.project.slug} · ${hit.name}`,
                mono: true,
                icon: hit.sensitive ? <Lock size={15} /> : <FileText size={15} />,
                hint: hit.sensitive ? `secret · ${where}` : where,
                hintMono: true,
                search: hit.environments.map((e) => e.name).join(" "),
                to: `${base}/p/${hit.project.slug}/e/${encodeURIComponent(env.name)}?item=${encodeURIComponent(hit.name)}`,
              },
            ];
          })
        : [];
    const actions: Entry[] = [
      ...(org ? [{ id: "action:new-project", group: "actions" as const, label: "New project…", icon: <Plus size={16} />, run: () => setDialog({ kind: "project" }) }] : []),
      ...(org && routeProject
        ? [
            {
              id: "action:new-environment",
              group: "actions" as const,
              label: `New environment in ${routeProject}…`,
              icon: <Plus size={16} />,
              run: () => setDialog({ kind: "environment", project: routeProject }),
            },
          ]
        : []),
      // Not offered where a Tailnet Requirement keeps values out of the dashboard.
      ...(org && routeProject && routeEnv && !routeTailnetOnly
        ? [
            {
              id: "action:reveal",
              group: "actions" as const,
              label: `Reveal secrets in ${routeProject} / ${routeEnv}`,
              icon: <Eye size={16} />,
              hint: "audited",
              to: `${base}/p/${routeProject}/e/${encodeURIComponent(routeEnv)}?reveal=1`,
            },
          ]
        : []),
      {
        id: "action:theme",
        group: "actions",
        label: `Switch to ${theme === "dark" ? "light" : "dark"} theme`,
        icon: theme === "dark" ? <Sun size={16} /> : <Moon size={16} />,
        search: "appearance mode",
        run: () => applyTheme(theme === "dark" ? "light" : "dark"),
      },
      {
        id: "action:shortcuts",
        group: "actions",
        label: "Keyboard shortcuts",
        icon: <Keyboard size={16} />,
        keys: ["?"],
        search: "help keys",
        run: () => window.dispatchEvent(new CustomEvent("varlatch:shortcuts")),
      },
    ];

    if (!query) {
      const recent: Entry[] = readRecent()
        .filter((r) => org && r.path.startsWith(`${base}/`))
        .slice(0, 5)
        .map((r) => ({ id: `recent:${r.path}`, group: "recent", label: r.label, mono: true, icon: <History size={15} />, to: r.path }));
      return [
        { group: "recent" as const, entries: recent },
        { group: "projects" as const, entries: projectEntries.slice(0, 6) },
        { group: "pages" as const, entries: pages },
        { group: "actions" as const, entries: actions },
      ].filter((g) => g.entries.length > 0);
    }
    const pick = (list: Entry[], limit: number) =>
      list
        .filter((e) => matchesFilter(query, e.label, e.hint, e.search))
        .map((e, i) => ({ e, i, s: score(e, query) }))
        .sort((a, b) => a.s - b.s || a.i - b.i)
        .slice(0, limit)
        .map((x) => x.e);
    return [
      { group: "environments" as const, entries: pick(envEntries, 6) },
      { group: "projects" as const, entries: pick(projectEntries, 6) },
      { group: "items" as const, entries: itemEntries },
      { group: "pages" as const, entries: pick(pages, 6) },
      { group: "actions" as const, entries: pick(actions, 6) },
    ].filter((g) => g.entries.length > 0);
  })();

  const flat = groups.flatMap((g) => g.entries);
  useEffect(() => {
    setCursor((c) => (flat.length === 0 ? 0 : Math.min(c, flat.length - 1)));
  }, [flat.length]);
  useEffect(() => {
    listRef.current?.querySelector(`[data-index="${cursor}"]`)?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  const runEntry = (entry: Entry, newTab = false) => {
    if (entry.to) {
      if (newTab) {
        window.open(entry.to, "_blank", "noopener");
        return;
      }
      setOpen(false);
      navigate(entry.to);
      return;
    }
    setOpen(false);
    entry.run?.();
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setCursor((c) => (flat.length ? (c + 1) % flat.length : 0));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setCursor((c) => (flat.length ? (c - 1 + flat.length) % flat.length : 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const entry = flat[cursor];
      if (entry) runEntry(entry, e.metaKey || e.ctrlKey);
    } else if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      if (text) setText("");
      else close();
    } else if (e.key === "Tab") {
      e.preventDefault();
    }
  };

  const mod = modKey();
  let index = -1;
  const searching = itemSearch.isFetching && query.length >= 2;

  return (
    <>
      {open &&
        createPortal(
          <div className="fixed inset-0 z-[70] flex items-start justify-center p-4 pt-[12vh]">
            <div className="fixed inset-0 animate-fade-in bg-overlay backdrop-blur-[2px]" aria-hidden="true" onMouseDown={close} />
            <div
              role="dialog"
              aria-modal="true"
              aria-label="Command palette"
              data-testid="command-palette"
              className="relative flex max-h-[70vh] w-full max-w-[640px] animate-pop-in flex-col overflow-hidden rounded-xl border border-bd bg-raised shadow-pop"
            >
              <div className="flex items-center gap-3 border-b border-bd px-4">
                <Search size={18} className="shrink-0 text-muted" />
                <input
                  ref={inputRef}
                  data-testid="palette-input"
                  role="combobox"
                  aria-expanded="true"
                  aria-controls={listId}
                  aria-activedescendant={flat[cursor] ? `${listId}-${cursor}` : undefined}
                  aria-label="Search projects, environments, items, pages and actions"
                  autoComplete="off"
                  spellCheck={false}
                  className="h-14 min-w-0 flex-1 bg-transparent text-[16px] text-fg placeholder:text-subtle focus:outline-none focus-visible:outline-none"
                  placeholder={canSearchItems ? "Search projects, environments, items…" : "Search projects, environments, pages…"}
                  value={text}
                  onChange={(e) => {
                    setText(e.target.value);
                    setCursor(0);
                  }}
                  onKeyDown={onKeyDown}
                />
                {searching && <Spinner />}
                <Kbd>esc</Kbd>
              </div>
              <div ref={listRef} id={listId} role="listbox" aria-label="Results" className="min-h-0 flex-1 overflow-y-auto py-2">
                {groups.map((g, gi) => (
                  <div key={g.group} role="group" aria-label={GROUP_TITLES[g.group]} className={cn(gi > 0 && "mt-1 border-t border-bd pt-1")}>
                    <div className="px-5 pb-1.5 pt-2.5 text-[11px] font-semibold uppercase tracking-wider text-subtle" aria-hidden="true">
                      {GROUP_TITLES[g.group]}
                    </div>
                    {g.entries.map((entry) => {
                      index += 1;
                      const i = index;
                      const active = i === cursor;
                      return (
                        <div
                          key={entry.id}
                          id={`${listId}-${i}`}
                          role="option"
                          aria-selected={active}
                          data-index={i}
                          data-palette-entry={entry.id}
                          // mousemove, not mouseenter: keyboard scrolling moves rows under a
                          // still pointer and must not steal the selection.
                          onMouseMove={() => setCursor(i)}
                          onMouseDown={(e) => e.preventDefault()}
                          onClick={(e) => runEntry(entry, e.metaKey || e.ctrlKey)}
                          className={cn(
                            "mx-2 flex h-10 cursor-pointer items-center gap-3 rounded-lg px-3 text-sm",
                            active ? "bg-accent-dim text-fg" : "text-fg/90",
                          )}
                        >
                          <span className={cn("flex w-4 shrink-0 items-center justify-center", active ? "text-fg" : "text-muted")}>
                            {entry.icon}
                          </span>
                          <span className={cn("min-w-0 flex-1 truncate", entry.mono && "font-mono text-[13.5px]")}>
                            <Highlight text={entry.label} needle={query} />
                          </span>
                          {entry.hint && (
                            <span className={cn("max-w-[45%] shrink-0 truncate text-muted", entry.hintMono ? "font-mono text-[12px]" : "text-[12.5px]")}>
                              <Highlight text={entry.hint} needle={query} />
                            </span>
                          )}
                          {entry.keys && !active && (
                            <span className="flex shrink-0 items-center gap-1">
                              {entry.keys.map((k) => (
                                <Kbd key={k}>{k}</Kbd>
                              ))}
                            </span>
                          )}
                          {active && (
                            <span
                              aria-hidden="true"
                              className="inline-flex h-6 min-w-6 shrink-0 items-center justify-center rounded-md border border-accent/40 bg-raised/60 px-1 font-mono text-[11px] text-fg"
                            >
                              ↵
                            </span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                ))}
                {flat.length === 0 && (
                  <p className="px-5 py-8 text-center text-[13px] text-muted">
                    {query ? (
                      <>
                        Nothing matches <span className="font-mono text-fg">{query}</span>.
                      </>
                    ) : (
                      "Loading…"
                    )}
                  </p>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-x-5 gap-y-1 border-t border-bd px-4 py-2.5 text-xs text-muted">
                <span className="inline-flex items-center gap-1.5">
                  <Kbd>↑</Kbd>
                  <Kbd>↓</Kbd> navigate
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <Kbd>↵</Kbd> open
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <Kbd>{mod}</Kbd>
                  <Kbd>↵</Kbd> new tab
                </span>
                <span className="ml-auto inline-flex items-center gap-1.5">
                  <Kbd>{mod === "⌘" ? "⌘K" : "Ctrl K"}</Kbd> toggle
                </span>
              </div>
            </div>
          </div>,
          document.body,
        )}
      {org && dialog?.kind === "project" && <NewProjectDialog org={org} open onClose={() => setDialog(null)} />}
      {org && dialog?.kind === "environment" && (
        <PaletteEnvironmentDialog org={org} project={dialog.project} onClose={() => setDialog(null)} />
      )}
    </>
  );
}

/** Mounts the shared dialog once the project's environments are known. */
function PaletteEnvironmentDialog({ org, project, onClose }: { org: string; project: string; onClose: () => void }) {
  const envs = useEnvironments(org, project);
  if (!envs.data) return null;
  return <NewEnvironmentDialog org={org} project={project} environments={envs.data.items} open onClose={onClose} />;
}
