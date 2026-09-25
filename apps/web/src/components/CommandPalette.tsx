// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Search } from "lucide-react";
import type { Environment, Project } from "@varlatch/protocol";
import { useOrgRealtime } from "../lib/realtime";
import { useSession } from "../lib/session";
import { Mono, cn } from "./ui";

/**
 * Cmd/Ctrl+K palette (design R2): client-side search over navigation,
 * projects, and environments the caller is already authorized to list —
 * plus, on servers advertising the search.items capability, server-side
 * Config Item name search (ADR-0030). Names only, never values.
 */
/** Best-effort platform detection for keycap shortcut hints. */
export function isMacPlatform(): boolean {
  return /mac|iphone|ipad/i.test(
    (navigator as { userAgentData?: { platform?: string } }).userAgentData?.platform ??
      navigator.platform,
  );
}

/** Keycap-styled key hint. */
function Key({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="rounded border border-bd bg-inset px-1 py-px font-mono text-[10px] leading-none">
      {children}
    </kbd>
  );
}

export function CommandPalette() {
  const { org } = useParams();
  const { api } = useSession();
  useOrgRealtime(org, ["project", "environment"], [["projects", org], ["palette-envs", org]]);
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);

  // Keep the active entry visible while arrowing through a scrolled list.
  useEffect(() => {
    listRef.current
      ?.querySelectorAll("li")
      [cursor]?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((v) => !v);
        setText("");
        setCursor(0);
      }
      if (e.key === "Escape") setOpen(false);
    };
    // The sidebar "Search" affordance opens the palette without the shortcut.
    const onOpen = () => {
      setText("");
      setCursor(0);
      setOpen(true);
    };
    window.addEventListener("keydown", onKey);
    window.addEventListener("varlatch:open-palette", onOpen);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("varlatch:open-palette", onOpen);
    };
  }, []);
  useEffect(() => {
    if (open) inputRef.current?.focus();
  }, [open]);

  const projects = useQuery({
    queryKey: ["projects", org],
    queryFn: () => api.listProjects(org as string),
    enabled: open && Boolean(org),
  });
  const envQueries = useQuery({
    queryKey: ["palette-envs", org, projects.data?.items.length],
    queryFn: async () => {
      const all = await Promise.all(
        (projects.data?.items ?? []).map(async (p: Project) => {
          const envs = await api.listEnvironments(org as string, p.slug);
          return envs.items.map((e: Environment) => ({ project: p.slug, env: e.name }));
        }),
      );
      return all.flat();
    },
    enabled: open && Boolean(projects.data),
  });
  // Feature-detect rather than probe: skewed self-hosted servers without
  // search.items degrade to the client-side filtering above.
  const meta = useQuery({
    queryKey: ["meta"],
    queryFn: () => api.meta(),
    staleTime: Infinity,
    enabled: open,
  });
  const canSearchItems = meta.data?.capabilities.includes("search.items") ?? false;
  const itemSearch = useQuery({
    queryKey: ["item-search", org, text],
    queryFn: () => api.searchConfigItems(org as string, { q: text, limit: 8 }),
    enabled: open && canSearchItems && Boolean(org) && text.length >= 2,
    placeholderData: (prev) => prev,
  });

  const entries = useMemo(() => {
    const nav = ["projects", "access", "audit", "settings"].map((n) => ({
      label: n,
      hint: "page",
      to: `/o/${org}/${n}`,
    }));
    const projectEntries = (projects.data?.items ?? []).map((p: Project) => ({
      label: p.slug,
      hint: "project",
      to: `/o/${org}/p/${p.slug}`,
    }));
    const envEntries = (envQueries.data ?? []).map((e) => ({
      label: `${e.project}/${e.env}`,
      hint: "environment",
      to: `/o/${org}/p/${e.project}/e/${encodeURIComponent(e.env)}`,
    }));
    // Server-side item hits (metadata only): jump straight into the first
    // authorized environment's editor with the filter prefilled.
    const itemEntries =
      text.length >= 2
        ? (itemSearch.data?.items ?? []).flatMap((hit) => {
            const env = hit.environments[0];
            if (!env) return [];
            return [
              {
                label: `${hit.project.slug}:${hit.name}`,
                hint:
                  hit.environments.length > 1
                    ? `item · ${hit.environments.length} environments`
                    : `item · ${env.name}`,
                to: `/o/${org}/p/${hit.project.slug}/e/${encodeURIComponent(env.name)}?item=${encodeURIComponent(hit.name)}`,
              },
            ];
          })
        : [];
    const all = [...nav, ...projectEntries, ...envEntries];
    if (!text) return all.slice(0, 12);
    const needle = text.toLowerCase();
    const navigation = all.filter((e) => e.label.toLowerCase().includes(needle));
    return [...navigation, ...itemEntries].slice(0, 12);
  }, [org, projects.data, envQueries.data, itemSearch.data, text]);

  if (!open) return null;
  const go = (to: string) => {
    setOpen(false);
    navigate(to);
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-black/50 flex items-start justify-center pt-32"
      onClick={() => setOpen(false)}
    >
      <div
        data-testid="command-palette"
        className="w-[480px] rounded-lg border border-bd bg-raised shadow-xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 px-3 border-b border-bd">
          <Search size={14} className="text-muted" />
          <input
            ref={inputRef}
            data-testid="palette-input"
            className="w-full bg-transparent py-2.5 text-sm focus:outline-none"
            placeholder={
              canSearchItems
                ? "Jump to a project, environment, item, or page…"
                : "Jump to a project, environment, or page…"
            }
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              setCursor(0);
            }}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") setCursor((c) => Math.min(c + 1, entries.length - 1));
              if (e.key === "ArrowUp") setCursor((c) => Math.max(c - 1, 0));
              if (e.key === "Enter" && entries[cursor]) go(entries[cursor].to);
            }}
          />
        </div>
        <ul ref={listRef} className="max-h-72 overflow-y-auto py-1">
          {entries.map((e, i) => (
            <li key={e.to}>
              <button
                data-palette-entry={e.label}
                className={cn(
                  "w-full flex items-center justify-between px-3 py-1.5 text-sm text-left cursor-pointer",
                  i === cursor ? "bg-accent-dim" : "hover:bg-inset",
                )}
                // mousemove, not mouseenter: keyboard-driven scrolling moves
                // rows under a stationary pointer and must not steal the cursor.
                onMouseMove={() => setCursor(i)}
                onClick={() => go(e.to)}
              >
                <Mono>{e.label}</Mono>
                <span className="text-xs text-muted">{e.hint}</span>
              </button>
            </li>
          ))}
          {entries.length === 0 && <li className="px-3 py-2 text-sm text-muted">No matches.</li>}
        </ul>
        <div className="flex items-center gap-3 border-t border-bd px-3 py-1.5 text-[11px] text-muted">
          <span className="inline-flex items-center gap-1"><Key>↑↓</Key> navigate</span>
          <span className="inline-flex items-center gap-1"><Key>↵</Key> open</span>
          <span className="inline-flex items-center gap-1"><Key>esc</Key> close</span>
          <span className="ml-auto inline-flex items-center gap-1">
            <Key>{isMacPlatform() ? "⌘K" : "Ctrl K"}</Key> toggle
          </span>
        </div>
      </div>
    </div>
  );
}
