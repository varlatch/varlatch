// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useMemo, useState } from "react";
import { keepPreviousData, useInfiniteQuery } from "@tanstack/react-query";
import { FileText, ShieldAlert, X } from "lucide-react";
import type { AuditEventFilters } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { dayLabel } from "../../lib/time";
import { FilterInput, matchesFilter, useListNavigation } from "../../components/FilterInput";
import { Button, EmptyState, Select, Skeleton, Spinner, cn } from "../../components/ui";
import { Drawer } from "../../components/Drawer";
import { useCapability, useProjects } from "../projects/hooks";
import { describeEvent, segmentsText, type AuditEventLike } from "./describe";
import { ActorMark, DecisionBadge, EventIconGlyph, SentenceText, actorOf, clock, sameDelivery, type AuditEvent } from "./parts";
import { useAuditNames } from "./useAuditNames";
import { AuditDetail } from "./AuditDetail";

/**
 * The audit timeline: plain-English events grouped by day, newest first,
 * served from the authoritative /v1 store with cursor paging. Facets query
 * the server when it supports audit filters; otherwise they filter the
 * loaded pages and say so. Used by the Audit page and the project and
 * environment Activity tabs (with a fixed scope).
 */

export type AuditFilterState = {
  text: string;
  actor: string;
  project: string;
  decision: "" | "allow" | "deny" | "info";
  range: "" | "1h" | "24h" | "7d" | "30d";
};

export const NO_FILTERS: AuditFilterState = { text: "", actor: "", project: "", decision: "", range: "" };

export type AuditScope = { projectId?: string | undefined; environmentId?: string | undefined; item?: string | undefined };

const RANGE_MS: Record<Exclude<AuditFilterState["range"], "">, number> = {
  "1h": 3_600_000,
  "24h": 86_400_000,
  "7d": 7 * 86_400_000,
  "30d": 30 * 86_400_000,
};

/** The start of a time range, rounded to the minute so query keys stay stable. */
export function rangeStart(range: AuditFilterState["range"], now = Date.now()): string | undefined {
  if (!range) return undefined;
  return new Date(Math.floor((now - RANGE_MS[range]) / 60_000) * 60_000).toISOString();
}

/** What the server filters on: facets plus the fixed scope. */
export function serverFilters(filters: AuditFilterState, scope: AuditScope, since: string | undefined): AuditEventFilters {
  const out: AuditEventFilters = {};
  if (filters.decision) out.decision = filters.decision;
  if (filters.actor) out.actorIdentityId = filters.actor;
  const project = scope.projectId ?? filters.project;
  if (project) out.projectId = project;
  if (scope.environmentId) out.environmentId = scope.environmentId;
  if (scope.item) out.item = scope.item;
  if (since) out.since = since;
  return out;
}

type Line = {
  event: AuditEvent;
  described: ReturnType<typeof describeEvent>;
  actor: ReturnType<typeof actorOf>;
  projectId: string | undefined;
  related: AuditEvent[];
  haystack: string;
};

/** True when the timeline filters only what is loaded (no server filters). */
export function useServerFiltering(): boolean {
  return useCapability("audit.filters");
}

function useWide(query = "(min-width: 1280px)"): boolean {
  const [wide, setWide] = useState(() => matchMedia(query).matches);
  useEffect(() => {
    const mq = matchMedia(query);
    const on = () => setWide(mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, [query]);
  return wide;
}

const RANGE_OPTIONS = [
  { value: "", label: "Any time" },
  { value: "1h", label: "Last hour" },
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
];

/** A facet as a chip: "Decision: all ▾", accent when set, with a clear button. */
function Facet({
  label,
  value,
  options,
  onChange,
  testId,
  allValue = "",
}: {
  label: string;
  value: string;
  options: { value: string; label: string }[];
  onChange: (v: string) => void;
  testId?: string;
  allValue?: string;
}) {
  const active = value !== allValue;
  return (
    <span className="inline-flex items-center">
      <Select
        size="md"
        prefix={label ? `${label}:` : undefined}
        value={value}
        onChange={onChange}
        options={options}
        data-testid={testId}
        aria-label={label || "Time range"}
        buttonClassName={cn(
          "h-8 rounded-lg",
          active && "border-accent/60 bg-accent/[0.06] text-fg",
          active && label && "rounded-r-none border-r-0",
        )}
      />
      {active && label && (
        <button
          type="button"
          aria-label={`Clear ${label.toLowerCase()} filter`}
          onClick={() => onChange(allValue)}
          className="inline-flex h-8 cursor-pointer items-center rounded-r-lg border border-l-0 border-accent/60 bg-accent/[0.06] pl-0.5 pr-2 text-muted hover:text-fg"
        >
          <X size={13} />
        </button>
      )}
    </span>
  );
}

export function AuditTimeline({
  org,
  filters,
  onFiltersChange,
  scope = {},
  facets = ["actor", "project", "decision", "range"],
  pageSize = 100,
  className,
  emptyHint,
}: {
  org: string;
  filters: AuditFilterState;
  onFiltersChange: (next: AuditFilterState) => void;
  scope?: AuditScope;
  facets?: ("actor" | "project" | "decision" | "range")[];
  pageSize?: number;
  className?: string;
  emptyHint?: React.ReactNode;
}) {
  const { api } = useSession();
  const server = useServerFiltering();
  const projects = useProjects(org);
  const { names, identities, identityById } = useAuditNames(org);
  const since = useMemo(() => rangeStart(filters.range), [filters.range]);
  const remote = server ? serverFilters(filters, scope, since) : {};

  const history = useInfiniteQuery({
    queryKey: ["audit", org, remote],
    queryFn: ({ pageParam }) =>
      api.listAuditEvents(org, { limit: pageSize, ...remote, ...(pageParam ? { cursor: pageParam } : {}) }),
    initialPageParam: "",
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    // Changing a facet keeps the current lines on screen until the new ones arrive.
    placeholderData: keepPreviousData,
  });

  const loaded = useMemo(
    () => (history.data?.pages.flatMap((p) => p.items) ?? []) as AuditEvent[],
    [history.data],
  );

  // Lines are described once per load; filtering then works on plain text.
  // One automatic push records several events (prepared, started, result):
  // they fold into one line and stay listed in its details.
  const lines = useMemo(() => {
    const out: Line[] = [];
    for (const event of loaded) {
      const prev = out[out.length - 1];
      if (prev && sameDelivery(prev.event, event)) {
        prev.related.push(event);
        continue;
      }
      const described = describeEvent(event, names);
      const actor = actorOf(event, identityById);
      const r = (event.resource ?? {}) as Record<string, unknown>;
      const env = names.environment(r.environmentId as string | undefined);
      const projectId = (r.projectId as string | undefined) ?? env?.projectId;
      out.push({
        event,
        described,
        actor,
        projectId,
        related: [],
        haystack: [
          actor.name,
          segmentsText(described.segments),
          described.title,
          event.eventType,
          event.action ?? "",
          String((event.metadata as Record<string, unknown> | undefined)?.items ?? ""),
        ].join(" "),
      });
    }
    return out;
  }, [loaded, names, identityById]);

  const sinceMs = since ? Date.parse(since) : undefined;
  const visible = lines.filter((l) => {
    if (!server) {
      if (filters.decision && l.event.decision !== filters.decision) return false;
      if (filters.actor && l.event.actorIdentityId !== filters.actor) return false;
      const project = scope.projectId ?? filters.project;
      if (project && l.projectId !== project) return false;
      if (scope.environmentId && (l.event.resource as Record<string, unknown> | undefined)?.environmentId !== scope.environmentId) return false;
      if (scope.item && !l.haystack.includes(scope.item)) return false;
      if (sinceMs !== undefined && Date.parse(l.event.occurredAt) < sinceMs) return false;
    }
    return matchesFilter(filters.text, l.haystack);
  });

  const localFacets = !server && (filters.decision || filters.actor || filters.project || filters.range || scope.projectId || scope.environmentId);
  const filteringLoaded = Boolean(filters.text.trim()) || Boolean(localFacets);

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = lines.find((l) => l.event.eventId === selectedId) ?? null;
  const nav = useListNavigation(visible, (l) => setSelectedId(l.event.eventId));
  const wide = useWide();

  const set = (patch: Partial<AuditFilterState>) => onFiltersChange({ ...filters, ...patch });
  const anyFilter = filters.text || filters.actor || filters.project || filters.decision || filters.range;

  // Group consecutive events by calendar day.
  const groups: { day: string; rows: { line: (typeof visible)[number]; index: number }[] }[] = [];
  visible.forEach((line, index) => {
    const day = dayLabel(line.event.occurredAt);
    const last = groups[groups.length - 1];
    if (last && last.day === day) last.rows.push({ line, index });
    else groups.push({ day, rows: [{ line, index }] });
  });

  const detail = selected && (
    <AuditDetail
      org={org}
      event={selected.event}
      described={selected.described}
      actor={selected.actor}
      related={selected.related}
      names={names}
      onClose={() => setSelectedId(null)}
      onFilterActor={facets.includes("actor") ? (id) => set({ actor: id }) : undefined}
      bare={!wide}
    />
  );

  return (
    <div className={className}>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <FilterInput
          value={filters.text}
          onChange={(text) => set({ text })}
          placeholder="Filter events…"
          className="min-w-56 flex-1"
          data-testid="audit-filter"
          aria-label="Filter events"
          onKeyDown={nav.onKeyDown}
        />
        {facets.includes("actor") && (
          <Facet
            label="Actor"
            value={filters.actor}
            onChange={(actor) => set({ actor })}
            testId="audit-actor"
            options={[
              { value: "", label: "anyone" },
              ...[...identities]
                .sort((a, b) => a.name.localeCompare(b.name))
                .map((i) => ({ value: i.id, label: i.name })),
            ]}
          />
        )}
        {facets.includes("project") && !scope.projectId && (
          <Facet
            label="Project"
            value={filters.project}
            onChange={(project) => set({ project })}
            testId="audit-project"
            options={[
              { value: "", label: "all" },
              ...(projects.data?.items ?? []).map((p) => ({ value: p.id, label: p.slug })),
            ]}
          />
        )}
        {facets.includes("decision") && (
          <Facet
            label="Decision"
            value={filters.decision}
            onChange={(decision) => set({ decision: decision as AuditFilterState["decision"] })}
            testId="audit-decision"
            options={[
              { value: "", label: "all" },
              { value: "allow", label: "allow" },
              { value: "deny", label: "deny" },
              { value: "info", label: "info" },
            ]}
          />
        )}
        {facets.includes("range") && (
          <Facet
            label=""
            value={filters.range}
            onChange={(range) => set({ range: range as AuditFilterState["range"] })}
            testId="audit-range"
            options={RANGE_OPTIONS}
          />
        )}
      </div>
      {filteringLoaded && (
        <p className="-mt-1 mb-3 text-xs text-muted" data-testid="audit-local-filter">
          {localFacets
            ? "Filtering loaded events only: this server cannot filter its full history, so load older events to look further back."
            : "Filtering loaded events by text."}
        </p>
      )}

      <div className={cn("flex items-start gap-4")}>
        <section
          className={cn(
            "min-w-0 flex-1 overflow-hidden rounded-xl border border-bd bg-raised transition-opacity",
            history.isPlaceholderData && "opacity-60",
          )}
          aria-busy={history.isFetching}
          data-testid="audit-feed"
          aria-label="Audit events"
          ref={nav.listRef as React.RefObject<HTMLElement>}
        >
          {history.isLoading ? (
            <div className="space-y-3 p-5">
              {Array.from({ length: 6 }, (_, i) => (
                <Skeleton key={i} className="h-6 w-full" />
              ))}
            </div>
          ) : history.isError ? (
            <EmptyState
              icon={<ShieldAlert size={20} />}
              title="The audit log is not available"
              description={String((history.error as Error)?.message ?? history.error)}
            />
          ) : visible.length === 0 ? (
            <EmptyState
              icon={<FileText size={20} />}
              title={anyFilter ? "No events match" : "No events yet"}
              description={anyFilter ? "Try a wider time range or clear the filters." : emptyHint}
              actions={
                anyFilter ? (
                  <Button size="sm" onClick={() => onFiltersChange({ ...NO_FILTERS })}>
                    Clear filters
                  </Button>
                ) : undefined
              }
            />
          ) : (
            groups.map((g) => (
              <div key={g.day}>
                <h3 className="border-b border-bd bg-inset/40 px-4 py-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-muted">
                  {g.day}
                </h3>
                <ul>
                  {g.rows.map(({ line, index }) => {
                    const e = line.event;
                    const deny = e.decision === "deny";
                    const isSelected = selectedId === e.eventId;
                    return (
                      <li
                        key={e.eventId}
                        data-audit-row={e.eventType}
                        {...nav.itemProps(index)}
                        onClick={() => setSelectedId(isSelected ? null : e.eventId)}
                        aria-selected={isSelected}
                        className={cn(
                          "relative grid cursor-pointer grid-cols-[3rem_minmax(0,1fr)_auto] items-center gap-x-3 border-b border-bd px-4 py-2.5 text-[13px] transition-colors last:border-b-0 md:grid-cols-[3rem_minmax(0,11.5rem)_minmax(0,1fr)_auto]",
                          deny && "bg-deny/[0.05]",
                          isSelected ? "bg-active" : "hover:bg-hover/70 data-[active]:bg-hover/70",
                        )}
                      >
                        {deny && <span aria-hidden="true" className="absolute inset-y-0 left-0 w-[3px] bg-deny" />}
                        <time className="font-mono text-xs tabular-nums text-muted" dateTime={e.occurredAt} title={new Date(e.occurredAt).toLocaleString()}>
                          {clock(e.occurredAt)}
                        </time>
                        <span className="flex min-w-0 items-center gap-2 max-md:col-start-2 max-md:row-start-1">
                          <ActorMark actor={line.actor} />
                          <span className={cn("truncate font-medium", line.actor.known ? "text-fg" : "font-mono text-xs text-muted")}>
                            {line.actor.name}
                          </span>
                        </span>
                        <span className="flex min-w-0 items-start gap-2 max-md:col-span-2 max-md:col-start-2 max-md:row-start-2 max-md:mt-1">
                          <span className="mt-0.5">
                            <EventIconGlyph icon={line.described.icon} deny={deny} />
                          </span>
                          <SentenceText segments={line.described.segments} className="min-w-0 text-muted" />
                          {line.related.length > 0 && (
                            <span className="mt-px shrink-0 rounded bg-hover px-1.5 text-[11px] text-muted" title="Related events of the same push">
                              +{line.related.length}
                            </span>
                          )}
                        </span>
                        <span className="max-md:col-start-3 max-md:row-start-1 max-md:justify-self-end">
                          <DecisionBadge decision={e.decision} />
                        </span>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))
          )}
          {history.hasNextPage && (
            <div className="flex items-center justify-center border-t border-bd p-2">
              <Button
                variant="ghost"
                size="sm"
                data-testid="audit-more"
                loading={history.isFetchingNextPage}
                onClick={() => void history.fetchNextPage()}
              >
                Load older events
              </Button>
            </div>
          )}
          {!history.isLoading && history.isFetching && !history.isFetchingNextPage && (
            <span className="sr-only">
              <Spinner /> Refreshing
            </span>
          )}
        </section>
        {selected && wide && <div className="sticky top-4 w-[380px] shrink-0">{detail}</div>}
      </div>
      {selected && !wide && (
        <Drawer open onClose={() => setSelectedId(null)} title={selected.described.title} width="w-[420px]">
          {detail}
        </Drawer>
      )}
    </div>
  );
}

