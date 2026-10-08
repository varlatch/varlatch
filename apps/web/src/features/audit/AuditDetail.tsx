// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { Link } from "react-router-dom";
import { ArrowUpRight, ChevronRight, Filter, KeyRound, X } from "lucide-react";
import { CopyButton } from "../../components/CodeBlock";
import { IconButton, Mono, cn } from "../../components/ui";
import { dayLabel } from "../../lib/time";
import { ACTION_LABELS, authorizationSummary, describeEvent, listedItems, placeOf, type Described, type NameResolver } from "./describe";
import { ActorMark, DecisionBadge, EventIconGlyph, SentenceText, clock, type Actor, type AuditEvent } from "./parts";

/**
 * One event, readable: who, through which credential and client, what,
 * where, the decision in words, when, and the request ID; the raw event JSON
 * stays one click away. A denial offers the way out: granting the access it
 * lacked.
 */
export function AuditDetail({
  org,
  event,
  described,
  actor,
  related = [],
  names,
  onClose,
  onFilterActor,
  bare = false,
}: {
  org: string;
  event: AuditEvent;
  described: Described;
  actor: Actor;
  /** Further events folded into this line (one automatic push). */
  related?: AuditEvent[] | undefined;
  names: NameResolver;
  onClose: () => void;
  onFilterActor?: ((identityId: string) => void) | undefined;
  /** Inside a drawer: no card chrome or title row (the drawer has them). */
  bare?: boolean | undefined;
}) {
  const r = (event.resource ?? {}) as Record<string, unknown>;
  const meta = (event.metadata ?? {}) as Record<string, unknown>;
  const deny = event.decision === "deny";
  const place = placeOf(r, names);
  const env = names.environment(r.environmentId as string | undefined);
  const project = names.project((r.projectId as string | undefined) ?? env?.projectId);
  const items = listedItems(meta);
  const item = typeof r.itemName === "string" ? r.itemName : undefined;
  const reason = authorizationSummary(event);
  const when = `${dayLabel(event.occurredAt)} ${clock(event.occurredAt, true)}`;
  const envLink =
    project && env ? `/o/${org}/p/${project}/e/${encodeURIComponent(env.name)}${item ? `?item=${encodeURIComponent(item)}` : ""}` : undefined;
  const actorLabel =
    actor.kind === "system" ? "Varlatch (automatic)" : actor.kind === "human" || actor.kind === "unknown" ? actor.name : `${actor.name} (${actor.kind})`;

  const rows: [string, React.ReactNode][] = [
    [
      "Actor",
      <span className="flex min-w-0 items-center gap-2">
        <ActorMark actor={actor} size="xs" />
        <span className={cn("truncate", !actor.known && "font-mono text-xs text-muted")}>{actorLabel}</span>
      </span>,
    ],
  ];
  if (event.credentialId) {
    const credential = actor.credential;
    rows.push([
      "Credential",
      <span className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
        {credential?.name && <span className="min-w-0 truncate">{credential.name}</span>}
        {credential && <Mono className="rounded-md border border-bd bg-inset px-1.5 py-0.5 text-xs">{credential.kind}</Mono>}
        <span className="flex min-w-0 items-center gap-1">
          <Mono className="truncate text-xs text-muted" title={event.credentialId}>
            {event.credentialId}
          </Mono>
          <CopyButton value={event.credentialId} label="Copy credential ID" />
        </span>
      </span>,
    ]);
  }
  if (event.client) rows.push(["Client", <span className="break-words">{event.client}</span>]);
  if (event.action) {
    rows.push([
      "Action",
      <span className="flex flex-wrap items-center gap-2">
        <Mono className="rounded-md border border-bd bg-inset px-1.5 py-0.5 text-xs">{event.action}</Mono>
        {ACTION_LABELS[event.action] && <span className="text-xs text-muted">{ACTION_LABELS[event.action]}</span>}
      </span>,
    ]);
  }
  if (place || item || items.length > 0) {
    rows.push([
      "Resource",
      <span className="font-mono text-[12.5px]">
        {place ?? "organization"}
        {item && <span className="text-muted"> · {item}</span>}
      </span>,
    ]);
  }
  if (items.length > 0) {
    rows.push([
      items.length === 1 ? "Item" : `Items (${items.length})`,
      <span className="flex flex-wrap gap-1">
        {items.map((name) => (
          <Mono key={name} className="rounded border border-bd bg-inset px-1.5 py-px text-[11.5px]">
            {name}
          </Mono>
        ))}
      </span>,
    ]);
  }
  rows.push([
    "Outcome",
    <span className="space-y-1">
      <DecisionBadge decision={event.decision} />
      {reason && <span className="block text-[13px] text-fg/90">{reason}</span>}
    </span>,
  ]);
  rows.push(["When", <span className="tabular-nums">{when}</span>]);
  if (event.requestId) {
    rows.push([
      "Request ID",
      <span className="flex min-w-0 items-center gap-1">
        <Mono className="truncate rounded-md border border-bd bg-inset px-1.5 py-0.5 text-xs" title={event.requestId}>
          {event.requestId.length > 18 ? `${event.requestId.slice(0, 16)}…` : event.requestId}
        </Mono>
        <CopyButton value={event.requestId} label="Copy request ID" />
      </span>,
    ]);
  }
  rows.push(["Event", <Mono className="text-xs text-muted">{event.eventType}</Mono>]);
  if (related.length > 0) {
    rows.push([
      "Also recorded",
      <ul className="space-y-1">
        {related.map((e) => (
          <li key={e.eventId} className="text-[12.5px] text-muted">
            <span className="font-mono text-xs tabular-nums">{clock(e.occurredAt, true)}</span>{" "}
            <SentenceText segments={describeEvent(e, names).segments} />
          </li>
        ))}
      </ul>,
    ]);
  }

  const body = (
    <div className="space-y-5">
      {bare && (
        <p className="text-[13px] text-muted">
          <span className="font-medium text-fg">{actor.name}</span> <SentenceText segments={described.segments} />
        </p>
      )}
      <dl className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-x-3 gap-y-3 text-[13px]">
        {rows.map(([label, value]) => (
          <React.Fragment key={label}>
            <dt className="pt-0.5 text-muted">{label}</dt>
            <dd className="min-w-0">{value}</dd>
          </React.Fragment>
        ))}
      </dl>
      <details className="group rounded-lg border border-bd bg-inset/50">
        <summary className="flex cursor-pointer list-none items-center justify-between px-3 py-2.5 text-[13px] text-muted hover:text-fg [&::-webkit-details-marker]:hidden">
          Raw event JSON
          <ChevronRight size={14} className="transition-transform group-open:rotate-90" />
        </summary>
        <pre className="max-h-80 overflow-auto border-t border-bd p-3 font-mono text-[11px] leading-relaxed text-fg">
          {JSON.stringify(related.length > 0 ? [event, ...related] : event, null, 2)}
        </pre>
      </details>
      <div className="flex flex-wrap gap-2">
        {deny && event.actorIdentityId && (
          <Link
            to={`/o/${org}/access?tab=grants&subject=${encodeURIComponent(event.actorIdentityId)}`}
            data-testid="audit-grant-access"
            className="inline-flex h-8 items-center gap-2 rounded-md border border-transparent bg-accent px-3 text-sm font-semibold text-accent-fg hover:bg-accent-strong"
          >
            <KeyRound size={14} /> Grant access…
          </Link>
        )}
        {onFilterActor && event.actorIdentityId && (
          <button
            type="button"
            onClick={() => onFilterActor(event.actorIdentityId!)}
            className="inline-flex h-8 cursor-pointer items-center gap-2 rounded-md border border-bd bg-raised px-3 text-sm text-fg hover:border-bd-strong hover:bg-hover"
          >
            <Filter size={13} className="text-muted" /> Only this actor
          </button>
        )}
        {envLink && (
          <Link
            to={envLink}
            className="inline-flex h-8 items-center gap-1.5 rounded-md border border-bd bg-raised px-3 text-sm text-fg hover:border-bd-strong hover:bg-hover"
          >
            Open <span className="font-mono text-[12.5px]">{env?.name}</span>
            <ArrowUpRight size={13} className="text-muted" />
          </Link>
        )}
      </div>
    </div>
  );

  if (bare) return <div data-testid="audit-drawer">{body}</div>;
  return (
    <aside data-testid="audit-drawer" className="animate-fade-in overflow-hidden rounded-xl border border-bd bg-raised">
      <header className="flex items-center gap-2.5 border-b border-bd px-5 py-3.5">
        <span className={cn("flex size-8 shrink-0 items-center justify-center rounded-lg", deny ? "bg-deny/10" : "bg-inset")}>
          <EventIconGlyph icon={described.icon} deny={deny} size={16} />
        </span>
        <h2 className="min-w-0 flex-1 truncate text-[15px] font-semibold">{described.title}</h2>
        <IconButton label="Close details" size="sm" onClick={onClose} className="-mr-1.5">
          <X size={15} />
        </IconButton>
      </header>
      <div className="px-5 py-4">{body}</div>
    </aside>
  );
}
