// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, X } from "lucide-react";
import type { Webhook } from "@varlatch/protocol";
import { useMirrorInvalidation } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { Button, Card, Input, Mono, Select, cn } from "../../components/ui";

/**
 * P4 Audit: one coherent timeline (design R1 §Q6) served from the
 * authoritative /v1 store with cursor paging; the reactive Convex mirror only
 * signals "new events exist" so the page refreshes without polling. Filters
 * are client-side over loaded pages; the provenance drawer shows the full
 * event; export downloads the authoritative NDJSON stream.
 */

type AuditEvent = {
  eventId: string;
  eventType: string;
  occurredAt: string;
  decision: string;
  actorIdentityId: string | null;
  requestId: string | null;
  action: string | null;
  resource: unknown;
  metadata: unknown;
  authorization: unknown;
  [key: string]: unknown;
};

export function AuditPage() {
  const { org: orgSlug } = useParams();
  const { api } = useSession();
  const orgQuery = useQuery({
    queryKey: ["org", orgSlug],
    queryFn: () => api.getOrganization(orgSlug as string),
    enabled: Boolean(orgSlug),
  });

  const history = useInfiniteQuery({
    queryKey: ["audit", orgSlug],
    queryFn: ({ pageParam }) =>
      api.listAuditEvents(orgSlug as string, { limit: 100, ...(pageParam ? { cursor: pageParam } : {}) }),
    initialPageParam: "",
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    enabled: Boolean(orgSlug),
  });

  // Reactive head: every mutation records an audit event, so any change
  // signal means new events — refetch the authoritative page.
  useMirrorInvalidation(orgQuery.data?.id, "*", [["audit", orgSlug]]);

  const [text, setText] = useState("");
  const [decision, setDecision] = useState("");
  const [selected, setSelected] = useState<AuditEvent | null>(null);

  const events = useMemo(
    () => (history.data?.pages.flatMap((p) => p.items) ?? []) as AuditEvent[],
    [history.data],
  );
  const filtered = events.filter((e) => {
    if (decision && e.decision !== decision) return false;
    if (!text) return true;
    const needle = text.toLowerCase();
    return [e.eventType, e.actorIdentityId, e.action, JSON.stringify(e.resource)]
      .filter(Boolean)
      .some((v) => String(v).toLowerCase().includes(needle));
  });

  const exportNdjson = async () => {
    const body = await api.exportAuditEventsNdjson(orgSlug as string);
    const url = URL.createObjectURL(new Blob([body], { type: "application/x-ndjson" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `varlatch-audit-${orgSlug}.ndjson`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">Security audit</h1>
        <div className="flex gap-2 items-center">
          <Input
            data-testid="audit-filter"
            placeholder="Filter events, actors, resources…"
            value={text}
            onChange={(e) => setText(e.target.value)}
            className="w-64"
          />
          <Select
            data-testid="audit-decision"
            value={decision}
            onChange={(v) => setDecision(v)}
            options={[
              { value: "", label: "all decisions" },
              { value: "allow", label: "allow" },
              { value: "deny", label: "deny" },
              { value: "info", label: "info" },
            ]}
          />
          <Button data-testid="audit-export" variant="ghost" onClick={() => void exportNdjson()}>
            <span className="inline-flex items-center gap-1.5">
              <Download size={13} /> NDJSON
            </span>
          </Button>
        </div>
      </div>
      <div className="flex gap-4">
        <Card className="p-0 overflow-hidden flex-1 min-w-0">
          <table className="w-full text-sm" data-testid="audit-feed">
            <thead>
              <tr className="text-left text-muted border-b border-bd">
                <th className="px-3 py-2 font-medium">When</th>
                <th className="px-3 py-2 font-medium">Event</th>
                <th className="px-3 py-2 font-medium">Decision</th>
                <th className="px-3 py-2 font-medium">Actor</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((e) => (
                <tr
                  key={e.eventId}
                  data-audit-row={e.eventType}
                  onClick={() => setSelected(e)}
                  className={cn(
                    "border-b border-bd/50 cursor-pointer hover:bg-inset",
                    selected?.eventId === e.eventId && "bg-inset",
                  )}
                >
                  <td className="px-3 py-1.5 font-mono text-xs text-muted whitespace-nowrap">
                    {e.occurredAt.replace("T", " ").slice(0, 19)}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-xs">{e.eventType}</td>
                  <td
                    className={cn(
                      "px-3 py-1.5 text-xs",
                      e.decision === "deny" ? "text-deny font-semibold" : "text-muted",
                    )}
                  >
                    {e.decision}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-xs text-muted truncate max-w-40">
                    {e.actorIdentityId ?? "—"}
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-3 py-4 text-muted text-sm">
                    No events match.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
          {history.hasNextPage && (
            <div className="p-2 border-t border-bd">
              <Button variant="ghost" data-testid="audit-more" onClick={() => void history.fetchNextPage()}>
                Load older events
              </Button>
            </div>
          )}
        </Card>
        {selected && (
          <Card data-testid="audit-drawer" className="w-96 shrink-0 self-start sticky top-4">
            <div className="flex items-center justify-between mb-2">
              <h2 className="font-medium font-mono text-sm">{selected.eventType}</h2>
              <button className="text-muted hover:text-fg cursor-pointer" onClick={() => setSelected(null)}>
                <X size={14} />
              </button>
            </div>
            <dl className="space-y-1.5 text-xs">
              {(
                [
                  ["Event", selected.eventId],
                  ["Occurred", selected.occurredAt],
                  ["Decision", selected.decision],
                  ["Action", selected.action],
                  ["Actor", selected.actorIdentityId],
                  ["Request", selected.requestId],
                ] as const
              ).map(([k, v]) => (
                <div key={k} className="flex gap-2">
                  <dt className="text-muted w-16 shrink-0">{k}</dt>
                  <dd>
                    <Mono className="break-all text-xs">{v ? String(v) : "—"}</Mono>
                  </dd>
                </div>
              ))}
            </dl>
            {[
              ["Resource", selected.resource],
              ["Authorization", selected.authorization],
              ["Metadata", selected.metadata],
            ].map(
              ([label, value]) =>
                value != null && (
                  <div key={String(label)} className="mt-2">
                    <p className="text-muted text-xs mb-0.5">{String(label)}</p>
                    <pre className="rounded-md bg-inset border border-bd p-2 text-[11px] font-mono overflow-x-auto">
                      {JSON.stringify(value, null, 2)}
                    </pre>
                  </div>
                ),
            )}
          </Card>
        )}
      </div>
      <WebhooksSection org={orgSlug as string} orgId={orgQuery.data?.id} />
    </div>
  );
}

/**
 * Audit webhooks: an operational sink for this same event stream. Signed
 * (HMAC-SHA256), ordered, at-least-once, starting from registration — never
 * history. The signing secret is shown exactly once.
 */
function WebhooksSection({ org, orgId }: { org: string; orgId: string | undefined }) {
  const { api } = useSession();
  const qc = useQueryClient();
  useMirrorInvalidation(orgId, ["webhook"], [["webhooks", org]]);
  const webhooks = useQuery({ queryKey: ["webhooks", org], queryFn: () => api.listWebhooks(org) });

  const [url, setUrl] = useState("");
  const [eventTypes, setEventTypes] = useState("");
  const [oneTime, setOneTime] = useState<{ url: string; secret: string } | null>(null);
  const create = useMutation({
    mutationFn: () => {
      const filter = eventTypes.split(",").map((t) => t.trim()).filter(Boolean);
      return api.createWebhook(org, { url, ...(filter.length > 0 ? { eventTypes: filter } : {}) });
    },
    onSuccess: (r) => {
      setOneTime({ url: r.url, secret: r.secret });
      setUrl("");
      setEventTypes("");
      void qc.invalidateQueries({ queryKey: ["webhooks", org] });
    },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.revokeWebhook(org, id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["webhooks", org] }),
  });
  // In-place edit (ADR-0029 §8): delivery identity is preserved — the
  // signing secret and cursor are untouched, and pending events (including
  // backlog) are redirected to the new URL/filter.
  const [editing, setEditing] = useState<string | null>(null);
  const [editUrl, setEditUrl] = useState("");
  const [editEventTypes, setEditEventTypes] = useState("");
  const update = useMutation({
    mutationFn: (w: Webhook) => {
      const filter = editEventTypes.split(",").map((t) => t.trim()).filter(Boolean);
      return api.updateWebhook(org, w.id, {
        expectedVersion: w.version,
        url: editUrl,
        eventTypes: filter.length > 0 ? filter : null,
      });
    },
    onSuccess: () => {
      setEditing(null);
      void qc.invalidateQueries({ queryKey: ["webhooks", org] });
    },
  });

  return (
    <Card data-testid="webhooks-section">
      <h2 className="font-medium mb-1">Audit webhooks</h2>
      <p className="text-muted text-sm mb-3">
        Every event above is also POSTed to registered endpoints — ordered, at-least-once, from
        registration onward (never history). Deliveries are signed:{" "}
        <Mono>X-Varlatch-Signature: t=&lt;unix&gt;,v1=&lt;hex&gt;</Mono> where v1 is
        HMAC-SHA256(secret, <Mono>&lt;t&gt;.&lt;raw-body&gt;</Mono>); verify it and reject stale
        timestamps.
      </p>
      <div className="flex flex-wrap gap-2 items-center mb-2">
        <Input
          data-testid="webhook-url"
          className="w-80"
          placeholder="https://ops.example.com/varlatch-audit"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <Input
          data-testid="webhook-event-types"
          className="w-64"
          placeholder="Event types (optional, comma-separated)"
          title="e.g. authentication.failed, value.disclosed — empty receives all events"
          value={eventTypes}
          onChange={(e) => setEventTypes(e.target.value)}
        />
        <Button
          data-testid="create-webhook"
          disabled={!/^https?:\/\/.+/.test(url) || create.isPending}
          onClick={() => create.mutate()}
        >
          Register
        </Button>
      </div>
      {create.error && <p className="text-deny text-sm mb-2">{String(create.error)}</p>}
      {revoke.error && <p className="text-deny text-sm mb-2">{String(revoke.error)}</p>}
      {oneTime && (
        <div
          data-testid="webhook-secret"
          className="mb-3 rounded-md border border-tier-production/50 bg-inset p-3 text-sm"
        >
          <p className="mb-1 font-medium">
            Signing secret for {oneTime.url} — shown once, never retrievable again.
          </p>
          <Mono className="break-all" data-testid="webhook-secret-value">{oneTime.secret}</Mono>
          <div className="mt-2">
            <Button data-testid="dismiss-webhook-secret" variant="ghost" onClick={() => setOneTime(null)}>
              I stored it — dismiss
            </Button>
          </div>
        </div>
      )}
      {webhooks.data?.items.length === 0 && (
        <p className="text-muted text-sm" data-testid="webhooks-empty">
          No webhooks — the audit stream is only consumed from this page and the export.
        </p>
      )}
      {(webhooks.data?.items ?? []).length > 0 && (
        <table className="w-full text-sm">
          <tbody>
            {webhooks.data!.items.map((w: Webhook) => (
              <React.Fragment key={w.id}>
              <tr data-webhook={w.url} className="border-t border-bd align-top">
                <td className="py-1.5">
                  <Mono className="break-all">{w.url}</Mono>
                </td>
                <td className="text-muted px-2">
                  {w.eventTypes ? <Mono className="text-xs">{w.eventTypes.join(", ")}</Mono> : "all events"}
                </td>
                <td className="text-muted whitespace-nowrap px-2 text-xs">
                  {w.lastAttemptAt ? (
                    <>
                      last {w.lastStatus ?? "?"} · {new Date(w.lastAttemptAt).toLocaleString()}
                      {w.failureCount > 0 && (
                        <span className="text-deny"> · {w.failureCount} failing</span>
                      )}
                    </>
                  ) : (
                    "no deliveries yet"
                  )}
                </td>
                <td className="text-right whitespace-nowrap">
                  <Button
                    variant="ghost"
                    data-testid={`edit-webhook-${w.id}`}
                    onClick={() => {
                      setEditing(editing === w.id ? null : w.id);
                      setEditUrl(w.url);
                      setEditEventTypes((w.eventTypes ?? []).join(","));
                    }}
                  >
                    {editing === w.id ? "Cancel" : "Edit"}
                  </Button>{" "}
                  <Button
                    variant="danger"
                    data-testid={`revoke-webhook-${w.id}`}
                    onClick={() => revoke.mutate(w.id)}
                  >
                    Revoke
                  </Button>
                </td>
              </tr>
              {editing === w.id && (
                <tr data-testid={`webhook-editor-${w.id}`}>
                  <td colSpan={4} className="pb-2">
                    <div className="flex flex-wrap items-center gap-2 rounded border border-bd bg-inset/40 p-2">
                      <Input className="w-80" value={editUrl} onChange={(e) => setEditUrl(e.target.value)} />
                      <Input
                        className="w-64"
                        placeholder="Event types (empty = all events)"
                        value={editEventTypes}
                        onChange={(e) => setEditEventTypes(e.target.value)}
                      />
                      <Button
                        data-testid={`save-webhook-${w.id}`}
                        disabled={!/^https?:\/\/.+/.test(editUrl) || update.isPending}
                        onClick={() => update.mutate(w)}
                      >
                        Save
                      </Button>
                      <span className="text-xs text-muted">
                        Keeps the signing secret and delivery cursor; pending events go to the new
                        URL/filter.
                      </span>
                      {update.error && <p className="text-deny text-sm">{String(update.error)}</p>}
                    </div>
                  </td>
                </tr>
              )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}
