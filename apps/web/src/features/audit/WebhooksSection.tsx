// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, ShieldAlert, Trash2, Webhook as WebhookIcon } from "lucide-react";
import type { Webhook } from "@varlatch/protocol";
import { useMirrorInvalidation } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { timeAgo } from "../../lib/time";
import { Button, Callout, Field, IconButton, Input, Mono, SectionCard, Status, cn, table } from "../../components/ui";
import { CopyButton } from "../../components/CodeBlock";
import { useConfirm } from "../../components/Dialog";
import { useToast } from "../../components/Toast";

const URL_PATTERN = /^https?:\/\/.+/;

function splitTypes(text: string): string[] {
  return text
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
}

/**
 * Audit webhooks: an operational sink for the same event stream. Deliveries
 * are signed, ordered and at least once, starting from registration (never
 * history). The signing secret is shown exactly once.
 */
export function WebhooksSection({ org, orgId, className }: { org: string; orgId: string | undefined; className?: string }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const toast = useToast();
  useMirrorInvalidation(orgId, ["webhook"], [["webhooks", org]]);
  const webhooks = useQuery({ queryKey: ["webhooks", org], queryFn: () => api.listWebhooks(org) });
  const refresh = () => void qc.invalidateQueries({ queryKey: ["webhooks", org] });

  const [url, setUrl] = useState("");
  const [eventTypes, setEventTypes] = useState("");
  const [oneTime, setOneTime] = useState<{ url: string; secret: string } | null>(null);
  const create = useMutation({
    mutationFn: () => {
      const filter = splitTypes(eventTypes);
      return api.createWebhook(org, { url, ...(filter.length > 0 ? { eventTypes: filter } : {}) });
    },
    onSuccess: (r) => {
      setOneTime({ url: r.url, secret: r.secret });
      setUrl("");
      setEventTypes("");
      refresh();
    },
    onError: (err) => toast.error("Could not register the webhook", { description: String((err as Error).message ?? err) }),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.revokeWebhook(org, id),
    onSuccess: () => {
      refresh();
      toast.success("Webhook revoked");
    },
    onError: (err) => toast.error("Could not revoke the webhook", { description: String((err as Error).message ?? err) }),
  });

  // In-place edit keeps delivery identity: the signing secret and cursor are
  // untouched and pending events go to the new URL or filter.
  const [editing, setEditing] = useState<string | null>(null);
  const [editUrl, setEditUrl] = useState("");
  const [editEventTypes, setEditEventTypes] = useState("");
  const update = useMutation({
    mutationFn: (w: Webhook) => {
      const filter = splitTypes(editEventTypes);
      return api.updateWebhook(org, w.id, {
        expectedVersion: w.version,
        url: editUrl,
        eventTypes: filter.length > 0 ? filter : null,
      });
    },
    onSuccess: () => {
      setEditing(null);
      refresh();
      toast.success("Webhook updated");
    },
  });

  const items = webhooks.data?.items ?? [];

  return (
    <SectionCard
      data-testid="webhooks-section"
      className={className}
      title="Audit webhooks"
      description="Every event above can also be POSTed to your endpoints: signed, ordered, at least once, from registration onward."
      bodyClassName="divide-y divide-bd"
    >
      <form
        className="flex flex-wrap items-end gap-3 px-5 py-4"
        onSubmit={(e) => {
          e.preventDefault();
          if (URL_PATTERN.test(url) && !create.isPending) create.mutate();
        }}
      >
        <Field label="Endpoint URL" className="min-w-64 flex-[2]">
          <Input
            data-testid="webhook-url"
            mono
            className="w-full"
            placeholder="https://ops.example.com/varlatch-audit"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
        </Field>
        <Field label="Event types" className="min-w-52 flex-1">
          <Input
            data-testid="webhook-event-types"
            mono
            className="w-full"
            placeholder="All events, or a comma-separated list"
            title="For example authorization.denied, secret.disclosed. Empty receives every event."
            value={eventTypes}
            onChange={(e) => setEventTypes(e.target.value)}
          />
        </Field>
        <Button type="submit" data-testid="create-webhook" disabled={!URL_PATTERN.test(url)} loading={create.isPending}>
          Register webhook
        </Button>
      </form>

      {oneTime && (
        <div className="px-5 py-4">
          <Callout
            tone="warn"
            icon={<ShieldAlert size={16} />}
            title="Signing secret: shown once"
            data-testid="webhook-secret"
            actions={
              <Button data-testid="dismiss-webhook-secret" size="sm" onClick={() => setOneTime(null)}>
                I stored it
              </Button>
            }
          >
            <p className="mb-2">
              Store it now for <Mono className="text-fg">{oneTime.url}</Mono>; Varlatch never shows it again.
            </p>
            <span className="flex items-center gap-1 rounded-md border border-bd bg-inset py-1 pl-2.5 pr-1">
              <Mono className="min-w-0 flex-1 break-all text-fg" data-testid="webhook-secret-value">
                {oneTime.secret}
              </Mono>
              <CopyButton value={oneTime.secret} label="Copy signing secret" />
            </span>
          </Callout>
        </div>
      )}

      {webhooks.isSuccess && items.length === 0 && (
        <p className="flex items-center gap-2 px-5 py-4 text-[13px] text-muted" data-testid="webhooks-empty">
          <WebhookIcon size={14} /> No webhooks yet. The audit log is read here and through the export.
        </p>
      )}

      {items.length > 0 && (
        <div className={table.wrap}>
          <table className={table.table}>
            <thead>
              <tr>
                <th className={table.th}>Endpoint</th>
                <th className={table.th}>Events</th>
                <th className={table.th}>Last delivery</th>
                <th className={cn(table.th, "w-0")}>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {items.map((w) => (
                <React.Fragment key={w.id}>
                  <tr data-webhook={w.url} className={table.tr}>
                    <td className={cn(table.td, "max-w-80")}>
                      <Mono className="break-all">{w.url}</Mono>
                    </td>
                    <td className={cn(table.td, "text-muted")}>
                      {w.eventTypes ? (
                        <span className="flex flex-wrap gap-1">
                          {w.eventTypes.map((t) => (
                            <Mono key={t} className="rounded border border-bd bg-inset px-1.5 py-px text-[11.5px]">
                              {t}
                            </Mono>
                          ))}
                        </span>
                      ) : (
                        "all events"
                      )}
                    </td>
                    <td className={cn(table.td, "whitespace-nowrap")}>
                      {w.lastAttemptAt ? (
                        <Status tone={w.failureCount > 0 ? "error" : "ok"}>
                          {w.failureCount > 0 ? `${w.failureCount} failing` : (w.lastStatus ?? "delivered")}
                          <span className="text-muted">· {timeAgo(w.lastAttemptAt)}</span>
                        </Status>
                      ) : (
                        <span className="text-[13px] text-muted">No deliveries yet</span>
                      )}
                    </td>
                    <td className={cn(table.td, "whitespace-nowrap text-right")}>
                      <IconButton
                        label={editing === w.id ? "Cancel editing" : "Edit webhook"}
                        data-testid={`edit-webhook-${w.id}`}
                        onClick={() => {
                          setEditing(editing === w.id ? null : w.id);
                          setEditUrl(w.url);
                          setEditEventTypes((w.eventTypes ?? []).join(", "));
                        }}
                      >
                        <Pencil size={14} />
                      </IconButton>
                      <IconButton
                        label="Revoke webhook"
                        tone="danger"
                        data-testid={`revoke-webhook-${w.id}`}
                        onClick={async () => {
                          const ok = await confirm({
                            title: "Revoke this webhook?",
                            tone: "danger",
                            confirmLabel: "Revoke webhook",
                            body: <Mono className="block break-all rounded-md border border-bd bg-inset px-2.5 py-1.5">{w.url}</Mono>,
                            consequences: [
                              { text: "Deliveries stop now, including events still waiting to be sent." },
                              { text: "The signing secret stops being used. Registering again creates a new one." },
                            ],
                          });
                          if (ok) revoke.mutate(w.id);
                        }}
                      >
                        <Trash2 size={14} />
                      </IconButton>
                    </td>
                  </tr>
                  {editing === w.id && (
                    <tr data-testid={`webhook-editor-${w.id}`} className="border-b border-bd bg-inset/40 last:border-b-0">
                      <td colSpan={4} className="px-4 py-3">
                        <form
                          className="flex flex-wrap items-end gap-3"
                          onSubmit={(e) => {
                            e.preventDefault();
                            if (URL_PATTERN.test(editUrl)) update.mutate(w);
                          }}
                        >
                          <Field label="Endpoint URL" className="min-w-64 flex-[2]">
                            <Input mono className="w-full" value={editUrl} onChange={(e) => setEditUrl(e.target.value)} />
                          </Field>
                          <Field label="Event types" className="min-w-52 flex-1">
                            <Input
                              mono
                              className="w-full"
                              placeholder="All events"
                              value={editEventTypes}
                              onChange={(e) => setEditEventTypes(e.target.value)}
                            />
                          </Field>
                          <Button variant="ghost" onClick={() => setEditing(null)}>
                            Cancel
                          </Button>
                          <Button
                            type="submit"
                            variant="primary"
                            data-testid={`save-webhook-${w.id}`}
                            disabled={!URL_PATTERN.test(editUrl)}
                            loading={update.isPending}
                          >
                            Save
                          </Button>
                        </form>
                        <p className="mt-2 text-xs text-muted">
                          Keeps the signing secret and the delivery position; waiting events go to the new URL and filter.
                        </p>
                        {update.error && <p className="mt-1 text-xs text-deny">{String((update.error as Error).message ?? update.error)}</p>}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <details className="group px-5 py-3 text-[13px] text-muted">
        <summary className="cursor-pointer list-none hover:text-fg [&::-webkit-details-marker]:hidden">
          How to verify a delivery
        </summary>
        <p className="mt-2">
          Each delivery carries <Mono className="text-fg">X-Varlatch-Signature: t=&lt;unix&gt;,v1=&lt;hex&gt;</Mono>, where v1 is
          HMAC-SHA256 of <Mono className="text-fg">&lt;t&gt;.&lt;raw body&gt;</Mono> with the signing secret. Verify it and reject
          stale timestamps.
        </p>
      </details>
    </SectionCard>
  );
}
