// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RotateCcw, ShieldAlert, ShieldCheck, TriangleAlert, X } from "lucide-react";
import type { Environment, Requirement, Tier } from "@varlatch/protocol";
import { VarlatchApiError } from "@varlatch/sdk";
import { useSession } from "../../lib/session";
import { Button, Callout, Checkbox, Field, Input, Segmented, Select, TierDot, cn } from "../../components/ui";
import { Dialog } from "../../components/Dialog";
import { errorMessage } from "../../shell/Shell";
import { TIERS } from "./shared";
import type { Names } from "./model";
import {
  NEW_REQUIREMENT,
  consequences,
  draftBody,
  draftErrors,
  draftFrom,
  entryError,
  requirementSentence,
  sameDraft,
  scopeLabel,
  type ListKind,
  type RequirementDraft,
} from "./requirements";

/**
 * Creates a requirement, or edits one with every field (target, tailnet,
 * devices, tags, users), so nothing is dropped on save. An edit is saved
 * only after a review that lists what it loosens and tightens; anything that
 * loosens needs the explicit confirmation there. The edit is tied to the
 * version it started from: a newer version, seen live or refused by the
 * server as VERSION_CONFLICT, closes the review and discards its
 * confirmation, and the user starts over from the current version.
 */
export function RequirementEditor({
  org,
  base,
  current,
  environments,
  names,
  onDone,
  onCancel,
}: {
  org: string;
  /** The requirement as it was when editing started; absent when creating one. */
  base?: Requirement | undefined;
  /** The same requirement as the dashboard sees it now, or undefined once it is gone. */
  current?: Requirement | undefined;
  environments: Environment[];
  names: Names;
  onDone: () => void;
  onCancel: () => void;
}) {
  const { api } = useSession();
  const qc = useQueryClient();
  const [start, setStart] = useState(base);
  const [draft, setDraft] = useState<RequirementDraft>(() => (base ? draftFrom(base) : NEW_REQUIREMENT));
  // The other target kind's value, kept while switching between them.
  const [otherTarget, setOtherTarget] = useState<RequirementDraft["target"] | null>(null);
  const [reviewing, setReviewing] = useState(false);
  const [refused, setRefused] = useState(false);

  const editing = start !== undefined;
  // The list the section shows (same query, same cache): after a refused save
  // it reloads, and only an actually newer version may replace the old one.
  const list = useQuery({ queryKey: ["requirements", org], queryFn: () => api.listRequirements(org) });
  const newer = start !== undefined && current !== undefined && current.version > start.version;
  const removed = editing && current === undefined;
  const stale = editing && (refused || (current !== undefined && current.version !== start.version));
  // A newer version invalidates the preview and any confirmation already given.
  useEffect(() => {
    if (stale || removed) setReviewing(false);
  }, [stale, removed]);

  const before = useMemo(() => (start ? draftFrom(start) : null), [start]);
  const errors = draftErrors(draft, before ?? undefined);
  const unchanged = before !== null && sameDraft(before, draft);
  const effects = useMemo(() => (before ? consequences(before, draft, environments, names) : null), [before, draft, environments, names]);

  const save = useMutation({
    mutationFn: async () => {
      if (start) await api.updateRequirement(org, start.id, { expectedVersion: start.version, ...draftBody(draft) });
      else await api.createTailnetRequirement(org, draftBody(draft));
    },
    onSuccess: () => {
      setReviewing(false);
      onDone();
    },
    onError: (err) => {
      if (err instanceof VarlatchApiError && err.code === "VERSION_CONFLICT") {
        setRefused(true);
        setReviewing(false);
        void qc.invalidateQueries({ queryKey: ["requirements", org] });
      }
    },
  });

  const startOver = () => {
    // Never restart against the version the server refused.
    if (!newer || !current) return;
    setStart(current);
    setDraft(draftFrom(current));
    setOtherTarget(null);
    setRefused(false);
    save.reset();
  };

  const setTargetKind = (kind: "tier" | "environments") => {
    if (kind === draft.target.kind) return;
    const fallback: RequirementDraft["target"] = kind === "tier" ? { kind: "tier", tier: "production" } : { kind: "environments", environmentIds: [] };
    const next = otherTarget?.kind === kind ? otherTarget : fallback;
    setOtherTarget(draft.target);
    setDraft({ ...draft, target: next });
  };
  const setList = (kind: ListKind, values: string[]) => setDraft({ ...draft, selector: { ...draft.selector, [kind]: values } });

  const testId = start ? `save-requirement-${start.id}` : "create-requirement";
  return (
    <form
      className="space-y-4"
      data-testid={start ? `requirement-editor-${start.id}` : "requirement-editor-new"}
      onSubmit={(e) => {
        e.preventDefault();
        if (errors.length || stale || removed) return;
        if (editing) {
          if (!unchanged) setReviewing(true);
        } else save.mutate();
      }}
    >
      {removed && (
        <Callout tone="warn" icon={<TriangleAlert size={17} />} data-testid="requirement-removed">
          This requirement was removed while you were editing it. Nothing was saved.
        </Callout>
      )}
      {stale && !removed && (
        <Callout
          tone="warn"
          icon={<TriangleAlert size={17} />}
          data-testid="requirement-conflict"
          title="This requirement changed while you were editing it"
          actions={
            newer ? (
              <Button size="sm" variant="secondary" icon={<RotateCcw size={13} />} onClick={startOver} data-testid="requirement-start-over">
                Start over from the current version
              </Button>
            ) : (
              <Button
                size="sm"
                variant="secondary"
                icon={<RotateCcw size={13} />}
                loading={list.isFetching}
                disabled={list.isFetching}
                onClick={() => void list.refetch()}
                data-testid="requirement-retry-load"
              >
                Retry loading
              </Button>
            )
          }
        >
          Your changes were not saved, and any review or confirmation is discarded.{" "}
          {newer ? (
            "Start over from the current version, then make your change again."
          ) : list.isFetching ? (
            "Loading the current version…"
          ) : (
            <span data-testid="requirement-not-loaded">
              The current version has not loaded{list.isError ? `: ${errorMessage(list.error)}` : " yet"}. Retry loading it before starting over.
            </span>
          )}
        </Callout>
      )}

      <fieldset disabled={stale || removed} className="space-y-4">
        <Field label="Applies to">
          <div className="space-y-2">
            <Segmented
              size="sm"
              aria-label="What the requirement covers"
              value={draft.target.kind}
              onChange={setTargetKind}
              options={[
                { value: "tier", label: "A tier", "data-testid": "req-target-tier" },
                { value: "environments", label: "Environments", "data-testid": "req-target-environments" },
              ]}
            />
            {draft.target.kind === "tier" ? (
              <Select
                className="w-56"
                value={draft.target.tier}
                onChange={(v) => setDraft({ ...draft, target: { kind: "tier", tier: v as Tier } })}
                aria-label="Tier"
                data-testid="req-tier"
                options={TIERS.map((t) => ({ value: t, label: t, icon: <TierDot tier={t} /> }))}
              />
            ) : (
              <EnvironmentPicker
                environments={environments}
                names={names}
                selected={draft.target.environmentIds}
                onChange={(environmentIds) => setDraft({ ...draft, target: { kind: "environments", environmentIds } })}
              />
            )}
          </div>
        </Field>
        <Field label="Tailnet" hint="Devices must be on this tailnet, and match any one of the devices, tags or users below.">
          <Input
            data-testid="req-tailnet"
            mono
            className="w-full max-w-sm"
            placeholder="example.ts.net"
            value={draft.selector.tailnet}
            onChange={(e) => setDraft({ ...draft, selector: { ...draft.selector, tailnet: e.target.value } })}
          />
        </Field>
        <div className="grid gap-4 lg:grid-cols-3">
          <ListField kind="nodes" label="Devices" hint="Node IDs (StableIDs)" placeholder="nAbc123CNTRL" values={draft.selector.nodes} onChange={(v) => setList("nodes", v)} />
          <ListField kind="tags" label="Tags" hint="Device tags" placeholder="tag:prod" values={draft.selector.tags} onChange={(v) => setList("tags", v)} />
          <ListField kind="users" label="Users" hint="Tailscale login names" placeholder="alice@example.com" values={draft.selector.users} onChange={(v) => setList("users", v)} />
        </div>
      </fieldset>

      {!editing && (
        <p className="text-xs text-muted">A new requirement only narrows access, but it can lock out devices that read these values today.</p>
      )}
      {errors.length > 0 && (draft.selector.tailnet || draft.selector.tags.length || draft.selector.nodes.length || draft.selector.users.length) ? (
        <ul className="space-y-0.5 text-xs text-deny" data-testid="requirement-errors">
          {errors.map((e) => (
            <li key={e}>{e}</li>
          ))}
        </ul>
      ) : null}
      {save.error && !refused && <p className="text-sm text-deny">{errorMessage(save.error)}</p>}
      <div className="flex items-center justify-end gap-2">
        {editing && unchanged && !stale && <span className="text-xs text-muted">No changes yet</span>}
        <Button size="sm" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button
          size="sm"
          variant="primary"
          type="submit"
          data-testid={editing ? `review-requirement-${start.id}` : testId}
          loading={!editing && save.isPending}
          disabled={errors.length > 0 || stale || removed || (editing && unchanged)}
        >
          {editing ? "Review change" : "Add requirement"}
        </Button>
      </div>

      {editing && before && effects && (
        <Dialog
          open={reviewing && !stale && !removed}
          onClose={() => setReviewing(false)}
          size="lg"
          tone={effects.loosens.length ? "danger" : "default"}
          data-testid="requirement-review"
          icon={
            <span className="flex size-9 items-center justify-center rounded-lg border border-bd bg-inset text-muted">
              {effects.loosens.length ? <ShieldAlert size={17} className="text-deny" /> : <ShieldCheck size={17} />}
            </span>
          }
          title={effects.loosens.length ? "This change may let more devices read values" : "Review this change"}
          description={`Applies to ${scopeLabel(draft.target, names)}${
            JSON.stringify(before.target) !== JSON.stringify(draft.target) ? ` (was ${scopeLabel(before.target, names)})` : ""
          }.`}
          footer={
            <>
              <Button variant="ghost" onClick={() => setReviewing(false)}>
                Back to editing
              </Button>
              <Button
                variant={effects.loosens.length ? "danger" : "primary"}
                data-testid={testId}
                loading={save.isPending}
                onClick={() => save.mutate()}
              >
                {effects.loosens.length ? "Loosen and save" : "Save"}
              </Button>
            </>
          }
        >
          <div className="space-y-4 text-[13px]">
            <div className="space-y-1.5">
              <p className="text-muted">Before</p>
              <p className="rounded-md border border-bd bg-inset px-3 py-2" data-testid="review-before">
                {requirementSentence(draftBody(before), names)}
              </p>
              <p className="text-muted">After</p>
              <p className="rounded-md border border-bd bg-inset px-3 py-2" data-testid="review-after">
                {requirementSentence(draftBody(draft), names)}
              </p>
            </div>
            {effects.loosens.length > 0 && (
              <Effects title="May loosen" tone="loosen" items={effects.loosens.map((c) => c.text)} testId="review-loosens" />
            )}
            {effects.tightens.length > 0 && (
              <Effects
                title="Tightens: devices that read these values today may be locked out"
                tone="tighten"
                items={effects.tightens.map((c) => c.text)}
                testId="review-tightens"
              />
            )}
            <p className="text-xs text-muted">Loosening is audited exactly like tightening.</p>
          </div>
        </Dialog>
      )}
    </form>
  );
}

function Effects({ title, tone, items, testId }: { title: string; tone: "loosen" | "tighten"; items: string[]; testId: string }) {
  return (
    <div data-testid={testId}>
      <p className={cn("font-medium", tone === "loosen" ? "text-deny" : "text-warn")}>{title}</p>
      <ul className="mt-1 list-disc space-y-0.5 pl-5">
        {items.map((t) => (
          <li key={t}>{t}</li>
        ))}
      </ul>
    </div>
  );
}

function ListField({
  kind,
  label,
  hint,
  placeholder,
  values,
  onChange,
}: {
  kind: ListKind;
  label: string;
  hint: string;
  placeholder: string;
  values: string[];
  onChange: (next: string[]) => void;
}) {
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const add = () => {
    const value = text.trim().replace(/,$/, "");
    if (!value) return;
    const problem = entryError(kind, value);
    if (problem) return setError(problem);
    if (!values.includes(value)) onChange([...values, value]);
    setText("");
    setError(null);
  };
  return (
    <Field label={label} hint={hint} error={error ?? undefined}>
      <div className="space-y-2" data-testid={`req-${kind}`}>
        {values.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {values.map((v) => (
              <span key={v} data-entry={v} className="inline-flex items-center gap-1 rounded-md border border-bd bg-inset py-0.5 pl-2 pr-1 font-mono text-[12.5px]">
                {v}
                <button type="button" aria-label={`Remove ${v}`} data-testid={`remove-${kind}-${v}`} className="rounded p-0.5 text-muted hover:bg-hover hover:text-fg" onClick={() => onChange(values.filter((x) => x !== v))}>
                  <X size={12} />
                </button>
              </span>
            ))}
          </div>
        )}
        <div className="flex gap-2">
          <Input
            data-testid={`req-${kind}-input`}
            mono
            className="w-full"
            placeholder={placeholder}
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              setError(null);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === ",") {
                e.preventDefault();
                add();
              }
            }}
          />
          <Button size="sm" variant="secondary" data-testid={`req-${kind}-add`} onClick={add} disabled={!text.trim()}>
            Add
          </Button>
        </div>
      </div>
    </Field>
  );
}

function EnvironmentPicker({
  environments,
  names,
  selected,
  onChange,
}: {
  environments: Environment[];
  names: Names;
  selected: string[];
  onChange: (next: string[]) => void;
}) {
  const [filter, setFilter] = useState("");
  const known = new Set(environments.map((e) => e.id));
  const unseen = selected.filter((id) => !known.has(id));
  const label = (e: Environment) => `${names.project(e.projectId)?.slug ?? "?"} / ${e.name}`;
  const shown = environments
    .filter((e) => label(e).toLowerCase().includes(filter.trim().toLowerCase()))
    .sort((a, b) => label(a).localeCompare(label(b)));
  const toggle = (id: string, on: boolean) => onChange(on ? [...selected, id] : selected.filter((x) => x !== id));
  return (
    <div className="space-y-2" data-testid="req-environments">
      <Input className="w-full max-w-sm" placeholder="Filter environments" value={filter} onChange={(e) => setFilter(e.target.value)} />
      <div className="max-h-56 space-y-1 overflow-y-auto rounded-md border border-bd p-2">
        {shown.map((e) => (
          <Checkbox
            key={e.id}
            data-testid={`req-env-${e.id}`}
            checked={selected.includes(e.id)}
            onChange={(on) => toggle(e.id, on)}
            label={
              <span className="inline-flex items-center gap-1.5 font-mono text-[12.5px]">
                <TierDot tier={e.tier as Tier} />
                {label(e)}
              </span>
            }
            description={!e.parentEnvironmentId ? "Also covers environments derived from it" : undefined}
          />
        ))}
        {shown.length === 0 && <p className="px-1 text-xs text-muted">No environments match.</p>}
      </div>
      {unseen.length > 0 && (
        <p className="text-xs text-muted" data-testid="req-unseen">
          Also covers {unseen.length === 1 ? "an environment" : `${unseen.length} environments`} you cannot see: {unseen.join(", ")}. Saving keeps{" "}
          {unseen.length === 1 ? "it" : "them"} unless you remove them here.{" "}
          {unseen.map((id) => (
            <button key={id} type="button" className="link" data-testid={`remove-unseen-${id}`} onClick={() => onChange(selected.filter((x) => x !== id))}>
              Remove {id}
            </button>
          ))}
        </p>
      )}
    </div>
  );
}
