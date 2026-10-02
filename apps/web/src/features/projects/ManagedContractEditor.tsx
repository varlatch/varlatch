// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useMemo, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Lock, MoreHorizontal, Plus, RotateCcw, ShieldAlert, Trash2, Undo2 } from "lucide-react";
import type { ContractRevision, Tier } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { modKey } from "../../lib/hotkeys";
import { Dialog } from "../../components/Dialog";
import { FilterInput, Highlight, matchesFilter } from "../../components/FilterInput";
import { Badge, Button, Callout, Checkbox, IconButton, Input, Menu, Mono, Select, Switch, TierDot, cn } from "../../components/ui";
import { useToast } from "../../components/Toast";
import {
  ITEM_NAME,
  changeCount,
  diffItems,
  draftItems,
  requiredFromKey,
  requiredKey,
  rowProblem,
  rowState,
  rowsFrom,
  type Change,
  type ContractItem,
  type DraftRow,
  type Requiredness,
} from "./contractDraft";
import { typeOffer } from "./semanticsMove";

/** What each item type accepts; shown in the type picker. */
const TYPE_HELP: Record<string, string> = {
  string: "Any text value.",
  number: "Digits with an optional decimal part, e.g. -12 or 3.5. From rules version 2, at most 2^53 - 1 in magnitude.",
  integer: "A whole number, e.g. -12 or 3000, at most 2^53 - 1 in magnitude. Needs rules version 3.",
  boolean: "true or false in any case, or 1 or 0.",
  url: "An absolute URL including its scheme, e.g. https://…",
  email: "An email address.",
  enum: "One of a fixed set of allowed values.",
};

const REQUIRED_OPTIONS = [
  { value: "always", label: "always", description: "Every environment fails validation without it." },
  { value: "tier:production", label: "production only", description: "Required in production environments." },
  { value: "tier:staging", label: "staging only", description: "Required in staging environments." },
  { value: "tier:development", label: "development only", description: "Required in development environments." },
  { value: "never", label: "optional", description: "May be left out; its type is still checked when set." },
];

function requiredIcon(key: string): React.ReactNode {
  if (key.startsWith("tier:")) return <TierDot tier={key.slice(5) as Tier} />;
  if (key === "always") return <span className="inline-block size-2 rounded-full bg-info" />;
  return <span className="inline-block size-2 rounded-full border border-muted" />;
}

function requiredOptions(current: Requiredness) {
  const opts = REQUIRED_OPTIONS.map((o) => ({ ...o, icon: requiredIcon(o.value) }));
  if (requiredKey(current) === "environments") {
    opts.push({
      value: "environments",
      label: "selected environments",
      description: "Required in specific environments, as pushed from the CLI.",
      icon: <span className="inline-block size-2 rounded-full bg-muted" />,
    });
  }
  return opts;
}

function typeOptions(version: number | undefined, newest: number) {
  return Object.keys(TYPE_HELP).map((t) => {
    const offer = typeOffer(t, version, newest);
    return offer.enabled
      ? { value: t, label: t, description: TYPE_HELP[t] }
      : { value: t, label: t, disabled: true, description: offer.reason };
  });
}

const EMPTY_NEW = { name: "", type: "string", required: "always", sensitive: false, defaultValue: "", description: "" };

/**
 * Managed contract editor: spreadsheet-style rows edited in place, kept as a
 * draft (changed rows marked, removals struck through) until "Publish
 * revision" pushes and activates a new revision. Security-relevant changes
 * (secret, required, type, items added or removed) need an explicit
 * acknowledgement first.
 */
export function ManagedContractEditor({
  org,
  project,
  active,
  items,
  version,
  newest,
  onPublished,
}: {
  org: string;
  project: string;
  active: ContractRevision | undefined;
  items: ContractItem[];
  /** The version a published revision gets: edits keep the active one's. */
  version: number | undefined;
  newest: number;
  onPublished: () => Promise<unknown>;
}) {
  const { api } = useSession();
  const toast = useToast();
  const [rows, setRows] = useState<DraftRow[]>(() => rowsFrom(items));
  const [baseId, setBaseId] = useState(active?.id ?? null);
  const [filter, setFilter] = useState("");
  const [draftNew, setDraftNew] = useState(EMPTY_NEW);
  const [addError, setAddError] = useState<string | null>(null);
  const [review, setReview] = useState<"view" | "publish" | null>(null);
  const [ack, setAck] = useState(false);
  const newKey = useRef(0);
  const nameInput = useRef<HTMLInputElement>(null);

  const changes = changeCount(rows);
  const dirty = changes > 0;
  const activeId = active?.id ?? null;
  const stale = baseId !== activeId;

  // The revision this editor just published: when it becomes active, the
  // draft starts over from it.
  const published = useRef<string | null>(null);
  // A newer active revision replaces a clean draft; a dirty one is kept and flagged.
  useEffect(() => {
    if (activeId === baseId) return;
    if (!dirty || (activeId !== null && activeId === published.current)) {
      published.current = null;
      setRows(rowsFrom(items));
      setBaseId(activeId);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeId]);

  useEffect(() => {
    if (!dirty) return;
    const onUnload = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", onUnload);
    return () => window.removeEventListener("beforeunload", onUnload);
  }, [dirty]);

  const pushed = useMemo(() => draftItems(rows), [rows]);
  const original = useMemo(() => rows.filter((r) => r.origin).map((r) => r.origin!), [rows]);
  const diff = useMemo(() => diffItems(original, pushed), [original, pushed]);
  const security = diff.some((c) => c.securityRelevant);
  const nameCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const r of rows) if (!r.removed) m.set(r.item.name, (m.get(r.item.name) ?? 0) + 1);
    return m;
  }, [rows]);
  const problems = rows.filter((r) => !r.removed && rowProblem(r.item, nameCounts));
  const integerOffer = typeOffer("integer", version, newest);
  const types = typeOptions(version, newest);

  const update = (key: string, patch: Partial<ContractItem>) =>
    setRows((all) => all.map((r) => (r.key === key ? { ...r, item: { ...r.item, ...patch } } : r)));
  const setRow = (key: string, fn: (r: DraftRow) => DraftRow) => setRows((all) => all.map((r) => (r.key === key ? fn(r) : r)));

  const publish = useMutation({
    mutationFn: async () => {
      const revision = await api.pushContractRevision(org, project, { contract: { schemaVersion: 1, items: pushed } });
      if (revision.id === activeId) return { unchanged: true };
      published.current = revision.id;
      await api.activateContractRevision(org, project, revision.id);
      await onPublished();
      return { unchanged: false, revision };
    },
    onSuccess: (r) => {
      setReview(null);
      setAck(false);
      if (r.unchanged) {
        toast.info("Nothing to publish", { description: "The draft matches the active revision." });
      } else {
        toast.success("Revision published", { description: `${pushed.length} items, now active in every environment.` });
      }
    },
    onError: (err) => toast.error("Could not publish the revision", { description: err instanceof Error ? err.message : String(err) }),
  });

  const startPublish = () => {
    if (!dirty || publish.isPending) return;
    if (problems.length > 0) {
      toast.error("Fix the highlighted rows first", { description: rowProblem(problems[0]!.item, nameCounts) ?? undefined });
      return;
    }
    if (security) {
      setAck(false);
      setReview("publish");
    } else publish.mutate();
  };

  // ⌘S / Ctrl+S publishes (through the review when it needs one).
  const startRef = useRef(startPublish);
  startRef.current = startPublish;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "s") {
        e.preventDefault();
        startRef.current();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const addItem = () => {
    const name = draftNew.name.trim();
    if (!ITEM_NAME.test(name)) return setAddError("Use capitals, digits and underscores, starting with a letter.");
    const existing = rows.find((r) => r.item.name === name);
    if (existing && !existing.removed) return setAddError(`${name} is already in the contract; edit its row instead.`);
    const offer = typeOffer(draftNew.type, version, newest);
    if (!offer.enabled) return setAddError(offer.reason);
    const item: ContractItem = {
      name,
      type: draftNew.type,
      sensitive: draftNew.sensitive,
      required: requiredFromKey(draftNew.required, { kind: "always" }),
      ...(draftNew.type === "enum" ? { enumValues: [] } : {}),
      ...(draftNew.defaultValue ? { defaultValue: draftNew.defaultValue } : {}),
      ...(draftNew.description ? { description: draftNew.description } : {}),
    };
    if (existing?.removed) {
      setRow(existing.key, (r) => ({ ...r, removed: false, item: { ...r.item, ...item } }));
    } else {
      newKey.current += 1;
      setRows((all) => [...all, { key: `new:${newKey.current}`, item, origin: null, removed: false }]);
    }
    setDraftNew(EMPTY_NEW);
    setAddError(null);
    nameInput.current?.focus();
  };

  const discard = () => {
    const snapshot = rows;
    setRows(rowsFrom(items));
    setBaseId(activeId);
    toast.undo("Draft discarded", () => setRows(snapshot));
  };

  const visible = rows.filter((r) => matchesFilter(filter, r.item.name, r.item.description, r.item.type));

  return (
    <>
      {stale && dirty && (
        <Callout
          tone="warn"
          className="mb-3"
          title="Someone published a newer revision while you were editing"
          actions={
            <Button size="sm" onClick={discard}>
              Start over from it
            </Button>
          }
        >
          Publishing this draft replaces it. Review the diff first.
        </Callout>
      )}
      <section className="overflow-hidden rounded-xl border border-bd bg-raised" data-testid="managed-editor">
        <header className="flex flex-wrap items-center gap-3 border-b border-bd px-5 py-3">
          <h2 className="flex items-center gap-2 text-[15px] font-semibold" data-testid="contract-authority" data-authority="managed">
            Contract
            {dirty ? (
              <span className="flex items-center gap-1.5 font-mono text-[13px] font-normal text-warn">
                · <span className="size-2 rounded-full bg-warn" /> draft
              </span>
            ) : (
              <span className="text-[13px] font-normal text-muted">
                · {pushed.length} item{pushed.length === 1 ? "" : "s"} · edited here
              </span>
            )}
          </h2>
          <FilterInput
            value={filter}
            onChange={setFilter}
            placeholder="Filter items…"
            className="ml-auto w-full max-w-xs"
            aria-label="Filter contract items"
            {...(filter ? { shown: visible.length, total: rows.length } : {})}
          />
        </header>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[980px] border-collapse text-sm" data-testid="contract-items">
            <thead>
              <tr>
                <th className="h-9 w-[220px] border-b border-bd px-4 text-left text-xs font-medium text-muted">Item</th>
                <th className="h-9 w-[150px] border-b border-bd px-2 text-left text-xs font-medium text-muted">Type</th>
                <th className="h-9 w-[190px] border-b border-bd px-2 text-left text-xs font-medium text-muted">Required</th>
                <th className="h-9 w-[64px] border-b border-bd px-2 text-left text-xs font-medium text-muted">Secret</th>
                <th className="h-9 w-[150px] border-b border-bd px-2 text-left text-xs font-medium text-muted">Default</th>
                <th className="h-9 border-b border-bd px-2 text-left text-xs font-medium text-muted">Description</th>
                <th className="h-9 w-12 border-b border-bd" />
              </tr>
            </thead>
            <tbody>
              {visible.map((r) => (
                <EditorRow
                  key={r.key}
                  row={r}
                  filter={filter}
                  problem={r.removed ? null : rowProblem(r.item, nameCounts)}
                  types={types}
                  onChange={(patch) => update(r.key, patch)}
                  onRemove={() =>
                    r.origin ? setRow(r.key, (x) => ({ ...x, removed: true })) : setRows((all) => all.filter((x) => x.key !== r.key))
                  }
                  onRestore={() => setRow(r.key, (x) => ({ ...x, removed: false }))}
                  onUndo={() => setRow(r.key, (x) => ({ ...x, item: x.origin ?? x.item, removed: false }))}
                />
              ))}
              {/* The add row: Enter in any field adds the item. */}
              <tr className="bg-inset/30" onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLElement).tagName === "INPUT" && addItem()}>
                <td className="px-4 py-2 align-top">
                  <Input
                    ref={nameInput}
                    data-testid="contract-item-name"
                    mono
                    className="w-full"
                    placeholder="NEW_ITEM"
                    aria-label="New item name"
                    value={draftNew.name}
                    invalid={Boolean(addError)}
                    onChange={(e) => {
                      setDraftNew({ ...draftNew, name: e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, "_") });
                      setAddError(null);
                    }}
                  />
                </td>
                <td className="px-2 py-2 align-top">
                  <Select
                    data-testid="contract-item-type"
                    aria-label="New item type"
                    className="w-full"
                    value={draftNew.type}
                    onChange={(type) => setDraftNew({ ...draftNew, type })}
                    options={types}
                  />
                </td>
                <td className="px-2 py-2 align-top">
                  <Select
                    data-testid="contract-item-required"
                    aria-label="New item required"
                    className="w-full"
                    value={draftNew.required}
                    onChange={(required) => setDraftNew({ ...draftNew, required })}
                    options={requiredOptions({ kind: "always" })}
                  />
                </td>
                <td className="px-2 py-2 align-top">
                  <span className="flex h-8 items-center">
                    <Switch
                      data-testid="contract-item-secret"
                      label="New item is a secret"
                      checked={draftNew.sensitive}
                      onChange={(sensitive) => setDraftNew({ ...draftNew, sensitive })}
                    />
                  </span>
                </td>
                <td className="px-2 py-2 align-top">
                  <Input
                    mono
                    className="w-full"
                    placeholder="none"
                    aria-label="New item default"
                    value={draftNew.defaultValue}
                    onChange={(e) => setDraftNew({ ...draftNew, defaultValue: e.target.value })}
                  />
                </td>
                <td className="px-2 py-2 align-top">
                  <Input
                    className="w-full"
                    placeholder="What it is for"
                    aria-label="New item description"
                    value={draftNew.description}
                    onChange={(e) => setDraftNew({ ...draftNew, description: e.target.value })}
                  />
                </td>
                <td className="py-2 pr-3 align-top">
                  <IconButton label="Add item" data-testid="contract-add-item" disabled={!draftNew.name} onClick={addItem} className="border-bd bg-raised">
                    <Plus size={16} />
                  </IconButton>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        {(addError || (!integerOffer.enabled && version !== undefined)) && (
          <div className="space-y-1 border-t border-bd px-5 py-2.5 text-xs">
            {addError && <p className="text-deny">{addError}</p>}
            {!integerOffer.enabled && version !== undefined && (
              <p className="text-muted" data-testid="integer-unavailable">
                integer: {integerOffer.reason}
              </p>
            )}
          </div>
        )}
      </section>

      {dirty && (
        <div className="pointer-events-none sticky bottom-6 z-30 mt-4 flex justify-end">
          <div
            className="pointer-events-auto flex animate-pop-in flex-wrap items-center gap-2 rounded-xl border border-bd bg-raised py-2 pl-4 pr-2 shadow-pop"
            data-testid="contract-draft-bar"
          >
            <span className="mr-2 flex items-center gap-2 text-sm text-warn">
              <span className="size-2.5 rounded-full bg-warn" />
              Draft · {changes} change{changes === 1 ? "" : "s"}
            </span>
            <span className="mx-1 h-6 w-px bg-bd" />
            <Button variant="ghost" onClick={discard}>
              Discard
            </Button>
            <Button data-testid="contract-view-diff" onClick={() => setReview("view")}>
              View diff
            </Button>
            <Button
              variant="primary"
              data-testid="contract-publish"
              loading={publish.isPending}
              onClick={startPublish}
              title={`Publish revision (${modKey()}+S)`}
            >
              Publish revision
            </Button>
          </div>
        </div>
      )}

      {review && (
        <DiffDialog
          diff={diff}
          names={pushed.map((i) => i.name)}
          mode={review}
          security={security}
          ack={ack}
          onAck={setAck}
          publishing={publish.isPending}
          onClose={() => setReview(null)}
          onPublish={() => {
            if (problems.length > 0) {
              setReview(null);
              startPublish();
            } else publish.mutate();
          }}
        />
      )}
    </>
  );
}

function EditorRow({
  row,
  filter,
  problem,
  types,
  onChange,
  onRemove,
  onRestore,
  onUndo,
}: {
  row: DraftRow;
  filter: string;
  problem: string | null;
  types: ReturnType<typeof typeOptions>;
  onChange: (patch: Partial<ContractItem>) => void;
  onRemove: () => void;
  onRestore: () => void;
  onUndo: () => void;
}) {
  const state = rowState(row);
  const item = row.item;
  const removed = row.removed;
  const rk = requiredKey(item.required);
  return (
    <tr
      data-contract-item={item.name}
      data-row-state={state}
      className={cn(
        "relative border-b border-bd align-top transition-colors",
        state === "edited" && "bg-warn/[0.04]",
        state === "new" && "bg-allow/[0.04]",
        removed && "bg-deny/[0.04]",
      )}
    >
      <td className="relative px-4 py-2">
        {state !== "unchanged" && (
          <span
            aria-hidden="true"
            className={cn("absolute inset-y-0 left-0 w-[3px]", state === "edited" ? "bg-warn" : state === "new" ? "bg-allow" : "bg-deny")}
          />
        )}
        <div className="flex min-h-8 items-center gap-2">
          {state === "edited" && <Badge tone="warn">edited</Badge>}
          {state === "new" && <Badge tone="accent">new</Badge>}
          {removed && <Badge tone="danger">removed</Badge>}
          {row.origin ? (
            <span className={cn("truncate font-mono text-[13px] font-medium text-fg", removed && "text-muted line-through")} title={item.name}>
              <Highlight text={item.name} needle={filter} />
            </span>
          ) : (
            <Input
              mono
              className="h-8 min-w-0 flex-1"
              aria-label="Item name"
              value={item.name}
              invalid={Boolean(problem)}
              onChange={(e) => onChange({ name: e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, "_") })}
            />
          )}
        </div>
        {problem && <p className="mt-1 text-xs text-deny">{problem}</p>}
      </td>
      <td className="px-2 py-2">
        <Select
          aria-label={`Type of ${item.name}`}
          data-testid={`row-type-${item.name}`}
          className="w-full"
          disabled={removed}
          value={item.type}
          onChange={(type) => onChange({ type, ...(type === "enum" && !item.enumValues ? { enumValues: [] } : {}) })}
          options={types.map((t) => (t.value === item.type ? { ...t, disabled: false } : t))}
        />
        {item.type === "enum" && !removed && (
          <Input
            mono
            className="mt-1.5 w-full"
            aria-label={`Allowed values of ${item.name}`}
            placeholder="a, b, c"
            value={(item.enumValues ?? []).join(", ")}
            onChange={(e) => onChange({ enumValues: e.target.value.split(",").map((v) => v.trimStart()) })}
            onBlur={(e) => onChange({ enumValues: e.target.value.split(",").map((v) => v.trim()).filter(Boolean) })}
          />
        )}
      </td>
      <td className="px-2 py-2">
        <Select
          aria-label={`Required for ${item.name}`}
          data-testid={`row-required-${item.name}`}
          className="w-full"
          disabled={removed}
          value={rk}
          onChange={(key) => onChange({ required: requiredFromKey(key, item.required) })}
          options={requiredOptions(row.origin?.required ?? item.required)}
        />
      </td>
      <td className="px-2 py-2">
        <span className="flex h-8 items-center gap-1.5">
          <Switch
            label={`${item.name} is a secret`}
            data-testid={`row-secret-${item.name}`}
            checked={item.sensitive}
            disabled={removed}
            onChange={(sensitive) => onChange({ sensitive })}
          />
          {item.sensitive && <Lock size={12} className="text-muted" aria-hidden="true" />}
        </span>
      </td>
      <td className="px-2 py-2">
        <Input
          mono
          className="w-full"
          placeholder="none"
          aria-label={`Default of ${item.name}`}
          disabled={removed}
          value={item.defaultValue ?? ""}
          onChange={(e) => onChange({ defaultValue: e.target.value })}
        />
      </td>
      <td className="px-2 py-2">
        <input
          className="h-8 w-full rounded-md border border-transparent bg-transparent px-2.5 text-[13px] text-muted placeholder:text-subtle transition-colors hover:border-bd focus:border-accent focus:bg-inset focus:text-fg focus:outline-none focus:ring-2 focus:ring-accent/20 disabled:opacity-50"
          placeholder="Add a description"
          aria-label={`Description of ${item.name}`}
          disabled={removed}
          value={item.description ?? ""}
          onChange={(e) => onChange({ description: e.target.value })}
        />
      </td>
      <td className="py-2 pr-3">
        <Menu
          label={`Actions for ${item.name || "new item"}`}
          buttonClassName="size-8 justify-center border border-bd"
          items={[
            ...(state === "edited" ? [{ label: "Undo changes", icon: <Undo2 size={14} />, onSelect: onUndo }] : []),
            removed
              ? { label: "Restore item", icon: <RotateCcw size={14} />, onSelect: onRestore }
              : {
                  label: row.origin ? "Remove item" : "Discard new item",
                  danger: true,
                  icon: <Trash2 size={14} />,
                  "data-testid": `remove-item-${item.name}`,
                  onSelect: onRemove,
                },
          ]}
        >
          <MoreHorizontal size={16} />
        </Menu>
      </td>
    </tr>
  );
}

function changeText(c: Change): React.ReactNode {
  const arrow = (from: string | undefined, to: string | undefined) => (
    <>
      <span className="text-muted line-through decoration-muted/60">{from || "none"}</span>
      <span className="mx-1.5 text-subtle">→</span>
      <span className="text-fg">{to || "none"}</span>
    </>
  );
  switch (c.kind) {
    case "added":
      return <span className="text-allow">added · {c.to}</span>;
    case "removed":
      return <span className="text-deny">removed from the contract</span>;
    case "secret":
      return <>secret: {arrow(c.from, c.to)}</>;
    case "required":
      return <>required: {arrow(c.from, c.to)}</>;
    case "type":
      return <>type: {arrow(c.from, c.to)}</>;
    case "enum":
      return <>allowed values: {arrow(c.from, c.to)}</>;
    case "default":
      return <>default: {arrow(c.from, c.to)}</>;
    case "description":
      return <>description: {arrow(c.from, c.to)}</>;
    default:
      return <>other details changed</>;
  }
}

function DiffDialog({
  diff,
  names,
  mode,
  security,
  ack,
  onAck,
  publishing,
  onClose,
  onPublish,
}: {
  diff: Change[];
  names: string[];
  mode: "view" | "publish";
  security: boolean;
  ack: boolean;
  onAck: (v: boolean) => void;
  publishing: boolean;
  onClose: () => void;
  onPublish: () => void;
}) {
  const relevant = diff.filter((c) => c.securityRelevant);
  const other = diff.filter((c) => !c.securityRelevant);
  const list = (changes: Change[]) => (
    <ul className="divide-y divide-bd rounded-lg border border-bd">
      {changes.map((c, i) => (
        <li key={`${c.name}:${c.kind}:${i}`} className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 px-3 py-2 text-[13px]" data-change={c.kind}>
          <Mono className="font-medium">{c.name}</Mono>
          <span className="min-w-0 break-words">{changeText(c)}</span>
        </li>
      ))}
    </ul>
  );
  return (
    <Dialog
      open
      onClose={onClose}
      size="md"
      data-testid="contract-diff"
      title={mode === "publish" ? "Publish this revision?" : "Draft changes"}
      description={`${diff.length} change${diff.length === 1 ? "" : "s"} against the active revision. Publishing activates the new revision for every environment at once.`}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            {mode === "publish" ? "Back to editing" : "Close"}
          </Button>
          <Button
            variant="primary"
            data-testid="contract-publish-confirm"
            disabled={(security && !ack) || diff.length === 0}
            loading={publishing}
            onClick={onPublish}
          >
            Publish revision
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {relevant.length > 0 && (
          <div className="space-y-2">
            <h3 className="flex items-center gap-1.5 text-[13px] font-semibold text-warn">
              <ShieldAlert size={14} /> Security-relevant
            </h3>
            {list(relevant)}
          </div>
        )}
        {other.length > 0 && (
          <div className="space-y-2">
            <h3 className="text-[13px] font-semibold">Defaults and descriptions</h3>
            {list(other)}
          </div>
        )}
        {diff.length === 0 && <p className="text-[13px] text-muted">The draft matches the active revision.</p>}
        <p className="text-xs text-muted" data-testid="contract-draft-names">
          The new revision lists {names.length} item{names.length === 1 ? "" : "s"}: <span className="font-mono">{names.join(", ")}</span>
        </p>
        {security && (
          <Checkbox
            data-testid="contract-publish-ack"
            checked={ack}
            onChange={onAck}
            label="I understand this changes which values are protected, required or accepted"
            description="Secrets are masked and audited by this flag; required items gate validation in every environment."
          />
        )}
      </div>
    </Dialog>
  );
}
