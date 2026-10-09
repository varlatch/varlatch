// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { Eye, EyeOff, Lock, Pencil, TriangleAlert } from "lucide-react";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { useToast } from "../../components/Toast";
import { FilterInput, Highlight, matchesFilter } from "../../components/FilterInput";
import { Drawer, SidePanel } from "../../components/Drawer";
import { CopyButton } from "../../components/CodeBlock";
import { Button, Callout, EmptyState, IconButton, Kbd, Segmented, Skeleton, cn } from "../../components/ui";
import { errorMessage } from "../../shell/Shell";
import { formatDateTime, timeAgo, useNow } from "../../lib/time";
import { keys, useEnvironmentContext } from "../projects/hooks";
import {
  cellStateOf,
  draftKind,
  editorKind,
  isSensitive,
  parseDotenv,
  plural,
  storedText,
  type CellState,
  type ContractItemMeta,
  type ServerItem,
} from "../values/model";
import { useContractItems, useEnvSyncTargets, useEnvValues, useItemChanges, usePlatformConnections } from "../values/queries";
import { useDisclosure } from "../values/useDisclosure";
import { useDrafts, useUnsavedGuard } from "../values/useDrafts";
import { useReviewSave } from "../values/useReviewSave";
import { ReviewDialog } from "../values/ReviewDialog";
import { RotateDialog } from "../values/RotateDialog";
import { ImportDialog } from "../values/TransferDialogs";
import { AddItemForm } from "../values/AddItemForm";
import { DisclosureNotice, DraftMarker, RefHint, RotatingMarker, SaveBar, SecretMask, TypeBadge } from "../values/bits";
import { ValueEditor, type CommitHow } from "../values/ValueEditor";
import { targetCoversItem, targetLabel } from "../sync/syncStatus";
import { ItemPanelBody, panelHeading, type PanelActions } from "./ItemPanel";
import { TailnetOnlyNotice } from "../values/TailnetOnly";
import { TAILNET_ONLY_GUIDANCE, isTailnetOnly } from "../../lib/tailnet";

/**
 * One environment's values: a list of items with an inline panel for the
 * selected one. Same draft -> review -> save flow as the project grid.
 * `?item=NAME` selects an item (palette deep link); `?reveal=1` reveals all
 * authorized Secrets here once, as the explicit action chosen in the palette.
 */

type Row = {
  name: string;
  server: ServerItem | undefined;
  contract: ContractItemMeta | undefined;
  sensitive: boolean;
  state: CellState;
};
type Segment = "all" | "missing" | "secrets";

function useWide(): boolean {
  const query = "(min-width: 1200px)";
  const [wide, setWide] = useState(() => matchMedia(query).matches);
  useEffect(() => {
    const mq = matchMedia(query);
    const on = () => setWide(mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);
  return wide;
}

export function EditorPage() {
  const { org, project, environment, environments } = useEnvironmentContext();
  const slug = project.slug;
  const envName = environment.name;
  useOrgRealtime(
    org,
    ["value", "contract", "sync"],
    [
      ["effective-values", org, slug],
      ["effective-meta", org, slug],
      keys.contract(org, slug),
      keys.syncTargets(org, slug, envName),
      ["item-changes", org, environment.id],
      ["audit-item", org, environment.id],
    ],
  );
  const { api } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const wide = useWide();

  const values = useEnvValues(org, slug, environment);
  const contract = useContractItems(org, slug);
  const targets = useEnvSyncTargets(org, slug, envName);
  const connections = usePlatformConnections(org);
  const changes = useItemChanges(org, environment.id);
  const now = useNow(60_000);
  const drafts = useDrafts();
  const disclosure = useDisclosure(org, slug);

  const [params, setParams] = useSearchParams();
  const [selected, setSelected] = useState<string | null>(() => params.get("item"));
  const [active, setActive] = useState<string | null>(() => params.get("item"));
  const [editing, setEditing] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [segment, setSegment] = useState<Segment>("all");
  const [rotateItem, setRotateItem] = useState<string | null>(null);
  const [deadlines, setDeadlines] = useState<Map<string, string>>(() => new Map());
  const [importRows, setImportRows] = useState<{ name: string; value: string }[] | null>(null);
  const [busy, setBusy] = useState<{ reveal?: boolean; finish?: boolean }>({});
  const listRef = useRef<HTMLDivElement>(null);
  const pendingFocus = useRef<string | null>(null);

  // Deep links from the palette.
  const itemParam = params.get("item");
  useEffect(() => {
    if (itemParam) {
      setSelected(itemParam);
      setActive(itemParam);
    }
  }, [itemParam]);
  const revealParam = params.get("reveal") === "1";
  // A Tailnet Requirement covers this environment: no value can be read here.
  const tailnetOnly = values.data?.tailnetOnly ?? isTailnetOnly(environment);
  const revealedOnce = useRef(false);

  const serverByName = values.data?.byName;
  const serverOf = useCallback(() => serverByName, [serverByName]);

  const rows: Row[] = useMemo(() => {
    const names = new Set<string>([...contract.items.map((i) => i.name), ...(values.data?.items ?? []).map((i) => i.name)]);
    const known = [...names].sort();
    const added = [...(drafts.drafts.get(envName)?.keys() ?? [])].filter((n) => !names.has(n));
    return [...known, ...added].map((name) => {
      const server = serverByName?.get(name);
      const c = contract.byName.get(name);
      return { name, server, contract: c, sensitive: isSensitive(server, c), state: cellStateOf(server, c, environment) };
    });
  }, [contract.items, contract.byName, values.data, serverByName, drafts.drafts, envName, environment]);

  const missingCount = rows.filter((r) => r.state === "missing_required").length;
  const secretCount = rows.filter((r) => r.sensitive).length;
  const visible = rows.filter(
    (r) =>
      matchesFilter(filter, r.name) &&
      (segment === "all" || (segment === "missing" ? r.state === "missing_required" : r.sensitive)),
  );
  const authorizedSecrets = rows.filter((r) => r.sensitive && r.server).map((r) => r.name);

  const envTargets = useMemo(() => targets.data?.items ?? [], [targets.data]);
  const targetsFor = useCallback(
    (items: string[]) =>
      envTargets
        .filter((t) => t.state === "active" && items.some((i) => targetCoversItem(t, i)))
        .map((t) => targetLabel(t, connections.data?.items)),
    [envTargets, connections.data],
  );

  const review = useReviewSave({
    org,
    project: slug,
    environments: [environment],
    drafts,
    serverOf,
    sensitiveOf: (_env, item) => isSensitive(serverByName?.get(item), contract.byName.get(item)),
    targetsOf: (_env, items) => targetsFor(items),
    onSaved: () => disclosure.maskEnv(envName),
  });
  useUnsavedGuard(drafts.count > 0, `You have ${plural(drafts.count, "unsaved change")} in ${envName}.`);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.metaKey || e.ctrlKey) || e.key.toLowerCase() !== "s") return;
      e.preventDefault();
      if (document.querySelector('[role="dialog"][aria-modal="true"]')) return;
      review.openReview();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [review]);

  const reveal = useCallback(
    async (request: string[] | "all") => {
      if (tailnetOnly) {
        toast.info(`Not revealed in ${envName}`, { description: TAILNET_ONLY_GUIDANCE });
        return;
      }
      setBusy((b) => ({ ...b, reveal: true }));
      try {
        const result = await disclosure.reveal(envName, request);
        if (result.withheld.length > 0) {
          toast.error(`Not revealed: ${result.withheld.join(", ")}`, {
            description: "Your access does not include revealing these secrets.",
          });
        }
      } catch (err) {
        toast.error("Could not reveal", { description: errorMessage(err) });
      } finally {
        setBusy((b) => ({ ...b, reveal: false }));
      }
    },
    [disclosure, envName, toast, tailnetOnly],
  );

  // ?reveal=1: one audited reveal-all, then the flag leaves the URL. In a
  // tailnet-only environment reveal() explains instead of disclosing.
  useEffect(() => {
    if (!revealParam || revealedOnce.current || !values.data) return;
    revealedOnce.current = true;
    void reveal("all");
    setParams(
      (p) => {
        const next = new URLSearchParams(p);
        next.delete("reveal");
        return next;
      },
      { replace: true },
    );
  }, [revealParam, values.data, reveal, setParams]);

  // Focus follows keyboard moves; the selection scrolls into view.
  useEffect(() => {
    const name = pendingFocus.current;
    if (!name) return;
    pendingFocus.current = null;
    listRef.current?.querySelector<HTMLElement>(`[data-row="${CSS.escape(name)}"]`)?.focus();
  });
  useEffect(() => {
    if (!selected || !values.data) return;
    const el = listRef.current?.querySelector(`[data-row="${CSS.escape(selected)}"]`);
    const r = el?.getBoundingClientRect();
    if (el && r && (r.top < 0 || r.bottom > window.innerHeight)) el.scrollIntoView({ block: "center" });
  }, [selected, values.data]);

  const select = (name: string | null) => {
    setSelected(name);
    if (name) setActive(name);
    setParams(
      (p) => {
        const next = new URLSearchParams(p);
        if (name) next.set("item", name);
        else next.delete("item");
        return next;
      },
      { replace: true },
    );
  };
  const focusRow = (name: string) => {
    setActive(name);
    pendingFocus.current = name;
  };

  const commit = (row: Row, value: string, how: CommitHow) => {
    if (row.sensitive && value === "") {
      // Blind overwrite: an empty secret field means "no change".
    } else if (!row.sensitive && row.server?.source === "self" && value === storedText(row.server)) {
      drafts.setDraft(envName, row.name, null);
    } else {
      drafts.setDraft(envName, row.name, { op: "set", value });
    }
    setEditing(null);
    const i = visible.findIndex((r) => r.name === row.name);
    if (how === "tab") focusRow(visible[Math.min(visible.length - 1, i + 1)]?.name ?? row.name);
    else if (how === "shift-tab") focusRow(visible[Math.max(0, i - 1)]?.name ?? row.name);
    else if (how === "enter") focusRow(row.name);
    else if (how === "save") {
      focusRow(row.name);
      window.setTimeout(() => review.openReview(), 0);
    }
  };

  const refresh = () => qc.invalidateQueries({ queryKey: keys.effectiveValues(org, slug, envName) });

  const panelActions = (row: Row): PanelActions => ({
    reveal: () => void reveal([row.name]),
    hide: () => disclosure.toggleLocal(envName, row.name),
    edit: () => {
      // On narrow screens the panel is a modal drawer: close it to edit in the list.
      if (!wide) select(null);
      setActive(row.name);
      setEditing(row.name);
    },
    revert: () => drafts.setDraft(envName, row.name, null),
    remove: () => drafts.setDraft(envName, row.name, { op: "delete" }),
    rotate: () => setRotateItem(row.name),
    finishRotation: () => {
      setBusy((b) => ({ ...b, finish: true }));
      void api
        .completeRotation(org, slug, envName, row.name)
        .then(async () => {
          setDeadlines((m) => {
            const next = new Map(m);
            next.delete(row.name);
            return next;
          });
          toast.success(`Finished rotating ${row.name}`, { description: "The previous value no longer works." });
          await refresh();
        })
        .catch((err) => toast.error(`Could not finish rotating ${row.name}`, { description: errorMessage(err) }))
        .finally(() => setBusy((b) => ({ ...b, finish: false })));
    },
  });

  const onListKey = (e: React.KeyboardEvent) => {
    if (editing) return;
    const target = e.target as HTMLElement;
    const name = target.getAttribute("data-row");
    if (!name) return;
    const i = visible.findIndex((r) => r.name === name);
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const next = visible[Math.max(0, Math.min(visible.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))];
      if (next) {
        focusRow(next.name);
        if (selected) select(next.name);
      }
    } else if (e.key === "Enter") {
      e.preventDefault();
      select(name);
    } else if (e.key === "e" || e.key === "E") {
      e.preventDefault();
      if (draftKind(drafts.get(envName, name), serverByName?.get(name)) !== "deleted") setEditing(name);
    } else if (e.key === "Escape" && selected) {
      e.preventDefault();
      select(null);
    }
  };

  const discard = () => {
    const saved = drafts.drafts;
    const n = drafts.count;
    drafts.setDrafts(new Map());
    setEditing(null);
    toast.undo(`Discarded ${plural(n, "change")}`, () => drafts.setDrafts(saved));
  };

  const existsIn = (_env: string, name: string) => Boolean(serverByName?.get(name) || drafts.drafts.get(envName)?.has(name));
  const selectedRow = selected ? rows.find((r) => r.name === selected) : undefined;
  const revealedHere = disclosure.revealedEnvs.includes(envName);

  const panel = selectedRow ? (
    (() => {
      const { icon, badges } = panelHeading(selectedRow.sensitive, selectedRow.contract?.type);
      const body = (
        <ItemPanelBody
          org={org}
          project={slug}
          env={environment}
          name={selectedRow.name}
          server={selectedRow.server}
          contract={selectedRow.contract}
          sensitive={selectedRow.sensitive}
          state={selectedRow.state}
          draft={drafts.get(envName, selectedRow.name)}
          disclosed={disclosure.shown(envName, selectedRow.name)}
          withheld={values.data?.withheld.has(selectedRow.name) ?? false}
          tailnetOnly={tailnetOnly}
          rotationDeadline={deadlines.get(selectedRow.name)}
          targets={envTargets.filter((t) => targetCoversItem(t, selectedRow.name))}
          connections={connections.data?.items}
          busy={busy}
          actions={panelActions(selectedRow)}
        />
      );
      return wide ? (
        <SidePanel
          data-testid="item-panel"
          title={selectedRow.name}
          icon={icon}
          badges={badges}
          onClose={() => select(null)}
          className="sticky top-4"
        >
          {body}
        </SidePanel>
      ) : (
        <Drawer
          open
          data-testid="item-panel"
          onClose={() => select(null)}
          title={
            <span className="inline-flex flex-wrap items-center gap-2">
              <span className="text-muted">{icon}</span>
              <span className="font-mono">{selectedRow.name}</span>
              {badges}
            </span>
          }
        >
          <div className="space-y-6">{body}</div>
        </Drawer>
      );
    })()
  ) : null;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2.5">
        <FilterInput
          className="w-full max-w-sm sm:w-72"
          value={filter}
          onChange={setFilter}
          placeholder={`Filter ${plural(rows.length, "item")}…`}
          aria-label="Filter items"
          data-testid="values-filter"
          {...(filter ? { shown: visible.length, total: rows.length } : {})}
          onKeyDown={(e) => {
            if ((e.key === "ArrowDown" || e.key === "Enter") && visible[0]) {
              e.preventDefault();
              focusRow(visible[0].name);
              if (e.key === "Enter") select(visible[0].name);
            }
          }}
        />
        <Segmented
          value={segment}
          onChange={setSegment}
          aria-label="Show"
          options={[
            { value: "all", label: "All" },
            { value: "missing", label: "Missing", count: missingCount },
            { value: "secrets", label: "Secrets", count: secretCount },
          ]}
        />
        <div className="flex-1" />
        {authorizedSecrets.length > 0 &&
          !revealedHere &&
          !tailnetOnly && (
            <Button
              icon={<Eye size={14} />}
              data-testid="reveal-all"
              loading={busy.reveal}
              onClick={() => void reveal("all")}
              title="Requests every secret you may reveal here. Recorded in the audit log."
            >
              Reveal all secrets <span className="text-xs text-muted">audited</span>
            </Button>
          )}
      </div>

      {tailnetOnly && <TailnetOnlyNotice org={org} project={project} env={environment} environments={environments} />}
      <DisclosureNotice envs={revealedHere ? [envName] : []} onMaskAll={disclosure.maskAll} />
      {review.error && (
        <Callout
          tone="danger"
          icon={<TriangleAlert size={15} />}
          data-testid="editor-error"
          actions={
            <Button size="sm" variant="ghost" onClick={review.clearError}>
              Dismiss
            </Button>
          }
        >
          {review.error}
        </Callout>
      )}

      <div className={cn("grid items-start gap-5", wide && selectedRow && "grid-cols-[minmax(0,1fr)_440px]")}>
        <div className="min-w-0 overflow-hidden rounded-xl border border-bd bg-raised">
          <div
            ref={listRef}
            role="listbox"
            aria-label={`${envName} values`}
            data-testid="values-table"
            onKeyDown={onListKey}
          >
            {values.isLoading &&
              [0, 1, 2, 3].map((i) => (
                <div key={i} className="flex h-14 items-center gap-4 border-b border-bd px-5">
                  <Skeleton className="h-4 w-40" />
                  <Skeleton className="h-4 w-28" />
                </div>
              ))}
            {values.isError && (
              <EmptyState title="Values unavailable" description={errorMessage(values.error)} />
            )}
            {!values.isLoading && rows.length === 0 && (
              <EmptyState
                title="No values yet"
                description="Add an item below, paste a .env file into it, or push a contract with varlatch contract push."
              />
            )}
            {rows.length > 0 && visible.length === 0 && (
              <p className="px-5 py-8 text-center text-[13px] text-muted">
                {filter ? `No item matches “${filter}”.` : segment === "missing" ? "Nothing is missing." : "No secrets."}
              </p>
            )}
            {!values.isLoading && visible.map((row) => (
              <ValueRow
                key={row.name}
                row={row}
                filter={filter}
                draft={drafts.get(envName, row.name)}
                disclosed={disclosure.shown(envName, row.name)}
                isDisclosed={disclosure.isDisclosed(envName, row.name)}
                withheld={values.data?.withheld.has(row.name) ?? false}
                tailnetOnly={tailnetOnly}
                selected={selected === row.name}
                active={active === row.name || (!active && row === visible[0])}
                editing={editing === row.name}
                conflict={review.conflicts.has(`${envName}\u0000${row.name}`)}
                changedAt={row.server?.source === "self" ? changes.data?.[row.name] : undefined}
                now={now}
                onSelect={() => select(row.name)}
                onEdit={() => {
                  setActive(row.name);
                  setEditing(row.name);
                }}
                onCommit={(value, how) => commit(row, value, how)}
                onCancel={() => {
                  setEditing(null);
                  focusRow(row.name);
                }}
                onEye={() =>
                  disclosure.isDisclosed(envName, row.name)
                    ? disclosure.toggleLocal(envName, row.name)
                    : void reveal([row.name])
                }
              />
            ))}
          </div>
          <div className="border-t border-bd bg-inset/30 px-5 py-3">
            <AddItemForm
              environments={[environment]}
              initialEnv={envName}
              exists={existsIn}
              onAdd={(_env, name, value) => drafts.setDraft(envName, name, { op: "set", value })}
              onPaste={(text) => {
                const parsed = parseDotenv(text);
                if (!parsed || parsed.length < 2) return false;
                setImportRows(parsed);
                return true;
              }}
            />
          </div>
        </div>
        {panel}
      </div>

      <SaveBar count={drafts.count} envs={[envName]} onDiscard={discard} onReview={review.openReview} />

      <ReviewDialog
        open={review.reviewOpen}
        groups={review.groups}
        saving={review.saving}
        onClose={review.closeReview}
        onSave={() => void review.save()}
      />
      <ImportDialog
        rows={importRows}
        environments={[environment]}
        initialEnv={envName}
        isSensitive={(_env, name) => isSensitive(serverByName?.get(name), contract.byName.get(name))}
        existing={existsIn}
        onClose={() => setImportRows(null)}
        onImport={() => {
          for (const { name, value } of importRows ?? []) drafts.setDraft(envName, name, { op: "set", value });
          setImportRows(null);
        }}
      />
      {rotateItem && (
        <RotateDialog
          open
          item={rotateItem}
          project={slug}
          env={envName}
          defaultGraceSeconds={contract.byName.get(rotateItem)?.rotationGraceSeconds}
          targets={targetsFor([rotateItem])}
          onClose={() => setRotateItem(null)}
          onRotate={async (value, graceSeconds) => {
            const result = await api.beginRotation(org, slug, envName, rotateItem, { value, graceSeconds });
            if (result.rotationDeadline) {
              setDeadlines((m) => new Map(m).set(rotateItem, result.rotationDeadline as string));
            }
            toast.success(`Rotation of ${rotateItem} started`, { description: "Finish it once consumers use the new value." });
            setRotateItem(null);
            await refresh();
          }}
        />
      )}
    </div>
  );
}

function ValueRow({
  row,
  filter,
  draft,
  disclosed,
  isDisclosed,
  withheld,
  tailnetOnly,
  selected,
  active,
  editing,
  conflict,
  changedAt,
  now,
  onSelect,
  onEdit,
  onCommit,
  onCancel,
  onEye,
}: {
  row: Row;
  filter: string;
  draft: ReturnType<ReturnType<typeof useDrafts>["get"]>;
  disclosed: { value: string } | undefined;
  isDisclosed: boolean;
  withheld: boolean;
  tailnetOnly: boolean;
  selected: boolean;
  active: boolean;
  editing: boolean;
  conflict: boolean;
  /** Last write, deletion or rotation here, when the audit log can say. */
  changedAt: string | undefined;
  now: number;
  onSelect: () => void;
  onEdit: () => void;
  onCommit: (value: string, how: CommitHow) => void;
  onCancel: () => void;
  onEye: () => void;
}) {
  const { name, server, contract, sensitive, state } = row;
  const kind = draftKind(draft, server);
  const flavour = editorKind(sensitive, contract);

  let value: React.ReactNode;
  if (editing) {
    value = (
      <ValueEditor
        kind={flavour.kind}
        options={flavour.kind === "options" ? flavour.options : undefined}
        initial={draft?.op === "set" ? draft.value : (storedText(server) ?? "")}
        placeholder={sensitive ? (server ? "New value (overwrites)" : "Secret value") : undefined}
        aria-label={`${name} value`}
        onCommit={onCommit}
        onCancel={onCancel}
        className="max-w-xl flex-1"
      />
    );
  } else if (draft?.op === "set") {
    value = sensitive ? (
      <SecretMask className="text-fg/80" />
    ) : (
      <span className="min-w-0 truncate font-mono text-[13px]" title={draft.value}>
        {draft.value || <em className="text-muted">(empty)</em>}
      </span>
    );
  } else if (draft?.op === "delete") {
    value = (
      <span className="min-w-0 truncate font-mono text-[13px] text-muted line-through decoration-deny/70">
        {sensitive ? "••••••••••" : (storedText(server) ?? "")}
      </span>
    );
  } else if (state === "missing_required") {
    value = (
      <span className="inline-flex items-center gap-1.5 rounded-md border border-dashed border-deny/60 bg-deny/[0.05] px-2 py-0.5 text-[12.5px] font-medium text-deny">
        <TriangleAlert size={12} /> missing · required
      </span>
    );
  } else if (state === "covered_by_default") {
    value = <span className="font-mono text-[13px] italic text-muted">default {contract?.defaultValue}</span>;
  } else if (!server) {
    value = <span className="text-muted">—</span>;
  } else if (sensitive) {
    value = disclosed ? (
      <span className="min-w-0 truncate font-mono text-[13px]">{disclosed.value}</span>
    ) : (
      <SecretMask />
    );
  } else if (withheld) {
    value = tailnetOnly ? (
      <span className="text-[12.5px] text-muted" title={TAILNET_ONLY_GUIDANCE}>
        set · tailnet only
      </span>
    ) : (
      <span className="text-[12.5px] text-muted">set · value hidden</span>
    );
  } else {
    value = (
      <span className="min-w-0 truncate font-mono text-[13px]" title={server.value ?? ""}>
        {server.value === "" ? <em className="text-muted">(empty)</em> : server.value}
      </span>
    );
  }

  const copy = !draft && server ? (sensitive ? disclosed?.value : withheld ? undefined : (server.value ?? undefined)) : undefined;

  return (
    <div
      role="option"
      aria-selected={selected}
      data-row={name}
      tabIndex={active ? 0 : -1}
      onClick={(e) => {
        if (!e.currentTarget.contains(e.target as Node)) return;
        if ((e.target as HTMLElement).closest("button, a, input, textarea")) return;
        onSelect();
      }}
      onDoubleClick={(e) => {
        if ((e.target as HTMLElement).closest("button, a, input, textarea")) return;
        if (kind !== "deleted") onEdit();
      }}
      className={cn(
        "group relative flex min-h-14 cursor-pointer items-center gap-4 border-b border-bd px-5 py-2 outline-none transition-colors last:border-b-0",
        "focus-visible:bg-hover/70",
        selected ? "bg-hover" : "hover:bg-hover/50",
        kind === "edited" && "bg-warn/[0.05]",
        kind === "new" && "bg-accent/[0.05]",
        kind === "deleted" && "bg-deny/[0.04]",
        conflict && "shadow-[inset_0_0_0_1.5px_var(--deny)]",
      )}
    >
      {selected && <span aria-hidden="true" className="absolute inset-y-0 left-0 w-[3px] bg-accent" />}
      <span className="flex w-[34%] min-w-0 shrink-0 items-center gap-2">
        <span className="truncate font-mono text-[13px] font-semibold">
          <Highlight text={name} needle={filter} />
        </span>
        <TypeBadge type={contract?.type} />
      </span>
      <span className="flex min-w-0 flex-1 items-center gap-2.5 overflow-hidden">
        {sensitive && !editing && <Lock size={13} className="shrink-0 text-muted" aria-label="Secret" />}
        {value}
        {!editing && server?.rawValue !== undefined && !draft && <RefHint item={name} expanded={server.value} />}
        {server?.rotating && <RotatingMarker item={name} />}
        {server?.source === "parent" && !draft && (
          <span className="shrink-0 text-[11px] text-muted" title="Inherited from the parent environment">
            inherited
          </span>
        )}
        <DraftMarker kind={kind} />
      </span>
      {changedAt && !editing && (
        <span
          className="hidden shrink-0 text-xs text-muted group-hover:invisible group-focus-within:invisible group-aria-selected:invisible md:inline"
          title={formatDateTime(changedAt)}
        >
          changed {timeAgo(changedAt, now)}
        </span>
      )}
      {!editing && (
        <span className="absolute right-3 top-1/2 flex -translate-y-1/2 items-center gap-0.5 rounded-md border border-bd bg-raised p-0.5 opacity-0 shadow-sm transition-opacity group-hover:opacity-100 group-focus-within:opacity-100 group-aria-selected:opacity-100">
          {sensitive && server && !draft && !tailnetOnly && (
            <IconButton
              size="sm"
              label={disclosed ? "Hide" : isDisclosed ? "Show again" : "Reveal (audited)"}
              data-testid={`eye-${name}`}
              onClick={onEye}
            >
              {disclosed ? <EyeOff size={14} /> : <Eye size={14} />}
            </IconButton>
          )}
          {copy !== undefined && copy !== null && <CopyButton value={copy} label={`Copy ${name}`} />}
          {kind !== "deleted" && (
            <IconButton
              size="sm"
              label={sensitive && server ? "Overwrite (no reveal needed)" : "Edit"}
              data-testid={`edit-${name}`}
              onClick={onEdit}
            >
              <Pencil size={13} />
            </IconButton>
          )}
          <Kbd className="mx-1 hidden group-aria-selected:inline-flex">E</Kbd>
        </span>
      )}
    </div>
  );
}
