// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { ChevronDown, Download, Eye, EyeOff, Layers, Lock, Plus, TriangleAlert } from "lucide-react";
import type { Environment, Tier } from "@varlatch/protocol";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { useToast } from "../../components/Toast";
import { FilterInput, Highlight, matchesFilter } from "../../components/FilterInput";
import { Menu } from "../../components/Select";
import {
  Badge,
  Button,
  Callout,
  EmptyState,
  IconButton,
  Segmented,
  Skeleton,
  TierDot,
  cn,
} from "../../components/ui";
import { errorMessage } from "../../shell/Shell";
import { keys, useProjectContext } from "./hooks";
import { NewEnvironmentDialog } from "./NewEnvironmentDialog";
import { ValuesGridCell, type CellActions } from "./ValuesGridCell";
import {
  cellStateOf,
  envPath,
  groupEnvironments,
  isSensitive,
  parseDotenv,
  plural,
  storedText,
  type ContractItemMeta,
} from "../values/model";
import { markTailnetOnly, tailnetAccess, useContractItems, useManyEnvValues, usePlatformConnections, useProjectSyncTargets } from "../values/queries";
import { useDisclosure } from "../values/useDisclosure";
import { useDrafts, useUnsavedGuard } from "../values/useDrafts";
import { useReviewSave } from "../values/useReviewSave";
import { ReviewDialog } from "../values/ReviewDialog";
import { RotateDialog } from "../values/RotateDialog";
import { ExportDialog, ImportDialog } from "../values/TransferDialogs";
import { AddItemForm } from "../values/AddItemForm";
import { DisclosureNotice, SaveBar, TypeBadge } from "../values/bits";
import { TailnetConnectPrompt, TailnetOnlyBadge } from "../values/TailnetOnly";
import { TAILNET_ONLY_GUIDANCE, isTailnetOnly } from "../../lib/tailnet";
import type { CommitHow } from "../values/ValueEditor";
import { targetCoversItem, targetLabel } from "../sync/syncStatus";

/**
 * The project's Values tab: one grid, rows = config items, columns = root
 * environments in tier order (derived environments grouped under their
 * root). Non-secret values show in place; Secrets stay masked until an
 * explicit, audited reveal. Cells edit inline into drafts; nothing is saved
 * until the review.
 */

type Segment = "all" | "missing" | "secrets";
type Pos = { row: string; col: number };

type Row = { name: string; contract: ContractItemMeta | undefined; sensitive: boolean; type: string | undefined };

export function ValuesGrid() {
  const { org, project, environments } = useProjectContext();
  const slug = project.slug;
  useOrgRealtime(
    org,
    ["value", "environment", "contract"],
    [["effective-values", org, slug], ["effective-meta", org, slug], keys.contract(org, slug)],
  );
  const { api } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();

  const groups = useMemo(() => groupEnvironments(environments), [environments]);
  const roots = useMemo(() => groups.map((g) => g.root), [groups]);
  const contract = useContractItems(org, slug);
  const columns = useManyEnvValues(org, slug, roots);
  const targetsByEnv = useProjectSyncTargets(org, project.id);
  const connections = usePlatformConnections(org);
  const drafts = useDrafts();
  // Columns a Tailnet Requirement covers: read through the tailnet endpoint
  // once this tab has connected, otherwise held back (`restricted`).
  const access = roots.map((env, i) => tailnetAccess(env, columns[i]?.data));
  const restrictedKey = roots
    .filter((_, i) => access[i]!.blocked)
    .map((env) => env.name)
    .join("\u0000");
  const protectedKey = roots
    .filter((_, i) => access[i]!.isProtected)
    .map((env) => env.name)
    .join("\u0000");
  const restricted = useMemo(() => new Set(restrictedKey ? restrictedKey.split("\u0000") : []), [restrictedKey]);
  const protectedEnvs = useMemo(() => new Set(protectedKey ? protectedKey.split("\u0000") : []), [protectedKey]);
  const disclosure = useDisclosure(org, slug, restricted, {
    protectedEnvs,
    onTailnetOnly: (env) => markTailnetOnly(qc, org, slug, env),
  });

  const [filter, setFilter] = useState("");
  const [segment, setSegment] = useState<Segment>("all");
  const [active, setActive] = useState<Pos | null>(null);
  const [editing, setEditing] = useState<Pos | null>(null);
  const [importRows, setImportRows] = useState<{ rows: { name: string; value: string }[]; env: string } | null>(null);
  // By id: the dialog follows the environment as it is now, protection included.
  const [exportEnvId, setExportEnvId] = useState<string | null>(null);
  const exportEnv = exportEnvId ? (environments.find((e) => e.id === exportEnvId) ?? null) : null;
  const [rotating, setRotating] = useState<{ env: Environment; item: string } | null>(null);
  const [newEnvOpen, setNewEnvOpen] = useState(false);
  const tableRef = useRef<HTMLTableElement>(null);
  const pendingFocus = useRef<Pos | null>(null);

  const serverOf = useCallback(
    (envName: string) => {
      const i = roots.findIndex((r) => r.name === envName);
      return i >= 0 ? columns[i]?.data?.byName : undefined;
    },
    [roots, columns],
  );

  // Rows: contract items, values present anywhere, then new drafted names.
  const rows: Row[] = useMemo(() => {
    const names = new Set<string>(contract.items.map((i) => i.name));
    for (const c of columns) for (const item of c.data?.items ?? []) names.add(item.name);
    const known = [...names].sort();
    const added: string[] = [];
    for (const env of roots) for (const n of drafts.drafts.get(env.name)?.keys() ?? []) if (!names.has(n) && !added.includes(n)) added.push(n);
    return [...known, ...added].map((name) => {
      const c = contract.byName.get(name);
      const server = columns.map((col) => col.data?.byName.get(name)).find(Boolean);
      return { name, contract: c, sensitive: isSensitive(server, c), type: c?.type };
    });
  }, [contract.items, contract.byName, columns, drafts.drafts, roots]);

  const stats = useMemo(
    () =>
      roots.map((env, i) => {
        const col = columns[i];
        const byName = col?.data?.byName;
        let missing = 0;
        const secrets: string[] = [];
        for (const r of rows) {
          const server = byName?.get(r.name);
          if (byName && cellStateOf(server, r.contract, env) === "missing_required") missing++;
          if (server && isSensitive(server, r.contract)) secrets.push(r.name);
        }
        return {
          missing,
          secrets,
          loading: col?.isLoading ?? true,
          error: col?.isError ?? false,
          // A Tailnet Requirement covers the column: no value can be read here.
          tailnetOnly: restricted.has(env.name),
        };
      }),
    [roots, columns, rows, restricted],
  );

  const missingRows = rows.filter((r) =>
    roots.some((env, i) => columns[i]?.data && cellStateOf(columns[i]!.data!.byName.get(r.name), r.contract, env) === "missing_required"),
  );
  const secretRows = rows.filter((r) => r.sensitive);
  const visible = rows.filter(
    (r) =>
      matchesFilter(filter, r.name) &&
      (segment === "all" || (segment === "missing" ? missingRows.includes(r) : r.sensitive)),
  );

  // Keep the active cell on screen and focused after keyboard moves.
  useEffect(() => {
    const p = pendingFocus.current;
    if (!p) return;
    pendingFocus.current = null;
    tableRef.current?.querySelector<HTMLElement>(`[data-pos="${CSS.escape(`${p.row}:${p.col}`)}"]`)?.focus();
  });
  const focusCell = useCallback((p: Pos) => {
    setActive(p);
    pendingFocus.current = p;
  }, []);

  const move = (from: Pos, dRow: number, dCol: number, wrap = false) => {
    let r = visible.findIndex((x) => x.name === from.row);
    let c = from.col + dCol;
    if (wrap && c >= roots.length) {
      c = 0;
      r++;
    } else if (wrap && c < 0) {
      c = roots.length - 1;
      r--;
    }
    r = Math.max(0, Math.min(visible.length - 1, r + dRow));
    c = Math.max(0, Math.min(roots.length - 1, c));
    const row = visible[r];
    if (row) focusCell({ row: row.name, col: c });
  };

  const review = useReviewSave({
    org,
    project: slug,
    environments: roots,
    drafts,
    serverOf,
    sensitiveOf: (env, item) => isSensitive(serverOf(env)?.get(item), contract.byName.get(item)),
    targetsOf: (env, items) =>
      (targetsByEnv.get(env.id) ?? [])
        .filter((t) => t.state === "active" && items.some((i) => targetCoversItem(t, i)))
        .map((t) => targetLabel(t, connections.data?.items)),
    onSaved: (envs) => envs.forEach(disclosure.maskEnv),
  });

  useUnsavedGuard(drafts.count > 0, `You have ${plural(drafts.count, "unsaved change")} in ${slug}.`);

  // Cmd/Ctrl+S opens the review from anywhere on the page.
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

  const commit = (p: Pos, value: string, how: CommitHow) => {
    const env = roots[p.col];
    if (!env) return;
    const server = serverOf(env.name)?.get(p.row);
    const row = rows.find((r) => r.name === p.row);
    const sensitive = isSensitive(server, row?.contract);
    if (sensitive && value === "") {
      // Blind overwrite: an empty secret field means "no change".
    } else if (!sensitive && server?.source === "self" && value === storedText(server)) {
      drafts.setDraft(env.name, p.row, null);
    } else {
      drafts.setDraft(env.name, p.row, { op: "set", value });
    }
    setEditing(null);
    if (how === "tab") move(p, 0, 1, true);
    else if (how === "shift-tab") move(p, 0, -1, true);
    else if (how === "enter") focusCell(p);
    else if (how === "save") {
      focusCell(p);
      window.setTimeout(() => review.openReview(), 0);
    }
  };

  const reveal = async (env: Environment, items: string[]) => {
    if (items.length === 0) return;
    if (stats[roots.indexOf(env)]?.tailnetOnly ?? isTailnetOnly(env)) {
      toast.info(`Not revealed in ${env.name}`, { description: TAILNET_ONLY_GUIDANCE });
      return;
    }
    try {
      const result = await disclosure.reveal(env.name, items);
      if (result.withheld.length > 0) {
        toast.error(`Not revealed: ${result.withheld.join(", ")}`, {
          description: "Your access does not include revealing these secrets.",
        });
      }
    } catch (err) {
      toast.error(`Could not reveal secrets in ${env.name}`, { description: errorMessage(err) });
    }
  };

  const refreshEnv = (env: string) => qc.invalidateQueries({ queryKey: keys.effectiveValues(org, slug, env) });

  const actionsFor = (row: Row, env: Environment, col: number): CellActions => {
    const p = { row: row.name, col };
    return {
      edit: () => {
        setActive(p);
        setEditing(p);
      },
      commit: (value, how) => commit(p, value, how),
      cancel: () => {
        setEditing(null);
        focusCell(p);
      },
      focus: () => setActive(p),
      reveal: () => void reveal(env, [row.name]),
      hide: () => disclosure.toggleLocal(env.name, row.name),
      revert: () => drafts.setDraft(env.name, row.name, null),
      remove: () => drafts.setDraft(env.name, row.name, { op: "delete" }),
      rotate: () => setRotating({ env, item: row.name }),
      finishRotation: () => {
        void api
          .completeRotation(org, slug, env.name, row.name)
          .then(() => {
            toast.success(`Finished rotating ${row.name}`, { description: `${env.name}: the previous value no longer works.` });
            return refreshEnv(env.name);
          })
          .catch((err) => toast.error(`Could not finish rotating ${row.name}`, { description: errorMessage(err) }));
      },
    };
  };

  const onGridKey = (e: React.KeyboardEvent) => {
    if (editing || !active) return;
    if (!(e.target as HTMLElement).hasAttribute("data-pos")) return;
    const map: Record<string, [number, number]> = {
      ArrowUp: [-1, 0],
      ArrowDown: [1, 0],
      ArrowLeft: [0, -1],
      ArrowRight: [0, 1],
    };
    const d = map[e.key];
    if (d) {
      e.preventDefault();
      move(active, d[0], d[1]);
      return;
    }
    if (e.key === "Enter" || e.key === "e" || e.key === "E") {
      e.preventDefault();
      const col = columns[active.col];
      if (col?.data) setEditing(active);
    } else if (e.key === "Home") {
      e.preventDefault();
      focusCell({ ...active, col: 0 });
    } else if (e.key === "End") {
      e.preventDefault();
      focusCell({ ...active, col: roots.length - 1 });
    }
  };

  const discard = () => {
    const saved = drafts.drafts;
    const n = drafts.count;
    drafts.setDrafts(new Map());
    setEditing(null);
    toast.undo(`Discarded ${plural(n, "change")}`, () => drafts.setDrafts(saved));
  };

  const existsIn = (env: string, name: string) =>
    Boolean(serverOf(env)?.get(name) || drafts.drafts.get(env)?.has(name));

  const handlePaste = (text: string, env: string) => {
    const parsed = parseDotenv(text);
    if (!parsed || parsed.length < 2) return false;
    setImportRows({ rows: parsed, env });
    return true;
  };

  const dirtyEnvs = roots.filter((e) => drafts.drafts.get(e.name)?.size).map((e) => e.name);
  const loadingAll = contract.isLoading || columns.some((c) => c.isLoading);

  if (roots.length === 0) {
    return (
      <>
        <EmptyState
          className="rounded-xl border border-dashed border-bd"
          icon={<Layers size={20} />}
          title="No environments yet"
          description={`Create development, staging and production for ${slug}: each holds its own values against the shared contract.`}
          actions={
            <Button variant="primary" icon={<Plus size={14} />} onClick={() => setNewEnvOpen(true)}>
              New environment
            </Button>
          }
        />
        <NewEnvironmentDialog
          org={org}
          project={slug}
          environments={environments}
          open={newEnvOpen}
          onClose={() => setNewEnvOpen(false)}
        />
      </>
    );
  }

  const revealable = roots.filter((_, i) => (stats[i]?.secrets.length ?? 0) > 0 && !stats[i]?.tailnetOnly);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2.5">
        <FilterInput
          className="w-full max-w-sm sm:w-72"
          value={filter}
          onChange={setFilter}
          placeholder={`Filter ${plural(rows.length, "item")}…`}
          data-testid="values-filter"
          aria-label="Filter items"
          {...(filter ? { shown: visible.length, total: rows.length } : {})}
          onKeyDown={(e) => {
            if ((e.key === "ArrowDown" || e.key === "Enter") && visible[0]) {
              e.preventDefault();
              focusCell({ row: visible[0].name, col: active?.col ?? 0 });
            }
          }}
        />
        <Segmented
          value={segment}
          onChange={setSegment}
          aria-label="Show"
          options={[
            { value: "all", label: "All", "data-testid": "segment-all" },
            { value: "missing", label: "Missing", count: missingRows.length, "data-testid": "segment-missing" },
            { value: "secrets", label: "Secrets", count: secretRows.length, "data-testid": "segment-secrets" },
          ]}
        />
        {revealable.length > 0 && (
          <Menu
            label="Reveal secrets"
            data-testid="reveal-menu"
            align="start"
            width="w-64"
            header={<p className="text-xs text-muted">Each reveal is recorded in the audit log.</p>}
            buttonClassName="h-8 gap-2 border border-bd bg-raised px-3 text-sm hover:border-bd-strong"
            items={revealable.map((env) => {
              const i = roots.indexOf(env);
              return {
                label: (
                  <span className="flex items-center gap-2">
                    <TierDot tier={env.tier as Tier} />
                    <span className="font-mono text-[13px]">{env.name}</span>
                  </span>
                ),
                hint: plural(stats[i]?.secrets.length ?? 0, "secret"),
                onSelect: () => void reveal(env, stats[i]?.secrets ?? []),
                "data-testid": `reveal-in-${env.name}`,
              };
            })}
          >
            <Eye size={14} />
            <span className="text-fg">Reveal secrets</span>
            <span className="text-xs">audited</span>
          </Menu>
        )}
        <div className="flex-1" />
        <Menu
          label="Export .env"
          data-testid="export-menu"
          width="w-60"
          header={<p className="text-xs text-muted">Non-secret values; secrets only if you choose.</p>}
          buttonClassName="h-8 gap-2 border border-bd bg-raised px-3 text-sm hover:border-bd-strong"
          items={environments.map((env) => ({
            label: (
              <span className={cn("flex items-center gap-2", env.parentEnvironmentId && "pl-4")}>
                <TierDot tier={env.tier as Tier} />
                <span className="truncate font-mono text-[13px]">{env.name}</span>
              </span>
            ),
            ...(isTailnetOnly(env) ? { hint: "tailnet only" } : {}),
            onSelect: () => setExportEnvId(env.id),
            "data-testid": `export-${env.name}`,
          }))}
        >
          <Download size={14} />
          <span className="text-fg">Export .env</span>
          <ChevronDown size={13} />
        </Menu>
      </div>

      <TailnetConnectPrompt envs={[...restricted]} />
      <DisclosureNotice envs={disclosure.revealedEnvs} onMaskAll={disclosure.maskAll} />
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

      <div className="overflow-x-auto rounded-xl border border-bd bg-raised">
        <table
          ref={tableRef}
          data-testid="matrix"
          role="grid"
          aria-label={`${slug} values`}
          className="w-full table-fixed border-collapse text-sm"
          style={{ minWidth: 240 + roots.length * 280 }}
          onKeyDown={onGridKey}
        >
          <colgroup>
            <col style={{ width: "max(22%, 240px)" }} />
            {roots.map((env) => (
              <col key={env.id} />
            ))}
          </colgroup>
          <thead>
            <tr>
              <th className="sticky left-0 z-10 h-12 border-b border-bd bg-raised px-4 text-left text-[13px] font-medium text-fg">
                Config item
              </th>
              {groups.map(({ root, derived }, i) => (
                <ColumnHeader
                  key={root.id}
                  org={org}
                  project={slug}
                  env={root}
                  derived={derived}
                  stat={stats[i]!}
                  tailnetBadge={
                    protectedEnvs.has(root.name) && (
                      <TailnetOnlyBadge org={org} project={project} env={root} environments={environments} compact />
                    )
                  }
                  revealed={stats[i]!.secrets.length > 0 && stats[i]!.secrets.every((s) => disclosure.isDisclosed(root.name, s))}
                  onReveal={() => void reveal(root, stats[i]!.secrets)}
                  onMask={() => disclosure.maskEnv(root.name)}
                  onOpenDerived={(e) => navigate(envPath(org, slug, e.name))}
                />
              ))}
            </tr>
          </thead>
          <tbody>
            {loadingAll && rows.length === 0 &&
              [0, 1, 2, 3].map((i) => (
                <tr key={i}>
                  <td className="h-[52px] border-b border-bd px-4">
                    <Skeleton className="h-4 w-36" />
                  </td>
                  {roots.map((env) => (
                    <td key={env.id} className="border-b border-l border-bd px-4">
                      <Skeleton className="h-4 w-24" />
                    </td>
                  ))}
                </tr>
              ))}
            {!loadingAll && rows.length === 0 && (
              <tr>
                <td colSpan={roots.length + 1} className="border-b border-bd">
                  <EmptyState
                    title="No configuration yet"
                    description="Add an item below, paste a .env file into it, or push a contract with varlatch contract push."
                  />
                </td>
              </tr>
            )}
            {rows.length > 0 && visible.length === 0 && (
              <tr>
                <td colSpan={roots.length + 1} className="border-b border-bd px-4 py-8 text-center text-[13px] text-muted">
                  {filter ? `No item matches “${filter}”.` : segment === "missing" ? "Nothing is missing." : "No secrets."}
                </td>
              </tr>
            )}
            {visible.map((row) => (
              <tr key={row.name} data-grid-row={row.name} className="hover:bg-hover/30">
                <th
                  scope="row"
                  className="sticky left-0 z-10 h-[52px] border-b border-bd bg-raised px-4 text-left font-normal"
                  title={row.contract?.description}
                >
                  <span className="flex min-w-0 items-center gap-2">
                    <span className="truncate font-mono text-[13px] font-semibold text-fg">
                      <Highlight text={row.name} needle={filter} />
                    </span>
                    <TypeBadge type={row.type} />
                    {row.sensitive && <Lock size={13} className="shrink-0 text-muted" aria-label="Secret" />}
                  </span>
                </th>
                {roots.map((env, col) => {
                  const column = columns[col];
                  const server = column?.data?.byName.get(row.name);
                  const isActive = active?.row === row.name && active.col === col;
                  return (
                    <ValuesGridCell
                      key={env.id}
                      name={row.name}
                      env={env}
                      pos={`${row.name}:${col}`}
                      server={server}
                      contract={row.contract}
                      sensitive={isSensitive(server, row.contract)}
                      state={cellStateOf(server, row.contract, env)}
                      draft={drafts.drafts.get(env.name)?.get(row.name)}
                      disclosed={disclosure.shown(env.name, row.name)}
                      withheld={column?.data?.withheld.has(row.name) ?? false}
                      tailnetOnly={stats[col]?.tailnetOnly ?? false}
                      loading={column?.isLoading ?? true}
                      unavailable={column?.isError ?? false}
                      conflict={review.conflicts.has(`${env.name}\u0000${row.name}`)}
                      active={isActive}
                      tabbable={isActive || (!active && col === 0 && row === visible[0])}
                      editing={editing?.row === row.name && editing.col === col}
                      historyHref={envPath(org, slug, env.name, row.name)}
                      actions={actionsFor(row, env, col)}
                    />
                  );
                })}
              </tr>
            ))}
          </tbody>
          <tfoot>
            <tr>
              <td colSpan={roots.length + 1} className="bg-inset/30 px-4 py-3">
                <AddItemForm
                  environments={roots}
                  initialEnv={roots[0]!.name}
                  exists={existsIn}
                  onAdd={(env, name, value) => drafts.setDraft(env, name, { op: "set", value })}
                  onPaste={handlePaste}
                />
              </td>
            </tr>
          </tfoot>
        </table>
      </div>

      <SaveBar count={drafts.count} envs={dirtyEnvs} onDiscard={discard} onReview={review.openReview} />

      <ReviewDialog
        open={review.reviewOpen}
        groups={review.groups}
        saving={review.saving}
        onClose={review.closeReview}
        onSave={() => void review.save()}
      />
      <ImportDialog
        rows={importRows?.rows ?? null}
        environments={roots}
        initialEnv={importRows?.env ?? roots[0]!.name}
        isSensitive={(env, name) => isSensitive(serverOf(env)?.get(name), contract.byName.get(name))}
        existing={existsIn}
        onClose={() => setImportRows(null)}
        onImport={(env) => {
          for (const { name, value } of importRows?.rows ?? []) drafts.setDraft(env, name, { op: "set", value });
          toast.success(`Imported ${plural(importRows?.rows.length ?? 0, "item")} as drafts`, {
            description: `Review and save them to write ${env}.`,
          });
          setImportRows(null);
        }}
      />
      <ExportDialog org={org} project={slug} env={exportEnv} onClose={() => setExportEnvId(null)} />
      {rotating && (
        <RotateDialog
          open
          item={rotating.item}
          project={slug}
          env={rotating.env.name}
          defaultGraceSeconds={contract.byName.get(rotating.item)?.rotationGraceSeconds}
          targets={(targetsByEnv.get(rotating.env.id) ?? [])
            .filter((t) => t.state === "active" && targetCoversItem(t, rotating.item))
            .map((t) => targetLabel(t, connections.data?.items))}
          onClose={() => setRotating(null)}
          onRotate={async (value, graceSeconds) => {
            await api.beginRotation(org, slug, rotating.env.name, rotating.item, { value, graceSeconds });
            toast.success(`Rotation of ${rotating.item} started`, {
              description: `${rotating.env.name}: finish it once consumers use the new value.`,
            });
            setRotating(null);
            await refreshEnv(rotating.env.name);
          }}
        />
      )}
    </div>
  );
}

function ColumnHeader({
  org,
  project,
  env,
  derived,
  stat,
  tailnetBadge,
  revealed,
  onReveal,
  onMask,
  onOpenDerived,
}: {
  org: string;
  project: string;
  env: Environment;
  derived: Environment[];
  stat: { missing: number; secrets: string[]; loading: boolean; error: boolean; tailnetOnly: boolean };
  tailnetBadge: React.ReactNode;
  revealed: boolean;
  onReveal: () => void;
  onMask: () => void;
  onOpenDerived: (env: Environment) => void;
}) {
  return (
    <th className="h-12 border-b border-l border-bd pl-4 pr-3 text-left font-normal" data-column={env.name}>
      <div className="flex min-w-0 items-center gap-1.5">
        <TierDot tier={env.tier as Tier} className="size-2.5 shrink-0" />
        <Link
          to={envPath(org, project, env.name)}
          className="min-w-0 truncate font-mono text-[13.5px] font-semibold text-fg hover:text-accent"
          data-testid={`column-${env.name}`}
        >
          {env.name}
        </Link>
        {!stat.loading &&
          (stat.error ? (
            <Badge tone="neutral">unavailable</Badge>
          ) : stat.missing > 0 ? (
            <Badge tone="danger" data-testid={`column-status-${env.name}`}>
              {stat.missing} missing
            </Badge>
          ) : (
            <Badge
              tone="accent"
              data-testid={`column-status-${env.name}`}
              title="Every required item has a value or a contract default"
            >
              valid
            </Badge>
          ))}
        {tailnetBadge}
        <span className="flex-1" />
        {derived.length > 0 && (
          <Menu
            label={`Environments derived from ${env.name}`}
            data-testid={`derived-${env.name}`}
            width="w-64"
            header={<p className="text-xs text-muted">Derived from {env.name}: inherit its values, override some.</p>}
            buttonClassName="h-6 shrink-0 gap-1 whitespace-nowrap rounded-md px-1.5 text-[11.5px] font-medium"
            items={derived.map((d) => ({
              label: <span className="font-mono text-[13px]">{d.name}</span>,
              hint: isTailnetOnly(d) ? `${d.kind} · tailnet only` : d.kind,
              onSelect: () => onOpenDerived(d),
            }))}
          >
            +{derived.length} derived
          </Menu>
        )}
        {stat.secrets.length > 0 && !stat.tailnetOnly && (
          <IconButton
            size="sm"
            label={revealed ? `Mask secrets in ${env.name}` : `Reveal ${plural(stat.secrets.length, "secret")} in ${env.name} (audited)`}
            data-testid={`reveal-column-${env.name}`}
            onClick={revealed ? onMask : onReveal}
            className="-mr-1.5"
          >
            {revealed ? <EyeOff size={14} /> : <Eye size={14} />}
          </IconButton>
        )}
      </div>
    </th>
  );
}
