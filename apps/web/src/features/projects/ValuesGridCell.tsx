// SPDX-License-Identifier: AGPL-3.0-or-later
import type React from "react";
import { Link } from "react-router-dom";
import { Ellipsis, Eye, History, Plus, RefreshCw, RotateCcw, Trash2, Undo2 } from "lucide-react";
import type { Environment } from "@varlatch/protocol";
import { CopyButton } from "../../components/CodeBlock";
import { Menu, type MenuItem } from "../../components/Select";
import { Skeleton, cn } from "../../components/ui";
import { DraftMarker, RefHint, RotatingMarker, SecretMask } from "../values/bits";
import { ValueEditor, type CommitHow } from "../values/ValueEditor";
import {
  draftKind,
  editorKind,
  storedText,
  type CellState,
  type ContractItemMeta,
  type Draft,
  type ServerItem,
} from "../values/model";
import type { Disclosed } from "../values/useDisclosure";
import { TAILNET_ONLY_GUIDANCE } from "../../lib/tailnet";

export type CellActions = {
  edit: () => void;
  commit: (value: string, how: CommitHow) => void;
  cancel: () => void;
  focus: () => void;
  reveal: () => void;
  hide: () => void;
  revert: () => void;
  remove: () => void;
  rotate: () => void;
  finishRotation: () => void;
};

/**
 * One grid cell: state, value or mask, draft marker, and on hover the small
 * copy / history / more buttons. Editing happens in place.
 */
export function ValuesGridCell({
  name,
  env,
  pos,
  server,
  contract,
  sensitive,
  state,
  draft,
  disclosed: revealed,
  withheld,
  tailnetOnly,
  loading,
  unavailable,
  conflict,
  active,
  tabbable,
  editing,
  historyHref,
  actions,
}: {
  name: string;
  env: Environment;
  pos: string;
  server: ServerItem | undefined;
  contract: ContractItemMeta | undefined;
  sensitive: boolean;
  state: CellState;
  draft: Draft | undefined;
  disclosed: Disclosed | undefined;
  withheld: boolean;
  /** A Tailnet Requirement covers the environment: values cannot be read here. */
  tailnetOnly: boolean;
  loading: boolean;
  unavailable: boolean;
  conflict: boolean;
  active: boolean;
  /** Reachable with Tab (the active cell, or the first one before any is active). */
  tabbable: boolean;
  editing: boolean;
  historyHref: string;
  actions: CellActions;
}) {
  const kind = draftKind(draft, server);
  // Plaintext disclosed before a Tailnet Requirement appeared is never shown or copied.
  const disclosed = tailnetOnly ? undefined : revealed;
  const editable = !loading && !unavailable;
  // Copy offers the saved value only; with a draft pending it would mislead.
  const copyValue = draft ? undefined : sensitive ? disclosed?.value : !withheld ? (server?.value ?? undefined) : undefined;

  let content: React.ReactNode;
  if (editing) {
    const flavour = editorKind(sensitive, contract);
    content = (
      <div className="flex items-center gap-2">
        <ValueEditor
          kind={flavour.kind}
          options={flavour.kind === "options" ? flavour.options : undefined}
          initial={draft?.op === "set" ? draft.value : (storedText(server) ?? "")}
          placeholder={
            sensitive
              ? server
                ? "New value (overwrites)"
                : "Secret value"
              : state === "covered_by_default"
                ? `default ${contract?.defaultValue ?? ""}`
                : undefined
          }
          aria-label={`${name} in ${env.name}`}
          onCommit={actions.commit}
          onCancel={actions.cancel}
          className="min-w-0 flex-1"
        />
        <DraftMarker kind={kind} />
      </div>
    );
  } else if (loading) {
    content = <Skeleton className="h-4 w-24" />;
  } else if (draft) {
    content = (
      <span className="flex min-w-0 items-center gap-2">
        {draft.op === "delete" ? (
          <span className="min-w-0 truncate font-mono text-[13px] text-muted line-through decoration-deny/70">
            {sensitive ? "••••••••••" : (storedText(server) ?? "")}
          </span>
        ) : sensitive ? (
          <SecretMask className="text-fg/80" />
        ) : (
          <span className="min-w-0 truncate font-mono text-[13px] text-fg" title={draft.value}>
            {draft.value === "" ? <span className="italic text-muted">(empty)</span> : draft.value}
          </span>
        )}
        <DraftMarker kind={kind} />
      </span>
    );
  } else if (unavailable) {
    content = <span className="text-[12.5px] text-subtle">unavailable</span>;
  } else if (state === "set" && server) {
    content = (
      <span className="flex min-w-0 items-center gap-2">
        {sensitive ? (
          disclosed ? (
            <span className="min-w-0 truncate font-mono text-[13px] text-fg">{disclosed.value}</span>
          ) : (
            <SecretMask />
          )
        ) : withheld && tailnetOnly ? (
          <span className="text-[12.5px] text-muted" title={TAILNET_ONLY_GUIDANCE}>
            set · tailnet only
          </span>
        ) : withheld ? (
          <span className="text-[12.5px] text-muted" title="Set; your access shows that it exists, not its value">
            set · value hidden
          </span>
        ) : server.rawValue !== undefined ? (
          <>
            <span className="min-w-0 truncate font-mono text-[13px] text-fg" title={`Expands to ${server.value ?? ""}`}>
              {server.rawValue}
            </span>
            <RefHint item={name} expanded={server.value} testId={`ref-${env.name}-${name}`} />
          </>
        ) : (
          <span className="min-w-0 truncate font-mono text-[13px] text-fg" title={server.value ?? ""}>
            {server.value === "" ? <span className="italic text-muted">(empty)</span> : server.value}
          </span>
        )}
        {server.rotating && <RotatingMarker item={name} testId={`rotating-${env.name}-${name}`} />}
      </span>
    );
  } else if (state === "covered_by_default") {
    content = (
      <span className="truncate font-mono text-[13px] italic text-muted" title="Not set here; the contract default applies">
        default {contract?.defaultValue}
      </span>
    );
  } else if (state === "missing_required") {
    content = (
      <span className="-mx-1.5 flex items-center justify-between gap-2 rounded-md border border-dashed border-deny/60 bg-deny/[0.05] py-1 pl-2.5 pr-1">
        <span className="truncate text-[12.5px] font-medium text-deny">missing · required</span>
        <button
          type="button"
          data-testid={`set-${env.name}-${name}`}
          onClick={(e) => {
            e.stopPropagation();
            actions.edit();
          }}
          className="inline-flex h-6 shrink-0 cursor-pointer items-center gap-1 rounded-md border border-bd bg-raised px-2 text-xs font-medium text-fg hover:border-bd-strong hover:bg-hover"
        >
          <Plus size={12} /> Set
        </button>
      </span>
    );
  } else {
    content = <span className="text-muted">—</span>;
  }

  const menu: MenuItem[] = [];
  if (editable) menu.push({ label: sensitive && server ? "Overwrite…" : "Edit", onSelect: actions.edit, hint: "E" });
  if (sensitive && server && !disclosed && !draft && !tailnetOnly) {
    menu.push({ label: "Reveal", icon: <Eye size={14} />, hint: "audited", onSelect: actions.reveal });
  }
  if (sensitive && disclosed) menu.push({ label: "Hide again", icon: <Eye size={14} />, onSelect: actions.hide });
  if (server?.source === "self" && !draft && !server.rotating) {
    menu.push({ label: "Rotate…", icon: <RefreshCw size={14} />, onSelect: actions.rotate });
  }
  if (server?.rotating) menu.push({ label: "Finish rotation", icon: <RefreshCw size={14} />, onSelect: actions.finishRotation });
  if (draft) menu.push({ label: "Revert change", icon: <Undo2 size={14} />, onSelect: actions.revert, separatorBefore: true });
  if (server?.source === "self" && draft?.op !== "delete") {
    menu.push({
      label: "Delete value",
      icon: <Trash2 size={14} />,
      danger: true,
      onSelect: actions.remove,
      separatorBefore: !draft,
    });
  }

  return (
    <td
      data-cell={`${name}:${env.name}:${state}`}
      data-pos={pos}
      tabIndex={tabbable ? 0 : -1}
      aria-selected={active}
      onFocus={(e) => {
        if (e.target === e.currentTarget) actions.focus();
      }}
      onClick={(e) => {
        // Portaled menus and popovers bubble through React; only direct clicks edit.
        if (!e.currentTarget.contains(e.target as Node)) return;
        if ((e.target as HTMLElement).closest("button, a, input, textarea")) return;
        actions.focus();
        if (editable && !editing) actions.edit();
      }}
      className={cn(
        "group relative h-[52px] border-b border-l border-bd px-4 align-middle outline-none transition-colors",
        editable && !editing && "cursor-text",
        active && !editing && "bg-hover/70 shadow-[inset_0_0_0_1.5px_var(--accent)]",
        conflict && "shadow-[inset_0_0_0_1.5px_var(--deny)]",
        kind === "edited" && "bg-warn/[0.05]",
        kind === "new" && "bg-accent/[0.05]",
        kind === "deleted" && "bg-deny/[0.04]",
      )}
    >
      {content}
      {!editing && !loading && !(state === "missing_required" && !draft) && (
        <span
          className={cn(
            "absolute right-1.5 top-1/2 hidden -translate-y-1/2 items-center gap-0.5 rounded-md border border-bd bg-raised p-0.5 shadow-sm",
            "group-hover:flex group-focus-within:flex",
          )}
        >
          {copyValue !== undefined && copyValue !== null && <CopyButton value={copyValue} label={`Copy ${name}`} />}
          {draft && (
            <button
              type="button"
              aria-label="Revert change"
              title="Revert change"
              onClick={actions.revert}
              className="flex size-7 cursor-pointer items-center justify-center rounded-md text-muted hover:bg-hover hover:text-fg"
            >
              <RotateCcw size={14} />
            </button>
          )}
          <Link
            to={historyHref}
            aria-label={`Open ${name} in ${env.name}`}
            title="History and details"
            className="flex size-7 items-center justify-center rounded-md text-muted hover:bg-hover hover:text-fg"
          >
            <History size={14} />
          </Link>
          {menu.length > 0 && (
            <Menu label={`More for ${name} in ${env.name}`} items={menu} buttonClassName="size-7 justify-center">
              <Ellipsis size={15} />
            </Menu>
          )}
        </span>
      )}
    </td>
  );
}
