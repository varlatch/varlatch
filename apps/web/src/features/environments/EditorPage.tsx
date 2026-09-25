// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useBlocker, useParams, useSearchParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Eye, EyeOff, Plug, Plus, RotateCcw, Trash2 } from "lucide-react";
import type { Tier } from "@varlatch/protocol";
import { VarlatchApiError } from "@varlatch/sdk";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { Button, Card, Input, Mono, TierChip, cn } from "../../components/ui";
import { RotationSyncStatus } from "../sync/IntegrationsPage";

/**
 * The values editor (design R1 §Q2/Q3, R2): local drafts -> Review & Save as
 * one atomic change set; non-sensitive values display normally; Secrets are
 * masked and revealed only through the explicit audited disclosure operation.
 * Server-disclosed plaintext auto-remasks (a display/privacy feature) and
 * never survives the auth boundary; user-typed drafts live in memory only.
 */

const REMASK_MS = 5 * 60 * 1000;

type Draft = { op: "set"; value: string } | { op: "delete" };

interface ServerItem {
  name: string;
  sensitive: boolean;
  source: "self" | "parent";
  versionId: string;
  value: string | null; // non-sensitive plaintext (references expanded) or null
  /** Literal stored text, present only when ${NAME} expansion changed value; edits write this. */
  rawValue?: string;
  /** True while a dual-phase rotation (ADR-0027) is active for this item. */
  rotating?: boolean;
}

export function EditorPage() {
  const { org, project, env } = useParams() as { org: string; project: string; env: string };
  const envName = decodeURIComponent(env);
  useOrgRealtime(
    org,
    ["value", "environment", "contract"],
    [
      ["environment", org, project],
      ["effective-values", org, project],
      ["effective-meta", org, project],
    ],
  );
  const { api, authEpoch } = useSession();
  const qc = useQueryClient();

  const envQuery = useQuery({
    queryKey: ["environment", org, project],
    queryFn: () => api.listEnvironments(org, project),
    select: (page) => page.items.find((e) => e.name === envName),
  });
  const itemsQuery = useQuery({
    queryKey: ["effective-values", org, project, envName],
    queryFn: async () => {
      const result = await api.effectiveConfiguration(org, project, envName, { includeValues: true });
      return (result.items ?? []) as ServerItem[];
    },
  });

  const [drafts, setDrafts] = useState<Map<string, Draft>>(new Map());
  const [disclosed, setDisclosed] = useState<Map<string, string>>(new Map());
  const [visible, setVisible] = useState<Set<string>>(new Set());
  // ?item= deep-links (e.g. from the command palette's item search) land
  // with the filter prefilled on the named Config Item.
  const [searchParams] = useSearchParams();
  const [filter, setFilter] = useState(searchParams.get("item") ?? "");
  const [reviewOpen, setReviewOpen] = useState(false);
  const [importPreview, setImportPreview] = useState<{ name: string; value: string }[] | null>(null);
  const [rotateItem, setRotateItem] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [conflicts, setConflicts] = useState<string[]>([]);
  const remaskTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const addNameRef = useRef<HTMLInputElement>(null);

  const maskAll = useCallback(() => {
    setDisclosed(new Map());
    setVisible(new Set());
  }, []);

  // Disclosed plaintext never survives re-auth or leaving this environment.
  useEffect(() => maskAll(), [authEpoch, envName, maskAll]);
  useEffect(() => () => maskAll(), [maskAll]);

  const armRemask = useCallback(() => {
    if (remaskTimer.current) clearTimeout(remaskTimer.current);
    remaskTimer.current = setTimeout(maskAll, REMASK_MS);
  }, [maskAll]);

  const reveal = useCallback(
    async (names: string[] | "all") => {
      try {
        setError("");
        const result = await api.discloseSecrets(
          org,
          project,
          envName,
          names === "all" ? { scope: "all-authorized-secrets" } : { items: names },
        );
        setDisclosed((prev) => {
          const next = new Map(prev);
          for (const item of result.items) next.set(item.name, item.value);
          return next;
        });
        setVisible((prev) => {
          const next = new Set(prev);
          for (const item of result.items) next.add(item.name);
          return next;
        });
        armRemask();
        if (result.withheld.length > 0) {
          setError(`Withheld by policy: ${result.withheld.join(", ")}`);
        }
      } catch (err) {
        setError(err instanceof VarlatchApiError ? `${err.code}: ${err.message}` : String(err));
      }
    },
    [api, org, project, envName, armRemask],
  );

  const setDraft = (name: string, draft: Draft | null) => {
    setDrafts((prev) => {
      const next = new Map(prev);
      if (draft === null) next.delete(name);
      else next.set(name, draft);
      return next;
    });
  };

  const serverItems = itemsQuery.data ?? [];
  const serverByName = useMemo(() => new Map(serverItems.map((i) => [i.name, i])), [serverItems]);
  const addedNames = [...drafts.keys()].filter((n) => !serverByName.has(n));
  const dirty = drafts.size > 0;

  // Unsaved-changes protection (drafts may hold sensitive user-typed plaintext).
  useEffect(() => {
    if (!dirty) return;
    const handler = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [dirty]);
  const blocker = useBlocker(dirty);
  useEffect(() => {
    if (blocker.state === "blocked") {
      if (confirm("Discard unsaved configuration changes?")) blocker.proceed();
      else blocker.reset();
    }
  }, [blocker]);

  // Cmd/Ctrl+S opens Review.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "s") {
        e.preventDefault();
        if (dirty) setReviewOpen(true);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [dirty]);

  const handlePaste = (text: string): boolean => {
    const lines = text.split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith("#"));
    const parsed: { name: string; value: string }[] = [];
    for (const line of lines) {
      const match = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line.trim());
      if (!match) return false; // ambiguous input: no silent partial import
      let value = match[2] as string;
      if (
        (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
        (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
      ) {
        value = value.slice(1, -1);
      }
      parsed.push({ name: match[1] as string, value });
    }
    if (parsed.length < 2) return false; // single line: treat as ordinary typing
    setImportPreview(parsed);
    return true;
  };

  const applyImport = () => {
    for (const { name, value } of importPreview ?? []) setDraft(name, { op: "set", value });
    setImportPreview(null);
  };

  const commit = async () => {
    const changes = [...drafts.entries()].map(([item, draft]) => {
      const server = serverByName.get(item);
      if (draft.op === "delete") {
        return {
          op: "delete" as const,
          item,
          ...(server ? { expectedVersionId: server.versionId } : {}),
        };
      }
      return {
        op: "set" as const,
        item,
        value: draft.value,
        ...(server ? { expectedVersionId: server.versionId } : {}),
      };
    });
    try {
      setError("");
      setConflicts([]);
      await api.applyChangeSet(org, project, envName, changes, {
        idempotencyKey: crypto.randomUUID(),
      });
      setDrafts(new Map());
      setReviewOpen(false);
      maskAll();
      await qc.invalidateQueries({ queryKey: ["effective-values", org, project, envName] });
      await qc.invalidateQueries({ queryKey: ["effective-meta", org, project] });
    } catch (err) {
      if (err instanceof VarlatchApiError && err.code === "VERSION_CONFLICT") {
        const items = ((err.details?.conflicts as { item: string }[]) ?? []).map((c) => c.item);
        setConflicts(items);
        setError(
          `Changed since review: ${items.join(", ")}. Nothing was written — refresh shows the current values; your draft is preserved.`,
        );
        await qc.invalidateQueries({ queryKey: ["effective-values", org, project, envName] });
      } else {
        setError(err instanceof VarlatchApiError ? `${err.code}: ${err.message}` : String(err));
      }
      setReviewOpen(false);
    }
  };

  const refreshValues = async () => {
    await qc.invalidateQueries({ queryKey: ["effective-values", org, project, envName] });
    await qc.invalidateQueries({ queryKey: ["effective-meta", org, project] });
  };
  const beginRotation = async (item: string, value: string, graceSeconds?: number) => {
    try {
      setError("");
      await api.beginRotation(org, project, envName, item, {
        value,
        ...(graceSeconds ? { graceSeconds } : {}),
      });
      setRotateItem(null);
      await refreshValues();
    } catch (err) {
      setError(err instanceof VarlatchApiError ? `${err.code}: ${err.message}` : String(err));
    }
  };
  const completeRotation = async (item: string) => {
    try {
      setError("");
      await api.completeRotation(org, project, envName, item);
      await refreshValues();
    } catch (err) {
      setError(err instanceof VarlatchApiError ? `${err.code}: ${err.message}` : String(err));
    }
  };

  const environment = envQuery.data;
  const tier = (environment?.tier ?? "development") as Tier;
  const rows = [
    ...serverItems.map((item) => ({ item, draft: drafts.get(item.name) })),
    ...addedNames.map((name) => ({
      item: null as ServerItem | null,
      name,
      draft: drafts.get(name) as Draft,
    })),
  ].filter((row) => {
    const name = row.item?.name ?? (row as { name: string }).name;
    return name.toLowerCase().includes(filter.toLowerCase());
  });

  const secretCount = serverItems.filter((i) => i.sensitive).length;

  return (
    <div className="space-y-4 pb-20">
      <div className="flex items-center gap-3 flex-wrap">
        <h1 className="text-lg font-semibold"><Mono>{envName}</Mono></h1>
        {environment && <TierChip tier={tier} />}
        {environment?.kind !== "shared" && (
          <span className="text-xs text-muted">{environment?.kind}</span>
        )}
        <Link
          to={`/o/${org}/p/${project}/e/${env}/integrations`}
          className="inline-flex items-center gap-1 text-sm text-muted hover:text-fg"
          data-testid="integrations-link"
        >
          <Plug size={14} /> Integrations
        </Link>
        <div className="flex-1" />
        <Input placeholder="Filter items…" value={filter} onChange={(e) => setFilter(e.target.value)} />
        {secretCount > 0 && (
          <Button variant="ghost" data-testid="reveal-all" onClick={() => void reveal("all")}>
            <Eye size={14} className="inline mr-1" />
            Reveal all Secrets
          </Button>
        )}
        {disclosed.size > 0 && (
          <Button variant="ghost" onClick={maskAll}>
            <EyeOff size={14} className="inline mr-1" />
            Mask all
          </Button>
        )}
      </div>

      {disclosed.size > 0 && (
        <p className="text-xs text-muted" data-testid="disclosure-notice">
          Secrets revealed — this disclosure was recorded in the audit log. Re-masking hides them
          from the screen; it is not revocation.
        </p>
      )}

      <Card className="p-0 overflow-hidden">
        <table className="w-full text-sm" data-testid="values-table">
          <thead>
            <tr className="text-left text-muted border-b border-bd">
              <th className="px-3 py-2 font-medium w-64">Config Item</th>
              <th className="px-3 py-2 font-medium">Value</th>
              <th className="px-3 py-2 font-medium w-28"></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const name = row.item?.name ?? (row as { name: string }).name;
              return (
                <ValueRow
                  key={name}
                  name={name}
                  item={row.item ?? null}
                  draft={row.draft}
                  disclosedValue={disclosed.get(name)}
                  visible={visible.has(name)}
                  conflicted={conflicts.includes(name)}
                  onToggleVisible={() => {
                    if (disclosed.has(name)) {
                      setVisible((prev) => {
                        const next = new Set(prev);
                        if (next.has(name)) next.delete(name);
                        else next.add(name);
                        return next;
                      });
                    } else {
                      void reveal([name]);
                    }
                  }}
                  onDraft={(draft) => setDraft(name, draft)}
                  onRotate={() => setRotateItem(name)}
                  onCompleteRotation={() => void completeRotation(name)}
                />
              );
            })}
            <AddRow
              inputRef={addNameRef}
              existing={new Set([...serverByName.keys(), ...drafts.keys()])}
              onAdd={(name, value) => setDraft(name, { op: "set", value })}
              onPaste={handlePaste}
            />
          </tbody>
        </table>
      </Card>
      {error && <p className="text-deny text-sm" data-testid="editor-error">{error}</p>}

      {dirty && (
        <div className="fixed bottom-0 left-60 right-0 border-t border-bd bg-raised px-6 py-3 flex items-center gap-3">
          <span className="text-sm" data-testid="dirty-count">
            {drafts.size} unsaved change{drafts.size === 1 ? "" : "s"}
          </span>
          <div className="flex-1" />
          <Button variant="ghost" onClick={() => setDrafts(new Map())}>Discard</Button>
          <Button data-testid="review-save" onClick={() => setReviewOpen(true)}>Review &amp; Save</Button>
        </div>
      )}

      {reviewOpen && (
        <ReviewDialog
          envName={envName}
          tier={tier}
          drafts={drafts}
          serverByName={serverByName}
          disclosed={disclosed}
          onCancel={() => setReviewOpen(false)}
          onCommit={() => void commit()}
        />
      )}

      {importPreview && (
        <Modal title={`Import ${importPreview.length} configuration items as draft changes?`}>
          <table className="w-full text-sm mb-4">
            <tbody>
              {importPreview.map((row) => (
                <tr key={row.name} className="border-b border-bd/40">
                  <td className="py-1 pr-4"><Mono>{row.name}</Mono></td>
                  <td className="py-1"><Mono className="text-muted">{row.value.slice(0, 60)}</Mono></td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setImportPreview(null)}>Cancel</Button>
            <Button data-testid="confirm-import" onClick={applyImport}>Import as drafts</Button>
          </div>
        </Modal>
      )}

      {rotateItem && (
        <RotateDialog
          item={rotateItem}
          onCancel={() => setRotateItem(null)}
          onConfirm={(value, grace) => void beginRotation(rotateItem, value, grace)}
        />
      )}
    </div>
  );
}

function ValueRow({
  name,
  item,
  draft,
  disclosedValue,
  visible,
  conflicted,
  onToggleVisible,
  onDraft,
  onRotate,
  onCompleteRotation,
}: {
  name: string;
  item: ServerItem | null;
  draft: Draft | undefined;
  disclosedValue: string | undefined;
  visible: boolean;
  conflicted: boolean;
  onToggleVisible: () => void;
  onDraft: (draft: Draft | null) => void;
  onRotate: () => void;
  onCompleteRotation: () => void;
}) {
  const isAdded = item === null;
  const isDeleted = draft?.op === "delete";
  const isChanged = draft?.op === "set" && !isAdded;
  const editing = draft?.op === "set";

  const displayValue = (() => {
    if (editing) return draft.value;
    if (!item) return "";
    if (!item.sensitive) return item.value ?? "";
    if (visible && disclosedValue !== undefined) return disclosedValue;
    return null; // masked
  })();

  return (
    <tr
      className={cn(
        "border-b border-bd/40 align-top",
        isAdded && "bg-allow/5",
        isChanged && "bg-tier-staging/5",
        isDeleted && "bg-deny/5 opacity-60",
        conflicted && "outline outline-1 outline-deny",
      )}
      data-row={name}
    >
      <td className="px-3 py-2">
        <Mono>{name}</Mono>
        <span className="ml-2 space-x-1">
          {item?.sensitive && (
            <span className="text-[10px] uppercase tracking-wide text-muted">secret</span>
          )}
          {item?.rotating && (
            <>
              <span
                className="text-[10px] uppercase tracking-wide text-tier-staging"
                title="Rotating: the previous value is still valid until the grace window closes (ADR-0027)"
                data-testid={`rotating-${name}`}
              >
                rotating
              </span>
              {/* Per-target sync evidence (ADR-0031 §5): complete rotation on
                  evidence, not hope. */}
              <RotationSyncStatus item={name} />
            </>
          )}
          {item?.rawValue !== undefined && (
            <span
              className="text-[10px] uppercase tracking-wide text-accent cursor-help"
              title={`Stored as: ${item.rawValue} — editing shows this literal text; \${NAME} expands server-side`}
              data-testid={`ref-${name}`}
            >
              ref
            </span>
          )}
          {item?.source === "parent" && (
            <span className="text-[10px] uppercase tracking-wide text-muted">inherited</span>
          )}
          {isAdded && <span className="text-[10px] uppercase text-allow">new</span>}
          {isChanged && <span className="text-[10px] uppercase text-tier-staging">edited</span>}
          {isDeleted && <span className="text-[10px] uppercase text-deny">deleted</span>}
        </span>
      </td>
      <td className="px-3 py-1.5">
        {editing ? (
          <textarea
            className="w-full rounded-md border border-bd bg-inset px-2 py-1 font-mono text-[13px] resize-y min-h-8 max-h-48 focus:outline-none focus:border-accent"
            rows={Math.min(6, (draft.value.match(/\n/g)?.length ?? 0) + 1)}
            value={draft.value}
            autoFocus={!isAdded}
            onChange={(e) => onDraft({ op: "set", value: e.target.value })}
            onKeyDown={(e) => {
              if (e.key === "Escape") onDraft(null);
            }}
          />
        ) : displayValue === null ? (
          <Mono className="text-muted select-none">••••••••</Mono>
        ) : (
          <Mono className="whitespace-pre-wrap break-all">{displayValue || <span className="text-muted">(empty)</span>}</Mono>
        )}
      </td>
      <td className="px-3 py-1.5 whitespace-nowrap text-right">
        {item?.sensitive && !editing && (
          <button
            className="text-muted hover:text-fg cursor-pointer mr-2"
            title={visible ? "Mask" : "Reveal (audited)"}
            data-testid={`eye-${name}`}
            onClick={onToggleVisible}
          >
            {visible ? <EyeOff size={14} /> : <Eye size={14} />}
          </button>
        )}
        {!editing && !isDeleted && (
          <button
            className="text-muted hover:text-fg cursor-pointer mr-2"
            title={item?.sensitive ? "Overwrite (no reveal needed)" : "Edit"}
            data-testid={`edit-${name}`}
            onClick={() =>
              // Reference-bearing values are edited as stored (${NAME} intact):
              // drafting the expanded text would silently destroy the reference.
              onDraft({ op: "set", value: item?.sensitive ? "" : (item?.rawValue ?? item?.value ?? "") })
            }
          >
            edit
          </button>
        )}
        {draft && (
          <button
            className="text-muted hover:text-fg cursor-pointer mr-2"
            title="Revert draft"
            onClick={() => onDraft(null)}
          >
            <RotateCcw size={13} />
          </button>
        )}
        {item && item.source === "self" && !isDeleted && !editing && !item.rotating && (
          <button
            className="text-muted hover:text-fg cursor-pointer mr-2"
            title="Rotate: overlap a new value with the current one for a grace window (ADR-0027)"
            data-testid={`rotate-${name}`}
            onClick={onRotate}
          >
            rotate
          </button>
        )}
        {item?.rotating && !editing && (
          <button
            className="text-tier-staging hover:brightness-125 cursor-pointer mr-2"
            title="Complete rotation: drop the previous value now"
            data-testid={`complete-rotation-${name}`}
            onClick={onCompleteRotation}
          >
            finish rotation
          </button>
        )}
        {item && item.source === "self" && !isDeleted && !editing && (
          <button
            className="text-muted hover:text-deny cursor-pointer"
            title="Delete (drafted)"
            data-testid={`delete-${name}`}
            onClick={() => onDraft({ op: "delete" })}
          >
            <Trash2 size={13} />
          </button>
        )}
      </td>
    </tr>
  );
}

/** Collects the new value (and optional grace) to begin a rotation. */
function RotateDialog({
  item,
  onCancel,
  onConfirm,
}: {
  item: string;
  onCancel: () => void;
  onConfirm: (value: string, graceSeconds?: number) => void;
}) {
  const [value, setValue] = useState("");
  const [graceHours, setGraceHours] = useState("");
  return (
    <Modal title={`Rotate ${item}`}>
      <p className="text-sm text-muted mb-3">
        The new value becomes the primary immediately; the current value stays valid until the
        grace window closes, so running consumers migrate without an outage. Finish the rotation
        once they have — then revoke the old credential upstream.
      </p>
      <label className="block text-xs text-muted mb-1">New value</label>
      <textarea
        data-testid="rotate-value"
        className="w-full rounded-md border border-bd bg-inset px-2 py-1 font-mono text-[13px] resize-y min-h-16 mb-3 focus:outline-none focus:border-accent"
        value={value}
        autoFocus
        onChange={(e) => setValue(e.target.value)}
      />
      <label className="block text-xs text-muted mb-1">Grace window (hours, optional)</label>
      <Input
        data-testid="rotate-grace"
        className="w-32 mb-4"
        placeholder="24"
        value={graceHours}
        onChange={(e) => setGraceHours(e.target.value.replace(/[^0-9]/g, ""))}
      />
      <div className="flex justify-end gap-2">
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button
          data-testid="confirm-rotate"
          disabled={!value}
          onClick={() => onConfirm(value, graceHours ? Number(graceHours) * 3600 : undefined)}
        >
          Begin rotation
        </Button>
      </div>
    </Modal>
  );
}

function AddRow({
  inputRef,
  existing,
  onAdd,
  onPaste,
}: {
  inputRef: React.RefObject<HTMLInputElement | null>;
  existing: Set<string>;
  onAdd: (name: string, value: string) => void;
  onPaste: (text: string) => boolean;
}) {
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const valid = /^[A-Z][A-Z0-9_]*$/.test(name) && !existing.has(name);
  const submit = () => {
    if (!valid) return;
    onAdd(name, value);
    setName("");
    setValue("");
    inputRef.current?.focus();
  };
  return (
    <tr>
      <td className="px-3 py-2">
        <Input
          ref={inputRef as React.Ref<HTMLInputElement>}
          data-testid="add-name"
          placeholder="NEW_ITEM"
          value={name}
          onChange={(e) => setName(e.target.value.toUpperCase())}
          onPaste={(e) => {
            const text = e.clipboardData.getData("text");
            if (text.includes("\n") && onPaste(text)) e.preventDefault();
          }}
        />
      </td>
      <td className="px-3 py-2">
        <Input
          data-testid="add-value"
          placeholder="value"
          className="w-full"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submit()}
        />
      </td>
      <td className="px-3 py-2 text-right">
        <Button variant="ghost" data-testid="add-item" disabled={!valid} onClick={submit}>
          <Plus size={14} className="inline" /> add
        </Button>
      </td>
    </tr>
  );
}

function Modal({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="fixed inset-0 bg-black/60 grid place-items-center z-50">
      <Card className="w-[34rem] max-h-[80vh] overflow-y-auto">
        <h2 className="font-semibold mb-3">{title}</h2>
        {children}
      </Card>
    </div>
  );
}

function ReviewDialog({
  envName,
  tier,
  drafts,
  serverByName,
  disclosed,
  onCancel,
  onCommit,
}: {
  envName: string;
  tier: Tier;
  drafts: Map<string, Draft>;
  serverByName: Map<string, ServerItem>;
  disclosed: Map<string, string>;
  onCancel: () => void;
  onCommit: () => void;
}) {
  const [confirmed, setConfirmed] = useState(tier !== "production");
  return (
    <Modal title={`Review changes to ${envName}`}>
      <p className="text-sm text-muted mb-3 flex items-center gap-2">
        <TierChip tier={tier} />
        {drafts.size} change{drafts.size === 1 ? "" : "s"} — applied as one atomic change set.
      </p>
      <table className="w-full text-sm mb-4">
        <tbody>
          {[...drafts.entries()].map(([name, draft]) => {
            const server = serverByName.get(name);
            const op = draft.op === "delete" ? "delete" : server ? "change" : "add";
            return (
              <tr key={name} className="border-b border-bd/40 align-top">
                <td className="py-1.5 pr-3 whitespace-nowrap">
                  <span
                    className={cn(
                      "text-[10px] uppercase tracking-wide mr-2",
                      op === "add" && "text-allow",
                      op === "change" && "text-tier-staging",
                      op === "delete" && "text-deny",
                    )}
                  >
                    {op}
                  </span>
                  <Mono>{name}</Mono>
                </td>
                <td className="py-1.5 text-muted">
                  {draft.op === "delete" ? (
                    server?.sensitive ? "Secret deleted" : `was: ${server?.value ?? "…"}`
                  ) : server ? (
                    server.sensitive && !disclosed.has(name) ? (
                      // Review never triggers disclosure (design R1 §Q2).
                      "Secret changed"
                    ) : (
                      <Mono className="break-all">
                        {(disclosed.get(name) ?? server.value ?? "…") + " → " + draft.value}
                      </Mono>
                    )
                  ) : (
                    <Mono className="break-all">{draft.value}</Mono>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {tier === "production" && (
        <label className="flex items-start gap-2 text-sm mb-4 cursor-pointer">
          <input
            type="checkbox"
            data-testid="production-confirm"
            checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)}
            className="mt-0.5"
          />
          <span>
            These changes affect <strong className="text-tier-production">production</strong>-tier
            configuration. I understand.
          </span>
        </label>
      )}
      <div className="flex justify-end gap-2">
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button data-testid="commit-changes" disabled={!confirmed} onClick={onCommit}>
          Save changes
        </Button>
      </div>
    </Modal>
  );
}
