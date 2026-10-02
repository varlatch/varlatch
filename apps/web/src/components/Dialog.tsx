// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { createContext, useCallback, useContext, useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Check, TriangleAlert, X } from "lucide-react";
import { Button, IconButton, Input, cn } from "./ui";

/**
 * Modal dialogs. `Dialog` is the building block; `useConfirm` and `usePrompt`
 * replace window.confirm/window.prompt with in-app dialogs that can list
 * consequences and require typing a name for rare destructive operations.
 */

const SIZES = { sm: "max-w-md", md: "max-w-xl", lg: "max-w-3xl", xl: "max-w-5xl" };

export function Dialog({
  open,
  onClose,
  title,
  description,
  icon,
  size = "md",
  dismissable = true,
  tone = "default",
  footer,
  className,
  children,
  "data-testid": testId,
}: {
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  description?: React.ReactNode | undefined;
  icon?: React.ReactNode | undefined;
  size?: keyof typeof SIZES | undefined;
  /** Scrim click and Escape close the dialog. */
  dismissable?: boolean | undefined;
  tone?: "default" | "danger" | undefined;
  footer?: React.ReactNode | undefined;
  className?: string | undefined;
  children?: React.ReactNode | undefined;
  "data-testid"?: string | undefined;
}) {
  const titleId = useId();
  const panelRef = useRef<HTMLDivElement>(null);
  const restoreRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    restoreRef.current = document.activeElement as HTMLElement | null;
    // Focus the first focusable control that is not the close button.
    const t = window.setTimeout(() => {
      const panel = panelRef.current;
      if (!panel || panel.contains(document.activeElement)) return;
      const target =
        panel.querySelector<HTMLElement>("[data-autofocus]") ??
        panel.querySelector<HTMLElement>("input:not([type=hidden]), textarea, select") ??
        panel.querySelector<HTMLElement>("[data-dialog-footer] button:last-child") ??
        panel;
      target.focus();
    }, 0);
    return () => {
      window.clearTimeout(t);
      restoreRef.current?.focus?.();
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && dismissable) {
        e.stopPropagation();
        onClose();
      }
      if (e.key === "Tab") {
        // Keep focus inside the dialog.
        const panel = panelRef.current;
        if (!panel) return;
        const focusables = [...panel.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]):not([aria-hidden="true"]), [tabindex]:not([tabindex="-1"])',
        )].filter((el) => el.offsetParent !== null);
        if (focusables.length === 0) return;
        const first = focusables[0]!;
        const last = focusables[focusables.length - 1]!;
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [open, dismissable, onClose]);

  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-[60] flex items-start justify-center overflow-y-auto p-4 pt-[10vh]">
      <div
        className="fixed inset-0 animate-fade-in bg-overlay backdrop-blur-[2px]"
        aria-hidden="true"
        onMouseDown={() => dismissable && onClose()}
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        data-testid={testId}
        className={cn(
          "relative w-full animate-pop-in rounded-xl border bg-raised shadow-pop focus:outline-none",
          tone === "danger" ? "border-deny/40 border-t-2 border-t-deny" : "border-bd",
          SIZES[size],
          className,
        )}
      >
        <div className="flex items-start gap-3 px-6 pt-5">
          {icon && <div className="mt-0.5 shrink-0">{icon}</div>}
          <div className="min-w-0 flex-1">
            <h2 id={titleId} className="text-lg font-semibold leading-tight text-fg">
              {title}
            </h2>
            {description && <div className="mt-1 text-[13px] text-muted">{description}</div>}
          </div>
          {dismissable && (
            <IconButton label="Close" size="sm" onClick={onClose} className="-mr-2 -mt-1">
              <X size={16} />
            </IconButton>
          )}
        </div>
        {children && <div className="px-6 pb-2 pt-4">{children}</div>}
        {footer && (
          <div data-dialog-footer className="mt-3 flex items-center justify-end gap-2 border-t border-bd px-6 py-4">
            {footer}
          </div>
        )}
      </div>
    </div>,
    document.body,
  );
}

export type ConfirmOptions = {
  title: React.ReactNode;
  description?: React.ReactNode | undefined;
  /** Bulleted consequences: what will happen. */
  consequences?: { icon?: React.ReactNode; text: React.ReactNode }[] | undefined;
  confirmLabel?: string | undefined;
  cancelLabel?: string | undefined;
  tone?: "default" | "danger" | undefined;
  /** Require typing this exact text before confirming (rare destructive ops). */
  typeToConfirm?: string | undefined;
  body?: React.ReactNode | undefined;
};

export type PromptOptions = {
  title: React.ReactNode;
  description?: React.ReactNode | undefined;
  label: string;
  initialValue?: string | undefined;
  placeholder?: string | undefined;
  confirmLabel?: string | undefined;
  mono?: boolean | undefined;
  /** Return an error message to block submission. */
  validate?: ((value: string) => string | null) | undefined;
};

type DialogRequest =
  | { kind: "confirm"; options: ConfirmOptions; resolve: (ok: boolean) => void }
  | { kind: "prompt"; options: PromptOptions; resolve: (value: string | null) => void };

const DialogContext = createContext<{
  confirm: (o: ConfirmOptions) => Promise<boolean>;
  prompt: (o: PromptOptions) => Promise<string | null>;
} | null>(null);

export function DialogProvider({ children }: { children: React.ReactNode }) {
  const [request, setRequest] = useState<DialogRequest | null>(null);
  const confirm = useCallback(
    (options: ConfirmOptions) => new Promise<boolean>((resolve) => setRequest({ kind: "confirm", options, resolve })),
    [],
  );
  const prompt = useCallback(
    (options: PromptOptions) => new Promise<string | null>((resolve) => setRequest({ kind: "prompt", options, resolve })),
    [],
  );
  const value = React.useMemo(() => ({ confirm, prompt }), [confirm, prompt]);
  return (
    <DialogContext.Provider value={value}>
      {children}
      {request?.kind === "confirm" && (
        <ConfirmDialog
          options={request.options}
          onDone={(ok) => {
            request.resolve(ok);
            setRequest(null);
          }}
        />
      )}
      {request?.kind === "prompt" && (
        <PromptDialog
          options={request.options}
          onDone={(v) => {
            request.resolve(v);
            setRequest(null);
          }}
        />
      )}
    </DialogContext.Provider>
  );
}

export function useConfirm(): (o: ConfirmOptions) => Promise<boolean> {
  const ctx = useContext(DialogContext);
  if (!ctx) throw new Error("useConfirm outside DialogProvider");
  return ctx.confirm;
}

export function usePrompt(): (o: PromptOptions) => Promise<string | null> {
  const ctx = useContext(DialogContext);
  if (!ctx) throw new Error("usePrompt outside DialogProvider");
  return ctx.prompt;
}

function ConfirmDialog({ options, onDone }: { options: ConfirmOptions; onDone: (ok: boolean) => void }) {
  const [typed, setTyped] = useState("");
  const danger = options.tone === "danger";
  const ready = !options.typeToConfirm || typed === options.typeToConfirm;
  return (
    <Dialog
      open
      onClose={() => onDone(false)}
      tone={danger ? "danger" : "default"}
      size="sm"
      data-testid="confirm-dialog"
      icon={
        danger ? (
          <span className="flex size-9 items-center justify-center rounded-full bg-deny/12 text-deny">
            <TriangleAlert size={18} />
          </span>
        ) : undefined
      }
      title={options.title}
      description={options.description}
      footer={
        <>
          <Button variant="secondary" onClick={() => onDone(false)} data-testid="confirm-cancel">
            {options.cancelLabel ?? "Cancel"}
          </Button>
          <Button
            variant={danger ? "danger-solid" : "primary"}
            disabled={!ready}
            onClick={() => onDone(true)}
            data-testid="confirm-ok"
          >
            {options.confirmLabel ?? "Confirm"}
          </Button>
        </>
      }
    >
      {(options.consequences?.length || options.body || options.typeToConfirm) && (
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (ready) onDone(true);
          }}
        >
          {options.consequences && options.consequences.length > 0 && (
            <ul className="space-y-2.5 text-[13px]">
              {options.consequences.map((c, i) => (
                <li key={i} className="flex items-start gap-2.5">
                  <span className="mt-0.5 shrink-0 text-muted">{c.icon ?? <span className="block size-1.5 translate-y-1.5 rounded-full bg-muted" />}</span>
                  <span className="text-fg/90">{c.text}</span>
                </li>
              ))}
            </ul>
          )}
          {options.body}
          {options.typeToConfirm && (
            <div className="space-y-1.5 border-t border-bd pt-4">
              <label className="block text-[13px] text-muted">
                Type <span className="rounded bg-inset px-1.5 py-0.5 font-mono text-fg">{options.typeToConfirm}</span> to confirm
              </label>
              <div className="relative">
                <Input
                  data-testid="confirm-type"
                  data-autofocus
                  mono
                  className="w-full pr-8"
                  value={typed}
                  autoComplete="off"
                  spellCheck={false}
                  onChange={(e) => setTyped(e.target.value)}
                />
                {ready && <Check size={15} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-accent" />}
              </div>
            </div>
          )}
        </form>
      )}
    </Dialog>
  );
}

function PromptDialog({ options, onDone }: { options: PromptOptions; onDone: (v: string | null) => void }) {
  const [value, setValue] = useState(options.initialValue ?? "");
  const error = options.validate?.(value.trim()) ?? null;
  const submit = () => {
    if (error || !value.trim()) return;
    onDone(value.trim());
  };
  return (
    <Dialog
      open
      onClose={() => onDone(null)}
      size="sm"
      data-testid="prompt-dialog"
      title={options.title}
      description={options.description}
      footer={
        <>
          <Button variant="secondary" onClick={() => onDone(null)}>
            Cancel
          </Button>
          <Button variant="primary" disabled={!!error || !value.trim()} onClick={submit} data-testid="prompt-ok">
            {options.confirmLabel ?? "Save"}
          </Button>
        </>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
        className="space-y-1.5"
      >
        <label className="block text-[13px] font-medium">{options.label}</label>
        <Input
          data-testid="prompt-input"
          data-autofocus
          mono={options.mono}
          className="w-full"
          value={value}
          placeholder={options.placeholder}
          onChange={(e) => setValue(e.target.value)}
          invalid={!!error && value.trim() !== ""}
        />
        {error && value.trim() !== "" && <p className="text-xs text-deny">{error}</p>}
      </form>
    </Dialog>
  );
}
