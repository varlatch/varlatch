// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { CircleAlert, CircleCheck, RotateCcw, X } from "lucide-react";
import { Button, IconButton, cn } from "./ui";

/**
 * Toasts: transient feedback for completed actions and failures, replacing
 * window.alert. Errors stay until dismissed; successes fade after a few
 * seconds; `undo` toasts run their action only if the user asks in time.
 */

type ToastTone = "success" | "error" | "info";
type ToastAction = { label: string; onClick: () => void };
type ToastItem = {
  id: number;
  tone: ToastTone;
  title: React.ReactNode;
  description?: React.ReactNode | undefined;
  action?: ToastAction | undefined;
  /** Milliseconds before auto-dismiss; null keeps it until dismissed. */
  duration: number | null;
  undo?: boolean | undefined;
};

type ToastApi = {
  success: (title: React.ReactNode, opts?: { description?: React.ReactNode; action?: ToastAction }) => void;
  error: (title: React.ReactNode, opts?: { description?: React.ReactNode; action?: ToastAction }) => void;
  info: (title: React.ReactNode, opts?: { description?: React.ReactNode; action?: ToastAction }) => void;
  /** Shows a toast with an Undo button for `ms`; calls onUndo if pressed. */
  undo: (title: React.ReactNode, onUndo: () => void, ms?: number) => void;
};

const ToastContext = createContext<ToastApi | null>(null);
let nextId = 1;

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const dismiss = useCallback((id: number) => setItems((all) => all.filter((t) => t.id !== id)), []);
  const push = useCallback((t: Omit<ToastItem, "id">) => {
    const id = nextId++;
    setItems((all) => [...all.slice(-3), { ...t, id }]);
  }, []);
  const api = React.useMemo<ToastApi>(
    () => ({
      success: (title, opts) => push({ tone: "success", title, duration: 4000, ...opts }),
      info: (title, opts) => push({ tone: "info", title, duration: 4000, ...opts }),
      error: (title, opts) => push({ tone: "error", title, duration: null, ...opts }),
      undo: (title, onUndo, ms = 6000) =>
        push({ tone: "info", title, duration: ms, undo: true, action: { label: "Undo", onClick: onUndo } }),
    }),
    [push],
  );
  return (
    <ToastContext.Provider value={api}>
      {children}
      {createPortal(
        <div
          aria-live="polite"
          className="pointer-events-none fixed bottom-5 right-5 z-[80] flex w-[380px] max-w-[calc(100vw-2.5rem)] flex-col gap-2"
        >
          {items.map((t) => (
            <Toast key={t.id} toast={t} onDismiss={() => dismiss(t.id)} />
          ))}
        </div>,
        document.body,
      )}
    </ToastContext.Provider>
  );
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast outside ToastProvider");
  return ctx;
}

function Toast({ toast, onDismiss }: { toast: ToastItem; onDismiss: () => void }) {
  const [paused, setPaused] = useState(false);
  const remaining = useRef(toast.duration);
  const startedAt = useRef(Date.now());

  useEffect(() => {
    if (remaining.current === null || paused) return;
    startedAt.current = Date.now();
    const t = window.setTimeout(onDismiss, remaining.current);
    return () => {
      window.clearTimeout(t);
      if (remaining.current !== null) remaining.current -= Date.now() - startedAt.current;
    };
  }, [paused, onDismiss]);

  const icon =
    toast.tone === "success" ? (
      <CircleCheck size={18} className="text-accent" />
    ) : toast.tone === "error" ? (
      <CircleAlert size={18} className="text-deny" />
    ) : toast.undo ? (
      <RotateCcw size={16} className="text-muted" />
    ) : (
      <CircleCheck size={18} className="text-info" />
    );

  return (
    <div
      role={toast.tone === "error" ? "alert" : "status"}
      data-testid={`toast-${toast.tone}`}
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      className={cn(
        "pointer-events-auto relative flex animate-toast-in items-start gap-3 overflow-hidden rounded-xl border bg-raised px-4 py-3 shadow-pop",
        toast.tone === "error" ? "border-deny/50" : "border-bd",
      )}
    >
      <span className="mt-px shrink-0">{icon}</span>
      <div className="min-w-0 flex-1 text-[13px]">
        <p className="font-medium text-fg">{toast.title}</p>
        {toast.description && <p className="mt-0.5 text-muted">{toast.description}</p>}
      </div>
      {toast.action && (
        <Button
          size="sm"
          variant="secondary"
          onClick={() => {
            toast.action!.onClick();
            onDismiss();
          }}
        >
          {toast.action.label}
        </Button>
      )}
      <IconButton label="Dismiss" size="sm" onClick={onDismiss} className="-mr-1.5 -mt-1">
        <X size={14} />
      </IconButton>
      {toast.undo && toast.duration && (
        <span
          aria-hidden="true"
          className="absolute bottom-0 left-0 h-0.5 bg-accent/70"
          style={{
            width: "100%",
            animation: `toast-drain ${toast.duration}ms linear forwards`,
            animationPlayState: paused ? "paused" : "running",
          }}
        />
      )}
    </div>
  );
}
