// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useId } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";
import { IconButton, cn } from "./ui";

/**
 * Right-hand slide-over for editing or inspecting one thing without leaving
 * the page (role editor, item details on narrow screens).
 */
export function Drawer({
  open,
  onClose,
  title,
  subtitle,
  footer,
  width = "w-[460px]",
  children,
  "data-testid": testId,
}: {
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  subtitle?: React.ReactNode | undefined;
  footer?: React.ReactNode | undefined;
  width?: string | undefined;
  children: React.ReactNode;
  "data-testid"?: string | undefined;
}) {
  const titleId = useId();
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-[55]">
      <div className="absolute inset-0 animate-fade-in bg-overlay" aria-hidden="true" onMouseDown={onClose} />
      <aside
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        data-testid={testId}
        className={cn(
          "absolute inset-y-0 right-0 flex max-w-full animate-slide-in-right flex-col border-l border-bd bg-raised shadow-pop",
          width,
        )}
      >
        <header className="flex items-start gap-3 border-b border-bd px-6 py-4">
          <div className="min-w-0 flex-1">
            <h2 id={titleId} className="text-lg font-semibold">
              {title}
            </h2>
            {subtitle && <p className="mt-0.5 text-[13px] text-muted">{subtitle}</p>}
          </div>
          <IconButton label="Close" onClick={onClose} className="-mr-2">
            <X size={16} />
          </IconButton>
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto px-6 py-5">{children}</div>
        {footer && <footer className="flex items-center justify-end gap-2 border-t border-bd px-6 py-4">{footer}</footer>}
      </aside>
    </div>,
    document.body,
  );
}

/** Inline side panel (not modal): sits beside a list on wide screens. */
export function SidePanel({
  title,
  icon,
  badges,
  onClose,
  className,
  children,
  "data-testid": testId,
}: {
  title: React.ReactNode;
  icon?: React.ReactNode | undefined;
  badges?: React.ReactNode | undefined;
  onClose?: (() => void) | undefined;
  className?: string | undefined;
  children: React.ReactNode;
  "data-testid"?: string | undefined;
}) {
  return (
    <aside
      data-testid={testId}
      className={cn("animate-fade-in self-start overflow-hidden rounded-xl border border-bd bg-raised", className)}
    >
      <header className="flex items-center gap-2.5 border-b border-bd px-5 py-3.5">
        {icon && <span className="shrink-0 text-muted">{icon}</span>}
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
          <h2 className="truncate font-mono text-[15px] font-semibold">{title}</h2>
          {badges}
        </div>
        {onClose && (
          <IconButton label="Close panel" size="sm" onClick={onClose} className="-mr-1.5">
            <X size={15} />
          </IconButton>
        )}
      </header>
      <div className="space-y-6 px-5 py-5">{children}</div>
    </aside>
  );
}

/** Titled block inside a panel or drawer. */
export function PanelSection({
  title,
  actions,
  children,
  className,
}: {
  title: React.ReactNode;
  actions?: React.ReactNode | undefined;
  children: React.ReactNode;
  className?: string | undefined;
}) {
  return (
    <section className={className}>
      <div className="mb-2.5 flex items-center justify-between gap-2">
        <h3 className="text-[13px] font-semibold text-fg">{title}</h3>
        {actions}
      </div>
      {children}
    </section>
  );
}
