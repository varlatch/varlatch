// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useId, useRef, useState } from "react";
import { Check, ChevronDown } from "lucide-react";
import { cn } from "./ui";

/**
 * Accessible custom listbox replacing native `<select>` (UI overhaul phase 1).
 *
 * A visually-hidden native `<select>` is kept in sync with the custom control:
 * Playwright's `selectOption` (used throughout apps/web/scripts/e2e-*.mjs)
 * keeps driving `[data-testid=…]` / bare `select` locators unchanged, and the
 * options' text stays readable for tests that assert on `option` contents.
 * The native element is 1×1, transparent and not in the tab order, so users
 * only ever see the token-styled custom control — no browser blue anywhere.
 */

export type SelectOption = {
  value: string;
  label: string;
  /** Optional muted second line under the label. */
  description?: string;
  icon?: React.ReactNode;
  disabled?: boolean;
};

export function Select({
  value,
  onChange,
  options,
  placeholder,
  disabled,
  className,
  buttonClassName,
  "data-testid": testId,
  "aria-label": ariaLabel,
  id,
}: {
  value?: string | undefined;
  onChange?: ((value: string) => void) | undefined;
  options: SelectOption[];
  placeholder?: string | undefined;
  disabled?: boolean | undefined;
  className?: string | undefined;
  buttonClassName?: string | undefined;
  "data-testid"?: string | undefined;
  "aria-label"?: string | undefined;
  id?: string | undefined;
}) {
  const listboxId = useId();
  const rootRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const [open, setOpen] = useState(false);
  const selectedIndex = options.findIndex((o) => o.value === (value ?? ""));
  const [activeIndex, setActiveIndex] = useState(selectedIndex);
  const typeahead = useRef<{ buffer: string; at: number }>({ buffer: "", at: 0 });

  const selected = selectedIndex >= 0 ? options[selectedIndex] : undefined;
  // The hidden native select must always reflect `value`; when the current
  // value (or an unset one behind a placeholder) has no matching option we add
  // a hidden sentinel so the native control can't silently show option #0.
  const needsSentinel = selectedIndex < 0;

  const close = () => {
    setOpen(false);
  };

  const openList = (at?: number) => {
    if (disabled) return;
    setActiveIndex(at ?? (selectedIndex >= 0 ? selectedIndex : firstEnabled(options)));
    setOpen(true);
  };

  const commit = (index: number) => {
    const opt = options[index];
    if (!opt || opt.disabled) return;
    onChange?.(opt.value);
    close();
  };

  // Close on click/focus outside.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) close();
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  // Keep the active option scrolled into view.
  useEffect(() => {
    if (!open) return;
    listRef.current
      ?.querySelector<HTMLElement>(`[data-index="${activeIndex}"]`)
      ?.scrollIntoView({ block: "nearest" });
  }, [open, activeIndex]);

  const move = (delta: number) => {
    let i = activeIndex;
    for (let step = 0; step < options.length; step++) {
      i = Math.min(options.length - 1, Math.max(0, i + delta));
      if (!options[i]?.disabled) break;
      if (i === 0 || i === options.length - 1) break;
    }
    setActiveIndex(i);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (disabled) return;
    if (!open) {
      if (["ArrowDown", "ArrowUp", "Enter", " "].includes(e.key)) {
        e.preventDefault();
        openList();
      }
      return;
    }
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        move(1);
        break;
      case "ArrowUp":
        e.preventDefault();
        move(-1);
        break;
      case "Home":
        e.preventDefault();
        setActiveIndex(firstEnabled(options));
        break;
      case "End":
        e.preventDefault();
        setActiveIndex(lastEnabled(options));
        break;
      case "Enter":
      case " ":
        e.preventDefault();
        commit(activeIndex);
        break;
      case "Escape":
        e.preventDefault();
        close();
        break;
      case "Tab":
        close();
        break;
      default: {
        if (e.key.length === 1 && !e.metaKey && !e.ctrlKey && !e.altKey) {
          const now = Date.now();
          const t = typeahead.current;
          t.buffer = (now - t.at > 500 ? "" : t.buffer) + e.key.toLowerCase();
          t.at = now;
          const hit = options.findIndex(
            (o) => !o.disabled && o.label.toLowerCase().startsWith(t.buffer),
          );
          if (hit >= 0) setActiveIndex(hit);
        }
      }
    }
  };

  return (
    <div ref={rootRef} className={cn("relative inline-block text-left", className)}>
      {/* Hidden native fallback — Playwright drives this; users never see it. */}
      <select
        data-testid={testId}
        aria-hidden="true"
        tabIndex={-1}
        disabled={disabled}
        value={value ?? ""}
        onChange={(e) => onChange?.(e.target.value)}
        className="absolute left-0 top-0 z-10 h-px w-px cursor-default appearance-none overflow-hidden border-0 bg-transparent p-0 opacity-0"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value} disabled={o.disabled}>
            {o.label}
          </option>
        ))}
        {/* Last, so tests reading the first option's text see a real option. */}
        {needsSentinel && options.length > 0 && <option value={value ?? ""} hidden></option>}
      </select>
      <button
        type="button"
        id={id}
        data-testid={testId ? `${testId}-trigger` : undefined}
        role="combobox"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listboxId : undefined}
        aria-activedescendant={open && activeIndex >= 0 ? `${listboxId}-${activeIndex}` : undefined}
        aria-label={ariaLabel}
        disabled={disabled}
        onClick={() => (open ? close() : openList())}
        onKeyDown={onKeyDown}
        className={cn(
          "flex w-full min-w-0 cursor-pointer items-center justify-between gap-2 rounded-md border border-bd bg-inset px-2 py-1.5 text-left text-sm text-fg",
          "focus:outline-none focus-visible:outline-2 focus-visible:outline-accent focus-visible:outline-offset-1",
          disabled && "cursor-not-allowed opacity-40",
          buttonClassName,
        )}
      >
        <span className="flex min-w-0 items-center gap-2">
          {selected?.icon && <span className="shrink-0 text-muted">{selected.icon}</span>}
          <span className={cn("truncate", !selected && "text-muted")}>
            {selected ? selected.label : (placeholder ?? "Select…")}
          </span>
        </span>
        <ChevronDown size={14} className="shrink-0 text-muted" aria-hidden="true" />
      </button>
      {open && (
        <ul
          ref={listRef}
          id={listboxId}
          role="listbox"
          aria-label={ariaLabel}
          className="absolute left-0 top-full z-40 mt-1 max-h-64 w-full min-w-max overflow-y-auto rounded-md border border-bd bg-raised py-1 shadow-lg"
        >
          {options.map((o, i) => (
            <li
              key={o.value}
              id={`${listboxId}-${i}`}
              data-index={i}
              role="option"
              aria-selected={i === selectedIndex}
              aria-disabled={o.disabled || undefined}
              onMouseEnter={() => !o.disabled && setActiveIndex(i)}
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => commit(i)}
              className={cn(
                "flex cursor-pointer items-start gap-2 px-2.5 py-1.5 text-sm",
                i === activeIndex && "bg-accent/10",
                o.disabled && "cursor-not-allowed opacity-40",
              )}
            >
              <span className="flex w-4 shrink-0 items-center pt-0.5 text-accent">
                {i === selectedIndex && <Check size={13} aria-hidden="true" />}
              </span>
              {o.icon && <span className="shrink-0 pt-0.5 text-muted">{o.icon}</span>}
              <span className="min-w-0">
                <span className="block truncate">{o.label}</span>
                {o.description && (
                  <span className="block text-xs text-muted">{o.description}</span>
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function firstEnabled(options: SelectOption[]): number {
  return Math.max(0, options.findIndex((o) => !o.disabled));
}
function lastEnabled(options: SelectOption[]): number {
  for (let i = options.length - 1; i >= 0; i--) if (!options[i]?.disabled) return i;
  return options.length - 1;
}

export type MenuItem = {
  label: React.ReactNode;
  onSelect: () => void;
  danger?: boolean;
  icon?: React.ReactNode;
  "data-testid"?: string;
};

/** Trigger + items dropdown for row/entity actions (token palette only). */
export function Menu({
  items,
  label,
  children,
  className,
  buttonClassName,
  "data-testid": testId,
}: {
  items: MenuItem[];
  /** Accessible name for the trigger. */
  label: string;
  /** Trigger contents; defaults to a horizontal-dots glyph via caller. */
  children?: React.ReactNode | undefined;
  className?: string | undefined;
  buttonClassName?: string | undefined;
  "data-testid"?: string | undefined;
}) {
  const menuId = useId();
  const rootRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (!open) {
      if (["ArrowDown", "ArrowUp", "Enter", " "].includes(e.key)) {
        e.preventDefault();
        setActiveIndex(0);
        setOpen(true);
      }
      return;
    }
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        setActiveIndex((i) => Math.min(items.length - 1, i + 1));
        break;
      case "ArrowUp":
        e.preventDefault();
        setActiveIndex((i) => Math.max(0, i - 1));
        break;
      case "Home":
        e.preventDefault();
        setActiveIndex(0);
        break;
      case "End":
        e.preventDefault();
        setActiveIndex(items.length - 1);
        break;
      case "Enter":
      case " ": {
        e.preventDefault();
        const item = items[activeIndex];
        if (item) {
          setOpen(false);
          item.onSelect();
        }
        break;
      }
      case "Escape":
        e.preventDefault();
        setOpen(false);
        break;
      case "Tab":
        setOpen(false);
        break;
    }
  };

  return (
    <div ref={rootRef} className={cn("relative inline-block", className)}>
      <button
        type="button"
        data-testid={testId}
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => setOpen((v) => !v)}
        onKeyDown={onKeyDown}
        className={cn(
          "cursor-pointer rounded-md p-1 text-muted hover:bg-inset hover:text-fg focus-visible:outline-2 focus-visible:outline-accent",
          buttonClassName,
        )}
      >
        {children ?? "⋯"}
      </button>
      {open && (
        <ul
          id={menuId}
          role="menu"
          aria-label={label}
          className="absolute right-0 top-full z-30 mt-1 w-44 rounded-md border border-bd bg-raised py-1 shadow-lg"
        >
          {items.map((item, i) => (
            <li key={i} role="none">
              <button
                type="button"
                role="menuitem"
                data-testid={item["data-testid"]}
                onMouseEnter={() => setActiveIndex(i)}
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => {
                  setOpen(false);
                  item.onSelect();
                }}
                className={cn(
                  "flex w-full cursor-pointer items-center gap-2 px-3 py-1.5 text-left text-sm",
                  i === activeIndex && "bg-inset",
                  item.danger ? "text-deny" : "text-fg",
                )}
              >
                {item.icon && <span className="shrink-0 text-muted">{item.icon}</span>}
                {item.label}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
