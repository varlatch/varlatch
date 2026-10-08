// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useEffect, useId, useRef, useState } from "react";
import { Check, ChevronDown } from "lucide-react";
import { cn } from "./ui";
import { Popover } from "./Popover";

/**
 * Accessible custom listbox replacing native `<select>`.
 *
 * A visually hidden native `<select>` is kept in sync with the custom control:
 * Playwright's `selectOption` (used throughout apps/web/scripts/e2e-*.mjs)
 * keeps driving `[data-testid=…]` / bare `select` locators unchanged, and the
 * options' text stays readable for tests that assert on `option` contents.
 * The native element is 1×1, transparent and not in the tab order.
 */

export type SelectOption = {
  value: string;
  label: string;
  /** Optional muted second line under the label. */
  description?: string | undefined;
  icon?: React.ReactNode | undefined;
  disabled?: boolean | undefined;
  /** A heading the option is listed under; consecutive options of one group share it. */
  group?: string | undefined;
};

/** Consecutive options under one heading (or none), with their indexes in `options`. */
function runsOf(options: SelectOption[]): { group: string | undefined; items: { option: SelectOption; index: number }[] }[] {
  const runs: { group: string | undefined; items: { option: SelectOption; index: number }[] }[] = [];
  options.forEach((option, index) => {
    const last = runs[runs.length - 1];
    if (last && last.group === option.group) last.items.push({ option, index });
    else runs.push({ group: option.group, items: [{ option, index }] });
  });
  return runs;
}

export function Select({
  value,
  onChange,
  options,
  placeholder,
  disabled,
  className,
  buttonClassName,
  size = "md",
  prefix,
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
  size?: "sm" | "md" | undefined;
  /** Muted label inside the trigger before the value, e.g. "Decision:" on a facet chip. */
  prefix?: React.ReactNode | undefined;
  "data-testid"?: string | undefined;
  "aria-label"?: string | undefined;
  id?: string | undefined;
}) {
  const listboxId = useId();
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const [open, setOpen] = useState(false);
  const selectedIndex = options.findIndex((o) => o.value === (value ?? ""));
  const [activeIndex, setActiveIndex] = useState(selectedIndex);
  const typeahead = useRef<{ buffer: string; at: number }>({ buffer: "", at: 0 });

  const selected = selectedIndex >= 0 ? options[selectedIndex] : undefined;
  const needsSentinel = selectedIndex < 0;

  const close = () => setOpen(false);
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
    triggerRef.current?.focus();
  };

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (!rootRef.current?.contains(t) && !listRef.current?.contains(t)) close();
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    listRef.current?.querySelector<HTMLElement>(`[data-index="${activeIndex}"]`)?.scrollIntoView({ block: "nearest" });
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
        e.stopPropagation();
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
          const hit = options.findIndex((o) => !o.disabled && o.label.toLowerCase().startsWith(t.buffer));
          if (hit >= 0) setActiveIndex(hit);
        }
      }
    }
  };

  return (
    <div ref={rootRef} className={cn("relative inline-block text-left", className)}>
      {/* Hidden native fallback: Playwright drives this; users never see it. */}
      <select
        data-testid={testId}
        aria-hidden="true"
        tabIndex={-1}
        disabled={disabled}
        value={value ?? ""}
        onChange={(e) => onChange?.(e.target.value)}
        className="absolute left-0 top-0 z-10 h-px w-px cursor-default appearance-none overflow-hidden border-0 bg-transparent p-0 opacity-0"
      >
        {runsOf(options).map((run, r) => {
          const items = run.items.map(({ option: o }) => (
            <option key={o.value} value={o.value} disabled={o.disabled}>
              {o.label}
            </option>
          ));
          return run.group === undefined ? (
            items
          ) : (
            <optgroup key={`group-${r}`} label={run.group}>
              {items}
            </optgroup>
          );
        })}
        {needsSentinel && options.length > 0 && <option value={value ?? ""} hidden></option>}
      </select>
      <button
        ref={triggerRef}
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
          "flex w-full min-w-0 cursor-pointer items-center justify-between gap-2 rounded-md border border-bd bg-inset text-left text-sm text-fg transition-colors hover:border-bd-strong",
          size === "sm" ? "h-7 px-2 text-xs" : "h-8 px-2.5",
          open && "border-accent ring-2 ring-accent/20",
          disabled && "cursor-not-allowed opacity-45",
          buttonClassName,
        )}
      >
        <span className="flex min-w-0 items-center gap-2">
          {prefix && <span className="-mr-0.5 shrink-0 text-muted">{prefix}</span>}
          {selected?.icon && <span className="flex shrink-0 items-center text-muted">{selected.icon}</span>}
          <span className={cn("truncate", !selected && "text-subtle")}>
            {selected ? selected.label : (placeholder ?? "Select…")}
          </span>
        </span>
        <ChevronDown size={14} className="shrink-0 text-muted" aria-hidden="true" />
      </button>
      <Popover anchor={triggerRef} open={open} matchWidth>
        <ul
          ref={listRef}
          id={listboxId}
          role="listbox"
          aria-label={ariaLabel}
          className="max-h-72 min-w-max animate-pop-in overflow-y-auto rounded-lg border border-bd bg-raised p-1 shadow-pop"
        >
          {runsOf(options).map((run, r) => {
            const items = run.items.map(({ option: o, index: i }) => (
              <li
                key={o.value}
                id={`${listboxId}-${i}`}
                data-index={i}
                role="option"
                aria-selected={i === selectedIndex}
                aria-disabled={o.disabled || undefined}
                onMouseMove={() => !o.disabled && setActiveIndex(i)}
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => commit(i)}
                className={cn(
                  "flex cursor-pointer items-start gap-2 rounded-md px-2 py-1.5 text-sm",
                  i === activeIndex && "bg-hover",
                  o.disabled && "cursor-not-allowed opacity-45",
                )}
              >
                {o.icon && <span className="flex shrink-0 items-center pt-0.5 text-muted">{o.icon}</span>}
                <span className="min-w-0 flex-1">
                  <span className="block truncate">{o.label}</span>
                  {o.description && <span className="block max-w-80 text-xs text-muted">{o.description}</span>}
                </span>
                <span className="flex w-4 shrink-0 items-center pt-0.5 text-accent">
                  {i === selectedIndex && <Check size={14} aria-hidden="true" />}
                </span>
              </li>
            ));
            if (run.group === undefined) return items;
            const heading = `${listboxId}-group-${r}`;
            return (
              <li key={heading} role="group" aria-labelledby={heading}>
                <div
                  id={heading}
                  className="px-2 pb-1 pt-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-muted"
                >
                  {run.group}
                </div>
                <ul role="none">{items}</ul>
              </li>
            );
          })}
        </ul>
      </Popover>
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
  danger?: boolean | undefined;
  disabled?: boolean | undefined;
  icon?: React.ReactNode | undefined;
  /** Muted trailing text, e.g. a shortcut. */
  hint?: React.ReactNode | undefined;
  /** Draw a divider above this item. */
  separatorBefore?: boolean | undefined;
  "data-testid"?: string | undefined;
};

/** Trigger + items dropdown for row and entity actions. */
export function Menu({
  items,
  label,
  children,
  className,
  buttonClassName,
  align = "end",
  header,
  width = "w-52",
  "data-testid": testId,
}: {
  items: MenuItem[];
  /** Accessible name for the trigger. */
  label: string;
  /** Trigger contents. */
  children?: React.ReactNode | undefined;
  className?: string | undefined;
  buttonClassName?: string | undefined;
  align?: "start" | "end" | undefined;
  /** Optional non-interactive content above the items. */
  header?: React.ReactNode | undefined;
  width?: string | undefined;
  "data-testid"?: string | undefined;
}) {
  const menuId = useId();
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const enabled = items.map((it, i) => (it.disabled ? -1 : i)).filter((i) => i >= 0);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (!rootRef.current?.contains(t) && !listRef.current?.contains(t)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  const step = (delta: number) => {
    const pos = enabled.indexOf(activeIndex);
    const next = enabled[Math.min(enabled.length - 1, Math.max(0, pos + delta))];
    if (next !== undefined) setActiveIndex(next);
  };
  const choose = (i: number) => {
    const item = items[i];
    if (!item || item.disabled) return;
    setOpen(false);
    item.onSelect();
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (!open) {
      if (["ArrowDown", "ArrowUp", "Enter", " "].includes(e.key)) {
        e.preventDefault();
        setActiveIndex(enabled[0] ?? 0);
        setOpen(true);
      }
      return;
    }
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        step(1);
        break;
      case "ArrowUp":
        e.preventDefault();
        step(-1);
        break;
      case "Home":
        e.preventDefault();
        setActiveIndex(enabled[0] ?? 0);
        break;
      case "End":
        e.preventDefault();
        setActiveIndex(enabled[enabled.length - 1] ?? 0);
        break;
      case "Enter":
      case " ":
        e.preventDefault();
        choose(activeIndex);
        break;
      case "Escape":
        e.preventDefault();
        e.stopPropagation();
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
        ref={triggerRef}
        type="button"
        data-testid={testId}
        aria-label={label}
        title={label}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => {
          setActiveIndex(enabled[0] ?? 0);
          setOpen((v) => !v);
        }}
        onKeyDown={onKeyDown}
        className={cn(
          "inline-flex cursor-pointer items-center rounded-md text-muted transition-colors hover:bg-hover hover:text-fg",
          children === undefined && "size-8 justify-center",
          open && "bg-hover text-fg",
          buttonClassName,
        )}
      >
        {children ?? "⋯"}
      </button>
      <Popover anchor={triggerRef} open={open} align={align}>
        <div className={cn("animate-pop-in rounded-lg border border-bd bg-raised p-1 shadow-pop", width)}>
          {header && <div className="border-b border-bd px-2 pb-2 pt-1 mb-1">{header}</div>}
          <ul ref={listRef} id={menuId} role="menu" aria-label={label}>
            {items.map((item, i) => (
              <li key={i} role="none">
                {item.separatorBefore && <div role="separator" className="-mx-1 my-1 h-px bg-bd" />}
                <button
                  type="button"
                  role="menuitem"
                  disabled={item.disabled}
                  data-testid={item["data-testid"]}
                  onMouseMove={() => !item.disabled && setActiveIndex(i)}
                  onMouseDown={(e) => e.preventDefault()}
                  onClick={() => choose(i)}
                  className={cn(
                    "flex w-full cursor-pointer items-center gap-2.5 rounded-md px-2 py-1.5 text-left text-sm",
                    i === activeIndex && !item.disabled && (item.danger ? "bg-deny/10" : "bg-hover"),
                    item.danger ? "text-deny" : "text-fg",
                    item.disabled && "cursor-not-allowed opacity-45",
                  )}
                >
                  {item.icon && (
                    <span className={cn("flex shrink-0 items-center", item.danger ? "text-deny" : "text-muted")}>
                      {item.icon}
                    </span>
                  )}
                  <span className="min-w-0 flex-1 truncate">{item.label}</span>
                  {item.hint && <span className="shrink-0 text-xs text-muted">{item.hint}</span>}
                </button>
              </li>
            ))}
          </ul>
        </div>
      </Popover>
    </div>
  );
}
